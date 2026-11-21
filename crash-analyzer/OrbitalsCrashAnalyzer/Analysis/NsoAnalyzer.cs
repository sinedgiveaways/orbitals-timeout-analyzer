using System.IO;
using System.Buffers.Binary;
using System.Text;
using K4os.Compression.LZ4;

namespace OrbitalsCrashAnalyzer.Analysis;

public static class NsoAnalyzer
{
    private sealed record Segment(string Name, uint FileOffset, uint MemoryOffset, uint FileSize, uint MemorySize, bool Compressed, byte[] Data);

    public static string Analyze(string path, IEnumerable<ulong>? interestingOffsets = null, string moduleName = "main")
    {
        var file = File.ReadAllBytes(path);
        if (file.Length < 0x30 || Encoding.ASCII.GetString(file, 0, 4) != "NSO0")
            throw new InvalidDataException("Le fichier ne possède pas un en-tête NSO0 valide.");

        uint flags = U32(file, 0x0C);
        var output = new StringBuilder();
        output.AppendLine($"[NSO {moduleName}] {path}");
        output.AppendLine($"Taille fichier : {file.Length:N0} octets | Flags : 0x{flags:X8}");
        var segments = new List<Segment>();
        string[] names = ["text", "rodata", "data"];
        for (int i = 0; i < 3; i++)
        {
            int h = 0x10 + i * 0x10;
            uint fileOffset = U32(file, h);
            uint memoryOffset = U32(file, h + 4);
            uint memorySize = U32(file, h + 8);
            uint fileSize = U32(file, 0x60 + i * 4);
            bool compressed = (flags & (1u << i)) != 0;
            if ((ulong)fileOffset + fileSize > (ulong)file.Length)
                throw new InvalidDataException($"Segment {names[i]} hors du fichier.");
            var packed = file.AsSpan((int)fileOffset, (int)fileSize).ToArray();
            byte[] data;
            if (compressed)
            {
                data = new byte[memorySize];
                int decoded = LZ4Codec.Decode(packed, 0, packed.Length, data, 0, data.Length);
                if (decoded != data.Length)
                    throw new InvalidDataException($"Décompression LZ4 de {names[i]} incomplète : {decoded}/{data.Length} octets.");
            }
            else
            {
                data = packed;
                if (data.Length != memorySize)
                    output.AppendLine($"AVERTISSEMENT : {names[i]} non compressé, taille fichier ({data.Length}) différente de taille mémoire ({memorySize}).");
            }
            segments.Add(new Segment(names[i], fileOffset, memoryOffset, fileSize, memorySize, compressed, data));
            output.AppendLine($"Segment {names[i],-6} : fichier=0x{fileOffset:X} taille-fichier=0x{fileSize:X} mémoire=0x{memoryOffset:X} taille-mémoire=0x{memorySize:X} {(compressed ? "LZ4" : "non compressé")}");
        }

        output.AppendLine();
        output.AppendLine("Recherche de marqueurs connus de l'analyse allocateur :");
        (string Name, byte[] Bytes)[] markers =
        [
            ("Metadata live 0x17EA5678", [0x78, 0x56, 0xEA, 0x17]),
            ("Metadata freed 0x39431234", [0x34, 0x12, 0x43, 0x39]),
            ("Allocator global 0x94C008B0", [0xB0, 0x08, 0xC0, 0x94]),
            ("Manager base 0x09072210", [0x10, 0x22, 0x07, 0x09])
        ];
        foreach (var marker in markers)
        {
            var locations = new List<string>();
            foreach (var seg in segments)
            {
                int from = 0;
                while (from <= seg.Data.Length - marker.Bytes.Length)
                {
                    int at = seg.Data.AsSpan(from).IndexOf(marker.Bytes);
                    if (at < 0) break;
                    int offset = from + at;
                    locations.Add($"{seg.Name}+0x{offset:X} (module+0x{seg.MemoryOffset + (uint)offset:X})");
                    from = offset + 1;
                    if (locations.Count >= 12) break;
                }
            }
            output.AppendLine($"  {marker.Name} : {(locations.Count == 0 ? "non trouvé" : string.Join("; ", locations))}");
        }

        output.AppendLine();
        output.AppendLine($"[SYMBOLES / CHAÎNES — {moduleName}]");
        string[] needles =
        [
            "GetTlsValue", "AllocateTlsSlot", "FreeTlsSlot", "TlsManager",
            "SearchUnusedTlsSlotUnsafe", "SetZeroToAllThreadsTlsSafe",
            "InvokeTlsDestructors", "GetUsedTlsSlotCount", "ThreadManager"
        ];
        int symbolHits = 0;
        foreach (var seg in segments)
        {
            for (int i = 0; i < seg.Data.Length - 4; i++)
            {
                if (seg.Data[i] < 0x20 || seg.Data[i] > 0x7e) continue;
                int end = i;
                while (end < seg.Data.Length && end - i < 256 && seg.Data[end] >= 0x20 && seg.Data[end] <= 0x7e) end++;
                if (end - i >= 4)
                {
                    string candidate = Encoding.ASCII.GetString(seg.Data, i, end - i);
                    if (needles.Any(n => candidate.Contains(n, StringComparison.OrdinalIgnoreCase)))
                    {
                        output.AppendLine($"  {seg.Name}+0x{i:X} (module+0x{seg.MemoryOffset + (uint)i:X}): {candidate}");
                        if (++symbolHits >= 80) break;
                    }
                    i = end;
                }
            }
            if (symbolHits >= 80) break;
        }
        if (symbolHits == 0) output.AppendLine("Aucune chaîne/symbole TLS lisible détecté dans les segments décompressés.");

        // Preserve caller-supplied priority: crash site, LR, then unwind frames.
        // Sorting here used to discard the most useful high offsets before Take(32).
        var offsets = (interestingOffsets ?? []).Distinct().Take(32).ToArray();
        if (offsets.Length > 0)
        {
            output.AppendLine();
            output.AppendLine("[FENÊTRES ARM64 — ADRESSES ${moduleName}+0x]");
            output.AppendLine("Dump des mots 32 bits et décodage des branches usuelles. Ce n'est pas un désassembleur complet.");
            foreach (var address in offsets)
            {
                var seg = segments.FirstOrDefault(s => address >= s.MemoryOffset && address + 4UL <= (ulong)s.MemoryOffset + (ulong)s.Data.Length);
                if (seg is null) { output.AppendLine($"{moduleName}+0x{address:X} : hors des segments chargés."); continue; }
                int at = checked((int)(address - seg.MemoryOffset));
                output.AppendLine();
                output.AppendLine($"-- {seg.Name} autour de main+0x{address:X} --");
                int start = Math.Max(0, at - 16 * 4);
                int end = Math.Min(seg.Data.Length - 4, at + 8 * 4);
                start &= ~3;
                for (int p = start; p <= end; p += 4)
                {
                    uint word = U32(seg.Data, p);
                    ulong pc = (ulong)seg.MemoryOffset + (uint)p;
                    output.AppendLine($"{(p == at ? ">>" : "  ")} {moduleName}+0x{pc:X}: {word:X8}  {Decode(word, pc)}");
                }
            }
        }
        output.AppendLine();
        output.AppendLine("Cette recherche de marqueurs est une recherche d'octets bruts : une valeur trouvée peut être une donnée ou une constante. Les fenêtres ARM64 sont limitées aux offsets main+0x du log.");
        return output.ToString();
    }

    private static string Decode(uint w, ulong pc)
    {
        if ((w & 0xFC000000) == 0x94000000) return $"BL 0x{unchecked((long)pc + SignExtend(w & 0x03FFFFFF, 26) * 4):X}";
        if ((w & 0xFC000000) == 0x14000000) return $"B 0x{unchecked((long)pc + SignExtend(w & 0x03FFFFFF, 26) * 4):X}";
        if ((w & 0xFFFFFC1F) == 0xD63F0000) return $"BLR X{(w >> 5) & 31}";
        if ((w & 0xFFFFFC1F) == 0xD61F0000) return $"BR X{(w >> 5) & 31}";
        if ((w & 0xFFFFFC1F) == 0xD65F0000) return $"RET X{(w >> 5) & 31}";
        if ((w & 0x9F000000) == 0x90000000) return "ADRP (adresse de page)";
        if ((w & 0x7F000000) == 0x11000000) return "ADD/SUB immédiat";
        if ((w & 0x3B000000) == 0x39000000) return "LDR/STR unsigned offset";
        if ((w & 0x7F200000) == 0x0B000000) return "ADD/SUB registre";
        if ((w & 0x7F000000) == 0x51000000) return "SUB immédiat";
        return "instruction ARM64 (décodage non implémenté)";
    }

    private static long SignExtend(uint value, int bits) => unchecked((int)(value << (32 - bits))) >> (32 - bits);
    private static uint U32(byte[] data, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
}
