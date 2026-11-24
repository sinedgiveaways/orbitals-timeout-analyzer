using System.Text;

namespace OrbitalsCrashAnalyzer.Analysis;

/// <summary>
/// Reads Windows MINIDUMP streams without loading the dump into RAM.
/// Supports large Memory64List dumps (including multi-gigabyte WER dumps).
/// </summary>
public static class WerMinidumpAnalyzer
{
    private const uint Signature = 0x504D444D; // MDMP
    private const uint ExceptionStream = 6;
    private const uint Memory64ListStream = 9;

    private sealed record MemoryRange(ulong Start, ulong Size, ulong FileOffset);

    public static string Analyze(string path)
    {
        var output = new StringBuilder();
        output.AppendLine("[WER MINIDUMP — ANALYSE AUTOMATIQUE]");
        output.AppendLine($"Fichier : {path}");
        var info = new FileInfo(path);
        output.AppendLine($"Taille : {info.Length:N0} octets ({info.Length / 1024d / 1024d / 1024d:F2} Gio)");

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 16, FileOptions.RandomAccess);
        using var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);
        if (fs.Length < 32 || ReadU32(br, 0) != Signature)
            throw new InvalidDataException("Signature MDMP absente ou fichier trop court.");

        uint streamCount = ReadU32(br, 8);
        uint directoryRva = ReadU32(br, 12);
        if (streamCount > 100000 || (ulong)directoryRva + (ulong)streamCount * 12 > (ulong)fs.Length)
            throw new InvalidDataException("Répertoire des streams minidump invalide.");

        output.AppendLine($"Streams : {streamCount} | répertoire : 0x{directoryRva:X}");
        uint exceptionRva = 0, exceptionSize = 0, memoryRva = 0, memorySize = 0;
        for (uint i = 0; i < streamCount; i++)
        {
            long entry = (long)directoryRva + i * 12L;
            uint type = ReadU32(br, entry);
            uint size = ReadU32(br, entry + 4);
            uint rva = ReadU32(br, entry + 8);
            if ((ulong)rva + size > (ulong)fs.Length) continue;
            if (type == ExceptionStream) { exceptionRva = rva; exceptionSize = size; }
            if (type == Memory64ListStream) { memoryRva = rva; memorySize = size; }
        }

        var ranges = new List<MemoryRange>();
        if (memoryRva != 0 && memorySize >= 16)
        {
            ulong count = ReadU64(br, memoryRva);
            ulong baseRva = ReadU64(br, memoryRva + 8);
            if (count > 2_000_000 || 16UL + count * 16UL > memorySize)
                throw new InvalidDataException("Memory64List invalide ou trop volumineuse.");
            ulong fileOffset = baseRva;
            for (ulong i = 0; i < count; i++)
            {
                long d = (long)memoryRva + 16L + (long)i * 16L;
                ulong start = ReadU64(br, d);
                ulong size = ReadU64(br, d + 8);
                if (size == 0) continue;
                if (fileOffset <= long.MaxValue && size <= (ulong)fs.Length && fileOffset + size <= (ulong)fs.Length)
                    ranges.Add(new MemoryRange(start, size, fileOffset));
                fileOffset = checked(fileOffset + size);
            }
            output.AppendLine($"Memory64List : {ranges.Count:N0} plages exploitables (RVA données 0x{baseRva:X})");
        }
        else output.AppendLine("Memory64List : absent — lecture mémoire virtuelle impossible.");

        byte[]? ReadMemory(ulong address, int length)
        {
            if (length < 0 || length > 1_048_576) return null;
            foreach (var range in ranges)
            {
                if (address < range.Start) continue;
                ulong delta = address - range.Start;
                if (delta > range.Size || (ulong)length > range.Size - delta) continue;
                ulong offset = range.FileOffset + delta;
                if (offset > long.MaxValue || offset + (ulong)length > (ulong)fs.Length) return null;
                fs.Position = (long)offset;
                var bytes = br.ReadBytes(length);
                return bytes.Length == length ? bytes : null;
            }
            return null;
        }

        ulong? ReadQword(ulong address)
        {
            var b = ReadMemory(address, 8);
            return b is null ? null : BitConverter.ToUInt64(b, 0);
        }

        output.AppendLine();
        output.AppendLine("[EXCEPTION / CONTEXTE HÔTE]");
        if (exceptionRva != 0 && exceptionSize >= 168)
        {
            uint threadId = ReadU32(br, exceptionRva);
            long er = (long)exceptionRva + 8;
            uint code = ReadU32(br, er);
            uint flags = ReadU32(br, er + 4);
            ulong exceptionAddress = ReadU64(br, er + 16);
            uint parameterCount = Math.Min(ReadU32(br, er + 24), 15u);
            output.AppendLine($"Thread ID : 0x{threadId:X}");
            output.AppendLine($"Exception : 0x{code:X8} | flags=0x{flags:X8} | adresse=0x{exceptionAddress:X}");
            output.AppendLine($"Paramètres : {parameterCount}");
            for (uint i = 0; i < parameterCount; i++)
                output.AppendLine($"  ExceptionInformation[{i}] = 0x{ReadU64(br, er + 32 + i * 8L):X}");

            uint contextRva = ReadU32(br, (long)exceptionRva + 164);
            if (contextRva != 0 && (ulong)contextRva + 256 <= (ulong)fs.Length)
            {
                // AMD64 CONTEXT: general registers begin at +120; RIP at +248.
                ulong rax = ReadU64(br, contextRva + 120L);
                ulong rcx = ReadU64(br, contextRva + 128L);
                ulong rdx = ReadU64(br, contextRva + 136L);
                ulong rbx = ReadU64(br, contextRva + 144L);
                ulong rsp = ReadU64(br, contextRva + 152L);
                ulong rbp = ReadU64(br, contextRva + 160L);
                ulong rsi = ReadU64(br, contextRva + 168L);
                ulong rdi = ReadU64(br, contextRva + 176L);
                ulong r8 = ReadU64(br, contextRva + 184L);
                ulong r9 = ReadU64(br, contextRva + 192L);
                ulong r10 = ReadU64(br, contextRva + 200L);
                ulong r11 = ReadU64(br, contextRva + 208L);
                ulong r12 = ReadU64(br, contextRva + 216L);
                ulong r13 = ReadU64(br, contextRva + 224L);
                ulong r14 = ReadU64(br, contextRva + 232L);
                ulong r15 = ReadU64(br, contextRva + 240L);
                ulong rip = ReadU64(br, contextRva + 248L);
                output.AppendLine($"RIP=0x{rip:X} | RSP=0x{rsp:X} | RBP=0x{rbp:X}");
                output.AppendLine($"RAX=0x{rax:X} RCX=0x{rcx:X} RDX=0x{rdx:X} RBX=0x{rbx:X}");
                output.AppendLine($"RSI=0x{rsi:X} RDI=0x{rdi:X} R8=0x{r8:X} R9=0x{r9:X}");
                output.AppendLine($"R10=0x{r10:X} R11=0x{r11:X} R12=0x{r12:X} R13=0x{r13:X} R14=0x{r14:X} R15=0x{r15:X}");
                var codeBytes = ReadMemory(rip, 32);
                output.AppendLine(codeBytes is null
                    ? "Octets à RIP : absents des plages capturées."
                    : "Octets à RIP : " + Convert.ToHexString(codeBytes));
                output.AppendLine($"RIP relatif à ucrtbase.dll (si base 0x7FFB2D3C0000) : 0x{rip - 0x7FFB2D3C0000:X}");
            }
            else output.AppendLine("Contexte CPU AMD64 absent ou RVA invalide.");
        }
        else output.AppendLine("ExceptionStream absent.");

        output.AppendLine();
        output.AppendLine("[OBJETS / ADRESSES DE L'ENQUÊTE CRASH C]");
        DumpBytes(output, ReadMemory, 0x1C92EAB0540, 0x40, "Structure de paramètres présumée");
        DumpBytes(output, ReadMemory, 0x700900A008, 0x40, "Objet/vtable observé précédemment");
        var vtable = ReadQword(0x700900A008);
        if (vtable.HasValue)
        {
            output.AppendLine($"Vtable lue à 0x700900A008 : 0x{vtable.Value:X}");
            foreach (ulong slot in new ulong[] { 0xA0, 0xA8 })
            {
                var target = ReadQword(vtable.Value + slot);
                output.AppendLine(target.HasValue
                    ? $"  vtable+0x{slot:X} = 0x{target.Value:X}"
                    : $"  vtable+0x{slot:X} : non capturé");
                if (target.HasValue) DumpBytes(output, ReadMemory, target.Value, 64, $"Code candidat vtable+0x{slot:X}");
            }
        }
        else output.AppendLine("Objet 0x700900A008 : non capturé.");

        output.AppendLine();
        output.AppendLine("[COUVERTURE DES ADRESSES]");
        foreach (ulong address in new ulong[] { 0x01460149013D0140, 0x12E1A8000C, 0x700A166CB0, 0x700A7AEF80 })
        {
            var range = ranges.FirstOrDefault(r => address >= r.Start && address - r.Start < r.Size);
            output.AppendLine(range is null
                ? $"0x{address:X} : aucune plage Memory64List ne couvre cette adresse (non concluant si dump incomplet)."
                : $"0x{address:X} : couverte par [0x{range.Start:X}, 0x{range.Start + range.Size:X})");
        }
        output.AppendLine("Les adresses absentes du dump ne sont pas automatiquement considérées invalides : la capture peut être partielle.");
        return output.ToString();
    }

    private static void DumpBytes(StringBuilder output, Func<ulong, int, byte[]?> read, ulong address, int length, string label)
    {
        var bytes = read(address, length);
        output.AppendLine(bytes is null
            ? $"{label} @ 0x{address:X} : non capturé / plage insuffisante."
            : $"{label} @ 0x{address:X} : {Convert.ToHexString(bytes)}");
    }

    private static uint ReadU32(BinaryReader br, long offset)
    {
        br.BaseStream.Position = offset;
        return br.ReadUInt32();
    }

    private static ulong ReadU64(BinaryReader br, long offset)
    {
        br.BaseStream.Position = offset;
        return br.ReadUInt64();
    }
}
