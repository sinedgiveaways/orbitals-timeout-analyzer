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
    private const uint ModuleListStream = 4;
    private const ulong SuspectIatSlot = 0x7FF6CA527650;

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
        uint exceptionRva = 0, exceptionSize = 0, memoryRva = 0, memorySize = 0, moduleRva = 0, moduleSize = 0;
        for (uint i = 0; i < streamCount; i++)
        {
            long entry = (long)directoryRva + i * 12L;
            uint type = ReadU32(br, entry);
            uint size = ReadU32(br, entry + 4);
            uint rva = ReadU32(br, entry + 8);
            if ((ulong)rva + size > (ulong)fs.Length) continue;
            if (type == ExceptionStream) { exceptionRva = rva; exceptionSize = size; }
            if (type == Memory64ListStream) { memoryRva = rva; memorySize = size; }
            if (type == ModuleListStream) { moduleRva = rva; moduleSize = size; }
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
        output.AppendLine("[MODULES WINDOWS / SLOT INDIRECT CRASH C]");
        bool suspectModuleFound = false;
        if (moduleRva != 0 && moduleSize >= 4)
        {
            uint moduleCount = ReadU32(br, moduleRva);
            if (moduleCount <= 100000 && 4UL + (ulong)moduleCount * 108UL <= moduleSize)
            {
                output.AppendLine($"ModuleList : {moduleCount} modules");
                for (uint i = 0; i < moduleCount; i++)
                {
                    long m = (long)moduleRva + 4L + i * 108L;
                    ulong imageBase = ReadU64(br, m);
                    uint imageSize = ReadU32(br, m + 8);
                    uint nameRva = ReadU32(br, m + 20);
                    string moduleName = ReadMinidumpString(br, nameRva, fs.Length);
                    if (SuspectIatSlot < imageBase || SuspectIatSlot - imageBase >= imageSize) continue;
                    suspectModuleFound = true;
                    ulong slotRva = SuspectIatSlot - imageBase;
                    output.AppendLine($"Slot 0x{SuspectIatSlot:X} appartient à {moduleName}");
                    output.AppendLine($"  ImageBase=0x{imageBase:X} | SizeOfImage=0x{imageSize:X} | RVA slot=0x{slotRva:X}");
                    var slotValue = ReadQword(SuspectIatSlot);
                    output.AppendLine(slotValue.HasValue
                        ? $"  Valeur capturée du slot : 0x{slotValue.Value:X}"
                        : "  Valeur du slot : non capturée dans Memory64List");
                    AnalyzePeSlot(output, ReadMemory, imageBase, imageSize, slotRva);
                }
            }
            else output.AppendLine("ModuleList présent mais taille/compte invalide.");
        }
        else output.AppendLine("ModuleList absent : impossible d'associer le slot à un module.");
        if (!suspectModuleFound)
            output.AppendLine($"Aucun module déclaré dans le dump ne contient 0x{SuspectIatSlot:X}.");

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


    private static string ReadMinidumpString(BinaryReader br, uint rva, long fileLength)
    {
        if (rva == 0 || (ulong)rva + 4 > (ulong)fileLength) return "<nom indisponible>";
        uint byteLength = ReadU32(br, rva);
        if (byteLength > 32768 || (ulong)rva + 4UL + byteLength > (ulong)fileLength || (byteLength & 1) != 0)
            return "<nom invalide>";
        br.BaseStream.Position = (long)rva + 4;
        return Encoding.Unicode.GetString(br.ReadBytes((int)byteLength)).TrimEnd('\0');
    }

    private static void AnalyzePeSlot(StringBuilder output, Func<ulong, int, byte[]?> read,
        ulong imageBase, uint imageSize, ulong slotRva)
    {
        byte[]? dos = read(imageBase, 64);
        if (dos is null || dos[0] != (byte)'M' || dos[1] != (byte)'Z')
        {
            output.AppendLine("  En-têtes PE DOS non capturés ou invalides : import non résolu.");
            return;
        }
        uint peOffset = BitConverter.ToUInt32(dos, 0x3C);
        if (peOffset > 0x100000 || peOffset + 24UL > imageSize)
        {
            output.AppendLine("  e_lfanew PE invalide.");
            return;
        }
        byte[]? nt = read(imageBase + peOffset, 24);
        if (nt is null || nt[0] != (byte)'P' || nt[1] != (byte)'E' || nt[2] != 0 || nt[3] != 0)
        {
            output.AppendLine("  En-têtes NT PE non capturés ou invalides.");
            return;
        }
        ushort optionalSize = BitConverter.ToUInt16(nt, 20);
        byte[]? opt = read(imageBase + peOffset + 24, Math.Min(optionalSize, (ushort)240));
        if (opt is null || opt.Length < 224 || BitConverter.ToUInt16(opt, 0) != 0x20B)
        {
            output.AppendLine("  Optional Header PE32+ non capturé ou non AMD64.");
            return;
        }
        uint importRva = BitConverter.ToUInt32(opt, 120);
        uint importSize = BitConverter.ToUInt32(opt, 124);
        uint iatRva = BitConverter.ToUInt32(opt, 208);
        uint iatSize = BitConverter.ToUInt32(opt, 212);
        output.AppendLine($"  PE32+ : ImportDirectory RVA=0x{importRva:X}/0x{importSize:X} | IAT RVA=0x{iatRva:X}/0x{iatSize:X}");
        if (slotRva >= iatRva && slotRva - iatRva < iatSize)
            output.AppendLine($"  Le slot tombe dans la plage IAT déclarée (index {(slotRva - iatRva) / 8}, décalage {(slotRva - iatRva) % 8}).");
        else
            output.AppendLine("  Le slot ne tombe pas dans la plage IAT déclarée du PE (ou la plage IAT est absente).");
        if (importRva == 0 || importSize < 20 || importRva >= imageSize)
        {
            output.AppendLine("  Import Directory absente/invalide : nom de fonction non résolu.");
            return;
        }

        bool found = false;
        uint maxDescriptors = Math.Min(importSize / 20, 4096u);
        for (uint d = 0; d < maxDescriptors; d++)
        {
            byte[]? desc = read(imageBase + importRva + d * 20UL, 20);
            if (desc is null) { output.AppendLine("  Descripteurs d'import non capturés dans le dump."); break; }
            uint originalThunk = BitConverter.ToUInt32(desc, 0);
            uint nameRva = BitConverter.ToUInt32(desc, 12);
            uint firstThunk = BitConverter.ToUInt32(desc, 16);
            if (originalThunk == 0 && nameRva == 0 && firstThunk == 0) break;
            string dll = ReadAsciiZ(read, imageBase + nameRva, 260) ?? "<DLL non capturée>";
            if (firstThunk == 0 || firstThunk >= imageSize) continue;
            ulong thunkBase = imageBase + (originalThunk != 0 ? originalThunk : firstThunk);
            for (uint n = 0; n < 65536; n++)
            {
                ulong entryRva = (ulong)firstThunk + n * 8UL;
                if (entryRva + 8 > imageSize) break;
                byte[]? thunkBytes = read(thunkBase + n * 8UL, 8);
                if (thunkBytes is null) break;
                ulong thunk = BitConverter.ToUInt64(thunkBytes, 0);
                if (thunk == 0) break;
                if (entryRva != slotRva) continue;
                found = true;
                const ulong OrdinalFlag64 = 0x8000000000000000;
                if ((thunk & OrdinalFlag64) != 0)
                    output.AppendLine($"  IMPORT IDENTIFIÉ : {dll}!ordinal #{thunk & 0xFFFF}");
                else if (thunk <= uint.MaxValue)
                {
                    string? function = ReadAsciiZ(read, imageBase + thunk + 2, 512);
                    output.AppendLine($"  IMPORT IDENTIFIÉ : {dll}!{function ?? "<nom non capturé>"}");
                }
                else output.AppendLine($"  IAT correspond à {dll}, thunk original hors RVA : 0x{thunk:X}");
                break;
            }
            if (found) break;
        }
        if (!found)
            output.AppendLine("  Aucune entrée d'import ne correspond exactement au slot (import data absente/partielle, slot non-IAT, ou table atypique).");
    }

    private static string? ReadAsciiZ(Func<ulong, int, byte[]?> read, ulong address, int maxLength)
    {
        var bytes = read(address, maxLength);
        if (bytes is null) return null;
        int end = Array.IndexOf(bytes, (byte)0);
        if (end < 0) end = bytes.Length;
        return Encoding.ASCII.GetString(bytes, 0, end);
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
