using System.Text;

namespace OrbitalsCrashAnalyzer.Analysis;

/// <summary>
/// Reads Windows MINIDUMP streams without loading the dump into RAM.
/// Supports large Memory64List dumps (including multi-gigabyte WER dumps).
/// </summary>
public static class WerMinidumpAnalyzer
{
    private const uint Signature = 0x504D444D; // MDMP
    private const uint ThreadListStream = 3;
    private const uint ModuleListStream = 4;
    private const uint MemoryListStream = 5;
    private const uint ExceptionStream = 6;
    private const uint Memory64ListStream = 9;
    private const ulong SuspectIatSlot = 0x7FF6CA527650;

    private sealed record MemoryRange(ulong Start, ulong Size, ulong FileOffset);
    private sealed record ModuleRange(ulong Base, uint Size, string Name);

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
        uint exceptionRva = 0, exceptionSize = 0, memoryRva = 0, memorySize = 0, moduleRva = 0, moduleSize = 0, threadRva = 0, threadSize = 0, memoryListRva = 0, memoryListSize = 0;
        for (uint i = 0; i < streamCount; i++)
        {
            long entry = (long)directoryRva + i * 12L;
            uint type = ReadU32(br, entry);
            uint size = ReadU32(br, entry + 4);
            uint rva = ReadU32(br, entry + 8);
            if ((ulong)rva + size > (ulong)fs.Length) continue;
            if (type == ThreadListStream) { threadRva = rva; threadSize = size; }
            if (type == MemoryListStream) { memoryListRva = rva; memoryListSize = size; }
            if (type == ExceptionStream) { exceptionRva = rva; exceptionSize = size; }
            if (type == Memory64ListStream) { memoryRva = rva; memorySize = size; }
            if (type == ModuleListStream) { moduleRva = rva; moduleSize = size; }
        }

        var ranges = new List<MemoryRange>();
        var modules = new List<ModuleRange>();
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

        // MemoryListStream (type 5) uses per-range RVAs, separate from Memory64List.
        if (memoryListRva != 0 && memoryListSize >= 4)
        {
            uint count = ReadU32(br, memoryListRva);
            if (count <= 2_000_000 && 4UL + (ulong)count * 16UL <= memoryListSize)
            {
                int added = 0;
                for (uint i = 0; i < count; i++)
                {
                    long d = (long)memoryListRva + 4L + i * 16L;
                    ulong start = ReadU64(br, d);
                    uint size = ReadU32(br, d + 8);
                    uint dataRva = ReadU32(br, d + 12);
                    if (size == 0 || (ulong)dataRva + size > (ulong)fs.Length) continue;
                    ranges.Add(new MemoryRange(start, size, dataRva));
                    added++;
                }
                output.AppendLine($"MemoryList : {added:N0} plages supplémentaires.");
            }
            else output.AppendLine("MemoryList présent mais compte/taille invalide.");
        }

        // A thread's stack is described directly by MINIDUMP_THREAD.Stack.
        if (threadRva != 0 && threadSize >= 4)
        {
            uint count = ReadU32(br, threadRva);
            if (count <= 100_000 && 4UL + (ulong)count * 48UL <= threadSize)
            {
                output.AppendLine($"ThreadList : {count} threads");
                for (uint i = 0; i < count; i++)
                {
                    long t = (long)threadRva + 4L + i * 48L;
                    uint id = ReadU32(br, t);
                    // MINIDUMP_THREAD layout: Teb at +16, Stack descriptor at +24.
                    // MINIDUMP_MEMORY_DESCRIPTOR = StartOfMemoryRange (+24), DataSize (+32), Rva (+36).
                    ulong stackStart = ReadU64(br, t + 24);
                    uint stackSize = ReadU32(br, t + 32);
                    uint stackDataRva = ReadU32(br, t + 36);
                    if (stackSize > 0 && (ulong)stackDataRva + stackSize <= (ulong)fs.Length)
                    {
                        // Add explicit thread stack mapping even if it was not in Memory64List.
                        ranges.Add(new MemoryRange(stackStart, stackSize, stackDataRva));
                        output.AppendLine($"  Thread 0x{id:X}: pile [0x{stackStart:X}, 0x{stackStart + stackSize:X}) ({stackSize:N0} octets){(id == (exceptionRva != 0 ? ReadU32(br, exceptionRva) : 0) ? " — thread fautif" : "")}");
                    }
                    else if (id == (exceptionRva != 0 ? ReadU32(br, exceptionRva) : 0))
                        output.AppendLine($"  Thread fautif 0x{id:X}: descripteur de pile vide/non capturé.");
                }
            }
            else output.AppendLine("ThreadList présent mais compte/taille invalide.");
        }

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
                    modules.Add(new ModuleRange(imageBase, imageSize, moduleName));
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
                AnalyzeStackCandidates(output, ReadMemory, rsp, modules);
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



    private static void AnalyzeStackCandidates(StringBuilder output, Func<ulong, int, byte[]?> read,
        ulong rsp, IReadOnlyList<ModuleRange> modules)
    {
        output.AppendLine();
        output.AppendLine("[PILE HÔTE — CANDIDATS D'ADRESSES DE RETOUR]");
        const int before = 0x100;
        const int after = 0x2000;
        if (rsp < before)
        {
            output.AppendLine("RSP trop bas pour lire la fenêtre de pile.");
            return;
        }

        ulong start = rsp - before;
        byte[]? stack = read(start, before + after);
        if (stack is null)
        {
            output.AppendLine($"Fenêtre de pile non capturée : [0x{start:X}, 0x{start + before + after:X}).");
            return;
        }

        output.AppendLine($"Fenêtre brute : [0x{start:X}, 0x{start + (ulong)stack.Length:X}) | RSP à +0x{before:X}");
        int found = 0;
        for (int offset = 0; offset <= stack.Length - 8; offset += 8)
        {
            ulong value = BitConverter.ToUInt64(stack, offset);
            foreach (var module in modules)
            {
                if (value < module.Base || value - module.Base >= module.Size) continue;
                output.AppendLine($"  pile+0x{offset:X} (0x{start + (ulong)offset:X}) = 0x{value:X} -> {module.Name}+0x{value - module.Base:X}");
                found++;
                break;
            }
            if (found >= 96)
            {
                output.AppendLine("  Limite de 96 candidats atteinte.");
                break;
            }
        }

        if (found == 0)
            output.AppendLine("Aucune valeur de la fenêtre ne pointe dans un module déclaré.");
        output.AppendLine($"Candidats trouvés : {found}. Ce balayage brut ne constitue pas un unwind x64 : certains pointeurs peuvent être des données, pas des adresses de retour.");
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
        uint relocRva = BitConverter.ToUInt32(opt, 152);
        uint relocSize = BitConverter.ToUInt32(opt, 156);
        ushort sectionCount = BitConverter.ToUInt16(nt, 6);
        output.AppendLine($"  PE32+ : ImportDirectory RVA=0x{importRva:X}/0x{importSize:X} | IAT RVA=0x{iatRva:X}/0x{iatSize:X}");
        output.AppendLine($"  BaseRelocationDirectory RVA=0x{relocRva:X}/0x{relocSize:X} | sections={sectionCount}");

        bool slotSectionFound = false;
        ulong sectionTableAddress = imageBase + peOffset + 24UL + optionalSize;
        for (uint sectionIndex = 0; sectionIndex < sectionCount && sectionIndex < 96; sectionIndex++)
        {
            byte[]? section = read(sectionTableAddress + sectionIndex * 40UL, 40);
            if (section is null) { output.AppendLine("  Section headers non capturés."); break; }
            string sectionName = Encoding.ASCII.GetString(section, 0, 8).TrimEnd('\0');
            uint virtualSize = BitConverter.ToUInt32(section, 8);
            uint virtualAddress = BitConverter.ToUInt32(section, 12);
            uint rawSize = BitConverter.ToUInt32(section, 16);
            uint rawPointer = BitConverter.ToUInt32(section, 20);
            uint characteristics = BitConverter.ToUInt32(section, 36);
            ulong span = Math.Max(virtualSize, rawSize);
            if (slotRva >= virtualAddress && (ulong)slotRva < (ulong)virtualAddress + span)
            {
                slotSectionFound = true;
                output.AppendLine($"  SECTION DU SLOT : {sectionName} | RVA=0x{virtualAddress:X} | VirtualSize=0x{virtualSize:X} | RawSize=0x{rawSize:X} | RawPtr=0x{rawPointer:X} | Characteristics=0x{characteristics:X}");
                output.AppendLine($"    Writable={(characteristics & 0x80000000) != 0} Executable={(characteristics & 0x20000000) != 0} Readable={(characteristics & 0x40000000) != 0}");
            }
        }
        if (!slotSectionFound) output.AppendLine("  Aucune section PE ne couvre le RVA du slot (headers absents ou image atypique).");
        DumpBytes(output, read, imageBase + slotRva, 32, "Octets autour du slot");

        if (relocRva != 0 && relocSize >= 8 && relocRva < imageSize)
        {
            bool relocFound = false;
            ulong cursor = 0;
            uint blocks = 0;
            while (cursor + 8 <= relocSize && blocks++ < 100000)
            {
                byte[]? block = read(imageBase + relocRva + cursor, 8);
                if (block is null) { output.AppendLine("  Table de relocations partiellement/non capturée."); break; }
                uint pageRva = BitConverter.ToUInt32(block, 0);
                uint blockSize = BitConverter.ToUInt32(block, 4);
                if (pageRva == 0 && blockSize == 0) break;
                if (blockSize < 8 || (blockSize & 1) != 0 || cursor + blockSize > relocSize) break;
                uint entries = (blockSize - 8) / 2;
                for (uint e = 0; e < entries; e++)
                {
                    byte[]? entryBytes = read(imageBase + relocRva + cursor + 8UL + e * 2UL, 2);
                    if (entryBytes is null) break;
                    ushort entry = BitConverter.ToUInt16(entryBytes, 0);
                    ushort type = (ushort)(entry >> 12);
                    uint targetRva = pageRva + (uint)(entry & 0x0FFF);
                    if (targetRva == slotRva)
                    {
                        relocFound = true;
                        output.AppendLine($"  RELOCATION DU SLOT : type={type} ({(type == 10 ? "IMAGE_REL_BASED_DIR64" : type == 0 ? "ABSOLUTE" : "autre")}) target RVA=0x{targetRva:X}");
                    }
                }
                cursor += blockSize;
            }
            if (!relocFound) output.AppendLine("  Aucune relocation de base ne cible exactement ce slot.");
        }
        else output.AppendLine("  Répertoire de relocations absent/invalide.");
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
