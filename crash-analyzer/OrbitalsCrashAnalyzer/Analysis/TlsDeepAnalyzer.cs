using System.Buffers.Binary;
using System.Text;
using K4os.Compression.LZ4;

namespace OrbitalsCrashAnalyzer.Analysis;

public static class TlsDeepAnalyzer
{
    private sealed record Seg(string Name, uint Mem, byte[] Data);

    public static string Analyze(string? mainPath, string? sdkPath, string? logText = null)
    {
        var b = new StringBuilder();
        b.AppendLine("========== ANALYSE TLS APPROFONDIE 0.5.0 ==========");
        b.AppendLine("Objectif : départager les quatre questions du dossier Crash B à partir des binaires.");
        b.AppendLine("Cette analyse est statique : elle ne prétend pas connaître les registres hôtes au moment exact de l'exception.");
        List<Seg>? main = null, sdk = null;
        if (!string.IsNullOrWhiteSpace(mainPath)) main = Load(mainPath);
        if (!string.IsNullOrWhiteSpace(sdkPath)) sdk = Load(sdkPath);

        if (main is not null)
        {
            b.AppendLine();
            b.AppendLine("[A] MAIN : SITE D'APPEL ET FONCTION FAUTIVE");
            Dump(main, 0x1750B84, 0xC0, 0x30, "BL connu vers main+0x1759B20 / préparation des arguments", b);
            b.AppendLine();
            b.AppendLine("[A1] Dernière définition statique de x0-x7 avant main+0x1750B84");
            TraceArguments(main, 0x1750B84, b);
            b.AppendLine();
            b.AppendLine("[A2] Fonction appelée main+0x1759B20 — fenêtre élargie");
            Dump(main, 0x1759B20, 0x100, 0x180, "fonction levée associée au PC hôte", b);
            b.AppendLine();
            b.AppendLine("[A3] Appels directs vers main+0x1759B20");
            FindBranches(main, 0x1759B20, b);
            b.AppendLine();
            b.AppendLine("[A4] Références au global TLS main+0x8FF78F8 et à sa cellule main+0x90100F8");
            FindAddressReferences(main, [0x8FF78F8, 0x90100F8], b);
        }
        else b.AppendLine("\n[MAIN] Non fourni : impossible de lire les instructions et d'établir les définitions de registres.");

        if (sdk is not null)
        {
            b.AppendLine();
            b.AppendLine("[B] SDK : GETTLSVALUE ET GESTIONNAIRE TLS");
            foreach (var off in new ulong[] { 0x16B670, 0x16B730, 0x16C520, 0x16C7B0, 0x16CC30, 0x16C3A0, 0x16E820, 0x16EF90 })
                Dump(sdk, off, 0x30, 0x50, $"SDK+0x{off:X}", b);
            b.AppendLine();
            b.AppendLine("[B1] Références directes à GetTlsValue / AllocateTlsSlot");
            FindBranches(sdk, 0x16B730, b);
            FindBranches(sdk, 0x16B670, b);
        }
        else b.AppendLine("\n[SDK] Non fourni : les chemins internes du SDK ne peuvent pas être confirmés dans ce passage.");

        b.AppendLine();
        AppendRuntimeEvidence(logText, b);

        b.AppendLine();
        b.AppendLine("[RÉPONSES AUX QUESTIONS]");
        b.AppendLine("1. Valeur réelle de TlsSlot (w0) au crash : NON DÉMONTRABLE par les seuls binaires. La section A1 donne les dernières définitions statiques de x0-x7 au site main+0x1750B84, mais ce site appelle main+0x1759B20, pas directement GetTlsValue. Les valeurs peuvent dépendre de mémoire et de chemins d'exécution.");
        b.AppendLine("2. Objet thread et couverture du tableau TLS : le binaire permet de vérifier les offsets d'accès, pas l'objet réellement pointé par TPIDRRO_EL0 au crash. Il faut les valeurs runtime déjà journalisées ou une instrumentation ciblée.");
        b.AppendLine("3. Base nulle côté invité ou introduite par la traduction hôte : le code ARM64 permet de localiser la chaîne d'accès invitée. Sans registres hôtes RCX/R8 et sans état invité synchronisé à l'instruction fautive, cette distinction reste ouverte.");
        b.AppendLine("4. Slot invalide avant l'appel ou corruption antérieure : une lecture statique peut révéler les validations et écritures visibles, mais ne prouve pas l'état mémoire au moment de l'exécution.");
        b.AppendLine();
        b.AppendLine("[CE QUE CETTE VERSION APPORTE]");
        b.AppendLine("- Fenêtres ARM64 élargies et décodage des instructions usuelles autour du site d'appel et de la fonction fautive.");
        b.AppendLine("- Dernière définition de x0-x7 avant le BL connu, avec valeur constante uniquement si elle peut être suivie sans ambiguïté.");
        b.AppendLine("- Recherche des branches directes et références ADRP/ADD vers les globals TLS connus.");
        b.AppendLine("- Décodage des fonctions SDK TLS connues.");
        b.AppendLine();
        b.AppendLine("[CE QUI RESTE NÉCESSAIRE POUR UNE PREUVE DYNAMIQUE]");
        b.AppendLine("- À l'entrée de main+0x1759B20 : x0-x7, TPIDR_EL0, TPIDRRO_EL0 et adresse de l'objet thread.");
        b.AppendLine("- À l'instruction hôte fautive : RCX, R8, RDX, RAX et adresse effective calculée.");
        b.AppendLine("- Au point d'entrée réel de GetTlsValue : w0/TlsSlot et pointeurs après chaque chargement.");
        b.AppendLine("Aucune de ces valeurs hôtes ne sera inventée à partir des registres invités.");
        return b.ToString();
    }

    private static List<Seg> Load(string path)
    {
        var f = File.ReadAllBytes(path);
        if (f.Length < 0x64 || Encoding.ASCII.GetString(f, 0, 4) != "NSO0")
            throw new InvalidDataException($"NSO invalide : {path}");
        uint flags = U32(f, 0x0C);
        var list = new List<Seg>();
        string[] names = ["text", "rodata", "data"];
        for (int i = 0; i < 3; i++)
        {
            int h = 0x10 + i * 0x10;
            uint fo = U32(f, h), mo = U32(f, h + 4), ms = U32(f, h + 8), fs = U32(f, 0x60 + i * 4);
            if ((ulong)fo + fs > (ulong)f.Length || ms > 0x40000000) throw new InvalidDataException($"Segment NSO invalide : {names[i]}");
            var packed = f.AsSpan((int)fo, (int)fs).ToArray();
            byte[] data;
            if ((flags & (1u << i)) != 0)
            {
                data = new byte[checked((int)ms)];
                int n = LZ4Codec.Decode(packed, 0, packed.Length, data, 0, data.Length);
                if (n != data.Length) throw new InvalidDataException($"Décompression incomplète : {names[i]} ({n}/{data.Length})");
            }
            else data = packed;
            list.Add(new Seg(names[i], mo, data));
        }
        return list;
    }

    private static void Dump(List<Seg> segs, ulong address, int before, int after, string title, StringBuilder output)
    {
        output.AppendLine("-- " + title + " --");
        var s = segs.FirstOrDefault(x => address >= x.Mem && address < (ulong)x.Mem + (ulong)x.Data.Length);
        if (s is null) { output.AppendLine($"0x{address:X}: hors segments."); return; }
        long center = (long)(address - s.Mem);
        long start = Math.Max(0, center - before) & ~3L;
        long end = Math.Min(s.Data.Length - 4L, center + after) & ~3L;
        for (long p = start; p <= end; p += 4)
        {
            uint w = U32(s.Data, (int)p);
            ulong pc = (ulong)s.Mem + (ulong)p;
            string mark = pc == address ? ">>" : "  ";
            output.AppendLine($"{mark} {s.Name}+0x{pc:X}: {w:X8}  {Decode(w, pc)}");
        }
    }

    private static void TraceArguments(List<Seg> segs, ulong callPc, StringBuilder output)
    {
        var s = segs.FirstOrDefault(x => callPc >= x.Mem && callPc < (ulong)x.Mem + (ulong)x.Data.Length);
        if (s is null) { output.AppendLine("Site hors segments."); return; }
        int end = (int)(callPc - s.Mem);
        int start = Math.Max(0, end - 0x100) & ~3;
        var state = Enumerable.Range(0, 8).Select(_ => (Text: "aucune définition dans la fenêtre", Value: (ulong?)null)).ToArray();
        for (int p = start; p < end; p += 4)
        {
            uint w = U32(s.Data, p); ulong pc = (ulong)s.Mem + (uint)p;
            int rd = WrittenRegister(w);
            if (rd >= 0 && rd < 8)
            {
                ulong? value = ConstantValue(w, pc, state);
                state[rd] = ( $"{s.Name}+0x{pc:X}: {w:X8} {Decode(w, pc)}", value);
            }
        }
        output.AppendLine($"Fenêtre linéaire examinée : {s.Name}+0x{(ulong)s.Mem+(uint)start:X} à {s.Name}+0x{callPc-1:X}.");
        output.AppendLine("Attention : cette analyse ne suit pas les branches, les chargements mémoire ni les chemins alternatifs.");
        for (int i = 0; i < 8; i++)
            output.AppendLine($"x{i}: {state[i].Text}" + (state[i].Value.HasValue ? $" | constante suivie=0x{state[i].Value.Value:X}" : " | valeur inconnue/dépendante de l'exécution"));
        output.AppendLine("Le BL à main+0x1750B84 cible main+0x1759B20 selon le dossier ; il ne constitue pas en lui-même un appel direct à sdk+0x16B730.");
    }

    private static int WrittenRegister(uint w)
    {
        if ((w & 0x7F800000) == 0x52800000 || (w & 0x7F800000) == 0x72800000) return (int)(w & 31);
        if ((w & 0x1F000000) == 0x11000000) return (int)(w & 31);
        if ((w & 0x9F000000) == 0x90000000 || (w & 0x9F000000) == 0x10000000) return (int)(w & 31);
        if (((w & 0x3B000000) == 0x39000000 || (w & 0x3B200C00) == 0x38200800) && (w & (1u << 22)) != 0) return (int)(w & 31);
        if ((w & 0x1F200000) == 0x0B000000) return (int)(w & 31);
        if ((w & 0x7FE0FC00) == 0x2A000000) return (int)(w & 31);
        return -1;
    }

    private static ulong? ConstantValue(uint w, ulong pc, (string Text, ulong? Value)[] regs)
    {
        int rd = (int)(w & 31), rn = (int)((w >> 5) & 31), rm = (int)((w >> 16) & 31);
        // The trace intentionally tracks only x0-x7. Other registers, SP and XZR
        // are valid ARM64 operands but are not represented in this small state array.
        ulong? GetTracked(int register) => register >= 0 && register < regs.Length ? regs[register].Value : null;

        if ((w & 0x7F800000) == 0x52800000)
        {
            int shift = (int)((w >> 21) & 3) * 16;
            return ((ulong)((w >> 5) & 0xFFFF)) << shift;
        }
        if ((w & 0x7F800000) == 0x72800000 && GetTracked(rd) is ulong old)
        {
            int shift = (int)((w >> 21) & 3) * 16;
            ulong mask = 0xFFFFUL << shift;
            return (old & ~mask) | (((ulong)((w >> 5) & 0xFFFF)) << shift);
        }
        if ((w & 0x9F000000) == 0x90000000)
        {
            ulong imm = ((ulong)((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3);
            long signed = SignExtend((uint)imm, 21);
            return unchecked((ulong)((long)(pc & ~0xFFFUL) + (signed << 12)));
        }
        if ((w & 0x7F000000) == 0x11000000 && GetTracked(rn) is ulong baseValue)
        {
            ulong imm = (w >> 10) & 0xFFF;
            if ((w & (1u << 22)) != 0) imm <<= 12;
            return (w & (1u << 30)) != 0 ? baseValue - imm : baseValue + imm;
        }
        if ((w & 0x7FE0FC00) == 0x2A000000) return GetTracked(rm);
        return null;
    }

    private static void FindBranches(List<Seg> segs, ulong target, StringBuilder output)
    {
        int hits = 0;
        foreach (var s in segs)
            for (int p = 0; p <= s.Data.Length - 4; p += 4)
            {
                uint w = U32(s.Data, p);
                if ((w & 0xFC000000) != 0x94000000) continue;
                ulong pc = (ulong)s.Mem + (uint)p;
                ulong dest = unchecked((ulong)((long)pc + SignExtend(w & 0x03FFFFFF, 26) * 4));
                if (dest != target) continue;
                output.AppendLine($"BL trouvé : {s.Name}+0x{pc:X} -> +0x{dest:X}");
                if (++hits >= 100) break;
            }
        if (hits == 0) output.AppendLine("Aucun BL direct trouvé dans les segments décompressés. Un appel indirect/PLT reste possible.");
    }

    private static void FindAddressReferences(List<Seg> segs, ulong[] targets, StringBuilder output)
    {
        foreach (var target in targets)
        {
            int hits = 0;
            foreach (var s in segs)
                for (int p = 0; p <= s.Data.Length - 8; p += 4)
                {
                    uint a = U32(s.Data, p), n = U32(s.Data, p + 4);
                    if ((a & 0x9F000000) != 0x90000000) continue;
                    int rd = (int)(a & 31);
                    if ((n & 0xFF000000) != 0x91000000 || ((n >> 5) & 31) != rd || (n & 31) != rd) continue;
                    ulong imm21 = ((ulong)((a >> 5) & 0x7FFFF) << 2) | ((a >> 29) & 3);
                    long page = ((long)(s.Mem + (uint)p) & ~0xFFFL) + (SignExtend((uint)imm21, 21) << 12);
                    ulong low = (n >> 10) & 0xFFF;
                    ulong resolved = unchecked((ulong)page + low);
                    if (resolved != target) continue;
                    output.AppendLine($"{s.Name}+0x{(ulong)s.Mem+(uint)p:X}: ADRP/ADD -> 0x{resolved:X}");
                    if (++hits >= 30) break;
                }
            if (hits == 0) output.AppendLine($"main+0x{target:X}: aucune paire ADRP/ADD exacte détectée (LDR literal, autre registre ou relocation possible).");
        }
    }

    private static string Decode(uint w, ulong pc)
    {
        int rd = (int)(w & 31), rn = (int)((w >> 5) & 31), rm = (int)((w >> 16) & 31);
        string R(int r, bool wide = true) => r == 31 ? (wide ? "sp" : "wzr") : (wide ? $"x{r}" : $"w{r}");
        if ((w & 0xFC000000) == 0x94000000) return $"BL 0x{unchecked((long)pc + SignExtend(w & 0x03FFFFFF,26)*4):X}";
        if ((w & 0xFC000000) == 0x14000000) return $"B 0x{unchecked((long)pc + SignExtend(w & 0x03FFFFFF,26)*4):X}";
        if ((w & 0xFFFFFC1F) == 0xD63F0000) return $"BLR {R(rn)}";
        if ((w & 0xFFFFFC1F) == 0xD61F0000) return $"BR {R(rn)}";
        if ((w & 0xFFFFFC1F) == 0xD65F0000) return $"RET {R(rn)}";
        if ((w & 0x9F000000) == 0x90000000)
        {
            ulong imm = ((ulong)((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3);
            return $"ADRP {R(rd)}, 0x{unchecked((ulong)((long)(pc & ~0xFFFUL) + (SignExtend((uint)imm,21)<<12))):X}";
        }
        if ((w & 0x9F000000) == 0x10000000) return $"ADR {R(rd)}";
        if ((w & 0x7F000000) == 0x11000000)
        {
            ulong imm = (w >> 10) & 0xFFF; if ((w & (1u<<22)) != 0) imm <<= 12;
            bool sub = (w & (1u<<30)) != 0, flags = (w & (1u<<29)) != 0;
            return $"{(sub ? "SUB" : "ADD")}{(flags ? "S" : "")} {((w & (1u << 31)) != 0 ? R(rd, false) : R(rd))}, {((w & (1u << 31)) != 0 ? R(rn, false) : R(rn))}, #0x{imm:X}";
        }
        if ((w & 0x7F800000) == 0x52800000) return $"MOVZ {R(rd,(w&(1u<<31))!=0)}, #0x{(w>>5)&0xFFFF:X}, LSL #{((w>>21)&3)*16}";
        if ((w & 0x7F800000) == 0x72800000) return $"MOVK {R(rd,(w&(1u<<31))!=0)}, #0x{(w>>5)&0xFFFF:X}, LSL #{((w>>21)&3)*16}";
        if ((w & 0x3B000000) == 0x39000000)
        {
            int size = (int)(w >> 30); ulong off = ((w >> 10) & 0xFFFUL) << size;
            bool load = (w & (1u<<22)) != 0;
            return $"{(load?"LDR":"STR")} {(size==3?R(rd):R(rd,false))}, [{R(rn)}, #0x{off:X}]";
        }
        if ((w & 0x3B200C00) == 0x38200800) return $"LDR/STR register-offset {R(rd)}, [{R(rn)}, {R(rm)}]";
        if ((w & 0x7FE0FC00) == 0x2A000000) return $"MOV {R(rd)}, {R(rm)}";
        if ((w & 0x7F200000) == 0x0B000000) return $"ADD/SUB register {R(rd)}, {R(rn)}, {R(rm)}";
        if ((w & 0xFFFFFFE0) == 0xD53BD040) return $"MRS {R(rd)}, TPIDR_EL0";
        if ((w & 0xFFFFFFE0) == 0xD53BD060) return $"MRS {R(rd)}, TPIDRRO_EL0";
        if ((w & 0xFFC00000) == 0xA9800000) return $"STP pair (base {R(rn)})";
        if ((w & 0xFFC00000) == 0xA9400000) return $"LDP pair (base {R(rn)})";
        if ((w & 0x7F000000) == 0x71000000) return $"SUBS/CMP immediate {R(rn,false)}, #0x{(w>>10)&0xFFF:X}";
        if ((w & 0x7E000000) == 0x34000000) return $"CBZ/CBNZ {R(rd)}, branch";
        if ((w & 0xFF000010) == 0x54000000) return "B.cond";
        return "instruction ARM64 (non décodée)";
    }


    private static void AppendRuntimeEvidence(string? logText, StringBuilder output)
    {
        output.AppendLine("[C] INDICES RUNTIME EXTRAITS DU LOG FOURNI");
        if (string.IsNullOrWhiteSpace(logText))
        {
            output.AppendLine("Aucun log fourni à l'analyse approfondie. Les seules valeurs runtime disponibles sont celles déjà préchargées dans le profil.");
            return;
        }
        var lines = logText.Replace("\r", "").Split('\n');
        var pattern = new System.Text.RegularExpressions.Regex(
            @"(?i)(?:\b(?:x[0-7]|w0|rcx|r8|rdx|rax|tpidr(?:ro)?_el0|tlr)\s*[=:]|GetTlsValue entry|guest thread=|host instruction:|reading address\s+0x104)");
        var hits = lines.Select((line, index) => (line, index))
            .Where(x => pattern.IsMatch(x.line))
            .TakeLast(100).ToArray();
        if (hits.Length == 0)
        {
            output.AppendLine("Aucune ligne de registre x0-x7/w0 ou RCX/R8 détectée dans le log fourni.");
            return;
        }
        output.AppendLine("Lignes sources correspondantes (numéros conservés ; proximité textuelle ne garantit pas qu'elles décrivent le même instant) :");
        foreach (var hit in hits)
            output.AppendLine($"  L{hit.index + 1}: {hit.line.Trim()}");
        bool guestArgs = hits.Any(x => System.Text.RegularExpressions.Regex.IsMatch(x.line, @"(?i)\b(?:x[0-7]|w0)\s*[=:]"));
        bool hostArgs = hits.Any(x => System.Text.RegularExpressions.Regex.IsMatch(x.line, @"(?i)\b(?:rcx|r8)\s*[=:]"));
        output.AppendLine($"Registres invités x0-x7/w0 présents : {(guestArgs ? "oui" : "non")}.");
        output.AppendLine($"Registres hôtes RCX/R8 présents : {(hostArgs ? "oui" : "non")}.");
    }

    private static long SignExtend(uint v, int bits) => unchecked((int)(v << (32-bits))) >> (32-bits);
    private static uint U32(byte[] d, int o) => BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(o,4));
}