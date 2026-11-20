using System.Text;
using System.Text.RegularExpressions;

namespace OrbitalsCrashAnalyzer.Analysis;

public static class CrashContextAnalyzer
{
    public static string Analyze(string text)
    {
        var output = new StringBuilder();
        output.AppendLine("[CONTEXTE CRASH — REGISTRES, TLS ET PILE]");
        var patterns = new (string Label, string Pattern)[]
        {
            ("Exception", @"(?im)^.*(?:FATAL: access violation|EXCEPTION_ACCESS_VIOLATION|segmentation fault).*$"),
            ("Adresse lue/écrite", @"(?im)^.*(?:reading|writing) address\s+0x[0-9a-f]+.*$"),
            ("Fonction recompilée", @"(?im)^\s*in lifted function\s+.*$"),
            ("PC invité", @"(?im)^\s*pc\s+0x[0-9a-f]+.*$"),
            ("Thread invité / TPIDR", @"(?im)^\s*guest thread=.*$"),
            ("TLR", @"(?im)^\s*TLR\[.*$"),
            ("Instruction hôte", @"(?im)^\s*host instruction:.*(?:\r?\n\s*.*reading address.*)?$"),
            ("LR", @"(?im)^\s*x30\s+.*$"),
            ("Frames invités", @"(?im)^\s*guest frame\s+\d+:.*$")
        };
        foreach (var (label, pattern) in patterns)
        {
            var matches = Regex.Matches(text, pattern).Cast<Match>().Select(m => m.Value.Trim()).TakeLast(12).ToArray();
            if (matches.Length == 0) continue;
            output.AppendLine(label + ":");
            foreach (var match in matches) output.AppendLine("  " + match.Replace("\n", " "));
        }

        var host = Regex.Match(text, @"(?im)^\s*host rcx\s+([0-9a-f]+).*?host r8\s+([0-9a-f]+)");
        if (host.Success && ulong.TryParse(host.Groups[1].Value, System.Globalization.NumberStyles.HexNumber, null, out var rcx)
            && ulong.TryParse(host.Groups[2].Value, System.Globalization.NumberStyles.HexNumber, null, out var r8))
        {
            output.AppendLine($"Analyse accès hôte : RCX=0x{rcx:X}, R8=0x{r8:X}. Vérifier le déplacement de l'instruction avant de conclure sur l'adresse effective.");
        }

        var tpidr = Regex.Matches(text, @"(?im)^\s*tpidr\[\d+\]\s+\w+\s+thread=(0x[0-9a-f]+)\s+pc=(0x[0-9a-f]+)\s+old=(0x[0-9a-f]+)\s+new=(0x[0-9a-f]+)")
            .Cast<Match>().ToArray();
        if (tpidr.Length > 0)
        {
            var threads = tpidr.Select(m => m.Groups[1].Value).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            var values = tpidr.Select(m => m.Groups[4].Value).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            output.AppendLine($"Trace TPIDR : {tpidr.Length} événements lisibles dans le texte fourni, {threads} threads distincts, {values} valeurs TPIDR finales distinctes.");
            output.AppendLine("Une valeur TPIDR stable ne prouve ni la validité ni l'invalidité des slots TLS.");
        }

        output.AppendLine("Limite : le journal décrit l'état observé au crash ; il ne prouve pas à lui seul si le défaut est dans l'appelant, le runtime TLS ou le code hôte généré.");
        return output.ToString();
    }

    // Put the actual crash site and unwind frames first. The NSO analyzer consumes
    // this ordered list and has a bounded number of disassembly windows.
    public static IReadOnlyList<ulong> FindMainOffsets(string text)
    {
        var prioritized = new List<ulong>();
        var seen = new HashSet<ulong>();

        void AddMatches(string pattern)
        {
            foreach (Match m in Regex.Matches(text, pattern))
            {
                if (ulong.TryParse(m.Groups[1].Value, System.Globalization.NumberStyles.HexNumber, null, out var value)
                    && seen.Add(value))
                    prioritized.Add(value);
            }
        }

        AddMatches(@"(?im)^\s*in lifted function\s+.*?main\+0x([0-9a-f]+)");
        AddMatches(@"(?im)^\s*x30\s+.*?main\+0x([0-9a-f]+)");
        AddMatches(@"(?im)^\s*lr\s+main\+0x([0-9a-f]+)");
        AddMatches(@"(?im)^\s*guest frame\s+\d+:\s*main\+0x([0-9a-f]+)");

        foreach (Match m in Regex.Matches(text, @"(?i)main\+0x([0-9a-f]+)"))
        {
            if (ulong.TryParse(m.Groups[1].Value, System.Globalization.NumberStyles.HexNumber, null, out var value)
                && seen.Add(value))
                prioritized.Add(value);
        }

        return prioritized;
    }
}
