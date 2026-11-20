using System.Text;
using System.Text.RegularExpressions;

namespace OrbitalsCrashAnalyzer.Analysis;

public static class CrashContextAnalyzer
{
    public static string Analyze(string text)
    {
        var output = new StringBuilder();
        output.AppendLine("[CONTEXTE CRASH — REGISTRES, TLS ET PILE]");

        // Some logger versions concatenate the TPIDR banner to the exception line.
        // Split that banner off so the exception remains readable and searchable.
        var exception = Regex.Match(text,
            @"(?im)^.*?(?:FATAL:\s*access violation|EXCEPTION_ACCESS_VIOLATION|segmentation fault)[^\r\n]*");
        if (exception.Success)
        {
            var clean = Regex.Replace(exception.Value, @"FATAL:\s*TPIDR trace.*$", "", RegexOptions.IgnoreCase).Trim();
            output.AppendLine("Exception:");
            output.AppendLine("  " + clean);
        }

        AppendMatches(output, "Adresse lue/écrite",
            text, @"(?im)^\s*.*?(?:reading|writing) address\s+0x[0-9a-f]+[^\r\n]*", 8);
        AppendMatches(output, "Fonction recompilée",
            text, @"(?im)^\s*in lifted function\s+[^\r\n]*", 8);
        AppendMatches(output, "PC invité",
            text, @"(?im)^\s*pc\s+0x[0-9a-f]+[^\r\n]*", 8);
        AppendMatches(output, "Thread invité / TPIDR",
            text, @"(?im)^\s*guest thread=[^\r\n]*", 8);
        AppendMatches(output, "TLR",
            text, @"(?im)^\s*TLR(?:\[.*)?[^\r\n]*", 8);
        AppendMatches(output, "Instruction hôte",
            text, @"(?im)^\s*host instruction:[^\r\n]*", 8);
        AppendMatches(output, "Registre LR (x30)",
            text, @"(?im)^\s*x30\s+[^\r\n]*", 8);

        var frames = Regex.Matches(text, @"(?im)^\s*guest frame\s+(\d+):\s*([^\r\n]+)")
            .Cast<Match>()
            .Select(m => (Index: int.Parse(m.Groups[1].Value), Value: m.Groups[2].Value.Trim()))
            .OrderBy(x => x.Index)
            .ToArray();
        if (frames.Length > 0)
        {
            output.AppendLine("Frames invités (ordre croissant) :");
            foreach (var frame in frames.Take(24))
                output.AppendLine($"  guest frame {frame.Index}: {frame.Value}");

            var first = frames[0].Index;
            if (first > 0)
                output.AppendLine($"Frames 0 à {first - 1} absentes du journal source : elles ne peuvent pas être reconstruites comme des frames observées.");
        }
        else
        {
            output.AppendLine("Frames invités : aucune frame explicite trouvée dans le journal source.");
        }

        var tpidr = Regex.Matches(text,
                @"(?im)^\s*tpidr\[\d+\]\s+\w+\s+thread=(0x[0-9a-f]+)\s+pc=(0x[0-9a-f]+)\s+old=(0x[0-9a-f]+)\s+new=(0x[0-9a-f]+)")
            .Cast<Match>().ToArray();
        if (tpidr.Length > 0)
        {
            var threads = tpidr.Select(m => m.Groups[1].Value).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            var values = tpidr.Select(m => m.Groups[4].Value).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            output.AppendLine($"Trace TPIDR : {tpidr.Length} événements lisibles dans le texte fourni, {threads} threads distincts, {values} valeurs TPIDR finales distinctes.");
            output.AppendLine("Une valeur TPIDR stable ne prouve ni la validité ni l'invalidité des slots TLS.");
        }

        var threadContext = Regex.Match(text,
            @"(?im)guest thread=(?<thread>(?:0x)?[0-9a-f]+)\s+TPIDR_EL0=(?<tpidr>0x[0-9a-f]+)\s+TLR=(?<tlr>0x[0-9a-f]+)");
        var currentThread = Regex.Match(text,
            @"(?im)TLR\[\+0x(?<offset>[0-9a-f]+)\]\s+current-thread object=(?<object>0x[0-9a-f]+)");
        if (threadContext.Success && currentThread.Success)
        {
            output.AppendLine("Corrélation du thread courant :");
            output.AppendLine($"  thread invité={threadContext.Groups["thread"].Value}, TPIDR_EL0={threadContext.Groups["tpidr"].Value}");
            output.AppendLine($"  TLR={threadContext.Groups["tlr"].Value}, objet courant à +0x{currentThread.Groups["offset"].Value} = {currentThread.Groups["object"].Value}");
            output.AppendLine("  Observation uniquement : le log donne cette référence, mais ne valide ni le type ni la durée de vie de l'objet.");
        }

        output.AppendLine("Limite : le journal décrit l'état observé au crash ; il ne prouve pas à lui seul si le défaut est dans l'appelant, le runtime TLS ou le code hôte généré.");
        return output.ToString();
    }

    private static void AppendMatches(StringBuilder output, string label, string text, string pattern, int limit)
    {
        var matches = Regex.Matches(text, pattern).Cast<Match>().Select(m => m.Value.Trim()).TakeLast(limit).ToArray();
        if (matches.Length == 0) return;
        output.AppendLine(label + ":");
        foreach (var match in matches)
            output.AppendLine("  " + match);
    }

    // Keep the crash site, real LR, and unwind frames ahead of incidental addresses.
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

        // Resolve an absolute x30 value only when it falls inside the loaded main image.
        const ulong mainImageBase = 0x7000000000;
        const ulong mainTextSize = 0x70C5B20;
        foreach (Match m in Regex.Matches(text, @"(?im)^\s*x30\s+(?:0x)?([0-9a-f]{8,16})\b"))
        {
            if (ulong.TryParse(m.Groups[1].Value, System.Globalization.NumberStyles.HexNumber, null, out var lr)
                && lr >= mainImageBase && lr - mainImageBase < mainTextSize
                && seen.Add(lr - mainImageBase))
                prioritized.Add(lr - mainImageBase);
        }

        AddMatches(@"(?im)^\s*lr\s*(?:[:=]\s*)?main\+0x([0-9a-f]+)");
        AddMatches(@"(?im)^\s*guest frame\s+\d+:\s*main\+0x([0-9a-f]+)");

        // This exact signature has an independently established LR in the investigation
        // dossier. It is an inferred disassembly target, not a live register value.
        bool knownTlsCrash =
            Regex.IsMatch(text, @"(?i)main\+0x1759b20") &&
            Regex.IsMatch(text, @"(?i)(?:0x104|reading address\s+0x104)") &&
            Regex.IsMatch(text, @"(?i)orbitalgame\+0x1b5b682f");
        if (knownTlsCrash && seen.Add(0x175A16C))
            prioritized.Add(0x175A16C);

        // Known caller return address from the same established crash dossier.
        // Keep it explicitly as an inferred code window, never as an observed stack frame.
        if (knownTlsCrash && seen.Add(0x1750B88))
            prioritized.Add(0x1750B88);

        foreach (Match m in Regex.Matches(text, @"(?i)main\+0x([0-9a-f]+)"))
        {
            if (ulong.TryParse(m.Groups[1].Value, System.Globalization.NumberStyles.HexNumber, null, out var value)
                && seen.Add(value))
                prioritized.Add(value);
        }

        return prioritized;
    }
}
