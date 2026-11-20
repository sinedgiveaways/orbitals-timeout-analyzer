using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace OrbitalsCrashAnalyzer.Analysis;

public static class LogAnalyzer
{
    private static readonly (string Name, string Pattern, string Meaning)[] Signatures =
    [
        ("Free d'un pointeur inconnu", @"Attempt to free an unrecognized pointer", "Le pointeur passé à free n'est pas reconnu par les métadonnées de l'allocateur."),
        ("Canary / métadonnée invalide", @"(?i)(canary|corrupt(?:ed|ion)?|invalid.*(?:pointer|metadata)|metadata.*invalid)", "Possible corruption de métadonnées ou écrasement mémoire."),
        ("Violation d'accès", @"(?i)(access violation|EXCEPTION_ACCESS_VIOLATION|segmentation fault|SIGSEGV)", "Accès mémoire invalide. Examiner PC, adresse effective et registres."),
        ("Abort Nintendo", @"nn::diag::Abort|AbortImpl", "Arrêt explicite via le mécanisme de diagnostic Nintendo."),
        ("Erreur Vulkan", @"(?i)(VK_ERROR_[A-Z_]+|Vulkan.*(?:error|failed))", "Erreur signalée par Vulkan ; elle peut être secondaire au crash."),
        ("Thread de rendu", @"(?i)(RenderThread|RHIThread|RHI thread)", "Le log mentionne un thread de rendu ; cela ne prouve pas que le GPU est la cause.")
    ];

    public static string Analyze(string path)
    {
        var text = File.ReadAllText(path);
        var lines = text.Replace("\r", "").Split('\n');
        var output = new StringBuilder();
        output.AppendLine($"[LOG] {path}");
        output.AppendLine($"Taille : {new FileInfo(path).Length:N0} octets | Lignes : {lines.Length:N0}");
        var hits = 0;
        foreach (var sig in Signatures)
        {
            var matches = lines.Select((line, index) => (line, index))
                .Where(x => Regex.IsMatch(x.line, sig.Pattern))
                .Take(8).ToArray();
            if (matches.Length == 0) continue;
            hits++;
            output.AppendLine();
            output.AppendLine($"[{sig.Name}] — {sig.Meaning}");
            foreach (var match in matches)
                output.AppendLine($"  L{match.index + 1}: {match.line.Trim()}");
        }
        if (hits == 0) output.AppendLine("Aucune des signatures connues n'a été détectée.");
        var addresses = Regex.Matches(text, @"(?i)(?:0x)?[0-9a-f]{8,16}")
            .Select(m => m.Value).Distinct(StringComparer.OrdinalIgnoreCase).Take(80).ToArray();
        output.AppendLine();
        output.AppendLine($"Adresses hexadécimales candidates : {addresses.Length}");
        output.AppendLine(string.Join(", ", addresses));
        return output.ToString();
    }
}
