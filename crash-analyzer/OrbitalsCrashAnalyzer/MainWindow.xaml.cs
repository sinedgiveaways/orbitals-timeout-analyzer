using Microsoft.Win32;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using OrbitalsCrashAnalyzer.Analysis;

namespace OrbitalsCrashAnalyzer;

public partial class MainWindow : Window
{
    private string? _logPath;
    private string? _mainPath;
    private string? _sdkPath;
    private string? _dumpPath;
    private string _lastReport = "Profil TLS préchargé. Les fichiers complémentaires sont facultatifs.";

    public MainWindow()
    {
        InitializeComponent();
        ReportBox.Text = _lastReport;
        RunAnalysis();
    }

    private void LoadLog_Click(object sender, RoutedEventArgs e)
    {
        var d = new OpenFileDialog { Title = "Ajouter un log Orbitals (facultatif)", Filter = "Logs|*.log;*.txt|Tous les fichiers|*.*" };
        if (d.ShowDialog() != true) return;
        _logPath = d.FileName; LogPathText.Text = _logPath; RunAnalysis();
    }

    private void LoadMain_Click(object sender, RoutedEventArgs e)
    {
        var d = new OpenFileDialog { Title = "Ajouter exefs/main (facultatif)", Filter = "NSO / main|main;*.nso|Tous les fichiers|*.*" };
        if (d.ShowDialog() != true) return;
        _mainPath = d.FileName; MainPathText.Text = _mainPath; RunAnalysis();
    }

    private void LoadSdk_Click(object sender, RoutedEventArgs e)
    {
        var d = new OpenFileDialog { Title = "Ajouter exefs/sdk (facultatif)", Filter = "NSO / sdk|sdk;*.nso|Tous les fichiers|*.*" };
        if (d.ShowDialog() != true) return;
        _sdkPath = d.FileName; SdkPathText.Text = _sdkPath; RunAnalysis();
    }


    private void LoadDump_Click(object sender, RoutedEventArgs e)
    {
        var d = new OpenFileDialog { Title = "Charger le minidump WER Orbitals", Filter = "Minidump Windows|*.dmp;*.mdmp|Tous les fichiers|*.*" };
        if (d.ShowDialog() != true) return;
        _dumpPath = d.FileName;
        DumpPathText.Text = _dumpPath;
        RunAnalysis();
    }

    private void Analyze_Click(object sender, RoutedEventArgs e) => RunAnalysis();

    private static IReadOnlyList<ulong> FindSdkOffsets(string text)
    {
        var values = new List<ulong>();
        var seen = new HashSet<ulong>();
        foreach (Match m in Regex.Matches(text, @"(?i)sdk\+0x([0-9a-f]+)"))
            if (ulong.TryParse(m.Groups[1].Value, System.Globalization.NumberStyles.HexNumber, null, out var v) && seen.Add(v))
                values.Add(v);

        bool tlsCrash = Regex.IsMatch(text, @"(?i)GetTlsValue|sdk\+0x16b730|reading address\s+0x104");
        if (tlsCrash)
            foreach (ulong v in new ulong[] { 0x16B670, 0x16B730, 0x16C520, 0x16C7B0, 0x16CC30 })
                if (seen.Add(v)) values.Add(v);
        return values.Take(32).ToArray();
    }

    private void RunAnalysis()
    {
        try
        {
            var report = new StringBuilder();
            report.AppendLine("ORBITALS CRASH ANALYZER — RAPPORT COMPLET");
            report.AppendLine($"Version : 0.6.0 | Date : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            report.AppendLine("Aucune préparation, génération ou recompilation du jeu n'est exécutée.");
            report.AppendLine(new string('=', 90));
            report.AppendLine(InvestigationProfile.Render());

            string logText = _logPath is not null ? File.ReadAllText(_logPath) : "";
            if (_logPath is not null)
            {
                report.AppendLine();
                report.AppendLine("[ANALYSE DU LOG FOURNI]");
                report.AppendLine(LogAnalyzer.Analyze(_logPath));
            }
            else
                report.AppendLine("\n[LOG] Aucun log relu : le profil ci-dessus reprend les résultats déjà établis. Ajouter un log uniquement pour examiner un nouvel événement ou vérifier un changement.");

            var mainOffsets = CrashContextAnalyzer.FindMainOffsets(logText).ToList();
            var sdkOffsets = FindSdkOffsets(logText).ToList();
            foreach (ulong v in new ulong[] { 0x1759B20, 0x175A16C, 0x1750B88, 0x1750650, 0x1718CF8, 0x1D77D64, 0x1D761E0, 0x1641F84 })
                if (!mainOffsets.Contains(v)) mainOffsets.Add(v);
            foreach (ulong v in new ulong[] { 0x16B670, 0x16B730, 0x16C520, 0x16C7B0, 0x16CC30 })
                if (!sdkOffsets.Contains(v)) sdkOffsets.Add(v);

            if (_mainPath is not null)
                report.AppendLine(NsoAnalyzer.Analyze(_mainPath, mainOffsets, "main"));
            else
                report.AppendLine("\n[MAIN] Non chargé. Le rapport conserve les adresses et faits déjà connus ; charger main seulement pour vérifier/désassembler ces offsets.");

            if (_sdkPath is not null)
                report.AppendLine(NsoAnalyzer.Analyze(_sdkPath, sdkOffsets, "sdk"));
            else
                report.AppendLine("\n[SDK] Non chargé. Les résultats antérieurs sur GetTlsValue et TlsManager restent affichés ; charger sdk uniquement pour une nouvelle vérification du binaire.");

            report.AppendLine();
            report.AppendLine(TlsDeepAnalyzer.Analyze(_mainPath, _sdkPath, logText));

            if (_dumpPath is not null)
            {
                report.AppendLine();
                report.AppendLine(WerMinidumpAnalyzer.Analyze(_dumpPath));
            }
            else
                report.AppendLine("\n[WER] Aucun minidump chargé. Charger le fichier .dmp pour analyser automatiquement l'exception, les registres AMD64, les plages mémoire, la structure Crash C et la vtable connue.");

            report.AppendLine();
            report.AppendLine("[MODE D'EMPLOI]");
            report.AppendLine("Le log, main et sdk sont désormais facultatifs. Commencer par lire le profil préchargé. Ajouter seulement le fichier nécessaire à la question en cours. L'application analyse localement les fichiers choisis et ne les téléverse pas.");
            report.AppendLine("Important : le profil embarque les résultats déjà communiqués, mais il ne contient pas les octets complets du log original. Pour vérifier un nouvel événement précis du log, ajouter le fichier local.");
            report.AppendLine();
            report.AppendLine("Limites techniques : décodeur ARM64 partiel ; pas de désassemblage x86-64 du code hôte recompilé ni de reconstruction complète ELF/dynsym/relocations. Une hypothèse ne devient pas une cause racine sans validation dynamique.");
            _lastReport = report.ToString();
            ReportBox.Text = _lastReport;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.ToString(), "Erreur d'analyse", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        var d = new SaveFileDialog { Title = "Exporter le rapport complet", Filter = "Rapport texte|*.txt", FileName = "OrbitalsCrashReport.txt" };
        if (d.ShowDialog() != true) return;
        File.WriteAllText(d.FileName, _lastReport, new UTF8Encoding(false));
        MessageBox.Show(this, "Rapport exporté.", "Orbitals Crash Analyzer", MessageBoxButton.OK, MessageBoxImage.Information);
    }
}
