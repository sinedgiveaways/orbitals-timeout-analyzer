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
    private string _lastReport = "Charge le log, exefs\\main et exefs\\sdk, puis lance l'analyse.";

    public MainWindow()
    {
        InitializeComponent();
        ReportBox.Text = _lastReport;
    }

    private void LoadLog_Click(object sender, RoutedEventArgs e)
    {
        var d = new OpenFileDialog { Title = "Sélectionner le log Orbitals", Filter = "Logs|*.log;*.txt|Tous les fichiers|*.*" };
        if (d.ShowDialog() != true) return;
        _logPath = d.FileName; LogPathText.Text = _logPath; RunAnalysis();
    }

    private void LoadMain_Click(object sender, RoutedEventArgs e)
    {
        var d = new OpenFileDialog { Title = "Sélectionner exefs/main", Filter = "NSO / main|main;*.nso|Tous les fichiers|*.*" };
        if (d.ShowDialog() != true) return;
        _mainPath = d.FileName; MainPathText.Text = _mainPath; RunAnalysis();
    }

    private void LoadSdk_Click(object sender, RoutedEventArgs e)
    {
        var d = new OpenFileDialog { Title = "Sélectionner exefs/sdk", Filter = "NSO / sdk|sdk;*.nso|Tous les fichiers|*.*" };
        if (d.ShowDialog() != true) return;
        _sdkPath = d.FileName; SdkPathText.Text = _sdkPath; RunAnalysis();
    }

    private void Analyze_Click(object sender, RoutedEventArgs e) => RunAnalysis();

    private static IReadOnlyList<ulong> FindSdkOffsets(string text)
    {
        var values = new List<ulong>();
        var seen = new HashSet<ulong>();
        foreach (Match m in Regex.Matches(text, @"(?i)sdk\\+0x([0-9a-f]+)"))
            if (ulong.TryParse(m.Groups[1].Value, System.Globalization.NumberStyles.HexNumber, null, out var v) && seen.Add(v))
                values.Add(v);

        bool tlsCrash = Regex.IsMatch(text, @"(?i)GetTlsValue|sdk\\+0x16b730|reading address\\s+0x104");
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
            report.AppendLine($"Version : 0.3.0 | Date : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            report.AppendLine(new string('=', 90));
            string logText = _logPath is not null ? File.ReadAllText(_logPath) : "";
            if (_logPath is not null) report.AppendLine(LogAnalyzer.Analyze(_logPath));
            else report.AppendLine("[LOG] Aucun log chargé.");

            var mainOffsets = CrashContextAnalyzer.FindMainOffsets(logText);
            var sdkOffsets = FindSdkOffsets(logText);

            if (_mainPath is not null)
                report.AppendLine(NsoAnalyzer.Analyze(_mainPath, mainOffsets, "main"));
            else report.AppendLine("[MAIN] Non chargé.");

            if (_sdkPath is not null)
                report.AppendLine(NsoAnalyzer.Analyze(_sdkPath, sdkOffsets, "sdk"));
            else
            {
                report.AppendLine("[SDK] Non chargé. Sans exefs/sdk, le PC sdk+0x16b730 ne peut pas être désassemblé.");
                if (sdkOffsets.Count > 0) report.AppendLine("Offsets SDK repérés : " + string.Join(", ", sdkOffsets.Select(x => "sdk+0x" + x.ToString("X"))));
            }

            report.AppendLine();
            report.AppendLine("[CORRÉLATION TLS — REPÈRES CONNUS]");
            report.AppendLine("GetTlsValue : sdk+0x16B730 ; wrapper AllocateTlsSlot : sdk+0x16B670.");
            report.AppendLine("TlsManager::SearchUnusedTlsSlotUnsafe : sdk+0x16C520 ; constructeurs TlsManager : sdk+0x16C7B0 ; AllocateTlsSlot : sdk+0x16CC30.");
            report.AppendLine("Ces repères ne sont appliqués qu'au binaire SDK fourni : vérifier que sa version correspond à celle du log.");
            report.AppendLine();
            report.AppendLine("Limites : le décodeur embarqué reconnaît certaines familles ARM64, pas toutes les instructions. Il ne décode pas les tables ELF de symboles/relocations ni le code hôte x86-64 généré. Les occurrences de chaînes sont des indices, pas des preuves d'exécution.");
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
