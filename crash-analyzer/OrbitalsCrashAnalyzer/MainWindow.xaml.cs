using Microsoft.Win32;
using System.IO;
using System.Text;
using System.Windows;
using OrbitalsCrashAnalyzer.Analysis;

namespace OrbitalsCrashAnalyzer;

public partial class MainWindow : Window
{
    private string? _logPath;
    private string? _nsoPath;
    private string _lastReport = "Charge un log ou un fichier main, puis lance l'analyse.";

    public MainWindow()
    {
        InitializeComponent();
        ReportBox.Text = _lastReport;
    }

    private void LoadLog_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Sélectionner un log Orbitals",
            Filter = "Fichiers log et texte|*.log;*.txt|Tous les fichiers|*.*"
        };
        if (dialog.ShowDialog() != true) return;
        _logPath = dialog.FileName;
        LogPathText.Text = _logPath;
        RunAnalysis();
    }

    private void LoadNso_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Sélectionner exefs/main",
            Filter = "NSO / main|main;*.nso|Tous les fichiers|*.*"
        };
        if (dialog.ShowDialog() != true) return;
        _nsoPath = dialog.FileName;
        NsoPathText.Text = _nsoPath;
        RunAnalysis();
    }

    private void Analyze_Click(object sender, RoutedEventArgs e) => RunAnalysis();

    private void RunAnalysis()
    {
        try
        {
            var report = new StringBuilder();
            report.AppendLine("ORBITALS CRASH ANALYZER — RAPPORT");
            report.AppendLine($"Date d'analyse : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            report.AppendLine(new string('=', 78));
            if (_logPath is not null)
            {
                report.AppendLine();
                report.AppendLine(LogAnalyzer.Analyze(_logPath));
            }
            else report.AppendLine("\n[LOG] Aucun log chargé.");
            if (_nsoPath is not null)
            {
                report.AppendLine();
                report.AppendLine(NsoAnalyzer.Analyze(_nsoPath));
            }
            else report.AppendLine("\n[NSO] Aucun binaire chargé.");
            report.AppendLine();
            report.AppendLine("NOTE : les correspondances sont des indices statiques, pas une preuve de causalité.");
            _lastReport = report.ToString();
            ReportBox.Text = _lastReport;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Erreur d'analyse", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = "Exporter le rapport",
            Filter = "Rapport texte|*.txt",
            FileName = "OrbitalsCrashReport.txt"
        };
        if (dialog.ShowDialog() != true) return;
        File.WriteAllText(dialog.FileName, _lastReport, new UTF8Encoding(false));
        MessageBox.Show(this, "Rapport exporté.", "Orbitals Crash Analyzer", MessageBoxButton.OK, MessageBoxImage.Information);
    }
}
