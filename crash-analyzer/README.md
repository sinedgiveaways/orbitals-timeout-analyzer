# Orbitals Crash Analyzer

Application Windows WPF en C#/.NET 10 pour analyser localement les logs Orbitals et les en-têtes/segments NSO.

## Fonctionnalités de la version 0.1

- Détection de signatures de crash (free d'un pointeur inconnu, canary, access violation, abort Nintendo, erreurs Vulkan).
- Extraction de lignes et d'adresses hexadécimales candidates depuis un log.
- Lecture de l'en-tête NSO, inspection des trois segments et décompression LZ4.
- Recherche de marqueurs binaires connus de l'analyse de l'allocateur.
- Export d'un rapport texte.

Les résultats sont des indices statiques et ne prouvent pas la cause racine. Le désassemblage ARM64 et les références croisées avancées sont prévus pour les prochaines versions.

## Compilation

```powershell
dotnet publish .\OrbitalsCrashAnalyzer\OrbitalsCrashAnalyzer.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

Le workflow GitHub Actions construit automatiquement une version Windows autonome.
