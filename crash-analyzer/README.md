# Orbitals Crash Analyzer

Application Windows WPF autonome (.NET 10) pour analyser localement les logs Orbitals Recomp et les segments NSO.

## État du projet — 20 novembre 2026

Le dossier de passation technique complet est ici : **[INVESTIGATION.md](INVESTIGATION.md)**.

Il contient :
- les deux familles de crash à ne pas confondre ;
- les résultats de rétro-ingénierie de l'allocateur déjà effectués ;
- les données du crash TLS actuellement prioritaire ;
- les limites de l'analyseur ;
- les commits récents et les vérifications encore nécessaires ;
- un plan d'action détaillé pour reprendre et terminer l'investigation.

**Priorité actuelle :** résoudre l'access violation à `0x104` dans le chemin invité `sdk+0x16b730` (`nn::os::GetTlsValue(TlsSlot)`). L'allocateur a déjà été largement étudié ; ne pas recommencer cette piste sans nouvelle preuve.

## Version 0.2.0 — fonctionnalités

- Détection des signatures de crash (free d'un pointeur inconnu, canary, access violation, abort Nintendo, Vulkan).
- Extraction des registres hôte/invité, PC, LR, TLR, frames invités et traces TPIDR présentes dans les logs.
- Lecture des segments NSO et décompression LZ4.
- Recherche de marqueurs allocateur connus.
- Extraction des offsets `main+0x...` et génération de fenêtres de code ARM64.
- Décodage limité de certaines branches et instructions ARM64 ; les mots bruts restent affichés.
- Export d'un rapport texte.

## Utilisation

1. Charger le fichier `orbitals.log`.
2. Charger `exefs/main` pour extraire les fenêtres ARM64 du module principal.
3. Cliquer sur « Analyser les fichiers chargés ».
4. Exporter le rapport texte.

L'application fonctionne localement : aucun log ni binaire n'est envoyé à GitHub.

## Limites

- Le décodeur intégré est partiel ; utiliser Capstone, Ghidra ou IDA pour un vrai désassemblage.
- Les offsets `sdk+0x...` ne peuvent pas être désassemblés depuis `exefs/main` : le binaire SDK correspondant est nécessaire.
- Les fenêtres et marqueurs sont des indices, pas une preuve de cause racine.

## Compilation et téléchargement

Workflow : [Build Orbitals Crash Analyzer (Windows)](https://github.com/sinedgiveaways/orbitals-timeout-analyzer/actions/workflows/build-crash-analyzer.yml).

Après un push sur `main), attendre un run vert, ouvrir le run, puis télécharger l'artefact `OrbitalsCrashAnalyzer-win-x64`. Vérifier que l'artefact correspond au commit courant avant de le tester.

L'ancien build 0.2.0 validé est documenté dans [INVESTIGATION.md](INVESTIGATION.md) ; il ne contient pas les corrections récentes de sélection des offsets.
