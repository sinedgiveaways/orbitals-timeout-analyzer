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

## Fonctionnalités de base (introduites en 0.2.0)

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

- Le décodeur ARM64 intégré reste partiel ; pour un désassemblage approfondi, utiliser Capstone ou un outil équivalent. Ghidra n'est pas requis pour cette investigation.
- Les offsets `sdk+0x...` ne peuvent pas être désassemblés depuis `exefs/main` : le binaire SDK correspondant est nécessaire.
- Les fenêtres et marqueurs sont des indices, pas une preuve de cause racine.

## Compilation et téléchargement

Workflow : [Build Orbitals Crash Analyzer (Windows)](https://github.com/sinedgiveaways/orbitals-timeout-analyzer/actions/workflows/build-crash-analyzer.yml).

Après un push sur `main`, attendre un run vert, ouvrir le run, puis télécharger l'artefact `OrbitalsCrashAnalyzer-win-x64`. Vérifier que l'artefact correspond au commit courant avant de le tester.

L'ancien build 0.2.0 validé est documenté dans [INVESTIGATION.md](INVESTIGATION.md) ; il ne contient pas les corrections récentes de sélection des offsets.


## État actuel — audit du 21 novembre 2026

La branche de code de l'analyseur principal est en version 0.5.2. Un build Windows x64 autonome a été vérifié avec succès sur le run [44867261298](https://github.com/sinedgiveaways/orbitals-timeout-analyzer/actions/runs/44867261298), commit `b5c72fac2bf1a5c59a83ce8b2da5fa1d377773f6`, artifact `OrbitalsCrashAnalyzer-win-x64` (ID `14691748393`). Les mises à jour documentaires ultérieures n'ont pas déclenché de nouveau build de l'application.

Pour la priorité Crash B, les outils Windows séparés sont également disponibles via les runs réussis [Pointer Provenance](https://github.com/sinedgiveaways/orbitals-timeout-analyzer/actions/runs/44951389432) et [QWORD Writer Hunter](https://github.com/sinedgiveaways/orbitals-timeout-analyzer/actions/runs/44941325433). Le QWORD Hunter ne doit pas être relancé pour répéter l'examen des six objets déjà effectué.

La documentation technique de référence à jour se trouve dans le dossier racine `docs/`, en particulier `docs/INVESTIGATION_INDEX.md`, `docs/CRASH_A.md`, `docs/CRASH_B.md` et `docs/CRASH_B_POINTER_PROVENANCE.md`. Ce README décrit les fonctions générales de l'application ; il ne remplace pas ces rapports d'investigation.
