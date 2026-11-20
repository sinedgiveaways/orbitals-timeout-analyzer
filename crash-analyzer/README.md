# Orbitals Crash Analyzer

Application Windows WPF autonome (.NET 10) pour analyser localement les logs Orbitals Recomp et les segments NSO.

## Version 0.2.0

- Détection des signatures de crash (free d'un pointeur inconnu, canary, access violation, abort Nintendo, Vulkan).
- Extraction des registres hôte/invité, PC, LR, TLR, frames invités et traces TPIDR présentes dans les logs.
- Extraction automatique des offsets `main+0x...` et génération de fenêtres de code ARM64 autour de ces adresses à partir de `exefs/main`.
- Décodage limité des instructions ARM64 de branchement (B/BL/BR/BLR/RET), ADRP, ADD/SUB et LDR/STR usuelles ; les mots bruts sont toujours affichés.
- Lecture NSO, décompression LZ4, recherche des marqueurs allocateur connus.
- Export d'un rapport texte.

## Utilisation

1. Charger le fichier `orbitals.log`.
2. Charger `exefs/main` (recommandé : permet d'extraire le code autour des frames).
3. Cliquer sur « Analyser les fichiers chargés ».
4. Exporter le rapport et le transmettre pour analyse.

L'application fonctionne localement : aucun log ni binaire n'est envoyé à GitHub.

## Limites importantes

Le décodeur intégré est volontairement partiel, pas un désassembleur ARM64 complet. Les offsets `sdk+0x...` ne sont pas désassemblés depuis le NSO `main`, car ils appartiennent au module SDK. Les résultats restent des indices et ne prouvent pas seuls la cause racine.

## Compilation

Le workflow GitHub Actions publie automatiquement un exécutable Windows x64 autonome dans l'artefact `OrbitalsCrashAnalyzer-win-x64`.
