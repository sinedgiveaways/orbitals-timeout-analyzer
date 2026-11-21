# Orbitals Crash B — Pointer Provenance v2

## Objectif
Analyser le vrai chemin mémoire observé dans `main_main_0184.o` autour de `.text+0x1952F` :
- chargements/écritures de `[rsi+0xD8]` ;
- provenance locale du pointeur extrait de ce slot ;
- chargement du premier QWORD (`[rax]`) ;
- écritures QWORD candidates à déplacement zéro ;
- branches et appels autour de l'instruction fautive.

L'accès fautif utilise un index de stride `0x38` et un champ `+0x5C`. Cette version ne cherche donc plus à assimiler ce chemin au précédent balayage `*0xE8`.

## Utilisation
1. Télécharger l'artefact Windows depuis l'onglet Actions du dépôt.
2. Lancer `Orbitals_CrashB_Pointer_Provenance.exe`.
3. Sélectionner le dossier `setup-work\obj`.
4. Le rapport `orbitals_crash_b_pointer_provenance_v2.txt` sera créé dans ce dossier.

## Périmètre
Lecture seule du fichier `main_main_0184.o`. Aucun lancement de `prepare.py`, aucune génération, aucune recompilation et aucun lancement du jeu.

## Limites
Suivi statique heuristique et linéaire. Il ne résout pas complètement le graphe de contrôle, les alias, les spills, les appels inter-fonctions ni les valeurs runtime. Les écritures candidates ne constituent pas une preuve de causalité.
