# Orbitals Crash B — analyseur E8 ciblé v5

## Installation
Place ce dossier dans le projet sous :
`orbitals-recomp\tools\crash_b_collection_analyzer_v5`

Lance `Lancer_analyseur.bat`. Le script utilise le Python intégré :
`orbitals-recomp\setup\python\python.exe`

Choisis ensuite `setup-work\obj`, clique **Analyser**, puis **Exporter TXT**.

## Ce que filtre la v5
La v4 remontait toutes les écritures à déplacement nul, d'où les 2 702 189 candidats. La v5 ne conserve que les écritures mémoire dont l'adresse utilise un registre repéré comme dérivé d'un `IMUL * 0xE8`, éventuellement propagé par `MOV` ou `LEA`, et avec un déplacement nul.

## Important
- La v5 relit les fichiers `.o/.obj` existants : elle ne peut pas réutiliser les 2 702 189 résultats de la v4, car la v4 ne les a pas exportés.
- Elle ne lance ni `prepare.py`, ni compilation, ni le jeu et ne modifie aucun fichier du jeu.
- Le filtrage est heuristique et local : il ne résout pas tous les alias mémoire, appels inter-fonctions ou chemins de contrôle. Les résultats sont des candidats à vérifier, pas une preuve.
- Capstone doit être disponible dans le Python intégré. L'installation déjà vérifiée est suffisante.
