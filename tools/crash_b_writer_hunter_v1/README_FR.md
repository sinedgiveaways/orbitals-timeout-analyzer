# Orbitals Crash B — E8 QWORD Writer Hunter v1

## Utilisation
1. Telecharge le dossier crash_b_writer_hunter_v1.
2. Copie-le dans orbitals-recomp\tools\.
3. Lance build_windows.bat.
4. Selectionne setup-work\obj.
5. Le rapport orbitals_crash_b_qword_report.txt est cree dans setup-work\obj.

## Perimetre
L'outil lit uniquement main_main_0156.o, main_main_0157.o, main_main_0173.o, main_main_0186.o, main_main_0330.o et main_main_0184.o.
Il n'execute pas prepare.py, ne genere rien, ne compile rien et ne lance pas le jeu.
Il recherche les stores QWORD utilisant localement un registre derive de IMUL * 0xE8 et imprime aussi le contexte elargi des 12 offsets connus.

## Limites
Analyse statique heuristique : pas de resolution complete des alias, du flot inter-fonctions ou des valeurs runtime. Un store QWORD a displacement zero est un candidat, pas une preuve de causalite.
