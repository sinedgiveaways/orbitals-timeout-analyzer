# orbitals-timeout-analyzer
Standalone Windows GUI for analyzing Orbitals Recomp timeout logs, with GitHub Actions build and downloadable executable releases.

## Dossier technique

Les résultats de l'investigation sont conservés dans le dossier [docs/](docs/INVESTIGATION_INDEX.md) :

- [Index et état global](docs/INVESTIGATION_INDEX.md)
- [Crash A — FMallocBinned3 / GOT-PLT](docs/CRASH_A.md)
- [Crash B — accès 0x104 / TLS](docs/CRASH_B.md)
- [Environnement et contraintes de build](docs/ENVIRONMENT_AND_BUILD.md)

Les documents séparent les faits établis, les hypothèses et les inconnues. Ils ne remplacent pas les logs bruts, qui doivent être conservés séparément.

## Compilation Windows

Le workflow GitHub Actions construit et publie une version autonome pour Windows x64. L'exécutable publié est indépendant du cycle de préparation et de recompilation du jeu Orbitals.


- [Rapport ciblé de provenance du pointeur Crash B](docs/CRASH_B_POINTER_PROVENANCE.md)
- [Résultats QWORD Hunter et 12 candidats Crash B](docs/CRASH_B_CANDIDATES_12.md)

- [Crash C — WER minidump / ucrtbase.dll](docs/CRASH_C_WER_UCRTBASE.md) — paramètres apparents de copie, source suspecte, pile hôte, limites et prochaines étapes.
