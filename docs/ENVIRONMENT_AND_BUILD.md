# Environnement Orbitals Recomp et contraintes de build

Dernière mise à jour : 2026-11-21

## Répertoire et source

- Répertoire de travail Windows : `C:\Users\mco2v\Downloads\orbitals-recomp`
- Source NUP : `Orbitals Deluxe Edition [040032B023CA4000][v327680].nup`
- Répertoire de sortie/extraction mentionné : `exefs` et `romfs`.

## Versions et identifiants observés

Versions/commits du port observés dans les logs :
- `0.2.0-g7bc8a0d` (ancien état) ;
- `0.2.0-g2d851a3` (log de rebuild) ;
- `0.2.0-g84b2e62` (en-tête runtime le plus récent communiqué).

Les builds d'analyse doivent rester distincts des builds mco2vie, avec le suffixe demandé `gpt-sined`.

## Configuration machine / runtime rapportée

- Windows x64.
- .NET host 8.0.6 x64.
- Runtimes .NET App/Desktop 6.0.11 et 8.0.6.
- Aucun SDK .NET installé dans l'environnement utilisateur rapporté.
- Python embarqué : 3.14.10.
- 24 threads, 8 Go de RAM.
- GPU NVIDIA RTX 4080, pilote 616.92.
- Vulkan 1.4.351.
- SDL 3.4.18.
- Présentation Vulkan mailbox observée.

## Comportement runtime récent communiqué

Le dernier runtime signalé présente une fenêtre de jeu visible, écran noir dès le démarrage et audio audible.

Le log mentionne notamment :
- `ORBITALS_VK_PRESENT=mailbox` ;
- cache pipeline ;
- `main` avec 1 471 402 relocations / 1 041 imports ;
- `subsdk0` avec 1 789 relocations / 331 imports ;
- `sdk` avec 37 566 relocations / 8 imports ;
- démarrage invité autour de 329 ms ;
- `nn::init::Start sdk+0x1374A0` ;
- un add-on AOC ;
- plusieurs imports SDK de codecs sans override hôte ;
- tests de fichiers `rom:/Engine/...` et `rom:/Orbitals/...` dont plusieurs entrées `Hardware.ini` / `GameplayTags.ini` renvoient `0x202` ;
- replay NVN asynchrone et rapports de soumission GPU activés ;
- appels NVN tels que `nvnQueueSubmitCommands`, `nvnQueueFlush`, `nvnSyncWait`.

Ces observations décrivent le runtime récent et ne sont pas automatiquement la cause du Crash B TLS.

## Contrainte majeure : éviter les reconstructions complètes

L'utilisateur ne veut pas relancer le cycle complet `prepare.py`, génération du code et compilation pour chaque expérimentation.

Un rebuild précédent a notamment affiché :
- `prepare.py --port 0.2.0-g2d851a3` ;
- 120 spin loops détectées ;
- 828 chunks main ;
- génération : environ 391,6 s ;
- compilation : 833 étapes.

Ce cycle a été considéré comme inadapté pour les expérimentations d'analyse. Privilégier :
- analyse des logs déjà existants ;
- analyse statique des NSO déjà extraits ;
- outils d'analyse séparés ;
- instrumentation ciblée ou patch runtime isolé uniquement si nécessaire.

Ne pas lancer une préparation ou recompilation complète sans raison démontrée et accord explicite.

## Analyseur Windows

Dépôt : `sinedgiveaways/orbitals-timeout-analyzer`.

Versions historiques :
- 0.4.0 : première version Windows GUI publiée en artifact ;
- 0.5.0 : rapport TLS approfondi ;
- 0.5.1 : garde contre l'exception `IndexOutOfRangeException` du suivi des registres ;
- 0.5.2 : séparation explicite du PC hôte, de la fonction invitée levée et du chemin SDK TLS.

Correctif 0.5.1 :
- le traceur suivait `x0-x7` mais pouvait tenter d'indexer `x8-x30`, SP ou XZR ;
- ajout d'un accès protégé aux registres suivis ;
- les registres hors de la plage suivie sont traités comme inconnus.

La version 0.5.2 ajoute notamment :
- fenêtres ARM64 élargies autour de `main+0x1750B84` et `main+0x1759B20` ;
- tentative de suivi statique des définitions de `x0-x7` avant le site BL ;
- recherche des branches directes et références ADRP/ADD vers les globals TLS connus ;
- décodage des fonctions SDK TLS ;
- extraction d'indices runtime depuis le log ;
- avertissements explicites sur les valeurs qui ne sont pas capturées.

**Important :** la présence du code source sur GitHub ne prouve pas qu'un artifact Windows 0.5.2 a été compilé, téléversé et testé. Vérifier le workflow et l'artifact avant d'annoncer un exécutable disponible.


## Mise à jour runtime — 21-11-2026

Dernier log rapporté : la fenêtre du jeu apparaît noire dès le démarrage, mais l'audio est audible. Le runtime utilise Vulkan mailbox ; le log indique un démarrage invité vers 329 ms, nn::init::Start sdk+0x1374A0, replay NVN asynchrone, appels nvnQueueSubmitCommands / nvnQueueFlush / nvnSyncWait et des probes rom:/Engine/... et rom:/Orbitals/.... Plusieurs Hardware.ini et GameplayTags.ini retournent 0x202. Ces lignes sont consignées comme observations, sans les attribuer au Crash B.

## Suivi de l'analyse Crash B

L'examen des six objets / 12 candidats 0xE8 est déjà terminé selon l'utilisateur. Ne pas redemander ce travail. Les résultats connus restent des écritures DWORD, sans preuve directe de l'écrivain QWORD du premier champ de l'élément. L'analyseur ne doit pas déclencher de rebuild du jeu : travailler sur les logs, NSO et objets existants.



## Correction de l'analyse Crash B — 21-11-2026

Le bloc consommateur hôte à main_main_0184.o+.text+0x1952F effectue une consultation avec stride 0x38. Les recherches d'écritures stride 0xE8 concernent une autre piste et ne doivent pas être présentées comme l'origine établie du pointeur fautif. Le QWORD Hunter six objets est déjà terminé ; ne pas le relancer. Les détails et le tableau sont dans docs/CRASH_B_POINTER_PROVENANCE.md.

Des occurrences globales de [rsi+0xD8] dans les chunks reçus montrent des usages de slot/pointeur/cursor et même d'offset DWORD signé dans une autre fonction ; il ne faut pas lui attribuer une sémantique universelle hors de la fonction concernée. Les chunks conservés vont jusqu'à 0x4CC32, sans marqueur de fin de rapport confirmé.


## Détails complets du dernier log NVN/runtime communiqué — 21-11-2026

Le log décrit les probes de fichiers sous les familles `rom:/Engine/.../Nintendo/...`, `rom:/Engine/.../Switch2/...` et `rom:/Orbitals/...`. Les probes `Hardware.ini` et `GameplayTags.ini` listées renvoient `0x202`.

Variables/options observées dans la session NVN replay :
- `ORBITALS_REPLAY_ASYNC=1` ;
- `ORBITALS_REPORT_AT_SUBMIT=1` ;
- `ORBITALS_QUEUE_WAITS` désactivé / census seulement ;
- `ORBITALS_SUBMIT_CATCHUP` ;
- `ORBITALS_REPORT_GPU_END` ;
- thread Vulkan recorder ;
- texture aliases activés ;
- DCC désactivé ;
- staging pool de 2 × 64 MiB conservé ;
- allocation headroom type-1 de 256 MiB (3 observées à ce stade) ;
- 11 allocations d'au moins 32 MiB observées sur d'autres threads.

Appels NVN relevés : `nvnQueueSubmitCommands`, `nvnQueueFlush` et `nvnSyncWait`. Le runtime utilise `ORBITALS_VK_PRESENT=mailbox`. Le log montre une fenêtre noire avec audio audible. Ces détails sont conservés comme observations de runtime et ne sont pas attribués causalement à Crash B.


## Historique des premiers outils Windows et du probe TLS (contexte historique)

Avant la branche d'analyseur 0.4.x–0.5.2 documentée ci-dessus, les échanges ont mentionné :

- un premier Orbitals Crash Analyzer 0.2.0 annoncé comme exécutable Windows x64 autonome d'environ 64,9 MB, centré sur le log et `main`, sans désassemblage SDK ;
- une version 0.3.0 annoncée avec chargement log/`main`/`sdk`, décompression NSO LZ4, fenêtres d'instructions ARM64 et marqueurs TLS (`GetTlsValue` `sdk+0x16B730`, `AllocateTlsSlot` `+0x16B670` / `+0x16CC30`, `SearchUnusedTlsSlotUnsafe` `+0x16C520`, constructeurs `TlsManager` `+0x16C7B0`), export TXT ; ses limites annoncées étaient l'absence d'analyse complète des relocations/symboles ELF et du code hôte généré ;
- un probe C# `OrbitalsTlsCrashProbe` dont un correctif de syntaxe/interpolation a été associé au commit `ab4107c`, mais les six erreurs restantes n'ont pas été confirmées comme résolues dans l'historique consultable.

Ces mentions retracent les annonces et limites des versions de travail ; elles ne certifient pas à elles seules que chaque binaire a été compilé, testé ou distribué. Ne pas confondre ces anciennes versions 0.2.0/0.3.0 avec les versions 0.4.0–0.5.2 du suivi actuel, ni présenter le probe comme validé.
