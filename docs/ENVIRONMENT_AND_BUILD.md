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
