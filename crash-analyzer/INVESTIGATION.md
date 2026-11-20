# Orbitals Recomp — dossier de passation et plan de résolution

**Dernière mise à jour : 20 novembre 2026**  
**Dépôt :** `sinedgiveaways/orbitals-timeout-analyzer`  
**But :** permettre à une autre personne ou à une nouvelle session de reprendre l'enquête sans refaire les analyses déjà terminées.

> **Périmètre de cette passation.** Ce document consolide les éléments techniques disponibles dans le dépôt et dans le fil de travail accessible au moment de sa rédaction. Il ne prétend pas reconstituer mot pour mot 43 conversations auxquelles le rédacteur n'a pas accès. Les faits observés, interprétations et tâches non terminées sont séparés explicitement.

---

## 0. État actuel en une minute

- Deux problèmes distincts ont été observés : (A) un `FMallocBinned3 Attempt to free an unrecognized pointer` suivi d'un abort Nintendo ; (B) une access violation hôte lisant `0x104`, dans un chemin invité symbolisé `nn::os::GetTlsValue(TlsSlot)`.
- L'allocateur du jeu a déjà fait l'objet d'une rétro-ingénierie statique substantielle. **Ne pas recommencer cette analyse sans nouvel élément reliant l'allocateur au crash TLS.**
- Le crash prioritaire à résoudre est le crash B : hôte `orbitalgame+0x1b5b682f`, fonction levée `main+0x1759b20`, PC invité `sdk+0x16b730`, LR invité `main+0x175a16c`.
- Le rapport 0.2.0 fourni par l'utilisateur confirme ce crash, mais ne contient pas le désassemblage du module `sdk`.
- L'analyseur WPF 0.2.0 existe et son workflow précédent a réussi. Des corrections de priorité des fenêtres ont été poussées sur `main` le 20 novembre 2026 ; **leur compilation et leur fonctionnement ne sont pas encore vérifiés**.
- La prochaine action est de laisser GitHub Actions compiler ces changements, puis de réanalyser le même `orbitals.log` avec le même `exefs/main`. Ensuite, désassembler avec Capstone/Ghidra les offsets utiles et obtenir le binaire SDK correspondant.

---

## 1. Dépôt, application et artefact connu

Dépôt : https://github.com/sinedgiveaways/orbitals-timeout-analyzer

### Ancienne application à préserver
- `tools/run/timeout_analyzer_gui.py`
- workflow historique : `.github/workflows/build-windows.yml`

Ne pas supprimer ni remplacer cette application lors des modifications du nouvel analyseur.

### Nouvelle application
- Sources : `crash-analyzer/OrbitalsCrashAnalyzer/`
- Dossier de passation : `crash-analyzer/INVESTIGATION.md`
- Guide utilisateur : `crash-analyzer/README.md`
- Workflow : `.github/workflows/build-crash-analyzer.yml`
- Technologie : C# WPF, .NET 10, publication autonome Windows x64 single-file.

### Dernier build précédemment vérifié (avant les corrections du 20 novembre)
- Version : 0.2.0
- Commit : `01491b1967bda81de15fbfb9ecbd6e38d4cff740`
- Run Actions : https://github.com/sinedgiveaways/orbitals-timeout-analyzer/actions/runs/44814038720
- Conclusion : `success`
- Artefact : `OrbitalsCrashAnalyzer-win-x64`
- Artifact ID : `14668807212`
- Taille : 59,393,346 octets
- SHA-256 : `beabba54522bc1e5a879dbf8fc9e8bb4747b54429d09a643c55fcbf89c5cfa9`
- Expiration connue : 2026-12-20.

Lien de téléchargement via la page Actions : ouvrir le run ci-dessus, section **Artifacts**, puis `OrbitalsCrashAnalyzer-win-x64`.

**Important :** cet artefact correspond à l'ancien commit 0.2.0, pas aux trois commits de correction listés dans la section 8. Ne pas le présenter comme contenant les dernières corrections.

---

## 2. Crash B — access violation / TLS (priorité actuelle)

### Données confirmées par le rapport

- Exception : `0xc0000005`.
- Adresse hôte : `00007FF9F51D682F` = `orbitalgame+0x1b5b682f`.
- Instruction hôte (octets) : `42 8b 4c 01 5c 48 85 c9 0f 84 93 f9 ff ff c5 f8`.
- Adresse lue : `0x104`.
- Fonction levée : `f_7001759b20 = main+0x1759b20`.
- PC invité : `0x700a16b730` = `sdk+0x16b730`, étiqueté `nn::os::GetTlsValue(TlsSlot)`.
- LR invité : `0x700175a16c` = `main+0x175a16c`.
- Frames invitées immédiates :
  - frame 0 : `main+0x1750b88`
  - frame 1 : `main+0x1750650`
  - frame 2 : `main+0x1718cf8`
  - frame 3 : `main+0x1d77d64`
  - frame 4 : `main+0x1d761e0`
  - frame 5 : `main+0x1641f84`
  - puis `main+0x32a0c`, `main+0x3348c`, `main+0x4a688`, `main+0x49e90`, `main+0x16198b4`, `main+0x1637dac`, `main+0x1c6ac`, `sdk+0x169630`, `sdk+0x170b78`.
- Thread invité : `0x254CC9A5000`.
- `TPIDR_EL0=0xa2003c740`.
- `TLR=0x7010078000`.
- `TLR[+0x1f8]` : objet thread `0x7c005a038`.
- Registres ARM64 invités communiqués :
  - `x0=0x7009072210`
  - `x1=0x7000737e0`
  - `x2=0xe`
  - `x3=0xb40012c10`
  - `x4=0xb40012c28`
  - `x5=0xb40012c2c`
  - `x6=0x7001582090`
  - `x7=0x18`
  - `x8=0xf1934a1d0`
  - `x9=0x3d`, `x10=0x3c`, `x11=0x38`
  - `x12=1`, `x13=0xb40012a2c`
  - `x14=1`, `x15=1`
  - `x16=0x700900a430`, `x17=0x700a16b730`
  - `x18=0x20`, `x19=0xb40012c10`, `x20=0`
  - `x21=0xb40012810`, `x22=0xfff`
  - `x23=0xf39affa00`, `x24=0x169`, `x25=0xa8`
  - `x26=0x117d0e8a8`, `x27=0x840166c00`, `x28=0xb40012978`
  - `x29=0x117d0e740`, `x30=0x700175a16c`, `sp=0x117d0e680`.

### Lecture de l'instruction hôte

Les cinq premiers octets `42 8B 4C 01 5C` se décodent en x86-64 comme un chargement de type `mov ecx,[rcx+r8+0x5c]`. Avec les registres hôtes communiqués (`RCX=0`, `R8=0xa8`), l'adresse effective est :

```text
0 + 0xa8 + 0x5c = 0x104
```

Ceci explique l'adresse signalée. Le pointeur de base utilisé par cette expression est nul. Cela ne permet pas encore d'identifier le champ source C++ ni de prouver si le défaut est dans l'appelant, la couche TLS ou le code hôte généré.

### Hypothèses encore ouvertes — ne pas les présenter comme des conclusions

1. L'appelant fournit un slot TLS ou un contexte de thread invalide/non initialisé.
2. Le runtime SDK récupère un objet/une structure TLS dont un pointeur interne est nul.
3. La traduction du code invité `GetTlsValue` vers le code hôte a un défaut de mapping de registres, d'ABI ou d'accès mémoire.
4. Le problème est une conséquence d'une corruption antérieure ; aucun élément actuel ne le démontre.

La stabilité des valeurs TPIDR dans la trace ne valide pas les slots TLS. Le fait que `TPIDR_EL0` et l'objet de thread lu via TLR aient des valeurs différentes ne constitue pas, à lui seul, une anomalie.

---

## 3. Crash A — allocateur (investigation déjà réalisée)

Ce crash est distinct du crash TLS. Son message caractéristique est :

```text
FMallocBinned3 Attempt to free an unrecognized pointer %p
```

Il est suivi d'un abort explicite via `nn::diag::Abort`. Ne pas fusionner ces deux événements sans nouvelle preuve.

### Gestionnaire et construction
- Base manager : `0x9072210`.
- Constructeur : `main+0xb6ca0`, appelé au démarrage depuis `main+0x14510` avec `x0=0x9072210`, `x1=0`.
- État heap : `[manager+0x2678]` et `[manager+0x2680]`.
- Global associé : `0x94c08a0`.
- Vtable finale : `0x7f35bc0` ; vtable temporaire : `0x7f36308`.
- Entrées vtable finale :
  - `+0x30` → `0xbb190` allocation
  - `+0x40` → `0xbb2a0` réallocation
  - `+0x50` → `0xbb5e0` libération
  - `+0x68` → `0xbb700` helper taille/classe
  - `+0x70` → `0xbb800` helper métadonnées/requête.
- Slot global du manager : `0x8ff70a80`, distinct de la base `0x9072210`.
- `main+0xc7460` construit les wrappers synchronisés/diagnostiques autour du manager.
- Wrappers externes identifiés : `0xbd950` alloc, `0xbdb40` realloc, `0xbdd70` free.
- `main+0x14550` incrémente un compteur global `0x94b1550` puis dispatch allocate ; `main+0x14580` le décrémente puis dispatch free. Interprétation probable : compteur d'allocations en cours, non confirmée.

### Fonctions d'allocation/libération
- `0xbb190` : allocation ; petits blocs (jusqu'à `0x20000`, alignement au plus `0x10`) via table de classes `0x94c008b0` et caches TLS/thread ; chemin lent `0xb8000`.
- `0xbb2a0` : realloc ; tente les caches ou `0xb8b80`, sinon allocation/copie/libération ; fallback `0xb90e0`.
- `0xb8000` : chemin lent d'allocation, classe, état TLS `0x70c2630`, segment actif `[x25+0x990]==1`, cache par thread, régions et métadonnées.
- Région sous verrou : `manager + 0x70 + (class << 7)`, verrou à `+0x60`.
- Helpers région : `0xb6ad0`, `0xb67a0`, `0xb8760`.
- `0xbb5e0` : dispatch free.
- `0xb8f40` : fast free ; classe, TLS/thread state, caches et slots atomiques partagés.
- `0xb90e0` : fallback free ; recherche la région/métadonnée, vérifie le marqueur live, puis libère la région de backing.

### Table de métadonnées et marqueurs
- `0xb8760` : table de hachage de métadonnées indexée à partir du pointeur et des champs manager `+0x08`, `+0x10`, `+0x18`, `+0x20), base de buckets `[manager+0x60]`.
- Nœud : clé à `+0`, base métadonnées à `+8), liens à `+0x10` et `+0x18`.
- Un nœud dont `+8 == 0` peut être réutilisé.
- `0xbc7e0` initialise les métadonnées avec le marqueur freed `0x39431234`.
- Marqueur live attendu par le chemin free : `0x17EA5678`.
- `0xb91f0` contient le message « Attempt to free an unrecognized pointer » ; chemin associé à `Runtime/Core/Private/HAL/MallocBinned3.cpp`, ligne source rapportée 959.
- `0xb92ac` efface `[node+8]` tout en laissant le nœud chaîné et réutilisable ; cela ne prouve pas une corruption.

### Pages, bitmaps et PLT
- `0x14e80` libère une plage de pages et met à jour la comptabilité.
- `0x14f80` réserve/alloue des pages.
- `0x2a860`, `0x2a300`, `0x2a700` manipulent les plages et compteurs de pages.
- `0xb9720` teste un bit ; `0xb6c20` efface des bits avec propagation hiérarchique ; `0xb86e0` les positionne.
- `0x29dc0` gère des blocs/listes liés.
- Correction PLT importante : `0x70c1ea0`, `0x70c1eb0`, `0x70c1ec0` sont des stubs importés pour `nn::os::TryLockMutex`, `LockMutex`, `UnlockMutex`, pas les fonctions internes de verrouillage.
- Table PLT : relocation à `0x70e94f8`, `DT_PLTGOT=0x9009fe8`, `DT_JMPREL=0x70e94f8`, `DT_PLTRELSZ=0x5bf8`, `DT_SYMTAB=0x7133ff0`, `DT_STRTAB=0x713a590`. Les slots GOT statiques initialisés au resolver ne révèlent pas les cibles runtime finales.

### Conclusion sur le crash allocateur
L'analyse statique explique les structures et les chemins normaux de l'allocateur, mais ne permet pas d'identifier le pointeur précis fautif au moment de l'ancien abort. La présence du motif `0x39431234` dans rodata à `module+0x75c9070` peut être une constante statique ; elle ne prouve pas une libération fautive.

---

## 4. Rapport de crash 0.2.0 reçu le 20 novembre 2026

Fichier analysé :
`C:\Users\mco2v\Downloads\orbitals-recomp\logs\orbitals.log`

- Taille : 1,242,654 octets.
- Lignes : 17,540.
- Date rapport : 2026-11-20 21:49:57.
- NSO : `C:\Users\mco2v\Downloads\orbitals-recomp\exefs\main`.
- Taille NSO : 80,716,406 octets ; flags `0x3f`.
- Segments :
  - text : fichier `0x105`, taille fichier `0x4003B93`, mémoire `0`, taille mémoire `0x70C5B20`, LZ4 ;
  - rodata : fichier `0x4003C98`, taille fichier `0x8B1F07`, mémoire `0x70C6000`, taille mémoire `0xE65F8C`, LZ4 ;
  - data : fichier `0x48B5B9F`, taille fichier `0x4446D7`, mémoire `0x7F2C000`, taille mémoire `0x11433A8`, LZ4.
- La trace TPIDR affiche 125 événements lisibles, 8 threads distincts et 8 valeurs finales distinctes dans l'extrait analysé. Le rapport précise que cela ne prouve ni la validité ni l'invalidité des slots TLS.
- Les fenêtres autour de `main+0x1444C` à `main+0x14D00` et autour d'autres petits offsets montrent notamment du code d'initialisation et des appels runtime/PLT. Cette zone autour de `main+0x14510` avait déjà été identifiée comme appel du constructeur de l'allocateur : ne pas la réanalyser sans raison nouvelle.
- Les recherches de marqueurs sont des recherches d'octets bruts ; une occurrence peut être une donnée/constante.
- Le rapport 0.2.0 est un seul événement TLS confirmé ; ne pas le présenter comme preuve que l'ancien abort allocator a disparu ou a la même cause.

---

## 5. Analyseur WPF — capacités et limites

### Capacités 0.2.0
- Détection de signatures : free inconnu, canary/métadonnée invalide, access violation, abort Nintendo, Vulkan, mentions de threads de rendu.
- Extraction des adresses candidates, registres, PC, LR, TLR, frames et événements TPIDR reconnus par les expressions régulières.
- Lecture NSO `NSO0`, décompression LZ4 des segments text/rodata/data.
- Recherche brute des quatre motifs allocateur : `0x17EA5678`, `0x39431234`, `0x94C008B0`, `0x09072210`.
- Extraction des offsets `main+0x...` depuis le log.
- Fenêtres de mots 32 bits ARM64 autour des offsets et décodage partiel de B/BL/BR/BLR/RET, ADRP, ADD/SUB et LDR/STR.
- Export du rapport texte.

### Limites à garder en tête
- Le décodeur embarqué n'est **pas** un désassembleur ARM64 complet.
- Les fenêtres sont des mots bruts plus quelques catégories de décodage ; elles ne remplacent pas Capstone, Ghidra ou IDA.
- Le fichier `exefs/main` ne contient pas le module `sdk`. L'adresse `sdk+0x16b730` ne peut donc pas être désassemblée depuis ce seul NSO.
- Le rapport actuel ne comprend pas un dump du code hôte généré autour de `orbitalgame+0x1b5b682f`.
- Les motifs hexadécimaux extraits du log sont des candidats, pas nécessairement des pointeurs valides.
- Les symboles `GetTlsValue` et les offsets rapportés sont des symboles/repères de travail ; il faut confirmer avec le binaire et les symboles de la bonne version du SDK.

### Corrections récentes poussées sur main — non encore validées par build
Le code de `MainWindow.xaml.cs` appelle bien `CrashContextAnalyzer.FindMainOffsets(logText)` puis transmet la liste à `NsoAnalyzer.Analyze(...)`. Le tri et la limite de 32 fenêtres se trouvaient dans `NsoAnalyzer`.

Commits du 20 novembre :
1. `de33eee5d888a6657254e6a9ac71a8a97e9a1480` — ordonner les offsets : fonction levée, LR, frames, puis autres offsets.
2. `fb0541ad965e579df2e3700e36e46a7e77a500d0` — ne plus trier numériquement les offsets avant `Take(32)`, ce qui supprimait les adresses hautes prioritaires.
3. `1c183c076477c37ce84d4e998c81799ca6868b82` — convertir le LR absolu `0x700175a16c` en offset `main+0x175a16c`, en utilisant le mapping main `0x7000000000` et la taille text `0x70c5b20`.

Le correctif 3 suppose que le mapping invité de main est bien `0x7000000000`, ce qui correspond aux adresses du rapport. Il faut vérifier dans le nouveau rapport que les fenêtres demandées apparaissent effectivement. Le code n'a pas encore été validé par une compilation après ces changements.

---

## 6. Plan d'action priorisé — objectif : terminer ce soir

### Étape 1 — valider le code (bloquant, immédiat)
1. Ouvrir https://github.com/sinedgiveaways/orbitals-timeout-analyzer/actions.
2. Vérifier le workflow **Build Orbitals Crash Analyzer (Windows)** déclenché par le dernier push sur `main`.
3. S'il est rouge, lire la première erreur de compilation et corriger avant toute autre analyse.
4. S'il est vert, télécharger le nouvel artefact `OrbitalsCrashAnalyzer-win-x64`. Ne pas utiliser l'ancien artefact du run 44814038720 pour tester les corrections.

### Étape 2 — refaire une seule analyse avec les mêmes entrées
1. Lancer le nouvel `OrbitalsCrashAnalyzer.exe`.
2. Charger le même `orbitals.log`.
3. Charger le même `exefs/main`.
4. Analyser et exporter le rapport.
5. Vérifier que les fenêtres suivantes sont présentes, dans cet ordre de priorité :
   - `main+0x1759b20` (fonction levée / site hôte correspondant au code invité)
   - `main+0x175a16c` (LR, extrait du registre x30 absolu)
   - `main+0x1750b88`
   - `main+0x1750650`
   - `main+0x1718cf8`
   - `main+0x1d77d64`
   - `main+0x1d761e0`
   - `main+0x1641f84`.
6. Si elles ne sont pas présentes, corriger l'extraction avant de poursuivre. Ne pas refaire de fenêtres autour des petites adresses de l'allocateur.

### Étape 3 — désassembler le code pertinent de main
1. Utiliser Capstone ARM64 (outil local existant `disasm_fn.py`) ou Ghidra/IDA.
2. Désassembler au minimum les offsets ci-dessus avec assez de contexte pour comprendre les blocs, les appels et les registres. La fenêtre actuelle de 64 octets avant / 32 octets après est un repérage, pas toujours assez pour reconstruire une fonction.
3. Examiner surtout le code qui prépare l'appel dans le chemin qui mène au PC SDK `sdk+0x16b730), le LR `main+0x175a16c`, et les frames 0–2.
4. Relever pour chaque appel : registres x0–x7 avant BL/BLR, valeurs construites par ADRP/ADD/LDR, slot TLS demandé si identifiable, et retour éventuel.
5. Ne pas déduire l'argument de `GetTlsValue` de `x0` sans confirmer l'ABI et les registres au bon point d'appel.

### Étape 4 — obtenir le bon binaire SDK (bloquant pour décoder le PC SDK)
1. Localiser le module `sdk`/NSO ou le binaire correspondant exactement à cette build de jeu/runtime.
2. Obtenir les symboles, map file ou table de symboles correspondant à cette version si disponibles.
3. Désassembler `sdk+0x16b730` et les fonctions voisines, notamment `GetTlsValue`.
4. Identifier les offsets de champs réellement chargés et le registre qui sert de base à l'accès hôte fautif.
5. Si le binaire SDK n'est pas disponible ce soir, documenter précisément ce blocage et terminer l'analyse de l'appelant main sans inventer le corps SDK.

### Étape 5 — départager appelant, SDK et recompilation
- Comparer l'ABI attendue de `nn::os::GetTlsValue(TlsSlot)` avec les registres invités juste avant l'appel.
- Vérifier que la valeur du slot et le pointeur de contexte/thread sont valides à l'entrée.
- Vérifier comment le runtime recompilé représente TPIDR_EL0, TLR et les slots TLS.
- Si les arguments invités sont valides mais que le code hôte utilise une base nulle, isoler un défaut de traduction/runtime.
- Si le pointeur/slot est déjà nul ou invalide à l'entrée, remonter à l'appelant.
- Ajouter une instrumentation ciblée (journaliser le slot, le thread courant, le pointeur de base et le retour) seulement après avoir identifié le chemin exact.
- Reproduire le même crash après chaque changement et comparer les mêmes champs.

### Étape 6 — clôture
- Consigner la conclusion comme **confirmée**, **probable** ou **non résolue**.
- Conserver le rapport avant/après et les hashes des binaires.
- Ne pas annoncer une correction du jeu tant qu'un build du runtime/jeu modifié n'a pas été testé sans le crash.
- Si le crash ne peut pas être résolu faute de binaire SDK/symboles, fournir un rapport de blocage précis plutôt qu'une hypothèse présentée comme une solution.

---

## 7. Fichiers et outils locaux connus

Projet utilisateur :
`C:\Users\mco2v\Downloads\orbitals-recomp`

Entrées :
- `logs\orbitals.log`
- `exefs\main`

Outil de désassemblage Python déjà évoqué :
- `disasm_fn.py`
- Fonction `load(path)` décompresse le NSO et reconstruit l'image.
- Usage connu :
  `python disasm_fn.py <exefs dir> main+0x1759b20 main+0x175a16c ... [--count 300] [--out fn.txt]`

Environnement Windows : exécuter les scripts Python avec l'interpréteur embarqué du projet, et non le Python système :
```powershell
.\setup\python\python.exe .\script.py
```

Éditer les scripts dans Notepad ; ne pas coller du code Python directement dans PowerShell. Pour limiter les erreurs, donner une seule commande PowerShell à la fois.

---

## 8. Règles de reprise — éviter de tourner en rond

1. Ne pas refaire l'analyse de l'allocateur : elle est consignée en section 3.
2. Ne pas confondre le crash allocator abort et le crash access violation TLS.
3. Ne pas considérer les fenêtres `main+0x144xx` comme le cœur du crash TLS : elles correspondent notamment au constructeur allocateur déjà étudié.
4. Ne pas déduire une cause racine à partir de TPIDR stable, d'un marqueur trouvé en rodata ou d'une adresse candidate.
5. Ne pas demander à l'utilisateur de recopier les registres ou les frames déjà consignés ici.
6. Toujours commencer par le dernier rapport et le dernier commit, pas par l'ancien build 0.2.0.
7. Toujours vérifier que l'artefact testé provient du commit contenant les corrections.
8. Une nouvelle analyse doit répondre à une question précise : quel argument/slot/pointeur entre dans GetTlsValue, où devient-il nul, et à quelle couche le défaut apparaît ?

## 9. Sources de référence

- Dépôt : https://github.com/sinedgiveaways/orbitals-timeout-analyzer
- Workflow build : https://github.com/sinedgiveaways/orbitals-timeout-analyzer/actions/workflows/build-crash-analyzer.yml
- Ancien run 0.2.0 vérifié : https://github.com/sinedgiveaways/orbitals-timeout-analyzer/actions/runs/44814038720
- Commit priorité offsets : https://github.com/sinedgiveaways/orbitals-timeout-analyzer/commit/de33eee5d888a6657254e6a9ac71a8a97e9a1480
- Commit ordre des fenêtres : https://github.com/sinedgiveaways/orbitals-timeout-analyzer/commit/fb0541ad965e579df2e3700e36e46a7e77a500d0
- Commit LR absolu : https://github.com/sinedgiveaways/orbitals-timeout-analyzer/commit/1c183c076477c37ce84d4e998c81799ca6868b82
