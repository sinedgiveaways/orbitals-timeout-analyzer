# Orbitals Recomp — dossier d'investigation

Dernière mise à jour : 2026-11-21  
Dépôt : `sinedgiveaways/orbitals-timeout-analyzer`

## Objectif

Conserver dans le dépôt les faits techniques établis pendant l'analyse des plantages d'Orbitals Recomp, distinguer les observations des hypothèses et éviter de refaire les mêmes recherches. Le dossier est organisé autour de deux incidents indépendants.

- [Crash A — FMallocBinned3 / pointeur non reconnu](CRASH_A.md)
- [Crash B — accès mémoire 0x104 / chemin TLS](CRASH_B.md)
- [Environnement, builds et contraintes de travail](ENVIRONMENT_AND_BUILD.md)



## Analyse des 12 candidats E8

- [Comparaison des 12 candidats d'écriture E8](CRASH_B_CANDIDATES_12.md) — regroupe les instructions reçues, distingue les écritures DWORD des pointeurs QWORD et consigne les vérifications encore nécessaires.

## Priorités

1. **Crash B est la priorité actuelle.** L'accès à `0x104` et le chemin TLS restent à expliquer.
2. **Crash A est suspendu**, pas résolu ni abandonné. Les recherches GOT/PLT déjà faites sont consignées dans son dossier.
3. Ne pas lancer une préparation, génération ou recompilation complète du jeu pour une simple analyse de logs ou de binaires.
4. Ne pas utiliser Ghidra : l'utilisateur ne souhaite pas cet outil.
5. Fournir un analyseur Windows GUI plutôt que multiplier les scripts PowerShell manuels.

## Règles de preuve

- Une adresse hôte (`orbitalgame+0x...`) n'est pas automatiquement une adresse invitée ARM64.
- Une fonction invitée levée par le recompilateur n'est pas automatiquement la fonction SDK dont le nom apparaît dans le dossier.
- Une adresse de trampoline partagée par de nombreuses entrées PLT ne prouve pas quel symbole a déclenché le crash.
- Les valeurs de registres non capturées doivent rester « inconnues » ; ne pas les déduire par supposition.
- Les résultats statiques ne remplacent pas une capture runtime au moment exact de l'exception.

## État synthétique au 2026-11-21

| Sujet | État |
|---|---|
| Crash A : erreur FMallocBinned3 | Identifiée, cause non déterminée |
| Crash A : cartographie PLT / trampoline | Partiellement établie |
| Crash B : PC hôte et fonction invitée levée | Corrélation établie dans le rapport |
| Crash B : GetTlsValue directement fautif | Non démontré |
| Crash B : valeur réelle de TlsSlot au moment du crash | Non capturée |
| Crash B : provenance du pointeur dans l'objet COFF | Première analyse locale effectuée ; champ pointeur nul suspecté dans le bloc de secours |
| Crash B : initialisation du premier qword des éléments de stride 0xE8 | À rechercher |
| Cause racine Crash B | Non déterminée |
| Analyseur Windows | Code 0.5.2 présent sur main ; artifact de cette version à vérifier séparément |

## Dernière avancée Crash B — 21-11-2026

L'analyse statique du fichier existant `setup-work/obj/main_main_0184.o` a localisé :
- l'écriture de `[rsi+0xD8]` à `0x18F5C`, avec une adresse d'élément calculée comme `base + index*0xE8` ;
- le bloc de secours `0x19507`, qui lit le premier qword de cet élément puis utilise ce qword comme base d'une lecture à `[base + R8 + 0x5C]` ;
- deux branches directes vers ce bloc : compteur de collection nul (`0x19473`) ou parcours atteignant la sentinelle `0x50` sans correspondance (`0x194A4`).

Le mécanisme est compatible avec un premier qword nul dans l'élément sélectionné, ce qui explique une lecture proche de zéro telle que `0x104`. Cela ne prouve pas encore quelle branche est prise au runtime, ni où le champ est initialisé. Le détail, les limites du CFG local et les extraits assembleur sont dans [CRASH_B.md](CRASH_B.md).

**État corrigé au 21-11-2026 :** l'analyse des six objets et des 12 candidats a déjà été réalisée. Le QWORD Hunter n'a trouvé aucun store QWORD à displacement zéro dans ces six objets. Ne pas relancer cette étape. La prochaine question n'est plus de refaire ce balayage, mais de corréler les write-through candidats du rapport de provenance avec l'élément extérieur réellement sélectionné au runtime, puis de capturer son premier QWORD au moment du crash.

## Limite de cette sauvegarde

Ce dossier consolide les faits, extraits et conclusions disponibles dans le contexte de travail au moment de sa rédaction. Il ne prétend pas archiver les fichiers de logs binaires complets ni chaque sortie PowerShell historique. Les logs originaux doivent être conservés séparément si l'on veut pouvoir reproduire chaque constat ligne par ligne.


## Compléments SDK TLS ajoutés — 21-11-2026

Le dossier [CRASH_B.md](CRASH_B.md) a été complété avec les derniers résultats confirmés :
- appel d'initialisation de `nn::os::AllocateTlsSlot` via GOT `0x900A1C8`, avec premier argument `0x90100F8` et callback `main+0x1A820) ;
- relocation type `1026` (`0x402`), addend nul, et nom manglé de l'import ;
- relocation/export de `SearchUnusedTlsSlotUnsafe` à `sdk+0x16C520), taille `0x284`, recherche de slots `0..31` ;
- points d'entrée SDK étudiés pour allocation TLS, mise à zéro des TLS de threads et création de threads, avec indication explicite des extraits partiels.

Ces éléments ne déterminent pas encore la cause racine. Les priorités restent la capture runtime du slot TLS avant/après allocation et l'identification des écrivains du premier qword des éléments de stride `0xE8`. Aucun rebuild complet n'est requis pour ces analyses.


## Mise à jour de l'investigation — 21-11-2026

CRASH_B.md intègre désormais les précisions du flux de données dans la boucle de sélection de l'élément 0xE8, les conditions statiques compatibles avec l'adresse 0x104, les hypothèses de concurrence/index/table, les compléments de désassemblage SDK TLS et le dernier runtime noir avec audio et retours 0x202 des probes de fichiers.

Correction importante : l'examen des six objets et des 12 candidats a déjà été réalisé par l'utilisateur. Cette étape est terminée et ne doit pas être redemandée. Les instructions connues sont des écritures DWORD ; elles ne désignent pas à elles seules l'écrivain du pointeur QWORD à l'offset +0. Les sorties complètes de chaque fonction candidate ne sont pas toutes archivées ici ; ne pas inventer leur conclusion.

La cause racine de Crash B reste non déterminée. Les preuves manquantes sont la branche runtime vers le bloc de secours, les registres hôtes synchronisés au PC fautif, le premier QWORD de l'élément choisi au moment précis du crash et l'état runtime du slot TLS. Toute analyse supplémentaire doit réutiliser les fichiers déjà extraits, sans prepare.py, génération ni recompilation complète.



## Errata et résultats QWORD Hunter — 21-11-2026

Une correction importante est apportée : le consommateur exact du crash dans main_main_0184.o (.text+0x1952F) utilise un stride **0x38**, et non 0xE8. Il charge [rsi+0xD8], puis le premier QWORD pointé, avant de lire [rcx+(2-edx)*0x38+0x5C]. Le modèle corrigé est celui de deux strides imbriqués : sélection de l'enregistrement extérieur à stride 0xE8, puis lecture de sa structure intérieure à stride 0x38. Le scan des six objets cherchait notamment le writer du premier QWORD extérieur ; aucun writer correspondant n'a été identifié dans ces six fichiers. Voir le rapport ciblé [CRASH_B_POINTER_PROVENANCE.md](CRASH_B_POINTER_PROVENANCE.md).

Le QWORD Hunter sur les six objets est terminé : 0156.o 7 stores stride-E8 / 6 QWORD / 0 disp0 ; 0157.o 3/0/0 ; 0173.o 5/0/0 ; 0184.o 2/0/0 ; 0186.o 3/0/0 ; 0330.o 2/0/0. Aucun store QWORD détecté à displacement zéro d'un élément stride-E8. Cela ne trouve pas le producteur du pointeur consommé à 0x1950E.

Les chunks de provenance [rsi+0xD8] contiennent des write-through et reloads à 0x24745, 0x350F3–0x3816D, 0x38309–0x388C7, 0x39191–0x47095, 0x39DEF, 0x439AF et 0x4CC32. Ils montrent plusieurs usages (dont offset signé dans une autre fonction), sans prouver l'identité du pointeur sur le chemin fautif. Les données reçues vont jusqu'à 0x4CC32 ; aucun « FIN DU RAPPORT » n'a été confirmé.

Le rapport principal demandé est court (1–3 pages) et centré sur les écritures de [rsi+0xD8], l'origine du pointeur chargé, les écritures du premier QWORD et les anomalies ; les détails secondaires restent séparés. Ne pas refaire l'étape des six objets.


## Clarification des strides — 21-11-2026

Les strides 0xE8 et 0x38 ne sont pas contradictoires : [rsi+0xD8] désigne un enregistrement extérieur sélectionné avec stride 0xE8 (écriture à 0x18F5C). Le premier QWORD de cet enregistrement fournit la base d'une structure intérieure, consultée à 0x1952F avec stride 0x38 et champ +0x5C. Le scan QWORD six objets cherchait donc notamment le writer du premier QWORD extérieur ; aucun store QWORD displacement 0 n'a été trouvé dans ces six fichiers. Voir le rapport ciblé pour la chaîne complète.


## Compléments archivés — 21-11-2026

Le rapport ciblé documente aussi les écritures PTR_FROM_RSI_D8 aux offsets +0x10/+0x18/+0x20/+0x28/+0x30/+0x38/+0x58/+0x60, deux écritures potentielles à offset zéro (0x24745 et 0x3816D) non corrélées au record du crash, et l'usage scalaire signé de [rsi+0xD8] à 0x4CC32. Le dernier log runtime est maintenant détaillé dans ENVIRONMENT_AND_BUILD.md : flags NVN, recorder, texture aliases, DCC, staging pool, allocations headroom et probes romfs.


## Détails exacts retrouvés — QWORD Hunter 0156.o (21-11-2026)

Le rapport utilisateur identifie six stores QWORD dans `main_main_0156.o` : `[r15+rbx+0x78]=0`, `+0x80=rax`, `+0xB8=0`, `+0xC0=rax`, `+0xC8=0`, `+0xD0=rax`. L'origine rapportée de `r15` est `203295`. `[rsi+0x230]` alimente les valeurs QWORD écrites à `+0x80`, `+0xC0` et `+0xD0`. Contexte voisin : `0x31C1C` lit un octet à `[r15+rbx+0xD8]`, `0x31C25` charge `[rsi+0xD8]`, et `0x31C3A` teste `[rdx+0x40]` avant de recharger `[rsi+0x58]` sur le chemin alternatif. Deux adresses de stores sont confirmées (`0x31AD2`, `0x31AFE`) ; les quatre autres offsets d'instruction exacts ne sont pas récupérés avec certitude. Aucun de ces six stores n'écrit le premier QWORD à displacement zéro.


## Points historiques à ne pas perdre — TLS manager et outils (21-11-2026)

- Le wrapper TLS a été décrit comme calculant le manager depuis le global `sdk+0xE6E010`, puis `+0x310`. Le premier scan global/constructeur n'a rien trouvé ; un scan de suivi instruction-par-instruction sur 4 octets a été proposé après une réserve sur l'arrêt anticipé possible de `md.disasm`, mais aucun résultat de suivi n'est conservé. Le zéro statique ne prouve pas un pointeur nul runtime.
- Valeurs de comparaison précédemment demandées pour l'entrée `GetTlsValue` : `RCX=0`, `R8=0xA8`, `TPIDR_EL0=0xA2003C740`, `TLR=0x7010078000`. Ne pas les présenter comme une capture simultanée au crash.
- L'historique mentionne les premiers outils Windows 0.2.0/0.3.0 et le probe `OrbitalsTlsCrashProbe` (commit correctif `ab4107c`, six erreurs restantes non confirmées résolues). Ce sont des annonces/états de travail, pas une preuve de build/test réussi. Voir `docs/ENVIRONMENT_AND_BUILD.md`.


## Audit de cohérence — corrections du 21-11-2026

Une relecture croisée du dépôt a révélé deux formulations historiques contradictoires dans cet index. Elles sont corrigées ici :

1. La phrase antérieure affirmant que « l'analyse ARM64 de collection stride-0xE8 reste distincte et n'est pas reliée à ce chemin » est trop catégorique. Le modèle actuellement retenu est celui de **deux strides imbriqués** : l'élément extérieur est sélectionné à stride `0xE8`, son premier QWORD fournit la base de la structure intérieure consultée à stride `0x38`. Le lien structurel est donc présent dans l'analyse statique ; ce qui n'est pas prouvé est que les objets/fonctions producteurs étudiés soient bien ceux de l'instance runtime fautive.
2. L'ancienne recommandation de rechercher encore les écritures QWORD dans les six objets est obsolète. Le QWORD Hunter sur les six objets et les 12 candidats est **terminé** ; ne pas refaire cette étape. Il n'a trouvé aucun store QWORD à displacement zéro dans ces six fichiers.

Le détail historique complet de l'allocateur, omis de la première version de `CRASH_A.md`, a été ajouté dans ce dernier document. Le dossier de passation `crash-analyzer/INVESTIGATION.md` est conservé comme historique du 20 novembre ; ses anciennes étapes (Ghidra, analyse 0.2.0, reprise du scan des six objets) ne remplacent pas les consignes actuelles de cet index.

### Builds Windows vérifiés dans GitHub Actions

- Analyseur WPF : run [44867261298](https://github.com/sinedgiveaways/orbitals-timeout-analyzer/actions/runs/44867261298), succès, commit `b5c72fac2bf1a5c59a83ce8b2da5fa1d377773f6`, artifact `OrbitalsCrashAnalyzer-win-x64`, ID `14691748393`, 59,409,094 octets, expiration `2026-12-21`.
- Outils Pointer Provenance + rapport fallback : run [44951389432](https://github.com/sinedgiveaways/orbitals-timeout-analyzer/actions/runs/44951389432), succès, commit `b9486a273e35a0b1b87857f183e1f366ba0cbd48`, artifact ID `14726090607`, 24,905,547 octets.
- QWORD Writer Hunter : run [44941325433](https://github.com/sinedgiveaways/orbitals-timeout-analyzer/actions/runs/44941325433), succès, commit `0634c2905f457d09d9280bc657fc318c7155e9d9`, artifact ID `14721153910`, 12,454,478 octets.

Les trois runs et leurs jobs ont été relus : statut `success`. Les commits de documentation postérieurs n'ont pas modifié le code de ces exécutables ; cela ne signifie pas que les dernières sources de l'analyseur ont été recompilées sur le dernier commit documentaire.


## Corrélation binaire/runtime du 22-11-2026

Un nouveau rapport et les binaires `main` / `sdk` ont été analysés. Le rapport détaillé est [CRASH_B_RUNTIME_2026-11-22.md](CRASH_B_RUNTIME_2026-11-22.md). Points majeurs :

- Le crash du build `0.2.0-g77add3c` montre `RCX=0`, `R8=0xA8`, `RDX=0xFFFFFFFF`, lecture `0x104`, et `x27=0x84017bc00` avec `[x27]=0`.
- Le désassemblage du binaire `main` confirme le calcul de `x27 = [x21+0x158] + w20*0xE8`, puis le chargement du premier QWORD et la lecture interne à stride `0x38`, champ `+0x5C` (instruction finale à `main+0x175A030`).
- `x27) est calculé dans la fonction `main+0x1759b20` elle-même ; ne pas attribuer sa construction uniquement aux frames appelantes.
- La page `0x84017b000) contenant le record a été allouée. Cela ne révèle pas le writer du premier QWORD.
- `main+0x1784920 / 0x1784ac0` contient un chemin de création/copie E8 qui peut initialiser les 16 premiers octets / copier `0xE0` octets, mais son lien avec le conteneur runtime fautif reste à prouver.
- Le champ `pc=sdk+0x16b730` du reporter est en désaccord avec les octets hôtes et le code ARM64 consommateur. Garder cette anomalie ouverte ; ne pas conclure que `GetTlsValue` est directement fautif.

**Suite immédiate :** ajouter une capture bornée de `[x21+0x158]`, `w20`, `w8), `x27` et d'un dump de `0x100) octets à `x27`, puis corréler le writer du premier QWORD. Ne pas modifier `thr_new()`, ne pas refaire les six scans QWORD et ne pas lancer de rebuild complet.


### Erratum registres — 22-11-2026

Le journal contient deux snapshots séparés : hôte (`RCX=0`, `R8=0xA8), `RDX=0xFFFFFFFF`) et invité (`x20=0`, `x21=0xB40012810`, `x25=0xA8), `x27=0x84017BC00`, `x8=x9=0x3D`, `x3=0xFFFFFFFF`). Aucun mapping hôte↔invité synchronisé n'est établi. Ne pas déduire `w8=-1) de `RDX=-1). La prochaine capture doit être prise au PC invité réel du chemin main, séparément d'une capture à l'entrée GetTlsValue. Détails dans `CRASH_B_RUNTIME_2026-11-22.md`.
