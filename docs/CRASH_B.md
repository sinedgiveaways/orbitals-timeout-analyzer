# Crash B — accès mémoire 0x104 / chemin TLS

Dernière mise à jour : 2026-11-21  
Statut : **priorité active — cause racine non déterminée**.

## Symptôme et classification

Crash B est l'accès mémoire invalide lors d'un chemin lié au TLS, avec lecture signalée à l'adresse **`0x104`** dans `nn::os::GetTlsValue(TlsSlot)` / le chemin d'exécution associé.

Il faut conserver la distinction entre :
- le PC hôte où l'exception Windows se produit ;
- la fonction invitée ARM64 levée/recompilée à laquelle le runtime associe ce PC ;
- la fonction SDK `GetTlsValue`, qui est un point d'intérêt du chemin TLS, mais dont l'exécution directe au PC fautif n'est pas démontrée.

## Rapport de crash

Rapport d'analyse connu : **ORBITALS CRASH ANALYZER 0.5.0**, fourni dans le fichier utilisateur `OrbitalsCrashReport_TLS(2).txt`.

Constantes relevées dans les rapports successifs :

- taille du log : **1 242 654 octets** ;
- nombre de lignes : **17 540** ;
- dernière zone d'intérêt : autour de la ligne **17 376** ;
- PC hôte observé selon les runs :
  - `orbitalgame+0x1B5B682F`
  - autre base ASLR : `orbitalgame+0x1B5B682F` (adresse absolue variable selon le chargement).

Instruction hôte rapportée autour de l'exception :

`42 8B 4C 01 5C 48 85 C9 ...`

Les cinq premiers octets se décodent en instruction x86-64 :

`mov ecx, [rcx + r8 + 0x5C]`

La lecture signalée est `0x104`. **Les valeurs de RCX et R8 au moment de l'exception ne sont pas capturées dans le rapport disponible.** Il ne faut donc pas affirmer que RCX vaut zéro ni déduire une valeur de R8.

## Corrélation hôte / invité / SDK

| Niveau | Adresse / symbole | Interprétation |
|---|---|---|
| PC hôte | `orbitalgame+0x1B5B682F` | Adresse de l'exception dans le processus hôte |
| Fonction invitée levée | `main+0x1759B20` / `f_7001759b20` | Fonction recompilée associée au PC hôte dans le rapport |
| Site d'appel invité | `main+0x1750B84` | Instruction `BL` vers `main+0x1759B20` ; retour à `main+0x1750B88` |
| Fonction SDK d'intérêt | `sdk+0x16B730` | `nn::os::GetTlsValue(TlsSlot)`; pas prouvée comme PC direct du crash |

Cette séparation est fondamentale : le PC hôte ne doit pas être présenté comme l'adresse ARM64 invitée, et la présence de `GetTlsValue` dans l'enquête ne prouve pas qu'il s'agit de la fonction directement fautive.

## Fonction invitée et site d'appel

- Site d'appel : `main+0x1750B84`, instruction `BL main+0x1759B20`.
- Adresse de retour : `main+0x1750B88`, relevée dans la pile invitée.
- Fonction appelée : `main+0x1759B20`, identifiée dans le rapport comme fonction levée `f_7001759b20`.
- Prologue/zone initiale déjà examinée :
  - `D503237F`
  - `D10483FF`
  - `B9420008`
  - `FD005BE8`
  - `A90C7BFD`

Le chemin d'appel observé ne démontre pas à lui seul un appel direct à `sdk+0x16B730`.

## Pile invitée rapportée

Une pile relevée dans un rapport antérieur contenait notamment les frames suivantes :

`main+0x175A16C`  
`main+0x1750B88`  
`main+0x1750650`  
`main+0x1718CF8`  
`main+0x1D77D64`  
`main+0x1D761E0`  
`main+0x1641F84`  
`main+0x32A0C`  
`main+0x3348C`  
`main+0x4A688`  
`main+0x49E90`  
`main+0x16198B4`  
`main+0x1637DAC`  
`main+0x1C6AC`  
`sdk+0x169630`  
`sdk+0x170B78`

Cette pile est un relevé historique ; elle ne doit pas être interprétée comme une preuve que chaque frame est directement impliquée dans l'accès fautif.

## Implémentation SDK de GetTlsValue

Adresse : `sdk+0x16B730`.

Séquence ARM64 observée :

1. `MRS x8, TPIDRRO_EL0`
2. `LDR x8, [x8, #0x1F8]`
3. `ADD x8, x8, w0, UXTW #3`
4. `LDR x0, [x8, #0x80]`
5. `RET`

Lecture conceptuelle : le code lit le pointeur TLS/thread via `TPIDRRO_EL0`, récupère le pointeur de thread à l'offset `0x1F8`, indexe une table par le slot `w0` (multiplié par 8), puis lit une valeur à l'offset `0x80`.

Cela rend la valeur de `w0/TlsSlot` et les pointeurs intermédiaires essentiels à capturer. Cette séquence SDK n'établit pas que l'exception hôte provient directement de cette fonction.

## Éléments runtime capturés

Un extrait récent indique :

- `GetTlsValue entry: no entry captured for thread=0x2e1c6d9d880`
- `TPIDR_EL0=0xa2003c740`
- `TLR=0x7010078000`
- `TLR[+0x1f8] current-thread object=0x7c0054038`
- chaîne x27 :
  - `x27=0x840180400`
  - `[x27]=0`
- thread invité : `0x2e1c6d9d880`

Autres runs / anciennes captures :
- thread `0x254cc9a5000`, même `TPIDR_EL0=0xa2003c740`, `TLR[+0x1F8]=0x7c005A038` ;
- thread `0x1B733654D00`, mêmes valeurs TPIDR/TLR rapportées et objet `0x7C005A038`.

Une trace TPIDR plus ancienne comptait environ **1 042 213 événements** et **8 threads**.

Attention : ces valeurs sont des observations provenant de moments/logs distincts. Leur proximité dans le dossier ne prouve pas qu'elles ont toutes été échantillonnées au même instant que l'exception.

## Gestionnaire TLS et slot global

Fonctions SDK examinées :

| Fonction | Adresse SDK |
|---|---:|
| `AllocateTlsSlot` (wrapper) | `sdk+0x16B670` |
| `GetTlsValue` | `sdk+0x16B730` |
| `SearchUnusedTlsSlotUnsafe` | `sdk+0x16C520` |
| Constructeurs `TlsManager` | `sdk+0x16C7B0` |
| `TlsManager::AllocateTlsSlot` | `sdk+0x16CC30` |

Autres observations :
- global TLS slot : `main+0x8FF78F8` ;
- cellule associée : `main+0x90100F8` ;
- valeur statique initiale de la cellule : `0xFFFFFFFF` ;
- appel d'initialisation repéré à `main+0x14090` ;
- destructeur repéré à `main+0x1A820` ;
- fonctions `main+0xBF5A0` et `main+0xBF540` chargent `w0` depuis `main+0x90100F8`, puis appellent `GetTlsValue` via PLT.

Le gestionnaire TLS examiné initialise un compteur à 0, un mutex à l'offset `+0x108`, réserve 32 entrées de destructeurs et recherche un slot libre parmi les indices 0 à 31. L'allocation appelle `SetZeroToAllThreadsTlsSafe`.

Le pointeur global de constructeur SDK à `sdk+0xE6E010` était nul dans l'image statique ; il peut être initialisé à l'exécution. La valeur statique seule ne suffit pas à conclure à un défaut d'initialisation runtime.

## Analyse statique de provenance — objet COFF main_main_0184.o (21-11-2026)

Un rapport de l'analyseur Windows a été produit sur le fichier existant :

`setup-work/obj/main_main_0184.o`

Aucune préparation, génération ou recompilation du jeu n'a été nécessaire pour cette analyse. Le fichier est un objet COFF x64 (`Machine=0x8664`) ; sa section `.text` brute fait `0x55C4F` octets. La fenêtre étudiée est `0x189A0–0x19550`, avec instruction de crash à l'offset objet `0x1952F`.

### Construction du pointeur conservé dans [rsi+0xD8]

Le chemin statique local contient :

```asm
0x18F09: mov r9, qword ptr [rsi + 0xa8]
0x18F4A: mov rax, qword ptr [r9 + 0x158]
0x18F51: imul r8, r8, 0xe8
0x18F58: lea rcx, [rax + r8]
0x18F5C: mov qword ptr [rsi + 0xd8], rcx
```

Interprétation limitée à ce qui est directement visible : `[rsi+0xD8]` reçoit l'adresse calculée comme `base + index*0xE8`, où la base provient du pointeur situé à `[ [rsi+0xA8] + 0x158 ]`. Cela désigne un élément dans une structure parcourue avec un pas de `0xE8`. Le type et la signification métier de cette structure ne sont pas encore connus.

### Chemin de déréférencement fautif

Le bloc de secours contient :

```asm
0x19507: mov rax, qword ptr [rsi + 0xd8]
0x1950E: mov rcx, qword ptr [rax]
0x19511: mov qword ptr [rsi + 0x58], 0x38
0x19519: mov eax, 2
0x1951E: sub eax, edx
0x19520: imul r8, rax, 0x38
0x19524: lea r9, [rcx + r8]
0x19528: mov qword ptr [rsi + 0xc8], r9
0x1952F: mov ecx, dword ptr [rcx + r8 + 0x5c] ; instruction fautive
```

Le point important est la double indirection : le code charge d'abord le pointeur `[rsi+0xD8]`, puis lit le premier qword de l'élément pointé (`mov rcx,[rax]`). L'accès fautif suivant utilise ce qword comme base. Si ce premier champ vaut zéro, l'adresse effective devient `0 + R8 + 0x5C`. La lecture à `0x104` est donc compatible avec une base nulle et un déplacement combiné de `0xA8` (par exemple `R8=0xA8)), mais cela ne suffit pas à établir à lui seul que ces registres appartiennent exactement à cette occurrence d'instruction.

**Conclusion statique solide :** le chemin de secours déréférence le premier qword de l'élément sélectionné, puis accède à un champ situé à `+R8+0x5C`. Un premier qword nul explique directement une lecture proche de zéro telle que `0x104`. Le pointeur `[rsi+0xD8]` lui-même n'est pas nul sur ce chemin, car le chargement de son premier qword a lieu avant l'accès fautif.

### Deux conditions d'entrée dans le bloc de secours

Le graphe de contrôle local identifie deux branches directes vers `0x19507` :

- `0x19473: je 0x19507` : le compteur de la collection lu à `[collection+0x470]` est nul ;
- `0x194A4: je 0x19507` : le parcours atteint la condition terminale `0x50` sans avoir trouvé de correspondance.

Le rapport local indique que l'unique écriture directe de `[rsi+0xD8]` pouvant atteindre ce bloc dans le CFG analysé est celle de `0x18F5C`. C'est une analyse locale et conservatrice : elle ne suit pas les alias mémoire, les appels inter-fonctions ni les branches indirectes. Elle ne prouve donc pas que tous les chemins d'exécution ont nécessairement exécuté cette écriture.

### Ce qui reste à déterminer

1. Quelle des deux branches vers `0x19507` est prise au runtime ?
2. Quel est le premier qword de l'élément `0xE8) au moment où il est sélectionné ?
3. Où et quand ce premier qword est-il initialisé ou écrit ?
4. Quelle fonction construit/remplit la collection accessible via `[rsi+0xA8]`, avec les champs `+0x468` (pointeur de données) et `+0x470` (compteur) ?
5. L'index utilisé dans le calcul `base + index*0xE8` sélectionne-t-il un élément valide dans tous les cas ?

La prochaine analyse doit donc rechercher les écritures au début des éléments de pas `0xE8` et remonter à la construction/remplissage de cette collection, en inspectant les objets déjà présents dans `setup-work/obj`. Il ne faut pas relancer `prepare.py` ni reconstruire le jeu pour cela.

## Binaire et structure

- NSO `main` : taille fichier **80 716 406 octets**.
- TEXT main : `0x70C5B20` octets.
- rodata : adresse mémoire `0x70C6000`, taille `0xE65F8C`.
- data : adresse mémoire `0x7F2C000`, taille `0x11433A8`.
- `sdk` : taille fichier **7 759 642 octets**.
- TEXT SDK décompressé : `0x879B50`.
- fenêtre `GetTlsValue` examinée : `sdk+0x16B6D0` à `sdk+0x16B790`.

## Questions encore ouvertes

1. Quelle est la vraie valeur de `w0/TlsSlot` à l'entrée effective de `GetTlsValue` au moment du crash ?
2. Quel pointeur exact est contenu à `TPIDRRO_EL0` puis à l'offset `+0x1F8` au moment précis de l'accès ?
3. La base nulle ou invalide vient-elle de l'état invité ou de la traduction hôte ? Les registres hôtes `RCX/R8` n'ont pas été capturés de façon synchronisée avec l'instruction objet examinée.
4. Le slot TLS est-il invalide, non initialisé, hors plage, ou bien une corruption antérieure a-t-elle détruit un pointeur ?
5. Quelle instruction et quel chemin d'exécution relient exactement `main+0x1759B20` à la lecture fautive ?
6. Quel code initialise le premier qword des éléments de la collection de stride `0xE8` ?

## Instrumentation ciblée recommandée

Si l'analyse statique des binaires ne permet pas de trancher, instrumenter seulement les points utiles, sans reconstruire tout le jeu :

### À l'entrée de `main+0x1759B20`
- `x0-x7` ;
- `TPIDR_EL0` ;
- `TPIDRRO_EL0` ;
- pointeur lu à `TPIDRRO_EL0` puis valeur à `+0x1F8`.

### À l'entrée réelle de `GetTlsValue`
- `w0/TlsSlot` ;
- pointeur de base ;
- adresse calculée après `ADD x8, x8, w0, UXTW #3` ;
- valeur du pointeur avant le chargement final à `+0x80`.

### Au PC hôte de l'exception
- `RCX`, `R8`, `RDX`, `RAX` ;
- adresse effective calculée pour `[RCX + R8 + 0x5C]`.

Ne pas remplacer une capture manquante par une déduction depuis les registres invités.

## Conclusion actuelle

Le rapport associe le PC hôte `orbitalgame+0x1B5B682F` à la fonction invitée levée `main+0x1759B20`. Le SDK contient un chemin TLS pertinent dans `GetTlsValue`, et des indices runtime montrent des valeurs TPIDR/TLR et des objets thread. L'analyse du COFF `main_main_0184.o` affine désormais le mécanisme mémoire : le bloc de secours sélectionne un élément de stride `0xE8`, charge son premier qword comme pointeur, puis le déréférence à l'offset `+R8+0x5C`. **La cause racine n'est toujours pas prouvée** : il faut encore identifier la branche runtime empruntée et le code qui initialise ce premier qword.


## Compléments d'analyse SDK TLS — extraits du 21-11-2026

Cette section ajoute les résultats des inspections SDK faites après la première rédaction du rapport. Elle sépare les faits confirmés des limites des extraits récupérés.

### Import de `AllocateTlsSlot` depuis main

Le code d'initialisation de `main` contient le passage d'adresse suivant :

```asm
0x14068: adrp x0, #0x9010000
0x1406C: add  x0, x0, #0xf8       ; x0 = 0x90100F8
0x14074: adr  x1, #0x1a820
0x14090: bl   #0x70c2160
```

La relocation GOT à `main+0x900A1C8` est de type `1026` (`0x402`), addend `0`, symbole :

`_ZN2nn2os15AllocateTlsSlotEPNS0_7TlsSlotEPFvmE`

Nom démanglé : `nn::os::AllocateTlsSlot(nn::os::TlsSlot*, void (*)(void*))`.

Le trampoline appelé à `main+0x70C2160` charge la cible depuis la GOT `0x900A1C8`. Le code d'initialisation passe donc l'adresse `0x90100F8` comme premier argument à l'import `AllocateTlsSlot`, et l'adresse `main+0x1A820` comme second argument. Cela confirme le rôle d'enregistrement d'un slot TLS avec callback dans cette séquence ; cela ne prouve pas encore que l'allocation ou l'initialisation échoue au runtime.

La cellule `main+0x90100F8` a été observée avec une valeur statique initiale `0xFFFFFFFF`. Cette valeur est compatible avec une sentinelle « slot non encore attribué », mais cette interprétation reste une hypothèse tant que le comportement runtime n'est pas capturé.

### Autres imports TLS et relocations GOT

Les relocations GOT suivantes ont été relevées comme type `1026` (`0x402`) avec addend nul :

| GOT main | Symbole |
|---:|---|
| `0x900A1C8` | `_ZN2nn2os15AllocateTlsSlotEPNS0_7TlsSlotEPFvmE` |
| `0x900A1D0` | `_ZN2nn2os11GetHostArgcEv` |
| `0x900A1D8` | `strcasecmp` |
| `0x900A1E0` | `_ZN2nn2os11GetHostArgvEv` |
| `0x900A1E8` | `strncasecmp_l` |
| `0x900A1F0` | `atoll` |

La table d'import de `main` comporte 1 041 symboles ; la liste des relocations contient 1 471 402 entrées. Ces chiffres décrivent la structure du binaire analysé, pas un indice de corruption à eux seuls.

### Gestionnaire TLS : recherche de slot libre

La relocation GOT `0xE74F90` du SDK pointe vers :

`_ZNK2nn2os6detail10TlsManager25SearchUnusedTlsSlotUnsafeEb`

La relocation est de type `1026`, addend `0`. L'entrée d'export fournie est :

```text
('_ZNK2nn2os6detail10TlsManager25SearchUnusedTlsSlotUnsafeEb',
 18, 2, 1492256, 644)
```

L'offset décimal `1492256` correspond à `sdk+0x16C520`, avec une taille déclarée de `644` octets (`0x284`).

L'extrait de désassemblage correct de `SearchUnusedTlsSlotUnsafe` a été fourni en deux parties, jusqu'à `sdk+0x16C7AC`. Il montre une recherche de slots libres dans les indices **0 à 31**. Les branches de saturation appellent `sdk+0x852A90`, puis comportent une instruction `udf` si cet appel retourne. La nature exacte du traitement de saturation n'est pas établie ici : `0x852A90` est un trampoline indirect chargeant une cible depuis la zone `0xE71040+`, et la relocation de cette cible n'a pas été documentée dans les extraits disponibles.

**Limite importante :** un premier extrait avait été étiqueté à tort comme provenant de `SearchUnusedTlsSlotUnsafe`, alors qu'il commençait à `sdk+0x16CC80`. L'adresse d'export confirme `sdk+0x16C520` comme adresse correcte de la fonction. Ne pas utiliser le premier extrait mal étiqueté comme preuve de son implémentation.

### Fonctions SDK examinées et limites des extraits

Les adresses suivantes ont été examinées dans les désassemblages fournis :

| Fonction | Adresse SDK | État des éléments conservés |
|---|---:|---|
| `AllocateTlsSlot` (wrapper) | `0x16B670` | Extrait fourni ; le wrapper redirige vers la logique du gestionnaire TLS |
| `GetTlsValue` | `0x16B730` | Séquence décrite plus haut dans ce rapport |
| `SearchUnusedTlsSlotUnsafe` | `0x16C520` | Extrait en deux parties jusqu'à `0x16C7AC` |
| Constructeurs `TlsManager` | `0x16C7B0` | Extrait partiel, interrompu vers `0x16C84C` |
| `TlsManager::AllocateTlsSlot` | `0x16CC30` | Extrait partiel, interrompu vers `0x16CE7C` |
| `SetZeroToAllThreadsTlsSafe` | `0x169A60` | Extrait partiel, interrompu vers `0x169B3C` |
| `ThreadManager::CreateThread` | `0x1693A0` | Zone examinée ; ne suffit pas à reconstituer toute l'initialisation TLS |
| `ThreadManagerImplByHorizon::CreateThread` | `0x1701D0` | Zone examinée ; extrait complet non conservé dans ce rapport |
| Écriture(s) du pointeur de thread courant | `0x1695C0`, `0x170B20` | Zones examinées ; il faut encore corréler leurs effets au thread qui plante |

Le fait que ces fonctions aient été désassemblées ou repérées ne prouve pas qu'elles sont fautives. Les extraits incomplets ne doivent pas être extrapolés.

### Ce que ces nouveaux éléments changent — et ne changent pas

Ils confirment qu'un appel explicite à `nn::os::AllocateTlsSlot` est préparé dans l'initialisation de `main`, avec une cellule globale située à `0x90100F8` et un callback à `main+0x1A820`. Ils documentent également une recherche de slots libres bornée aux indices 0–31 et les points d'entrée SDK impliqués dans l'allocation et l'initialisation TLS.

Ils ne démontrent toujours pas :
1. la valeur runtime de `0x90100F8` après l'appel à `AllocateTlsSlot` ;
2. si l'appel retourne un slot valide ou suit une branche de saturation ;
3. si le callback `main+0x1A820` est exécuté pour le thread qui plante ;
4. si `SetZeroToAllThreadsTlsSafe` initialise correctement l'entrée du thread concerné ;
5. si la lecture à `0x104` provient directement d'un accès TLS ou du chemin de collection décrit dans l'analyse COFF ;
6. quelle instruction relie précisément les observations SDK et le PC hôte de l'exception.

### Prochaines vérifications ciblées

1. Capturer la valeur de la cellule `main+0x90100F8` avant et après l'appel à `AllocateTlsSlot`.
2. Capturer le résultat/slot utilisé par `GetTlsValue` (`w0)) et les pointeurs intermédiaires au même instant.
3. Déterminer si la recherche de slot libre retourne un indice dans `0..31` ou atteint la branche de saturation.
4. Corréler l'appel au callback `main+0x1A820` et le passage dans `SetZeroToAllThreadsTlsSafe` avec le thread fautif.
5. Continuer séparément la recherche des écrivains du premier qword dans les éléments de stride `0xE8` du fichier `main_main_0184.o`.

Ces vérifications doivent réutiliser les binaires et objets déjà présents. Elles ne nécessitent pas de relancer `prepare.py`, la génération ou une recompilation complète.
