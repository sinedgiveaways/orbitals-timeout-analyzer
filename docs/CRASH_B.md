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

Le gestionnaire TLS examiné initialise un compteur à 0, un mutex à l'offset `+0x108), réserve 32 entrées de destructeurs et recherche un slot libre parmi les indices 0 à 31. L'allocation appelle `SetZeroToAllThreadsTlsSafe`.

Le pointeur global de constructeur SDK à `sdk+0xE6E010` était nul dans l'image statique ; il peut être initialisé à l'exécution. La valeur statique seule ne suffit pas à conclure à un défaut d'initialisation runtime.

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
2. Quel pointeur exact est contenu à `TPIDRRO_EL0` puis à l'offset `+0x1F8) au moment précis de l'accès ?
3. La base nulle ou invalide vient-elle de l'état invité ou de la traduction hôte ? Les registres hôtes `RCX/R8` n'ont pas été capturés.
4. Le slot TLS est-il invalide, non initialisé, hors plage, ou bien une corruption antérieure a-t-elle détruit un pointeur ?
5. Quelle instruction et quel chemin d'exécution relient exactement `main+0x1759B20` à la lecture fautive ?

## Instrumentation ciblée recommandée

Si l'analyse statique des binaires ne permet pas de trancher, instrumenter seulement les points utiles, sans reconstruire tout le jeu :

### À l'entrée de `main+0x1759B20`
- `x0-x7) ;
- `TPIDR_EL0) ;
- `TPIDRRO_EL0) ;
- pointeur lu à `TPIDRRO_EL0` puis valeur à `+0x1F8`.

### À l'entrée réelle de `GetTlsValue`
- `w0/TlsSlot) ;
- pointeur de base ;
- adresse calculée après `ADD x8, x8, w0, UXTW #3` ;
- valeur du pointeur avant le chargement final à `+0x80`.

### Au PC hôte de l'exception
- `RCX`, `R8`, `RDX), `RAX) ;
- adresse effective calculée pour `[RCX + R8 + 0x5C]`.

Ne pas remplacer une capture manquante par une déduction depuis les registres invités.

## Conclusion actuelle

Le rapport associe le PC hôte `orbitalgame+0x1B5B682F` à la fonction invitée levée `main+0x1759B20`. Le SDK contient un chemin TLS pertinent dans `GetTlsValue`, et des indices runtime montrent des valeurs TPIDR/TLR et des objets thread. **La cause racine n'est pas encore prouvée.** La priorité est de déterminer les valeurs réelles des registres et pointeurs au bon point d'exécution, puis de remonter à l'origine du pointeur invalide.
