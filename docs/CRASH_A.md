# Crash A — FMallocBinned3 / pointeur non reconnu

Dernière mise à jour : 2026-11-21  
Statut : **investigation suspendue** pendant que Crash B est prioritaire.

## Symptôme

Crash A est le plantage associé à l'erreur mémoire de `FMallocBinned3` décrite comme **`unrecognized pointer`**.

Une adresse de trampoline observée pendant les investigations GOT/PLT est :

- `main+0x70C1DB0` (souvent rapportée sous la forme `0x70c1db0`).

Cette adresse est un point technique observé dans le chemin PLT/trampoline. Elle ne constitue pas, à elle seule, l'identification du symbole fautif.

## Faits établis sur la PLT

- Zone PLT observée : `main+0x900A000` à environ `main+0x900A5BF8`.
- Nombre d'entrées `R_AARCH64_JUMP_SLOT` relevé : **981**.
- Ces entrées étaient initialisées vers la même adresse de trampoline : `0x70C1DB0`.
- Une table interne commençant vers `main+0x900B528` a été relevée avec **188 entrées** pointant vers ce même trampoline.

Quelques entrées de stub identifiées :

| Symbole | Adresse observée |
|---|---:|
| `AbortImpl` | `main+0x900A050` |
| `TryLockMutex` | `main+0x900A068` |
| `LockMutex` | `main+0x900A070` |
| `UnlockMutex` | `main+0x900A078` |
| `SetAllocator` | `main+0x900A090` |

Les adresses ci-dessus sont les adresses de stubs/slots observées dans la PLT, pas la preuve qu'un de ces symboles a causé l'erreur.

## Ce que cela démontre — et ne démontre pas

Cela démontre qu'un grand nombre d'entrées PLT partagent un même trampoline initialisé. Cela ne démontre pas :

- que `AbortImpl` est appelé ;
- que l'appel fautif est un appel d'allocation ou de libération ;
- que le trampoline lui-même corrompt le pointeur ;
- quel pointeur exact `FMallocBinned3` a rejeté ;
- si le pointeur était déjà corrompu avant l'appel à l'allocateur.

L'utilisateur a explicitement signalé qu'un trampoline partagé ne suffit pas à conclure qu'`AbortImpl` est le responsable. Cette réserve doit être respectée.

## Informations binaires générales disponibles

Binaire `main` NSO observé :

- taille du fichier : **80 716 406 octets** ;
- segment TEXT en mémoire : `0x70C5B20` octets ;
- rodata en mémoire à `0x70C6000`, taille `0xE65F8C` ;
- data en mémoire à `0x7F2C000`, taille `0x11433A8` ;
- le point de crash du Crash B est `main+0x1B5B682F`, distinct de la piste Crash A.

Ces données binaires sont consignées comme contexte du même exécutable ; elles ne localisent pas encore le pointeur invalide du Crash A.

## Inconnues restantes

1. Quel appel exact conduit à l'erreur `FMallocBinned3` ?
2. Quelle valeur de pointeur est rejetée ?
3. Quelle est la pile d'appels invitée et hôte au moment de l'erreur ?
4. Le pointeur vient-il d'une mauvaise résolution d'import, d'une allocation/libération incorrecte, d'un décalage d'adresse ou d'une corruption antérieure ?
5. Quelle entrée PLT est effectivement utilisée sur le chemin fautif ?

## Prochaine reprise recommandée

Quand Crash B sera suffisamment avancé :

1. repartir du log original du Crash A et extraire le message complet, les registres et la pile au moment exact de l'erreur ;
2. identifier le pointeur rejeté et son allocation/provenance si le runtime peut le journaliser ;
3. suivre l'entrée PLT réellement empruntée, au lieu de déduire le symbole à partir du trampoline partagé ;
4. corréler le symbole avec les relocations et la fonction appelante ;
5. ne modifier la résolution GOT/PLT qu'après avoir isolé un chemin fautif reproductible.

**Conclusion actuelle :** le Crash A est caractérisé au niveau du symptôme et d'une partie de la structure PLT, mais sa cause racine et sa correction ne sont pas connues.


## Complément de rétro-ingénierie de l'allocateur (dossier de passation du 20-11-2026)

Les éléments suivants avaient été consignés dans le dossier de passation historique mais n'étaient pas repris dans ce rapport dédié. Ils décrivent le fonctionnement statique observé ; ils ne désignent pas le pointeur fautif du crash.

### Gestionnaire et dispatch

- Base du manager observée : `0x9072210`, constructeur `main+0xB6CA0`, appelé au démarrage depuis `main+0x14510` avec `x0=0x9072210`, `x1=0`.
- État heap : champs `[manager+0x2678]` et `[manager+0x2680]` ; global associé `0x94C08A0`.
- Vtable finale `0x7F35BC0`, temporaire `0x7F36308`. Entrées finales : `+0x30 -> 0xBB190` (allocation), `+0x40 -> 0xBB2A0` (reallocation), `+0x50 -> 0xBB5E0` (libération), `+0x68 -> 0xBB700` (helper taille/classe), `+0x70 -> 0xBB800` (helper métadonnées/requête).
- Slot global du manager : `0x8FF70A80`, distinct de la base manager `0x9072210`.
- `main+0xC7460` construit des wrappers synchronisés/diagnostiques ; wrappers externes identifiés : `0xBD950` alloc, `0xBDB40` realloc, `0xBDD70` free.
- `main+0x14550` incrémente le global `0x94B1550` avant dispatch allocate ; `main+0x14580` le décrémente avant dispatch free. L'interprétation comme compteur d'opérations en cours est probable, pas confirmée.

### Fonctions et chemins internes

- `0xBB190` : allocation ; petits blocs (jusqu'à `0x20000`, alignement au plus `0x10`) via table de classes `0x94C008B0` et caches TLS/thread ; chemin lent `0xB8000`.
- `0xBB2A0` : realloc ; essaie caches ou `0xB8B80`, sinon allocation/copie/libération ; fallback `0xB90E0`.
- `0xB8000` : allocation lente, classe, état TLS `0x70C2630`, segment actif `[x25+0x990]==1`, cache par thread, régions et métadonnées.
- Région sous verrou : `manager + 0x70 + (class << 7)`, verrou à `+0x60`. Helpers région : `0xB6AD0`, `0xB67A0`, `0xB8760`.
- `0xBB5E0` : dispatch free ; `0xB8F40` : fast free (classe, TLS/thread state, caches et slots atomiques partagés) ; `0xB90E0` : fallback free (recherche région/métadonnée, vérification du marqueur live, libération de la région backing).

### Table de métadonnées et marqueurs

- `0xB8760` : table de hachage de métadonnées indexée à partir du pointeur et des champs manager `+0x08`, `+0x10`, `+0x18`, `+0x20`, base des buckets `[manager+0x60]`.
- Nœud : clé à `+0`, base métadonnées à `+8`, liens à `+0x10` et `+0x18`. Un nœud dont `+8 == 0` peut être réutilisé.
- `0xBC7E0` initialise les métadonnées avec le marqueur freed `0x39431234`. Le marqueur live attendu par le chemin free est `0x17EA5678`.
- `0xB91F0` contient le message « Attempt to free an unrecognized pointer », associé au chemin `Runtime/Core/Private/HAL/MallocBinned3.cpp`, ligne source rapportée 959. `0xB92AC` efface `[node+8]` en laissant le nœud chaîné et réutilisable ; ce comportement ne prouve pas une corruption.

### Pages, bitmaps et relocations PLT

- `0x14E80` libère une plage de pages et met à jour la comptabilité ; `0x14F80` réserve/alloue des pages ; `0x2A860`, `0x2A300`, `0x2A700` manipulent plages et compteurs.
- `0xB9720` teste un bit ; `0xB6C20` efface des bits avec propagation hiérarchique ; `0xB86E0` positionne des bits ; `0x29DC0` gère des blocs/listes liés.
- Correction d'identification : `0x70C1EA0`, `0x70C1EB0`, `0x70C1EC0` sont des stubs importés `nn::os::TryLockMutex`, `LockMutex`, `UnlockMutex`, pas les fonctions internes de verrouillage.
- Métadonnées ELF rapportées : relocation PLT `0x70E94F8`, `DT_PLTGOT=0x9009FE8`, `DT_JMPREL=0x70E94F8`, `DT_PLTRELSZ=0x5BF8`, `DT_SYMTAB=0x7133FF0`, `DT_STRTAB=0x713A590`. Les slots GOT statiques initialisés au resolver ne révèlent pas les cibles runtime finales.

**Conclusion de ce complément :** ces fonctions expliquent la structure et les chemins normaux de l'allocateur, mais aucune ne révèle encore la valeur du pointeur rejeté ni l'appel exact qui a provoqué Crash A. L'occurrence de `0x39431234` dans rodata (`module+0x75C9070`) peut être une constante statique et ne prouve pas une libération fautive.
