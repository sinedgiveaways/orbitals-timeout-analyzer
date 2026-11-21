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
