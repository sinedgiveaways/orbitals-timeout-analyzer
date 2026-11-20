# Orbitals Recomp — dossier d'investigation (20 novembre 2026)

Ce document rassemble les observations statiques et le dernier rapport de crash communiqué. Les faits établis sont séparés des hypothèses.

## Crash access violation / TLS

Log observé :
- Exception : `0xc0000005`
- PC hôte : `orbitalgame+0x1b5b682f`
- Fonction recompilée : `main+0x1759b20`
- PC invité : `sdk+0x16b730`, symbole indiqué `nn::os::GetTlsValue(TlsSlot)`
- LR invité : `main+0x175a16c`
- Frames invités : `main+0x1750b88`, `main+0x1750650`, `main+0x1718cf8`, `main+0x1d77d64`, `main+0x1d761e0`, `main+0x1641f84`, puis autres frames.

Registres hôte observés :
- `RCX=0`, `R8=0xa8`
- l'exception signale une lecture à `0x104`
- octets d'instruction hôte : `42 8b 4c 01 5c`

Le calcul `0 + 0xa8 + 0x5c = 0x104` correspond aux registres et au déplacement rapportés, mais doit être confirmé par le décodage exact de l'instruction et le contexte du code hôte. Il indique une base nulle dans cette expression d'adresse effective.

État invité :
- thread : `0x254CC9A5000`
- `TPIDR_EL0=0xa2003c740`
- `TLR=0x7010078000`
- `TLR[+0x1f8]` donne l'objet thread `0x7c005a038`
- `x0=0x7009072210`, `x2=0xe`, `x20=0`, `x25=0xa8`, `x30=main+0x175a16c`.

Interprétation prudente :
- Le contexte TPIDR/TLR reporté est non nul. Cela n'exclut pas un problème de slot TLS, de structure interne, de convention d'appel ou de code hôte généré.
- Le PC invité est étiqueté `GetTlsValue`; il s'agit d'une forte indication du chemin exécuté, pas d'une preuve que l'implémentation SDK est fautive.
- La cause à départager : argument/état fourni par l'appelant, implémentation TLS/runtime, ou traduction JIT/AOT du code invité vers le code hôte.
- Examiner en priorité l'appel à `GetTlsValue` autour de `main+0x1759b20` et son retour `main+0x175a16c`. La version 0.2 extrait automatiquement des fenêtres ARM64 pour les offsets `main+0x` trouvés dans le log.

## Trace TPIDR

La fin du log contient 128 événements récents (sur 1 042 213). Plusieurs threads possèdent des valeurs TPIDR distinctes, répétées à l'identique dans les lectures affichées. Cette stabilité apparente ne démontre pas que les slots TLS référencés sont valides.

## Analyse allocateur déjà réalisée

Éléments statiques étudiés dans le NSO :
- Base manager : `0x9072210`.
- Slot global manager : `0x8ff70a80` (distinct de la base).
- Global allocateur/classe : `0x94c008b0`.
- Vtable finale manager : `0x7f35bc0`, avec entrées identifiées pour allocate/realloc/free et helpers.
- `0xb8760` gère une table de métadonnées indexée par région.
- `0xbc7e0` initialise des métadonnées avec `0x39431234`.
- `0xb90e0` fallback free recherche la région et vérifie le marqueur live `0x17EA5678`; le chemin diagnostic signale « Attempt to free an unrecognized pointer » lorsque le nœud attendu n'a pas de métadonnées.
- `0xb91f0` contient le message diagnostic correspondant.
- `0xbb190` allocate, `0xbb2a0` realloc, `0xbb5e0` free.
- Les chemins rapides utilisent notamment l'état TLS/thread local et des caches par classe.
- Les stubs `0x70c1ea0`, `0x70c1eb0`, `0x70c1ec0` sont des stubs PLT vers `nn::os::TryLockMutex`, `LockMutex`, `UnlockMutex`, et non les implémentations des mutex.

Marqueur `0x39431234` trouvé dans rodata à `module+0x75c9070` : cela peut être une constante/donnée statique ; ce n'est pas une preuve qu'un bloc a été libéré à l'exécution.

## Ne pas confondre les deux familles de crash

1. Access violation TLS ci-dessus.
2. Crash séparé `FMallocBinned3 Attempt to free an unrecognized pointer`, suivi de `nn::diag::Abort`.

Aucune preuve ne permet de conclure que ces deux événements ont la même cause. Les chaînes RDG dans une pile ne prouvent pas que RDG est responsable.

## Ce que l'outil peut maintenant fournir

La version 0.2 extrait les registres et frames des logs, puis affiche les mots ARM64 autour de tous les offsets `main+0x` détectés lorsque `exefs/main` est chargé. Elle décode certaines branches et instructions courantes pour faciliter l'identification de l'appelant et de l'instruction précédant le LR.

Pour aller plus loin, il faudra comparer les instructions autour de `main+0x1759b20` et `main+0x175a16c`, puis les autres frames. Le module `sdk` nécessite son propre binaire/symboles ; le NSO `main` ne contient pas nécessairement le code SDK.
