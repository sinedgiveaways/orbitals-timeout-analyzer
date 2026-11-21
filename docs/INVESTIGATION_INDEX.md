# Orbitals Recomp — dossier d'investigation

Dernière mise à jour : 2026-11-21  
Dépôt : `sinedgiveaways/orbitals-timeout-analyzer`

## Objectif

Conserver dans le dépôt les faits techniques établis pendant l'analyse des plantages d'Orbitals Recomp, distinguer les observations des hypothèses et éviter de refaire les mêmes recherches. Le dossier est organisé autour de deux incidents indépendants.

- [Crash A — FMallocBinned3 / pointeur non reconnu](CRASH_A.md)
- [Crash B — accès mémoire 0x104 / chemin TLS](CRASH_B.md)
- [Environnement, builds et contraintes de travail](ENVIRONMENT_AND_BUILD.md)

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

**Prochaine étape :** analyser les objets déjà présents dans `setup-work/obj` pour retrouver les écritures au début des enregistrements de stride `0xE8` et les fonctions qui construisent/remplissent la collection. Ne pas relancer `prepare.py` ou une recompilation complète.

## Limite de cette sauvegarde

Ce dossier consolide les faits, extraits et conclusions disponibles dans le contexte de travail au moment de sa rédaction. Il ne prétend pas archiver les fichiers de logs binaires complets ni chaque sortie PowerShell historique. Les logs originaux doivent être conservés séparément si l'on veut pouvoir reproduire chaque constat ligne par ligne.


## Compléments SDK TLS ajoutés — 21-11-2026

Le dossier [CRASH_B.md](CRASH_B.md) a été complété avec les derniers résultats confirmés :
- appel d'initialisation de `nn::os::AllocateTlsSlot` via GOT `0x900A1C8), avec premier argument `0x90100F8) et callback `main+0x1A820) ;
- relocation type `1026` (`0x402`), addend nul, et nom manglé de l'import ;
- relocation/export de `SearchUnusedTlsSlotUnsafe` à `sdk+0x16C520), taille `0x284`, recherche de slots `0..31` ;
- points d'entrée SDK étudiés pour allocation TLS, mise à zéro des TLS de threads et création de threads, avec indication explicite des extraits partiels.

Ces éléments ne déterminent pas encore la cause racine. Les priorités restent la capture runtime du slot TLS avant/après allocation et l'identification des écrivains du premier qword des éléments de stride `0xE8). Aucun rebuild complet n'est requis pour ces analyses.
