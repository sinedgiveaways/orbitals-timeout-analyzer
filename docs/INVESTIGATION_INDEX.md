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
| Cause racine Crash B | Non déterminée |
| Analyseur Windows | Code 0.5.2 présent sur main ; artifact de cette version à vérifier séparément |

## Limite de cette sauvegarde

Ce dossier consolide les faits, extraits et conclusions disponibles dans le contexte de travail au moment de sa rédaction. Il ne prétend pas archiver les fichiers de logs binaires complets ni chaque sortie PowerShell historique. Les logs originaux doivent être conservés séparément si l'on veut pouvoir reproduire chaque constat ligne par ligne.
