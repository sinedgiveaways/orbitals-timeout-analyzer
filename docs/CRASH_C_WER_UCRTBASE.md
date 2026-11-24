# Crash C — WER minidump / accès mémoire dans ucrtbase.dll

Date de consignation : 2026-11-24  
Dump : `C:\OrbitalsDumps\orbitals-recomp.exe.16952.dmp` (environ 8,8 Go)  
Statut : **piste de copie mémoire et source suspecte identifiées ; origine de la source et cause racine non établies.**

> Ce dossier décrit un incident distinct des Crash A (FMallocBinned3/GOT-PLT) et Crash B (lecture 0x104 / TLS). Ne pas fusionner leurs symptômes ni leurs conclusions.

## 1. Exception Windows

- Module fautif rapporté : `ucrtbase.dll`
- Base du module : `0x7FFB2D3C0000`
- Adresse d'exception / RIP : `0x7FFB2D4AE44D` (offset module `0xEE44D`)
- Code : `0xC0000005` — violation d'accès
- Thread ID : `0x5B10` (23312)
- Type d'accès indiqué dans `ExceptionInformation[0]` : lecture (`0`)
- Adresse indiquée dans `ExceptionInformation[1]` : `0xFFFFFFFFFFFFFFFF`

Octets à RIP : `C5 FE 6F 02`, décodés comme :

```asm
vmovdqu ymm0, ymmword ptr [rdx]
```

Il s'agit d'une lecture vectorielle de 32 octets. Le code se trouve dans une routine de copie/déplacement mémoire optimisée de l'Universal CRT. Le nom exact de la fonction n'est pas confirmé par les éléments conservés.

**Réserve essentielle :** le contexte sauvegardé donne `RDX=0x01460149013D0140`, alors que les informations d'exception signalent `0xFFFFFFFFFFFFFFFF`. Ces deux valeurs ne concordent pas. Il ne faut donc pas affirmer que RDX du contexte est nécessairement l'adresse exacte de l'accès qui a déclenché l'exception. La routine a pu modifier ses registres avant le fault, ou les informations capturées peuvent ne pas représenter le même état précis.

## 2. Structure contenant les paramètres de copie

Une structure hôte à `0x1C92EAB0540` a été lue dans le dump :

| Offset | Valeur | Lecture provisoire |
|---|---:|---|
| +0x00 | `0x00000012E1A8000C` | destination |
| +0x08 | `0x01460149013D0140` | source suspecte |
| +0x10 | `0x0000000005240500` | taille |
| +0x18 | `0x0000000017EA5678` | marqueur observé |
| +0x20 | `0x000000011C51F4FF` | champ non interprété |
| +0x28 | `0x0000000E40012C2C` | champ non interprété |
| +0x30 | `0x0000007001582090` | champ non interprété |
| +0x38 | `0x0000000000000018` | champ non interprété |

La taille `0x05240500` vaut **86 246 656 octets (82,25 Mio)**.

La destination `0x12E1A8000C` tombe dans une région présente dans la liste mémoire du dump : `[0x12E1A80000, 0x12E1C00000)`.

Aucune région capturée dans la Memory64List ne couvre la source `0x01460149013D0140`. Cela la rend suspecte, mais **l'absence d'une région dans un minidump ne prouve pas à elle seule que l'adresse était non mappée dans le processus** : le dump peut ne pas inclure toute la mémoire.

## 3. Appelant hôte retrouvé sur la pile

Le contexte du thread fautif donne notamment :

- `RSP=0x19AFFFF1D8`
- `RSI=0x1C92EAB0540`
- `RDI=0x12E1A8000C`
- `RBX=0x01460149013D0140`
- `R14=0x05240500`

Les trois valeurs RDI/RBX/R14 correspondent aux trois premiers champs interprétés de la structure.

Le premier qword de pile à `RSP+0` est `0x7FF6C82A0D1F`, soit un retour dans `orbitals-recomp.exe` à RVA `0x40D1F`. Le code autour de l'appel montre le chargement des trois champs de la structure, puis la préparation des arguments :

- `RCX = RDI` (destination)
- `RDX = RBX` (source)
- `R8 = R14` (taille)

Un appel est effectué depuis `0x7FF6C82A0D1A` vers un thunk à `0x7FF6C896C430`. Cette séquence relie fortement la structure au chemin de copie, mais la résolution finale du thunk et la fonction réellement atteinte restent à confirmer.

## 4. Wrapper auxiliaire et redirection non résolue

Une fonction/wrapper a été examinée à :

- Adresse : `0x7FF6C8280810`
- RVA dans `orbitals-recomp.exe` : `0x20810`

Le scan exploratoire des appels directs `CALL rel32` vers cette adresse n'a rapporté aucun résultat. Ce résultat n'exclut pas les appels indirects, les thunks ou une recherche imparfaite.

Le thunk examiné à `0x7FF6C896C430` utilise une redirection indirecte dont l'emplacement relevé est `0x7FF6CA527650`. La valeur lue à cet emplacement dans le dump est `0x0000000000010000`, qui ne constitue pas une adresse de fonction plausible dans ce contexte.

Conséquence : **le lien entre ce thunk, le wrapper à RVA 0x20810 et ucrtbase.dll n'est pas démontré**. Ne pas utiliser cette redirection comme preuve de la cible réelle.

La fonction située à `0x7FF6C827D260` contient un compteur atomique et plusieurs appels de formatage/journalisation. Elle ressemble à une routine de logging ; elle n'a pas été identifiée comme la copie mémoire elle-même.

## 5. Résultats négatifs / limites de l'analyse

- Le scan direct des instructions `CALL rel32` vers `0x7FF6C8280810` n'a pas fourni de cible appelante.
- La valeur `0x10000` lue à `0x7FF6CA527650` ne résout pas le thunk.
- La source n'est pas présente dans les régions mémoire capturées, mais la couverture du dump n'est pas exhaustive.
- Le désaccord entre `ExceptionInformation[1]` (`0xFFFFFFFFFFFFFFFF`) et le RDX du contexte (`0x01460149013D0140`) interdit de déclarer la source de la structure comme adresse exacte du fault sans capture synchronisée.
- Aucun correctif n'a été écrit ni validé.
- Aucun cycle `prepare.py`, génération ou recompilation complète du jeu n'est requis pour poursuivre cette analyse.

## 6. Prochaines étapes précises

1. Résoudre le thunk `0x7FF6C896C430` et son IAT/slot avec une méthode qui distingue les adresses virtuelles des données réellement capturées dans le dump.
2. Identifier la cible effective de l'appel préparé à `0x7FF6C82A0D1A`, et confirmer si elle entre dans le wrapper `orbitals-recomp.exe+0x20810` ou directement dans l'CRT.
3. Désassembler la routine de copie autour de `ucrtbase.dll+0xEE44D` et reconstruire son état de registres au point exact de faute ; expliquer l'écart entre l'adresse d'exception et le contexte.
4. Remonter la provenance de `0x01460149013D0140` dans l'appelant et vérifier la validité de la destination et de la taille avant la copie.
5. Seulement après identification du producteur de la source, concevoir un correctif localisé et tester sans régénérer/recompiler tout le jeu.

## Conclusion provisoire

Le dump montre un plantage de lecture dans une routine vectorisée de l'Universal CRT, sur un chemin qui semble recevoir une destination, une source et une taille de copie de 82,25 Mio. La source fournie dans la structure est très suspecte et absente des plages mémoire enregistrées. **La fonction qui produit cette source, la cible effective du thunk et l'adresse exacte ayant déclenché l'exception restent à établir.** Ce rapport ne prétend pas avoir identifié la cause racine.
