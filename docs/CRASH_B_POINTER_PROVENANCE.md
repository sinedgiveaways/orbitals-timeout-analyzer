# Crash B — Pointer Provenance (rapport ciblé)

Date : 21-11-2026  
Périmètre : résultats QWORD Hunter et désassemblage COFF communiqués par l'utilisateur.  
Statut : **analyse partielle ; producteur du pointeur fautif non identifié**.

## 1. Site consommateur exact

Objet : `setup-work/obj/main_main_0184.o`  
Fonction hôte levée : `.text 0x189A0–0x19A6C`  
Instruction signalée : `.text+0x1952F`

Séquence du bloc de secours :

```asm
0x19507: mov rax, qword ptr [rsi + 0xd8]
0x1950E: mov rcx, qword ptr [rax]
0x19511: mov qword ptr [rsi + 0x58], 0x38
0x19519: mov eax, 2
0x1951E: sub eax, edx
0x19520: imul r8, rax, 0x38
0x19524: lea r9, [rcx + r8]
0x1952F: mov ecx, dword ptr [rcx + r8 + 0x5c]
```

Il y a **deux niveaux distincts** : le slot `[rsi+0xD8]` pointe vers un enregistrement extérieur sélectionné avec un stride **0xE8** (adresse calculée à `0x18F5C` comme `base + index*0xE8`) ; le premier QWORD de cet enregistrement, chargé dans `rcx` à `0x1950E`, sert de base à une seconde structure consultée avec un stride **0x38**. La chaîne est : slot local `[rsi+0xD8]` → adresse de l'enregistrement extérieur E8 (`rax`) → premier QWORD de cet enregistrement (base interne `rcx`) → lecture `[rcx + (2-edx)*0x38 + 0x5C]`.

Le premier QWORD de l'enregistrement extérieur stride-0xE8 est donc la base de la structure intérieure consultée avec stride 0x38. Un pointeur nul pourrait expliquer une lecture proche de zéro, mais les valeurs synchronisées de RCX/R8 au PC fautif ne sont pas disponibles. Il n'est pas prouvé que RCX valait zéro au moment de l'exception.

## 2. Les six objets : résultat QWORD Hunter terminé

L'utilisateur a confirmé que l'examen des six objets et des douze sites candidats est déjà terminé. Tableau du scan :

| Objet | Stores stride 0xE8 | Stores QWORD | Stores QWORD displacement 0 |
|---|---:|---:|---:|
| `main_main_0156.o` | 7 | 6 | 0 |
| `main_main_0157.o` | 3 | 0 | 0 |
| `main_main_0173.o` | 5 | 0 | 0 |
| `main_main_0184.o` | 2 | 0 | 0 |
| `main_main_0186.o` | 3 | 0 | 0 |
| `main_main_0330.o` | 2 | 0 | 0 |

Dans `main_main_0156.o`, deux des six QWORD stores sont explicitement conservés dans les résultats disponibles : `.text+0x31AD2` écrit zéro à displacement `+0x78`, et `.text+0x31AFE` écrit `rax` à displacement `+0x80`. Les quatre autres adresses/destinations exactes ne sont pas suffisamment documentées dans le relevé récupéré. Aucun QWORD store détecté n'écrit au displacement `+0` d'un élément stride-`0xE8`.

Les douze sites DWORD listés dans `CRASH_B_CANDIDATES_12.md` sont des écritures d'index/valeurs/sentinelles, notamment `0xFFFFFFFF`. Ils ne démontrent pas l'écriture du premier QWORD consommé à `0x1950E`. **Aucun producteur du pointeur fautif n'a été identifié par ce scan.**

## 3. Autres usages de [rsi+0xD8] observés dans les chunks QWORD Hunter

Les occurrences globales montrent que cette position de frame est réutilisée comme slot/spill selon les fonctions ; elles ne définissent pas un champ métier universel. Les résultats transmis incluent :

- `.text+0x24745` : provenance étiquetée `PTR_FROM_RSI_D8`, avec `mov rdx,[rsi+0xd8]` puis `mov [rdx],rcx` (écriture à offset zéro via le pointeur rechargé).
- Rechargements du slot : `0x350F3` (rcx), `0x351E6` (rax), `0x35817` (rcx), `0x362D7` (rax), `0x365F0` (rcx), `0x36756` (rax), `0x38166` (rax).
- `0x3816D` : `[rax]=r14`, écriture QWORD à offset zéro via le pointeur rechargé à `0x38166`.
- Autres écritures via pointeurs classés `PTR_FROM_RSI_D8` : `0x38309 [rax+0x20]=r13`, `0x3869F [rcx+0x18]=rax`, `0x3888F [r8+0x38]=rdx`, `0x3889A [rdx+0x60]=r13d`, `0x388C7 [rcx+0x58]=rdx`.
- Lectures du premier QWORD / déréférencements signalés : `0x365F7` après le reload `0x365F0`, puis `0x39191`, `0x393DD`, `0x3967B` et `0x47095`.
- `0x39DE0` écrit `[rcx+0xF0]`, puis `0x39DEF` avance le slot en stockant `rcx+0xF0` dans `[rsi+0xD8]`.
- `0x439AF` stocke `rax+0x4C` dans `[rsi+0xD8]`.
- À `0x4CC32`, `movsxd r8,dword ptr [rsi+0xd8]` puis multiplication et écritures via `r8` montrent qu'une autre fonction traite ce slot comme un **offset DWORD signé**, pas comme un pointeur.

Ces résultats montrent plusieurs usages de pointeurs/cursors et même une interprétation scalaire du même offset de frame dans des fonctions distinctes. Ils ne prouvent pas que les pointeurs rechargés dans ces autres fonctions sont celui consommé à `main_main_0184.o+0x1950E`.

## 4. Deux strides imbriqués : 0xE8 extérieur et 0x38 intérieur

Il ne faut pas opposer les deux valeurs : elles décrivent deux niveaux de la chaîne. À `0x18F5C`, le code place dans `[rsi+0xD8]` l'adresse d'un enregistrement extérieur calculée comme `base + index*0xE8`. Le bloc de secours charge ce pointeur extérieur dans `rax`, puis son premier QWORD dans `rcx`. Ce premier QWORD est la base d'une structure intérieure, consultée à `0x1952F` avec le stride `(2-edx)*0x38` et le champ `+0x5C`.

L'analyse ARM64 de la sélection par index `k`, bitmap de présence, et élément `data+k*0xE8` décrit le niveau extérieur et est compatible avec cette chaîne. Les conditions statiques relevées — bit de présence actif, `[element+0xD8] == 0xFFFFFFFF`, absence de correspondance et premier QWORD nul (`[x27]=0`) — peuvent expliquer le calcul `0x104` si elles correspondent au même chemin dynamique. Elles ne sont toutefois pas une capture runtime synchronisée. La course de publication du bitmap avant initialisation du premier QWORD reste une hypothèse, pas une cause démontrée.

## 5. Limites et état final

- Étape d'examen des six objets / douze candidats : **terminée**, ne pas la refaire.
- Aucun store QWORD au displacement zéro d'un élément stride-`0xE8` détecté dans les six objets.
- Des écritures à offset zéro via certains pointeurs rechargés depuis `[rsi+0xD8]` existent ailleurs, mais elles ne sont pas reliées au pointeur exact du crash.
- Producteur et origine du premier QWORD chargé à `.text+0x1950E` : **non identifiés**.
- Branche exacte empruntée au runtime et valeurs synchronisées RCX/R8/RDX/RAX au PC fautif : **non capturées**.
- Les chunks de provenance récupérés vont jusqu'à `.text+0x4CC32`. Aucun marqueur final « FIN DU RAPPORT » n'est présent dans les éléments retrouvés ; ce document consigne donc les résultats connus sans prétendre que le relevé transmis était complet.

Aucune préparation, génération ou recompilation du jeu n'est nécessaire pour conserver ou poursuivre cette analyse.


## Complément — détails des résultats de provenance transmis

Les résultats d'écriture indirecte étiquetés `PTR_FROM_RSI_D8` comprennent des écritures aux offsets `+0x10`, `+0x18`, `+0x20`, `+0x28`, `+0x30`, `+0x38`, `+0x58` and `+0x60`. Les exemples d'instructions explicitement conservés sont `0x38309 [rax+0x20]=r13`, `0x3869F [rcx+0x18]=rax`, `0x3888F [r8+0x38]=rdx`, `0x3889A [rdx+0x60]=r13d` (DWORD), and `0x388C7 [rcx+0x58]=rdx`. Les extraits identifient également `0x24745` as `mov rdx,[rsi+0xD8]` followed by `mov [rdx],rcx`, and `0x38166` as a reload followed at `0x3816D` by `[rax]=r14`. Ces deux écritures indirectes à l'offset zéro sont des candidats possibles pour écrire le premier QWORD dans leurs contextes respectifs, mais rien ne prouve que leurs destinations soient l'enregistrement extérieur sélectionné sur le chemin du crash.

À `0x4CC32`, la séquence conservée est `movsxd r8,dword ptr [rsi+0xD8]`, then `imul r8,rdx`, followed by stores through the computed offset at `[r8+rcx]`, `[r8+rcx+8]` and `[r8+rcx+0xC]`. Cela confirme que le même offset de frame peut être un scalaire signé dans une autre fonction ; il ne faut pas traiter chaque occurrence de `[rsi+0xD8]` comme la même variable pointeur.
