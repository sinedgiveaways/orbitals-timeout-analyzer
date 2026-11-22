# Crash B — corrélation binaire/runtime du 22-11-2026

Date : 2026-11-22  
Build runtime observé : `0.2.0-g77add3c`  
Binaire `main` analysé : 80 716 406 octets, SHA-256 `ddac7c7648c98c15cd5b57c15e33ae02aa698503350aa6b40d16de0578f90d40`  
Binaire `sdk` analysé : 7 759 642 octets, SHA-256 `d3b35139a0b5c3b73921b60334e359281ae8d41a640b9a1852c4b66768c9053a`  
Statut : **mécanisme de lecture nul confirmé ; producteur runtime du premier QWORD encore à identifier.**

## 1. Capture runtime du 22-11

Le rapport `orbitals(1).log` indique :

- fonction hôte levée : `f_7001759b20 = main+0x1759b20` ;
- octets fautifs : `42 8b 4c 01 5c`, soit `mov ecx, [rcx+r8+0x5c]` ;
- registres hôtes : `RCX=0`, `R8=0xA8`, `RDX=0xFFFFFFFF` ;
- adresse lue : `0x104` ;
- chaîne invitée : `x27=0x84017bc00`, `[x27]=0` ;
- adresse de thread : `0x226c7e5fca0` ;
- le champ de rapport `pc` indique pourtant `sdk+0x16b730`.

Le calcul hôte est exact : `0 + 0xA8 + 0x5C = 0x104`. Le registre hôte `RDX=-1` est cohérent avec le calcul d'index `2-(-1)=3`, puis `3*0x38=0xA8`.

**Incohérence de diagnostic à conserver :** le champ `pc=sdk+0x16b730` ne concorde pas avec les octets fautifs ni avec la fonction hôte levée `main+0x1759b20`. Les octets correspondent au chargement ARM64 situé dans `main+0x175a030` (détails ci-dessous), et non au corps de `GetTlsValue`. Ne pas conclure que `GetTlsValue` est l'instruction directement fautive sur la seule base du champ `pc`. Le défaut de capture `GetTlsValue entry: no entry captured` reste un fait distinct à investiguer, mais il ne localise pas à lui seul la faute.

Source runtime : `orbitals(1).log`, lignes 17365–17399. L'allocation de la page contenant `x27` est journalisée à la ligne 17096 : `AllocateMemoryPages address 0x84017b000 size 0x1000 result 0`. La page contient `x27=0x84017bc00` (offset `+0xC00`). Cette proximité prouve que l'adresse appartient à une page allouée, pas que le champ `[x27]` a été initialisé.

## 2. Désassemblage ARM64 vérifié dans le binaire main

La séquence exacte dans `main_text.bin` est :

```asm
main+0x1759DE4: ldr    x9, [x21, #0x158]
main+0x1759DE8: mov    w10, #0xE8
main+0x1759DF0: umaddl x27, w20, w10, x9
...
main+0x1759DFC: ldr    w8, [x27, #0xD8]
...
main+0x175A01C: ldr    x9, [x27]
main+0x175A020: mov    w10, #2
main+0x175A024: mov    w11, #0x38
main+0x175A028: sub    w10, w10, w8
main+0x175A02C: umaddl x25, w10, w11, x9
main+0x175A030: ldr    w9, [x25, #0x5C]
```

La construction de `x27` est donc **dans la fonction main+0x1759b20 elle-même**, et non nécessairement dans les frames appelantes :

`x27 = *(x21 + 0x158) + unsigned(w20) * 0xE8`.

Le premier QWORD de l'élément extérieur est chargé par `ldr x9,[x27]`. Il fournit la base d'une table intérieure de stride `0x38`. Le champ lu est à `+0x5C`.

Si `[x27]=0` et si `w8=-1`, alors `2-w8=3`, `x25=3*0x38=0xA8`, et la lecture à `x25+0x5C` atteint `0x104`. C'est la correspondance exacte avec les valeurs hôtes observées. La capture des registres invités n'est toutefois pas entièrement synchronisée avec les registres hôtes : ne pas assimiler directement le registre hôte RDX au registre invité w8 sans vérifier le mapping du lifter.

**Correction d'offset :** l'instruction ARM64 finale est à `main+0x175A030`, pas `main+0x175A034`. À `+0x175A034` se trouve le branchement conditionnel qui suit.

## 3. Origine de la page et limites

Le log montre une allocation invitée à `0x84017b000`, taille `0x1000`, puis le crash avec `x27=0x84017bc00`. Cela confirme que le record fautif est situé dans cette page allouée. Le log ne donne ni la pile d'appel de l'allocation ni la fonction qui a écrit le premier QWORD du record.

Le registre `x21` capturé vaut `0xB40012810`. Le champ `[x21+0x158]` est donc le prochain pointeur à relever au crash. Avec `w20` et le calcul de stride, il permettra de vérifier indépendamment l'origine exacte de `x27`.

## 4. Constructeur/copie candidat à corréler — pas encore prouvé

Un autre chemin du binaire, autour de `main+0x1784920`, contient :

```asm
1784948: bl   0x1307b90
178494C: ldr  q0, [x24]
178495C: str  q0, [x1]
...
1784A10: bl   0x1784AC0
```

Dans `main+0x1784ac0`, le chemin de remplacement d'un élément existant appelle la copie mémoire avec destination `x19`, source `x20`, taille `0xE0` :

```asm
1784B98: mov  w2, #0xE0
1784B9C: mov  x0, x19
1784BA0: mov  x1, x20
1784BA4: bl   0x70c1df0
```

Le chemin de création initialise aussi les 16 premiers octets du nouvel élément par `str q0,[x1]`, avec `q0` chargé depuis `[x24]`. Ce chemin est un **candidat crédible** pour initialiser le premier QWORD d'un enregistrement de même disposition E8, mais aucune preuve actuelle ne relie son objet/conteneur à `[x21+0x158]` et au record runtime `0x84017bc00`. Il ne faut donc pas le présenter comme l'écrivain causal avant corrélation des bases et des identifiants d'éléments.

## 5. Prochaine capture — ordre précis

Ne pas modifier `thr_new()` et ne pas lancer `prepare.py`, la génération ou une recompilation complète.

### Capture minimale au crash

Capturer dans le même instantané :

1. `x21`, `w20`, `w8` ;
2. `[x21+0x158]` ;
3. `x27` et recalcul de `[x21+0x158] + w20*0xE8` ;
4. les `0x100` octets à partir de `x27`, avec au minimum les QWORD aux offsets `+0x00`, `+0x10`, `+0xD0`, `+0xD8`, `+0xE0) ;
5. si `[x27]` est non nul, les premiers `0x100` octets de la table pointée ;
6. les valeurs hôtes `RCX/R8/RDX` et les registres invités bruts, sans conversion supposée entre les deux jeux de registres.

Toutes les lectures mémoire du reporter doivent être bornées et protégées contre les pages non mappées. Ne pas suivre un pointeur nul ou illisible.

### Attribution du writer

Après la capture minimale, corréler la base `[x21+0x158]` avec le conteneur manipulé par `main+0x1784920 / 0x1784ac0`. Si les bases/records correspondent, suivre la source `[x24]` copiée dans le premier QWORD. Sinon, rechercher un autre producteur.

La meilleure preuve serait une trace des écritures à l'adresse exacte `x27+0` entre l'allocation de la page et le crash, ou un point de capture ciblé sur le chemin de copie lorsqu'il traite ce même index. Ne pas relancer le scan déjà terminé des six objets QWORD Hunter.

### GetTlsValue — piste séparée

Conserver une capture d'entrée `GetTlsValue` (w0/TlsSlot, thread, TPIDRRO, TLR, objet thread) seulement pour résoudre l'incohérence du champ `pc` et le message `no entry captured`. Ne pas mélanger cette mesure avec la provenance de `[x27]` tant que le lien n'est pas démontré.

## 6. Conclusion mise à jour

- **Confirmé :** le code de `main+0x1759b20` construit un élément extérieur de stride `0xE8`, charge son premier QWORD, puis consulte une structure intérieure de stride `0x38`.
- **Confirmé :** le premier QWORD de l'élément runtime `x27=0x84017bc00` vaut zéro au moment du rapport.
- **Confirmé :** l'accès hôte `0x104` correspond à `RCX=0`, `R8=0xA8`, offset `0x5C`.
- **Confirmé :** la page `0x84017b000` contenant `x27` a été allouée.
- **Candidat non prouvé :** le chemin de création/copie `main+0x1784920 / 0x1784ac0`.
- **Non déterminé :** qui doit écrire `[x27]`, si l'écriture est absente ou écrasée, et si le chemin candidat correspond au même conteneur.
- **À corriger dans le diagnostic :** l'étiquette `pc=sdk+0x16b730` ne concorde pas avec l'instruction hôte et le code ARM64 identifié. Le PC direct doit être revalidé avant d'attribuer ce crash à `GetTlsValue`.

Aucun correctif runtime n'est recommandé avant la capture ciblée ci-dessus.
