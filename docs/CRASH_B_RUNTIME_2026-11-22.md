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

`x27 = *(x21 + 0x158) + unsigned(w20 * 0xE8`.

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


## Erratum de synchronisation des registres — 22-11-2026

Relecture directe des lignes 17345–17399 du journal : le snapshot invité indique `x20=0`, `x21=0xB40012810`, `x25=0xA8), `x27=0x84017BC00`, ainsi que `x8=0x3D`, `x9=0x3D`, `x3=0xFFFFFFFF`. Le snapshot hôte, distinct, indique `RCX=0`, `R8=0xA8, `RDX=0xFFFFFFFF`.

**Correction :** il ne faut pas mapper `RDX=0xFFFFFFFF` vers `w8` ni affirmer que `w8=-1`. Le journal ne donne pas de mapping de registres hôte↔invité démontré. De plus, le champ `pc` indique `sdk+0x16B730`, alors que la fonction levée est `main+0x1759B20`; le snapshot invité ne peut donc pas être traité comme un état synchronisé à l'instruction `main+0x175A030` sans valider le reporter.

Ce qui reste robuste : l'hôte calcule bien `RCX + R8 + 0x5C = 0x104), le traceur rapporte `[x27]=0), et le binaire contient le chemin de lecture à stride E8 extérieur / 0x38 intérieur. Le rapprochement des deux est fort, mais la correspondance exacte des registres et du moment de capture reste à prouver.

Le snapshot invité donne `x20=0). Si ce registre est bien conservé depuis la boucle du calculateur, l'expression statique `x27 = [x21+0x158] + w20*0xE8` se réduit à `x27 = [x21+0x158]`. Il faut encore lire réellement `[x21+0x158]` au moment du crash pour le confirmer ; le journal ne le contient pas.

### Capture suivante corrigée

- Capturer ensemble le PC invité effectif, `x21`, `x20`, `x27, `[x21+0x158]`, `[x27], `[x27+0xD0]`, `[x27+0xD8], `[x27+0xE0] et les registres hôtes.
- Capturer les registres ARM64 au PC `main+0x175A030` ou juste avant `main+0x175A01C`, pas seulement le snapshot attaché à `sdk+0x16B730`.
- Enregistrer séparément l'entrée réelle de `GetTlsValue` pour comprendre pourquoi le reporter associe ce PC à la fonction levée.
- Ne déduire aucun mapping hôte/invité avant une capture simultanée ou une table de mapping fournie par le recompilateur.


## Chaîne statique du producteur candidat — inspection complémentaire du 22-11

Un balayage des instructions `BL` du binaire `main` donne les références directes suivantes :

- `main+0x1784920` est appelé directement à un seul endroit : `main+0x174E4A8`.
- `main+0x1784AC0` est appelé par `main+0x1784A10`.
- `main+0x1759B20` est appelé directement à `main+0x1750B84`.

Dans le caller `main+0x174E180`, le chemin vers `main+0x174E4A8` est maintenant mieux compris :

1. `x20) reçoit `x1` à l'entrée de `main+0x174E180` ; le conteneur de records est adressé via `[x20+0x158]`.
2. Le code parcourt des éléments de stride `0xE8` et compare leur premier QWORD à une clé/pointeur `x8`.
3. À `main+0x174E1FC`, le local `[x29-0x50]` est initialisé à zéro.
4. À `main+0x174E20C`, un appel virtuel est effectué via le vtable de `x25`, slot `+0xA8), avec `x1=&([x29-0x50])` et `x2=&([x29-0x54])` comme paramètres de sortie.
5. Le code recharge cette sortie à `main+0x174E2F0` / `main+0x174E308`. Le chemin de création atteint ensuite `main+0x174E480`, où `x8=[x29-0x50]` est copié dans le premier QWORD du record source sur la pile (`[sp+0xF0]`).
6. À `main+0x174E4A8`, `x0=x20+0x158`, `x1=sp+0xF0), puis appel de `main+0x1784920`. Cette fonction copie les 16 premiers octets du record source dans le nouvel élément (`ldr q0,[x24]` puis `str q0,[x1]` à `178494C/178495C`).

C'est une chaîne statique cohérente pour créer un élément E8 dont le premier QWORD provient du paramètre de sortie de l'appel virtuel `[vtable(x25)+0xA8]`. **Elle ne prouve pas que ce conteneur est l'instance utilisée par le crash** : dans le consommateur, `x21=x0) et `x0) est reçu du caller `main+0x1750B84`; il faut comparer l'adresse runtime de cet objet avec l'objet `x20) du producteur.

### Conséquence pour la suite

La prochaine capture doit ajouter, sur le chemin producteur `main+0x174E180), l'adresse de `x20), la valeur de `x25), le pointeur écrit dans `[x29-0x50]` par le callback virtuel et l'adresse du record destination. Sur le chemin consommateur `main+0x1759B20), capturer `x21), `[x21+0x158]`, l'index `w20, et `x27`. Si `x20_producteur == x21_consommateur` et que l'adresse de record correspond, le callback `vtable+0xA8` devient le producteur à tracer. Si les objets diffèrent, cette piste n'est pas la source du record fautif.

Le point décisif est donc maintenant la **comparaison des adresses d'instance**, pas une nouvelle recherche générique de stores QWORD. Ne pas relancer le scan des six objets.


## Correction majeure : le PC et les registres du crash reporter ne sont pas un snapshot ARM64 synchronisé

Inspection du source runtime de la branche `sinedgiveaways/pmocer-latibro`, branche `copilot/orbital-copilot-analyse`, commit consulté `866c88ce9d0c434ad75226cd9a3a8d22c6bf1015` :

- `runtime/core/boot/main.c`, fonction `crash_handler`, affiche `c->pc` comme PC invité (lignes 298–299), alors que `Cpu.pc` est explicitement décrit dans `runtime/cpu/cpu.h` comme la cible du prochain dispatch indirect, pas comme un compteur de programme maintenu à chaque instruction.
- Le champ `in lifted function f_...` est obtenu par `lifted_function(rip)` (main.c, lignes 221–242) : il retrouve le début de fonction hôte levée le plus proche avant le RIP, pas l'instruction invitée exacte.
- Plus important, `recomp/regs.py` indique que le générateur conserve les registres invités les plus utilisés dans des variables locales C (`xN`) et ne les recopie dans `c->x[N]` qu'aux points de synchronisation : appels, SVC, trap, retour et sorties de fonction. Le crash handler qui imprime directement `c->x[]` peut donc afficher des valeurs anciennes pour les registres maintenus dans les variables locales au moment du crash.

Cela explique pourquoi le log peut afficher simultanément `pc=sdk+0x16b730` et `in lifted function main+0x1759b20`, ainsi que pourquoi les registres invités imprimés ne doivent pas être considérés comme synchronisés avec les registres hôtes. **L'ancienne formulation disant que le champ PC est simplement « erroné » était trop catégorique : c'est surtout un champ de dispatch/stale PC, pas le PC exact de l'instruction qui a fauté.**

### Nouvelle priorité : fiabiliser la capture avant de suivre le writer

Ne pas utiliser le snapshot actuel `c->x[]` pour conclure que `x20=0`, que `x27) vaut réellement `0x84017bc00` à l'instruction fautive, ou pour comparer les instances producteur/consommateur. Ces valeurs restent des indices à confirmer.

Ajouter un probe ciblé dans le générateur de code pour les deux fonctions connues :

1. Consommateur `main+0x1759b20) : synchroniser/sauvegarder les registres invités au point juste avant l'instruction `main+0x175a030`, avec PC invité explicite `main+0x175a030`. Capturer `x20`, `x21), `x27), `x8), `x25), `sp), `[x21+0x158]`, `[x27]) et les champs record lisibles.
2. Producteur `main+0x174e180) : capturer `x20), `x25), la sortie du callback virtuel `vtable+0xa8), l'adresse de destination du record et le premier QWORD copié.
3. Écrire ces données dans un petit snapshot crash-safe, consultable par `crash_handler`, sans allocations ni locks dans le chemin de crash.

Une stratégie possible est de désactiver les register-locals uniquement dans ces fonctions ciblées, ou d'ajouter un point de synchronisation explicite dans le générateur avant le probe. Ne pas désactiver les register-locals globalement. Le probe doit être activable par `ORBITALS_CRASH_B_PROBE=1` et ne doit rien faire en mode normal.

Après cette correction, une seule exécution permettra de comparer des valeurs invitées cohérentes. Seulement ensuite, si `x20_producteur == x21_consommateur` et que les records correspondent, suivre le callback virtuel. Aucun patch fonctionnel de TLS ou de `thr_new()` avant cette preuve.
