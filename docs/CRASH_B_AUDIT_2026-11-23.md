# Audit de cohérence Crash B — 23-11-2026

## Objet

Cette note corrige et complète les conclusions de l'audit des logs, du binaire et des branches GitHub. Elle ne constitue pas une résolution du crash. **Crash B reste prioritaire** ; Crash A (FMallocBinned3 / pointeur non reconnu) reste suspendu.

## Conclusion actuelle

Le crash hôte observé est une lecture à l'adresse `0x104` dans `orbitalgame.dll`, à RVA `0x1B5B682F`. Les octets hôtes `42 8B 4C 01 5C` correspondent à :

```asm
mov ecx, [rcx + r8 + 0x5C]
```

Avec les registres hôtes du rapport (`RCX=0`, `R8=0xA8`), le calcul donne bien `0 + 0xA8 + 0x5C = 0x104`. `RDX=0xFFFFFFFF` est également rapporté, mais **aucun mapping valide hôte → registres ARM64 invités n'a été établi**. Il est donc incorrect d'en déduire `w8=-1` ou une valeur précise de `w8`.

Le désassemblage invité identifie dans `main+0x1759B20` le chemin suivant :

```asm
main+0x1759DE4: ldr    x9, [x21, #0x158]
main+0x1759DE8: mov    w10, #0xE8
main+0x1759DF0: umaddl x27, w20, w10, x9
...
main+0x175A01C: ldr    x9, [x27]
main+0x175A020: mov    w10, #2
main+0x175A024: mov    w11, #0x38
main+0x175A028: sub    w10, w10, w8
main+0x175A02C: umaddl x25, w10, w11, x9
main+0x175A030: ldr    w9, [x25, #0x5C]
```

Le modèle statique comporte deux niveaux : un enregistrement extérieur de stride `0xE8`, puis une structure intérieure pointée par son premier QWORD, indexée avec le stride `0x38`. L'instruction invitée candidate au point de lecture fautif est `main+0x175A030`. La correspondance exacte avec l'instruction hôte doit encore être confirmée par une capture synchronisée.

## Ce qui est observé mais pas encore prouvé au moment exact du crash

Un rapport antérieur donne `x27=0x84014D000` et `[x27]=0`, avec `x21=0xB40012810`. D'autres exécutions ont d'autres valeurs de `x27`. Le bloc mémoire a été signalé comme alloué et les premiers octets de cet enregistrement sont nuls.

**Réserve majeure :** le crash reporter lit `c->x[]`, alors que le code généré peut conserver les registres invités dans des variables locales C. Les valeurs rapportées peuvent donc être périmées et ne sont pas garanties synchronisées avec l'instruction fautive. Les dumps d'entrée de fonction ne remplacent pas non plus une capture à `main+0x175A030`.

Le champ diagnostique `pc=sdk+0x16B730` ne suffit pas à démontrer que `nn::os::GetTlsValue` est la fonction réellement fautive : il peut représenter une cible de dispatch en attente. La fonction levée identifiée est `main+0x1759B20`, et l'instruction invitée suspecte est à `main+0x175A030`. Le lien causal direct avec le code SDK TLS n'est pas établi.

## Instrumentation par thread : correction importante

Une instrumentation TLS par thread existe dans le commit :

`9dd31b19011b0047cb52f34fc763f7f903e7fad5`

Branche : `tls-crash-b-capture-gpt-sined` du dépôt `sinedgiveaways/pmocer-latibro`.

Elle comprend :
- 32 emplacements de threads ;
- 64 entrées par type d'événement et par thread ;
- deux catégories : entrées `GetTlsValue` et entrées de `main+0x1759b20` ;
- capture de `x0-x7`, `x27`, `TPIDR_EL0`, `TPIDRRO_EL0`, `LR` et du compteur de débordement ;
- activation par `ORBITALS_TLS_DIAG=1`, via `FN_ENTER` / `fnprof_hit` / `rt_tls_diag_hit` et `rt_dispatch`.

Le workflow GitHub Actions `44900273712` a réussi sur ce commit et a produit l'artifact `orbitals-recomp-exe-gpt-sined` (artifact ID `14705487424`, environ 10,4 MB). L'utilisateur a confirmé avoir téléchargé cet artifact.

**Mais l'historique disponible ne confirme pas que cet artifact a été exécuté avec `ORBITALS_TLS_DIAG=1`,  ni qu'un log résultant a été récupéré.** Une extraction PowerShell antérieure n'a trouvé aucun `*.log` dans le dossier courant ; cela ne prouve pas que le programme instrumenté n'a rien enregistré.

Autre limite : cette instrumentation capture l'entrée de la fonction `main+0x1759b20`, pas les registres au milieu de la fonction à `main+0x175A030`. Elle ne répond donc pas à elle seule à la question du registre réellement utilisé lors de la lecture fautive.

Le build `0.2.0-g80c5db8` de la branche `orbitals-port` utilise encore l'ancien anneau global de 64 entrées. Le message « no entry captured » de ce build **ne teste pas** la nouvelle instrumentation par thread du commit ci-dessus.

## Producteur candidat

Les fonctions `main+0x174E180`, `main+0x1784920` et `main+0x1784AC0` restent des candidates : elles construisent un enregistrement temporaire, obtiennent un pointeur via un callback virtuel à `vtable+0xA8`,  le stockent en tête de l'enregistrement et copient les premiers 16 octets vers un élément de stride `0xE8`.

Le consommateur utilise `x21` et `[x21+0x158]` ; le producteur examiné utilise `x20) et `[x20+0x158]`. L'identité runtime de ces conteneurs, l'index correspondant, le résultat du callback et la destination de la copie ne sont pas encore établis. Il s'agit d'une piste, pas d'un producteur confirmé.

Les scans des six objets COFF et des 12 candidats DWORD, le QWORD Writer Hunter et le Pointer Provenance ont déjà été exécutés. Ne pas relancer ces scans. Les résultats ne désignent pas encore le writer du premier QWORD de l'élément réellement consommé.

## Mesure suivante — capture synchronisée ciblée

La prochaine instrumentation doit capturer au point exact `main+0x175A030`, sur le thread qui plante :

- PC invité et registres ARM64 réellement vivants : `x20`, `x21`, `x27`, `w8`, `x25`, `SP`, `LR` ;
- `[x21+0x158]`,  l'index `w20`,  `[x27]` et les octets de l'enregistrement extérieur ;
- l'adresse effective calculée pour le chargement `[x25+0x5C]` ;
- un snapshot hôte associé à la même exception, avec RIP et registres hôtes.

Au producteur candidat, capturer séparément `x20`, `x25`, l'adresse de la vtable, la cible du callback `+0xA8`, son résultat, la destination de la copie et le premier QWORD écrit. Comparer ensuite l'identité du conteneur et l'index avec ceux du consommateur.

## Contraintes opérationnelles à respecter

- Ne pas lancer `prepare.py`, génération ou recompilation complète pour cette instrumentation.
- Ne pas modifier arbitrairement `thr_new()`, les tailles TLS ou `GetTlsValue` sans preuve.
- Ne pas demander de réinstaller ProcDump, de refaire les scans COFF, de vérifier de nouveau le PDB/DLL, ou de refaire les imports.
- L'utilisateur ne souhaite pas utiliser Ghidra.
- Privilégier un outil Windows GUI ou un patch d'instrumentation ciblé qui réutilise les artefacts et objets déjà générés.

## État final

| Question | État au 23-11-2026 |
|---|---|
| Adresse hôte lue | `0x104`, confirmée par les registres hôtes rapportés |
| Instruction invitée candidate | `main+0x175A030`, à synchroniser avec l'exception |
| Enregistrement extérieur stride `0xE8` | Modèle statique établi |
| Structure intérieure stride `0x38` | Modèle statique établi |
| `[x27]=0` au moment exact du crash | Non prouvé |
| Valeur de `w8` au moment exact du crash | Non capturée |
| `GetTlsValue` cause directe | Non démontré |
| Instrumentation par thread | Commit et artifact CI confirmés ; exécution avec le flag et log non confirmés |
| Producteur du premier QWORD | Candidat, pas confirmé |
| Cause racine Crash B | Non déterminée |
| Crash A | Suspendu, non résolu |
