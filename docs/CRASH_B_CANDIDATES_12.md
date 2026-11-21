# Crash B — suivi des 12 candidats d'écriture E8

Date : 2026-11-21  
Statut : **piste de structure à confirmer — aucun écrivain du pointeur QWORD n'est identifié à ce stade**.

## Données reçues

Les 12 résultats proviennent du scan des objets COFF x64 sous `setup-work/obj`. Les offsets ci-dessous sont des offsets dans la section `.text` du fichier objet, pas des adresses virtuelles du jeu.

| Candidat | Objet | Offset .text | Instruction |
|---:|---|---:|---|
| 1 | `main_main_0156.o` | `0x3795F` | `mov dword ptr [rbx+rsi], edi` |
| 2 | `main_main_0157.o` | `0x07D6A` | `mov dword ptr [rax+rcx], 0xFFFFFFFF` |
| 3 | `main_main_0157.o` | `0x23F0A` | `mov dword ptr [rax+r8], ecx` |
| 4 | `main_main_0157.o` | `0x23F15` | `mov dword ptr [r8+rax], 0xFFFFFFFF` |
| 5 | `main_main_0173.o` | `0x2968B` | `mov dword ptr [rdx+rcx], r14d` |
| 6 | `main_main_0173.o` | `0x2968F` | `mov dword ptr [rcx+rax], 0xFFFFFFFF` |
| 7 | `main_main_0173.o` | `0x29F1C` | `mov dword ptr [r9+rcx], r8d` |
| 8 | `main_main_0173.o` | `0x29F44` | `mov dword ptr [rdx+rcx], 0xFFFFFFFF` |
| 9 | `main_main_0186.o` | `0x615A7` | `mov dword ptr [r9+rdx], r10d` |
| 10 | `main_main_0186.o` | `0x615CB` | `mov dword ptr [rdx+r8], 0xFFFFFFFF` |
| 11 | `main_main_0330.o` | `0x17282` | `mov dword ptr [rdx+rax], r9d` |
| 12 | `main_main_0330.o` | `0x17291` | `mov dword ptr [rcx+rax], 0xFFFFFFFF` |

## Regroupement des séquences

- **Candidats 3–4** : deux écritures successives calculées avec le pas `0xE8`, une valeur variable puis `0xFFFFFFFF`.
- **Candidats 5–6** : même forme générale dans un autre objet ; le contexte teste le champ `[rbx+0x34]` avant l'écriture variable.
- **Candidats 7–8** : autre séquence avec un test de registre et une valeur sentinelle.
- **Candidats 9–10** : même forme générale dans `main_main_0186.o`.
- **Candidats 11–12** : même forme générale dans `main_main_0330.o`.
- **Candidat 2** : initialisation sentinelle isolée dans le contexte fourni.
- **Candidat 1** : écriture variable distincte ; son calcul `r11 * 0xE8` doit être suivi séparément.

La répétition entre plusieurs objets peut correspondre à du code générique instancié/inliné ou à plusieurs parcours de données similaires. Elle ne prouve pas qu'il s'agit du même tableau à l'exécution.

## Ce que ces résultats établissent — et n'établissent pas

1. Chaque instruction affichée écrit **un DWORD de 4 octets**, pas un QWORD de 8 octets.
2. Le scan a associé l'adresse à un calcul `IMUL * 0xE8`. Les extraits ne montrent pas toujours l'origine complète de l'autre registre qui fournit la base du tableau.
3. Les valeurs `0xFFFFFFFF` ressemblent à des sentinelles, mais leur signification exacte n'est pas démontrée.
4. Aucun de ces extraits ne montre directement l'écriture QWORD du pointeur lu ensuite par le code du crash.
5. Il n'est donc pas possible de désigner un candidat comme cause du pointeur nul ni de relier formellement ces séquences au chemin fautif `main_main_0184.o` / `.text+0x1952F`.

## Prochaine analyse statique nécessaire

Pour chaque séquence prioritaire (3–4, 5–6, 9–10 et 11–12), il faut récupérer la fonction entière ou au minimum :
- les instructions qui construisent le registre de base du tableau ;
- les lectures/écritures QWORD à `[base + index*0xE8 + 0]` ;
- les éventuelles initialisations/allocation du tableau ;
- les branches qui déterminent si l'élément existe ou reste vide.

Puis comparer les champs et le flux de données avec le consommateur dans `main_main_0184.o` à `.text+0x19507–0x1952F`, qui charge un QWORD depuis le début de l'élément sélectionné avant l'accès fautif.

**Contrainte d'accès :** ces six fichiers objets sont uniquement présents sur le PC de l'utilisateur et ne sont pas dans ce dépôt. GitHub ne peut pas lire directement `C:\Users\...\setup-work\obj`. Une action GitHub hébergée ne pourra pas analyser ces objets tant qu'ils ne sont pas fournis au dépôt ou à un runner connecté à la machine locale. Ne pas prétendre que l'analyse complète a été exécutée depuis GitHub.


## État de l'étape 3 — examen des six objets : TERMINÉ

L'utilisateur a explicitement confirmé que l'examen des six objets contenant les 12 candidats a déjà été effectué. Cette étape ne doit pas être redemandée ni reproposée comme prochaine étape.

Les 12 instructions ci-dessus restent des écritures DWORD de 4 octets. Elles ne montrent pas directement l'écriture QWORD du premier champ de l'élément base + index*0xE8. Le dossier ne conserve pas ici l'intégralité des désassemblages des fonctions examinées ni une preuve reliant un candidat au pointeur nul consommé dans main_main_0184.o. Aucun candidat ne peut donc être désigné comme constructeur ou écrivain causal sur la seule base de cette liste.

Statut : examen effectué ; lien causal non établi. La suite doit exploiter les conclusions détaillées déjà obtenues localement, sans refaire les scans ni demander de nouveau les mêmes sorties.