# Indenture face au guide ANSSI sur l'IA agentique

Le 30 octobre 2026, l'ANSSI a publié *Sécuriser un système IA agentique*, V1.0, dans sa
collection « Les Essentiels »
([fiche](https://messervices.cyber.gouv.fr/guides/essentiels-ia-agentique),
[PDF](https://messervices.cyber.gouv.fr/documents-guides/anssi_essentiels_ia_agentique_1.0.pdf)).
Sept principes. Trois décrivent, presque ligne pour ligne, ce que cet outil fait — et c'est une
coïncidence : la version 0.1.2 a été livrée la veille du jour où nous avons découvert que le
guide existait.

Ce document met les sept principes en face de ce qu'Indenture fait réellement, **et de ce qu'il
ne fait pas.** C'est la seconde moitié qui est utile. Si vous êtes ingénieur et qu'on vient de
vous tendre ce guide, vous devriez pouvoir déterminer en cinq minutes quelles cases cet outil
aide à cocher et lesquelles il ne touche pas du tout.

**Ce que ce document n'est pas.** Ce n'est ni une certification, ni un audit, ni une attestation,
ni une revendication de conformité. **L'ANSSI n'a pas examiné cet outil, n'a pas relu ce document
et ne le cautionne pas.** Les verdicts ci-dessous sont une auto-évaluation de l'auteur de
l'outil, vérifiée contre le code en version 0.1.2 — pas contre le README. Les citations du guide
sont courtes et attribuées ; lisez le PDF plutôt que de faire confiance à ce résumé.

**Et une chose à régler avant de lire le reste.** Le principe 5 demande un filtrage que l'agent
ne puisse « contourner ou modifier ». L'application d'Indenture passe par un hook de l'hôte :
**l'application appartient donc à l'hôte, pas à l'outil** — et un hôte peut échouer en ouvert.
Si le hook ne démarre pas, Claude Code signale l'échec et lance la commande quand même ; un
échec analogue est rapporté sur Codex. Rien de ce qui suit ne vaut quoi que ce soit si
`indenture doctor` ne répond pas `healthy`.

---

## Résumé

**Aucun principe n'est couvert de bout en bout.** Deux sortent complètement du périmètre de ce
qu'un outil de ce type peut adresser.

| Principe | Indenture |
|---|---|
| 1 · Analyser et traiter les risques de bout en bout | **Hors périmètre** — organisationnel |
| 2 · Limiter l'autonomie du système agentique | **Contribue à une exigence** |
| 3 · Classer et contrôler les actions des agents | **Partiel — une des trois classes d'action manque entièrement** |
| 4 · Séparer et cloisonner les environnements | **Hors périmètre**, une exigence contribuée |
| 5 · Fonder l'autorisation sur un contrôle déterministe | **Largement couvert — deux manques, dont un structurel** |
| 6 · Limiter l'impact d'un système agentique | **Partiel** |
| 7 · Démontrer et maintenir la maîtrise du système | **Une exigence bien couverte, les autres non** |

---

## 1 · Analyser et traiter les risques de bout en bout

**Le guide demande** une analyse de risque dès la conception, des mesures de sécurité associées à
chaque risque identifié, et de « bloquer la mise en service tant qu'un risque reste
inacceptable ».

**Indenture : hors périmètre.** C'est un processus que mène une équipe, pas une fonction que
fournit un fichier. Le seul lien honnête est en aval : une fois décidé quels effets sont
inacceptables, le fichier de politique est un endroit où les écrire sous une forme qui s'exécute.

---

## 2 · Limiter l'autonomie du système agentique

**Le guide demande** de définir et documenter la mission du système à sa conception puis au
minimum tous les ans, de n'élargir l'autonomie qu'après avoir vérifié l'efficacité des mesures,
et — l'exigence qui concerne cet outil — de « faire respecter cet inventaire par des contrôles de
configuration externes au modèle ».

**Ce qu'Indenture fait.** `policy.json` est précisément un tel contrôle : il est externe au
modèle, il déclare chaque acteur, la *lane* dans laquelle il opère, et ce qu'il peut transmettre
à qui. Le modèle ne le lit pas, ne peut pas l'élargir, et depuis la 0.1.2 ne peut pas y écrire.

**Ce qu'il ne fait pas.** Définir la mission, la documenter, la réviser chaque année et décider
quand élargir l'autonomie : c'est à vous. Indenture n'a aucune notion de « mission » à laquelle
comparer quoi que ce soit.

---

## 3 · Classer et contrôler les actions des agents

**Le guide demande** de définir des critères de criticité et de documenter l'impact métier, de
répartir les actions entre « exécution autonome, approbation humaine obligatoire et action
interdite », de soumettre les actions critiques à une approbation humaine, de « garder le
mécanisme d'approbation hors de portée du système agentique », de « présenter à l'approbateur
humain l'action exacte, son objectif et ses effets attendus », et de « n'exécuter que l'action
approuvée ».

**Ce qu'Indenture fait.** Deux des trois classes existent. `allow` est l'exécution autonome ; une
règle sans `"allow": true` est une action interdite, et `default: "deny"` fait de l'interdiction
le cas par défaut plutôt que l'exception. Les *lanes* (`contained` / `wide` / `irreversible`)
sont l'axe de criticité. Et le mécanisme est bien hors de portée de l'agent : depuis la 0.1.2 le
hook refuse comme type `tamper` toute écriture sur la politique, sur lui-même, sur `indenture.py`
et sur `.claude/settings*.json`, depuis les outils d'édition comme depuis le shell.

**Ce qu'il ne fait pas — et c'est le manque le plus intéressant de toute la cartographie.** Il
n'y a **aucune classe « approbation humaine »**. Indenture répond oui ou non ; il ne sait pas
suspendre une action et attendre quelqu'un. Un refus renvoie le travail vers un humain en
disant à l'agent de solliciter l'opérateur, et le champ `reason` est rendu au modèle pour qu'il
puisse expliquer ce qu'il voulait faire — mais c'est un refus avec une indication, pas un
circuit d'approbation. Rien ne présente l'action exacte à un approbateur, et rien ne garantit
que seule l'action approuvée s'exécute ensuite.

C'est la plus grosse pièce manquante de l'outil face au guide, et c'est le même trou que le
contrôle 5 du KYA (le recours). C'est une question de conception ouverte, pas un secret :
**[les contributions et les cas d'usage sont bienvenus](../../CONTRIBUTING.md).**

---

## 4 · Séparer et cloisonner les environnements

**Le guide demande** des identités, secrets et connecteurs dédiés par environnement
(développement, évaluation, production), des espaces mémoire séparés par organisation cliente et
par environnement, des communications externes transitant exclusivement par des interfaces
maîtrisées, et de « considérer que toute donnée transmise à un modèle hébergé peut être
accessible à son fournisseur ».

**Indenture : hors périmètre.** Il ne gère ni identités, ni secrets, ni connecteurs, ni mémoire,
ni sortie réseau. Une exigence est contribuée de biais : le journal vit dans un répertoire, donc
un environnement séparé a par construction son journal et sa politique — ce qui est une
séparation faible, pas un cloisonnement.

Le dernier point de ce principe mérite deux lectures si vous journalisez des charges utiles :
voir le principe 6.

---

## 5 · Fonder l'autorisation sur un contrôle déterministe

C'est le principe pour lequel l'outil a été construit. Quatre exigences : deux couvertes, une
partielle, une pas adressée du tout.

**5.1 — Un filtrage déterministe en amont de chaque outil ou ressource, indépendant de l'agent,
que l'agent ne puisse contourner ni modifier.** Couvert par conception, avec la réserve posée en
tête de document. L'évaluateur est déterministe : règles ordonnées, la première qui correspond
décide, aucun modèle dans la boucle. C'est un processus séparé qui lit un fichier où l'agent ne
peut pas écrire. Ce n'est **pas** incontournable : un agent qui écrit un script puis l'exécute
est vu comme la commande qui lance le script, et l'hôte peut échouer en ouvert. Les deux limites
sont écrites dans [`SECURITY.md`](../../SECURITY.md).

**5.2 — Authentifier le demandeur et vérifier automatiquement ses droits, l'action, ses
paramètres réels, sa cible et le respect des règles métier ; politique que le modèle ne peut pas
altérer ; refus par défaut.** Partiel, et le manque est nommé.

- *Authentifier le demandeur* — **pas fait.** Un acteur est une chaîne de caractères, prise dans
  `INDENTURE_ACTOR` ou `argv[1]`. Tout ce qui peut poser une variable d'environnement peut se
  nommer n'importe comment. C'est pour ça que le format d'entrée réserve un champ `principal`,
  qu'aucune implémentation n'écrit aujourd'hui : **une entrée sans ce champ signifie que l'acteur
  n'a pas été attribué.** Voir [`DESIGN.md`](../DESIGN.md) §3.4.
- *Vérifier les droits, l'action, la cible* — fait, à la granularité acteur → cible → type.
- *Les paramètres réels* — partiel. Le hook fourni classe en reconnaissant des motifs dans une
  chaîne de commande : il voit `vercel --prod` mais ne décompose pas les arguments en champs. En
  mode bibliothèque, vous appelez `authorize()` vous-même et pouvez être aussi précis que vous
  voulez.
- *Politique que le modèle ne peut pas altérer* — fait depuis la 0.1.2.
- *Refus par défaut* — fait, et pas désactivable par accident : une liste d'acteurs vide déclare
  **personne**, pas tout le monde.

**5.3 — Vérifier qu'un enchaînement d'actions autorisées individuellement ne produit pas un effet
interdit par les règles métier ou de sécurité.** **Pas adressé.** Chaque appel est évalué seul.
Il n'y a ni fenêtre, ni compteur, ni notion de séquence. Trois transmissions permises qui,
ensemble, exfiltrent quelque chose sont trois entrées autorisées dans le journal. Le journal rend
la séquence **visible après coup** — `log`, `why`, `replay` — mais rien ne la refuse sur le
moment.

**5.4 — N'accorder aux agents aucune confiance ni aucun privilège implicites.** Couvert, et
c'était un vrai défaut corrigé avant publication : une liste d'acteurs vide signifiait
auparavant « tout le monde est connu », soit un *fail-open* au cœur d'un outil default-deny.

---

## 6 · Limiter l'impact d'un système agentique

**Le guide demande** de considérer comme non fiables les entrées et sorties du système, de
limiter le nombre d'appels successifs entre agents et d'alerter sur les fréquences anormales, de
« maintenir les secrets hors du contexte du modèle, des mémoires et des journaux », de prévoir un
arrêt d'urgence avec révocation des accès déclenchable par un mécanisme de supervision, de tester
les mécanismes de restauration, et de vérifier qu'après une restauration une action déjà exécutée
avec un effet externe n'est pas rejouée.

**Ce qu'Indenture fait.** Les secrets hors du journal sont traités délibérément : les charges
utiles sont stockées sous forme d'empreinte et non de contenu par défaut, et la liste `redact` de
la politique remplace les clés nommées avant toute écriture. La liste par défaut couvre
`api_key`, `token`, `password`, `authorization` et `secret` ; elle est à vous d'étendre, et il
vaut mieux l'étendre avant d'activer le stockage des charges utiles.

`replay` reconstitue l'état à une entrée donnée. Il est **en lecture seule** — il recalcule une
vue depuis le journal et ne réexécute jamais rien — donc la dernière exigence de ce principe est
satisfaite par construction plutôt que par une fonctionnalité.

**Ce qu'il ne fait pas.** Aucune limitation de débit entre agents, aucune alerte sur les
fréquences d'appel, aucun arrêt d'urgence. Révoquer un accès consiste à éditer la politique, ce
qui agit sur l'appel suivant ; un run déjà lancé continue. La révocation en cours de run demande
quelque chose qu'un fichier local ne peut pas fournir.

---

## 7 · Démontrer et maintenir la maîtrise du système

Cinq exigences. Une est la raison d'être de cet outil ; les quatre autres ne sont pas son travail.

**7.1 — Inventaire des composants logiciels, prompts système et dépendances ; versionner ce que
l'on développe ; vérifier provenance, intégrité et vulnérabilités connues.** Hors périmètre.

**7.2 — Tester avant déploiement puis régulièrement, pour détecter les dérives du modèle ;
prévoir un retour arrière.** Hors périmètre pour le système agentique. (Indenture a 89 tests à
lui, un par affirmation de sa documentation. C'est de l'hygiène, pas de la conformité.)

**7.3 — Superviser en production les actions de l'agent en les comparant à la mission documentée
et aux outils autorisés, pour détecter les changements d'objectif et les séquences d'actions
inhabituelles (UEBA).** Partiel, et le partage est net : Indenture produit la **matière
première** — chaque transmission autorisée et refusée, avec l'acteur, la cible, le type, la lane,
la règle qui a décidé et une empreinte de ce qui a été transmis — et n'exerce **aucune
supervision**. Aucune mission à laquelle comparer, aucune base de référence, aucune détection
d'anomalie. Brancher un outil de détection sur `journal.jsonl` est raisonnable ; Indenture ne le
fera pas pour vous.

**7.4 — Maintenir les journaux du système agentique hors de portée des modifications de l'agent
pour préserver leur intégrité, afin de pouvoir reconstituer après un incident la séquence
complète : demande → autorisation → action → résultat.** C'est l'exigence que cet outil couvre le
mieux, et il ne la couvre pas entièrement.

Hors de portée de l'agent : depuis la 0.1.2, oui, pour les chemins évidents. Intégrité :
l'empreinte de chaque entrée couvre ses propres champs et l'empreinte précédente, et `verify`
recalcule la chaîne. Reconstitution : `log`, `why`, `replay` et `blame` rebâtissent la séquence.

**Mais le guide demande quatre maillons et le journal en enregistre trois.** La demande,
l'autorisation et l'action y sont. **Le résultat n'y est pas.** Une entrée dit qu'une
transmission a été autorisée par la règle *n* à 14 h 32 ; elle ne dit pas si l'action a ensuite
réussi, échoué, ou fait autre chose. Un hook `PreToolUse` est interrogé *avant* et n'apprend
jamais l'issue. Fermer ce maillon suppose d'enregistrer aussi après exécution, et rien dans
l'outil ne le fait aujourd'hui.

Deux limites d'intégrité sont également écrites plutôt qu'escamotées : **couper la fin du journal
laisse une chaîne valide** — une chaîne plus courte se vérifie quand même, donc seul un reçu
tiers le détectera — et une chaîne est *tamper-evident*, pas *tamper-proof* : qui peut réécrire
le fichier peut recalculer toutes les empreintes. Il existe une version plus forte de cette
objection, à connaître avant de s'appuyer sur n'importe quel journal chaîné, celui-ci inclus :
une chaîne signée établit l'**intégrité mais pas la complétude**, donc une action omise se
vérifie parfaitement ([arXiv 2610.07459](https://arxiv.org/pdf/2610.07459)). Cela ne se résout
pas par une meilleure cryptographie, mais par un enregistreur indépendant.

**7.5 — Tenir à jour le référentiel des responsables des politiques, des alertes et des
exceptions.** Hors périmètre. Cela dit, `blame` et un `git log` sur un `policy.json` versionné
vous disent qui a changé une règle et quand, ce qui est un début.

---

## Le bilan honnête

Cinq choses que le guide demande et que cet outil ne fait pas. Aucune n'est cachée ailleurs dans
la documentation, et chacune est une question de conception ouverte plutôt qu'une promesse de
feuille de route.

1. **Aucune voie d'approbation humaine** (principe 3). Oui ou non, jamais « attends ».
2. **Aucune authentification du demandeur** (principe 5.2). Un acteur est une chaîne ;
   `principal` est réservé et non écrit.
3. **Aucun contrôle d'enchaînement** (principe 5.3). Chaque appel est jugé seul.
4. **Aucun résultat enregistré** (principe 7.4). Demande, autorisation, action — pas l'issue.
5. **Aucune révocation en cours de run** (principe 6). Éditer la politique attrape l'appel
   suivant, pas le run en cours.

Et trois limites qui sont des propriétés de l'approche plutôt que des fonctions manquantes :
l'application appartient à l'hôte et un hôte peut échouer en ouvert ; un script écrit puis
exécuté n'est pas vu pour ce qu'il est ; un journal tronqué se vérifie quand même.

## Comment se servir de ce document

Comme de quelque chose à poser sur la table, pas comme d'une réponse. Si votre RSSI vous tend les
sept principes, ceci vous dit qu'un seul outil couvre l'essentiel du principe 5, une partie des
3, 6 et 7, et rien des 1 et 4 — ce qui est un résultat sain pour un unique fichier Python de
bibliothèque standard, et un résultat déplorable si quelqu'un attendait un produit de conformité.

Si vous travaillez dans un contexte où l'un des cinq manques ci-dessus est celui qui compte, ça
vaut plus pour ce projet qu'une étoile.
[Ouvrez une issue](https://github.com/Sylv-ctr/indenture/issues) en disant lequel, et ce qui
casse chez vous.

---

*Écrit le 24 novembre 2026 contre Indenture 0.1.2 et le guide ANSSI V1.0 (10/26). Le guide peut
être révisé ; ce document n'est pas mis à jour automatiquement. Lisez le PDF.*
