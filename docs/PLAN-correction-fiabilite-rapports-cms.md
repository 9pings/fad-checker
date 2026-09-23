# Plan de correction — fiabilité des audits CMS/frameworks

Date : 23 septembre 2026. État : corrections de la vague 1 implémentées et revues ;
les résultats vérifiés les plus récents figurent en tête du handoff. La vague 2
reste à faire.

Ce plan complète `PLAN-plugins-cms-frameworks.md` (§6.3–6.4) et reprend les défauts du
`HANDOFF-plugins-cms-frameworks.md`, ainsi que ceux reproduits lors de la revue du
23 septembre. Il porte sur les plugins expérimentaux WordPress, Drupal, Symfony et
Laravel. La vague Joomla/PrestaShop/TYPO3/Magento attend la validation de ce plan.

## Invariants à conserver

- Développer chaque correction en TDD : test rouge sur le défaut observé, correction,
  puis test vert. La suite ordinaire reste hors ligne et déterministe ; les tests de
  dépôts réels restent optionnels.
- Garder `--app-plugins` explicite pour ces plugins expérimentaux. Aucun passage en
  sélection automatique.
- Un avis absent du rapport ne signifie jamais « sûr » lorsque la source, l'identité,
  la version ou le chemin d'attribution manque. Conserver des contrôles de couverture
  distincts des constats de vulnérabilité.
- Une occurrence physique et un avis donnent un seul `findingId`, même si plusieurs
  sources, composants ou instances y sont liés. Préserver toutes les expositions.
- Préserver le sens `direct/transitive` du gestionnaire de paquets à côté de
  `applicationRelation`. Aucun calcul applicatif ne doit modifier `dep.scope`.
- Les rapports de recette destinés à être relus sont générés en ligne avec OSV actif.
  Wordfence utilise un snapshot conforme aux conditions du fournisseur ; les données
  publiées des CVE, plages, corrections et CVSS restent réelles dans les tests.

## 1. Corriger les résultats et verdicts potentiellement faux (priorité bloquante)

### 1.1 Interroger tous les paquets Drupal en mode live

**Défaut reproduit.** `drupal.js` met en cache le premier snapshot sous la seule URL du
fournisseur. Si la seconde instance possède un module public absent de la première,
sa coordonnée n'est pas demandée : `CMS_PACKAGE_NOT_QUERIED`, aucun avis. Le cache
sur disque ne contient également que la première requête.

- Ajouter à `test/live-advisories.test.js` un test à deux instances Drupal avec
  `drupal/core` dans les deux et `drupal/foo` uniquement dans la seconde. Le faux
  endpoint ne renvoie que les paquets présents dans `packages[]`. Vérifier l'avis
  de `drupal/foo`, la couverture de chaque occurrence, et le snapshot réutilisable
  contenant l'union des paquets réellement interrogés. Inverser l'ordre des
  instances pour exclure une dépendance à l'ordre de découverte.
- Dans `lib/application-plugins/drupal.js` et, si nécessaire,
  `lib/application-plugins/runner.js`, rendre la collecte consciente de l'ensemble
  des paquets demandés : requête sur l'union des identités publiques de toutes les
  instances ou chargement des identités manquantes avant leur évaluation. Fusionner
  seulement des réponses effectivement obtenues ; si une requête requise échoue,
  sortir avec le code 2 avant d'écrire un rapport. Adapter le cache atomique et sa
  provenance pour représenter exactement l'union collectée.
- Recette : toutes les identités publiques inventoriées ont soit un contrôle exécuté
  contre une réponse qui les couvrait, soit une limite explicite ; aucune n'est
  omise parce qu'une autre instance a rempli le cache en premier. Les composants
  privés ne sont jamais envoyés au fournisseur.

### 1.2 Valider les sources explicitement configurées avant la découverte

**Défaut reproduit.** Sur un arbre sans WordPress, `--app-plugins wordpress
--wordfence-feed /chemin/inexistant` termine avec le code 0 : le fichier n'est lu
que lorsqu'une instance atteint `assess`. Cela contredit `docs/USAGE.md`.

- Ajouter à `test/application-cli.test.js` des cas sans instance correspondante
  pour les deux fournisseurs locaux : fichier absent, JSON invalide et schéma
  invalide. Exiger le code 2 et aucun rapport, avec ou sans
  `--max-advisory-age`. Vérifier qu'un fichier valide reste accepté même quand
  aucune instance ne correspond.
- Dans `lib/application-plugins/runner.js`, valider une seule fois chaque fichier
  explicitement configuré avant la découverte : lisibilité, limite de taille,
  décodage JSON, schéma fournisseur et fraîcheur si demandée. Réutiliser l'objet
  validé pendant l'évaluation pour éviter deux lectures divergentes. Conserver la
  règle de sélection explicite du plugin correspondant.
- Recette : toute source locale annoncée mais inutilisable fait échouer le scan
  avant l'écriture des rapports, indépendamment du contenu de `--src`.

### 1.3 Agréger correctement la couverture d'une instance

**Défaut reproduit.** `renderApplicationSummary` trie les contrôles par gravité
croissante et affiche `completed` pour WordPress alors que le core est évalué et
14 thèmes sont `not-run`. Une instance avec constat n'affiche pas non plus de note
sur cette évaluation incomplète.

- Ajouter à `test/application-report.test.js` le cas `core: completed` +
  `theme: not-run` + CVE sur le core ; vérifier la synthèse HTML et Word en EN/FR.
  Tester aussi `failed`, `partial`, plusieurs fournisseurs et zéro constat.
- Calculer un résumé par **capacité et fournisseur** à partir de tous les contrôles
  de l'instance. La présence de `failed`, `partial` ou `not-run` empêche le verdict
  `completed`. Afficher `executed/expected` et le nombre de composants non évalués ;
  une couverture mixte doit être lisible comme partielle, même si un avis a été
  trouvé. Conserver les détails par occurrence dans la section 6.4 et en JSON.
- Recette sur WordPress 6.4.2 : 1 core évalué, 14 thèmes non évalués ; la synthèse
  ne dit jamais que la voie Wordfence est complète.

## 2. Rendre les limites du rapport lisibles et actionnables

### 2.1 Identifier chaque composant concerné, puis regrouper les alertes

- Tester un rapport avec plusieurs thèmes `CMS_IDENTITY_UNVERIFIED` et un module
  privé : chaque ligne de couverture doit donner `occurrenceId`, nom et chemin du
  composant ; les avertissements de chapitre 0 doivent donner la raison, l'action
  et la liste des composants concernés. Ne pas confondre 14 contrôles incomplets
  avec 14 causes différentes.
- Exploiter `coverage.occurrenceId` et l'inventaire dans `lib/cve-report.js` ; si
  nécessaire, enrichir les avertissements structurés créés dans `fad-checker.js`
  sans transformer le message texte en clé de regroupement. Regrouper par
  application, capacité, source et diagnostic, avec compte et chemins détaillés.
- Recette : les 14 thèmes du dépôt WordPress réel sont distinguables dans 6.4 ;
  le chapitre 0 présente un groupe navigable au lieu de 14 messages identiques.

### 2.2 Réparer la numérotation et la traduction du rapport

- Ajouter des assertions ciblées dans `test/application-report.test.js` ou
  `test/cve-report.test.js` : la section « Direct deps to update » relève de 5.x,
  sans 7.0 orphelin ; sa traduction est « Dépendances directes à mettre à jour ».
- Traduire les libellés visibles de capacité, voie, état d'exécution et diagnostic
  dans `lib/i18n.js`, pour la synthèse, 6.4 et le chapitre 0. Préserver les codes
  stables (`CMS_*`, `sourceId`, `execution`) dans le JSON. Tester les deux sens :
  absence de phrases anglaises en FR et absence de phrases françaises en EN.
- Recette : les six rapports du corpus n'ont pas de numéro de section inexistant
  ni de couverture brute en anglais dans la version FR.

### 2.3 Traiter les avertissements de manifests sans masquer une perte de couverture

- Regrouper les avertissements `no-lockfile` par application/type de manifeste,
  avec nombre, liste de chemins et nombre de plages ignorées ; conserver chaque
  chemin dans le JSON. Le rapport Drupal réel ne doit plus afficher une vingtaine
  de blocs quasi identiques.
- Tester la fixture volontairement invalide
  `core/modules/system/tests/fixtures/HtaccessTest` du dépôt Drupal réel : pas de
  composant ni de CVE issu de cette fixture ; afficher son chemin et l'échec de
  parsing comme limite circonscrite, sans suggérer que toute l'instance a échoué.
  Conserver le comportement sans crash.

## 3. Corriger l'attribution et les vues par instance

### 3.1 Distinguer cible de l'avis et bibliothèque introduite

- Tests rouges dans `test/application-inventory.test.js` pour : CVE sur le core,
  composant Symfony officiel, bundle, plugin et thème = `direct` ; CVE sur une
  bibliothèque du lock = `indirect` sous ses origines prouvées ; bibliothèque sans
  origine = `unknown`. Tester les deux origines d'une bibliothèque partagée, les
  scopes prod/dev, et le layout `drupal/drupal` où la racine Composer `replace`
  `drupal/core`.
- Dans `lib/application-inventory.js`, limiter la relation directe aux kinds
  ciblables par l'avis. Une `library` du lock ne s'attribue pas elle-même comme
  origine. Relier le manifeste Composer de la racine au composant primaire
  core/framework de l'application, sur preuve de layout et de manifeste ; ne
  créer aucun rattachement à un plugin à partir du seul `vendor` partagé.
- Recette sur le corpus réel : les 60 constats Drupal aujourd'hui « origine
  inconnue » ont une origine core si le manifeste la prouve ; les CVE sur
  bibliothèques ne gonflent plus le compte applicatif des CVE directes. Les CVE
  du core, de `symfony/http-foundation` et de `laravel/framework` restent directes.
  Documenter les comptes exacts observés après correction, sans les coder comme
  hypothèses avant le test.

### 3.2 Montrer un constat partagé dans chaque instance exposée

- Étendre `test/application-report.test.js` à une occurrence commune à deux
  instances : même `findingId`, une occurrence physique, deux expositions, et
  détail accessible dans **chaque** section d'instance HTML et Word. Vérifier que
  les compteurs globaux restent une union de findings, pas la somme des lignes
  affichées ; exposer le renvoi « partagé » et les origines propres à l'instance.
- Faire grouper `renderApplicationCves` sur toutes les relations d'application,
  pas seulement `applicationIds[0]`. Si le modèle aplati ne porte pas les origines
  par instance, l'enrichir avant le rendu et dans le JSON plutôt que déduire un
  propriétaire depuis le premier identifiant.

### 3.3 Aligner résumés, graphiques et exports

- Une fois les relations corrigées, faire consommer à la synthèse, aux tableaux,
  aux quatre graphiques prévus par `PLAN-plugins-cms-frameworks.md` §6.4 et au JSON
  la même agrégation de `findingId`. Les graphiques nomment les instances et les
  origines, montrent les recoupements des dépendances partagées, et affichent leur
  périmètre et leur couverture. Ne pas présenter des groupes qui se recoupent
  comme des parts exclusives d'un donut.
- Vérifier la parité HTML/Word des sections d'instance et des limites, puis SARIF,
  SBOM, CSAF et diff : même occurrence, même relation et aucune disparition
  interprétée comme « corrigée » si le fournisseur ou la couverture a disparu.
  Ajouter des tests de contrat sur les données, pas seulement des recherches de
  chaînes dans le HTML.

## 4. Recette de clôture

1. `npm test` vert, sans réseau ; les nouveaux tests de régression échouent bien
   avant leur correction. `git diff --check` vert.
2. `FAD_REAL_INSTANCES=1 node --test test/real-instances.test.js` vert : quatre
   clones réels aux tags prévus, quatre CVE attendues, toutes attribuées. Ajouter
   un test à deux instances Drupal pour la source live, avec réponse réseau
   contrôlée dans la suite ordinaire.
3. Régénérer **en ligne** les rapports EN/FR du corpus et les quatre rapports
   individuels, puis contrôler `SHA256SUMS`, les comptes JSON/HTML/Word,
   l'absence d'ID/ancres cassés, la couverture par occurrence et les sections
   d'instance partagées. Publier dans le handoff les comptes exacts et les limites
   restantes, sans utiliser un rapport `--offline` pour conclure à l'absence de CVE.
4. Corriger la phrase périmée de `docs/USAGE.md` qui affirme que Wordfence et
   Drupal ne sont pas encore connectés ; mettre à jour README, changelog et
   handoff seulement pour les comportements effectivement validés.

La vague suivante et les autres fonctions du plan général reprennent après cette
recette, sans considérer la réussite des tests actuels comme preuve suffisante de
couverture ou de qualité du rapport.
