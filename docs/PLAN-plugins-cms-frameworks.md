# Plan de support CMS et frameworks par plugins

Date : 23 septembre 2026. Base étudiée : fad-checker 2.5.2.
Statut : feuille de route historique ; l'état d'implémentation et les vérifications récentes figurent dans `HANDOFF-plugins-cms-frameworks.md`.

## 1. Objectif et décisions proposées

Étendre fad-checker pour auditer des applications WordPress, Drupal, Symfony et les autres CMS/frameworks courants, en conservant ses engagements : analyse locale sans exécution du projet, preuves traçables, fonctionnement hors ligne, rapports exploitables par un auditeur et intégration CI.

Le niveau de qualité attendu impose deux résultats de même importance : trouver les vulnérabilités connues applicables et expliquer précisément les éléments que le scan n'a pas pu évaluer. « Aucun avis trouvé » ne signifie ni « composant sûr », ni « application sécurisée ».

Décisions recommandées :

1. Ajouter une couche de **plugins d'analyse applicative**, complémentaire des codecs de gestionnaires de paquets. Un plugin Symfony réutilise Composer ; un plugin WordPress découvre également des composants sans Composer.
2. Livrer d'abord des plugins intégrés et testés avec fad-checker. Stabiliser leur contrat avant d'ouvrir un chargement de code tiers.
3. Première livraison qualifiée : **Symfony, WordPress et Drupal**, avec inventaire, avis de sécurité, cycle de vie et couverture explicite. Laravel suit immédiatement, en réutilisant le socle Composer.
4. Vague suivante : Joomla, PrestaShop, TYPO3, Magento Open Source/Adobe Commerce. Chaque plugin obtient son propre niveau de qualification, sans promesse uniforme sur leurs extensions tierces.
5. Commencer par la SCA et le contexte applicatif. Les contrôles de configuration statiques seront un lot distinct, avec une conclusion limitée à ce que les fichiers prouvent.
6. Corriger les pertes d'information du socle avant d'y ajouter les nouveaux plugins.
7. Dans le chapitre CVE, organiser les résultats par **CMS/framework → instance → CVE directes / CVE indirectes par origine**. Les failles du core, des extensions, thèmes et bundles sont directes ; les failles de leurs dépendances sont indirectes dans cette vue applicative. Cette présentation fait partie de la première livraison.
8. Faire calculer **tableaux, résumés et graphiques à partir d'une agrégation commune**, avec les mêmes identifiants de findings, filtres et périmètres. Les groupes qui se recoupent ne doivent pas être représentés comme les parts exclusives d'un total.

Le mot « plugin » désigne ici un module de fad-checker. Une extension WordPress, Drupal ou Joomla est un **composant audité** ; aucun plugin n'est à installer dans l'application cliente.

## 2. Ce que le projet fournit déjà

L'étude porte sur la CLI, les codecs, la collecte Composer, les services CVE/OSV, les exports, la provenance, les contrôles de couverture, les tests et la CI. Il ne s'agit pas d'un audit exhaustif du moteur existant.

| Socle observé | Réutilisation prévue |
| --- | --- |
| Contrat et registre des codecs dans `lib/codecs/codec.interface.js` et `lib/codecs/index.js` | Conserver les codecs pour les coordonnées, manifests et registres de paquets |
| Composer : lockfiles, fallback sur versions exactes, Packagist, OSV `Packagist` | Socle commun aux applications PHP |
| Symfony/Laravel déjà reconnus pour le regroupement EOL dans `lib/outdated.js` et `data/eol-composer-frameworks.json` | Réutiliser les correspondances, sans déduire qu'une application Symfony existe de tout paquet `symfony/*` |
| Analyse de la plateforme PHP dans `lib/codecs/composer/platform.js` | Conserver la distinction entre contrainte déclarée et runtime réellement déployé |
| OSV, NVD, EPSS, KEV, priorité, suppressions et VEX | Enrichir les avis CMS via le pipeline commun lorsque les identifiants le permettent |
| HTML, Word, JSON, SARIF, CycloneDX et CSAF | Ajouter preuves et couverture dans les formats appropriés |
| Cache, export/import hors ligne, descripteur anonymisé | Étendre aux données des plugins et fournisseurs spécialisés |
| `source-health`, provenance, limitations, exclusions, diff et gate CI | Faire de la couverture une donnée commune à tous ces services |
| CI Node 20/22/24 sur Linux, Node 22 sur Windows | Conserver la matrice et vérifier aussi les binaires compilés |

Vérification du 23 septembre : **884 tests réussis, 0 échec**, sous Node 24.14.0. Le premier lancement dans le bac à sable échouait notamment sur les accès au cache utilisateur et les sous-processus ; le lancement autorisé hors bac à sable passe. Ce résultat valide la suite actuelle, pas une couverture CMS qui reste à construire.

### Prérequis de fiabilité identifiés

| Observation dans le code | Conséquence | Travail préalable |
| --- | --- | --- |
| `composer.codec.js`, lignes 69–70 et 84–85 : `out.set()` remplace l'entrée de même coordonnée | Deux projets PHP peuvent perdre une version, son scope et son origine ; risque de faux négatif | Préserver les occurrences par application/version/emplacement et agréger sans écrasement |
| Reproduction sur `test/fixtures` : `symfony/console` 5.4.47 dans deux locks et 6.2.10 dans un troisième ; seul 6.2.10 subsiste | Le problème existe sur les fixtures actuelles, indépendamment des plugins futurs | Ajouter une régression multisite avant correction |
| `composer/parse.js` ne restitue que nom/version/scope ; tous les paquets de `packages` deviennent `prod` | Pas de graphe direct/transitif ni de métadonnées nécessaires aux CMS | Lire aussi les liens, types, sources, remplacements et métadonnées d'installation utiles |
| `lib/scan-completeness.js` examine les versions non résolues Maven | Ce diagnostic ne couvre pas les identités/versions CMS inconnues | Un registre de couverture multi-capacités |
| `lib/json-export.js` ne sérialise pas les avertissements transmis au rapport HTML | La CI et le diff ne disposent pas de toutes les limites du scan | Exporter `warnings`, `coverage`, `applications` et inventaire applicatif |
| `lib/osv.js:176` utilise `Maven` comme fallback d'un écosystème inconnu | Un ajout naïf de `wordpress` pourrait interroger le mauvais écosystème | Routage explicite ; écosystème non pris en charge = capacité indisponible |
| `lib/source-health.js` est fondé sur une liste de domaines ; HTTP 401 n'est pas classé comme indisponible | Insuffisant pour de nouveaux fournisseurs authentifiés et leurs erreurs fonctionnelles | Déclarer les sources par fournisseur, vérifier statut HTTP **et** schéma de réponse |
| `collectExcludedDirs()` refait un parcours avec l'union des exclusions des codecs | La liste ne représente pas exactement le travail de chaque analyseur | Enregistrer les événements réels du parcours par capacité |
| La provenance de plusieurs caches utilise le mtime le plus récent | Un fichier récent ne prouve pas que toutes les recherches ont été couvertes | Tracer les entrées effectivement consultées et les snapshots utilisés |

Autre point à tester dans le lot initial : une interruption de source doit appliquer la même politique avec JSON seul, HTML seul, exports combinés ou sans rapport. Ne pas dépendre d'un branchement propre au rendu HTML.

## 3. Périmètre produit et ordre de qualification

L'ordre ci-dessous est une priorité d'ingénierie, fondée sur la demande et le socle PHP existant ; ce n'est pas un classement mesuré des parts de marché.

| Vague | Plugin | Première couverture à qualifier | Limites à déclarer |
| --- | --- | --- | --- |
| 1 | Symfony | Applications modernes/legacy explicitement testées, composants et bundles Composer, dépendances, avis, support | Une bibliothèque utilisant `symfony/console` n'est pas une application Symfony ; configuration exécutée inconnue |
| 1 | WordPress | Core, extensions, thèmes parents/enfants, MU-plugins, drop-ins, installations classiques et Bedrock | Slugs ambigus, extensions privées/premium, versions absentes, activation et multisite non établis |
| 1 | Drupal | Core, modules, thèmes, profils, Composer et distributions sans lock ; reconnaissance Drupal 7 historique | Projets hors politique de sécurité, branches legacy, patches privés, configuration active absente |
| 1b | Laravel | Application, framework et paquets Composer, avis et support | Paquets Illuminate isolés ; configuration runtime et cache non observés |
| 2 | Joomla | Core et manifests XML des composants/modules/plugins/templates | Registre et avis des extensions hétérogènes ; version de base de données distincte du code |
| 2 | PrestaShop | Core, modules/thèmes identifiables, dépendances Composer et JS | Versions calculées en PHP, modules commerciaux, overrides et forks |
| 2 | TYPO3 | Core Composer et legacy, extensions et dépendances | Support communautaire vs support contractuel, forks et extensions privées |
| 2 | Magento / Adobe Commerce | Édition, version produit, modules Composer, versions `-pN`, avis éditeur | Modules commerciaux, hotfixes hors version, statut réel des patches et droits de support |
| 3 | Django, Rails, Spring Boot, puis Next.js/Nuxt | Plugins applicatifs adossés à PyPI, Ruby, Maven/Gradle et npm existants | Définir des critères d'application propres à chaque framework ; ne pas assimiler chaque bibliothèque à une application |

Pour chaque plugin, publier une matrice « versions testées / formats reconnus / capacités / exclusions ». Une ancienne branche peut être **reconnue et signalée EOL** sans bénéficier d'une promesse de couverture complète des avis.

Modes d'entrée à distinguer :

- **Arbre source** : décrit l'intention des manifests et les fichiers présents ; ne prouve pas le déploiement.
- **Copie d'installation** : permet d'observer les composants sur disque ; ne prouve pas leur activation ni leur accessibilité HTTP.
- **Extension seule** : audit valable de cette extension ; absence de core attendue, sans inventer un site complet.
- **Monorepo/multisite** : plusieurs applications, versions et installations physiques ; conserver leurs frontières.
- **Inventaire fourni par l'opérateur** : futur import documenté, daté et attribué ; niveau de confiance distinct des observations locales.

Les archives CMS non extraites, images de conteneurs et sites accessibles uniquement par URL ne font pas partie de la première livraison. Une entrée non prise en charge doit être annoncée, jamais présentée comme un scan réussi sans composant.

## 4. Architecture cible

```text
Arbre local + manifests + inventaires explicitement fournis
                         |
           Découverte et journal de parcours
                 /                       \
         Codecs existants          Plugins applicatifs
      Paquets et dépendances      Applications / extensions
                 \                       /
             Composants + occurrences + preuves
                         |
             Routage explicite des fournisseurs
       OSV / Packagist / Drupal / WordPress / éditeurs
                         |
             Avis normalisés + verdicts + couverture
                         |
      Enrichissement / triage / priorité / diff / gate CI
                         |
            Rapports et exports communs
```

### 4.1 Contrat de plugin

Proposition de modules :

```text
lib/application-plugins/
  plugin.interface.js       validation du contrat et de sa version
  index.js                  registre statique ordonné
  select.js                 sélection explicite / auto / désactivation
  runner.js                 cycle de vie, erreurs, budgets, diagnostics
  wordpress/{index,detect,collect,identity,versions,rules}.js
  drupal/{index,detect,collect,identity,versions,rules}.js
  symfony/{index,detect,collect,rules}.js
  laravel/...
lib/advisories/
  provider.interface.js
  index.js
  match.js                  évaluations et déduplication communes
  providers/{wordfence,drupal,packagist,...}.js
lib/application-inventory.js
lib/scan-coverage.js
lib/evidence.js
```

Interface indicative, à verrouiller par des tests de contrat :

```js
{
  id, version, apiVersion, label,
  supportedLayouts, capabilities, requiredCodecs, providerIds,
  discover(context),                     // applications candidates + preuves
  collect(application, context),         // observations et composants
  assess(application, inventory, context), // contrôles locaux purs
  remediation(finding, context)          // recommandations structurées
}
```

Le noyau décide du routage vers les fournisseurs ; chaque plugin produit les identités nécessaires. Il ne réimplémente pas OSV, NVD, les exports, les caches ou les gates.

`context` fournit un accès borné aux fichiers, l'index des manifests déjà parsés, les exclusions, les budgets, les horodatages injectables et le journal de couverture. Les fournisseurs reçoivent le client réseau/cache commun. Les hooks ne lancent ni PHP, ni Composer, ni WP-CLI, ni Drush, ni console Symfony, et ne chargent aucun code de la cible.

Un plugin intégré reste du code de confiance exécuté dans le processus de fad-checker : ce contrat n'est pas un sandbox. Les plugins tiers éventuels nécessiteront un lot séparé : installation explicite, compatibilité d'API, provenance vérifiable, dépendances verrouillées et modèle d'isolation documenté. Aucun chargement automatique depuis le dépôt audité.

### 4.2 Découverte et frontières d'application

- Indexer l'arbre une fois autant que possible ; mutualiser avec `parallel-walk` et les parseurs existants. Ne pas multiplier les parcours complets par plugin.
- Produire des candidats avec preuves positives : marqueurs structurants, manifests, ancres de version. Un nom de dossier seul ne suffit pas.
- Attribuer les fichiers au bon projet et distinguer application embarquée, bibliothèque, extension autonome, exemples et fixtures. Les cas ambigus restent visibles.
- Ne pas arrêter la découverte à la première application trouvée. Tester installations imbriquées et plusieurs document roots.
- Les exclusions utilisateur restent prioritaires. Un plugin peut lire des métadonnées ciblées sous `vendor` lorsque sa politique le prévoit ; il ne transforme pas automatiquement chaque dépendance en application indépendante.
- Journaliser `parsed`, `excluded`, `unreadable`, `symlink-skipped`, `budget-exceeded`, avec chemin, capacité et raison. Une erreur de lecture devient une limite de couverture.
- Borner profondeur, nombre et taille des fichiers, expansion YAML/XML et temps de parsing. Aucun suivi de lien symbolique hors racines autorisées ; signaler les emplacements externes non analysés.

### 4.3 Identité, versions et occurrences

Le modèle doit distinguer quatre notions :

| Entité | Rôle |
| --- | --- |
| `Application` | Type, racine relative, contexte source/installation, preuves de détection et limites |
| `Component` | Identité canonique du produit/paquet, type core/module/plugin/theme/bundle/library et aliases prouvés |
| `Occurrence` | Version observée, emplacement, application, portée prod/dev et provenance |
| `Evidence` | Fichier, champ ou lignes, méthode, empreinte et données minimales ayant justifié la conclusion |

Exemple d'observation :

```js
{
  applicationId: "site-a",
  componentId: "wordpress:plugin:example",
  occurrenceId: "site-a:wp-content/plugins/example",
  kind: "plugin",
  version: { raw: "1.2.3", normalized: "1.2.3", scheme: "php" },
  identityStatus: "verified",   // verified | probable | unknown | conflict
  versionStatus: "observed",    // observed | locked | declared | unknown | conflict
  activation: "unknown",       // ne pas déduire l'activation de la présence
  evidence: [{ path: "wp-content/plugins/example/example.php", field: "Version" }]
}
```

`verified` signifie « identité établie selon la méthode indiquée », pas « authenticité cryptographique du composant garantie ». Conserver la force de la preuve : métadonnée déclarative, correspondance de catalogue, empreinte de distribution, import externe.

Stratégie de migration :

1. Étendre de façon additive les enregistrements et conserver un inventaire d'occurrences canonique.
2. Alimenter la Map historique avec une vue agrégée compatible : `versions`, `versionPaths`, relations et scopes sans perte. Ne pas imposer immédiatement une réécriture de tous les codecs.
3. Dédupliquer les requêtes par fournisseur/identité/version, puis réattribuer les résultats à **chaque occurrence** avec son scope. Un paquet en production sur un site et en développement ailleurs ne doit pas fusionner en une portée globale erronée.
4. Adapter rapports, SBOM, CSAF, SARIF, suppressions et diff pour conserver ces relations.
5. Ne pas réutiliser `ecosystemType` pour transformer un paquet Composer en pseudo-paquet Symfony. Employer des relations applicatives et des identités CMS supplémentaires.

Les identifiants doivent être stables entre deux scans et indépendants du chemin absolu de checkout. Deux installations du même slug ou deux versions du même paquet restent deux occurrences. Les métadonnées Composer et les headers locaux ne se fusionnent que si elles décrivent effectivement la même installation ; une divergence crée un conflit traçable.

### 4.4 Sources d'avis et rapprochement

Contrat fournisseur : capacités, domaines autorisés, authentification, sémantique de version, schéma de données, état de synchronisation, politique de cache et attribution. Une réponse contient des avis **et** un résultat de recherche structuré ; une exception ou un cache absent n'est jamais normalisé en tableau vide concluant.

Un avis normalisé conserve : identifiant d'origine, aliases CVE/GHSA/PKSA/SA/UUID, éditeur, produit exact, plages affectées, branches corrigées, préconditions publiées, dates, statut retiré/rejeté, sévérité originale, CVSS s'il existe, références et obligations d'attribution.

Règles de matching :

- Identité exacte et schéma de version compatibles avant de conclure à une version affectée. Aucun rapprochement confirmé à partir d'un simple titre, nom commercial ou mot-clé CPE.
- Préserver les aliases et dédupliquer par groupe d'avis **et occurrence**. Deux avis sans alias commun ne sont pas fusionnés seulement parce que leurs titres se ressemblent.
- Ne pas fabriquer un CVE pour un avis sans CVE. Il reste une vulnérabilité exploitable par le rapport et le gate selon sa sévérité documentée.
- EPSS et KEV ne sont interrogés que pour les CVE applicables. Absence de score = inconnue, pas risque nul.
- Conserver les désaccords entre fournisseurs et la règle d'arbitrage. Une réponse vide d'un fournisseur n'annule pas un avis positif d'un autre.
- Appliquer les retraits et corrections d'avis. Dater les snapshots pour permettre la reproduction d'un résultat historique.
- Distinguer version affectée, préconditions applicatives inconnues et exploitabilité observée. Le plugin ne prouve pas l'exécution d'une route ou l'exposition réseau.

Pour PHP/WordPress, qualifier les comparaisons selon la sémantique attendue, et non avec un tri numérique simplifié ou SemVer npm appliqué partout. Le [manuel PHP `version_compare`](https://www.php.net/manual/en/function.version-compare.php) sert de référence pour construire les fixtures de comparaison. Les contraintes Composer demandent leur propre traitement.

La recommandation doit choisir une version corrigée de la branche pertinente, sans downgrade, et indiquer si une migration majeure est nécessaire. Une version minimale corrigée ne constitue pas une résolution prouvée de toutes les contraintes de l'application.

## 5. Spécification des premiers plugins

### 5.1 WordPress

**Détection et inventaire**

- Core : extraire statiquement l'affectation de version dans `wp-includes/version.php`, corroborée par la structure d'installation. Détecter des copies multiples et les distributions incomplètes.
- Extensions : lire les headers des fichiers PHP candidats avec des bornes de taille/profondeur et la sémantique des headers WordPress. Séparer nom d'affichage, slug candidat, éditeur, version et URI de mise à jour.
- Thèmes : lire `style.css`, inventorier parent et enfant séparément et relier `Template`. La [documentation officielle du thème](https://developer.wordpress.org/themes/core-concepts/main-stylesheet/) décrit ces champs ; un parent absent reste une lacune explicite.
- Inclure les extensions présentes mais dont l'activation est inconnue, les MU-plugins et les drop-ins. Un chargeur PHP dynamique empêche de prouver les extensions effectivement chargées : inventaire du code présent et diagnostic dédiés. Voir les [particularités officielles des MU-plugins](https://developer.wordpress.org/advanced-administration/plugins/mu-plugins/).
- Traiter Bedrock et ses chemins propres par un adaptateur de layout, en réutilisant Composer. Référence : [structure Bedrock](https://roots.io/bedrock/docs/folder-structure/).
- Accepter des chemins supplémentaires explicitement configurés. Si `WP_CONTENT_DIR` ou un chemin est calculé dynamiquement, ne pas l'exécuter ; indiquer ce qui manque.
- Multisite : distinguer code partagé et instances déclarées. Sans inventaire runtime explicite, ne pas annoncer la liste complète des sites, thèmes actifs ou extensions activées réseau.

**Identité et version**

Le nom du répertoire, le nom visible et le text domain sont des indices, pas des identifiants uniques. Tenir compte de `Plugin URI`, `Update URI`, du catalogue et des correspondances Composer contrôlées ; ne jamais confondre une variante premium avec une version gratuite homonyme. Les [headers officiels](https://developer.wordpress.org/plugins/plugin-basics/header-requirements/) documentent notamment l'URI de mise à jour pour les produits tiers.

La version principale provient du header PHP. `Stable Tag` décrit la publication ; ce champ ne remplace pas la version installée. Cette distinction est explicitée dans la [documentation des readmes WordPress](https://developer.wordpress.org/plugins/wordpress-org/how-your-readme-txt-works/). Une version manquante ou contradictoire conserve le composant dans l'inventaire avec diagnostic ; elle n'autorise pas une conclusion « non affecté ».

**Avis et intégrité**

Fournisseur initial proposé : Wordfence Intelligence **v3**, qui documente des flux complets `production` et `scanner`, avec authentification par clé et limites d'usage. Retenir le flux `production` pour les détails du rapport, puis qualifier les droits d'usage, d'attribution et de transfert de cache. Référence : [API Wordfence v3](https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/). Cette proposition n'implique pas qu'une clé soit déjà disponible.

Prévoir WPScan comme fournisseur alternatif ou complémentaire, sous réserve du contrat effectivement utilisable ; son [API couvre core, plugins et thèmes](https://wpscan.com/api/). Ne pas annoncer une couverture universelle des composants premium. Un plugin WordPress sans flux opérationnel fait de l'inventaire et affiche que la recherche d'avis n'a pas été effectuée.

Lot complémentaire : comparer les fichiers à des checksums de distributions officielles lorsque le fournisseur le permet, version/locale/canal fixés. « Modifié », « référence absente » et « conforme à cette référence » sont trois résultats différents ; une modification ne prouve pas un malware, une conformité ne prouve pas l'absence de vulnérabilité. Inventorier aussi les fichiers supplémentaires dans le périmètre contrôlé.

### 5.2 Drupal

**Détection et inventaire**

- Lire le lock Composer lorsqu'il existe, `drupal/core` et ses métapaquets ; corroborer avec les marqueurs statiques du core lorsqu'il est présent.
- Inventorier modules, thèmes et profils depuis les `.info.yml` ; prévoir un parseur `.info` legacy distinct et des racines `sites/*`, `modules`, `themes`, `profiles`, `web/` et chemins explicitement configurés.
- Regrouper plusieurs sous-modules appartenant au même projet distribué. Leur nom machine peut différer de l'identité du projet portant l'avis.
- Traiter les modules custom et distributions modifiées comme tels ; aucune assimilation par nom à un projet public.
- Conserver la version brute et normalisée. Qualifier le mapping des versions historiques du type `7.x-1.2` ou `8.x-1.2` vers les versions de paquet ; ne pas retirer un préfixe sans contexte.
- Lire `core.extension.yml` comme une déclaration exportée, pas comme la preuve de l'état actif de la base de production.

`core_version_requirement` exprime une compatibilité avec Drupal, pas la version installée du module ; la [documentation des fichiers `.info.yml`](https://www.drupal.org/docs/develop/creating-modules/let-drupal-know-about-your-module-with-an-infoyml-file) sert de référence au parseur.

**Sources et couverture**

Le [descripteur officiel du dépôt Composer Drupal](https://packages.drupal.org/8/packages.json) annonce une API `security-advisories` sur `packages.drupal.org`. L'intégration doit utiliser ce fournisseur et son identité de projet, en complément des avis de dépendances Composer ; une recherche Packagist vide ne remplace pas ce contrôle. Qualifier l'API sur des réponses enregistrées : requêtes, schéma, pagination éventuelle et complétude.

Afficher séparément l'éligibilité du projet/branche à la politique de sécurité. Cette politique dépend notamment des projets et des versions stables couverts ; ne pas assimiler une préversion ou un projet non couvert à un projet sans faille. Référence : [politique de sécurité Drupal](https://www.drupal.org/node/475848).

Drupal 7 doit être reconnu comme cas historique : la [fin de support officielle](https://www.drupal.org/psa-2025-01-06) indique la fin des avis de la Security Team pour Drupal 7 et ses projets compatibles. Un contrat de maintenance tiers ne se déduit pas des fichiers du core.

Un patch Composer déclaré ou un fichier patch présent ne prouve pas que le correctif est appliqué. Le finding reste ouvert, ou fait l'objet d'un VEX motivé ; seules des preuves explicitement qualifiées peuvent modifier son statut.

### 5.3 Symfony

**Socle à enrichir**

- Détecter une application à partir d'un ensemble cohérent : `framework-bundle`, kernel/front controller, `bin/console`, configuration ou structure legacy. Classer séparément les projets utilisant seulement des composants Symfony.
- Réutiliser la collecte Composer améliorée pour composants et bundles ; conserver les versions exactes de chaque paquet. Un bundle tiers ne suit pas nécessairement la version du framework.
- Conserver `require`, `require-dev`, `replace`, `provide`, références de source, aliases et contraintes. Construire les liens directs/transitifs à partir du root et du lock, sans exécuter un solveur de dépendances.
- Traiter `symfony/symfony` et ses remplacements contrôlés sans compter deux fois les mêmes composants. Un `replace` générique ou un paquet virtuel ne prouve pas l'existence de tout le code remplacé ; suivre la [sémantique Composer](https://getcomposer.org/doc/04-schema.md#replace).
- `symfony.lock` et `extra.symfony.require` servent au contexte ; ils ne remplacent pas les versions résolues de `composer.lock`.
- Pour une copie installée sans lock, lire les métadonnées Composer installées exploitables statiquement, avec avertissement de provenance ; sans version résolue, conserver l'incertitude.

**Avis, support et recommandations**

Réutiliser OSV `Packagist`, compléter par un adaptateur Packagist Security Advisories si le corpus montre un apport ou une meilleure traçabilité. Le [flux officiel Packagist](https://packagist.org/security-advisories/) agrège des avis et fournit des identifiants PKSA : conserver leurs aliases lors de la déduplication.

Confronter les données de cycle de vie aux [publications officielles Symfony](https://symfony.com/releases) et à leur représentation JSON ; ne pas coder les dates en dur. Réutiliser le regroupement EOL existant tout en séparant branches, paquets versionnés indépendamment et périmètres de support. Une divergence entre sources devient traçable.

Les recommandations identifient le paquet directement modifiable ou le parent qui impose une dépendance, la version corrigée et les contraintes PHP connues. Elles sont des propositions à valider, jamais une garantie qu'une commande `composer require` isolée résout le graphe entier.

### 5.4 Laravel et vagues suivantes

Laravel réutilise ce socle avec une détection applicative propre (`laravel/framework`, `artisan`, bootstrap/config), sans classer toute utilisation d'Illuminate comme application Laravel. Qualifier les remplacements du monorepo et les versions des paquets tiers.

Pour chaque autre CMS : livrer d'abord le détecteur, l'inventaire, les règles d'identité/version et le tableau des limites ; ensuite seulement annoncer les recherches d'avis validées. Sources candidates à qualifier : [Joomla Security Centre](https://developer.joomla.org/security-centre.html), [avis PrestaShop](https://github.com/PrestaShop/PrestaShop/security/advisories), [avis TYPO3](https://typo3.org/help/security-advisories), [bulletins Adobe Commerce](https://helpx.adobe.com/security/products/magento.html). Ces publications ne constituent pas automatiquement une API exhaustive d'extensions.

## 6. Couverture : rendre les trous mesurables et actionnables

### 6.1 Ne pas confondre résultat et exécution du contrôle

Pour chaque application, occurrence et capacité, enregistrer deux axes indépendants :

- Exécution : `completed`, `partial`, `not-run`, `failed`, `not-applicable`.
- Résultat : `affected`, `no-match`, `indeterminate`, `not-applicable`.

Ajouter identité/version, sources effectivement utilisées, âge des données, nombre de recherches attendues/exécutées, raisons et action attendue. Un composant peut avoir un avis confirmé **et** une couverture partielle d'autres sources.

Exemples de diagnostics stables :

| Code proposé | Signification | Action indiquée dans le rapport |
| --- | --- | --- |
| `CMS_IDENTITY_AMBIGUOUS` | Le composant ressemble à plusieurs produits | Fournir une correspondance explicite avec preuve |
| `CMS_VERSION_UNKNOWN` | Pas de version exploitable | Fournir le lock ou un inventaire de déploiement daté |
| `CMS_VERSION_CONFLICT` | Lock et fichiers locaux divergent | Vérifier l'installation et préciser la cible de l'audit |
| `CMS_UNSUPPORTED_LAYOUT` | Application reconnue, disposition non gérée | Configurer les racines ou extraire une distribution prise en charge |
| `CMS_PATH_UNREADABLE` | Répertoire pertinent inaccessible | Corriger l'accès ou documenter l'exclusion |
| `CMS_PROVIDER_UNCONFIGURED` | Fournisseur nécessaire sans configuration utilisable | Configurer la source ou importer un snapshot autorisé |
| `CMS_SOURCE_UNAVAILABLE` | Erreur réseau, quota, authentification ou réponse invalide | Rétablir la source et relancer |
| `CMS_CACHE_MISS` / `CMS_DATA_STALE` | Données absentes ou trop anciennes | Rafraîchir le cache hors enclave et l'importer |
| `CMS_OUTSIDE_SECURITY_POLICY` | Projet/branche hors politique publiée | Audit complémentaire, migration ou support adapté |
| `CMS_ACTIVATION_UNKNOWN` | Présence du code connue, activation non prouvée | Vérification runtime si nécessaire pour le triage |
| `CMS_PATCH_STATUS_UNKNOWN` | Patch déclaré, application non prouvée | Attestation ou vérification du correctif |
| `CMS_PRIVATE_COMPONENT` | Composant explicitement identifié comme privé | Source d'avis interne ou revue dédiée |

Une absence dans un registre public n'est pas une preuve suffisante qu'un composant est privé : elle peut aussi provenir d'une identité incorrecte ou d'un catalogue incomplet.

Le rapport présente des compteurs concrets, par exemple : « 27 composants présents ; 23 identifiés et versionnés ; 21 recherches d'avis effectuées ; 2 recherches manquantes ; 4 composants non évaluables ». Une seconde dimension décrit les répertoires exclus/inaccessibles, dont le nombre réel de composants est inconnu. Ne pas afficher un pourcentage de « sécurité » ni cacher les inconnus en les retirant du dénominateur.

### 6.2 Comportement CLI et CI

Propositions d'options, **non disponibles actuellement** :

```text
--app-plugins auto|none|wordpress,drupal,symfony
--list-app-plugins
--scan-context source|installation|component
--fail-on-incomplete
--max-advisory-age <durée>
```

Les intégrer aux groupes CLI existants et à la configuration persistante après validation des noms. Fournir aussi un fichier de configuration validé pour racines supplémentaires, identités explicites et profils de capacités exigées. Les secrets restent dans les mécanismes de configuration locale ou variables dédiées, jamais dans le dépôt audité.

Politique proposée :

| Situation | Sorties | Code |
| --- | --- | --- |
| Contrôles exécutés, gate vulnérabilités non déclenché | Rapport normal, état de couverture visible | `0` |
| Vulnérabilités déclenchant `--fail-on` | Rapport normal avec constats | `1` |
| Limite intrinsèque, composant inconnu ou cache incomplet, sans politique stricte | Rapport explicitement partiel ; aucun libellé « sain » | `0` ou `1` selon le gate vulnérabilités |
| Même situation avec `--fail-on-incomplete` sur une capacité exigée | Rapport partiel, diagnostic CI structuré | `2` |
| Source en ligne activée en panne sans cache acceptable, réponse invalide ou crash d'un plugin requis | Diagnostic d'échec ; pas de rapport normal, conformément à la politique existante de panne de source | `2` |

Le code `2` prend priorité sur `1`, mais les constats déjà disponibles restent dans le diagnostic. Distinguer un rapport d'audit partiel d'un diagnostic d'échec. Une éventuelle option d'export après panne sera explicite et marquera tous les artefacts comme incomplets ; elle n'est pas nécessaire à la première livraison.

`--fail-on-incomplete` vérifie le profil de capacités demandé, pas toutes les capacités imaginables : l'activation runtime inconnue n'empêche pas un audit SCA de fichiers présents ; une version inconnue, une branche non qualifiée ou un fournisseur nécessaire désactivé rendent cette SCA partielle. Les exclusions acceptées délimitent le périmètre sans effacer leur existence du rapport.

Ne pas activer implicitement Composer si l'opérateur l'a explicitement désactivé. Le plugin dépendant explique les capacités perdues ; un profil exigeant ces capacités échoue. Aucun drapeau inconnu ou plugin absent ne doit être ignoré silencieusement.

### 6.3 Rapports, exports et diff

#### Organisation du chapitre CVE par application et instance

Exigence ajoutée à la demande de l'utilisateur : chaque CMS/framework a sa propre sous-section, avec ses instances et l'attribution des vulnérabilités indirectes aux plugins, thèmes, modules, bundles ou autres composants qui les introduisent.

Organisation recommandée : garder ensemble tous les constats d'une instance. Cela permet de remettre la section au responsable du site concerné, avec ses failles directes et ses dépendances vulnérables dans le même périmètre. Dans `1.1 Production`, les sous-sections applicatives complètent les vues existantes par écosystème :

```text
1. CVE
  1.1 Production
    WordPress — 2 instances
      boutique/ — version observée, résumé et couverture
        CVE directes
          Core WordPress
          Extensions : extension A, extension B…
          Thèmes : thème parent, thème enfant…
          MU-plugins et drop-ins
        CVE indirectes — regroupées par composant d'origine
          Core → bibliothèque X → avis
          Extension A → bibliothèque Y → bibliothèque Z → avis
          Thème parent → bibliothèque JavaScript → avis
          Dépendances de l'application / dépendances partagées
          Origine non déterminée — explication et preuve disponible
      vitrine/ — version observée, résumé et couverture
        CVE directes
        CVE indirectes par origine
    Drupal — 1 instance
      portail/
        CVE directes : core, modules, thèmes et profils
        CVE indirectes : par core / module / thème / profil
    Symfony — 1 instance
      api/
        CVE directes : framework, composants du framework et bundles
        CVE indirectes : par framework / bundle / application
    Autres dépendances par écosystème
      Maven, npm, Composer… non attribuées à une application
  1.2 JavaScript embarqué — vue spécialisée et renvois
  1.3 Dépendances de développement — même attribution applicative
  1.4 Correspondances écartées par le filtrage CPE
```

Dans le HTML, utiliser des blocs repliables CMS/instance et des intertitres/tableaux pour les origines ; éviter d'imposer six niveaux de titres. Fournir une synthèse par CMS avec instance, chemin, version, nombres de constats directs/indirects, priorité et couverture. Les instances sans finding restent listées dans cette synthèse : « aucun avis correspondant dans les données consultées » ou « évaluation incomplète », selon le cas.

Dans Word, produire la même structure et les mêmes preuves, avec des tableaux lisibles sans interaction. Dans les deux formats, chaque instance a une ancre stable et une copie de section qui inclut ses limites de couverture. Les origines peuvent être triées par priorité KEV/EPSS/CVSS puis nom, pour exposer les actions les plus urgentes en premier.

#### Sens précis de « direct » et « indirect »

Dans la vue applicative, le classement suit **le composant effectivement visé par l'avis** :

| Avis visant… | Classement dans l'instance |
| --- | --- |
| Le core WordPress/Drupal ou le framework lui-même | Direct — core/framework |
| Une extension, un thème, module, profil ou bundle | Direct — extension/thème/etc. concerné |
| Un composant officiellement identifié du framework Symfony | Direct — framework, avec le paquet exact affecté |
| Une bibliothèque embarquée/requise par une extension ou un thème | Indirect — sous cette extension ou ce thème, avec chemin d'introduction |
| Une bibliothèque tierce requise par le core/framework | Indirect — sous le core/framework |
| Une bibliothèque ajoutée au projet applicatif sans rattachement à une extension | Indirect dans la vue CMS/framework — sous « Dépendances de l'application », en précisant son lien Composer/npm direct ou transitif |
| Une bibliothèque présente dans l'instance dont le parent n'est pas établi | Origine non déterminée ; aucune attribution inventée à un plugin |

Ce classement applicatif est distinct du lien `direct/transitive` du gestionnaire de paquets et du scope `prod/dev`. Une extension installée manuellement peut avoir une faille directe sans apparaître dans un `require` Composer. À l'inverse, un paquet Symfony utilisé par Drupal est une dépendance indirecte du core Drupal : il ne crée pas artificiellement une instance Symfony supplémentaire.

Ne pas surcharger `dep.scope` pour réaliser cette présentation. Ajouter des relations explicites : `applicationRelation`, `ownerOccurrenceIds`, `dependencyPaths`, `attributionStatus` et `evidenceIds`, en conservant la relation du gestionnaire de paquets. Les graphiques et totaux annoncent l'axe utilisé ; on ne mélange pas silencieusement les directs applicatifs avec les directs Maven/Composer du reste du rapport.

#### Attribution des indirectes et absence de double comptage

1. Construire un graphe par instance : racine applicative, core/framework, extensions/thèmes/bundles, dépendances et relations d'embarquement. Les liens portent leur preuve, type et niveau de certitude.
2. Réutiliser les `require` du root et des paquets du lock Composer, les relations npm existantes et les manifests propres à chaque extension. Les métadonnées qui prouvent un graphe ne prouvent pas son exécution runtime.
3. Pour une bibliothèque embarquée, un emplacement sous le répertoire d'une extension établit un lien physique « embarquée par » ; une signature de bibliothèque/manifest doit établir son identité et sa version. Un nom de fichier seul ne suffit pas. Un répertoire `vendor` partagé au niveau du site ne permet pas d'inventer le plugin parent.
4. Intégrer aussi les résultats retire.js aux origines applicatives connues. La vue spécialisée des JS embarqués référence le même finding ; elle ne crée pas une seconde vulnérabilité dans les totaux.
5. Préserver plusieurs chemins quand plusieurs extensions utilisent la même occurrence vulnérable. Montrer le finding sous chaque origine avec « dépendance partagée », un identifiant et un renvoi communs. Borner les chemins affichés et signaler toute troncature sans perdre les composants ni l'état de couverture.
6. Compter globalement les **constats uniques** par groupe d'avis/occurrence, et séparément les **avis distincts**, **instances concernées** et **chemins d'introduction**. Les nombres par origine peuvent se recouper : les totaux globaux sont des unions, jamais la somme naïve des groupes.
7. Deux copies physiques indépendantes de la même bibliothèque restent deux occurrences à corriger. Une installation physique partagée entre plusieurs sites possède une occurrence commune et plusieurs relations d'exposition à des instances ; ne pas la dupliquer simplement à cause d'un `applicationId` différent.
8. Attribuer chaque finding à une vue principale. Les vues écosystème et application peuvent offrir des renvois/filtres sur le même inventaire ; les tables génériques par défaut accueillent les dépendances non attribuées. Aucune disparition de finding lorsque la détection applicative est partielle.
9. Si la bibliothèque et l'avis sont connus mais son origine ne l'est pas, maintenir le finding confirmé dans « Origine non déterminée » et ajouter `CMS_DEPENDENCY_ORIGIN_UNKNOWN`. L'incertitude porte sur le rattachement, pas nécessairement sur la vulnérabilité.

L'instance désigne une application identifiable par sa racine et ses preuves. Un réseau WordPress ou un Drupal multisite peut partager le code sans fournir la liste des sites actifs : présenter l'installation partagée et les sites explicitement connus, puis signaler les relations non établies. Ne jamais inventer une section par nom de domaine absent des données collectées.

#### Données communes à tous les formats

- Chapitre 0 : verdict de couverture, applications et limites bloquantes en tête, avec chemins, raisons et actions. Séparer ces limites des failles confirmées.
- Inventaire applicatif : tous les cores/extensions/thèmes/bundles identifiés, y compris sans avis et sans version.
- Vulnérabilités : application, occurrence, preuve de version, plage affectée, avis, conditions connues/inconnues, correction et sources. Conserver les catégories EOL, configuration et intégrité séparées des CVE.
- JSON : introduire une version de schéma, champs additifs puis migration explicite si nécessaire ; inclure inventaire, preuves, diagnostics, couverture et identifiants de règles/plugins/fournisseurs. Exporter les liens instance → composant d'origine → occurrence affectée, les chemins, leur certitude et les identifiants uniques des findings : un consommateur doit pouvoir reproduire les regroupements du rapport.
- SARIF : résultats pour les constats et notifications d'exécution pour les problèmes de scan ; emplacements exacts lorsque disponibles.
- CycloneDX : composants et relations applicatives, versions multiples conservées, propriétés de provenance/qualité. PURL Composer seulement si la coordonnée Composer est réelle ; pour un produit CMS natif, adopter une convention `generic` validée ou omettre le PURL, sans inventer un type non standard.
- CSAF/VEX : conserver les produits et occurrences ; pas de `known_not_affected` fondé sur un cache manquant, une désactivation supposée ou un patch seulement déclaré. Adapter les identifiants non-CVE dans les champs permis par le schéma.
- Diff : une disparition de constat avec source absente, application exclue ou version devenue inconnue signifie **non réévalué**, pas **corrigé**. Séparer retrait d'avis, suppression de composant, correction observée et changement de périmètre.
- Suppressions : règle ciblée par application/composant/avis, justification, auteur et échéance ; visibles dans les exports. Une suppression de vulnérabilité ne supprime pas une lacune de couverture.
- HTML/Word : mêmes données et conclusions, contenus externes échappés, liens de protocoles autorisés, aucune ressource distante requise. Traductions FR/EN dans `lib/i18n.js`, preuves et textes d'avis conservés dans leur langue d'origine.

### 6.4 Cohérence des graphiques avec les sections CVE

Exigence ajoutée à la demande de l'utilisateur : l'intégration CMS/frameworks doit conserver la cohérence des charts, de leurs totaux et de leur lecture avec le rapport entier. Ce travail appartient au premier jalon de livraison.

**État actuel à prendre en compte.** `lib/charts.js` calcule les CWE directs à partir de `dep.scope`, attribue les indirectes au seul `dep.via[0]`, classe les modules à partir de `manifestPaths`, puis calcule la priorité. `renderCharts()` reçoit `prodMatchesActive` depuis `lib/cve-report.js`. Ces entrées ne suffisent pas aux instances CMS ni à plusieurs origines d'une même dépendance. Le rendu effectif utilise des donuts, y compris pour les dépendances indirectes ; le commentaire de tête évoquant des barres ne décrit plus ce rendu.

**Agrégation commune proposée.** Ajouter un module pur, par exemple `lib/finding-summary.js`, qui reçoit l'inventaire canonique de findings, leurs relations et la couverture. Il expose les ensembles de `findingId` filtrés et leurs agrégats. Les cartes récapitulatives, les tableaux, les quatre graphiques, la copie de résumé et le JSON consomment ce même modèle, sans recompter chacun des tableaux aplatis.

Le périmètre d'une agrégation comporte explicitement : global/CMS/instance, production/développement, classe de finding, suppressions, filtrage CPE, classification applicative ou relation de paquets, et politique d'inclusion du code embarqué. Les CVE de bibliothèques PHP/JS reconnues dans une instance entrent une seule fois dans l'ensemble correspondant, même si elles sont aussi présentées dans une vue spécialisée. Les classes d'artefacts hors de ce périmètre sont nommées dans le titre ou la note du résumé concerné.

| Carte | Évolution proposée pour les rapports applicatifs | Règles de cohérence |
| --- | --- | --- |
| Faiblesses CWE | Barres par CWE sur les constats de production du périmètre sélectionné, avec possibilité de limiter aux directes | Un finding peut avoir plusieurs CWE ; compter une fois par CWE, afficher le nombre de constats distincts et ceux sans CWE. Aucun pourcentage présenté comme une partition des vulnérabilités |
| CVE indirectes par origine | Barres empilées par sévérité, libellées `instance · extension/thème/bundle/core` ; regrouper les dépendances partagées par liens réels | Chaque barre compte les findings uniques de cette origine. Une même occurrence peut figurer sous deux origines : note explicite de recoupement, total global par union et groupe « origine non déterminée » |
| Instances les plus concernées | Barres par instance, triées sur les constats critiques/élevés comme le classement actuel des modules ; garder les modules non applicatifs dans un groupe distinct | Dénominateur et filtres annoncés. Des instances partageant du code peuvent se recouper. Pour une seule instance, afficher directes/indirectes/non attribuées avec une classification principale exclusive et documentée |
| Priorité de correction | Conserver un donut si les bandes sont exclusives ; ajouter « non déterminée » lorsque les données ne suffisent pas | Une bande par finding unique, même règle que le tri des tableaux, total égal au résumé du même périmètre |

Les couleurs et libellés de sévérité restent identiques à ceux des tableaux, avec valeurs lisibles et légende ; la couleur seule ne doit pas porter l'information. Conserver l'approche SVG autonome existante, les quatre cartes et la copie PNG/tableau, sans dépendance à un CDN. Les barres doivent respecter des échelles comparables lorsque le lecteur compare des cartes ou instances.

Règles transversales obligatoires :

1. **Unité explicite** : « constats », « avis distincts », « occurrences affectées » et « instances concernées » ne sont pas interchangeables. Une CVE sur deux copies physiques produit deux constats, mais un seul avis distinct.
2. **Union des identifiants** : les totaux sont calculés sur des ensembles de findings. Deux providers, deux aliases d'avis ou deux chemins de dépendance ne multiplient pas le finding.
3. **Relations multiples** : ne pas choisir arbitrairement le premier plugin ou `via[0]`. Préserver toutes les origines prouvées ; afficher les recoupements sans les transformer en parts de camembert. Une classification principale du composant peut être exclusive pour un résumé direct/indirect, tandis que ses chemins restent multiples.
4. **Top N** : le reste est calculé depuis les identifiants des findings des groupes masqués. `capRows()` additionne actuellement les lignes restantes ; ce calcul doit être adapté aux ensembles qui se recoupent. Si « autres origines » recoupe les origines visibles, le libellé le précise ; aucune fausse égalité « top N + autres = total unique ».
5. **Inconnus visibles** : absence de CWE, d'origine, de score ou de couverture ne signifie pas zéro. Une carte sans données suffisantes affiche « non évalué » ou « données insuffisantes », selon la cause.
6. **Priorité inconnue** : revoir `lib/priority.js` pour qu'un avis sans CVSS, sans sévérité exploitable et sans preuve KEV ne soit pas assimilé automatiquement à une faible priorité. La même bande « non déterminée » doit apparaître dans tableaux, charts et exports ; ne pas modifier uniquement le rendu.
7. **Couverture** : chaque vue porte l'état de couverture et son périmètre. Un graphique vide avec fournisseur indisponible ne doit jamais signifier « aucune vulnérabilité ». Les limites majeures restent visibles à côté des chiffres et dans l'image/table copiée.
8. **Filtres synchronisés** : si le HTML offre un filtre CMS/instance/prod-dev, il s'applique simultanément aux cartes, compteurs et tableaux concernés. Un filtre local à un tableau ne modifie pas silencieusement une synthèse globale : le périmètre de chacun reste indiqué.
9. **Word et copies** : le `.doc` statique représente le périmètre global annoncé et ses sections d'instance. Une copie PNG ou tableau inclut titre, filtre, unité, légende et note de couverture. Les valeurs sont identiques à celles du modèle JSON correspondant.
10. **Compatibilité** : un scan sans CMS conserve son classement utile par modules. Si une correction de comptage ou de classification change un chiffre existant, la documenter avec une régression ; ne pas préserver une erreur au seul motif de stabilité visuelle.

Cas de réception concret : une instance comporte une CVE propre à une extension A et une occurrence de bibliothèque portant une autre CVE, partagée par A et un thème B. Le résumé doit montrer **2 constats uniques**, dont **1 direct et 1 indirect**. Les barres des indirectes indiquent **1 sous A et 1 sous B**, avec recoupement signalé ; leur somme 2 ne devient pas le total des indirectes. Si la bibliothèque possède deux CWE, chaque barre CWE peut la compter, mais elle demeure un seul constat dans le total. Les bandes de priorité totalisent 2, sous réserve du même périmètre et des mêmes exclusions.

Un second cas couvre deux copies physiques de la bibliothèque dans deux instances : deux constats pour l'avis commun, une occurrence par instance et aucune attribution à la mauvaise version. Un troisième fait disparaître la source d'avis : les graphiques indiquent la couverture dégradée, et le diff ne présente pas cette disparition comme une correction.

## 7. Hors ligne, reproductibilité et protection des données

Chaque fournisseur doit avoir son espace de cache et une enveloppe versionnée : version d'API et de normaliseur, date de collecte, date publiée si fournie, empreinte du contenu, périmètre couvert, complétude, attribution et paramètres de fraîcheur. Un fichier partiellement téléchargé ou mal formé ne remplace jamais le dernier snapshot valide.

Règles de fonctionnement :

- Écritures atomiques, limites de taille, reprise et validation. Une synchronisation complète n'est complète qu'après validation de toutes ses pages/parties.
- Réessais bornés et respect des quotas. HTTP 401, 403, 429, erreur métier et rupture de schéma ont des diagnostics distincts.
- `--offline` interdit tout accès réseau, y compris découverte de source, renouvellement de jeton et recherche de slug ; ne pas essayer « juste une requête ».
- Un cache froid expose un contrôle non réalisé. Un cache ancien peut rester utilisable hors ligne, en conservant son âge ; la politique `max-advisory-age` détermine s'il satisfait le gate de couverture.
- Export/import : snapshots cohérents, contrôles d'intégrité, conservation des retraits d'avis, absence de downgrade silencieux et aucune clé API exportée. Qualifier les droits de redistribution selon le fournisseur avant de promettre le transfert de données.
- Adapter `lib/provenance.js` et `lib/cache-archive.js` : enregistrer ce qui a été effectivement utilisé, pas uniquement ce qui existe dans le cache.
- Étendre le descripteur anonymisé avec version de schéma : identités publiques et versions nécessaires, aucune racine, configuration, URL privée, clé ou association à un client. Les champs applicatifs sensibles ne doivent pas entrer par propagation automatique.
- Préférer les flux complets quand disponibles. Les requêtes unitaires vers une source publique ne doivent pas transmettre des identités privées par simple heuristique ; réutiliser exclusions et politique de registres du projet.

Les valeurs de secrets présentes dans `wp-config.php`, `.env` ou les fichiers de configuration ne figurent pas dans les preuves exportées. Stocker seulement les éléments nécessaires à la conclusion et leur localisation ; un hash de fichier contenant des secrets doit lui aussi rester local si aucune nécessité de transfert n'est établie.

## 8. Contrôles de configuration : lot distinct et borné

Après qualification de l'inventaire et des avis, ajouter un petit catalogue de règles à forte valeur et preuve locale : debug explicitement activé dans un contexte identifié, configuration de profiler, permissions dangereuses déclarées, artefacts sensibles sous un document root explicitement établi.

Chaque règle déclare : identifiant/version, frameworks et versions pris en charge, préconditions, fichiers nécessaires, preuve, conclusion autorisée, cas indéterminés et remédiation. Priorité aux parsers structurés ; une regex isolée dans n'importe quel fichier n'est pas une preuve de configuration effective.

Les substitutions d'environnement, includes PHP, conteneurs compilés, valeurs en base et caches d'application limitent l'évaluation statique. L'[ordre de chargement et les environnements Symfony](https://symfony.com/doc/current/configuration.html) doivent notamment être respectés. Un `APP_DEBUG=1` dans un fichier d'exemple ne suffit pas à conclure que la production est exposée.

Séparer dans la sortie : configuration observée, risque conditionnel et exposition non vérifiée. Pas de SAST complet, DAST, fuzzing HTTP, login automatique, exploitation, analyse de base de données ou détection générale de backdoors dans cette feuille de route initiale.

## 9. Validation et critères de sortie

### 9.1 Corpus et tests indispensables

Chaque plugin doit apporter des fixtures minimales dérivées de distributions réelles, avec origine, version, licence, réduction documentée et résultats attendus. Compléter par des distributions de référence figées et leurs empreintes, utilisées dans un benchmark reproductible.

| Famille | Cas de validation obligatoires |
| --- | --- |
| Détection | Projet réel, bibliothèque isolée, nom trompeur, extension seule, layout custom, racines imbriquées, monorepo mixte |
| Identité | Dossier renommé, même nom commercial pour deux éditeurs, gratuit/premium, fork, custom, projet Drupal à plusieurs modules, alias Composer |
| Versions | Deux versions dans deux sites, version absente, lock/local en conflit, version `dev`, préversion, alias, métapaquet, patch déclaré |
| Plages | Bornes inclusives/exclusives, trous entre plages, versions corrigées par branche, absence de correctif, rollback, suffixes PHP/Drupal/Magento |
| Avis | Avis sans CVE, aliases multiples, retrait, correction rétroactive, désaccord de sources, sévérité inconnue, préconditions non vérifiables |
| Résilience | Timeout, 401/403/429/5xx, réponse HTML avec HTTP 200, JSON tronqué, schéma modifié, source vide légitime vs synchronisation interrompue |
| Hors ligne | Cache froid, chaud, ancien, corrompu, partiel ; export/import ; identité inconnue ; aucun réseau dans tous les cas |
| Périmètre | Exclusions, permissions refusées, liens symboliques, chemins externes, limites atteintes, metadata ciblées dans `vendor` |
| Sécurité du scanner | PHP jamais exécuté, aucun sous-processus de cible, YAML/XML malveillant, entités externes refusées, entrées longues, chemins traversants, XSS dans headers/avis |
| Intégration | Rapport sans résultat, JSON seul, tous les exports, langues FR/EN, codes 0/1/2, suppressions, baseline partielle, identifiants stables |
| Attribution applicative | CVE directe du core/plugin/thème ; bibliothèque indirecte par origine ; deux instances à versions différentes ; composant partagé par deux plugins ; copies physiques distinctes ; origine inconnue ; Symfony interne à Drupal ; même finding référencé par retire.js et la vue applicative |
| Graphiques | Totaux égaux aux ensembles des tableaux ; multi-CWE ; aliases/fournisseurs dédupliqués ; origines partagées ; top N avec recoupements ; scopes multiples ; filtre d'instance ; score inconnu ; données absentes ; parité SVG/Word/PNG/table/JSON |
| Performance | Plusieurs centaines d'applications et milliers d'extensions ; mémoire bornée, requêtes dédupliquées, pas de parcours complet supplémentaire par plugin |

Les tests normaux restent **sans réseau**, conformément à `CONTRIBUTING.md`. Les tests différentiels utilisent des sorties de référence enregistrées de WP-CLI/Drush/Composer ou des comparateurs de versions, produits sur des fixtures contrôlées. Aucune exécution de ces outils sur la cible pendant un scan fad-checker.

Prévoir une vérification périodique séparée des contrats d'API, activée explicitement avec les identifiants nécessaires. Elle détecte l'évolution des services ; elle ne rend pas la suite unitaire dépendante d'Internet.

### 9.2 Mesures de qualité

- **Inventaire** : chaque composant attendu du corpus pris en charge doit être retrouvé, avec toutes ses occurrences ; ceux volontairement non évaluables doivent produire le diagnostic attendu.
- **Matching** : précision/rappel sur un corpus annoté par composant/version/avis ; conserver la liste des faux positifs et faux négatifs et leur adjudication. Ne pas considérer la sortie d'un autre scanner comme vérité absolue.
- **Seuil de livraison** : 100 % des cas déterministes approuvés passent ; aucun faux positif ou faux négatif connu non expliqué sur le corpus de qualification. Une limitation acceptée est publiée et détectable dans le rapport.
- **Couverture** : 100 % des chemins d'erreur testés produisent le bon état de contrôle ; jamais de `no-match` sur échec ou absence de données.
- **Organisation CVE** : chaque finding de l'inventaire figure dans une vue principale ou un groupe non attribué, sans perte ; les unions d'identifiants dans HTML/Word/JSON concordent. Les regroupements directs/indirects, totaux uniques et renvois de dépendances partagées sont testés sur plusieurs instances.
- **Graphiques** : tests de contrat entre `finding-summary`, `charts`, rapport et exports ; partitions exclusives égales au total unique, groupes recoupants explicitement marqués, aucune troncature de top N silencieuse et état de couverture conservé dans les copies. Vérification visuelle HTML/Word en FR/EN pour les noms longs et plusieurs instances.
- **Reproductibilité** : mêmes entrées, versions de plugins, politique, date d'évaluation et snapshots donnent les mêmes constats normalisés, hors champs volatils explicitement listés.
- **Non-régression** : suite existante verte et comparaison des scans de référence sans application CMS ; seuls les ajouts documentés de schéma peuvent changer les exports.
- **Performance** : établir la base au lot 0 ; budget proposé pour la découverte sur corpus sans CMS : moins de 10 % de surcoût médian, à confirmer sur Linux et WSL. Mesurer séparément synchronisation réseau et analyse locale.
- **Packaging** : mêmes plugins disponibles via npm et binaires Bun Linux/Windows/macOS visés ; aucun fichier de règles absent du bundle.

Ces objectifs sont des portes de validation du développement, pas une promesse de détection de toutes les vulnérabilités existantes.

## 10. Plan de réalisation et dépendances

Charges indicatives en jours-personne, pour un développeur familier du code, tests et documentation inclus. Elles seront recalibrées après le lot 0 et la qualification des sources. Ne pas convertir ces charges en engagement calendaire avant d'avoir fixé le corpus et les droits d'accès.

| Lot | Livrables et principaux fichiers | Dépendances | Critère d'acceptation | Charge |
| --- | --- | --- | --- | --- |
| 0 — Qualification | Matrice des versions/layouts, corpus annoté, exemples de rapports attendus, contrats et droits des fournisseurs, mesures initiales | Aucune | Périmètre vérifiable et limites publiables pour WP/Drupal/Symfony | 3–5 j |
| 1 — Fiabilité du socle | Occurrences Composer, métadonnées et liens ; `composer.codec.js`, `composer/parse.js`, `dep-record.js`, attribution | Lot 0 | Cas reproduit 5.4.47/6.2.10 corrigé, scopes et emplacements conservés | 5–8 j |
| 2 — Contrat des plugins et couverture | Registre/runner, découverte, `scan-coverage`, preuves, routage fournisseurs, source-health, options CLI | Lot 1 | Plugin de test intégrable sans branche spécifique dans la CLI ; erreurs visibles | 7–10 j |
| 3 — Symfony | Détection application/composants, graphe, avis, EOL, recommandations, fixtures | Lot 2 | Corpus Symfony moderne/legacy qualifié ; aucun doublon Composer | 4–6 j |
| 4 — WordPress | Layouts, core/extensions/thèmes/MU/drop-ins, identité, versions, fournisseur v3, cache | Lot 2 + accès source qualifié | Corpus classique/Bedrock/multisite/extension seule ; absence de clé explicitement partielle | 8–12 j |
| 5 — Drupal | Composer et `.info*`, mapping projet/module, versions, avis Drupal et politique de support | Lot 2 + API qualifiée | Core/contrib/custom/legacy/multisite correctement distingués | 7–10 j |
| 6 — Chaîne d'audit complète | Sections CVE CMS/framework → instance → directes/indirectes par origine ; agrégation commune et charts cohérents ; JSON/HTML/Word/SARIF/SBOM/CSAF, diff, VEX, gates, provenance, export cache/anonymisation | Lots 2–5 ; graphe, agrégations et squelette d'exports dès lot 2 | Attribution et totaux sans doublon, charts/tableaux/exports concordants et scénario air-gapped complet | 10–16 j |
| 7 — Qualification finale | Benchmark, analyse des écarts, documentation, FR/EN, CI/packaging, performance | Lots 3–6 | Tous les critères du §9 satisfaits | 5–8 j |

Ordre recommandé : **0 → 1 → 2 → Symfony → WordPress → Drupal → qualification finale**. Le travail sur les exports accompagne chaque plugin ; le lot 6 clôt la vérification transversale, il ne reporte pas la conception du rapport à la fin.

Budget de première livraison WP/Drupal/Symfony, incluant les sections CVE par instance, l'attribution des indirectes et la cohérence des graphiques : **49–75 jours-personne**, soit environ **10–15 semaines** pour une personne à temps plein, hors délais d'accès aux données et marge d'aléas. Prévoir une réserve de 20–30 % pour les layouts et identités non couverts découverts dans le corpus réel.

Lots additionnels après ce jalon : Laravel 3–5 j ; Joomla 5–8 j ; PrestaShop 6–10 j ; TYPO3 5–8 j ; Magento/Adobe Commerce 8–12 j ; intégrité WordPress et premiers contrôles de configuration 6–10 j. Ce sont des fourchettes initiales, conditionnées à la disponibilité des avis et à la portée des branches legacy.

Découpage conseillé en PRs :

1. Régression et correction des collisions Composer, sans plugin nouveau.
2. Enrichissement Composer et modèle d'occurrences/preuves.
3. Registre de couverture et sérialisation JSON, avec comportement CI documenté.
4. Contrat de plugins, découverte, sélection et plugin de test.
5. Contrat fournisseurs, routage explicite, cache/source-health/provenance.
6. Symfony avec tests et rendu minimal complet.
7. Inventaire WordPress et diagnostics ; puis fournisseur et matching dans une PR distincte.
8. Inventaire Drupal et diagnostics ; puis source d'avis et mapping dans une PR distincte.
9. Sections CVE par CMS/framework et instance, directes/indirectes par origine, agrégation partagée des tableaux/charts/résumés, totaux sans doublon, parité des exports, diff sensible à la couverture, workflow hors ligne et migrations. Construire et tester le graphe et les regroupements avec chaque plugin dès les PRs 6–8.
10. Benchmark annoté, documentation des limites, qualification et activation automatique des plugins qualifiés.

Chaque plugin passe par `experimental` puis `qualified`. L'auto-détection par défaut ne doit activer que des comportements qualifiés ; la présence d'un CMS reconnu mais non pris en charge déclenche un diagnostic. Les capacités restent affichées individuellement : un plugin qualifié pour l'inventaire peut encore être partiel pour une source d'avis.

## 11. Exploitation et maintenance après livraison

- Pour chaque plugin/fournisseur : responsable, contrat d'API, dernières branches testées, corpus, fréquence de revue et historique de changements.
- Versionner règles et mappings d'identité séparément des snapshots d'avis ; les inclure dans la provenance.
- Surveiller ruptures d'API, changements de licence, changements de versioning et cycles de support. Une capacité retirée n'est pas transformée en contrôle vide.
- Toute anomalie de résultat recevable apporte une fixture et une régression, conformément aux conventions du dépôt.
- Requalifier avant de déclarer une nouvelle version majeure de CMS supportée ; le simple succès du parseur ne suffit pas.
- Mettre à jour `ARCHITECTURE.md`, `USAGE.md`, `DATA-SOURCES.md`, `README.md`, les complétions et le changelog lors des livraisons, en distinguant capacités réelles et limites.

## 12. Décisions à confirmer lors du lot 0

Le plan peut démarrer avec les valeurs proposées sans attendre une sélection exhaustive de tous les CMS. Les décisions suivantes conditionnent la portée des livraisons suivantes :

1. Corpus métier prioritaire : sites déployés, arbres Git, extensions seules ; poids des branches legacy et distributions personnalisées.
2. Fournisseur WordPress effectivement exploitable : clé, quotas, attribution et transfert de cache ; alternative si ce fournisseur ne répond pas aux contraintes du produit.
3. Profils de couverture à exiger en CI et politique de fraîcheur par source ; pas de seuil universel implicite.
4. Format et migration des exports : additif autant que possible, version majeure si une correction de sens casse un consommateur.
5. Nécessité réelle de plugins externes installables ; la première version proposée les livre intégrés pour maîtriser leur qualification.

Le premier résultat à livrer est la correction de la collecte multi-applications et le contrat de couverture. Les plugins pourront ensuite ajouter des contrôles sans que leurs absences de données, ambiguïtés ou pannes deviennent des conclusions rassurantes à tort.
