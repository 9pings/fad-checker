# Handoff — implémentation CMS/frameworks

## 6e session (23 sept. 2026) — qualification des avis vague 2 + intégrité WordPress, testée sous tous les angles

Décisions utilisateur actives : « finir et tester sous tous les angles » ; « si un CMS/framework
est présent il doit être activé » (6e session, **remplace** la règle de la 1re session
« jamais en auto ») ; **ne pas simplifier la gestion des versions utilisée par le reste de
l'app** — les essais qui touchaient `satisfiesComposerConstraint`/`satisfiesGroup`
(packagist-audit.js) ont été revertés ; les grammaires propres aux flux GitHub vivent dans
`lib/application-providers/github-advisories.js` (normalisation avant l'évaluation
partagée). Seule modification résiduelle du module partagé : l'export *additif* de
`cmpComposerVersions`. Le reste de l'app (voies Packagist/OSV/NVD, Drupal) garde son
comportement d'avant, testé vert.

### Livré (tout testé vert, TDD)

1. **Voies d'avis Github des éditeurs, PrestaShop + TYPO3**
   (`lib/application-providers/github-advisories.js`, `--prestashop-advisories[-live]`,
   `--typo3-advisories[-live]`) : le flux machine que ces éditeurs maintiennent eux-mêmes
   (61 et 97 avis vivants le 2026-09-23 ; joomla/joomla-cms et magento/magento2 ont des
   flux vides — vérifié — leurs bulletins restent HTML, ces voies restent
   `CMS_ADVISORY_NOT_QUALIFIED`). Le flux complet du dépôt est récupéré une fois par scan
   (pagination Link, échec explicite au-delà de la limite), validé, mis en cache atomique,
   puis apparié par coordonnée Composer inventoriée (`prestashop/prestashop`,
   `typo3/cms-core` + extensions système). Constats réels sur les flux :
   - PrestaShop écrit « `< 8.2.6 and < 9.1.1` » pour DEUX branches affectées (deux
     versions corrigées) mais « `>= 8.0.0 and < 8.1.1` » pour UN intervalle — la grammaire
     distingue les deux par la forme des clauses ; TYPO3 joint ses intervalles par des
     virgules sémantique OR (« `13.0.0-13.4.33, 14.0.0-14.3.5` ») — en AND Composer
     l'ensemble serait vide et chaque avis réel un faux négatif.
   - ~30 avis PrestaShop 2020-2021 ont une identité de paquet **vide** dans le flux
     officiel : attribués au coord du core (inférence documentée, l'URL de l'avis reste
     la preuve) ; sans fallback configuré, un diagnostic groupé
     `CMS_ADVISORY_UNATTRIBUTABLE` les signale — jamais de silence.
   - Les plages non bornées (« `> 1.7.0.0` ») ne sont décidables que par leur
     `patched_versions` : une version au-dessus de la version corrigée de l'éditeur est
     saine. Les versions produits 4 parties exactes (« 1.6.0.1 ») sont décidées dans la
     voie, sans toucher l'évaluateur partagé.
2. **Capacité « integrity » WordPress — checksums de distribution**
   (`lib/application-providers/wp-checksums.js`, `--wp-checksums <fichier>`,
   `--wp-checksums-live [url]`, `--wp-checksums-locale <locale>`, défaut en_US) :
   référence officielle api.wordpress.org/1.0 épinglée par version+locale, comparaison
   octet à octet (md5) des fichiers core de chaque instance. Trois résultats distincts,
   tous en diagnostics (jamais de constat CVE) : `CMS_FILE_MODIFIED` (diffère de la
   distribution officielle), `CMS_FILE_MISSING` (présent dans la référence, absent de
   l'arbre — un checkout Git n'est pas l'archive de distribution, ne bascule pas le
   verdict), `CMS_FILE_EXTRA` (fichier inattendu dans `wp-admin/`/`wp-includes/`, le
   périmètre contrôlé ; `wp-content/` est le domaine utilisateur, jamais signalé).
   `affected` uniquement sur fichiers modifiés ou inattendus dans les répertoires core ;
   référence d'une autre version → `CMS_CHECKSUMS_REFERENCE_MISMATCH`, aucun verdict ;
   listes plafonnées avec avis de troncature honnête ; i18n FR complète (libellés de
   capacité + actions par diagnostic).
3. **Fusion des constats applicatifs par le seam alias-aware** (`mergeBySource`) : un
   constat éditeur que la voie Composer standard avait déjà trouvé (mesuré sur l'extrait
   TYPO3 v13.4.2 : épingle exacte `typo3/cms-core: 13.4.2` dans
   `typo3/sysext/seo/composer.json` vs marqueur core observé) devient UN constat avec
   l'union des sources (`github-typo3-advisories+nvd+osv+packagist`), le fix éditeur
   voyage avec la fusion, l'attribution applicative est reconstruite depuis
   l'occurrence physique. Les constats invisibles aux voies standard (core Drupal,
   catalogue WordPress) passent intacts. L'union des libellés se fait par token
   (`osv+packagist`, plus `osv+packagist+packagist`).
4. **Suites gated étendues** : `test/wave2-real-instances.test.js` (FAD_REAL_INSTANCES=1)
   télécharge les archives officielles PrestaShop 8.2.1 et TYPO3 v13.4.2, les réduit aux
   fichiers marqueurs documentés, et asserte les flux vivants de bout en bout ;
   `test/real-instances.test.js` conduit désormais `--wp-checksums-live` sur l'arbre réel
   (conforme 2960/2960 → no-match ; un commentaire ajouté à `wp-load.php` → affected avec
   le fichier nommé ; arbre restauré) et le corpus online avec `--wp-checksums-live`.
5. **Activation automatique sur présence** (`select.js`, `runner.js`) : `--app-plugins
   auto` (défaut) inventorie tout layout reconnu, expérimental ou qualifié ; le
   diagnostic d'annonce `CMS_PLUGIN_UNQUALIFIED` disparaît avec le garde-fou qu'il
   annonçait. **Aligné sur les outils officiels** (documenté dans COMPARISON.md, section
   « Detection on presence », vérifié 2026-09-23) : `composer audit` audite le lock du
   cwd, OSV-Scanner `scan -r .` balaie tout lockfile trouvé, Trivy `fs .` détecte chaque
   langue présente (mode `precise` par défaut vs `comprehensive` — notre conjonction de
   marqueurs est l'analogue « precise »), Snyk `test` auto-détecte, `drush pm:security`
   boote le site dans lequel il est ; le seul contre-exemple (WPScan 2026 : plugins
   derrière `-e ap`) est une économie de quota API cloud, la détection du CMS y restant
   automatique. Notre découpage : inventaire local automatique (pas de réseau), voies
   d'avis réseau derrière leur configuration explicite (`CMS_PROVIDER_UNCONFIGURED`
   sinon, jamais de résultat propre). Faux positifs vérifiés sur trois plans : chaque
   détection est une conjonction de marqueurs physiques positifs (un `require` seul ne
   crée jamais une application — testé) ; le corpus réel (4 dépôts + 4 extraits) donne
   exactement 8 applications en auto, aucune fantôme ; quatre bibliothèques PHP réelles
   clonées à HEAD (guzzle/guzzle, laravel/framework *en tant que paquet*, le monorepo
   symfony/symfony, composer/composer) donnent **0 application**.

### Vérification à l'arrêt (tout vert)

- `npm test` : **1077 tests — 1070 réussis, 0 échec, 7 sautés** (5 real-instances + 2
  wave-2 gated). `git diff --check` vert. **Aucun commit créé** (conforme à la règle).
- Gated réseau : **7/7 verts** — real-instances 5/5 (corpus 4 dépôts réels + OSV live +
  Drupal live 15 avis officiels + checksums WordPress réels) et wave-2 2/2
  (PrestaShop 8.2.1 : 10 avis réels dont GHSA-xrwj fix 8.2.8 et CVE-2026-44212 fix 8.2.6,
  couverture completed/affected, AUCUN faux positif 2020 ; 8.2.8 : 0 avis. TYPO3 13.4.2 :
  ≥ 8 avis cms-core dont CVE-2026-19418 fix 13.4.34, cms-seo no-match honnête ;
  13.4.34 : 0).
- Docker air-gap (`node:22-bookworm` neuf, `--network none` — seule `lo`, `--read-only`,
  HOME vide en tmpfs, UID 1000) : suite **identique à l'hôte** (1077/1070/0/7 sous Node
  22 là où l'hôte est en Node 24), import du cache (25 988 entrées), scan combiné
  hors ligne des 4 dépôts réels + 4 extraits éditeurs : OSV 210 vulnérabilités et
  Packagist +6 servis **depuis le cache** (identiques au connecté), **242 constats,
  0 doublon (id+coord@version+app), 0 non attribué**, voies github + integrity actives
  depuis leurs snapshots locaux, **12/12 empreintes SHA-256** des 6 formats × EN/FR
  validées dans le conteneur. Artefacts : `/tmp/fad-e2e-airgap-v3/out/`.
- Rapports connectés des 4 extraits officiels avec voies live
  (`/tmp/wave2-lane-report{,-fr}/`) : 32 constats, 0 doublon, 0 non attribué, sources
  unifiées, HTML sans balise non fermée, sans id dupliqué ni ancre cassée, 12/12
  SHA-256. NB : un premier scan avait révélé 8 doublons (voie Composer standard
  `nvd+osv+packagist` vs voie éditeur) — corrigé par le point 3.

### Limites restantes (documentées)

- Joomla et Magento/Adobe Commerce : aucun flux machine éditeur (vérifié 2026-09-23,
  flux GitHub vides) → `CMS_ADVISORY_NOT_QUALIFIED`, à requalifier si l'éditeur publie
  un flux.
- Cycle de vie/support des CMS vague 2 : toujours `CMS_LIFECYCLE_NOT_QUALIFIED`
  (communauté vs contrat, forks — non entamé, plan §5.4 inchangé).
- API GitHub sans authentification : limites de débit GitHub s'appliquent (60 req/h/IP).
- La voie integrity compare les fichiers core (racine de la référence + wp-admin +
  wp-includes) ; `wp-content/` est hors périmètre contrôlé, par design.
- Benchmark de performance (lot 7) : non refait cette session ; les durées de scan sont
  restées dans les ordres de grandeur précédents.
- Piège d'environnement (WSL) : `rsync` et `tar` depuis `/mnt/w` (drvfs) perdent
  silencieusement des fichiers de `node_modules` — pour un replay, copier `node_modules`
  dans un `tar` séparé et vérifier le compte de fichiers avant de lancer le conteneur.

### Point de reprise conseillé

Le plan général `PLAN-plugins-cms-frameworks.md` : cycle de vie/support des CMS (Symfony
d'après les publications officielles JSON, puis les autres), puis benchmark annoté et
qualification finale (lot 7), puis contrôles de configuration (§8). Conserver : suite
ordinaire hors ligne/déterministe, plugins derrière `--app-plugins`, rapports de revue
en ligne, fusion alias-aware avant tout ajout de source, aucun commit sans demande.

## Reprise du 23 septembre 2026 — en cours

Objectif demandé : valider le parcours complet dans un Docker neuf sans réseau, puis
réaliser la vague 2 (Joomla, PrestaShop, TYPO3, Magento/Adobe Commerce). Cette section
sera mise à jour au fil des résultats ; les états antérieurs restent historiques.

- Préparation terminée : `--export-cache` a produit une archive de 15,24 Mo sans
  `config.json`. Une copie autonome du programme, quatre projets réels et les deux
  snapshots CMS locaux ont été placés sous `/tmp/fad-e2e-airgap.loi1WY/`.
- Parcours complet dans `node:22-bookworm`, `--network none`, système en lecture seule,
  UID non privilégié et HOME initialement vide : seule l'interface `lo` existe ;
  `npm test` donne 1025 réussites, 4 sauts, 0 échec ; `--import-cache` réussit ;
  scan `--offline --app-plugins all` des quatre projets avec snapshots locaux ; les
  six formats HTML, Word, JSON, CycloneDX, CSAF et SARIF sont générés et leurs six
  SHA-256 sont valides. Le premier rapport contenait 211 identifiants uniques,
  identiques au rapport connecté d'alors ; la correction du fallback Composer
  décrite plus bas retire ensuite un faux positif et ramène le compte à 210.
  Artefacts et logs de ce premier replay :
  `/tmp/fad-e2e-airgap.loi1WY/out/`. Le premier essai avec `--app-plugins auto` s'était
  arrêté normalement avant rapport : les plugins expérimentaux exigent la sélection
  explicite. Le scan complet a révélé un compteur de progression `12/11` : la phase
  PHP runtime n'était pas comptée. Correction de `totalSteps` faite, à rejouer.
- Vague 2 : quatre plugins expérimentaux ajoutés (`joomla`, `prestashop`, `typo3`,
  `magento`). Ils détectent les marqueurs propres à chaque produit, inventorient
  les composants et conservent leurs versions/éditions et preuves. Les advisories
  applicatives restent explicitement `not-run (CMS_ADVISORY_NOT_QUALIFIED)` : les
  pages des éditeurs identifiées ne constituent pas un flux machine exhaustif.
  Les dépendances Composer passent par les voies OSV/Packagist existantes.
  Sept tests ciblés passent ; nouvelle suite complète et replay Docker après la vague 2
  encore à faire. Magento garde le suffixe produit `-pN` depuis `composer.lock` et
  n'assimile pas `setup_version` à la version de code. TYPO3 lit `typo3/cms-core`
  depuis le lock ; Joomla confronte son manifest au code de version ; PrestaShop
  distingue la version installée de la version de l'installateur.
- Validation des sources locales : extraits de dépôts éditeurs aux tags Joomla 5.4.1,
  PrestaShop 8.2.1, TYPO3 v13.4.2 et Magento 2.4.7-p3 sous
  `/tmp/fad-wave2-official/`. Les quatre sont détectés ; les versions affichées
  sont 5.4.1, 8.2.1 et 13.4.2. Le checkout source Magento ne contient pas de
  `composer.lock` produit : version inconnue, comme attendu. L'ancien fallback
  Composer acceptait `4.4.*` comme version exacte depuis le `composer.json`
  PrestaShop : corrigé. Sans lock, l'inventaire des dépendances est partiel et
  annonce `CMS_LOCKFILE_MISSING` ; les versions source ne prouvent pas une
  installation. Les produits Magento et paquets distribués par
  `repo.magento.com` ne sont plus interrogés dans le registre public Packagist.
- Scan CLI hors ligne sur ces quatre extraits : quatre instances dans JSON,
  HTML/Word/JSON/CycloneDX/CSAF/SARIF et SHA-256 valides ; HTML sans ID dupliqué
  ni ancre cassée (`/tmp/fad-wave2-report/`). Les tests ciblés des plugins et du
  routage de source passent. Les voies applicatives d'avis et de cycle de vie
  restent explicitement `not-run` jusqu'à qualification d'une source adaptée.
- Nouveau Docker propre après intégration vague 2 : `--network none`, seule interface
  `lo`, HOME vide, import de l'archive par la CLI, suite complète 1039 tests
  (1035 réussis, 4 sautés), puis scans du corpus original et des quatre extraits
  éditeurs. Les 12 empreintes SHA-256 des deux jeux de six formats sont valides
  (`/tmp/fad-e2e-airgap.loi1WY/out2/`). Le compteur de progression est bien `12/12`.
  Le corpus contient maintenant 210 constats : le seul identifiant retiré est
  CVE-2015-5723 sur `doctrine/annotations@1.2.*`, qui venait d'une plage déclarée
  dans un `composer.json` sans lock et ne prouvait aucune version installée. Les
  210 autres identifiants correspondent exactement à l'ancien rapport en ligne.
  Les rapports de référence sont régénérés avec ce correctif.
- Six rapports connectés corrigés sous `/tmp/realinst/reports-wave2-corrected/` :
  corpus EN/FR 210 constats, WordPress 1, Drupal 77, Symfony 68, BookStack 64.
  Le corpus connecté et le dernier corpus Docker ont exactement les mêmes 210
  `findingId` (aucun écart). Les 18 empreintes sont valides ; JSON sans doublons,
  HTML et Word sans ID dupliqué ni ancre interne cassée. Les quatre extraits
  officiels de la vague 2 ont leurs propres rapports EN/FR sous
  `/tmp/fad-wave2-report/` et `/tmp/fad-wave2-report-fr/`.

## État historique après la revue corrective, avant la vague 2

À ce stade, la vague 2 n'était pas commencée. Les sections ci-dessous conservent
leur historique ; l'état le plus récent est en tête du document.

- WordPress 6.4.2 est affecté par CVE-2024-31210 (7.6 HIGH selon l'avis éditeur,
  corrigé en 6.4.3). CVE-2024-31211 est corrigé dès 6.4.2 et a été retiré de la
  fixture. Le snapshot de test réduit ne prouve pas la complétude du flux Wordfence.
  L'API Wordfence v3 est publique avec clé Bearer gratuite : `WORDFENCE_API_KEY` ou
  `--wordfence-api-key` active son endpoint officiel ; sans clé, le scan live s'arrête
  avec un avertissement. Une instance WordPress sans source affiche aussi un avertissement.
- Packagist refuse désormais les paquets omis, réponses mal formées ou erreurs HTTP,
  sans les cacher comme des listes vides. Les anciennes entrées vides non vérifiables
  sont invalidées ; les alias `sources[].remoteId` participent à la fusion. Les plages
  `^0.0.3` et `1.0 - 2.0` suivent Composer. Drupal rejette `advisories: []`.
- Les origines partagées sont groupées par ensemble réel de composants. Les vues
  applicatives utilisent des barres pour les catégories qui peuvent se recouper ; les
  quatre cartes passent sur deux colonnes afin de rendre les libellés lisibles.
- `npm test` : 1029 tests, 1025 réussis, 4 sautés, 0 échec. Tests sur quatre dépôts
  réels : 4/4. La même suite passe dans `node:22-bookworm` neuf avec
  `docker run --network none --read-only` et un HOME vide. Deux scans à snapshots
  locaux, WordPress et Drupal, passent dans ce conteneur sans réseau. Un second
  conteneur avec copie explicite du cache donne exactement les 211 identifiants
  applicatifs du scan en ligne, avec OSV, Packagist et NVD servis depuis le cache.
- Six rapports EN/FR et individuels ont été régénérés dans
  `/tmp/realinst/reports-fixed/` : corpus 211 constats, WordPress 1, Drupal 78,
  Symfony 68, BookStack 64. Les trois fichiers de chaque rapport passent
  `sha256sum -c` ; les HTML n'ont ni ID dupliqué ni ancre cassée. La baisse de deux
  constats Drupal provient de la fusion de deux avis Packagist avec
  `GHSA-f6p5-76fp-m248`, celle d'un constat WordPress de la correction du faux positif.


Mise à jour du 23 septembre 2026 : la revue indépendante a confirmé les défauts de
rapport ci-dessous et reproduit trois autres écarts bloquants (cache Drupal live
incomplet sur plusieurs instances, synthèse de couverture faussement `completed`,
fichier d'avis configuré mais absent ignoré sans instance correspondante), ainsi
qu'un constat partagé absent du détail de sa seconde instance. Le
[plan de correction](PLAN-correction-fiabilite-rapports-cms.md) est à suivre avant
le prochain lot ;
il intègre les remarques « EN ATTENTE » de ce document. Vérification lors de cette
revue : 982/986 tests ordinaires réussis (4 sautés), 4/4 tests d'instances réelles
réussis, `git diff --check` et checksums des six rapports valides. Aucune correction
de code ni aucun commit n'a été effectué pendant la revue.

Date : 23 septembre 2026, fin de la 2e session (reprendre depuis ce point).
Les décisions utilisateur de la 1re session restent actives (voir plus bas). Tout est dans l'arbre de travail, **non commité**. `docs/PLAN-plugins-cms-frameworks.md` (non suivi par Git) reste la feuille de route ; il n'a pas été modifié.

## Décisions utilisateur (1re session, toujours actives)

- Implémenter en TDD `docs/PLAN-plugins-cms-frameworks.md` jusqu'au bout.
- Séparer les extensions personnalisées/non publiques et rendre visibles les CVE de leurs dépendances.
- Prendre en charge `symfony.lock`.
- Refuser un `-t/--target` non vide sans `--force`.
- Plugins CMS **expérimentaux** : jamais en `auto`, `--app-plugins` explicite requis.

## Décisions utilisateur (2e session)

- Les rapports à faire relire doivent être générés **en ligne** (OSV actif) : un rapport `--offline` a des chapitres CVE vides pour Symfony/Laravel et se lit faussement comme « rien ne marche ». C'est le diagnostic de l'incident « rien marche » — le scan fonctionnait, les rapports fournis étaient hors ligne.
- Tests d'instances réelles = **clonage Git de repos réels** à un tag vulnérable, pas de fixtures fabriquées (`rm -rf test/fixtures/real-instances` a été fait ; approche remplacée).
- Wordfence publie un flux v3 gratuit avec authentification Bearer. La fixture de test est volontairement réduite à CVE-2024-31210 et ne prouve pas la complétude du flux. Son score et son vecteur suivent l’avis WordPress : 7.6 HIGH.

## Livré depuis le handoff précédent (tout testé, tout vert)

1. **Découverte à preuve positive** : le contexte `component` lit et valide le contenu (`type` module/theme/profil pour `.info.yml`, champ `name` pour `.info` legacy) avant de produire un candidat ; l'evidence cite le champ validé. Faux marqueurs → `CMS_INFO_INVALID` par fichier ; un scan component qui ne reconnaît rien → `CMS_COMPONENT_NOT_RECOGNIZED` (runner). Contrat `discover` étendu : peut retourner `{ candidates, diagnostics }` en plus du tableau simple (`lib/application-plugins/runner.js`). Sous-modules d'un projet distribué regroupés : `parentComponentId`, `coord` hérité en `probable` avec evidence `submodule-of` ; backfill de version depuis le lock après regroupement (`lib/application-plugins/drupal.js`).
2. **`--max-advisory-age <durée>`** (`lib/advisory-freshness.js`, pur) : seule compte une date **déclarée dans le fichier** (`collectedAt`/`generatedAt` top-level ou clé réservée `_fadSnapshot.collectedAt`, seule métadonnée tolérée par `indexFeed`). Non déclaré / mal formé / trop ancien → exit 2 avant rapport. La date déclarée voyage dans la provenance (`sourceSnapshot.collectedAt`).
3. **Sources live + cache atomique** (`lib/application-providers/live-snapshot.js`) : `--drupal-advisories-live` interroge l'API officielle vérifiée `https://packages.drupal.org/8/security-advisories` (paramètre `packages[]`, sans auth) pour les seules identités `drupal/*` publiques inventoriées ; `WORDFENCE_API_KEY` ou `--wordfence-api-key` authentifie le flux v3 officiel ; `--wordfence-feed-url` permet de remplacer son URL. Snapshot estampillé `_fadSnapshot.collectedAt` à la collecte, validé par le même schéma, écrit atomiquement (temp+rename) sous `~/.fad-checker/advisory-snapshots/`. Refus sous `--offline` (exit 2), provider requis → exit 2 si réponse inutilisable. Le runner auto-déclare les providers requis pour les sources live.
4. **Synthèse d'instances dans la section 1.5** du rapport (`renderApplicationSummary` dans `lib/cve-report.js`) : une ligne par instance — CMS, chemin, version observée (core, sinon framework), comptes direct/indirect/origine inconnue, pire priorité (bande + CVSS), couverture par capacité **avec la voie nommée** (`advisories (wordfence-v3): completed`, `advisories (application-advisories): not-run (CMS_ADVISORY_NOT_QUALIFIED)`), note explicite pour les instances sans constat (« No matching advisory in the consulted data. » / « Evaluation incomplete. » / « No advisory check recorded. »). S'affiche même à zéro constat. i18n FR complet (`lib/i18n.js` ; le test i18n exige les deux directions).
5. **Tests d'instances réelles** (`test/real-instances.test.js`, **optionnels** : `FAD_REAL_INSTANCES=1 node --test test/real-instances.test.js`, réseau + git requis ; sinon sautés — la suite ordinaire reste hors ligne et rapide). Clones réels vérifiés en live avant d'écrire les tests :
   - WordPress/WordPress @ 6.4.2 → CVE-2024-31210 (fix 6.4.3, 7.6 HIGH avis WordPress) ; 14 thèmes réels, tous exacts vs leurs vrais `style.css`.
   - drupal/drupal @ 8.5.0 → SA-CORE-2018-002 / CVE-2018-7600 (enregistrement réel de l'API officielle). **Le repo shippe son vrai composer.lock** (44 paquets, symfony/http-foundation v3.4.4) ; la racine `replace` drupal/core, d'où le fallback marqueur (point 7).
   - symfony/symfony-demo @ v2.6.0 → lock réel pinne http-foundation v7.1.1 → CVE-2024-50345 (fix 7.1.7, confirmé OSV live).
   - BookStackApp/BookStack @ v24.10 → lock réel pinne laravel/framework v10.48.22 → CVE-2024-52301 (fix 10.48.23, confirmé OSV live). Le skeleton laravel/laravel ne commit plus de lock, d'où BookStack.
   - Un 4e test scanne le corpus **en ligne** (OSV live) et exige les 4 CVE réelles attribuées + zéro finding non attribué.
6. **Bug réel trouvé par ces tests, corrigé** : Drupal 8+ était détecté comme application Drupal 7 fantôme (`core/includes/bootstrap.inc` + `core/modules/system/system.module` existent aussi en D8). La découverte D7 exige désormais le `define('VERSION', '7.…')` dans `bootstrap.inc` comme preuve de contenu.
7. **Version core Drupal corroborée** (`lib/application-plugins/drupal.js`) : sans lock résolu, la version est **observée** depuis `const VERSION` de `core/lib/Drupal.php` (`versionStatus: "observed"`, evidence fichier+champ) → les avis réels sont évalués au lieu de mourir en `CMS_VERSION_UNKNOWN`. Le lock reste l'autorité (`locked`) ; divergence lock/marqueur → `CMS_VERSION_CONFLICT` avec les deux valeurs, inventaire `partial`.
8. Multi-instances : occurrences physiques préservées (une ligne/un total par occurrence, fusion des sources OSV+NVD+Drupal par occurrence ; avis sans CVE jamais fusionné dans une ligne CVE — pas d'alias commun, pas de CVE fabriqué). Audits de contenu menés : symfony-demo 118/118 et BookStack 147/118→147/147 composants exacts vs locks réels (versions + scopes), 0 erreur.

## Vérification à l'arrêt

- `npm test` : **986 tests — 982 réussis, 0 échec, 4 sautés** (les 4 tests d'instances réelles, gated).
- `FAD_REAL_INSTANCES=1 node --test test/real-instances.test.js` : **4/4 verts** (clones + scans + OSV live, ~3 min).
- `git diff --check` : aucune erreur. **Aucun commit créé** (66 fichiers modifiés/nouveaux dans l'arbre).
- Rapports réels régénérés en ligne pour revue manuelle dans `/tmp/realinst/reports/` (éphémère : corpus-all, corpus-all-fr, wordpress-6.4.2, drupal-8.5.0, symfony-demo-v2.6.0, bookstack-v24.10 — chaque dossier a `cve-report.html`, `findings.json`, `SHA256SUMS` ; `sha256sum -c` OK ; HTML autonomes). Les clones sont dans `/tmp/realinst/`. Les tests gated recréent l'équivalent.

## 3e session (23 sept. 2026) — re-vérification en conditions réelles, focus qualité/fiabilité des rapports

Décision utilisateur : la priorité est la **qualité et la fiabilité des rapports** ; ne pas attaquer le lot suivant avant d'avoir vérifié ce qui est livré, en conditions réelles. Les bugs HTML constatés doivent être notés ici.

### Re-vérifié vert (3e session)

- `npm test` : 986 tests — 982 réussis, 0 échec, 4 sautés (inchangé).
- `FAD_REAL_INSTANCES=1 node --test test/real-instances.test.js` : **4/4 verts** (rejoués, clones frais).
- `sha256sum -c` OK sur les 6 dossiers de `/tmp/realinst/reports/` (s'ils existent encore ; sinon régénérer en ligne).
- HTML structurellement valide (parseur dédié, 6 rapports) : aucune balise non fermée, aucun `id` dupliqué, toutes les ancres internes résolvent, aucun `undefined`/`NaN`/`[object Object]` dans le texte rendu.
- `findings.json` du corpus : 191 findings, **0 doublon** (id+app+coord@version), tous attribués à une application, comptes cohérents (183 prod + 8 dev = 191 ; section 1.5 et synthèse d'instances d'accord).

### BUGS HTML constatés (à corriger — priorité avant le lot direct/indirect)

1. **Numérotation de section cassée** : la sous-section « 7.0 Direct deps to update » est rendue sous « 5. Fix Recommendations » (EN) / « 7.0 Deps directes à mettre à jour » sous « 5. Recommandations de correction » (FR). Aucune section 7 n'existe. Cause : `lib/cve-report.js:1068-1073` (commentaire « Section 7.0 » + `minorSection(\`7.0 ...\`)`), vestige d'un ancien numérotage. Attendu : renuméroter en 5.x.
2. **Couverture inactionnable — le composant n'est pas nommé** : dans 6.4 « Application coverage », 14 lignes strictement identiques `wordpress:wp | advisories · wordfence-v3 | not-run | indeterminate | 0/1 | CMS_IDENTITY_UNVERIFIED` (une par thème réel non vérifié), **sans aucune colonne identifiant le composant concerné**. Idem dans la section 0 : 14 avertissements identiques `wordpress:wp: advisories not-run (CMS_IDENTITY_UNVERIFIED)`. L'opérateur ne sait pas quel thème vérifier ; le compte d'avertissements du corpus passe à 45 à cause de ces doublons. Cause côté production : `lib/application-providers/wordfence-v3.js:106-111` (le libellé warning/coverage n'embarque pas l'occurrence) + rendu `lib/cve-report.js`. Les lignes recipe symfony (`symfony.lock recipe doctrine/common has no matching...`) nomment bien le paquet : s'en inspirer.
3. **i18n FR incomplète dans le rapport (contrairement au point 4 « Livré » ci-dessus)** : en FR, restent en anglais : les voies de couverture de la synthèse d'instances (« inventory: completed », « advisories (wordfence-v3): completed », « advisories (application-advisories): not-run (CMS_ADVISORY_NOT_QUALIFIED) », « recipes: completed ») et tous les avertissements cms-coverage bruts. Le test i18n « deux directions » ne couvre pas ces chaînes. Mineur : « Deps directes à mettre à jour » → « Dépendances directes à mettre à jour ».

### Confirmations en conditions réelles des remarques déjà en attente (pas de nouveau bug, mais constaté sur les vrais rapports)

- **Lot 1 (direct/indirect)** confirmé trompeur aujourd'hui : le rapport du corpus annonce « 183 direct, 0 indirect » alors que 103 findings visent des composants `library` et 60 sont « origine inconnue » (layout drupal/drupal qui `replace` drupal/core). Un lecteur croit à 183 failles directes du code applicatif.
- **Remarque 2 (fixture HtaccessTest)** : vérifié — la fixture ne pollue **ni** l'inventaire ni les findings (0 composant/finding sous `tests/fixtures` des repos scannés) ; elle produit 2 warnings `parse-error` rendus bruts (composer.json ET composer.lock volontairement invalides du repo Drupal). La décision reste ouverte (warning brut vs limite de couverture tracée), l'absence de pollution est acquise.
- **Remarque 3 (regroupement best-effort)** confirmé sévère : le rapport drupal seul affiche ~20 avertissements « Manifest without a lockfile — best-effort (ranges skipped) » en vrac, un par composer.json de composant core.
- **Lot 4 (charts)** confirmé : 2 charts seulement, aucune instance applicative nommée dans leurs données.

### Bugs NON constatés (vérifiés absents)

- Pas de fuite de balises/entités dans le texte rendu, pas d'ancres cassées, pas d'ID dupliqués, pas de doublon dans findings.json, pas de finding non attribué.

## 4e session (23 sept. 2026) — plan de fiabilité exécuté intégralement

`docs/PLAN-correction-fiabilite-rapports-cms.md` est implémenté de bout en bout, en TDD (chaque lot : test rouge sur le défaut observé, puis correction, puis vert). Aucun commit créé.

### Livré (tout testé vert)

1. **§1.1 Union des paquets Drupal en live** : `mergeDrupalSnapshots` (`lib/application-providers/live-snapshot.js`) fusionne uniquement des réponses obtenues ; `drupal.js assess()` charge les identités manquantes d'une seconde instance avant son évaluation, réécrit le cache disque avec l'union exacte et une provenance ré-estampillée. Test double-instance aux deux ordres de découverte dans la suite ordinaire (`test/live-advisories.test.js`).
2. **§1.2 Sources locales validées avant la découverte** : `runApplicationPlugins` valide une seule fois chaque fichier configuré (lisibilité, taille, JSON, schéma via `indexFeed`/`validateSnapshot` fraîcheur si demandée), réutilise l'objet parsé dans `assess`. Fichier absent/invalide/schéma invalide → exit 2 sans rapport même sans instance correspondante ; fichier valide → exit 0. `drupal-advisories.js` exporte `validateSnapshot`.
3. **§1.3 Agrégation de couverture par capacité ET fournisseur** (`renderApplicationSummary`) : `failed` > `partial` > `not-run` > `completed`, mixte lu comme partiel, `executed/expected` + « N not evaluated » + diagnostics comptés, note « Evaluation incomplete » même avec constat. WordPress 6.4.2 réel : `advisories (wordfence-v3): partial (1/15, 14 not evaluated — CMS_IDENTITY_UNVERIFIED)`.
4. **§2.1 Couverture actionnable** : colonne Composant en 6.4 (kind · nom · chemin · occurrenceId) ; chapitre 0 regroupe les gaps par (application, capacité, source, diagnostic) en un bloc navigable avec compte, action attendue (`diagnosticAction`) et liste des composants — 14 lignes identiques deviennent 1 bloc avec 14 composants nommés (groupement construit dans `fad-checker.js`, rendu traduit dans `cve-report.js`).
5. **§2.2 Numérotation + i18n** : « 7.0 » orphelin → « 5.1 Direct deps to update » / FR « 5.1 Dépendances directes à mettre à jour » ; libellés capacité/voie/exécution/résultat traduits (synthèse, 6.4, chapitre 0) via `capabilityLabel`/`executionLabel`/`resultLabel` ; codes `CMS_*`, `sourceId`, `execution` restent bruts dans le JSON.
6. **§2.3 Regroupement des avertissements par manifeste** : `renderWarnings` groupe `no-lockfile` et `parse-error` en un bloc par type (chaque manifeste listé avec son détail épinglés/plages ignorées ; le JSON garde une entrée par manifeste). Fixture HtaccessTest du vrai drupal/drupal : 0 composant/finding issu de la fixture, 2 limites parse circonscrites listées — assertions ajoutées au test gated.
7. **§3.1 Direct/indirect conforme au plan §6.3** (`lib/application-inventory.js`) : `TARGET_KINDS` seulement rootent un BFS `composer-require` et obtiennent une self-relation direct ; une `library` ne s'attribue jamais elle-même ; attribution `root-manifest` au composant primaire (core/framework) pour les paquets du manifeste racine non réclamés — couvre le layout drupal/drupal qui `replace` drupal/core. Nouvelles clés `applicationExposures` par instance dans le JSON.
8. **§3.2 Constat partagé par instance** : `renderApplicationCves` groupe sur TOUTES les relations d'application avec origines par instance (`perAppExposure` : `applicationExposures` > relations par occurrence > owners filtrés par application) ; renvoi « Also exposed in » dans chaque section ; compteurs globaux = union de findings ; la synthèse compte direct/indirect par instance.
9. **§3.3 Alignement charts/exports** : chart « Most vulnerable instances » sur les scans applicatifs (`mostVulnerableApplications`, exposés par instance, occurrences partagées comptées dans chacune, centre = findings distincts, note = recoupement + gaps d'avis) ; SARIF portait déjà findingId/relation (test de contrat ajouté), SBOM porte `fad:finding` = `findingId=relation` par occurrence, CSAF garde un produit affecté par occurrence physique (test de contrat), diff occurrence-aware + reclassement « unassessed » déjà testés.

### Ajustements post-recette (décisions utilisateur)

- **Avertissements « runtime PHP indéterminable » supprimés** (EN + FR) : un runtime déployé n'est pas une propriété des manifestes, la note se déclenchait sur pratiquement tout arbre source (24 sur le corpus, 23 sur drupal seul) et noyait les avertissements actionnables. `evaluatePhpRuntime` ne produit plus que des findings ; un runtime indéterminé reste silencieux (jamais un verdict, jamais une note). Le vrai verdict PHP est inchangé : un finding est toujours émis quand la contrainte déclarée prouve un runtime EOL. Heading et traduction retirés du rapport, tests mis à jour, USAGE/CHANGELOG documentés.
- **Charts applicatifs corrigés** (voir plus haut) : donut CWE = findings DIRECTS applicatifs uniquement ; 2e donut = « Indirect CVEs per direct dependency » groupé par composant d'origine. Les rapports de `/tmp/realinst/reports/` sont régénérés AVEC enrichissement NVD/EPSS/KEV complet.

### Comptes exacts observés après correction (corpus réel, EN LIGNE, `/tmp/realinst/reports/`)

- Suite ordinaire : **1002 tests — 998 réussis, 0 échec, 4 sautés** (gated). `git diff --check` vert.
- Gated réel : **4/4 verts** (clones frais + OSV live + assertions HtaccessTest).
- Corpus (4 instances) : 191 findings — **28 direct / 162 indirect / 1 unknown** (avant correction : 131 direct / 0 indirect / 60 unknown). Par instance : drupal 1/59/1, symfony-demo 22/44/0, bookstack 4/59/0, wordpress 1/0/0. 191 findingIds uniques ; 189 findings portent des `applicationExposures` par instance (les 2 restants sont les avis Wordfence/Drupal hors Composer, mono-application, fallback correct).
- Invariants vérifiés : CVE du core Drupal, de `symfony/http-foundation` (dans symfony-demo) et de `laravel/framework` **directes** ; le même http-foundation sous le core Drupal et sous laravel/framework **indirect** (testé). L'unknown restant = occurrence de plage `1.2.*` de `doctrine/annotations` depuis un sous-manifeste core sans lock — déjà listée comme limite best-effort, restée inconnue honnêtement (le verrouillé 1.2.7 est indirect sous le core).
- **Charts applicatifs corrigés après revue utilisateur** : le donut CWE restait vide (0/191 findings sans enrichissement NVD — les scans de revue désactivaient `-d nvd,epss,kev`) et le donut « sous-dépendances » ne voyait jamais les findings Composer (jamais `scope: transitive`). Désormais, sur un scan applicatif : le donut CWE porte les findings DIRECTS applicatifs uniquement (33 sur le corpus — les vulnérabilités des versions des CMS/frameworks), le 2e donut s'intitule « Indirect CVEs per direct dependency » (FR « CVE indirectes par dépendance directe ») et groupe les indirectes par composant d'origine (core Drupal 55, laravel/framework 37, symfony/framework-bundle 27…), les sans-origine restent un compte en note. **Les rapports finaux de `/tmp/realinst/reports/` sont régénérés AVEC enrichissement complet (NVD/EPSS/KEV actifs, aucune option `-d`)** — 174/191 findings du corpus portent des CWE, la suite de tests reste hors ligne/déterministe (les fixtures fournissent les CWE).
- Rapports régénérés EN/FR en ligne : `/tmp/realinst/reports/{corpus-all,corpus-all-fr,wordpress-6.4.2,drupal-8.5.0,symfony-demo-v2.6.0,bookstack-v24.10}/` — chaque dossier : `cve-report.html`, `cve-report.doc`, `findings.json`, `SHA256SUMS` (3/3 OK). Parseur : 0 balise non fermée sur les 12 fichiers ; 0 id dupliqué ; 0 ancre cassée ; « 7.0 Direct deps » absent ; FR sans reste anglais de couverture ; chart-instances présent EN/FR.
- Docs : `docs/USAGE.md` phrase périmée corrigée (les sources Wordfence/Drupal SONT connectées ; ce sont les capabilities application-advisories Symfony/Laravel qui restent `not-run (CMS_ADVISORY_NOT_QUALIFIED)`), README et CHANGELOG (section Unreleased/Fixed) mis à jour uniquement pour les comportements validés ci-dessus.

### Limites restantes (documentées, hors périmètre de ce plan)

- `application-advisories` (Symfony/Laravel) toujours `not-run (CMS_ADVISORY_NOT_QUALIFIED)` : leurs CVE viennent de la voie Composer standard.
- Les 14 thèmes du WordPress réel gardent `CMS_IDENTITY_UNVERIFIED` (identité catalogue non prouvée) — la voie est honnête et groupée, la couverture restera partielle tant que l'opérateur ne déclare pas les identités.
- Occurrences de plages (best-effort sans lock) sans origine : restent « unknown » avec le warning groupé correspondant — un verrouillage (`composer install`) est l'action indiquée.
- Vague 2 (Joomla, PrestaShop, TYPO3, Magento), checksums/intégrité WordPress, cycle de vie/support CMS, benchmark de performance : non entamés (plan général inchangé).

### Point de reprise conseillé

Le plan de fiabilité est clos. Reprendre le plan général `PLAN-plugins-cms-frameworks.md` : parité HTML/Word restante éventuelle côté filtres, puis vague 2. Conserver : suite ordinaire hors ligne/déterministe, plugins derrière `--app-plugins`, rapports de revue en ligne, aucun commit sans demande.

## 5e session (23 sept. 2026) — comparaison avec les outils officiels + correctifs de rappel

Décision utilisateur : comparer les résultats des scans CMS aux **outils officiels quand ils
existent** (composer audit pour Composer, l'API packages.drupal.org pour Drupal, l'enregistrement
publié pour WordPress ; drush `pm:security` n'énumère pas les CVE — il signale une mise à jour de
sécurité via le release history), déduire les correctifs, les implémenter et retester. Tout en TDD,
aucun commit créé.

### Mesures de comparaison (2026-09-23, données vivantes)

- `composer audit` 2.10.3 sur les 3 arbres à lock réel, alias PKSA↔GHSA↔CVE résolus :
  drupal 62 / symfony-demo 68 / bookstack 64 uniques (son « 65 » compte 2× GHSA-5vg9-5847-vvmq).
  fad avant correctifs : 60 / 66 / 63 → **5 findings manquants**, tous de la même classe :
  twig/twig CVE-2026-46636 + CVE-2026-46627 (@1.35.0 drupal, @3.10.3 symfony-demo),
  knplabs/knp-snappy CVE-2026-46643 (@1.5.0 bookstack). Cause racine vérifiée en direct :
  OSV ne porte ces CVE qu'en entrées CVEProject **sans coordonnées Packagist** (plages
  GIT/CPE), donc aucune requête OSV paquet+version ne peut les retourner ; la voie NVD CPE
  additive de fad est limitée à Maven. Tout le reste était à parité exacte, y compris
  league/commonmark 13/13 et les avis laravel/aws/onelogin.
- API officielle packages.drupal.org pour drupal/core : 90 avis, **15 affectent réellement
  8.5.0**. `--drupal-advisories-live` de fad : 15/15 trouvés (0 manqué) — parité exacte avec
  l'enregistrement officiel ; drush n'énumère pas, composer audit ne voit pas drupal/core
  (absent du lock, root `replace`), fad l'attrape par la voie dédiée.
- WordPress 6.4.2 : la fixture réduite contient CVE-2024-31210 (7.6 HIGH, correction 6.4.3). L’avis éditeur de CVE-2024-31211 indique une correction dès 6.4.2 : cette CVE ne doit pas figurer dans le rapport de cette version. La fixture ne démontre aucune complétude du flux Wordfence.

### Livré (tout testé vert)

1. **Voie « packagist-audit » pour Composer** (`lib/packagist-audit.js`, défaut ON,
   `-d packagist-audit` pour couper) : interroge l'endpoint exact de `composer audit`
   (`packagist.org/api/security-advisories/`, lots de 100 paquets, seuls des NOMS voyagent),
   évalue les contraintes officielles par version verrouillée (`|`/`||`, `^`, `~`, `X.Y.*`,
   partiels, intervalles ; jeton imparsable → indécidable, jamais un verdict), cache par
   paquet 24 h dans `~/.fad-checker/packagist-advisories/`, offline = cache chaud
   uniquement (zéro réseau — testé par tripwire). Recette sur les 3 arbres réels :
   **parité exacte avec composer audit** (68/68, 62/62, 64/64 uniques), 0 doublon.
2. **Fusion de sources alias-aware** (`lib/merge-sources.js`, extrait de `fad-checker.js`
   pour être testable) : un même avis peut arriver clé par son CVE (OSV) ou par son GHSA
   remoteId (Packagist sans champ cve — commonmark GHSA-8rr7/jjv6/j8pm/c2pc sur le corpus) ;
   la collision se résout par `aliases`+`ghsa` au lieu de dupliquer. L'id primaire existant
   gagne, les alias fusionnés sont l'union, sévérité non-UNKNOWN préférée. Sans ce correctif,
   la voie packagist ajoutait 4 doublons sur symfony-demo.
3. **Contraintes Drupal `X.Y.*` décidées** (`affectedComposerVersion`) : une version hors de
   la branche `11.2.*`/`11.0.*` (SA-CORE-2026-010/011/012 réels) est `no-match` au lieu de
   `CMS_CONSTRAINT_UNSUPPORTED` ; le scan live du vrai drupal 8.5.0 passe de
   `partial/indeterminate` + diagnostic à `completed/affected`.
4. **Suite real-instances durcie** : le test online conduit `--drupal-advisories-live` et
   asserte l'enregistrement officiel complet (≥15 avis pour 8.5.0, CVE-2018-7600/7602/9861,
   CVE-2024-11941, SA-CORE-2023-001 sans CVE, couverture `completed` — attrape un matcher
   ou un snapshot sous-déclaratif) ; la fixture WordPress ne porte que CVE-2024-31210 et vérifie l’absence de CVE-2024-31211 sur 6.4.2.
5. **Cleanup** : `validateSnapshot` dupliqué mot pour mot supprimé de
   `lib/application-providers/drupal-advisories.js` (code mort, aucune modification de
   comportement).
6. Docs alignées sur ce qui est validé : README, USAGE (`--no-packagist-audit`),
   COMPARISON (sources + parité composer audit), CHANGELOG (Unreleased Added/Fixed),
   CLAUDE.md (architecture, TTL, liste des sources).

### Vérification à l'arrêt (5e session)

- `npm test` : **1022 tests — 1018 réussis, 0 échec, 4 sautés** (gated ; +18 tests au fil de
  la session : voie Packagist, fusion alias-aware, wildcards Drupal, chapitre vendored-JS
  groupé). `git diff --check` vert.
- `FAD_REAL_INSTANCES=1 node --test test/real-instances.test.js` : **4/4 verts** (clones frais,
  corpus offline + scan online avec Drupal live : 15 avis officiels, couverture core
  `completed/affected`, la CVE WordPress 6.4.3 applicable à 6.4.2, CVE-2024-50345, CVE-2024-52301, 0 finding
  non attribué).
- Recomptage réel après correctifs (scans en ligne, hors enrichissement NVD) : symfony-demo
  68 (= composer audit), drupal 64 composer-lane dont les 2 twig + 15 core via la voie live,
  bookstack 64 uniques.

### Rapports de revue régénérés (fin de 5e session, restructure du chapitre vendored-JS incluse)

Les 6 rapports de `/tmp/realinst/reports/` ont été régénérés EN LIGNE, enrichissement complet
(NVD/EPSS/KEV actifs, clé NVD configurée), `--ecosystem composer`, flux Wordfence à
1 CVE applicable à 6.4.2, `--drupal-advisories-live` (couverture core `completed/affected`,
`tool-fetched`, collecte fraîche). Comptes après la revue corrective : corpus **211 findings** ;
wordpress-6.4.2 **1** ; drupal-8.5.0 **78** ; symfony-demo-v2.6.0 **68** ; bookstack-v24.10
**64**. Les 3 manques mesurés vs `composer audit` (twig CVE-2026-46636/46627,
knp-snappy CVE-2026-46643) sont présents, enrichis NVD (CWE-1336, CWE-400, CWE-78), 0 doublon.
Validation structurelle des 6 HTML : 0 id dupliqué, 0 ancre cassée, 0 balise non fermée,
« 7.0 Direct deps » absent, FR sans reste anglais de couverture, `sha256sum -c` 3/3 partout.
Le chapitre « Vendored JS vulns » est désormais une ligne par lib physique (corpus : 736
findings groupés en 383 lignes, sous-tableaux au clic, .doc force-ouvert), avec les cellules
CVE liées (NVD ou source) et CWE (NVD) sur la ligne.

Revue utilisateur post-régénération (même session) :

- **En-têtes de tableau minimaux** : le thead du tableau retire (chapitre CVE) mesurait
  **185 px** — la règle globale `td.cve, td.cve a { white-space: nowrap }` s'appliquait à la
  cellule-liste d'identifiants, et les identifiants de repli de retire (phrases de prose,
  tinymce 4.9.11 du corpus) tenaient sur une ligne de 4280 px → tableau à 7× son conteneur,
  colonnes CWE/compteur écrasées à ~30 px. Corrigé : classe `ids` dédiée (chaque identifiant
  CVE/GHSA reste insécable, la liste se coupe ENTRE les identifiants, un repli de prose se
  replie comme du texte), en-tête FR du compteur en forme courte (« Vuln. », aligné sur le
  pill d'inventaire), colgroup rééquilibré [9,18,24,22,15,12]. Même famille corrigée au
  passage sur TOUS les tableaux : `thead th { word-break: normal }` — l'ancien
  `word-break: break-word` laissait le calcul de largeur intrinsèque écraser une colonne à
  quelques caractères et « Version corrigée » se cassait en 7 lignes (thead de 173 px sur le
  rapport drupal, plus haut que toute ligne de données). Mesuré au moteur de rendu après
  correctifs : **thead retire 29 px (une ligne), tableau = son conteneur (687 px)**, aucun
  thead ne dépasse 53 px (EOL FR, 3 mots) sur les 6 rapports.
- **2e donut applicatif renommé** : « Indirect CVEs per direct dependency » / FR « CVE
  indirectes par dépendance directe » (était « per introducing component ») — le
  regroupement (indirectes comptées sous la dépendance directe qui les introduit) est
  inchangé, le titre dit maintenant ce que le lecteur regarde.

### Point de reprise conseillé

La vague 2 (Joomla, PrestaShop, TYPO3, Magento) du plan général reste l'étape suivante.
Nouvel invariant à conserver : toute nouvelle voie d'avis s'aligne sur l'outil officiel de son
écosystème (Packagist audit pour Composer, API packages.drupal.org pour Drupal, flux vendeur
pour Wordfence) et la fusion d'alias est testée avant tout ajout de source.

## Remarques utilisateur EN ATTENTE — prochain lot, dans cet ordre

0. ~~Corriger les 3 bugs HTML de la 3e session~~ — **fait en 4e session** (points 4-6 du plan de fiabilité ci-dessus, §§2.1-2.2). Les remarques 1 à 5 ci-dessous ont été traitées par ce même plan (1 = §3.1, 2 = §2.3, 3 = §2.3, 4 = §3.3) ; la vague 2 et les fonctions restantes du plan général restent ouvertes.

1. **Direct/indirect conforme au plan §6.3** — pas encore implémenté, analyse faite, code non touché. Attendu : une CVE sur une **bibliothèque** doit apparaître en **INDIRECT**, groupée sous le composant d'origine (core/framework/plugin/thème qui l'introduit) ; une CVE visant le CMS/core/framework/composant officiel/bundle/extension/thème doit apparaître en **DIRECT**. Aujourd'hui : (a) tout paquet du lock est inventorié comme composant, donc un avis sur twig/doctrine/etc. est classé « direct » par self-ownership ; (b) les deps du lock Drupal d'un projet racine qui `replace` drupal/core restent « origine non déterminée » (60 findings du clone réel). Piste conçue : dans `lib/application-inventory.js`, définir `TARGET_KINDS = {core, framework, framework-component, bundle, module, theme, profile, plugin, mu-plugin, drop-in}` ; seuls ces kinds rootent un BFS `composer-require` et obtiennent une self-relation « direct » ; un kind `library` ne s'attribue pas lui-même (indirect via ses requirers, sinon unknown) ; marquer le composant **primaire** (`primary: true`) dans les 4 plugins (core pour wordpress/drupal, framework pour symfony/laravel) qui possède les occurrences des manifests à la racine d'app (`composer.lock`/`composer.json` du root) → les deps du core deviennent indirectes sous le core, y compris le layout drupal/drupal. Relire d'abord `test/application-inventory.test.js` (5 tests, lus, aucun ne contredit le modèle a priori) puis `test/application-drupal*.test.js`, `test/real-instances.test.js` (assertions owners/relation à mettre à jour : le test symfony exige déjà `framework.id` + `httpFoundation.id` et `direct` — http-foundation est `framework-component`, donc cible, ça reste vert ; vérifier les splits du corpus : drupal doit passer à ~1 direct / ~60 indirect / 0 unknown).
2. **Parse-error à vérifier** : pendant le scan réel de drupal/drupal, `core/modules/system/tests/fixtures/HtaccessTest/composer.lock` produit « composer.lock parse failed: Unexpected end of JSON input ». C'est un vrai fichier du repo Drupal (fixture de test volontairement invalide). Vérifier le comportement (aujourd'hui warning sans crash), décider si un fixture de test cassé doit être une limite de couverture tracée plutôt qu'un warning brut, et s'assurer que les fixtures de tests des CMS scannés ne polluent pas l'inventaire/les counts.
3. **Grouper « Manifest without a lockfile — best-effort (ranges skipped) »** : la liste des manifests best-effort (composer.json sans lock, etc.) doit être regroupée dans le rapport au lieu d'être affichée en vrac. Vérifier le rendu actuel de cette section.
4. **Charts à mettre à jour** (`lib/charts.js`) : assimiler les instances applicatives à des projets (le donut « most vulnerable components » doit nommer les instances), les plugins/themes/extensions comme deps **directes** et leurs sub-deps comme **indirectes**. Aujourd'hui les charts sont calculés sur l'agrégation générale sans vue applicative (le plan §6.3 demande « tableaux, résumés et graphiques à partir d'une agrégation commune »). Dépend du point 1 (le modèle direct/indirect doit être en place d'abord).
5. Reste du plan inchangé : parité complète des regroupements applicatifs HTML/Word (filtres synchronisés), vague 2 (Joomla, PrestaShop, TYPO3, Magento — **non entamée**, arrêt demandé juste avant), checksums/intégrité WordPress, cycle de vie/support CMS, benchmark de performance sur corpus réel.

## Points d'entrée conseillés

`lib/application-inventory.js` + `test/application-inventory.test.js` (lot 1, le prochain), puis `lib/cve-report.js` (`renderApplicationSummary`, `renderApplicationCves`, section 1.5), `lib/charts.js` (lot 4), `test/real-instances.test.js` (`FAD_REAL_INSTANCES=1`). Conserver : la suite ordinaire hors ligne et sans réseau ; les plugins CMS expérimentaux derrière `--app-plugins` explicite ; les scans sans code PHP/WordPress/Drupal cible ; aucun commit sans demande.
