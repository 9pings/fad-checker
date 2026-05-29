# Design — Codecs & support multi-écosystème (C#/.NET, PHP, Python)

**Date** : 2026-05-29
**Statut** : approuvé (brainstorming) — prêt pour le plan d'implémentation

## Objectif

1. Réorganiser tout le code spécifique à un écosystème (aujourd'hui Maven + npm/yarn,
   éparpillé dans `lib/core.js`, `lib/npm/*`, `lib/outdated.js`, `lib/osv.js`,
   `lib/cve-report.js`, `fad-checker.js`) derrière une **interface codec** uniforme.
2. Ajouter trois écosystèmes en **parité complète** (vuln, EOL, obsolete, outdated,
   recette de fix dans le report) : **C#/.NET (nuget)**, **PHP (composer)**, **Python (pypi)**.

## Décisions cadrées (brainstorming)

- **Parité complète d'emblée** pour les 3 nouveaux écosystèmes.
- **Big-bang** : extraction complète maven/npm vers des codecs (pas de cohabitation
  « ancien monde / nouveau monde »). Le big-bang **réorganise, il ne réécrit pas** la
  logique métier éprouvée (résolution POM/BOM, walker Maven Central, parsers lockfiles).
- **depRecord généralisé** : schéma neutre `{ ecosystem, namespace, name, version,
  versions[], coordKey, manifestPaths[], … }`.
- **Règle de résolution de manifeste uniforme** (changement de philosophie) :
  lockfile présent → on le prend ; sinon **fallback** sur le manifeste lâche
  (`composer.json` / `requirements.txt` / `*.csproj` / `package.json`) **avec warning**.
  Versions épinglées scannées, ranges/floating skippées individuellement + warning.
- **TOML** : dépendance légère **`smol-toml`** (maintenue, zéro dép transitive, TOML 1.0).

### ⚠️ Changement de contrat assumé (npm)

Comportement actuel : un `package.json` sans `package-lock.json`/`yarn.lock` est
**entièrement skippé** (warning chapitre 0). Nouveau comportement : il est **parsé en
best-effort** (versions épinglées) avec warning `no-lockfile — résultats partiels`.
Le test existant `no-lockfile` est adapté en conséquence (vérifie désormais le
fallback+warning, plus le skip total).

## Architecture

### L'interface codec

`lib/codecs/codec.interface.js` documente le contrat (objet, pas de classe imposée) :

```js
{
  id,            // "maven" | "npm" | "yarn" | "nuget" | "composer" | "pypi"
  label,         // "Maven", "npm", "NuGet", "Composer", "PyPI"
  osvEcosystem,  // "Maven" | "npm" | "NuGet" | "Packagist" | "PyPI" | null

  manifestNames,            // fichiers revendiqués par ce codec
  detect(dir) -> bool,      // ce repo contient-il mes manifestes ?

  collect(dir, opts) -> { deps: Map<coordKey, depRecord>, warnings: [] },

  coordKey(dep),            // clé Map normalisée
  formatCoord(dep),         // affichage report
  osvPackageName(dep),      // nom pour OSV

  checkRegistry(deps, opts) -> { outdated:[], deprecated:[] },
  resolveEolProduct(dep) -> { product, label } | null,

  recipe,                   // { label, pinSection, pinIntro, snippet(deps), directSection }
  nativeScanners,           // scanners au-delà du tronc commun OSV/NVD
}
```

### Le depRecord généralisé

```js
{
  ecosystem,        // "maven"|"npm"|"yarn"|"nuget"|"composer"|"pypi"
  namespace,        // groupId (maven) / scope @org (npm) / vendor (composer) / "" sinon
  name,             // artifactId / package name
  version,          // version représentative (la plus haute) pour affichage/EOL/outdated
  versions[],       // toutes les versions concrètes distinctes (CVE/OSV itèrent dessus)
  coordKey,         // clé de la Map, ex "maven:org.apache:log4j", "pypi:requests"
  scope, isDev,
  manifestPaths[],  // remplace pomPaths/manifestPaths
  // transitif : via, viaPaths, depth
  // lock-specific : lockType, resolved, integrity
}
```

`coordKey` ne collisionne jamais entre écosystèmes (préfixe `ecosystem:`).

### Registre des codecs

`lib/codecs/index.js` :
- `getCodec(id)` → codec
- `allCodecs()` → tous les codecs enregistrés
- `detectCodecs(srcDir)` → codecs dont `detect()` est vrai

### Services partagés (agnostiques — plus aucun `if ecosystem === …`)

- `lib/osv.js` — querybatch groupé par `codec.osvEcosystem`, nom via `codec.osvPackageName`.
- `lib/nvd.js` — enrichment par CVE-id, totalement agnostique. **Activé pour tous les
  écosystèmes** : dès qu'OSV remonte un `CVE-xxxx`, NVD/CPE s'appliquent.
- `lib/cpe.js` — refinement / filtrage faux positifs sur les matches, agnostique.
- Fetch `endoflife.date` — partagé ; le codec ne fournit que `{ product }`.
- Cache (`~/.fad-checker/`) — partagé.

### Scanners rattachés à un codec (`nativeScanners`)

- `maven` → CVE-index local cvelistV5 (`lib/cve-download.js` + tier matching `lib/cve-match.js`).
- `npm`/`yarn` → retire.js (`lib/retire.js`).
- `nuget` / `composer` / `pypi` → aucun (couverts par OSV + NVD).

### Flux d'orchestration (`fad-checker.js`)

```
1. detectCodecs(src) filtré par --ecosystem
2. resolved = Map() ; pour chaque codec actif : merge codec.collect(src,opts).deps
3. expansion transitive : déléguée au codec (maven → walker Maven Central ; autres → lock)
4. vuln :
   a. OSV (tronc commun) groupé par codec.osvEcosystem
   b. nativeScanners par codec (maven: CVE-index ; npm/yarn: retire.js)
   c. NVD enrichment (agnostique, par CVE-id)
   d. CPE refinement (agnostique)
5. EOL / obsolete / outdated : codec.resolveEolProduct + codec.checkRegistry
6. render : sections pilotées par les codecs présents
```

## Spécifications par codec

### maven (extrait)

`collect()` enveloppe `lib/core.js` (parse POM, résolution parent, merge multi-profils,
`<dependencyManagement>`, imports `scope=import`/BOM) **conservés tels quels** + walker
`lib/transitive.js`. WebJars : `webjarToNpm()` reste **dans le codec maven** (un WebJar
est un artifact Maven émettant une coord npm ; le codec maven route ces deps vers le
chemin npm pour EOL/registre).

| Aspect | Valeur |
|---|---|
| coordKey | `maven:groupId:artifactId` |
| osvEcosystem | `Maven` |
| nativeScanners | CVE-index cvelistV5 |
| registre | Maven Central Solr |
| obsolete | `data/known-obsolete.json` (curated) |
| EOL | `by_group_artifact` / `by_group_prefix` |
| recette | `<dependencyManagement>` + maj des deps directes |

### npm / yarn (extrait)

`collect()` enveloppe `lib/npm/parse.js` + `lib/npm/collect.js` (parsers
package-lock v1/2/3, yarn.lock v1) **conservés**. Deux codecs partageant `osvEcosystem=npm`
et le préfixe coordKey `npm:` ; `ecosystemType` distingue pour report/recette.

| Aspect | Valeur |
|---|---|
| coordKey | `npm:name` (ou `npm:@scope/name`) |
| osvEcosystem | `npm` |
| nativeScanners | retire.js |
| registre | npm registry (`deprecated` + `dist-tags.latest`) |
| EOL | `by_npm_name` / `by_npm_scope` |
| recette | `overrides` (npm) / `resolutions` (yarn) |

### nuget (C#/.NET) — nouveau

| Aspect | Valeur |
|---|---|
| manifestes | `packages.lock.json` (lock, résolu+transitif), `*.csproj` (`<PackageReference>`, XML via xml2js), `packages.config` (XML legacy) |
| CPM | `Directory.Packages.props` lu comme **table de versions** ; `PackageReference` sans `Version` résolu contre `<PackageVersion>`, sinon warning `unresolved-versions` |
| fallback | `.csproj` épinglé scanné ; floating (`1.*`, `[1.0,2.0)`) skip+warning |
| coordKey | `nuget:<name-lower>` (NuGet case-insensitive ; casse d'origine gardée pour l'affichage) |
| osvEcosystem | `NuGet` |
| registre | `api.nuget.org` registration index → version stable max + `deprecation.reasons`/`alternatePackage` |
| EOL | endoflife.date `dotnet` (target framework `net6.0`/`net48`…), `aspnet`, `entity-framework` via `by_nuget_name` |
| recette | maj `<PackageReference>` + note CPM `Directory.Packages.props` |

### composer (PHP) — nouveau

| Aspect | Valeur |
|---|---|
| manifestes | `composer.lock` (JSON, `packages[]` + `packages-dev[]`, concret+transitif) ; `composer.json` sans lock → fallback+warning |
| coordKey | `composer:vendor/package` (case-insensitive normalisé) |
| osvEcosystem | `Packagist` |
| registre | `repo.packagist.org/p2/{vendor}/{pkg}.json` → dernière version + champ **`abandoned`** (≈ deprecated, peut pointer un remplaçant) |
| EOL | endoflife.date `php`, `laravel`, `symfony`, `drupal` via `by_composer_name` |
| recette | `composer require vendor/pkg:^x` / bloc `composer.json` |

### pypi (Python) — nouveau

| Aspect | Valeur |
|---|---|
| manifestes | `poetry.lock` (TOML), `Pipfile.lock` (JSON), `uv.lock` / `pdm.lock` (TOML), `requirements.txt` (épinglé `==` seul) |
| fallback | `requirements.txt` à ranges → skip+warning ; `pyproject.toml`/`Pipfile` sans lock → fallback+warning |
| normalisation | PEP 503 : `Foo.Bar_baz` → `foo-bar-baz` pour clé/OSV/registre ; casse d'origine pour affichage |
| coordKey | `pypi:<name-pep503>` |
| osvEcosystem | `PyPI` |
| registre | `pypi.org/pypi/{name}/json` → `info.version` (latest) + détection `yanked` par version + classifier `Development Status :: 7 - Inactive` comme signal obsolete |
| EOL | endoflife.date `python`, `django`, `numpy`, `fastapi` via `by_pypi_name` |
| recette | `pip install 'pkg>=x'` / ligne `requirements.txt` / bloc selon le lock détecté |

## Données

- `data/eol-mapping.json` gagne `by_nuget_name`, `by_composer_name`, `by_pypi_name`.
- `data/known-obsolete.json` reste Maven-only : les autres écosystèmes ont des champs
  registre authoritatifs (`deprecation` NuGet, `abandoned` Packagist, `yanked` PyPI).

## CLI

- `--ecosystem` : enum → **liste** : `auto` (défaut, = `detect()` vrai) | `all` | liste
  explicite `maven,nuget,pypi,…`.
- `--no-<id>` génériques : `--no-maven --no-npm --no-yarn --no-nuget --no-composer --no-pypi`.
- `--no-js` conservé comme **alias** de `--no-npm`+`--no-yarn` (rétro-compat).
- `--transitive` / `--transitive-depth` : s'appliquent au codec maven uniquement
  (no-op documenté ailleurs ; les autres ont le transitif via lock).
- `--snyk` : inchangé (POM nettoyé maven).

## Report (`lib/cve-report.js`)

- Sections par écosystème (1.a, 1.b, …) **générées dynamiquement** selon les codecs
  présents, ordre stable : `maven, npm, yarn, nuget, composer, pypi`.
- `RECIPE_SPECS` / `ECO_LABELS` / `ECO_MANIFEST_KIND` alimentés depuis `codec.label`,
  `codec.recipe`, `codec.manifestNames` — fin des maps codées en dur.
- `formatCoord(dep)` délégué au codec — fin des `if (ecosystem === "npm")` dans le rendu.

## Tests

Objectif : les 96 tests existants restent verts + nouveaux tests.

- Fixtures : `csharp-app/` (.csproj + packages.lock.json + packages.config +
  Directory.Packages.props), `php-app/` (composer.json + composer.lock),
  `python-app/` (un répertoire par format : requirements.txt épinglé, poetry.lock,
  Pipfile.lock, uv.lock).
- Un fichier de test par codec (`nuget.test.js`, `composer.test.js`, `pypi.test.js`) :
  parsing, coordKey, normalisation de noms (PEP 503, case-insensitive NuGet),
  fallback no-lockfile.
- Test de contrat paramétré sur `allCodecs()` : chaque codec implémente toute l'interface.
- Fixture `polyglot/` mêlant les 5 écosystèmes (ou extension de `monorepo-mixed`).

## Ordre d'exécution du big-bang (chaque étape laisse le pipeline fonctionnel)

1. `codec.interface.js` + `lib/codecs/index.js` (registre vide).
2. Généraliser le `depRecord` (`namespace`/`name`/`coordKey`/`manifestPaths`) — adapter
   collecteurs + report + tests existants.
3. Extraire `maven` et `npm`/`yarn` dans des codecs (déplacement, pas réécriture) ;
   brancher l'orchestrateur sur le registre. **→ les 96 tests repassent ici.**
4. Rendre `osv.js` / `nvd.js` / `cpe.js` / endoflife agnostiques (via codec).
5. Ajouter `composer` (lock JSON, le plus simple), puis `pypi`, puis `nuget`.
6. Report dynamique + CLI liste + fixtures + tests nouveaux.

## Hors périmètre (YAGNI)

- Pas de résolution de ranges/floating (cohérent lockfile-first ; ranges → warning).
- Pas de support yarn-berry (déjà `unsupported` aujourd'hui), pas de pnpm dans ce lot.
- Pas de scanner natif dédié pour nuget/composer/pypi (OSV + NVD suffisent à la parité).
- Pas de curation obsolete pour les nouveaux écosystèmes (champs registre authoritatifs).
