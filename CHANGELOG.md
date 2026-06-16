# Changelog

All notable changes to `fad-checker` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Custom registries for npm, PyPI, Ruby and Go** (previously Maven-only). Point
  fad-checker at private Verdaccio/Artifactory/GitHub Packages (npm), devpi (PyPI),
  Gemfury/Geminabox (Ruby) or a private GOPROXY/Athens (Go). They are tried in
  declared order, the public registry last; auth via `--auth user:pass` (→ Basic)
  or `--token TOK` (→ Bearer), inline `https://user:pass@host/` also accepted.
  CRUD: `--add-repo <eco> <name> <url>`, `--remove-repo <eco> <name>`,
  `--list-repos` (grouped by ecosystem); one-off repeatable `--repo <eco>=<url>`.
  New `lib/registries.js`; per-codec fetchers honour `opts.registries`.
- **Layered configuration.** Defaults can come from a JSON config file
  (`--config <file.json>`, else auto-discovered `./.fad-env.json`) and from the
  `FAD_CHECKER_ENV` environment variable (a string of CLI flags). Precedence:
  **CLI flag > config file > `FAD_CHECKER_ENV` > `~/.fad-checker/config.json` >
  defaults**; `registries` are unioned across every layer. New `lib/options-env.js`.
- **`--source` alias** for `-s`/`--src` (and the JSON config key `"source"`/`"src"`).
- **Vendored-JS inventory (report chapter 1D + JSON `vendoredJs`).** retire.js now
  runs with `--verbose`, so fad lists **every** identified standalone JS library
  committed into the tree (jQuery, Bootstrap, PDF.js, …) — **vulnerable or not** —
  as a cyber-hygiene inventory of unmanaged third-party code (the JS twin of the
  native-binary chapter 1C). Each entry: component, version, file, detection
  method, and vulnerability status. Vulnerable libs remain detailed in chapter 2.
  On by default; `--no-vendored-js-inventory` keeps only the vulnerable findings.
- **`--exclude-path <glob...>`** — ignore sub-paths during the directory walk,
  gitignore-style (matched relative to `--src`, prunes the dir + its subtree),
  across every ecosystem. Repeatable; also `excludePath: [...]` in `.fad-env.json`,
  unioned across config layers. **`--no-default-excludes`** walks the normally
  pruned dirs (`node_modules`, `vendor`, `target`, `.git`, …). New `lib/path-filter.js`.
- **Ignored-directories appendix (report chapter 11 + JSON `excludedDirs`).** The
  HTML/`.doc` report now ends with an appendix listing the ACTUAL directories the
  scan did not walk — resolved by re-walking `--src` once under the same prune
  policy the codecs use (the default-exclude set at any depth + your
  `--exclude-path` rules), each path shown relative to the scan root and tagged
  with the rule that pruned it (`default` vs `--exclude-path`). Surfaced in the
  findings JSON as `excludedDirs[]` + `summary.excludedDirs`. New
  `collectExcludedDirs()` in `lib/path-filter.js`.

### Changed
- **BREAKING:** the persisted-registry store moved from the Maven-only
  `maven_repos` config key + 2-arg `--add-repo <name> <url>` to a per-ecosystem
  `registries` map + `--add-repo <ecosystem> <name> <url>`. `--repo` now requires
  the `<ecosystem>=<url>` form (a bare URL is rejected). Re-add any private Maven
  repos with `--add-repo maven <name> <url>`.

### Fixed
- **retire.js now skips the same dirs as the rest of the scan.** The vendored-JS
  scan walks the tree itself and was handed a bare `--ignore node_modules,…` list,
  which retire `path.resolve()`s against its **own working directory** — so a
  `node_modules` (or `target`/`dist`/…) nested anywhere under `--src` was scanned
  whenever fad-checker ran from a different directory than the source tree. retire
  is now driven by a generated `--ignorefile` anchored to `--src` that prunes the
  default SKIP dirs **at any depth** and honors `--exclude-path` /
  `--no-default-excludes`, matching `lib/path-filter.js`.
- **Offline NVD enrichment (incl. CWEs) no longer silently dropped.** The NVD cache
  enforces a 7-day TTL and a schema version; offline, a TTL-expired or older-schema
  entry was treated as a miss — and since an air-gapped box can't re-fetch, the CVE
  lost **all** its NVD enrichment (CWE list, CVSS vector, references, CPE configs).
  That was the "offline scan was missing some CWE titles that the online scan had".
  Offline now reads the warmed cache regardless of age/schema (a missing field just
  stays missing — strictly better than dropping everything); online still enforces
  TTL + schema so it re-fetches and upgrades. CWE IDs were already persisted in the
  cache body (`_schema:2`) and travel in `--export-cache`; CWE *titles* come from the
  bundled `data/cwe-names.json` (identical online/offline).

## [2.1.0]

### Added
- **Embedded-binary scanning (chapter 1B).** The Maven codec now discovers Maven
  coordinates inside committed `.jar`/`.war`/`.ear` archives — vendored libs,
  Spring-Boot fat-jars, shaded uber-jars — by unzipping them **in memory** (via
  `fflate`, recursing into nested jars without touching disk, so there is no
  zip-slip risk). Each artifact's coordinate is read from
  `META-INF/maven/.../pom.properties` → `MANIFEST.MF` → file name; unidentifiable
  archives are flagged in chapter 0 rather than scanned blindly. Findings carry
  `provenance:"embedded"`, report in a dedicated **Embedded binaries** chapter
  (grouped by containing archive), feed the `--fail-on` gate, and are labelled in
  the SBOM (`fad:provenance`/`fad:location` + unique `bom-ref`), SARIF
  (`provenance` + nested-jar location) and JSON exports. Auto when archives are
  present; `--no-jars` disables it.

### Changed
- **Unified output flags.** Every output now has its own `--report-<type>` flag
  taking an OPTIONAL path (omit it → a default name under `--report-output`):
  `--report-html`, `--report-doc`, `--report-sbom`, `--report-csaf`,
  `--report-json`, `--report-sarif`. With no `--report-*` flag, HTML + `.doc` are
  written as before; selecting any flag writes exactly that set.
  **BREAKING:** the old `--export-sbom`/`--export-csaf`/`--export-json`/`--export-sarif`
  flags are removed — use `--report-sbom`/`-csaf`/`-json`/`-sarif`. (The unrelated
  `--export-cache` / `--export-anonymized` flags are unchanged.)
- **`--no-report` now writes NO output files at all** (gate-only / CI mode) — the
  scan, terminal summary and `--fail-on` gate still run. Previously it
  short-circuited the whole flow, so `--no-report --fail-on …` silently passed.

### Fixed
- **Catastrophic data loss**: `--target` being a *parent* of `--src` passed the
  guardrail and `rimraf`'d the source tree. The guard now rejects overlap in both
  directions.
- **Missed npm/yarn/pnpm CVEs**: only the highest version of a duplicated package
  was scanned; nested-`node_modules` lower versions are now accumulated.
- **CPE false negatives**: AND-configurations with a `vulnerable:false` platform
  node wrongly dropped real findings.
- **VEX over-suppression**: an unmappable product id suppressed a CVE for every
  dependency.
- **CSAF/SBOM/SARIF scoring**: OSV CVSS *vectors* were mis-read as the score
  (`3.1`), the NVD CVSS version label was malformed (`CVSS:V31`), and an NVD record
  without metrics clobbered an OSV-derived vector — so CSAF emitted no scores and
  SBOM showed `method:other`. CVSS v3 base scores are now computed from the vector,
  labels normalised, and exports stay schema-valid (no empty `known_affected`, no
  `UNKNOWN` baseSeverity, no v4 vector under a v3 score).
- **CI / parsing**: an invalid `--fail-on <level>` (typo) now hard-fails instead of
  silently disabling the gate; Maven version ordering for dot-aligned qualifiers
  (`5.0.0.RC1` vs `5.0.0.5`) corrected; classic poetry.lock `category="dev"` and
  `go.sum` highest-version selection fixed.

## [2.0.1]

### Fixed
- **EOL detection for PyPI / NuGet** used dead endoflife.date product slugs
  (`fastapi`, `aspnetcore`, `efcore` → HTTP 404), so no .NET / FastAPI EOL was ever
  flagged. NuGet ASP.NET Core / EF Core packages now map to the `dotnet` product
  (their versions track .NET cycles); `fastapi` removed (no endoflife.date source).

### Added
- Detailed capability test suite (`test/codec-capabilities.test.js`): end-to-end EOL
  per ecosystem (seeded cycles), registry findings (abandoned / yanked / inactive /
  deprecation) + outdated gating, cycle-matching logic, fix recipes, and report
  rendering of EOL/Obsolete/Outdated. Plus a guard asserting every eol-mapping product
  slug is a known-valid endoflife.date product.

## [2.0.0]

Major release: **codec architecture** + three new ecosystems.

### Added
- **Codec abstraction** (`lib/codecs/`): every ecosystem now lives behind a single
  interface (`detect` / `collect` / `coordKey` / `formatCoord` / `osvPackageName` /
  `checkRegistry` / `resolveEolProduct` / `recipe` / `nativeScanners`) discovered through
  a registry. OSV, NVD, CPE refinement and endoflife.date are shared, ecosystem-agnostic
  services. Adding an ecosystem is adding a codec — no orchestrator changes.
- **Composer (PHP)** codec — `composer.lock` / `composer.json`, Packagist `abandoned`,
  EOL (Laravel/Symfony/Drupal), `composer require` fix recipe.
- **PyPI (Python)** codec — `poetry.lock` / `Pipfile.lock` / `uv.lock` / `pdm.lock` /
  `requirements.txt`, PEP 503 name normalisation, PyPI `yanked` + "Inactive" classifier,
  EOL (Django/NumPy/FastAPI), `pip install` fix recipe.
- **NuGet (C#/.NET)** codec — `packages.lock.json` / `*.csproj` (+ Central Package
  Management via `Directory.Packages.props`) / `packages.config`, NuGet `deprecation`,
  EOL (.NET/ASP.NET Core/EF Core), `dotnet add package` fix recipe.
- `--ecosystem` is now a **list** (`auto` | `all` | comma list) and per-codec opt-outs
  `--no-maven` / `--no-npm` / `--no-yarn` / `--no-nuget` / `--no-composer` / `--no-pypi`.
- Generalized `depRecord` (`ecosystem` / `namespace` / `name` / `coordKey`).
- Dependency: `smol-toml` (TOML lockfile parsing).

### Changed
- **npm no-lockfile behaviour (contract change)**: a `package.json` without a sibling
  `package-lock.json` / `yarn.lock` is now parsed **best-effort** (pinned exact versions
  scanned, ranges skipped, `no-lockfile` warning) instead of being skipped entirely. The
  same lockfile-first, best-effort fallback applies to Composer / PyPI / NuGet.
- The orchestrator now loops over detected codecs; report sections, labels, coordinate
  formatting and fix recipes are driven by the codec registry.
- Maven CVE-index (cvelistV5) and retire.js are now `nativeScanners` owned by their codec.
- `--no-js` is retained as an alias for `--no-npm` + `--no-yarn`.

### Notes
- Maven map keys stay bare `g:a` (collision-free against the prefixed `npm:` / `nuget:` /
  `composer:` / `pypi:` keyspaces) to keep transitive resolution and existing behaviour intact.
- Verified non-regression against a real Maven + npm project: identical findings modulo
  upstream advisory drift.

## [1.x]
- Maven + npm/Yarn + vendored-JS scanning; CVEProject + OSV + NVD + CPE; EOL / obsolete /
  outdated; HTML + Word report; private-dep cleanup for Snyk.
