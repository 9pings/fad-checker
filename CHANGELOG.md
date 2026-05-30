# Changelog

All notable changes to `fad-checker` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

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
