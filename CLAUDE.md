# CLAUDE.md

Code-level orientation for contributors and Claude Code sessions on this repo.

## What this is

`fad-checker` — **Fucking Autonomous Dependency Checker**. Node.js CLI (`fad-checker`, or short alias `fad`) that:

1. Walks a multi-module Maven tree, removes private/excluded dependencies (regex on groupId), writes a parallel directory of "cleaned" POMs that can be fed to Snyk.
2. Walks every JS package (`package.json` + `package-lock.json` v1/v2/v3, `yarn.lock` v1 **or Berry/v2+**, or `pnpm-lock.yaml` v5/v6/v9), every PHP package (`composer.lock`, or `composer.json` best-effort), and every Python project (`poetry.lock`/`Pipfile.lock`/`uv.lock`/`pdm.lock`, or `pyproject.toml`/`requirements.txt` best-effort), and every .NET project (`packages.lock.json`, or `*.csproj`/`*.fsproj`/`*.vbproj`+`Directory.Packages.props`/`packages.config` best-effort), every Go module (`go.mod`/`go.sum`) and every Ruby app (`Gemfile.lock`) in the same source tree. Each ecosystem is a **codec** (`lib/codecs/`): maven, npm, yarn, composer, pypi, nuget, go, ruby, binary. Adding one is adding a codec. The Maven codec additionally scans **embedded binaries** — committed `.jar`/`.war`/`.ear` archives (vendored libs, Spring-Boot fat-jars, shaded uber-jars) are unzipped in-memory (via `fflate`, recursing into nested jars without touching disk) and their Maven coordinates read from `META-INF/maven/.../pom.properties` → `MANIFEST.MF` → file name. These get `provenance: "embedded"` and are listed in their own **report chapter 1B** — a full inventory of *every* embedded coordinate (vulnerable or not, the JAR twin of chapters 1C/1D), with CVE status cross-referenced per coord and the full CVE detail for vulnerable ones (`--no-jars` to disable; built by `lib/embedded.js#buildEmbeddedInventory`, shared by the HTML report + JSON export). The **binary codec** finds committed **native binaries** — `.dll`/`.exe`/`.so`/`.dylib` that no package manager governs — selected by extension **and** magic-byte confirmation (PE/ELF/Mach-O; images/fonts/assets are rejected even with a spoofed extension), hashed (SHA-1 + SHA-256, `provenance: "binary"`), then **identified by checksum** online (deps.dev query-by-hash → exact package coordinate; CIRCL hashlookup → known OS/distro/CDN/NSRL file + free `KnownMalicious` flag) to answer two questions: is it **unmodified/known** (integrity), and does it **exist in a registry and therefore belong as a declared dependency** (governance). Surfaced in report **chapter 1C (Unmanaged / vendored binaries)** (`--no-binaries` to disable). No malware/antivirus lane and no binary-metadata parsing — identity is hash-lookup, integrity is hash-comparison.
3. Scans the union against:
   - the CVEProject `cvelistV5` Maven-relevant index (built locally),
   - OSV.dev (multi-ecosystem),
   - NIST NVD (enrichment: CVSS, CPE configurations, references),
   - EPSS (FIRST.org exploit-prediction percentile) + CISA KEV (known-exploited catalogue) — prioritisation signals,
   - retire.js (vendored JS signatures),
   - optionally Snyk (`--snyk`).
4. Cross-checks every match's NVD CPE configurations against the dep version (`lib/cpe.js`) to filter false positives, then computes a **composite priority** per match (`lib/priority.js`): KEV (exploited) > EPSS-weighted CVSS, exposed as a band + score and used to sort the report.
5. Reports EOL frameworks (endoflife.date — Maven & npm), obsolete libs (curated Maven + npm-registry per-version `deprecated` field — authoritative, skips nothing), outdated libs (Maven Central + npm registry `dist-tags.latest`), and **licenses** (`lib/license-policy.js`, **opt-in — off by default, enable with `--licenses`**): each dep's license is normalised to SPDX and classified (permissive / weak / strong / network copyleft / proprietary / unknown), with copyleft & unknown flagged. **WebJars** (`org.webjars*`) are reduced to their npm coordinate by `webjarToNpm()` and run through the npm EOL/deprecation/outdated paths — so e.g. `org.webjars:angularjs:1.8.3` is flagged EOL. Each EOL finding is **traceable to its origin**: the report's EOL chapter shows a **Source** column (`endoflife.date/<slug>` + the `data/eol-mapping.json` rule that matched — `via`/`viaKey`, one of group-artifact/group-prefix/npm-name/npm-scope/webjar/composer-name/pypi-name/nuget-name), and for a **transitive** ("dep of a dep") EOL finding the Dependency column renders the resolver's `via` chain (`root → … → dep`) instead of a defining manifest.
6. Produces a self-contained HTML report + Word-compatible `.doc`, organised by ecosystem and by defining manifest, with a Priority column, a Licenses chapter, per-tool fix recipes and an executive summary. Also exports machine-readable **CycloneDX 1.6 SBOM** (vulnerabilities inline, `--report-sbom`), **CSAF 2.0 VEX** (`--report-csaf`), a flat **findings JSON** (`--report-json`) and a **SARIF 2.1.0** log for GitHub/GitLab code scanning (`--report-sarif`).
7. CI-friendly: `--fail-on <low|medium|high|critical|kev>` sets a non-zero exit code (KEV = fail only on known-exploited). Triage with `--ignore <file>` (CVE/coord/glob rules) and `--vex <file>` (ingest a CSAF VEX) suppresses accepted-risk / false-positive findings from the report + gate while keeping them flagged in the exports.

No build tool (`mvn`, `npm install`, `yarn`) is required on PATH — `pom.xml` / `package-lock.json` / `yarn.lock` are parsed directly.

## Running

```bash
npm install
npm test                  # 427 unit tests via node --test

# basic cleanup workflow
node fad-checker.js -s ./proj                                        # read-only, full report
node fad-checker.js -s ./proj -t ../pom-clean -e "^client\\."        # write cleaned tree
node fad-checker.js -s ./proj -t ../pom-clean -e "^client\\." --snyk # also drive snyk

# read the full usage doc
cat docs/USAGE.md
```

Binary builds (requires `bun`):

```bash
npm run build:linux   # → dist/fad-checker-linux
npm run build:win     # → dist/fad-checker.exe
npm run build         # both
```

Guardrails enforced at startup:
- `--target` is required only when you want a cleaned POM tree. Without it the run is read-only.
- `--target` may not equal or be a subdirectory of `--src`.
- `--target` is `rimraf`'d before being rewritten — never point at anything precious.

## Architecture (one-liner per file)

```
fad-checker.js                 Thin CLI: commander parsing, orchestration only (loops over active codecs).
lib/codecs/index.js          Codec registry: getCodec / allCodecs / detectCodecs.
lib/codecs/codec.interface.js  Codec contract + assertCodecShape() validator.
lib/codecs/maven.codec.js    Maven codec (wraps core.js + transitive.js + CVE-index scanner).
lib/codecs/npm.codec.js      npm codec (wraps lib/codecs/npm/* + retire.js scanner). yarn.codec.js shares it.
lib/codecs/select.js         resolveActiveCodecs(): --ecosystem list + --no-<id> → active codec ids.
lib/codecs/recipes.js        Per-ecosystem fix-recipe specs (pin snippet + direct-update wording).
lib/codecs/composer.codec.js   Composer (PHP) codec.
lib/codecs/composer/parse.js        composer.lock + composer.json parsers.
lib/codecs/composer/registry.js     Packagist query → latest stable + `abandoned` flag.
lib/codecs/pypi.codec.js     PyPI (Python) codec.
lib/codecs/pypi/parse.js          poetry.lock/Pipfile.lock/uv.lock/pdm.lock (smol-toml) + pyproject.toml (PEP 621/poetry) + requirements.txt (recursive -r/-c) parsers (PEP 503).
lib/codecs/pypi/registry.js       PyPI JSON query → latest + yanked + inactive classifier.
lib/codecs/nuget.codec.js    NuGet (C#/.NET) codec.
lib/codecs/nuget/parse.js           packages.lock.json + *.csproj/*.fsproj/*.vbproj (+CPM Directory.Packages.props) + packages.config parsers.
lib/codecs/nuget/registry.js        NuGet registration query → latest stable + per-version deprecation.
lib/codecs/go.codec.js       Go codec (go.mod/go.sum). go/parse.js (require+indirect, go.sum fallback) + go/registry.js (proxy.golang.org @latest).
lib/codecs/maven/jar-scan.js   Embedded-binary scanner: walks .jar/.war/.ear, reads each archive in-memory (fflate, recursive), extracts Maven coord (pom.properties→MANIFEST→filename) → provenance:"embedded" depRecords keyed embedded:<path>.
lib/codecs/ruby.codec.js     Ruby codec (Gemfile.lock). ruby/parse.js (GEM specs) + ruby/registry.js (rubygems gems/<g>.json → latest + licenses).
lib/codecs/binary.codec.js   Binary codec (committed native libs, no manifest). binary/sniff.js (extension allowlist + magic-byte confirm) + binary/scan.js (walk + SHA-1/SHA-256 hash) → provenance:"binary" depRecords keyed binary:<path>.
lib/hash-id.js               Identity-by-checksum: deps.dev query-by-hash (→ exact coord) then CIRCL hashlookup (→ known-good + KnownMalicious). Cached (hash-id-cache.json, 24h), offline-aware.
lib/embedded.js              buildEmbeddedInventory(): full inventory of provenance:"embedded" coords (vuln or not) for report chapter 1B + JSON. Pure. CVE count/severity cross-referenced by coordKey.
lib/unmanaged.js             enrichUnmanaged() sets identity+integrity (pristine/known-good/unknown) on hash-bearing records; buildInventory() derives per-file signals (nameMismatch / shouldBeManaged / noOnlineInfo / knownMalicious) for report chapter 1C + JSON.
lib/dep-record.js            makeDepRecord(): generalized depRecord ({ ecosystem, namespace, name, coordKey, … }).
lib/core.js                  POM parsing, parent resolution, all-profile merge, rewrite.
lib/maven-version.js         Maven version parsing + range comparison (no external deps).
lib/cve-download.js          Bulk download of CVEProject/cvelistV5 + Maven-relevant index build.
lib/cve-match.js             Resolved-dep collection + 3-tier CVE matching with dedup.
lib/cve-report.js            Self-contained HTML and Word-compatible (.doc) report rendering.
lib/cpe.js                   CPE 2.3 parsing + NVD configurations evaluator (post-match refinement).
lib/epss.js                  EPSS (FIRST.org) percentile/score enrichment of matched CVEs (24h cache).
lib/kev.js                   CISA KEV catalogue membership enrichment (24h cache).
lib/priority.js              Composite priority (KEV > EPSS-weighted CVSS) → band + score + sortKey. Pure.
lib/license-policy.js        SPDX normalization + copyleft/proprietary classification (data/license-policy.json).
lib/maven-license.js         Network-free Maven license detection from cached POMs (transitive.js cache).
lib/purl.js                  Package-URL (purl) builder per ecosystem. Pure. Shared by the exporters.
lib/sbom-export.js           CycloneDX 1.6 SBOM (components + vulnerabilities inline / VDR). Pure builder + writer.
lib/csaf-export.js           CSAF 2.0 VEX (csaf_vex) document. Pure builder + writer.
lib/sarif-export.js          SARIF 2.1.0 log (rule per CVE, security-severity, manifest locations). Pure builder + writer.
lib/json-export.js           Flat findings JSON (all chapters + summary, diff-friendly). Pure builder + writer.
lib/gate.js                  evaluateGate(matches, level): CI exit-code decision (none|…|critical|kev). Pure.
lib/suppress.js              Triage: parse --ignore rules + --vex (CSAF) → suppress matches. Pure.
lib/outdated.js              EOL (endoflife.date), obsolete (curated), outdated (Maven Central).
lib/transitive.js            Maven Central POM walker (transitive resolution).
lib/osv.js                   OSV.dev batched query + per-vuln detail fetch.
lib/nvd.js                   NIST NVD enrichment (CVSS, references, CPE configurations).
lib/snyk.js                  `snyk test --all-projects --json` runner + merge.
lib/retire.js                retire.js (vendored-JS scanner) wrapper + cache + normaliser. Runs with --verbose; extractVendoredInventory() lists ALL identified libs (vuln or not) → report chapter 1D; scanWithRetireFull() returns {matches, inventory, error}. A real scan FAILURE (retire crashed / empty-unparseable output) sets `error` (via diag) → surfaced as a chapter-0 `retire-failed` warning instead of a silent empty 1D. Cache body carries `_schema:2`; an entry without it (pre-verbose build) is a cache MISS so the inventory isn't silently emptied offline. **Launcher** (`findRetireLauncher`/`chooseRetireLauncher`): node dev runs `node_modules/.bin/retire`; the **bun-compiled single binary** has no node_modules and an air-gapped box has no `retire` on PATH, so it **re-execs ITSELF** with `__FAD_RETIRE__=1` — `fad-checker.js`'s top guard then hands off to the statically-bundled `retire/lib/cli.js` (self-runs on require). So vendored-JS scanning works fully offline from the one binary; the only external input is the phase-2-warmed signature DB passed via `--jsrepo`.
lib/scan-completeness.js     Warnings for deps fad-checker couldn't fully resolve.
lib/codecs/npm/parse.js             package.json, package-lock.json (v1/2/3), yarn.lock v1 + Berry, pnpm-lock.yaml (v5/6/9) parsers.
lib/codecs/npm/collect.js           Merge across JS manifests → unified resolvedDeps Map.
lib/codecs/npm/registry.js          npm registry packument query → per-version deprecation + dist-tags.latest (npm EOL feeds via lib/outdated.js).
lib/cache-archive.js         tar.gz / zip export & import of ~/.fad-checker/ (incl. retire findings + signatures).
lib/deps-descriptor.js       Anonymized dep descriptor serialize/deserialize (PASSI offline→online round-trip).
lib/config.js                Persistent user config in ~/.fad-checker/config.json (mode 0600): NVD key + `registries` map.
lib/registries.js            Per-ecosystem registry list assembly (union across layers, dedup, public base last) + Basic/Bearer auth + fan-out. Generalizes maven-repo.js to npm/pypi/ruby/go.
lib/path-filter.js           Shared dir-walk pruning: makeDirFilter({srcRoot,defaultSkip,excludePath,useDefaults}) → skipDir(absChild,name). Default per-walker SKIP sets + gitignore-style --exclude-path globs (minimatch, relative to srcRoot). Consulted by every walker.
lib/maven-repo.js            Maven HTTP fan-out (POM/metadata/HEAD). buildRepoList reads registries.maven, appends Central last.
lib/options-env.js           Layered option resolution: --config/.fad-env.json (JSON) + FAD_CHECKER_ENV (CLI-flag string) merged onto commander opts via getOptionValueSource.
data/                        known-obsolete.json, eol-mapping.json, cpe-coord-map.json, known-public-namespaces.json, license-policy.json
completions/                 fad-checker.bash, fad-checker.zsh
test/                        node:test suite + fixtures (simple, complex-enterprise, monorepo-mixed, …).
```

For the deep dive — pipeline stages, the resolved-deps Map shape, report structure — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Important conventions

- **`coord()` always trims**: real-world POMs occasionally contain whitespace around `<artifactId>`. Every coord-derived lookup goes through `coord()` in `lib/core.js`.
- **`byId` keys are never polluted with `undefined`**: only indexed when both `groupId` and `artifactId` are present. Enforced by test.
- **All profiles are merged, never prompted for**: every profile's deps are unioned so Snyk sees every dep any profile could pull in. `activeByDefault` wins only for property value conflicts.
- **No `process.exit(1)` mid-pipeline**: a parse/rewrite failure for one POM logs and continues so the summary still prints.
- **HTML report is self-contained**: inline CSS, no external assets. The `.doc` variant is the same HTML with Office XML namespace meta tags — Word opens it natively.
- **Codec abstraction**: every ecosystem lives behind a codec (`lib/codecs/*`) implementing one interface (`detect`/`collect`/`coordKey`/`formatCoord`/`osvPackageName`/`checkRegistry`/`resolveEolProduct`/`recipe`/`nativeScanners`). The orchestrator loops over the codecs `detectCodecs()` returns. OSV/NVD/CPE and the endoflife.date fetch are **shared, ecosystem-agnostic** services that ask the codec for a package/product name. CVE-index (maven) and retire.js (npm) are `nativeScanners` owned by their codec. Adding an ecosystem = adding a codec, no orchestrator edits.
- **Map keys are ecosystem-namespaced** (`dep.coordKey`): Maven uses a **bare** `g:a` (kept prefix-free so `transitive.js` internals and existing tests are untouched); npm uses `npm:name`; new ecosystems use `nuget:`/`composer:vendor/pkg`/`pypi:`. Bare `g:a` is collision-free against those prefixes. Built by `makeDepRecord()`; `groupId`/`artifactId`/`pomPaths` are kept as real duplicated alias fields (not getters — depRecords are spread in hot paths).
- **Every distinct version is scanned, not just the highest**: when profiles/modules pin the same `g:a` to different versions, the resolved-dep entry keeps `version` = highest (representative for display/EOL/outdated) but `versions` = all distinct concrete versions. CVE matching (`matchOne`) and OSV (`queryOsvForDeps`) iterate `versions` so a vuln affecting only a lower-versioned profile variant isn't missed. Match dedup keys are `g:a:version|cve.id` (version included) to preserve per-version findings.
- **npm no-lockfile = best-effort (not skipped)**: `package.json` without a sibling `package-lock.json`/`yarn.lock` is parsed best-effort — pinned exact versions (`"1.2.3"`) are scanned, ranges (`"^1.0.0"`) are skipped, and a `no-lockfile` warning (chapter 0) flags the partial coverage. (Earlier versions skipped such manifests entirely.)
- **`--ecosystem` is a list**: `auto` (default = `detectCodecs()`) | `all` | comma list `maven,npm,nuget,composer,pypi` (legacy `both`/`maven`/`npm` still parse). Per-codec opt-out via `--no-maven`/`--no-npm`/`--no-yarn`/`--no-nuget`/`--no-composer`/`--no-pypi`/`--no-go`/`--no-ruby`; `--no-js` is an alias for `--no-npm`+`--no-yarn`. `--no-jars` disables the Maven codec's embedded-binary scan; `--no-binaries` disables the native-binary (binary codec) scan. The binary codec is a cross-cutting catch-all: in `auto` mode it's always a candidate (committed native libs can live in any project, and `detectCodecs`' manifest-glob matcher misses versioned sonames like `libz.so.1`).
- **Unmanaged / native-binary provenance**: `provenance: "binary"` records (committed `.dll`/`.exe`/`.so`/`.dylib`, keyed `binary:<path>`) carry `hashes: {sha1, sha256}` + `declaredName`. They have no resolved coordinate until `lib/hash-id.js` identifies them by checksum (deps.dev → CIRCL), so the Maven CVE-index matcher and the transitive resolver skip `provenance === "binary"`; OSV skips them too (no version). `lib/unmanaged.js#enrichUnmanaged` then sets `identity` + `integrity` (`pristine` = deps.dev exact published-artifact match; `known-good` = CIRCL; `unknown` = neither), and `buildInventory` derives `shouldBeManaged` (identity resolves to a real registry package), `nameMismatch` (filename ≠ checksum identity), `noOnlineInfo`, and `knownMalicious` (free CIRCL signal — there is **no** dedicated malware/AV lane). Surfaced in report **chapter 1C** and the JSON export's `unmanaged` array + `summary.unmanaged`. Every source is cached + `--offline`-aware (reads warmed cache, never blocks).
- **Embedded-binary provenance**: every depRecord carries `provenance` (`"manifest"` default, `"embedded"` for jar-discovered coords, `"binary"` for committed native libs). Embedded records are keyed `embedded:<manifestPath>` (NOT `g:a`) so they never merge with a declared dep of the same coordinate — that keeps the dedicated **chapter 1B (Embedded binaries)** complete and lets a coord that's both declared and embedded show in both places (intended). Match dedup (`cve-match.js`, `mergeBySource`) keys on `dep.coordKey` (identical to `g:a` for declared Maven, distinct for embedded). Embedded coords are excluded from Maven Central transitive resolution (a fat-jar ships its own deps, found by recursion) and counted/gated separately. Exports carry it: SBOM component `fad:provenance`/`fad:location` properties + a unique `bom-ref`, SARIF result `provenance` + the nested-jar `location`, JSON `provenance`.
- **Unified output flags** (`fad-checker.js` → `runReportFlow`): one `--report-<type>` per output (`html`/`doc`/`sbom`/`csaf`/`json`/`sarif`), each with an OPTIONAL path arg (`true` = default name under `--report-output`; string = explicit path; `undefined` = not requested). If NO `--report-*` is given, the default set is HTML + `.doc`; selecting any flag writes exactly that set. `--no-report` writes NOTHING (gate-only) — the scan, terminal summary and `--fail-on` gate still run. The old `--export-sbom/csaf/json/sarif` flags were **removed** (renamed to `--report-*`); `--export-cache`/`--export-anonymized` are unrelated and unchanged. `writeReports({htmlPath, docPath})` writes only the non-null paths (legacy `outputDir` still writes both).
- **CI gating & triage**: `--fail-on <low|medium|high|critical|kev>` (`lib/gate.js`) sets `process.exitCode = 1` after all reports/exports are written, gating on `prodActive` (non-dev, non-cpeFiltered, non-suppressed); `kev` fails only on a CISA-known-exploited finding. `--ignore <file>` (CVE id / coord-glob / `# reason` per line) and `--vex <file>` (CSAF `known_not_affected`/`fixed`, products mapped to coords by purl) mark matches `suppressed` (`lib/suppress.js`) — dropped from the report chapters + gate, retained & flagged in the JSON/SBOM/CSAF/SARIF exports, noted in chapter 0.
- **SARIF / JSON exports** (`--report-sarif` / `--report-json`): machine-readable findings. SARIF 2.1.0 carries one rule per CVE with `security-severity` (GitHub Code Scanning) + manifest `locations`; the JSON is fad's own flat all-chapters format for diffing between audits.
- **Source identifiers**: every match carries `source: "fad" | "osv" | "nvd" | "snyk" | "retire"` (or a `+`-joined combination).
- **Anonymized descriptor (PASSI offline→online)**: `--export-anonymized <f>` (offline, needs `-s`) serializes the collected `resolved` Map to a flat `fad-deps/1` JSON keeping only public coordinates (`ecosystem`/`ecosystemType`/`namespace`/`name`/`version`/`versions`/`scope`/`isDev`) — **strips** paths, registry URLs, integrity, parent chains — then exits. `--import-anonymized <f>` (online, **no `-s`**) rebuilds the Map (empty `manifestPaths`, recomputed `coordKey`) via `lib/deps-descriptor.js` and runs `runReportFlow` to **warm the coordinate-keyed caches**. Round-trip = export (offline) → import + `--export-cache` (online) → `--import-cache` + normal `--offline -s ./proj` (offline) for the full path-bearing report. Private/public sorting is the auditor's job via `-e` (offline can't check Maven Central). `--import-anonymized` keeps the report path-free (`projectInfo.src` = withheld).

## Testing

```bash
node --test test/*.test.js            # full suite (427 tests)
node --test test/core.test.js         # one file
```

Test fixtures live in `test/fixtures/`:
- `simple/` — 3 POMs with parent inheritance + property substitution
- `complex-enterprise/` — Spring Boot parent (external), local BOM via `scope=import`, three profiles
- `private-lib-detection/` — mixed public/private groupIds, external private parent
- `monorepo-mixed/` — Maven + npm (package-lock v3) + yarn.lock v1 + a no-lockfile package.json
- `cve-samples/` — small CVE / NVD JSON files for the matchers

## Gotchas / edge cases worth knowing

- CVE bundle from CVEProject is ~500 MB unpacked. Shells out to `curl + unzip` (fallback to `fetch()` + `unzip` / `Expand-Archive`). Extracted JSON deleted after index build. Ships as `cves.zip.zip` (nested zip) — `extractZip()` recurses up to 3 levels.
- `endoflife.date` API responses cached 7 days; Maven Central version lookups cached 24 hours. Cache lives in `~/.fad-checker/`.
- **Persistent config**: `~/.fad-checker/config.json` (mode 0600). Set NVD key via `fad-checker --set-nvd-key <KEY>` (free, instant from <https://nvd.nist.gov/developers/request-an-api-key> — bumps rate limit from 5/30s to 50/30s).
- **Custom registries (per ecosystem)**: stored under the config key `registries` ({ `<eco>`: [{name,url,auth?,token?}] }) for `maven|npm|pypi|ruby|go`. **No `maven_repos` back-compat** — that key is gone. CRUD via `--add-repo <eco> <name> <url> [--auth user:pass] [--token TOK]`, `--remove-repo <eco> <name>`, `--list-repos` (grouped); one-off `--repo <eco>=<url>` (repeatable). Each codec's `fetch*` (npm/pypi/ruby/go `registry.js`) takes `opts.registries`, tries them first (per-registry auth), public base appended **last** by `registries.withPublic` — byte-identical to the old single-base behaviour when empty. NuGet/Composer private feeds not yet supported. PyPI/Ruby custom bases must speak the same JSON API (not a bare PEP 503 simple index).
- **Walk pruning (`lib/path-filter.js`)**: every directory walker (Maven `core.js`, `detectCodecs`, npm `parse.js`, composer/go/nuget/pypi/ruby codecs, `maven/jar-scan.js`, `binary/scan.js`) takes a `skipDir(absChild, name)` predicate built by `makeDirFilter`. It combines the walker's own basename `SKIP` set (the **default excludes**, bypassable with `--no-default-excludes` / `defaultExcludes:false`) with user `--exclude-path` globs (gitignore-style via `minimatch`, matched against the path **relative to `srcRoot`**; a glob prunes the dir AND its subtree). `excludePath` is **unioned** across config layers (CLI + file + env + global), like registries. `parallel-walk.js#walkDirs` now passes the child's absolute path to `skipDir`. Each `codec.collect(dir, opts)` receives `opts.excludePath` + `opts.defaultExcludes` and builds the filter (`srcRoot = opts.srcRoot || dir`).
- **Layered options (`lib/options-env.js`)**: precedence **CLI flag > config file (`--config <file.json>` / `./.fad-env.json`, JSON keyed by camelCase option names) > `FAD_CHECKER_ENV` (a CLI-flag string, parsed via a throwaway commander clone) > `~/.fad-checker/config.json` > commander defaults**. A file/env value fills an option only when `program.getOptionValueSource(name)` is `default`/undefined (user didn't pass it). `registries` are **unioned** across layers, never overridden. Source flag has aliases: `-s`/`--src`/`--source` + JSON `source`/`src` → internal `src` (no code-wide rename). Wired in `fad-checker.js` right after `program.parse()`; `regMap`/`registriesFor(eco)` threaded into `runReportFlow`.
- **`--offline` umbrella flag**: skips every network call (CVE/OSV/NVD/EPSS/KEV/Maven Central/endoflife/npm-registry/retire). Falls back to whatever is already cached. Per-source variants (`--cve-offline`, `--no-osv`, `--no-nvd`, `--no-epss`, `--no-kev`, `--no-retire`, `--no-transitive`) and per-codec toggles (`--no-maven`/`--no-npm`/`--no-yarn`/`--no-nuget`/`--no-composer`/`--no-pypi`, `--no-js`) still work independently. npm registry deprecation always runs when online; npm (and Maven) outdated is gated by `--no-all-libs`. **License detection is opt-in (`--licenses`, off by default)**; when enabled it piggybacks on the registry passes (no extra fetch) + Maven cached POMs. (Legacy `--no-licenses` is accepted as a no-op since licenses are already off by default.)
- **Machine-readable exports**: `--report-sbom [f]` writes a CycloneDX 1.6 SBOM with vulnerabilities inline (VDR); `--report-csaf [f]` writes a CSAF 2.0 VEX. Both use the full match set (prod+dev+embedded+cpeFiltered; cpeFiltered marked as a property/note rather than dropped). purls are built by `lib/purl.js`.
- `snyk` is not a hard dep — shells out via `execFile`. `snyk` exits 1 on findings; the JSON is still on stdout.
- The cleaned POM is the union of every profile's deps. Counts will be larger than the source POM. Intentional — don't "fix" that.
- Unresolved `${…}` Maven variables stay verbatim in the rewritten POM. `lib/cve-match.js` resolves them lazily via `resolveDepVersion()` when scanning. Deps that *still* can't be resolved (external BOM not in source tree) surface in chapter 0 as `unresolved-versions` warnings.
- **retire.js** doesn't like `--outputpath /dev/stdout`. We write to a temp file and read it back. Exit code 13 means "vulns found" — expected, not an error.
- **retire.js signatures live in `~/.fad-checker/retire-signatures/jsrepository-v5.json`** (not retire's default `/tmp/.retire-cache`, whose 1 h TTL would force a network refetch). We pass them via `--jsrepo <file>` so retire loads from disk — **no network, no TTL**. `warmRetireSignatures()` fetches them online; `--export-cache` bundles them so phase-3 offline JS scanning works. retire is **offline-only** in the PASSI flow (it needs the actual `.js` files, absent online) and its findings cache stays path-keyed (`md5(srcDir)`), which is fine since it only runs on the same offline machine/path. With no source dir (`--import-anonymized`), `runRetire` returns `null` (nothing to scan).

### Per-cache TTLs

| Cache | Location | TTL |
|---|---|---|
| CVEProject bulk index | `~/.fad-checker/cve-data/maven-cve-index.json` | 24 h |
| OSV per-dep stub list | `~/.fad-checker/osv-cache/<eco>__<g>__<a>__<v>.json` | 12 h |
| OSV vuln details | `~/.fad-checker/osv-cache/vuln_<id>.json` | 12 h |
| NVD CVE record | `~/.fad-checker/nvd-cache/<cveId>.json` | 7 d |
| EPSS scores | `~/.fad-checker/epss-cache.json` | 24 h |
| CISA KEV catalogue | `~/.fad-checker/kev-cache.json` | 24 h |
| endoflife.date cycles | `~/.fad-checker/eol-cache.json` | 7 d |
| Maven Central latest | `~/.fad-checker/version-cache.json` | 24 h |
| npm registry (deprecation + latest) | `~/.fad-checker/npm-registry-cache.json` | 24 h |
| Go module proxy (latest) | `~/.fad-checker/go-proxy-cache.json` | 24 h |
| RubyGems (latest + licenses) | `~/.fad-checker/rubygems-cache.json` | 24 h |
| Binary identity (deps.dev + CIRCL by hash) | `~/.fad-checker/hash-id-cache.json` | 24 h |
| Transitive POM | `~/.fad-checker/poms-cache/<g>__<a>__<v>.pom` | ∞ (immutable on Maven Central) |
| retire.js findings | `~/.fad-checker/retire-cache/<md5(src)>.json` | 24 h (carries `_schema:2` — a body written by a pre-`--verbose` build, i.e. without `_schema`, is treated as a **miss** so the vendored-JS inventory chapter 1D isn't silently emptied on an offline re-run) |
| retire.js signatures | `~/.fad-checker/retire-signatures/jsrepository-v5.json` | warmed online, reused offline via `--jsrepo` |
