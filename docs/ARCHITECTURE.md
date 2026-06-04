# Architecture

This is the deep-dive for anyone modifying `fad-checker`'s internals or wondering why a particular finding shows up the way it does. For day-to-day usage, see [`USAGE.md`](USAGE.md).

## Module map

```
fad-checker.js                 Thin CLI: commander parsing + orchestration (loops over active codecs).
lib/codecs/                  Per-ecosystem codecs (maven, npm, yarn, composer, pypi, nuget, go, ruby, binary) + registry + select + recipes (see "Codecs" below).
lib/codecs/binary/                 Native-binary scanner: sniff.js (extension + magic-byte gate) + scan.js (walk + SHA-1/SHA-256). The binary codec finds committed .dll/.exe/.so/.dylib (provenance:"binary").
lib/hash-id.js               Identity-by-checksum: deps.dev (→ exact coordinate) then CIRCL hashlookup (→ known-good + KnownMalicious). Cached, offline-aware.
lib/unmanaged.js             enrichUnmanaged() (identity + integrity on hash-bearing records) + buildInventory() (per-file signals for report chapter 1C / JSON).
lib/codecs/composer/                composer.lock/composer.json parsers + Packagist registry (PHP codec internals).
lib/codecs/pypi/                  poetry/pipfile/uv/pdm/requirements parsers + PyPI registry (Python codec internals).
lib/codecs/nuget/                   packages.lock.json/csproj/packages.config parsers + NuGet registry (.NET codec internals).
lib/codecs/go/                    go.mod/go.sum parsers + Go module-proxy registry (Go codec internals).
lib/codecs/ruby/                  Gemfile.lock parser + RubyGems registry (Ruby codec internals).
lib/dep-record.js            makeDepRecord(): the generalized depRecord shared by all codecs.
lib/core.js                  POM parsing, parent resolution, all-profile merge, rewrite.
lib/maven-version.js         Maven version parsing + range comparison (no external deps).
lib/cve-download.js          Bulk download of CVEProject/cvelistV5 + Maven-relevant index build.
lib/cve-match.js             Resolved-dep collection + 3-tier CVE matching with dedup.
lib/cve-report.js            Self-contained HTML and Word-compatible (.doc) report rendering.
lib/cpe.js                   CPE 2.3 parsing + NVD configurations evaluator (post-match refinement).
lib/outdated.js              EOL (endoflife.date — `findEolProduct` tags each match with via/viaKey origin), obsolete (curated), outdated (Maven Central).
lib/embedded.js              buildEmbeddedInventory(): full inventory of provenance:"embedded" coords (vuln or not) → report chapter 1B + JSON. Pure.
lib/transitive.js            Maven Central POM walker (transitive resolution).
lib/osv.js                   OSV.dev batched query + per-vuln detail fetch.
lib/nvd.js                   NIST NVD enrichment (CVSS, references, CPE configurations).
lib/epss.js                  EPSS (FIRST.org) percentile/score enrichment (24h cache).
lib/kev.js                   CISA KEV catalogue membership enrichment (24h cache).
lib/priority.js              Composite priority (KEV > EPSS-weighted CVSS) → band/score/sortKey. Pure.
lib/license-policy.js        SPDX normalization + copyleft/proprietary classification.
lib/maven-license.js         Network-free Maven license from cached POMs.
lib/purl.js                  Package-URL builder per ecosystem. Pure.
lib/sbom-export.js           CycloneDX 1.6 SBOM (vulnerabilities inline). Pure builder + writer.
lib/csaf-export.js           CSAF 2.0 VEX (csaf_vex). Pure builder + writer.
lib/sarif-export.js          SARIF 2.1.0 log (rule per CVE + manifest locations). Pure builder + writer.
lib/json-export.js           Flat findings JSON (all chapters + summary). Pure builder + writer.
lib/gate.js                  evaluateGate(matches, level) → CI exit-code decision. Pure.
lib/suppress.js              Triage: --ignore rules + --vex (CSAF) ingestion → suppress matches. Pure.
lib/snyk.js                  `snyk test --all-projects --json` runner + merge.
lib/retire.js                retire.js (vendored-JS scanner) wrapper + cache + normaliser.
lib/scan-completeness.js     Warnings for deps we couldn't fully resolve.
lib/codecs/npm/parse.js             package.json, package-lock.json (v1/2/3), yarn.lock v1 + Berry, pnpm-lock.yaml (v5/6/9) parsers.
lib/codecs/npm/collect.js           Merge across JS manifests → unified resolvedDeps Map.
lib/codecs/npm/registry.js          npm registry packument query → per-version deprecation + dist-tags.latest.
lib/cache-archive.js         tar.gz / zip export & import of ~/.fad-checker/ (incl. retire findings + signatures).
lib/deps-descriptor.js       Anonymized dep descriptor serialize/deserialize (PASSI offline→online round-trip).
lib/config.js                Persistent user config in ~/.fad-checker/config.json (mode 0600).
data/                        Curated JSON: known-obsolete, eol-mapping, cpe-coord-map, known-public-namespaces.
completions/                 fad-checker.bash, fad-checker.zsh
test/                        node:test suite + fixtures (simple, complex-enterprise, monorepo-mixed, …).
```

## Codecs

Every ecosystem-specific behaviour lives behind a **codec** (`lib/codecs/*.codec.js`)
implementing one interface (`lib/codecs/codec.interface.js`):

```
id, label, osvEcosystem, manifestNames,
detect(dir), collect(dir,opts) → {deps, warnings},
coordKey(dep), formatCoord(dep), osvPackageName(dep),
checkRegistry(deps,opts) → {outdated, deprecated},
resolveEolProduct(dep), recipe, nativeScanners
```

- `lib/codecs/index.js` is the registry: `getCodec(id)`, `allCodecs()`, `detectCodecs(dir)`.
- `lib/codecs/select.js` turns `--ecosystem <list>` + `--no-<id>` into the active codec ids.
- The orchestrator collects deps by looping the active codecs, then runs the **shared,
  ecosystem-agnostic** services (OSV, NVD, CPE refinement, endoflife.date) which ask the
  codec only for a package/product name. `nativeScanners` are extra scanners a codec owns
  and the orchestrator runs at their pipeline position by `kind`: `cve` (maven → local
  cvelistV5 index, merged into the CVE chapter) and `vendored` (npm → retire.js, its own
  chapter). New ecosystems (NuGet/Composer/PyPI) ship as codecs with no native scanners —
  OSV + NVD cover them — so no orchestrator changes are needed to add one.

## The resolved-deps Map

The whole pipeline hinges on a single `Map<string, depRecord>` keyed by:
- `groupId:artifactId` for Maven entries
- `npm:<name>` for npm/yarn entries

Each `depRecord` carries:

```js
{
  groupId, artifactId, version,
  scope,             // "compile" | "test" | "import" | "transitive" | "parent" | "prod" | "dev" | "peer" | "optional"
  isDev,             // Maven test/provided OR npm dev/devOptional/optional
  ecosystem,         // "maven" | "npm"
  ecosystemType,     // "maven" | "npm" | "yarn" | "retire"
  pomPaths,          // absolute paths to manifests declaring this dep
  manifestPaths,     // same as pomPaths but used by the npm collector
  // Transitive-only:
  via, viaPaths, depth,
  // npm-only:
  lockType, resolved, integrity,
}
```

The Maven keyspace and npm keyspace never collide — `:lodash` (Maven groupId-less) becomes `npm:lodash` so the same Map can hold both ecosystems without overwrites.

## Cleanup pipeline (`lib/core.js`)

1. `findPomFiles(src)` — recursive walk, skips known output dirs (`target/`, `node_modules/`, `.git/`, `.idea/`, `dist/`, `build-output/`, `out/`, `.next/`, `.nuxt/`, `coverage/`, `.gradle/`, `.mvn/`, `.vscode/`, `bower_components/`, `jspm_packages/`). Note: `build/` is **not** skipped on the Maven side because some multi-module projects use it for a BOM module.
2. `parsePom()` — xml2js to JSON. Extracts groupId/artifactId/version, `<parent>`, properties, and indexes every profile (recording which one is `activeByDefault`). Templates with literal `\${…}` are skipped.
3. `getAllInheritedProps()` — merges `<dependencies>`, `<dependencyManagement>`, `<properties>` from **every** `<profile>` (with `activeByDefault` properties winning for value conflicts), follows `<scope>import</scope>` BOMs to other local POMs, and recurses into resolved parents.
4. `rewritePoms()` — strips everything outside `nodeToKeep`, runs `cleanDeps()` to apply the `-e` regex, rewrites the `<parent>.relativePath` and `version` to the parent's value (not the child's). Skips disk writes when `readOnly`.

## Report pipeline (driven by `fad-checker.js` when `--report` is set)

1. **Collect** — `collectResolvedDeps()` dedupes by `groupId:artifactId`, keeps the highest version on conflict, includes external parent POMs as `scope='parent'`. `--ignore-test` honored. For npm, `collectNpmDeps()` walks JS manifests (lockfile-only — `package.json` without sibling lockfile is skipped + warned).
2. **Transitive expansion** (optional, `--transitive`) — `expandWithTransitives()` walks the Maven Central POM graph honouring exclusions, root depMgmt overrides, nearest-wins on version conflict, `--transitive-depth` cap. Skips test + optional scopes by default.
3. **CVE index** — `ensureCveIndex()` downloads the daily CVEProject zip (via `curl + unzip`, or falls back to `fetch()` + `unzip` / PowerShell `Expand-Archive`), filters to Maven-relevant entries, caches the compact index to `~/.fad-checker/cve-data/maven-cve-index.json`. Fresh for 24h. `--cve-refresh` forces rebuild, `--cve-offline` uses cache only.
4. **CVE matching** — `matchDepsAgainstCves()` runs three tiers:
   - `exact`: `byPackageName["g:a"]` hit
   - `probable`: `byProduct[artifactId]` + vendor matches groupId (`apache` ↔ `org.apache.*`)
   - `possible`: product-only match
   Dedupes by `(dep, cve.id)` and sorts by severity. npm deps are skipped here — they're scanned by OSV instead.
5. **OSV** (default on) — `queryOsvForDeps()` POSTs batched queries to `api.osv.dev/v1/querybatch` (Maven ecosystem for Maven deps, npm ecosystem for npm deps). Per-dep stub list cached 12h; per-vuln details cached 12h.
6. **NVD enrichment** (default on) — for every CVE id matched, fetch the full NVD record (description, CVSS vectors, references categorised by tag, CPE configurations). Rate-limited per NIST policy (5/30s unauthenticated, 50/30s with `NVD_API_KEY`).
7. **CPE refinement** — `refineMatchesWithCpe()` walks NVD's `configurations[].nodes[]` against each matched dep:
   - Confirms the dep version actually falls in the vulnerable range (else `cpeFiltered: true` — likely false positive).
   - Upgrades match `confidence` from `possible` → `probable` → `exact` when a curated `cpe-coord-map.json` entry confirms vendor:product → dep coord.
7b. **EPSS + KEV + priority** (default on, `--no-epss`/`--no-kev`) — `lib/epss.js` batches matched CVE ids to FIRST.org for the exploit-prediction percentile; `lib/kev.js` checks the CISA KEV catalogue. `lib/priority.js` then attaches a composite `cve.priority` (band + 0-100 score) to every match: KEV (exploited) outranks EPSS-weighted CVSS. The report sorts by it and surfaces a Priority column + KEV/EPSS chips. Both caches 24h.
8. **retire.js** (default on) — shells out to `retire --outputformat json --jspath <src>`. Output normalised to fad-checker match shape, with the vendored file path attached so the report can show where the offending `.js` lives. Cache: `~/.fad-checker/retire-cache/<md5(src)>.json`, 24h TTL. The cache body carries a `_schema` version (currently `2`, stamped once retire began running with `--verbose` and thus storing the *full* identified-library inventory): an entry without `_schema >= 2` was written by a pre-verbose build and is treated as a **cache miss** so an offline re-run re-scans (with local signatures) rather than silently emptying the vendored-JS inventory chapter 1D.
9. **EOL / Obsolete / Outdated** — `lib/outdated.js` (Maven) + `lib/codecs/npm/registry.js` (npm):
   - **WebJars** (`org.webjars*` — client-side JS shipped as Maven artifacts) are reduced to their npm-equivalent coordinate by `webjarToNpm()` (`lib/codecs/npm/collect.js`): `org.webjars.npm` is a deterministic npm mirror (`angular__core` → `@angular/core`); classic `org.webjars`/bower names pass through. They then flow through the **same npm paths** below — no WebJar-specific data.
   - **EOL**: matches dep coord against `data/eol-mapping.json`, fetches the cycle list from endoflife.date (cached 7d), flags cycles past their EOL date. npm packages and WebJars resolve by JS library name via `by_npm_name` / `by_npm_scope` (e.g. npm `angular`/webjar `angularjs` → AngularJS 1.x, `@angular/*` → Angular, `react`/`jquery`/`vue`/`bootstrap`). `findEolProduct` records **which rule matched** (`via`/`viaKey`) so the report's EOL **Source** column shows `endoflife.date/<slug>` + `matched via <rule> = <key>`. A **transitive** EOL finding renders its `via` chain (`root → … → dep`, from `lib/transitive.js`) in the Dependency column instead of a defining manifest, so a "dep of a dep" is traceable to the direct dependency pulling it in.
   - **Obsolete**: Maven via curated `data/known-obsolete.json` (log4j 1.x, jackson-mapper-asl, joda-time, commons-httpclient 3.x, …); npm **and WebJars** via the registry's per-version `deprecated` field (authoritative maintainer data — every dep is checked, nothing curated, nothing skipped).
   - **Outdated**: Maven Central Solr query; npm registry `dist-tags.latest` (npm deps and WebJars). Both gated by `--no-all-libs`. Cache 24h. Concurrency 8.
   - **Licenses** (`--no-licenses`): each registry pass also returns the package's license (no extra request); Maven licenses come network-free from cached POMs (`lib/maven-license.js`). `lib/license-policy.js` normalises to SPDX and classifies (permissive / weak / strong / network copyleft / proprietary / unknown), flagging copyleft + unknown.
10. **Snyk** (optional, `--snyk`) — runs `snyk test --all-projects --json` against the cleaned target dir. Normalised + merged. Findings in both sources tagged `source: "both"`.
11. **Outputs** — controlled by the `--report-<type>` family (`html`/`doc`/`sbom`/`csaf`/`json`/`sarif`), each taking an optional path (else a default name under `--report-output`, default `./fad-checker-report/`). With no `--report-*` flag the default set is HTML + `.doc`; `--no-report` writes nothing (gate-only). `writeReports()` renders `cve-report.html` (self-contained, inline CSS) and/or `cve-report.doc` (same HTML with Office XML meta tags so Word opens it natively).
12. **Machine-readable exports** (optional) — `--report-sbom` writes a CycloneDX 1.6 SBOM with vulnerabilities inline (VDR); `--report-csaf` writes a CSAF 2.0 VEX; `--report-json` a flat findings doc; `--report-sarif` a SARIF 2.1.0 log. All build purls via `lib/purl.js` and use the full match set (cpeFiltered marked, not dropped; embedded-jar coords carry `provenance:"embedded"`).

## Report structure

```
<Executive Summary>            ← global criticality + key bullet counts
<Summary cards>                ← critical / high / medium / low / KEV / EOL / obsolete / outdated / licenses
<Toolbar>                      ← expand-all / collapse-all / expand CVE details

0. Warnings & scan-completeness ← chapter 0 if any warnings
1. CVE Vulnerabilities — production (N)
  1.a Maven (n)
    1.a.0 All (n)              ← combined direct + transitive
    By pom.xml (k files)       ← wrapper always present
      <relative-path-1> (m)    ← direct deps in this pom only
      <relative-path-2> (m)
      …
  1.b npm (package-lock) (n)
    1.b.0 All (n)
    By package-lock.json (k files)
      web/package-lock.json (m)
2. CVE in dev dependencies (M) ← same structure as 1
3. Vendored JS scan — retire.js (R)
4. End-of-Life Frameworks
5. Obsolete / Deprecated Libraries
6. Outdated Libraries
7. Licenses                     ← grouped by SPDX policy category (copyleft/unknown flagged)
8. Fix Recommendations          ← per-ecosystem snippets
  8.a Maven                     ← dependencyManagement XML
  8.b npm                       ← package.json overrides
  8.c yarn                      ← package.json resolutions
```

## Important conventions

- **`coord()` always trims**: real-world POMs occasionally contain whitespace around `<artifactId>` (seen in the wild). Every coord-derived lookup goes through `coord()` in `lib/core.js`.
- **`byId` keys are never polluted with `undefined`**: we only index a POM by id when both `groupId` and `artifactId` are present. Test `byId does not get polluted with undefined keys` enforces this.
- **All profiles are merged, never prompted for**: previous versions prompted the user when a POM had multiple profiles. We now union every profile's deps so Snyk sees every dep any profile could pull in. `activeByDefault` wins only for property value conflicts.
- **No `process.exit(1)` mid-pipeline**: a parse/rewrite failure for one POM logs and continues so the summary still prints.
- **HTML report is self-contained**: inline CSS, no external assets. The `.doc` variant is the same HTML with Office XML namespace meta tags — Word opens it natively.
- **Map keys are ecosystem-namespaced**: Maven uses `g:a`, npm uses `npm:name`. They never collide so they can share one resolved-deps Map.
- **Lockfile-only npm**: `package.json` without sibling `package-lock.json`/`yarn.lock` is intentionally skipped (its ranges aren't queryable) and reported in chapter 0. Avoids false negatives on deps that haven't been installed yet.
- **Source identifiers**: every match carries `source: "fad" | "osv" | "nvd" | "snyk" | "retire"` (or a `+`-joined combination like `"fad+osv+nvd"`). The legacy "mbdc" identifier was renamed to "fad" in 3.0.

## Gotchas / edge cases worth knowing

- The CVE bundle from CVEProject is ~500 MB unpacked. We shell out to `curl + unzip` (Node built-in fallback to `fetch()` + system `unzip` / PowerShell `Expand-Archive`). The extracted JSON is deleted after the index is built.
- The bundle ships as `cves.zip.zip` (a zip whose sole content is another zip). `extractZip()` recurses up to 3 levels.
- `endoflife.date` API responses are cached locally for 7 days; Maven Central and npm registry version lookups for 24 hours.
- **Persistent config**: `~/.fad-checker/config.json` (mode 0600) stores per-user state, currently the NVD API key. Set via `fad-checker --set-nvd-key <KEY>`.
- **`--offline` umbrella flag**: skips every network call (CVE index download, OSV queries, NVD enrichment, EPSS/KEV lookups, endoflife.date lookups, Maven Central version queries, npm registry queries, transitive POM fetches, retire.js scans). Falls back to whatever is already cached. Per-source variants (`--cve-offline`, `--no-osv`, `--no-nvd`, `--no-epss`, `--no-kev`, `--no-licenses`, `--no-retire`, `--no-js`) still work independently.
- `snyk` is not a dependency — we shell out via `execFile`. `snyk` exits 1 when it finds vulnerabilities, which is expected (the JSON is still on stdout).
- The cleaned POM is the union of every profile's deps. Counts will therefore be larger than the source POM. This is intentional — verify your reasoning before "reducing" them.
- Unresolved `${…}` Maven variables are kept verbatim in the rewritten POM. `lib/cve-match.js` resolves them lazily via `resolveDepVersion()` when collecting deps for the scan. Deps that *still* can't be resolved (external BOM) are surfaced in chapter 0 as `unresolved-versions` warnings.
- **Per-cache TTLs** are documented in the README's "Caching" table.

## Testing

```bash
npm test                          # full suite (319 tests)
node --test test/core.test.js     # one file
```

Test fixtures live in `test/fixtures/`:
- `simple/` — 3 POMs with parent inheritance + property substitution
- `complex-enterprise/` — Spring Boot parent (external), local BOM via `scope=import`, three profiles (two of which inject env-specific JDBC drivers), test-scoped JUnit, jackson-databind via BOM-managed version
- `private-lib-detection/` — mixed public/private groupIds and an externally-hosted private parent — verifies missing-parent tracking
- `monorepo-mixed/` — combined Maven (4 POMs: parent + BOM + 2 modules) + JS (npm package-lock v3 + yarn.lock v1 + a no-lockfile package.json to test the warning)
- `cve-samples/` — small CVE / NVD JSON files to exercise the matchers without the 500 MB real bundle
