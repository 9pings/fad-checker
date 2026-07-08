# Architecture

This is the deep-dive for anyone modifying `fad-checker`'s internals or wondering why a particular finding shows up the way it does. For day-to-day usage, see [`USAGE.md`](USAGE.md).

## Module map

```
fad-checker.js                 Thin CLI: commander parsing + orchestration (loops over active codecs).
lib/codecs/                  Per-ecosystem codecs (maven, gradle, npm, yarn, composer, pypi, nuget, go, ruby, binary) + registry + select + recipes (see "Codecs" below).
lib/codecs/gradle/                gradle.lockfile + gradle.properties + build.gradle(.kts) best-effort DSL parser (parse.js) + version-catalog libs.versions.toml resolver (catalog.js). Emits ecosystem "maven" / ecosystemType "gradle" records; surfaces platform() BOMs for the maven-bom backfill.
lib/codecs/binary/                 Native-binary scanner: sniff.js (extension + magic-byte gate) + scan.js (walk + SHA-1/SHA-256). The binary codec finds committed .dll/.exe/.so/.dylib (provenance:"binary").
lib/hash-id.js               Identity-by-checksum: deps.dev (→ exact coordinate) then CIRCL hashlookup (→ known-good + KnownMalicious). Cached, offline-aware.
lib/unmanaged.js             enrichUnmanaged() (identity + integrity on hash-bearing records) + buildInventory() (per-file signals for report chapter 1C / JSON).
lib/certs/                   Certificate / key-material scanner (NOT a codec — crypto material has no version/registry/CVE/EOL). sniff.js (extension + conventional-SSH-name gate) + analyze.js (X.509 via built-in crypto.X509Certificate, key classification incl. private/public + all SSH/PEM/PuTTY/PGP formats, weak-crypto findings — pure) + scan.js (walk + sha256) + index.js (scanCertificates). → report chapter 2.4 + JSON `certificates` + SARIF `FAD-*`. 100% offline.
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
lib/version-overlay.js       Per-module version-mediation overlay (recovers transitive versions the global pass masks via cross-module depMgmt bleed; additive).
lib/osv.js                   OSV.dev batched query + per-vuln detail fetch.
lib/osv-db.js                Offline-complete OSV matching from an imported local OSV DB (Maven; `--osv-db`).
lib/malware.js               Supply-chain risk lane: known-malicious (MAL-) flagging + offline typosquat heuristic (`--typosquat`).
lib/nvd.js                   NIST NVD enrichment (CVSS, references, CPE configurations, CWE list). Offline serves the warmed cache regardless of TTL/schema (never drops enrichment air-gapped).
lib/epss.js                  EPSS (FIRST.org) percentile/score enrichment (24h cache).
lib/kev.js                   CISA KEV catalogue membership enrichment (24h cache).
lib/priority.js              Composite priority (KEV > EPSS-weighted CVSS) → band/score/sortKey. Pure.
lib/license-policy.js        SPDX normalization + copyleft/proprietary classification.
lib/maven-license.js         Network-free Maven license from cached POMs.
lib/purl.js                  Package-URL builder per ecosystem. Pure.
lib/sbom-export.js           CycloneDX 1.6 SBOM (vulnerabilities inline). Pure builder + writer.
lib/csaf-export.js           CSAF 2.0 VEX (csaf_vex). Pure builder + writer.
lib/sarif-export.js          SARIF 2.1.0 log (rule per CVE + manifest locations). Pure builder + writer.
lib/json-export.js           Flat findings JSON (all chapters + summary, incl. excludedDirs[] + provenance + diff). Pure builder + writer.
lib/gate.js                  evaluateGate(matches, level) → CI exit-code decision. Pure.
lib/suppress.js              Triage: --ignore rules + --vex (CSAF) ingestion → suppress matches. Pure.
lib/provenance.js            buildScanProvenance() → scan-provenance manifest (tool/runtime/mode + config + per-data-source freshness). Pure given a cacheDir. Feeds JSON `provenance` + report chapter 12.
lib/diff.js                  diffFindings()/summarizeDiff() → differential audit between two findings JSON docs (added/removed/unchanged per category). Pure. Powers --baseline / `fad diff` / --fail-on-new.
lib/report-integrity.js      SHA256SUMS integrity manifest over the written artifacts (sha256sum format, `sha256sum -c`-verifiable). --no-checksums disables.
lib/snyk.js                  `snyk test --all-projects --json` runner + merge.
lib/retire.js                retire.js (vendored-JS scanner) wrapper + cache + normaliser. buildRetireIgnorePatterns() generates a retire --ignorefile mirroring the codecs' prune policy (default SKIP dirs at any depth + --exclude-path, anchored to --src).
lib/scan-completeness.js     Warnings for deps we couldn't fully resolve.
lib/codecs/npm/parse.js             package.json, package-lock.json (v1/2/3), yarn.lock v1 + Berry, pnpm-lock.yaml (v5/6/9) parsers.
lib/codecs/npm/collect.js           Merge across JS manifests → unified resolvedDeps Map.
lib/codecs/npm/registry.js          npm registry packument query → per-version deprecation + dist-tags.latest.
lib/cache-archive.js         tar.gz / zip export & import of ~/.fad-checker/ (incl. retire findings + signatures).
lib/deps-descriptor.js       Anonymized dep descriptor serialize/deserialize (anonymized offline→online round-trip).
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
detect(dir), collect(dir,opts) → {deps, warnings, parsedManifests},  // parsedManifests = every file parsed

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
- **Gradle is modeled as the Maven ecosystem.** Its codec emits records with
  `ecosystem: "maven"` (bare `g:a` coordKey) so the Maven CVE-index `nativeScanner`,
  OSV `Maven`, the Maven-Central transitive walk, the external import-BOM backfill, outdated
  and EOL all cover Gradle deps unchanged — but `ecosystemType: "gradle"` so the report
  buckets them into a dedicated "Gradle" chapter and offers a Gradle `constraints { }` fix
  recipe (`codecFor()` resolves the codec by `ecosystemType` first). The only Gradle-specific
  orchestrator wiring is: include it in the transitive/CVE/scan-completeness gates
  (`runMaven || runGradle`) and feed its `platform(...)` BOMs into the same
  `lib/maven-bom.js` managed-version backfill the Maven path uses. A backfilled dep is stamped
  `versionSource = { via: "bom", bom: "<g:a:v>" }` (the top-level platform/import BOM coord), which
  the report renders as a `version managed by: <bom> (BOM)` line and the findings JSON carries on
  `dep.versionSource` — so a versionless dep's resolved version is traceable to its BOM, not mistaken
  for a fabricated one. Gradle is **excluded** from
  the per-codec registry loop (its outdated/obsolete/EOL come from the Maven passes, which
  already select every `ecosystem === "maven"` dep) to avoid double-processing.

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
  ecosystem,         // "maven" | "npm"  (Gradle deps are "maven" — Maven coordinates)
  ecosystemType,     // "maven" | "gradle" | "npm" | "yarn" | "retire"
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
1b. **BOM / parent version resolution** (`lib/maven-bom.js`, mainline — runs whenever there's a Maven external import-BOM **or** external `<parent>`) — backfills the version of every declared dep that pins none of its own. `collectImportBoms()` (scope=import) resolves FIRST (a local declaration wins over inherited parent versions), then `collectExternalParents()` (the `<parent>` chain — core.js only follows LOCAL parents) fills the rest, tagged `via:"parent"`. Both fetch via `effectivePom()` (cache-first, offline-aware). `collectPropertyOverrides()` feeds the project's own `<properties>` in as `propertyOverrides`, so a patched `<log4j2.version>` wins over the framework default for parent-managed coords (import-BOM-managed coords resolve in the BOM's own context and are not overridden). This is what makes a versionless `spring-boot-starter-actuator` scannable whether it's pinned by an import BOM or inherited from `spring-boot-starter-parent`. Runs BEFORE step 2 so backfilled versions feed transitive resolution.
2. **Transitive expansion** (optional, `--transitive`) — `expandWithTransitives()` walks the Maven Central POM graph honouring exclusions, root depMgmt overrides, nearest-wins on version conflict, `--transitive-depth` cap. Skips test + optional scopes by default. This pass is **global** (one tree, one `rootDepMgmt` = highest version per coord).
2b. **Per-module version mediation** (`lib/version-overlay.js`, runs when step 2 does) — the global pass above applies any module's depMgmt pin across the WHOLE reactor, masking a *different* module's older (often vulnerable) transitive of the same coord. `expandPerModuleOverlay()` re-resolves **each module independently** with ONLY its own effective depMgmt (local parent chain via `core.resolveParentPath` + external parent/import-BOMs via `effectivePom`, `effCache`-memoised) and **appends** any genuinely-present version not already in `versions[]` (with `maskedVersions[]` provenance). Purely additive — never removes, never reseeds, so it can only ADD coverage. On reference-project: 156 → 181 Snyk-covered, 0 over-attribution FPs.
3. **CVE index** — `ensureCveIndex()` downloads the daily CVEProject zip (via `curl + unzip`, or falls back to `fetch()` + `unzip` / PowerShell `Expand-Archive`), filters to Maven-relevant entries, caches the compact index to `~/.fad-checker/cve-data/maven-cve-index.json`. Fresh for 24h. `--cve-refresh` forces rebuild, `--cve-offline` uses cache only.
4. **CVE matching** — `matchDepsAgainstCves()` runs three tiers:
   - `exact`: `byPackageName["g:a"]` hit
   - `probable`: `byProduct[artifactId]` + vendor matches groupId (`apache` ↔ `org.apache.*`)
   - `possible`: product-only match
   Dedupes by `(dep, cve.id)` and sorts by severity. npm deps are skipped here — they're scanned by OSV instead.
5. **OSV** (default on) — `queryOsvForDeps()` POSTs batched queries to `api.osv.dev/v1/querybatch` (Maven ecosystem for Maven deps, npm ecosystem for npm deps). Per-dep stub list cached 12h; per-vuln details cached 12h.
5b. **OSV local DB** (`--osv-db`, Maven) — `lib/osv-db.js` imports the full OSV Maven `all.zip` once (online) into a compact local index, then matches EVERY dep against it (`matchOsvDbDeps`, range eval via `maven-version`), merged via `mergeBySource`. Online it adds nothing (the live OSV query above already covers it), but **offline it makes Maven recall complete and cache-independent** — when the per-dep OSV cache is cold (different machine, TTL-expired, offline-discovered deps) it lifts reference-project from 6→117 covered. The OSV-Scanner air-gap model.
6. **NVD enrichment** (default on) — for every CVE id matched, fetch the full NVD record (description, CVSS vectors, references categorised by tag, CPE configurations, **CWE list**). Rate-limited per NIST policy (5/30s unauthenticated, 50/30s with `NVD_API_KEY`). Cached per-CVE (`nvd-cache/<id>.json`, `_schema:2`, 7-day TTL). **Offline**, `readCache` bypasses the TTL and the schema check and serves the warmed body — an air-gapped box can't re-fetch, so dropping a stale/older entry would silently lose ALL of that CVE's enrichment (CWEs included); a missing field is better than nothing. Online still enforces TTL + schema to re-fetch and upgrade. (CWE *titles* are a static bundled map, `data/cwe-names.json`; identical online/offline.)
7. **CPE refinement** — `refineMatchesWithCpe()` walks NVD's `configurations[].nodes[]` against each matched dep:
   - Confirms the dep version actually falls in the vulnerable range (else `cpeFiltered: true` — likely false positive).
   - Upgrades match `confidence` from `possible` → `probable` → `exact` when a curated `cpe-coord-map.json` entry confirms vendor:product → dep coord.
7b. **EPSS + KEV + priority** (default on, `--no-epss`/`--no-kev`) — `lib/epss.js` batches matched CVE ids to FIRST.org for the exploit-prediction percentile; `lib/kev.js` checks the CISA KEV catalogue. `lib/priority.js` then attaches a composite `cve.priority` (band + 0-100 score) to every match: KEV (exploited) outranks EPSS-weighted CVSS. The report sorts by it and surfaces a Priority column + KEV/EPSS chips. Both caches 24h.
8. **retire.js** (default on) — shells out to `retire --outputformat json --jspath <src>`. Output normalised to fad-checker match shape, with the vendored file path attached so the report can show where the offending `.js` lives. retire does its own directory walk, so to prune the **same dirs the codec walkers skip** it's handed a generated `--ignorefile` (`buildRetireIgnorePatterns`): the default SKIP set (`node_modules`, `target`, `dist`, …) matched **by basename at any depth** plus the user's `--exclude-path` globs **anchored to `--src`** (honoring `--no-default-excludes`). This is done via an ignorefile of `@`-prefixed segment patterns because retire's plain `--ignore` flag `path.resolve()`s every entry against retire's *own* cwd — so a bare `node_modules` silently missed `<src>/…/node_modules` whenever fad ran from a different directory than `--src`, and could never express "this dir at any depth". Cache: `~/.fad-checker/retire-cache/<md5(src)>.json`, 24h TTL. The cache body carries a `_schema` version (currently `2`, stamped once retire began running with `--verbose` and thus storing the *full* identified-library inventory): an entry without `_schema >= 2` was written by a pre-verbose build and is treated as a **cache miss** so an offline re-run re-scans (with local signatures) rather than silently emptying the vendored-JS inventory chapter 1D. A genuine **scan failure** (retire crashed mid-walk — e.g. ENOENT on the `--src` path, an unreadable file — leaving empty/unparseable output) is no longer swallowed: `scanWithRetireFull` returns an `error`, which the orchestrator surfaces as a chapter-0 `retire-failed` warning so a missing 1D reads as "the scan broke (here's why)" instead of "nothing found". Run with `-v` to see the exact retire stderr.
8b. **Certificate / key-material scan** (default on, `--no-certs`) — `lib/certs/` walks `--src` for committed crypto material: X.509 certificates (`.pem`/`.crt`/`.cer`/`.der`, parsed with the built-in `crypto.X509Certificate`), private/public keys (PEM PKCS#1/8/SEC1, OpenSSH every algorithm, PuTTY `.ppk`, PGP, one-line SSH in `*.pub`/`authorized_keys`/`known_hosts`) and keystores (JKS/JCEKS by magic, PKCS#12 by extension). Every key is labelled **private** (critical) or **public** (low); certs are flagged expired / expiring (`--cert-expiry-days`, default 90) / weak-key (RSA<2048) / weak-signature (MD5/SHA1 via OID byte-scan) / self-signed. Pure local scan — **no network, no decryption**, so identical online/offline. → report chapter 2.4, JSON `certificates`, SARIF `FAD-*` rules. Inventory only (not wired into the `--fail-on` gate).
9. **EOL / Obsolete / Outdated** — `lib/outdated.js` (Maven) + `lib/codecs/npm/registry.js` (npm):
   - **WebJars** (`org.webjars*` — client-side JS shipped as Maven artifacts) are reduced to their npm-equivalent coordinate by `webjarToNpm()` (`lib/codecs/npm/collect.js`): `org.webjars.npm` is a deterministic npm mirror (`angular__core` → `@angular/core`); classic `org.webjars`/bower names pass through. They then flow through the **same npm paths** below — no WebJar-specific data.
   - **EOL**: matches dep coord against `data/eol-mapping.json`, fetches the cycle list from endoflife.date (cached 7d), flags cycles past their EOL date. npm packages and WebJars resolve by JS library name via `by_npm_name` / `by_npm_scope` (e.g. npm `angular`/webjar `angularjs` → AngularJS 1.x, `@angular/*` → Angular, `react`/`jquery`/`vue`/`bootstrap`). `findEolProduct` records **which rule matched** (`via`/`viaKey`) so the report's EOL **Source** column shows `endoflife.date/<slug>` + `matched via <rule> = <key>`. A **transitive** EOL finding renders its `via` chain (`root → … → dep`, from `lib/transitive.js`) in the Dependency column instead of a defining manifest, so a "dep of a dep" is traceable to the direct dependency pulling it in.
   - **Obsolete**: Maven via curated `data/known-obsolete.json` (log4j 1.x, jackson-mapper-asl, joda-time, commons-httpclient 3.x, …); npm **and WebJars** via the registry's per-version `deprecated` field (authoritative maintainer data — every dep is checked, nothing curated, nothing skipped).
   - **Outdated**: Maven Central Solr query; npm registry `dist-tags.latest` (npm deps and WebJars). Both gated by `--no-all-libs`. Cache 24h. Concurrency 8.
   - **Licenses** (`--licenses`, **opt-in / off by default**): each registry pass also returns the package's license (no extra request); Maven licenses come network-free from cached POMs (`lib/maven-license.js`). `lib/license-policy.js` normalises to SPDX and classifies (permissive / weak / strong / network copyleft / proprietary / unknown), flagging copyleft + unknown.
10. **Snyk** (optional, `--snyk`) — runs `snyk test --all-projects --json` against the cleaned target dir. Normalised + merged. Findings in both sources tagged `source: "both"`.
11. **Outputs** — controlled by the `--report-<type>` family (`html`/`doc`/`sbom`/`csaf`/`json`/`sarif`), each taking an optional path (else a default name under `--report-output`, default `./fad-checker-report/`). With no `--report-*` flag the default set is HTML + `.doc`; `--no-report` writes nothing (gate-only). `writeReports()` renders `cve-report.html` (self-contained, inline CSS) and/or `cve-report.doc` (same HTML with Office XML meta tags so Word opens it natively).
12. **Machine-readable exports** (optional) — `--report-sbom` writes a CycloneDX 1.6 SBOM with vulnerabilities inline (VDR); `--report-csaf` writes a CSAF 2.0 VEX; `--report-json` a flat findings doc; `--report-sarif` a SARIF 2.1.0 log. All build purls via `lib/purl.js` and use the full match set (cpeFiltered marked, not dropped; embedded-jar coords carry `provenance:"embedded"`).
13. **Audit-trail outputs** — a **provenance manifest** (`lib/provenance.js`) is attached to `projectInfo` and rendered as report chapter 12 + the JSON `provenance` block. With `--baseline <file>` the current findings are diffed (`lib/diff.js`) into a Δ report chapter + the JSON `diff` block, and `--fail-on-new` gates on new production CVEs. Unless `--no-checksums`, a `SHA256SUMS` manifest (`lib/report-integrity.js`) is written beside the artifacts. A standalone `fad-checker diff a.json b.json` compares two exports without scanning.

## Report structure

```
<Executive Summary>            ← global criticality, then 3 blocks:
                                  (1) top-3 most critical — DIRECT production deps first,
                                      worst transitives only fill empty slots (tagged "transitive"),
                                      each row listing ALL of that finding's CWEs beside it;
                                  (2) the 2 most-overdue end-of-life frameworks;
                                  (3) one-line "everything else" (high/critical counts,
                                      dev CVE, vendored-JS, EOL/obsolete/outdated,
                                      unmanaged native binaries, scan alerts).
                                  "📋 Copy summary" yields a Word-pasteable rich+plain version of all three.
<Summary cards>                ← critical / high / medium / low / KEV / EOL / obsolete / outdated / licenses (compacted to one line)
<Overview charts>              ← 4 inline-SVG donuts on one row under the totals (lib/charts.js):
                                  CWE of direct vulns (legend = CWE titles) · sub-dep CVEs per root dep
                                  (CVE count, legend = readable dep name; rootless/npm shown as a note) ·
                                  direct vs transitive (per-severity counts in the legend) · fix-priority
                                  bands. Each donut has a "📋 Copy chart" button (SVG→canvas→PNG →
                                  clipboard) for pasting into Word.
<Toolbar>                      ← expand-all / collapse-all / expand CVE details

Chapters are grouped under SIX root chapters (a two-level hierarchy), with two
standalone chapters (Warnings, baseline diff) pinned at the top:

0. Warnings & scan-completeness ← standalone, top; only if any warnings
Δ. Changes since baseline       ← standalone, top; only with --baseline (new/fixed/unchanged per category + new prod CVEs)

1. CVE (X direct, Y indirect, Z dev)              ← ROOT
  1.1 Production (N)
    1.1.a Maven (n)
      1.1.a.0 All (n)           ← combined direct + transitive
      By pom.xml (k files)       ← wrapper always present
        <relative-path> (m)      ← direct deps in this pom only
    1.1.b npm (package-lock) (n)
      …
  1.2 Vendored JS vulns — retire.js (R)
  1.3 Dev dependencies (M)        ← same eco/manifest structure as 1.1
  1.4 Likely false positives — CPE-filtered   ← only if any
2. Unmanaged / unversioned components (X embedded, Y native, Z vendored JS, C crypto)   ← ROOT
  2.1 Embedded binaries — JAR/WAR/EAR
  2.2 Unmanaged / vendored native binaries
  2.3 Unmanaged / vendored JavaScript
  2.4 Certificates & key material (certs + private/public keys + keystores)
3. Maintenance / lifecycle (X EOL, Y obsolete, Z outdated)   ← ROOT
  3.1 End-of-Life frameworks
  3.2 Obsolete / deprecated
  3.3 Outdated
4. Licenses                     ← ROOT (standalone); grouped by SPDX policy category (copyleft/unknown flagged)
5. Fix Recommendations          ← ROOT (standalone); per-ecosystem snippets (Maven depMgmt / npm overrides / yarn resolutions / …)
6. Scan context & limitations   ← ROOT
  6.1 Scanned dependency descriptors  ← COMPLETE list of every manifest/lockfile each codec parsed
                                         (codec.collect → parsedManifests), relative to src, with
                                         per-file direct-dep count; files that contributed NOTHING
                                         (ranges-only / no lockfile) listed with count 0 — nothing
                                         silently omitted. Transitives + committed binaries excluded.
  6.2 Ignored directories             ← dirs the prune policy skipped (default-excludes + --exclude-path); only if any
  6.3 Methodology, data sources & limitations ← provenance data-source table (freshness) + run config + explicit "what fad does NOT assess"
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
- **`--offline` umbrella flag**: skips every network call (CVE index download, OSV queries, NVD enrichment, EPSS/KEV lookups, endoflife.date lookups, Maven Central version queries, npm registry queries, transitive POM fetches, retire.js scans). Falls back to whatever is already cached. Per-source variants (`--cve-offline`, `--no-osv`, `--no-nvd`, `--no-epss`, `--no-kev`, `--no-retire`, `--no-js`) still work independently. (Licenses are opt-in via `--licenses`, off by default.)
- `snyk` is not a dependency — we shell out via `execFile`. `snyk` exits 1 when it finds vulnerabilities, which is expected (the JSON is still on stdout).
- The cleaned POM is the union of every profile's deps. Counts will therefore be larger than the source POM. This is intentional — verify your reasoning before "reducing" them.
- Unresolved `${…}` Maven variables are kept verbatim in the rewritten POM. `lib/cve-match.js` resolves them lazily via `resolveDepVersion()` when collecting deps for the scan. Deps that *still* can't be resolved (external BOM) are surfaced in chapter 0 as `unresolved-versions` warnings.
- **Per-cache TTLs** are documented in the README's "Caching" table.

## Testing

```bash
npm test                          # full suite (519 tests)
node --test test/core.test.js     # one file
```

Test fixtures live in `test/fixtures/`:
- `simple/` — 3 POMs with parent inheritance + property substitution
- `complex-enterprise/` — Spring Boot parent (external), local BOM via `scope=import`, three profiles (two of which inject env-specific JDBC drivers), test-scoped JUnit, jackson-databind via BOM-managed version
- `private-lib-detection/` — mixed public/private groupIds and an externally-hosted private parent — verifies missing-parent tracking
- `monorepo-mixed/` — combined Maven (4 POMs: parent + BOM + 2 modules) + JS (npm package-lock v3 + yarn.lock v1 + a no-lockfile package.json to test the warning)
- `gradle-kotlin-catalog/`, `gradle-groovy-lockfile/`, `gradle-hybrid/` — Gradle: Kotlin DSL + version catalog + `buildSrc/` `platform()` BOM; Groovy DSL + `gradle.lockfile`; and a `pom.xml`+`build.gradle` hybrid (Maven/Gradle keyspace coexistence)
- `cve-samples/` — small CVE / NVD JSON files to exercise the matchers without the 500 MB real bundle
