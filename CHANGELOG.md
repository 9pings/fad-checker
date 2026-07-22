# Changelog

All notable changes to `fad-checker` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- **An imported BOM's `<properties>` leaked into the importing project — and won.**
  `<scope>import</scope>` imports a BOM's `<dependencyManagement>` and **nothing else**: the
  BOM resolves its managed versions in its own property context, and its `<properties>` never
  become the importer's. `core.js` merged them, and merged them so the BOM won
  (`{...merged.properties, ...imported.properties}`), so a BOM silently redefined the
  importing project's own property values. On Apache Dubbo 2.7.8 the reactor root sets
  `<hibernate_validator_version>5.2.4.Final</hibernate_validator_version>` and
  `dubbo-dependencies-bom` redefines it to `5.4.1.Final`, so `dubbo-filter-validation`'s
  `<version>${hibernate_validator_version}</version>` resolved to the wrong version — and a
  different version is a different CVE set. (`mvn dependency:tree` reports
  `hibernate-validator:jar:5.2.4.Final:test` for that module.) The BOM's managed entries are
  now interpolated against the BOM's own properties at the import boundary and the properties
  are dropped, mirroring what `transitive.js#effectivePom` already did for EXTERNAL import
  BOMs. Locked by `test/bom-property-leak.test.js`, which guards both directions: the leak
  must stop **and** importing a BOM must still supply managed versions.
- **A version declared only at test scope is now reported as dev.** `isDev` lives on the
  coord-wide record, so a version declared solely at `<scope>test</scope>` inherited the
  coordinate's production flag whenever the same coordinate was production at some other
  version — counting toward the production total and the `--fail-on` gate. Per-version scopes
  are now recorded next to per-version paths (`versionScopes`, mirror of `versionPaths`), and
  attribution applies the same widest-wins rule already used for overlay-recovered versions.
  On Dubbo, `hibernate-validator:5.2.4.Final` moves to the dev chapter, attributed to
  `dubbo-filter-validation` — exactly what Maven reports.

  Air-gapped recall on the public benchmark reaches **657/657 (100%)** of OSV-Scanner's own
  online finding set, up from 653.

### Changed
- **The benchmark now measures every scanner at full capability, not just air-gapped.**
  `docs/BENCHMARK.md` carries two tables, because they answer different questions. **Full
  capability** (all five online, best configuration, populated `~/.m2`, union 908 pairs):
  fad-checker 790 (87.0%), OSV-Scanner 657, Snyk 603, Trivy 546, Grype+Syft 45. **No tool
  finds everything, fad included** — its 118 misses all come from Snyk, 30 of them under a
  proprietary `SNYK-*` id no public database carries, and **88 genuine public-CVE misses that
  remain undiagnosed**. **No network** (`unshare -rn`, against OSV-Scanner's online output):
  fad 657/657, Grype+Syft 45, Trivy 40, OSV-Scanner 37.
  Also documented: Trivy's result is identical online and with a fully populated `~/.m2` (the
  local repository substitutes for the network entirely), Grype+Syft does not move at all
  between default and fully-enabled configuration, and the `settings.xml` mirror trick for
  reproducing the run when Maven Central rate-limits the IP.
- **The per-module overlay could not recover a version held only on a TEST classpath.**
  The overlay exists because the global transitive pass dedupes by `g:a` across the whole
  reactor and keeps one version per coordinate — but it hardcoded
  `includedScopes: ["compile","runtime","provided"]`, so a version reachable only through a
  test-scoped dependency was structurally unreachable. Measured on Apache Dubbo 2.7.8, this
  one omission accounted for **every one** of the 78 findings OSV-Scanner reported that fad
  missed (`jackson-databind:2.8.4:test` in dubbo-registry-sofa,
  `hibernate-validator:5.2.4.Final:test` in dubbo-filter-validation, `okhttp:3.11.0` /
  `okio:1.14.0` in dubbo-configcenter-apollo, `commons-compress:1.18:test` in
  dubbo-remoting-etcd3 — each verified against `mvn dependency:tree`).
  Air-gapped recall on that project: **579 → 653 of 657 (88.1% → 99.4%)**, production
  findings unchanged at 651, dev findings 11 → 147, **zero production finding lost**.
- **A version is now dev only when EVERY module resolving it does so at test scope.**
  On Dubbo, `jackson-databind:2.10.4` is test-scoped in `dubbo-config-spring` but
  **compile**-scoped in `dubbo-configcenter-nacos`. Reading the first recorded provenance
  called the version dev and dropped a genuine production finding out of the count and out
  of the `--fail-on` gate.
- **The overlay records provenance per module even when the version is already known.**
  It used to `continue` on the first module to contribute a version, so a second module
  resolving the same version at a different scope left no trace at all — which is exactly
  what made the previous item invisible.
- **A DECLARED version now wins over any transitive provenance for the same version.**
  `xstream:1.4.10` is declared outright in `dubbo-registry-eureka` *and* reached as a
  test-scoped transitive of `dubbo-config-api`; letting the transitive provenance win
  demoted 35 findings, one of them KEV, into the dev chapter. A manifest that writes
  `<version>` for a coordinate is the authority on that version.

### Previously fixed
- **The transitive closure of a test-scoped dependency was never scanned.** Maven's scope
  matrix says `test → compile = test`: the compile dependencies of a test-scoped dependency
  are on the test classpath, and so are theirs, recursively (only `test → test` is omitted).
  `expandWithTransitives` passed test-scoped roots into resolution (`includeTestDeps`, on
  unless `--ignore-test`) but `resolveTransitiveDeps` then filtered accepted propagated
  scopes to `compile/runtime/provided`, so **every child of a test root was discarded at the
  first hop**. Net effect: the dev chapter only ever listed *directly declared* test
  dependencies, never their transitives. On Apache Dubbo 2.7.8 this hid
  `spring-boot:1.5.17.RELEASE` and `spring-boot-autoconfigure:1.5.17.RELEASE`, four hops down
  `registry-test → registry-server-integration → spring-boot-starter`, all of which
  `mvn dependency:tree` reports at scope=test.
- **Scope is now widened, never narrowed, when a coord is reached by several paths.** This is
  the half of the fix above that matters most. The traversal dedupes by `g:a` and keeps the
  first chain walked, so marking everything under a test root as dev let **BFS order decide
  the scope**: a coordinate reachable from *both* a test root and a compile root got stamped
  test if the test path happened to be walked first. Measured: 6 production findings
  (`spring-core:4.3.16.RELEASE`, `commons-lang:2.6`, …) silently moved into the dev chapter,
  dropping out of the production count **and out of the `--fail-on` gate**. A false negative
  on the production classpath is worse than the gap being fixed. A revisit now upgrades
  `test` to the wider propagated scope and never the reverse. Locked by
  `test/transitive-test-scope.test.js` (6 tests, including the both-paths case and the
  `test → test` omission).
  Net on Dubbo: **575 → 579** recovered pairs, production findings **unchanged at 650**, dev
  findings 7 → 11.
- **Maven hard-pin versions (`[1.2.3]`) are now normalised to the bare version.**
  Maven's `[x]` syntax means *exactly* x — a concrete version wearing range brackets —
  and real upstream POMs use it (`io.grpc:grpc-netty:1.22.1` declares
  `<version>[4.1.35.Final]</version>`). fad kept the brackets verbatim, so the coordinate
  was wrong **everywhere downstream**: the report, the purl, and every SBOM/CSAF/SARIF/JSON
  export carried `netty-codec-http2@[4.1.35.Final]`, which cannot be joined with any other
  tool's output for the same dependency. Fixed by `lib/maven-version.js#normalizeHardPin`,
  applied on both paths that produce a version — `cve-match.js#resolveDepVersion` (declared
  deps, after `${…}` interpolation, so `[${netty.version}]` works) and `lib/transitive.js`
  (deps read out of upstream POMs, which is where this actually came from). A **genuine
  range keeps its brackets**: choosing a version out of `[1.0,2.0)` is resolution, not
  normalisation, and it must keep surfacing as unresolved rather than silently becoming
  concrete. Found by the new public benchmark, where it cost **9 recovered findings**
  (566 → 575 of OSV-Scanner's reference set on Apache Dubbo 2.7.8). Note that the OSV cache
  is keyed by coordinate **and** version, so this fix invalidates entries warmed under the
  old string — an offline re-run needs a cache re-warm to see the corrected coordinate.
- **Docs referenced a `--transitive` flag that does not exist.** Transitive resolution is
  **on by default**; `--no-transitive` disables it. Corrected in `ARCHITECTURE.md` and
  `COMPARISON.md`.

### Added
- **`docs/BENCHMARK.md` — a reproducible air-gapped recall benchmark.** Replaces the
  unverifiable private-project figure that headlined the README. Measured on **Apache Dubbo
  2.7.8** (105-module reactor, pinned commit), with both scanners run under `unshare -rn` in
  a namespace with **no network interface**, and graded against **OSV-Scanner's own online
  output** as the reference set (657 distinct `package@version | vulnerability` pairs) rather
  than against fad's own notion of a finding: **fad-checker recovers 575 (87.5%)**,
  **OSV-Scanner recovers 37 (5.6%)**. Documents the exact commands, the tool versions, the
  82 pairs fad misses **and why** (version-mediation divergence, plus two genuinely
  unresolved `spring-boot` coordinates), and the caveats — a warmed cache is required, and
  one project is one shape.

### Changed
- `docs/COMPARISON.md`: four competitor cells corrected after re-verification against
  upstream docs and source. Syft **does** have Maven transitive resolution
  (`java.resolve-transitive-dependencies`, opt-in, off by default); Trivy consults a local
  `~/.m2` before the network; Trivy **does** report end-of-service-life, but only for OS
  distributions (the EOL row is now scoped to *application* frameworks); and the
  "scan without exposing the codebase" row now concedes the SBOM-then-scan-online route,
  keeping only the two differences that are sourceable. Adds a version stamp for every tool
  compared and an explicit note that no ⚠️/❌ cell means "unmaintained".

### Previously fixed
- **External `<parent>` POMs (spring-boot-starter-parent) now backfill their managed
  versions.** A versionless dep whose version is inherited from an external `<parent>`
  (e.g. `spring-boot-starter-actuator` under `spring-boot-starter-parent`, whose own
  parent `spring-boot-dependencies` holds the version table) was left unresolved and
  **dropped from the CVE/OSV/EOL/outdated scans** — the mainline backfill (`lib/maven-bom.js`)
  only handled `<scope>import</scope>` BOMs, never the `<parent>` case, so this failed
  even online (the `--transitive` overlay resolved the parent but couldn't backfill the
  primary version). `collectExternalParents()` now feeds external parents through the same
  `effectivePom` → `backfillVersions` path as import BOMs (import BOMs win on precedence),
  stamped `versionSource={via:"parent",…}` → report "version managed by … (parent POM)".
  It runs in the **mainline** flow (not just `--transitive`), so the warmed cache always
  captures the parent POMs for **offline/air-gapped** reuse. **Child property overrides are
  honored** (Maven semantics): a project that redefines `<log4j2.version>2.17.1</log4j2.version>`
  to patch a CVE resolves the managed coord to `2.17.1`, not the framework default
  (`collectPropertyOverrides()` → `effectivePom`'s new `propertyOverrides`; import-BOM-managed
  coords are correctly left un-overridden). The "missing parent POM — potentially private"
  warning now **partitions** parents fad resolves from Maven Central/cache (public) from the
  truly-unresolvable ones (private), instead of flagging every external parent as suspect.
- **Anonymized descriptor closes the versionless-Spring-Boot round-trip in one exchange.**
  The `fad-deps/1` descriptor now carries a `maven` hints block (`externalParents[]` +
  `importBoms[]` coords + version `propertyOverrides{}`) so a no-source-tree online
  `--import-anonymized` run can resolve the versionless deps' versions and warm their
  `coord+version`-keyed CVE caches — previously that needed a second air-gapped exchange.
  Only public coords + version strings travel (a private parent listed is a harmless online
  no-op); the source tree never leaves the enclave.
- **CVE-index recall: real-world pre-2023 records were dropped (incl. Log4Shell).**
  `isMavenRelevant()` only accepted CVE 5.x records carrying machine-readable Maven
  metadata (`packageName`/`collectionURL`/`versionType:"maven"`) or an EXACT-match
  known vendor — but CNAs publish legal-entity vendors ("Apache Software Foundation")
  and display products ("Apache Log4j2"), so **CVE-2021-44228 was absent from the
  index** and an offline scan of `log4j-core:2.14.0` reported no Log4Shell. The filter
  now tokenises vendors, strips leading vendor words from products, and consults the
  curated `data/cpe-coord-map.json` — which also **backfills `packageName`** on
  product-only records so they match at tier-1. `versions[].changes[]` timelines
  (how 44228 encodes its affected windows) are expanded into plain affected windows,
  placeholder bounds (`lessThan:"log4j-core*"`, `"*"`, `"unspecified"`) no longer
  poison comparisons (fail-closed preserved), and `fixVersion` picks the **highest**
  version-like upper bound instead of the first (multi-branch advisories suggested a
  downgrade). Rebuilt index: **6 589 → 15 236 CVE (+131 %)**. Regression-tested against
  the real cvelistV5 record (`test/fixtures/cve-samples/cve-2021-44228-real.json`).
- **OSV offline: warmed cache older than the 12 h TTL was silently discarded.**
  `--offline` now bypasses the OSV cache TTL (same rule as the NVD cache): on an
  air-gapped box the warmed cache is the only source, and expiring it reported
  "0 OSV vulns" for every ecosystem. Online behaviour is unchanged.
- **Go: `replace` directives are now applied** (module→module replaces rewrite the
  scanned coordinate — a `replace` downgrade was invisible; directory replaces are
  dropped with a chapter-0 `local-replace` warning), and **pre-1.17 modules merge the
  `go.sum` graph** (their `go.mod` lists direct deps only — transitives were skipped).
- **PyPI: `pip-compile --generate-hashes` output parsed correctly.** The trailing
  `\` of hash-pinned lines (and inline ` --hash=…` options) made every dep of such a
  requirements file silently skipped. `uv.lock` no longer inventories the project's
  own virtual/editable package. Same-name deps pinned to different versions across
  files now ALL land in `versions[]` (every distinct version scanned, as Maven does).
- **NuGet: `Directory.Packages.props` is resolved by walking UP the tree** (MSBuild
  semantics — nearest wins). Before, only the csproj's own directory was searched, so
  a root-level CPM solution collected **zero** deps. Also: `VersionOverride` support,
  exact-range pins `[1.2.3]` accepted as concrete, distinct resolved versions across
  projects/TFMs all scanned, and **paged registration indexes** (Newtonsoft.Json-class
  packages) have the needed pages fetched instead of returning empty findings.
- **Registry caches (go/pypi/nuget): offline runs no longer re-stamp cache freshness**
  (a stale cache would then look fresh to the next online run and skip its refetch).

### Changed
- **Report chapters reorganised into a two-level hierarchy.** Related chapters are now
  grouped under six **root chapters**, each whose header carries a breakdown count:
  **1. CVE** (`X direct, Y indirect, Z dev` — sub: Production, Vendored JS vulns, Dev,
  Likely false positives) · **2. Unmanaged / unversioned components** (`X embedded,
  Y native, Z vendored JS` — sub: embedded JAR/WAR/EAR, native binaries, vendored JS) ·
  **3. Maintenance / lifecycle** (`X EOL, Y obsolete, Z outdated`) · **4. Licenses** ·
  **5. Fix Recommendations** · **6. Scan context & limitations** (sub: scanned
  descriptors, ignored dirs, methodology). **0. Warnings** and **Δ. Changes since
  baseline** stay pinned at the top. The table of contents is now hierarchical
  (roots + indented sub-chapters).

### Added
- **Certificate & key-material scanner (report chapter 2.4).** A new standalone scanner
  (`lib/certs/`, on by default, `--no-certs` to disable) walks the source tree for
  committed cryptographic material and surfaces it in a dedicated report chapter, the
  JSON export (`certificates` array + `summary.certificates`/`certPrivateKeys`) and SARIF
  (`FAD-*` rules). It detects **X.509 certificates** (PEM/DER, parsed with Node's built-in
  `crypto.X509Certificate`) and flags **expired**, **expiring** (within `--cert-expiry-days`,
  default 90), **weak key** (RSA<2048 / weak EC curve), **weak signature** (MD5/SHA1) and
  **self-signed**; **private & public keys** — every key explicitly labelled **private**
  (a committed secret → critical) or **public** (low) — across PEM (PKCS#1/8/SEC1),
  **OpenSSH of every algorithm** (RSA/DSA/ECDSA/Ed25519 incl. FIDO `-sk`), PuTTY `.ppk`,
  PGP and one-line SSH (`*.pub`, `authorized_keys`, `known_hosts`); and **keystores**
  (JKS/JCEKS by magic byte, PKCS#12 by extension). Detection is by extension **and**
  conventional SSH filename. **100% offline** — no network, no decryption — inventory-only
  (does not affect the `--fail-on` gate).
- **Scan-provenance manifest + Methodology chapter (audit reproducibility).** Every
  report now carries a provenance manifest — tool version, run mode (offline/online),
  the findings-affecting configuration, and the **freshness of every data source**
  (CVE index, OSV, NVD, KEV, EPSS, endoflife, registry caches) read from
  `~/.fad-checker/`. Surfaced in the JSON export's `provenance` block and in the
  report's new **chapter 12 — "Methodology, data sources & limitations"**, which also
  states explicitly **what fad-checker does *not* assess** (reachability, runtime
  config, secrets/IaC, first-party code, malware beyond the OSV/CIRCL signal, legal
  license advice). New `lib/provenance.js`.
- **Differential audits (`--baseline` / `fad diff`).** Diff a scan against a prior
  findings JSON: the report gains a **"Δ Changes since baseline"** chapter, the JSON
  export gains a `diff` block (summary + new/fixed CVEs), and CI can gate on **new**
  findings with `--fail-on-new` (exit 1 on any new production CVE). Standalone
  `fad-checker diff <baseline.json> <current.json> [--report-json <out>] [--fail-on-new]`
  for ad-hoc comparison. Finding identity = CVE id + ecosystem + coord + version. New
  `lib/diff.js`.
- **Report integrity manifest.** A standard `SHA256SUMS` is written beside the report
  artifacts (verifiable with `sha256sum -c`); `--no-checksums` disables it. New
  `lib/report-integrity.js`.
- **Private registries for NuGet and Composer** (previously the only registry-backed
  ecosystems without private-feed support). NuGet custom feeds speak the v3
  registration API (a service-index `…/index.json` is auto-resolved to its
  `RegistrationsBaseUrl`); Composer custom feeds are queried via the v2
  `<base>/p2/<vendor>/<pkg>.json` metadata API. Same `--add-repo nuget|composer …`
  CRUD + auth as the other ecosystems.
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
- **A failing `--snyk` run is no longer silently reported as "0 findings".** Snyk
  exits 2 on a command error (e.g. not authenticated) and 3 when it detects no
  supported project — but in `--json` mode it still writes a JSON document to
  **stdout**, shaped `{ ok:false, error:"…" }`. `runSnykTest`'s catch block treated
  *any* stdout on a non-zero exit as "vulns found (exit 1)", so that error JSON was
  parsed to zero vulnerabilities and surfaced as a green `Snyk: 0 findings merged`,
  hiding the failure. It now distinguishes real results (a `vulnerabilities` array or
  `ok:true`) from error stubs and **throws the snyk error message** (deduped, joined),
  which the orchestrator shows as a `Snyk run failed: …` warning. A snyk crash with no
  stdout now surfaces `stderr` instead of `execFile`'s generic "Command failed", and a
  timeout is reported as such. New pure helper `snykOutputError()` (unit-tested).
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
