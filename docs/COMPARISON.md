# fad-checker vs other tools — and how it stays build-free

`fad-checker` is **not** a Trivy/Grype competitor — those are container-and-SBOM supply-chain
scanners. It targets a narrower job: a **zero-setup, multi-ecosystem audit of a source
checkout, with an audit-ready report and a confidential / air-gapped workflow** — the kind
of thing a security consultant or a regulated / air-gapped engagement needs.

## At a glance

| | **fad-checker** | OSV-Scanner | Trivy | Grype + Syft | OWASP DC | Snyk OSS |
| --- | --- | --- | --- | --- | --- | --- |
| Ecosystems it targets¹ | Maven, **Gradle**, npm, Yarn, **pnpm**, Composer, PyPI, NuGet, Go, Ruby + vendored JS + **native binaries** | 11+ langs / 19+ lockfiles | 20+ | 20+ | Java/.NET (others exp.) | many |
| Reads lockfiles without `install`/build | ✅ | ✅ | ✅ | ✅ | ⚠️ Java needs Maven Central/build | ❌ build required |
| Best-effort when **no lockfile** (pinned versions) | ✅ | ❌ | ❌ | ❌ | ⚠️ | ⚠️ |
| Vulnerability sources | CVEProject + OSV + NVD + EPSS + KEV + retire.js (+ Snyk), merged | OSV.dev | Aqua DB | Anchore DB | NVD / CPE | Snyk DB |
| False-positive control | CPE/version cross-check | ecosystem-aware | ecosystem-aware | ecosystem-aware | ⚠️ CPE → noisy | ecosystem-aware |
| **EOL** of an application framework⁴ | ✅ endoflife.date | ❌ | ⚠️ OS distros only | ❌ | ❌ | ❌ |
| **Outdated / deprecated** | ✅ registries + curated | ❌ | ❌ | ❌ | ❌ | ⚠️ web UI only |
| Containers / OS packages | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| SBOM (CycloneDX/SPDX) | ✅ CycloneDX 1.6 (+ CSAF 2.0 VEX) | ✅ | ✅ | ✅ (Syft) | ~ | ✅ |
| License compliance | ✅ SPDX + copyleft policy | ~ | ✅ | ~ | ❌ | ✅ |
| EPSS / KEV prioritization | ✅ FIRST.org EPSS + CISA KEV | ~ | ✅ | ✅ | ❌ | ✅ |
| CI gating (`--fail-on`) + triage | ✅ severity/KEV + ignore/VEX | ✅ | ✅ | ✅ | ⚠️ | ✅ |
| Malware / typosquat | ⚠️ OSV `MAL-` gate + `--typosquat` heuristic | ~ | ~ | ❌ | ❌ | ✅ |
| Auto-remediation / PRs | ❌ (fix recipes only) | ✅ `fix` | ❌ | ❌ | ❌ | ✅ |
| Offline | ✅ cache | ✅ local DB | ✅ | ✅ | ✅ feed | ❌ mostly online |
| Offline Maven **transitive** graph³ | ✅ cached POMs | ❌ disabled under `--offline` | ⚠️ needs a populated `~/.m2` | ⚠️ opt-in, off by default⁵ | ⚠️ mirror | ❌ |
| **Scan without exposing paths**² | ✅ anonymized descriptor | ❌ | ❌ | ⚠️ SBOM, carries paths | ❌ | ❌ |
| **Maven private-dep cleanup** (→ Snyk) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Output | **HTML + Word `.doc`** + JSON / SARIF / CycloneDX / CSAF | table/JSON/SARIF | table/JSON/SARIF | table/JSON/SARIF | HTML/XML/JSON | JSON / cloud UI |

¹ Narrower language coverage — no Rust/Dart/Swift (Go and Ruby are now covered).

² Phase 1 exports only public coordinates; the online scan never sees your source tree
(see [Air-gapped](../README.md#air-gapped-audits)). Two honest qualifications. **(a)** You *can*
approximate this elsewhere by generating an SBOM on the isolated machine and scanning it online
(`grype sbom:./sbom.json`, `trivy sbom`). The difference is that a Syft SBOM is **not
anonymized**: its CycloneDX encoder stamps every component with `syft:location` file paths, so
the SBOM carries your internal tree layout off the machine. fad's `fad-deps/1` descriptor drops
paths, registry URLs, integrity hashes and parent chains by construction.
**(b)** The direction differs: in the SBOM route the *report* is produced online; fad brings a
cache back and produces the report, with real paths and manifests, **inside** the enclave.
Sources: [Syft CycloneDX encoder](https://github.com/anchore/syft/blob/main/syft/format/internal/cyclonedxutil/helpers/component.go),
[Grype README](https://github.com/anchore/grype/blob/main/README.md).

³ Measured on **Apache Dubbo 2.7.8** (105-module reactor, commit `0be2a1bb`), every scanner run
under `unshare -rn` with no network interface. Reference set: OSV-Scanner's own **online**
output (657 distinct `package@version | vulnerability` pairs, third-party dependencies only).

| Scanner, no network | Recovers | Notes |
| --- | --- | --- |
| **fad-checker** `--offline` | **653 (99.4%)** | resolves the Maven graph from cached POMs |
| Grype + Syft (defaults) | 45 (6.8%) | Syft's transitive option applies to **archives**, not `pom.xml`⁵ |
| Trivy `--offline-scan` | 40 (6.1%) | warns "Child dependencies will not be found" |
| OSV-Scanner `--offline` | 37 (5.6%) | transitive resolution disabled offline, per its own docs |

Online, OSV-Scanner finds 92 vulnerable Maven packages here and 3 offline; the missing 89 are
transitive. Trivy and Grype are **container and SBOM scanners** — pointing them at a raw source
checkout is not their primary job, and the `~/.m2` on the test machine was populated (287 MB),
which favours them. A Trivy *online* run could not be completed: Maven Central rate-limited the
IP (`429`, `Retry-After: 1800`) after the other scans, and Trivy aborts fatally on that. Full
method, the 4 pairs fad still misses and the caveats → [`BENCHMARK.md`](BENCHMARK.md).
OSV-Scanner's own docs, not this measurement, are the load-bearing claim:
> "This feature is enabled by default when scanning, but it can be disabled using the
> `--no-resolve` flag. It is also disabled in the offline mode."
> — [supported languages and lockfiles](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)

⁴ Scoped deliberately to **application** frameworks and libraries (Spring Boot 2.x, AngularJS,
Django, a deprecated npm package). Trivy *does* compute an end-of-service-life status, but only
for **OS distributions** (`pkg/detector/ospkg/detect.go`). Snyk's Package Health Score exists
only on `security.snyk.io` package pages; its docs state that CLI, IDE and CI/CD integrations do
not display package health, so it can't gate a build on it.

⁵ Syft has `java.resolve-transitive-dependencies`, but it is **opt-in, `false` by default, and
scoped to archives**: the option lives on `ArchiveCatalogerConfig` and its own doc comment reads
"for java packages found **within archives**". On a source checkout scanned by the
`java-pom-cataloger` it therefore does nothing — verified by measurement, enabling it on Dubbo
2.7.8 changed the result by zero findings (58 → 58). Even for archives it relies on Maven
Central (`java.use-network`, also `false` by default) or a populated local repository; Syft's
own tip is to run `mvn help:effective-pom` first, which needs both Maven and a network. Source:
[`config.go`](https://github.com/anchore/syft/blob/main/syft/pkg/cataloger/java/config.go).

**Versions compared** (table last verified **2026-07-22**): OSV-Scanner **v2.4.0**, Trivy
**v0.72.0**, Grype **v0.116.0** + Syft **v1.49.0**, OWASP Dependency-Check **v12.2.2**, Snyk CLI
**v1.1306.x**. All of these are actively maintained projects; none of the ⚠️/❌ cells above mean
"abandoned". Every competitor cell is meant to be checkable against the linked upstream doc. If
one is wrong or has gone stale, [open an issue](https://github.com/9pings/fad-checker/issues) and
it gets corrected.

**Where it fits:** a one-shot audit of a polyglot checkout you may not be able to build, a
presentable HTML/Word deliverable, and confidential / air-gapped engagements.

**Where it doesn't:** container/OS scanning, reachability analysis, auto-fix PRs — reach for
**Trivy** or **Grype + Syft**.

You don't have to choose — `fad-checker` takes Snyk's results as input (`--snyk`) and merges them.

> Sources: [OSV-Scanner lockfiles](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/) ·
> [Trivy Java/`pom.xml` (Maven Central, `--offline-scan`)](https://trivy.dev/docs/latest/coverage/language/java/) ·
> [Syft `java-pom-cataloger` (source dirs)](https://github.com/anchore/syft/issues/676) ·
> [OWASP DC needs internet/build for Java](https://jeremylong.github.io/DependencyCheck/data/index.html) ·
> [Snyk requires building the project](https://docs.snyk.io/supported-languages/technical-specifications-and-guidance) ·
> [EOL/outdated "most tools skip" (Aikido)](https://www.aikido.dev/code/outdated-eol-software)

## How it's autonomous (no build tools)

Because it doesn't need anything you don't already have on disk:

| You don't need | Why |
| --- | --- |
| Maven installed | `pom.xml` files are parsed directly with xml2js. Properties, profiles and local BOMs are resolved in-process. Transitive deps are fetched from Maven Central by default (cached forever); `--no-transitive` disables it. |
| `mvn dependency:tree` | Same as above. We walk the tree ourselves. |
| `npm install` / a `node_modules/` | `package-lock.json` (v1/v2/v3), `yarn.lock` (v1 + Berry/v2+) and `pnpm-lock.yaml` (v5/v6/v9) are parsed as text/JSON/YAML. Versions come from the lockfile — no installation. |
| `yarn install` / `pnpm install` | Same. We read `yarn.lock` (v1 + Berry) and `pnpm-lock.yaml` directly. |
| `composer install` | `composer.lock` is parsed directly (concrete versions + transitive). `composer.json` alone → best-effort on pinned versions + warning. |
| `pip` / `poetry` / a venv | `poetry.lock`, `Pipfile.lock`, `uv.lock`, `pdm.lock` are parsed for concrete versions; `pyproject.toml` (PEP 621 + poetry) and `requirements.txt` (following `-r`/`-c` includes) are best-effort on exact pins. Names normalised per PEP 503. |
| `dotnet restore` | `packages.lock.json` is parsed; otherwise `*.csproj`/`*.fsproj`/`*.vbproj` (+ `Directory.Packages.props` Central Package Management) and legacy `packages.config`, best-effort on pinned versions. |
| `go build` / a Go toolchain | `go.mod` is parsed (the full pruned graph on Go ≥1.17, `// indirect` → transitive); `go.sum` is the fallback. No module download. |
| `bundle install` | `Gemfile.lock` is parsed for the resolved gem set. No Ruby, no bundler. |
| `snyk` binary | Built-in CVE matching via CVEProject + OSV + NVD (merged), prioritised with EPSS + CISA KEV. Snyk is *optional* (`--snyk`). |
| A network connection | First run downloads CVE / OSV / EOL data; subsequent runs use cached copies (`--offline` to force). |

For each ecosystem it reads the **lockfile** (or, failing that, the manifest's pinned versions) straight off disk:

| Ecosystem | Read directly | Transitive versions come from |
| --- | --- | --- |
| Maven | `pom.xml` (+ parents, BOMs, profiles) | child POMs fetched from Maven Central (cached) — resolved **per-module** so a depMgmt pin in one module can't hide a vulnerable transitive in another |
| Gradle | `gradle.lockfile` → `gradle/libs.versions.toml` → `build.gradle(.kts)` best-effort (Groovy+Kotlin DSL, `libs.*` catalog, `buildSrc/`) | child POMs from Maven Central (same as Maven); `platform(...)` BOMs backfill versionless deps |
| npm / Yarn / pnpm | `package-lock.json` · `yarn.lock` (v1+Berry) · `pnpm-lock.yaml` | the lockfile itself |
| Composer | `composer.lock` (else `composer.json`) | the lockfile |
| PyPI | `poetry.lock` · `Pipfile.lock` · `uv.lock` · `pdm.lock` (else `pyproject.toml`/`requirements.txt`) | the lockfile |
| NuGet | `packages.lock.json` (else `*.csproj`/`packages.config`) | the lockfile |
| Go | `go.mod` (`// indirect` → transitive; `go.sum` fallback) | the module graph in `go.mod` |
| Ruby | `Gemfile.lock` (`specs:`) | the lockfile |
| Vendored JS / binaries | the committed `.js` / `.jar` / `.so` files themselves | n/a (read in place) |

Highlights of the matching layer: **three CVE sources merged** (CVEProject + OSV.dev + NVD),
**CPE/version cross-check** to drop false positives, **EPSS + CISA KEV** prioritisation,
lockfile-first with a **best-effort pinned-version fallback** when no lockfile, in-memory
**embedded-JAR** unzip (no disk, no zip-slip), and **checksum identity** for native binaries.
Pipeline and per-stage detail → [`ARCHITECTURE.md`](ARCHITECTURE.md).
