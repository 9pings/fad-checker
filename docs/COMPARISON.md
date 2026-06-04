# fad-checker vs other tools — and how it stays build-free

`fad-checker` is **not** a Trivy/Grype competitor — those are container-and-SBOM supply-chain
scanners. It targets a narrower job: a **zero-setup, multi-ecosystem audit of a source
checkout, with an audit-ready report and a confidential / air-gapped workflow** — the kind
of thing a security consultant or an ANSSI-PASSI engagement needs.

## At a glance

| | **fad-checker** | OSV-Scanner | Trivy | Grype + Syft | OWASP DC | Snyk OSS |
| --- | --- | --- | --- | --- | --- | --- |
| Ecosystems it targets¹ | Maven, npm, Yarn, **pnpm**, Composer, PyPI, NuGet, Go, Ruby + vendored JS + **native binaries** | 11+ langs / 19+ lockfiles | 20+ | 20+ | Java/.NET (others exp.) | many |
| Reads lockfiles without `install`/build | ✅ | ✅ | ✅ | ✅ | ⚠️ Java needs Maven Central/build | ❌ build required |
| Best-effort when **no lockfile** (pinned versions) | ✅ | ❌ | ❌ | ❌ | ⚠️ | ⚠️ |
| Vulnerability sources | CVEProject + OSV + NVD + EPSS + KEV + retire.js (+ Snyk), merged | OSV.dev | Aqua DB | Anchore DB | NVD / CPE | Snyk DB |
| False-positive control | CPE/version cross-check | ecosystem-aware | ecosystem-aware | ecosystem-aware | ⚠️ CPE → noisy | ecosystem-aware |
| **EOL** (end-of-life) detection | ✅ endoflife.date | ❌ | ❌ | ❌ | ❌ | ~ |
| **Outdated / deprecated** | ✅ registries + curated | ❌ | ❌ | ❌ | ❌ | ~ |
| Containers / OS packages | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| SBOM (CycloneDX/SPDX) | ✅ CycloneDX 1.6 (+ CSAF 2.0 VEX) | ✅ | ✅ | ✅ (Syft) | ~ | ✅ |
| License compliance | ✅ SPDX + copyleft policy | ~ | ✅ | ~ | ❌ | ✅ |
| EPSS / KEV prioritization | ✅ FIRST.org EPSS + CISA KEV | ~ | ✅ | ✅ | ❌ | ✅ |
| CI gating (`--fail-on`) + triage | ✅ severity/KEV + ignore/VEX | ✅ | ✅ | ✅ | ⚠️ | ✅ |
| Malware / typosquat | ⚠️ OSV `MAL-` gate + `--typosquat` heuristic | ~ | ~ | ❌ | ❌ | ✅ |
| Auto-remediation / PRs | ❌ (fix recipes only) | ✅ `fix` | ❌ | ❌ | ❌ | ✅ |
| Offline | ✅ cache | ✅ local DB | ✅ | ✅ | ✅ feed | ❌ mostly online |
| Offline Maven **transitive** graph³ | ✅ cached POMs | ❌ disabled offline | ❌ | ❌ | ⚠️ mirror | ❌ |
| **Scan without exposing the codebase**² | ✅ anonymized descriptor | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Maven private-dep cleanup** (→ Snyk) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Output | **HTML + Word `.doc`** + JSON / SARIF / CycloneDX / CSAF | table/JSON/SARIF | table/JSON/SARIF | table/JSON/SARIF | HTML/XML/JSON | JSON / cloud UI |

¹ Narrower language coverage — no Rust/Dart/Swift (Go and Ruby are now covered).

² Phase 1 exports only public coordinates; the online scan never sees your source tree —
see [Air-gapped / PASSI](../README.md#air-gapped--passi-audits). OSV-Scanner has an offline
mode, but it still needs the **source on the scanning machine**.

³ Measured on a 25-module Spring/JSF project, fully air-gapped: fad covered **181/202**
Snyk-corroborated findings vs OSV-Scanner v2.3.8's **64/202** — **0 on Maven**, because its
transitive resolution is disabled without network. fad resolves the Maven graph from cached
POMs (and `--osv-db` makes its offline OSV recall cache-independent).

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
| Maven installed | `pom.xml` files are parsed directly with xml2js. Properties, profiles and local BOMs are resolved in-process. Transitive deps fetched from Maven Central if `--transitive` (cached forever). |
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
