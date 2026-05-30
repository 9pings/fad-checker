# fad-checker

[![npm version](https://img.shields.io/npm/v/fad-checker.svg)](https://www.npmjs.com/package/fad-checker)
[![npm downloads](https://img.shields.io/npm/dm/fad-checker.svg)](https://www.npmjs.com/package/fad-checker)
[![license](https://img.shields.io/npm/l/fad-checker.svg)](https://github.com/n8tz/fad-checker/blob/main/package.json)
[![node](https://img.shields.io/node/v/fad-checker.svg)](https://nodejs.org)

> **F**ucking **A**utonomous **D**ependency **C**hecker

`fad-checker` scans **Maven**, **npm**, **Yarn**, **Composer (PHP)**, **PyPI (Python)**, **NuGet (C#/.NET)** and **vendored JavaScript** in any source tree — multi-module, monorepo, polyglot, whatever you've got — and produces a single self-contained HTML report with CVE, EOL, obsolete and outdated findings, plus per-ecosystem fix recipes.

It runs against the source files alone. **No `mvn`, no `npm install`, no `composer install`, no `pip`, no `dotnet restore`, no Docker.** It reads `pom.xml`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `composer.lock`, `poetry.lock`/`Pipfile.lock`/`uv.lock`/`pdm.lock`/`pyproject.toml`/`requirements.txt`, and `packages.lock.json`/`*.csproj`/`*.fsproj`/`*.vbproj`/`packages.config` directly.

> **Supported ecosystems: Maven, npm, Yarn (v1 + Berry/v2+), pnpm, Composer, PyPI, NuGet.** Each is a self-contained **codec** (`lib/codecs/`) — adding another is adding a codec, no orchestrator surgery. Vendored JS (jQuery, Bootstrap, PDF.js, etc.) is also scanned via retire.js.

---

## Why "Autonomous"?

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
| `snyk` binary | Built-in CVE matching via 4 independent sources (see below). Snyk is *optional* (`--snyk`). |
| A network connection | First run downloads CVE / OSV / EOL data; subsequent runs use cached copies (`--offline` to force). |

Exactly **two** runtime dependencies must be on PATH (or installed automatically through npm): Node ≥ 20 and `retire` (the npm package, installed by `npm install`). Everything else is bundled or fetched lazily.

---

## What it finds

| Chapter | Source | What it catches |
| --- | --- | --- |
| **0. Warnings** | local heuristics | Missing lockfiles, unresolved Maven versions (BOM-managed), private libs not on Maven Central |
| **1. CVE (production)** | CVEProject + OSV.dev + NVD + CPE | Public CVE / GHSA in production deps, per ecosystem, per manifest file |
| **2. CVE in dev deps** | same | Same, but for `test`/`provided` (Maven) and `dev`/`optional`/`peer` (npm) |
| **3. Vendored JS** | [retire.js](https://retirejs.github.io/) | Old jQuery/Bootstrap/Angular/PDF.js copies sitting in `static/` or `webapp/` with no lockfile |
| **4. EOL frameworks** | endoflife.date | Spring Boot 2.5, Hibernate 4.x, EOL JDKs, AngularJS, Laravel/Symfony, Django, .NET, etc. |
| **5. Obsolete libraries** | curated list (Maven) + registry maintainer flags | log4j 1.x, jackson-mapper-asl, joda-time, …; npm `deprecated`, Composer `abandoned`, PyPI `yanked`/inactive, NuGet `deprecation` |
| **6. Outdated libraries** | Maven Central + npm / Packagist / PyPI / NuGet registries | Available newer versions, with release dates |
| **7. Fix Recommendations** | computed | Per-ecosystem pin recipes: Maven `<dependencyManagement>`, npm `overrides`, yarn `resolutions`, `composer require`, `pip install`, `dotnet add package` |

The HTML report opens in any browser, contains every detail (CVSS vectors, references, full descriptions, CPE configurations, via-paths for transitives) and ships a Word-compatible `.doc` twin.

---

## Quick start

```bash
npm install -g fad-checker
fad-checker -s ./my-project
```

That's it. The report lands in `./fad-checker-report/cve-report.html`.

Want a 10× faster NVD enrichment? [Get a free NVD API key](https://nvd.nist.gov/developers/request-an-api-key) (instant), then:

```bash
fad-checker --set-nvd-key YOUR_KEY
```

---

## Common runs

```bash
# Read-only full scan (default: all sources on)
fad-checker -s ./proj

# Exclude private/internal libs by groupId regex
fad-checker -s ./proj -e "^(com\.acme|org\.private)\."

# Also write cleaned POMs (private deps stripped, ready for Snyk)
fad-checker -s ./proj -t ../proj-clean -e "^com\.acme\."

# Then run Snyk on the cleaned tree and merge findings
fad-checker -s ./proj -t ../proj-clean -e "^com\.acme\." --snyk

# Faster: skip Maven Central / no transitive walk
fad-checker -s ./proj --no-all-libs --no-transitive

# Fully offline (uses cached data only)
fad-checker -s ./proj --offline

# Pick ecosystems — --ecosystem is a list: auto (default) | all | comma list
fad-checker -s ./proj --ecosystem maven            # Maven only
fad-checker -s ./proj --ecosystem maven,npm,pypi   # several
fad-checker -s ./proj --no-nuget --no-composer     # or opt out per codec
```

Run `fad-checker --help` for the full flag list.

---

## What a report looks like

```
Executive Summary [CRITICAL] — 1708 dependencies scanned
  • 81 CVE in production deps (critical=5, high=53, medium=12, low=11)
  • 32 CVE in dev/test deps
  • 17 vulnerable vendored JS finding(s) (retire.js)
  • 2 end-of-life frameworks
  • 13 obsolete / deprecated libs
  • 172 outdated libs
  • 4 scan-completeness alerts — see chapter 0

0. Warnings & scan-completeness (4)
1. CVE Vulnerabilities — production (81)
   1.a Maven (49)
      1.a.0 All (49)
      By pom.xml (14 files)
         build/building/pom.xml (17)
         services/api/pom.xml (17)
         … 12 more
   1.b npm (package-lock) (32)
      1.b.0 All (32)
      By package-lock.json (1 file)
         web/package-lock.json (32)
2. CVE in dev dependencies (32)
3. Vendored JS scan — retire.js (17)
4. End-of-Life Frameworks (2)
5. Obsolete / Deprecated Libraries (13)
6. Outdated Libraries (172)
7. Fix Recommendations
```

Each CVE row shows: severity badge · CVE / GHSA id · dep coord & version · which manifest file declares it · source(s) (CVEProject / OSV / NVD / Snyk / retire / fad) · fix-version · summary. Click a row for the full panel (CVSS vectors, NVD references categorised by type, transitive paths, CPE configurations).

---

## Install

### As a global CLI

```bash
npm install -g fad-checker
```

### From source

```bash
git clone <repo-url> fad-checker
cd fad-checker
npm install
node fad-checker.js --help
```

### Single-binary build (no Node required)

```bash
npm install        # one-time, brings in bun
npm run build      # → dist/fad-checker-linux + dist/fad-checker.exe
```

### Shell completion

```bash
fad-checker --completion bash > /etc/bash_completion.d/fad-checker
# or for zsh:
fad-checker --completion zsh  > ~/.zsh/completions/_fad-checker
```

---

## How it scans without any build tool

This is the surprising bit. The whole point is that you can run `fad-checker` against a *checkout* with no build environment.

- **Maven** — `pom.xml` files are parsed with xml2js. Property substitution (`${jackson.version}`), parent inheritance, local BOM imports (`<scope>import</scope>`) and every profile are resolved in-process. Transitive deps are walked by fetching child POMs from Maven Central (cached forever — POMs are immutable). When the project uses an **external BOM** (`spring-boot-dependencies` etc.), the deps whose version comes from that BOM can't be resolved without `mvn` itself — those are surfaced in chapter 0 as "unresolved-versions" so you know what's missing.
- **npm / Yarn / pnpm** — `package-lock.json` (v1, v2, v3), `yarn.lock` (v1 + Berry/v2+, via `js-yaml`) and `pnpm-lock.yaml` (v5/v6/v9, via `js-yaml`) are parsed directly. Lockfiles already contain every transitive version. No `node_modules/` traversal, no `npm install`.
- **Composer (PHP)** — `composer.lock` (`packages` + `packages-dev`) gives concrete + transitive versions; `composer.json` alone is best-effort.
- **PyPI (Python)** — `poetry.lock` / `Pipfile.lock` / `uv.lock` / `pdm.lock` are parsed (TOML via `smol-toml`, or JSON); `pyproject.toml` (PEP 621 `[project]` + `[tool.poetry]`) and `requirements.txt` (following `-r`/`-c` includes recursively, with `-c` constraint pins applied to ranges) are best-effort on exact pins. Package names are PEP 503-normalised (`Flask-SQLAlchemy` → `flask-sqlalchemy`).
- **NuGet (C#/.NET)** — `packages.lock.json` is authoritative; otherwise `*.csproj` / `*.fsproj` / `*.vbproj` `<PackageReference>` (resolving Central Package Management against `Directory.Packages.props`) and legacy `packages.config`. Ids are case-insensitive.
- **Lockfile-first, best-effort fallback** — when a lockfile is present it wins. When it's absent, the loose manifest (`package.json` / `composer.json` / `pyproject.toml` / `requirements.txt` / `*.csproj`) is still parsed for its **pinned exact versions**, with ranges skipped and a `no-lockfile` warning in chapter 0 flagging the partial coverage.
- **Vendored JavaScript** — `retire.js` shells out and scans `.js` / `.min.js` files by signature, catching old jQuery / Bootstrap / Angular / PDF.js copies that no lockfile knows about.
- **CVE data** — three independent sources merged:
  - **CVEProject** (the canonical `cvelistV5` bundle, filtered to Maven-relevant entries)
  - **OSV.dev** (Google + GitHub Security Lab, multi-ecosystem)
  - **NVD** (official NIST records, used for enrichment: full CVSS, references, CPE configurations)
- **CPE refinement** — once a CVE is matched, its NVD CPE configurations are checked against the dep version range. A match outside the vulnerable range is flagged `cpeFiltered: true` (likely false positive). A curated `data/cpe-coord-map.json` maps CPE `vendor:product` to Maven `g:a` (60+ entries seeded: log4j, jackson, spring, tomcat, jetty, netty, …).

---

## Caching

All cached data lives in `~/.fad-checker/`:

| Cache | Path | TTL |
| --- | --- | --- |
| Maven CVE index (CVEProject bundle, filtered) | `cve-data/maven-cve-index.json` | 24 h |
| OSV per-dep lookups | `osv-cache/<ecosystem>__<g>__<a>__<v>.json` | 12 h |
| OSV vuln details | `osv-cache/vuln_<id>.json` | 12 h |
| NVD CVE records | `nvd-cache/<cveId>.json` | 7 d |
| endoflife.date cycles | `eol-cache.json` | 7 d |
| Maven Central latest versions | `version-cache.json` | 24 h |
| Transitive POMs from Maven Central | `poms-cache/<g>__<a>__<v>.pom` | ∞ (immutable) |
| retire.js findings | `retire-cache/<md5(src)>.json` | 24 h |
| retire.js signature DB | `retire-signatures/jsrepository-v5.json` | warmed online, used offline |
| User config (NVD key) | `config.json` (mode 0600) | — |

Export the lot to share between machines:

```bash
fad-checker --export-cache fad-cache.tar.gz
# on the other box:
fad-checker --import-cache fad-cache.tar.gz
```

`--include-config` ships the NVD API key too (off by default).

> The cache export bundles **everything** under `~/.fad-checker/` (except `config.json`),
> including the retire.js findings **and** the warmed retire.js signature DB — so a
> machine that imports it can scan vendored JavaScript fully offline.

---

## Air-gapped / PASSI audits: anonymized dependency descriptor

When the audited system is **offline / confidential** (typical of a PASSI engagement) it
can't reach OSV / NVD / Maven Central / npm. Split the work across machines while keeping
**zero environment information** off the secure enclave: an anonymized descriptor carries
only **public package coordinates** — no filesystem paths, no registry URLs, no
hostnames/usernames — and the **detailed report is produced back on the offline machine**.

The transfer relies on a property of fad-checker's caches: they are keyed by *coordinate*
or *vuln id*, never by path, so they are **machine-independent**. The online step just
**warms the caches**; the offline step replays the scan and gets cache hits.

```bash
# ── Phase 1 — OFFLINE (audited machine): export the anonymized descriptor ──
# Exclude private/internal packages with -e (offline we can't tell private from public).
fad-checker -s ./proj -e "^(client|internal)\." --export-anonymized deps.json
#   → deps.json: public coordinates only. Review it before it leaves the enclave.

# ── Phase 2 — ONLINE (any machine, no source needed): warm the caches ──
fad-checker --import-anonymized deps.json     # scans coordinates → OSV/NVD/CVE/registry/EOL + retire signatures
fad-checker --export-cache fad-cache.tar.gz   # bundle the warmed ~/.fad-checker/

# ── Phase 3 — OFFLINE (audited machine): full report, all local context ──
fad-checker --import-cache fad-cache.tar.gz
fad-checker -s ./proj --offline               # re-collect locally (real paths) + cache hits
#   → full HTML/.doc report with manifests & structure, generated inside the enclave.
```

What the descriptor (`fad-deps/1`) contains vs. drops:

| Kept (needed to scan) | Dropped (environment) |
| --- | --- |
| ecosystem, ecosystemType | manifest paths / pom paths |
| namespace, name | resolved registry URLs |
| version, versions | integrity hashes |
| scope, isDev | parent chains, lockfile type |

The online phase report is itself path-free; vendored-JavaScript (retire.js) findings are
produced **offline in phase 3**, since retire needs the actual `.js` files — its signature
DB is warmed online (phase 2) and carried by `--export-cache`.

---

## Custom Maven repositories

Out of the box `fad-checker` queries Maven Central for transitive POMs and latest versions. If your project depends on artifacts that live on a private Nexus / Artifactory / JBoss repo, add them so transitive resolution and outdated checks work end-to-end.

```bash
# Persist a repo (lives in ~/.fad-checker/config.json)
fad-checker --add-repo nexus       https://nexus.acme.com/repository/maven-public/
fad-checker --add-repo nexus-priv  https://nexus.acme.com/repository/maven-private/  --auth alice:s3cr3t
fad-checker --list-repos
fad-checker --remove-repo nexus-priv

# One-off (not persisted) — repeatable
fad-checker -s ./proj --repo https://nexus.acme.com/repository/maven-public/
# Inline auth in the URL also works:
fad-checker -s ./proj --repo https://alice:s3cr3t@nexus.acme.com/repository/maven-public/
```

Repos are tried **in declared order, Maven Central last**. Auth is sent as a `Basic <base64>` header. POMs and `maven-metadata.xml` are cached per coord, so subsequent runs are free even against a private repo.

---

## Data sources & acknowledgments

`fad-checker` is glue around several outstanding public datasets. Each is used per its license terms.

| Source | What we use | License | API / endpoint |
| --- | --- | --- | --- |
| [CVEProject `cvelistV5`](https://github.com/CVEProject/cvelistV5) | Daily bulk CVE bundle, filtered to Maven-relevant entries | CC0-1.0 | GitHub release asset (zip) |
| [OSV.dev](https://osv.dev/) (Google + GitHub Security Lab) | Per-dep vulnerability lookup (Maven, npm, Packagist, PyPI, NuGet, …) | CC-BY 4.0 | `POST api.osv.dev/v1/querybatch`, `GET api.osv.dev/v1/vulns/{id}` |
| [NIST NVD](https://nvd.nist.gov/) | Canonical CVE description + CVSS vectors + CPE configurations + CWE | US-gov public domain | `GET services.nvd.nist.gov/rest/json/cves/2.0?cveId=…` — free [API key](https://nvd.nist.gov/developers/request-an-api-key) bumps the rate limit 10× |
| [endoflife.date](https://endoflife.date/) | Framework / runtime EOL cycle data | MIT | `GET endoflife.date/api/{product}.json` |
| [Maven Central](https://search.maven.org/) | Latest-version lookups + transitive POM fetches | Free public service | Solr `search.maven.org/solrsearch/select?q=…` + `repo1.maven.org/maven2/<coord>` |
| [npm registry](https://registry.npmjs.org/) | Per-version `deprecated` + `dist-tags.latest` | Free public service | `GET registry.npmjs.org/<pkg>` |
| [Packagist](https://packagist.org/) | Latest stable + `abandoned` flag | Free public service | `GET packagist.org/packages/<vendor>/<pkg>.json` |
| [PyPI](https://pypi.org/) | Latest + `yanked` + "Inactive" classifier | Free public service | `GET pypi.org/pypi/<pkg>/json` |
| [NuGet](https://www.nuget.org/) | Latest stable + per-version `deprecation` | Free public service | `GET api.nuget.org/v3/registration5-gz-semver2/<id>/index.json` |
| [retire.js](https://retirejs.github.io/retire.js/) | Vendored-JS signature DB + scanner | Apache-2.0 | npm package `retire`, executed locally |
| [Snyk](https://snyk.io/) (optional) | Additional CVE source via `snyk test --all-projects --json` | Per Snyk EULA; needs a Snyk account | Local CLI `snyk` |
| [MITRE CWE](https://cwe.mitre.org/) | Weakness category links in the report | Free public reference | Linked by URL only, no API call |

Persistent caches mean each source is hit at most once per its TTL (see [Caching](#caching) table). No telemetry, no third-party analytics — every request listed above is made directly to the named endpoint with a `User-Agent: fad-checker-*` header.

---

## Safety rails

Built-in guardrails that fire **before** any disk write:

- `--target` is required unless you're running read-only (no `-t`).
- `--target` may not equal or be a subdirectory of `--src`.
- `--target` is `rimraf`'d before being rewritten — never point it at anything precious.

---

## Comparison

`fad-checker` is **not** a Trivy/Grype competitor — those are container-and-SBOM supply-chain
scanners. It targets a narrower job: a **zero-setup, multi-ecosystem audit of a source
checkout, with an audit-ready report and a confidential / air-gapped workflow** — the kind
of thing a security consultant or an ANSSI-PASSI engagement needs.

| | **fad-checker** | OSV-Scanner | Trivy | Grype + Syft | OWASP DC | Snyk OSS |
| --- | --- | --- | --- | --- | --- | --- |
| Ecosystems it targets¹ | Maven, npm, Yarn, **pnpm**, Composer, PyPI, NuGet + vendored JS | 11+ langs / 19+ lockfiles | 20+ | 20+ | Java/.NET (others exp.) | many |
| Reads lockfiles without `install`/build² | ✅ | ✅ | ✅ | ✅ | ⚠️ Java needs Maven Central/build | ❌ build required |
| Best-effort when **no lockfile** (pinned versions) | ✅ | ❌ | ❌ | ❌ | ⚠️ | ⚠️ |
| Vulnerability sources | CVEProject + OSV + NVD + retire.js (+ Snyk), merged | OSV.dev | Aqua DB | Anchore DB | NVD / CPE | Snyk DB |
| False-positive control | CPE/version cross-check | ecosystem-aware | ecosystem-aware | ecosystem-aware | ⚠️ CPE → noisy | ecosystem-aware |
| **EOL** (end-of-life) detection | ✅ endoflife.date | ❌ | ❌ | ❌ | ❌ | ~ |
| **Outdated / deprecated** | ✅ registries + curated | ❌ | ❌ | ❌ | ❌ | ~ |
| Containers / OS packages | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| SBOM (CycloneDX/SPDX) | ❌ | ✅ | ✅ | ✅ (Syft) | ~ | ✅ |
| License compliance | ❌ | ~ | ✅ | ~ | ❌ | ✅ |
| EPSS / KEV prioritization | ❌ | ~ | ✅ | ✅ | ❌ | ✅ |
| Auto-remediation / PRs | ❌ (fix recipes only) | ✅ `fix` | ❌ | ❌ | ❌ | ✅ |
| Offline | ✅ cache | ✅ local DB | ✅ | ✅ | ✅ feed | ❌ mostly online |
| **Scan without exposing the codebase**³ | ✅ anonymized descriptor | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Maven private-dep cleanup** (→ Snyk) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Output | self-contained **HTML + Word `.doc`** | table/JSON/SARIF | table/JSON/SARIF | table/JSON/SARIF | HTML/XML/JSON | JSON / cloud UI |

¹ Narrower language coverage — no Go/Rust/Ruby/Dart.
² Reading **lockfiles** without a build is the norm today: OSV-Scanner, Trivy and Grype/Syft
do it too. For **Maven `pom.xml`** specifically, *every* tool — `fad-checker` included — must
reach Maven Central (or rely on a real build / CycloneDX SBOM) to resolve transitive versions;
Trivy can resolve wrong transitive versions in that mode, while `fad-checker` flags what it
can't resolve in chapter 0. The genuine "no build" win is **vs Snyk** (requires building the
project) and **OWASP DC** (needs Maven Central access for Java accuracy).
³ Phase 1 exports only public coordinates; the online scan never sees your source tree —
see [Air-gapped / PASSI](#air-gapped--passi-audits-anonymized-dependency-descriptor). OSV-Scanner
has an offline mode, but it still needs the **source on the scanning machine**.

**Where it fits:** a one-shot audit of a polyglot checkout you may not be able to build, a
presentable HTML/Word deliverable, and confidential / air-gapped engagements.
**Where it doesn't:** continuous CI supply-chain security, container/OS scanning, SBOM
pipelines, license/EPSS gating, auto-fix PRs — reach for **Trivy** or **Grype + Syft**.

You don't have to choose — `fad-checker` takes Snyk's results as input (`--snyk`) and merges them.

> Sources: [OSV-Scanner lockfiles](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/) ·
> [Trivy Java/`pom.xml` (Maven Central, `--offline-scan`)](https://trivy.dev/docs/latest/coverage/language/java/) ·
> [Syft `java-pom-cataloger` (source dirs)](https://github.com/anchore/syft/issues/676) ·
> [OWASP DC needs internet/build for Java](https://jeremylong.github.io/DependencyCheck/data/index.html) ·
> [Snyk requires building the project](https://docs.snyk.io/supported-languages/technical-specifications-and-guidance) ·
> [EOL/outdated "most tools skip" (Aikido)](https://www.aikido.dev/code/outdated-eol-software)

---

## Docs

- [`docs/USAGE.md`](docs/USAGE.md) — every flag, every workflow, examples.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — internals: codecs, collection, matching, report pipeline.
- [`CHANGELOG.md`](CHANGELOG.md) — release history.
- [`CLAUDE.md`](CLAUDE.md) — code-level orientation for contributors.

---

## License

MIT — see [`LICENSE`](LICENSE).
