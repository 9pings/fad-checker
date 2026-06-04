# fad-checker

[![npm version](https://img.shields.io/npm/v/fad-checker.svg)](https://www.npmjs.com/package/fad-checker)
[![npm downloads](https://img.shields.io/npm/dm/fad-checker.svg)](https://www.npmjs.com/package/fad-checker)
[![license](https://img.shields.io/npm/l/fad-checker.svg)](https://github.com/n8tz/fad-checker/blob/main/package.json)
[![node](https://img.shields.io/node/v/fad-checker.svg)](https://nodejs.org)

> **F**abulous **A**utonomous **D**ependency **C**hecker<br>
> AKA **F**uckin' **A**utonomous **D**ependency **C**hecker<br>

`fad-checker` scans **Maven**, **npm**, **Yarn**, **Composer (PHP)**, **PyPI (Python)**, **NuGet (C#/.NET)**, **Go**, **Ruby**, **vendored JavaScript** and **committed native binaries** in any source tree — multi-module, monorepo, polyglot, whatever you've got — and produces a single self-contained HTML report with CVE (prioritised by **EPSS + CISA KEV**), EOL, obsolete, outdated and **license** findings, plus per-ecosystem fix recipes. It also exports a **CycloneDX 1.6 SBOM** and a **CSAF 2.0 VEX**.


🌐 **[Project site & docs →](https://n8tz.github.io/fad-checker/)**

<p align="center"><img src="docs/assets/cli.png" alt="fad-checker terminal output — a [n/N] checklist warming each vulnerability database, then CVE findings coloured by severity" height="760"></p>

It runs against the source files alone. **No `mvn`, no `npm install`, no `composer install`, no `pip`, no `dotnet restore`, no Docker.** It reads `pom.xml`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `composer.lock`, `poetry.lock`/`Pipfile.lock`/`uv.lock`/`pdm.lock`/`pyproject.toml`/`requirements.txt`, and `packages.lock.json`/`*.csproj`/`*.fsproj`/`*.vbproj`/`packages.config` directly.

> **Supported ecosystems: Maven, npm, Yarn (v1 + Berry/v2+), pnpm, Composer, PyPI, NuGet, Go, Ruby + committed native binaries.** Each is a self-contained **codec** (`lib/codecs/`) — adding another is adding a codec, no orchestrator surgery. Vendored JS (jQuery, Bootstrap, PDF.js, etc.) is also scanned via retire.js. **Embedded JARs** committed into the tree — vendored libs, Spring-Boot fat-jars, shaded uber-jars inside `.jar`/`.war`/`.ear` — are unzipped in-memory and their Maven coordinates scanned too (disable with `--no-jars`). **Committed native binaries** (`.dll`/`.exe`/`.so`/`.dylib`) are detected (magic-byte confirmed, so images/assets are never picked up) and **identified by checksum** via deps.dev + CIRCL — to flag tampered/unknown files and libraries that ought to be declared dependencies (disable with `--no-binaries`).

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
| `go build` / a Go toolchain | `go.mod` is parsed (the full pruned graph on Go ≥1.17, `// indirect` → transitive); `go.sum` is the fallback. No module download. |
| `bundle install` | `Gemfile.lock` is parsed for the resolved gem set. No Ruby, no bundler. |
| `snyk` binary | Built-in CVE matching via CVEProject + OSV + NVD (merged), prioritised with EPSS + CISA KEV (see below). Snyk is *optional* (`--snyk`). |
| A network connection | First run downloads CVE / OSV / EOL data; subsequent runs use cached copies (`--offline` to force). |

Exactly **one** runtime dependencies must be on PATH (or installed automatically through npm): Node ≥ 20. Everything else is bundled or fetched lazily.

---

## What it finds

| Chapter | Source | What it catches |
| --- | --- | --- |
| **0. Warnings** | local heuristics | Missing lockfiles, unresolved Maven versions (BOM-managed), private libs not on Maven Central |
| **1. CVE (production)** | CVEProject + OSV.dev + NVD + CPE | Public CVE / GHSA in production deps, per ecosystem, per manifest file — each row **prioritised** by CISA KEV + EPSS + CVSS |
| **1B. Embedded binaries** | same, on coords read from archives | CVEs in libraries **shipped inside committed `.jar`/`.war`/`.ear`** (vendored libs, Spring-Boot fat-jars, shaded uber-jars) — not declared in any `pom.xml`. Grouped by containing archive |
| **1C. Unmanaged / vendored binaries** | deps.dev + CIRCL (by checksum) | Committed **native binaries** (`.dll`/`.exe`/`.so`/`.dylib`) no package manager governs — identified by hash, flagged **should-be-managed** (exists in a registry), **name≠checksum** (filename disagrees with the hash), **unknown** (no source knows it) or **malicious** (free CIRCL signal) |
| **1D. Unmanaged / vendored JavaScript** | [retire.js](https://retirejs.github.io/) (`--verbose`) | **Inventory of every standalone JS lib** committed into the tree (jQuery, Bootstrap, PDF.js, …) that no package manager governs — vulnerable *or not*. A cyber-hygiene constat: unknown provenance/integrity/patch story. `--no-vendored-js-inventory` to skip |
| **2. Vendored JS (vulnerable)** | [retire.js](https://retirejs.github.io/) | The subset of the above with known CVEs/advisories — old jQuery/Bootstrap/Angular/PDF.js copies with no lockfile |
| **3. CVE in dev deps** | same | Same as chapter 1, but for `test`/`provided` (Maven) and `dev`/`optional`/`peer` (npm) |
| **Supply-chain risk** | OSV `MAL-…` + name heuristic | **Known-malicious** packages (always block the CI gate, any `--fail-on` level) and **suspected typosquats** (`--typosquat`: an npm/PyPI name one edit from a popular package — `lodahs`↔`lodash`) |
| **4. EOL frameworks** | endoflife.date | Spring Boot 2.5, Hibernate 4.x, EOL JDKs, AngularJS, Laravel/Symfony, Django, .NET, etc. |
| **5. Obsolete libraries** | curated list (Maven) + registry maintainer flags | log4j 1.x, jackson-mapper-asl, joda-time, …; npm `deprecated`, Composer `abandoned`, PyPI `yanked`/inactive, NuGet `deprecation` |
| **6. Outdated libraries** | Maven Central + npm / Packagist / PyPI / NuGet registries | Available newer versions, with release dates |
| **7. Licenses** *(opt-in: `--licenses`)* | registry metadata + Maven POMs → SPDX policy | Each dep's license normalised to SPDX and classified; copyleft (GPL/AGPL/LGPL/MPL), proprietary and unknown flagged for review |
| **8. Fix Recommendations** | computed | Per-ecosystem pin recipes: Maven `<dependencyManagement>`, npm `overrides`, yarn `resolutions`, `composer require`, `pip install`, `dotnet add package` |

The HTML report opens in any browser, contains every detail (CVSS vectors, references, full descriptions, CPE configurations, via-paths for transitives) and ships a Word-compatible `.doc` twin. Every match carries a **composite priority** (KEV-exploited > EPSS likelihood > CVSS severity), and the run can additionally emit a **CycloneDX 1.6 SBOM** (`--report-sbom`, vulnerabilities inline) and a **CSAF 2.0 VEX** (`--report-csaf`) for downstream tooling.

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

# Exclude private/internal libs by groupId/name regex
fad-checker -s ./proj -e "^(com\.acme|org\.private)\."

# Ignore whole sub-paths during the walk (gitignore-style glob, relative to -s)
fad-checker -s ./proj --exclude-path "packages/legacy/**" --exclude-path "**/fixtures/**"
fad-checker -s ./proj --no-default-excludes          # walk everything (incl. node_modules/.git)

# Also write cleaned POMs (private deps stripped, ready for Snyk)
fad-checker -s ./proj -t ../proj-clean -e "^com\.acme\."

# Then run Snyk on the cleaned tree and merge findings
fad-checker -s ./proj -t ../proj-clean -e "^com\.acme\." --snyk

# Faster: skip Maven Central / no transitive walk
fad-checker -s ./proj --no-all-libs --no-transitive

# Fully offline (uses cached data only) — zero network, guaranteed (see Air-gapped below)
fad-checker -s ./proj --offline

# Offline-COMPLETE OSV recall (Maven): import the full OSV DB once, then match offline
# regardless of the per-dep cache (the OSV-Scanner air-gap model)
fad-checker -s ./proj --osv-db                     # online: download (~9 MB) + match
fad-checker -s ./proj --osv-db --offline           # offline: match against the imported DB

# Supply-chain risk: known-malicious packages always flagged; add the typosquat heuristic
fad-checker -s ./proj --typosquat

# License + copyleft-policy chapter (off by default)
fad-checker -s ./proj --licenses

# Pick ecosystems — --ecosystem is a list: auto (default) | all | comma list
fad-checker -s ./proj --ecosystem maven            # Maven only
fad-checker -s ./proj --ecosystem maven,npm,pypi   # several
fad-checker -s ./proj --no-nuget --no-composer     # or opt out per codec
fad-checker -s ./proj --no-binaries                # skip the native-binary scan

# Private registry + reusable defaults (see "Configuration file & environment")
fad-checker --add-repo npm verdaccio https://npm.acme.com/ --token "$NPM_TOKEN"
fad-checker --config ./ci/fad-env.json             # all options from a JSON file
fad-checker --source ./proj                        # --source / --src are aliases
```

Run `fad-checker --help` for the full flag list.

---

## What a report looks like

<p align="center"><img src="docs/assets/report.png" alt="fad-checker HTML report — executive summary with severity tiles and a detailed CVE table with CWE, descriptions and fix versions" width="900"></p>

The console prints a summary; the full detail lives in the self-contained HTML/`.doc`:

```
╭───────────────────────────────────────────────────╮
│ fad-checker v2.2.1 · Autonomous Dependency Checker │
╰───────────────────────────────────────────────────╯
Executive Summary [CRITICAL] — 1708 dependencies scanned
  • 81 CVE in production deps (critical=5, high=53, medium=12, low=11)
  • 32 CVE in dev/test deps · 17 vulnerable vendored JS (retire.js)
  • 2 EOL frameworks · 13 obsolete/deprecated · 172 outdated
  • 4 scan-completeness alerts — see chapter 0
```

The HTML report organises this into chapters (0 Warnings, 1 CVE prod, 1B embedded JARs,
1C native binaries, 1D vendored-JS inventory, 2 vendored-JS vulns, 3 dev CVE, 4 EOL,
5 obsolete, 6 outdated, 7 Licenses *(opt-in)*, 8 Fix Recommendations), each grouped by
ecosystem and manifest. Every CVE row carries: severity badge · CVE/GHSA id · coord &
version · declaring manifest · source(s) · fix-version · priority (KEV/EPSS) — click for
the full panel (CVSS vectors, references, transitive paths, CPE configs).

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

**TL;DR** — `fad-checker` never runs your build. For each ecosystem it reads the **lockfile** (or, failing that, the manifest's pinned versions) straight off disk to learn the exact dependency versions, then matches those coordinates against vulnerability/EOL/registry data over the network (cached, `--offline`-able). No `mvn`, `npm install`, `pip`, `dotnet restore`, `go build` or `bundle` — and no `node_modules/`.

| Ecosystem | Read directly | Transitive versions come from |
| --- | --- | --- |
| Maven | `pom.xml` (+ parents, BOMs, profiles) | child POMs fetched from Maven Central (cached) |
| npm / Yarn / pnpm | `package-lock.json` · `yarn.lock` (v1+Berry) · `pnpm-lock.yaml` | the lockfile itself |
| Composer | `composer.lock` (else `composer.json`) | the lockfile |
| PyPI | `poetry.lock` · `Pipfile.lock` · `uv.lock` · `pdm.lock` (else `pyproject.toml`/`requirements.txt`) | the lockfile |
| NuGet | `packages.lock.json` (else `*.csproj`/`packages.config`) | the lockfile |
| Go | `go.mod` (`// indirect` → transitive; `go.sum` fallback) | the module graph in `go.mod` |
| Ruby | `Gemfile.lock` (`specs:`) | the lockfile |
| Vendored JS / binaries | the committed `.js` / `.jar` / `.so` files themselves | n/a (read in place) |

Highlights of the matching layer: **three CVE sources merged** (CVEProject + OSV.dev + NVD), **CPE/version cross-check** to drop false positives, **EPSS + CISA KEV** prioritisation, lockfile-first with a **best-effort pinned-version fallback** when no lockfile, in-memory **embedded-JAR** unzip (no disk, no zip-slip), and **checksum identity** for native binaries. Outputs: HTML + `.doc` by default, plus opt-in `--report-sbom`/`-csaf`/`-json`/`-sarif`; CI gating via `--fail-on` with `--ignore`/`--vex` triage.

Two things set the Maven path apart for multi-module / air-gapped work:

- **Per-module version mediation** (automatic). The global transitive pass resolves the whole reactor as one tree; that can let a `<dependencyManagement>` pin in one module hide an *older, vulnerable* transitive of the same library in another module. fad re-resolves each module with **only its own** effective depMgmt and recovers those masked versions — on a real 25-module project that lifted Snyk-corroborated coverage **156 → 181**, recovering CVEs (e.g. `poi 3.11` / CVE-2017-12626) that a single Snyk scan of the tree missed.
- **Offline-complete OSV** (`--osv-db`). Imports the full OSV database (Maven) once, then matches every dep against it offline — so air-gapped recall no longer depends on which deps the per-dep OSV cache happened to warm (the [OSV-Scanner](https://github.com/google/osv-scanner) `--download-offline-databases` model). On a cold-cache offline run that's the difference between **6** and **117** of 202 findings covered.

> Full per-ecosystem and per-stage detail lives in **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)** and **[`docs/USAGE.md`](docs/USAGE.md)**.

---

## Caching

All cached data lives in `~/.fad-checker/` — every source is hit at most once per its
TTL (12 h–7 d, transitive POMs forever as they're immutable). Full per-cache TTL table
in [`docs/USAGE.md`](docs/USAGE.md). Export the lot to share between machines:

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

> **Zero-data-sent guarantee.** Under `--offline`, fad-checker makes **no network calls
> whatsoever** — it reads only the warmed `~/.fad-checker/` caches and never transmits a
> dependency, path or finding off the machine. It is regression-tested
> (`test/offline-guarantee.test.js`, a tripwire fetcher that throws if touched) and
> auditor-reproducible: `unshare -rn node fad-checker.js -s ./proj --offline …` runs it in a
> namespace with **no network interface** and yields byte-identical findings. Unlike the
> mainstream OSS scanners, fad also resolves the **Maven transitive graph** offline — so on
> an air-gapped multi-module project it finds the transitive CVEs they can't (see
> `docs/USAGE.md` → *Zero-data-sent guarantee*).

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

## Custom repositories & registries

Register private **Nexus / Artifactory / Verdaccio / devpi / GOPROXY** registries (for **`maven`, `npm`, `pypi`, `ruby`, `go`**) so transitive resolution, outdated/deprecation and license lookups reach them:

```bash
fad-checker --add-repo maven nexus https://nexus.acme.com/repository/maven-public/ --auth alice:s3cr3t
fad-checker --add-repo npm   verdaccio https://npm.acme.com/ --token "$NPM_TOKEN"
fad-checker -s ./proj --repo npm=https://npm.acme.com/        # one-off, repeatable
```

Tried in declared order, public registry last; auth via `--auth user:pass` / `--token TOK` / inline URL; responses cached per coordinate. NuGet/Composer private feeds aren't supported yet. **Full details, the PyPI/Ruby JSON-API caveat and `--list-repos`/`--remove-repo` → [`docs/USAGE.md`](docs/USAGE.md).**

---

## Configuration file & environment

Don't retype flags every run. Precedence: **CLI flag > `--config <file.json>` / `./.fad-env.json` (JSON, keys = camelCase options) > `FAD_CHECKER_ENV` (a string of CLI flags) > `~/.fad-checker/config.json` > defaults.** A file/env value only fills an option you didn't pass; **registries are merged across every layer**.

```bash
fad-checker --config ./ci/fad-env.json
FAD_CHECKER_ENV='--fail-on high --no-nuget' fad-checker -s ./proj
```

`-s` / `--src` / `--source` are aliases. **`-e/--exclude`** is a regex on the **coordinate** (drops deps); **`--exclude-path`** is a gitignore-style glob on the **path** (prunes the walk). Full `.fad-env.json` schema → [`docs/USAGE.md`](docs/USAGE.md).

---

## Data sources & acknowledgments

`fad-checker` is glue around several outstanding public datasets. Each is used per its license terms.

| Source | What we use | License | API / endpoint |
| --- | --- | --- | --- |
| [CVEProject `cvelistV5`](https://github.com/CVEProject/cvelistV5) | Daily bulk CVE bundle, filtered to Maven-relevant entries | CC0-1.0 | GitHub release asset (zip) |
| [OSV.dev](https://osv.dev/) (Google + GitHub Security Lab) | Per-dep vulnerability lookup (Maven, npm, Packagist, PyPI, NuGet, …) | CC-BY 4.0 | `POST api.osv.dev/v1/querybatch`, `GET api.osv.dev/v1/vulns/{id}` |
| [NIST NVD](https://nvd.nist.gov/) | Canonical CVE description + CVSS vectors + CPE configurations + CWE | US-gov public domain | `GET services.nvd.nist.gov/rest/json/cves/2.0?cveId=…` — free [API key](https://nvd.nist.gov/developers/request-an-api-key) bumps the rate limit 10× |
| [FIRST.org EPSS](https://www.first.org/epss/) | Exploit-prediction score + percentile per CVE | CC-BY 4.0 | `GET api.first.org/data/v1/epss?cve=…` (batched) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known-exploited-vulnerability catalogue membership | US-gov public domain | `GET cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| [endoflife.date](https://endoflife.date/) | Framework / runtime EOL cycle data | MIT | `GET endoflife.date/api/{product}.json` |
| [Maven Central](https://search.maven.org/) | Latest-version lookups + transitive POM fetches | Free public service | Solr `search.maven.org/solrsearch/select?q=…` + `repo1.maven.org/maven2/<coord>` |
| [npm registry](https://registry.npmjs.org/) | Per-version `deprecated` + `dist-tags.latest` | Free public service | `GET registry.npmjs.org/<pkg>` |
| [Packagist](https://packagist.org/) | Latest stable + `abandoned` flag | Free public service | `GET packagist.org/packages/<vendor>/<pkg>.json` |
| [PyPI](https://pypi.org/) | Latest + `yanked` + "Inactive" classifier | Free public service | `GET pypi.org/pypi/<pkg>/json` |
| [NuGet](https://www.nuget.org/) | Latest stable + per-version `deprecation` | Free public service | `GET api.nuget.org/v3/registration5-gz-semver2/<id>/index.json` |
| [Go module proxy](https://proxy.golang.org/) | Latest module version (outdated) | Free public service | `GET proxy.golang.org/<module>/@latest` |
| [RubyGems](https://rubygems.org/) | Latest stable + licenses | Free public service | `GET rubygems.org/api/v1/gems/<gem>.json` |
| [deps.dev](https://deps.dev/) | Native-binary identity by checksum (→ package coordinate) | Free public API (CC-BY) | `GET api.deps.dev/v3/query?hash.type=SHA1&hash.value=<base64>` |
| [CIRCL hashlookup](https://hashlookup.circl.lu/) | Known-good file identity (NSRL/distro/CDN) + KnownMalicious | Free public service | `GET hashlookup.circl.lu/lookup/sha256/<hash>` |
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
| Auto-remediation / PRs | ❌ (fix recipes only) | ✅ `fix` | ❌ | ❌ | ❌ | ✅ |
| Offline | ✅ cache | ✅ local DB | ✅ | ✅ | ✅ feed | ❌ mostly online |
| Offline Maven **transitive** graph³ | ✅ cached POMs | ❌ disabled offline | ❌ | ❌ | ⚠️ mirror | ❌ |
| **Scan without exposing the codebase**² | ✅ anonymized descriptor | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Maven private-dep cleanup** (→ Snyk) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Output | **HTML + Word `.doc`** + JSON / SARIF / CycloneDX / CSAF | table/JSON/SARIF | table/JSON/SARIF | table/JSON/SARIF | HTML/XML/JSON | JSON / cloud UI |

¹ Narrower language coverage — no Rust/Dart/Swift (Go and Ruby are now covered).

² Phase 1 exports only public coordinates; the online scan never sees your source tree —
see [Air-gapped / PASSI](#air-gapped--passi-audits-anonymized-dependency-descriptor). OSV-Scanner
has an offline mode, but it still needs the **source on the scanning machine**.

³ Measured on a 25-module Spring/JSF project, fully air-gapped: fad covered **181/202**
Snyk-corroborated findings vs OSV-Scanner v2.3.8's **64/202** — **0 on Maven**, because its
transitive resolution is disabled without network. fad resolves the Maven graph from cached
POMs (and `--osv-db` makes its offline OSV recall cache-independent).

**Where it fits:** a one-shot audit of a polyglot checkout you may not be able to build, a
presentable HTML/Word deliverable, and confidential / air-gapped engagements.

**Where it doesn't:** container/OS scanning,
reachability analysis, auto-fix PRs — reach for **Trivy** or **Grype + Syft**.

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
