# fad-check

> **F**ucking **A**utonomous **D**ependency **C**hecker
>
> One CLI, every ecosystem, zero build tools required.

`fad-check` scans **Maven**, **npm**, **Yarn** and **vendored JavaScript** in any source tree — multi-module, monorepo, polyglot, whatever you've got — and produces a single self-contained HTML report with CVE, EOL, obsolete and outdated findings, plus per-ecosystem fix recipes.

It runs against the source files alone. **No `mvn`, no `npm install`, no `yarn`, no Docker.** It reads `pom.xml`, `package-lock.json` and `yarn.lock` directly.

> **Currently supported ecosystems: Maven, npm, Yarn (v1).** Vendored JS (jQuery, Bootstrap, PDF.js, etc.) is also scanned via retire.js. Yarn v2/Berry and pnpm are not yet supported — they're surfaced as warnings in chapter 0 so you know they were skipped.

---

## Why "Autonomous"?

Because it doesn't need anything you don't already have on disk:

| You don't need | Why |
| --- | --- |
| Maven installed | `pom.xml` files are parsed directly with xml2js. Properties, profiles and local BOMs are resolved in-process. Transitive deps fetched from Maven Central if `--transitive` (cached forever). |
| `mvn dependency:tree` | Same as above. We walk the tree ourselves. |
| `npm install` / a `node_modules/` | `package-lock.json` (v1/v2/v3) and `yarn.lock` v1 are parsed as text/JSON. Versions come from the lockfile — no installation. |
| `yarn install` | Same. We read `yarn.lock` v1. |
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
| **4. EOL frameworks** | endoflife.date | Spring Boot 2.5, Hibernate 4.x, EOL JDKs, etc. |
| **5. Obsolete libraries** | curated list (`data/known-obsolete.json`) | log4j 1.x, jackson-mapper-asl, joda-time, commons-httpclient 3.x, … |
| **6. Outdated libraries** | Maven Central Solr API | Available newer versions, with release dates |
| **7. Fix Recommendations** | computed | Per-ecosystem pin recipes: Maven `<dependencyManagement>`, npm `overrides`, yarn `resolutions` |

The HTML report opens in any browser, contains every detail (CVSS vectors, references, full descriptions, CPE configurations, via-paths for transitives) and ships a Word-compatible `.doc` twin.

---

## Quick start

```bash
npm install -g fad-check
fad-check -s ./my-project
```

That's it. The report lands in `./fad-check-report/cve-report.html`.

Want a 10× faster NVD enrichment? [Get a free NVD API key](https://nvd.nist.gov/developers/request-an-api-key) (instant), then:

```bash
fad-check --set-nvd-key YOUR_KEY
```

---

## Common runs

```bash
# Read-only full scan (default: all sources on)
fad-check -s ./proj

# Exclude private/internal libs by groupId regex
fad-check -s ./proj -e "^(com\.acme|org\.private)\."

# Also write cleaned POMs (private deps stripped, ready for Snyk)
fad-check -s ./proj -t ../proj-clean -e "^com\.acme\."

# Then run Snyk on the cleaned tree and merge findings
fad-check -s ./proj -t ../proj-clean -e "^com\.acme\." --snyk

# Faster: skip Maven Central / no transitive walk
fad-check -s ./proj --no-all-libs --no-transitive

# Fully offline (uses cached data only)
fad-check -s ./proj --offline

# Only one ecosystem
fad-check -s ./proj --ecosystem maven   # or npm | both | auto (default)
```

Run `fad-check --help` for the full flag list.

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
npm install -g fad-check
```

### From source

```bash
git clone <repo-url> fad-check
cd fad-check
npm install
node fad-check.js --help
```

### Single-binary build (no Node required)

```bash
npm install        # one-time, brings in bun
npm run build      # → dist/fad-check-linux + dist/fad-check.exe
```

### Shell completion

```bash
fad-check --completion bash > /etc/bash_completion.d/fad-check
# or for zsh:
fad-check --completion zsh  > ~/.zsh/completions/_fad-check
```

---

## How it scans without any build tool

This is the surprising bit. The whole point is that you can run `fad-check` against a *checkout* with no build environment.

- **Maven** — `pom.xml` files are parsed with xml2js. Property substitution (`${jackson.version}`), parent inheritance, local BOM imports (`<scope>import</scope>`) and every profile are resolved in-process. Transitive deps are walked by fetching child POMs from Maven Central (cached forever — POMs are immutable). When the project uses an **external BOM** (`spring-boot-dependencies` etc.), the deps whose version comes from that BOM can't be resolved without `mvn` itself — those are surfaced in chapter 0 as "unresolved-versions" so you know what's missing.
- **npm / Yarn** — `package-lock.json` (v1, v2, v3) and `yarn.lock` v1 are parsed directly. Lockfiles already contain every transitive version. No `node_modules/` traversal, no `npm install`. A package.json *without* a sibling lockfile is intentionally skipped (its ranges aren't queryable) and reported in chapter 0.
- **Vendored JavaScript** — `retire.js` shells out and scans `.js` / `.min.js` files by signature, catching old jQuery / Bootstrap / Angular / PDF.js copies that no lockfile knows about.
- **CVE data** — three independent sources merged:
  - **CVEProject** (the canonical `cvelistV5` bundle, filtered to Maven-relevant entries)
  - **OSV.dev** (Google + GitHub Security Lab, multi-ecosystem)
  - **NVD** (official NIST records, used for enrichment: full CVSS, references, CPE configurations)
- **CPE refinement** — once a CVE is matched, its NVD CPE configurations are checked against the dep version range. A match outside the vulnerable range is flagged `cpeFiltered: true` (likely false positive). A curated `data/cpe-coord-map.json` maps CPE `vendor:product` to Maven `g:a` (60+ entries seeded: log4j, jackson, spring, tomcat, jetty, netty, …).

---

## Caching

All cached data lives in `~/.fad-check/`:

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
| User config (NVD key) | `config.json` (mode 0600) | — |

Export the lot to share between machines:

```bash
fad-check --export-cache fad-cache.tar.gz
# on the other box:
fad-check --import-cache fad-cache.tar.gz
```

`--include-config` ships the NVD API key too (off by default).

---

## Safety rails

Built-in guardrails that fire **before** any disk write:

- `--target` is required unless you're running read-only (no `-t`).
- `--target` may not equal or be a subdirectory of `--src`.
- `--target` is `rimraf`'d before being rewritten — never point it at anything precious.

---

## Compared to…

| Tool | What `fad-check` adds |
| --- | --- |
| `mvn dependency:tree` | No Maven needed; multi-source CVE scan; HTML report |
| `npm audit` | Polyglot (Maven + npm + vendored JS in one report); EOL & obsolete checks; works without `npm install` |
| Snyk CLI | Free; offline-capable; integrates Snyk's results if you have it |
| OWASP DC | Faster (cached); cleaner UI; multi-source dedup |

You don't have to choose — `fad-check` will use any of them as input (`--snyk`) and merge results.

---

## Docs

- [`docs/USAGE.md`](docs/USAGE.md) — every flag, every workflow, examples.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — internals: collection, matching, report pipeline.
- [`CLAUDE.md`](CLAUDE.md) — code-level orientation for contributors.

---

## License

MIT — see [`LICENSE`](LICENSE).
