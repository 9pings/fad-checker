# Spec — "Audit-pro" features (provenance, diff, methodology/integrity, private NuGet/Composer feeds)

Status: implemented · Author: fad-checker · Scope: features #1, #2, #7, #8 from the
professional-auditor gap analysis.

This spec documents **what** was built, the **design decisions** taken autonomously,
and **why**, so the implementation and tests are traceable to intent. It is the
"spec dev" deliverable; the code + tests are the contract.

---

## 1. Scan provenance / reproducibility manifest

**Problem.** A professional audit must be *defensible* and *reproducible*: months
later, a finding has to be explainable from the exact inputs that produced it, and a
second auditor must get the same result. Before this change the report only carried
`generatedAt`, `toolVersion`, and `cveDataDate` — not the state of OSV, NVD, KEV,
EPSS, endoflife, the Maven Central / npm caches, nor the run configuration.

**Solution.** A new pure module `lib/provenance.js` builds a **scan-provenance
manifest**: tool + version, generation time, runtime (node/platform/arch), the
run **mode** (offline or online), the run **configuration** (only the flags that
change *what is found* — active codecs, transitive on/off + depth, OSV/NVD/EPSS/KEV
toggles, licenses, typosquat, fail-on, ignore/vex in use, exclude-path,
default-excludes), and a **data-sources** table.

Each data source's freshness is read from its own cache file under `~/.fad-checker/`
(injected `cacheDir` so it is testable against a temp dir):

| Source | Cache file | "as of" marker |
|---|---|---|
| CVEProject Maven index | `cve-data/meta.json` | `builtAt` + `cveCount` |
| OSV.dev | `osv-cache/` | newest entry mtime + file count |
| OSV local DB | `osv-db/maven-index.json` | mtime |
| NIST NVD | `nvd-cache/` | file count (records cached) |
| EPSS | `epss-cache.json` | `meta.fetchedAt` |
| CISA KEV | `kev-cache.json` | `_fetchedAt` (+ catalog `dateReleased`/`catalogVersion`) |
| endoflife.date | `eol-cache.json` | `meta.fetchedAt` |
| Maven Central | `version-cache.json` | `meta.fetchedAt` |
| npm registry | `npm-registry-cache.json` | `meta.fetchedAt` |
| NuGet / Packagist / Go / RubyGems | `*-cache.json` | `meta.fetchedAt` |

Per-source `status` ∈ `disabled` (turned off by a flag this run) · `missing`
(no cache, source not warmed) · `cached` (present). The manifest never asserts
"online vs offline fetched this exact run" — it reports the **cache state**, which is
the reproducible truth and what `--offline` re-runs read from.

**Surfaced in:**
- `projectInfo.provenance` (assembled in `runReportFlow`),
- the findings JSON export top-level `provenance` block,
- the HTML/`.doc` report's Methodology chapter (feature #7).

**Decision — no `--snapshot` lockfile of sources (yet).** A true byte-for-byte
source pin (download-once, replay) is large; the cache archive (`--export-cache` /
`--import-cache`) already provides reproducibility on the same machine, and the
manifest makes the source state *legible*. A formal snapshot/lock is left as a
follow-up.

---

## 2. Diff / baseline (differential audit)

**Problem.** Repeat audits (retainers, CI) need "what changed since last time", and
the most useful CI gate is "fail on **new** findings", not an absolute threshold. The
findings JSON was advertised as diff-friendly but there was no diff.

**Solution.** A new pure module `lib/diff.js`:
- `findingKey(f)` — stable identity for a CVE finding: `id ∥ ecosystem ∥ coord ∥ version`.
- `diffFindings(baseDoc, curDoc)` — per category (`cve`, `eol`, `obsolete`,
  `outdated`, `licenses`) returns `{ added, removed, unchanged }`, plus a `summary`
  with counts (and a CVE severity breakdown of the added set). Suppressed /
  CPE-filtered CVE findings are excluded from the gate-relevant counts but still
  diffed.
- `summarizeDiff(diff)` — flat counts for printing.

**CLI surface:**
- Standalone subcommand `fad diff <baseline.json> <current.json>` (intercepted
  pre-parse, mirroring `--add-repo` / `--export-cache`): prints new/fixed/unchanged,
  lists the new CVE findings; `--report-json <out>` writes the diff document;
  `--fail-on-new` exits non-zero when there is ≥1 new production CVE finding.
- Main-run flag `--baseline <file>`: diff the current scan against a prior findings
  JSON, print the delta, embed a `diff` block in the JSON export. With
  `--fail-on-new` the gate fails on any new production finding (independent of, and
  combinable with, `--fail-on`).

**Decision — operate on the findings JSON, not a bespoke state file.** The export is
already the canonical, stable record; diffing it keeps one source of truth and lets
auditors diff any two historical reports.

---

## 7. Methodology, data sources & limitations chapter + report integrity

**Problem.** An audit deliverable must state its **methodology and limitations**
explicitly (what was *not* assessed — a scope/liability matter) and be **tamper-
evident** when handed to a client.

**Solution.**
- **Methodology chapter** (HTML/`.doc`, appendix 12): renders the provenance
  data-source table (with "as of" dates) + a curated, explicit **Limitations**
  list — fad-checker does **not** assess: reachability / exploitability in the
  running app, runtime configuration & mitigations, secrets, IaC / container base
  images, business-logic flaws, malware beyond the OSV `MAL-`/CIRCL signal, and it
  is not legal license advice; private coords absent from public registries can't be
  CVE-matched; results reflect the data-source state in the table. Plus a one-line
  "how to reproduce" hint.
- **Integrity manifest.** `lib/report-integrity.js` writes a `SHA256SUMS` file in the
  report directory listing the SHA-256 of every artifact written this run, in
  standard `sha256sum` format (`<hex>␠␠<relative-path>`), verifiable with
  `sha256sum -c SHA256SUMS`. On by default whenever ≥1 file is written; `--no-checksums`
  disables it.

**Decision — checksums, not signatures.** A detached cryptographic signature needs
key management/distribution that doesn't fit a zero-config CLI. A SHA-256 manifest is
standard, dependency-free, offline, and gives the client tamper-evidence; signing the
manifest with the auditor's own key is then a trivial external step.

---

## 8. Private NuGet / Composer registry feeds

**Problem.** NuGet and Composer were the only ecosystems whose registry lookups
(deprecation / outdated / license) had no private-feed support, silently degrading
coverage on enterprise repos that resolve .NET/PHP from internal Artifactory / Azure
Artifacts / Private Packagist / Satis.

**Solution.** Bring both in line with npm/pypi/ruby/go:
- `lib/registries.js`: add `nuget` and `composer` to `SUPPORTED` and `PUBLIC_BASES`
  (`https://api.nuget.org/v3/registration5-gz-semver2/`, `https://packagist.org/`).
- **NuGet** (`lib/codecs/nuget/registry.js`): `fetchRegistration` now tries
  `opts.registries` first (per-registry Basic/Bearer auth) then the public base,
  via the shared `withPublic`/`authHeaderFor` helpers. Custom feeds speak the NuGet
  v3 registration API; a base URL ending in `index.json` is treated as a **service
  index** and resolved to its `RegistrationsBaseUrl` resource (memoised).
- **Composer** (`lib/codecs/composer/registry.js`): custom registries are queried via
  the Composer **v2 metadata** endpoint `<base>/p2/<vendor>/<pkg>.json` and converted
  (`composerV2ToPackageObject`) into the same package-object shape `packagistToFindings`
  consumes; the public base keeps the rich `packages/<name>.json` Packagist API.
- The CLI already threads `registries: registriesFor(id)` into every codec's
  `checkRegistry`, and `--add-repo` / `--repo` validate against `SUPPORTED`, so
  enabling the two ecosystems there completes the wiring.

**Decision — same-API constraint, documented.** As with pypi/ruby, a custom NuGet base
must speak the v3 registration API and a custom Composer base the v2 `/p2/` metadata
API (a bare NuGet service index is auto-resolved). Translating arbitrary feed formats
is out of scope.
