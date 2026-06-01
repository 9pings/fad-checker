# Design — dep-scan parity features for fad-checker

Date: 2026-06-01
Status: approved (user granted full autonomy to implement → deliver)

## Goal

Close the most valuable gaps between fad-checker and OWASP dep-scan, without
disturbing the codec architecture. Four feature groups:

1. **Prioritisation sources** — EPSS (FIRST.org) + CISA KEV, plus a composite
   priority score.
2. **License scan** — per-codec license detection + SPDX normalisation + a
   copyleft policy, rendered as a new report chapter.
3. **SBOM export** — CycloneDX 1.6 JSON with vulnerabilities inline (VDR/VEX).
4. **VEX export** — CSAF 2.0 `csaf_vex` document.

Explicitly **out of scope**: a direct GitHub Security Advisory (GHSA) source
(OSV already aggregates GHSA — adding a GH-token source is redundant),
reachability analysis, OS/container/Kubernetes scanning. These remain
dep-scan differentiators we intentionally do not chase here.

## Principles

- Reuse existing patterns: cache `{_schema,_fetchedAt,body}` + TTL, injectable
  `fetcher` for tests, `--offline` umbrella + per-source `--no-*` toggles,
  `onProgress` for the progress UI, pure extractor + cached driver split.
- New ecosystem-agnostic services attach data onto the existing `match` object
  (`{ dep, cve, confidence, source, ... }`) the same way `lib/nvd.js` does.
- New codec capability is **optional** (like `nativeScanners`) so existing
  codecs and `assertCodecShape()` are untouched.
- No `process.exit` mid-pipeline; a failing step logs and the report still
  renders. TDD: a `node:test` file per new module, fetcher mocked.

---

## 1. EPSS + CISA KEV + composite priority

### lib/epss.js
- `enrichEpss(matches, opts) → matches` (mutates in place).
- Source: `https://api.first.org/data/v1/epss?cve=CVE-a,CVE-b,…` (batch ≤100).
- Cache: `~/.fad-checker/epss-cache.json`, shape `{ meta:{fetchedAt}, entries:{ "CVE-…": {score, percentile} } }`, **TTL 24 h** (EPSS recomputed daily).
- Attaches `m.cve.epssScore` (0–1 float) and `m.cve.epssPercentile` (0–1).
- Respects `offline` (cache-only), injectable `fetcher`, `onProgress`.
- Pure helper `parseEpssResponse(json) → Map<cveId,{score,percentile}>` (unit-tested without network).

### lib/kev.js
- `enrichKev(matches, opts) → matches`.
- Source: single CISA catalogue `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
- Cache: `~/.fad-checker/kev-cache.json`, shape `{ _fetchedAt, body:{cveIDs:[…], byId:{…}} }`, **TTL 24 h**.
- Attaches `m.cve.kev = true`, `m.cve.kevDateAdded`, `m.cve.kevDueDate`, `m.cve.kevRansomware` when the CVE is in the catalogue.
- Pure helper `indexKevCatalog(json) → {set, byId}`.

### lib/priority.js (pure, no I/O)
- `computePriority(cve) → { score, band, sortKey }`.
  - `band`: `"exploited"` (KEV true) > `"critical"`/`"high"`/`"medium"`/`"low"` derived from a blended figure.
  - Blended numeric `score` 0–100: base = CVSS×10 (fallback severity→score), boosted by EPSS percentile, hard-overridden to ≥90 + band `exploited` when KEV.
  - `sortKey`: tuple `[kev?1:0, epssPercentile, cvssScore]` for stable descending sort.
- `attachPriority(matches)` sets `m.cve.priority = computePriority(m.cve)` for every match; called once after EPSS+KEV enrichment.
- `sortByPriority(matches)` — descending by priority then CVE id.

### Wiring (fad-checker.js, inside runReportFlow)
- New flags: `--no-epss`, `--no-kev`. Both also gated by `--offline` (cache-only).
- New pipeline steps after NVD enrichment + CPE refinement (~line 606), before
  the prod/dev split. Each is a `progress.start(...)` step counted in `totalSteps`:
  - `willEpss = !!options.epss` ; `willKev = !!options.kev`.
  - Run `enrichEpss` then `enrichKev`, then `attachPriority(cveMatches)`.
- The CLI "Results" headline and the report tables sort by priority; KEV shows a
  badge, EPSS shows percentile.
- `mergeBySource` already merges `cve` fields, so EPSS/KEV survive merges.

### Report (lib/cve-report.js)
- `renderCveRow` / `renderCveTable`: add an **EPSS** column (percentile %) and a
  **KEV** badge cell (🛑 when exploited). `renderDetailPanel` shows EPSS score +
  percentile and KEV dates/ransomware flag.
- New "Priority" summary card (count of exploited/KEV findings).
- Table default sort switches from severity to `priority.sortKey`.

---

## 2. License scan (detection + copyleft policy)

### Codec capability (optional)
- New optional method `checkLicenses(resolvedDeps, opts) → { licensed: [{ dep, licenses:[spdxId], source, raw }] }`.
- Added to `lib/codecs/codec.interface.js` as a **known-optional** key (documented;
  not in `REQUIRED_KEYS`). `assertCodecShape` unchanged.
- Implementations:
  - **npm** (`lib/codecs/npm/registry.js`): extract `packument.license` /
    `versions[v].license` (already fetched — no extra request). Reuse cache; add
    `license` to cached entry (bump cache shape tolerated via `||`).
  - **pypi** (`lib/codecs/pypi/registry.js`): `info.license` + `info.classifiers`
    (`License :: OSI Approved :: …`).
  - **composer** (`lib/codecs/composer/registry.js`): version `license` array.
  - **nuget** (`lib/codecs/nuget/registry.js`): `catalogEntry.licenseExpression`
    (best-effort; older packages expose only `licenseUrl` → unknown).
  - **maven** (`lib/codecs/maven.codec.js`): `<licenses><license><name>` from the
    POM; local POM first, else Maven Central POM via the `transitive.js` cache.
    Best-effort (often inherited → unknown).

### lib/license-policy.js + data/license-policy.json
- `normalizeSpdx(raw) → spdxId|null` — maps common free-form strings
  ("Apache 2.0", "The MIT License", "BSD-3", "GNU GPLv3") to SPDX ids; handles
  `OR`/`AND`/`WITH` expressions by splitting and classifying each.
- `classify(spdxId) → category` where category ∈
  `permissive | weak-copyleft | strong-copyleft | network-copyleft | proprietary | unknown`.
- `data/license-policy.json`: id→category table + alias map (data-driven, editable).
- `assessLicenses(licensedFindings) → { byCategory, flagged }` where `flagged`
  are strong/network copyleft + unknown.

### Wiring
- New flag `--no-licenses` (on by default when online; cache-only offline).
- New step in `runReportFlow` after the registry steps: for each active codec
  with `checkLicenses`, gather findings; pass `licenseResults` to `writeReports`.
- `lib/cve-report.js`: new chapter **"Licenses"** grouped by category, copyleft
  strong/network highlighted; a summary card for "copyleft / unknown licenses".
  Added to the ToC and executive summary counts.

---

## 3. lib/purl.js (shared) + lib/sbom-export.js

### lib/purl.js (pure)
- `purlFor(dep) → "pkg:type/namespace/name@version"`.
  - type map: maven→`maven` (namespace=groupId, name=artifactId),
    npm→`npm` (scope kept in name), composer→`composer`, pypi→`pypi`,
    nuget→`nuget`.
  - URL-encode per the purl spec; omit version when null.
- Unit-tested across all five ecosystems incl. scoped npm + maven coords.

### lib/sbom-export.js
- `buildCycloneDx(resolvedDeps, cveMatches, meta) → object` (pure, testable).
- `writeCycloneDx(resolvedDeps, cveMatches, outputPath, meta)` writes JSON.
- CycloneDX **1.6**: `bomFormat`, `specVersion:"1.6"`, `metadata.tools` (fad-checker + version),
  `components[]` (type `library`, `bom-ref`=purl, `purl`, `name`, `version`, `group`,
  `licenses[]` when known), `vulnerabilities[]` from matches:
  `id` (CVE), `source`, `ratings[]` (CVSS score/severity/vector/method),
  `cwes[]`, `affects[{ref:purl}]`, `properties[]` for `fad:epss`,
  `fad:epssPercentile`, `fad:kev`, `fad:priorityBand`.
- Dedup vulnerabilities by CVE id; aggregate affected refs.

### Wiring
- Flag `--export-sbom <file>`; after `writeReports()` in `runReportFlow`, call
  `writeCycloneDx(resolved, cveMatches, options.exportSbom, {projectInfo})`.
  (Uses the full `cveMatches` incl. dev + cpeFiltered, with a property marking FP.)

---

## 4. lib/csaf-export.js

- `buildCsaf(resolvedDeps, cveMatches, projectInfo) → object` (pure).
- `writeCsaf(resolvedDeps, cveMatches, projectInfo, outputPath)`.
- CSAF 2.0 `csaf_vex`:
  - `document`: `category:"csaf_vex"`, `csaf_version:"2.0"`, `title`,
    `publisher` (category `vendor`, name `fad-checker`), `tracking`
    (id, dates from `projectInfo.generatedAt`, version, status `final`).
  - `product_tree.full_product_names[]`: one per dep, `product_id` = stable slug,
    `product_identification_helper.purl` = purl.
  - `vulnerabilities[]`: per CVE, `cve`, `notes` (description),
    `product_status.known_affected` = product_ids, `scores[]` (CVSS),
    `flags`/`threats` carrying EPSS/KEV context where present.
- Reuses `lib/purl.js` and `computePriority`.

### Wiring
- Flag `--export-csaf <file>`; called alongside the SBOM export.

---

## Files touched

New: `lib/epss.js`, `lib/kev.js`, `lib/priority.js`, `lib/license-policy.js`,
`lib/purl.js`, `lib/sbom-export.js`, `lib/csaf-export.js`,
`data/license-policy.json`.
New tests: `test/epss.test.js`, `test/kev.test.js`, `test/priority.test.js`,
`test/license-policy.test.js`, `test/purl.test.js`, `test/sbom-export.test.js`,
`test/csaf-export.test.js`, plus license-extraction cases in the existing
registry tests.
Edited: `fad-checker.js` (flags + wiring), `lib/cve-report.js` (EPSS/KEV columns,
priority sort, license chapter), each `*/registry.js` + `maven.codec.js`
(`checkLicenses`), `lib/codecs/codec.interface.js` (doc the optional key),
`CLAUDE.md`, `docs/USAGE.md`, `docs/ARCHITECTURE.md`, `README.md`.

## Implementation order (independent, each ends green)

1. `purl.js` (+test) — needed by SBOM & CSAF, zero deps.
2. `epss.js`, `kev.js`, `priority.js` (+tests) + wiring + report columns/sort.
3. `license-policy.js` + `data/license-policy.json` + per-codec `checkLicenses`
   (+tests) + report chapter + wiring.
4. `sbom-export.js` + `csaf-export.js` (+tests) + export flags.
5. Full-suite regression run (`node --test test/*.test.js`), real end-to-end run
   on a fixture (`polyglot`) verifying flags + generated files.
6. Docs/README update.

## Regression strategy

- Every new module ships its own `node:test` file with a mocked `fetcher`.
- After each phase, run the **full** suite, not just the new file.
- End-to-end: run the CLI offline against `test/fixtures/polyglot` with
  `--export-sbom`/`--export-csaf` and assert the files parse as valid JSON of
  the expected shape; run once more without the new flags to confirm the
  baseline report is unchanged in structure.
- New flags default ON when online but degrade to cache-only under `--offline`
  and are individually disableable, so existing invocations behave the same
  (modulo the extra enrichment columns).
