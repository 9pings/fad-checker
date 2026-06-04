# Handoff — Maven *global version mediation* masks vulnerable transitive versions

Status: **OPEN / unsolved.** Two in-process fixes were attempted and reverted (see
"Failed approaches"). This doc is a clean-slate brief so the next attempt doesn't
repeat them. Date: 2026-06-04.

---

## 1. The problem (one sentence)

In a multi-module Maven build, when **module A** pins a library to a *new* version
(directly or via `<dependencyManagement>`) and **module B** pulls an *older*,
**vulnerable** version of the same library transitively, fad-checker reports only the
**new** version and **misses the CVE on the old one** — because it resolves the whole
reactor with one **global** dependency-management map instead of Maven's **per-module**
mediation.

### Concrete example (real, from the `melino` project — Spring/JSF, 25 modules)

| coordinate | fad resolves | Maven/Snyk actually has | missed CVE | OSV has it at the old version? |
|---|---|---|---|---|
| `org.apache.poi:poi` | `5.4.1` | `3.11` (transitive via tika/jmeter) | CVE-2017-12626 (HIGH) | **yes** |
| `commons-collections:commons-collections` | `3.2.2` | `3.2.1` | CVE-2015-7501 (CRITICAL deser. RCE) | **yes** |
| `org.apache.pdfbox:pdfbox` | `3.0.5` | `1.8.8` | CVE-2016-2175 | **yes** |
| `org.apache.xmlbeans:xmlbeans` | `5.3.0` | `2.6.0` | CVE-2021-23926 | **yes** |
| `org.apache.commons:commons-compress` | `1.27.1` | `1.8.1` | CVE-2024-25710 | **yes** |
| `commons-io:commons-io` | `2.19.0` | `2.4` | CVE-2021-29425 | **yes** |
| `org.apache.commons:commons-lang3` | `3.20.0` | `3.3.2` | CVE-2025-48924 | **yes** |

All 7 are recoverable: OSV (fad's Maven matcher) returns the CVE for the **old**
version. fad just never *scans* the old version because it's masked.

> The CVE-index angle is a dead end: it's fresh (rebuilt daily) but small **by design**
> (`lib/cve-download.js#isMavenRelevant` keeps only cvelistV5 records with an explicit
> Maven coordinate; old Java CVEs are CPE-only → excluded). OSV is the real Maven
> matcher. Don't chase the index.

---

## 2. Hard constraints (these killed the obvious fixes)

1. **Must work fully offline / air-gapped.** No `mvn`, no Snyk, no build tools. Snyk
   needs `mvn dependency:tree` (online, downloads the world) — explicitly **NOT an
   acceptable solution**. Resolution uses only `~/.fad-checker/poms-cache/` (immutable
   POMs, warmed online once, then offline). See `lib/transitive.js#fetchPom` (cache-first,
   `if (offline) return null`).
2. **No regression.** Baseline on `melino`: **156 of 210 snyk findings covered, 46
   missed** (and 435 unit tests green). Any fix must keep covered ≥ 156 and all tests
   green. The bar is "recover the 7 above → ~163 covered" *without* dropping coverage.
3. **False positives matter.** Scanning a version that isn't actually on any classpath
   (because a direct dep legitimately overrides it via nearest-wins) erodes trust. The
   ideal fix adds the *genuinely-present* old versions, not every version ever seen.

---

## 3. Root cause (exact code)

The scan set is one **global** `Map<g:a, depRecord>` (`lib/cve-match.js#collectResolvedDeps`).
Each record carries `version` (highest seen) and `versions[]` (all distinct concrete
versions); **`matchOne` (`cve-match.js:~182`) scans every entry of `versions[]`** — so
the fix is fundamentally "get the masked old version into `versions[]`".

Two mechanisms collapse versions to one and mask the old one:

1. **`collectResolvedDeps` dedups by `g:a` globally** (line ~82-87) and *also collects
   `<dependencyManagement>` entries as if they were deps* (line 86). So a coord pinned in
   one module's depMgmt enters the global set at the pinned version.
2. **`expandWithTransitives` (`cve-match.js:118`)** builds `rootDepMgmt` from **every**
   global dep with a concrete version (lines ~123-132) and passes it to
   `resolveTransitiveDeps`. In `lib/transitive.js:~349` that map **force-overrides** the
   transitive's version:
   ```js
   if (rootDepMgmt.has(childKey)) resolvedVersion = rootDepMgmt.get(childKey).version;
   ```
   → so the transitive `poi 3.11` is rewritten to `5.4.1` before it's ever recorded, and
   the `if (resolvedDeps.has(key)) continue` (line ~149) drops it anyway.

Net: the *global* rootDepMgmt applies one module's pin to **all** modules. Maven applies
depMgmt only **within the module subtree that declares it**.

---

## 4. Failed approaches (do NOT repeat without addressing the noted failure)

### 4a. "managed-only rootDepMgmt" — build `rootDepMgmt` from real `<dependencyManagement>` pins only, not from plain direct deps
- Idea: a plain `<dependency>` shouldn't pin transitives in other modules; only depMgmt.
- Helper written: `collectManagedVersions(propsByPom)` (extract non-import depMgmt pins).
- **Result on melino: identical (156 covered, 0 recovered).** The melino pins live in an
  **inherited** depMgmt (super-pom / module parents), so they're "managed" anyway →
  managed-only still force-overrides. Also **adds false-positive risk** on projects where
  a direct dep overrides a transitive *without* depMgmt (nearest-wins would drop the old
  one, but managed-only would surface and scan it).
- Verdict: no benefit here, real downside elsewhere.

### 4b. "per-module resolution" — resolve each pom independently with only its own depMgmt, union the results
- Idea: the architecturally-correct fix (mirrors Maven).
- Implemented `expandTransitivesPerModule` (per-pom directs from `entry.dependencies`,
  versionless filled from that module's managed map, `rootDepMgmt` = that module's pins +
  imported-BOM pins; added an `effCache` memo on `effectivePom` so 25 modules stay ~1s).
- **Result on melino: SEVERE REGRESSION — 156 → 65 covered, fad ids 240 → 149.**
- Why it regressed: the **global** pass seeds transitive resolution from a *richer* pool
  — `collectResolvedDeps` puts `<dependencyManagement>` entries into the dep set, so
  global resolves the trees of depMgmt-only coords too (236 transitive). Per-module seeds
  only real `<dependencies>` (148 transitive) → finds far fewer → loses ~half the CVEs.
  (Arguably 148 is "more correct" — depMgmt entries aren't real deps — but the lost
  coverage is unacceptable, and some of those depMgmt-rooted transitives were real hits.)
- Verdict: cannot replace the global pass with naive per-module; the global pass's
  "over-seeding" is load-bearing for recall.

---

## 5. Key insight for the next attempt

The tension: **recall** wants the rich global seed (incl. depMgmt-as-roots) AND the
masked old transitive versions; **correctness/FP** wants Maven's per-module mediation.
A viable fix probably **keeps the global pass as the base** (don't regress the 156) and
**adds masked versions on top**, e.g.:

- **Option A — additive per-module overlay.** Run the existing global
  `expandWithTransitives` unchanged (base set, no regression). THEN run a per-module pass
  whose *only* job is to discover `(g:a, version)` pairs **not already in `versions[]`**
  and append them (never remove, never reseed the base). Net effect can only *add*
  coverage. Cost: a second resolution pass (mitigate with the `effCache` memo + warm
  poms-cache; both already prototyped). Watch FP rate.
- **Option B — track all versions seen, pre-mediation.** Teach `resolveTransitiveDeps`
  (transitive.js) to record, per `g:a`, every distinct version encountered **before**
  `rootDepMgmt` force-override and nearest-wins, and surface them. Then
  `expandWithTransitives` appends any version differing from the declared one to
  `versions[]`. This avoids a second pass but needs care: only count versions actually
  reachable on a compile/runtime path (respect scope + exclusions) to bound FPs.
- **Option C — proper per-module, but seed from the union** of (real `<dependencies>`)
  ∪ (the global transitive base) so recall isn't lost, while applying per-module depMgmt
  for the *version* decision. More faithful, more work.

Whatever the approach: the acceptance test is **covered ≥ 163 on melino AND ≥ baseline
on every other project AND 435+ tests green**, fully offline from warmed poms-cache.

---

## 6. Reproduction & test data

### Repro commands (need warmed `~/.fad-checker/poms-cache`, then offline)
```bash
# fad side (offline OK once poms-cache warm). outTest == the extracted cnaps Spring Boot tree;
# melino is the richer multi-module case below.
MELINO="/mnt/wsl/WipDrive/EY/sources-vote-melino-project-17.4-MINJU-1.2.0"
node fad-checker.js -s "$MELINO" --no-all-libs --no-retire --report-json /tmp/fad.json

# Snyk reference set already captured at /tmp/snyk-melino.json (snyk --all-projects --json
# on the cleaned tree, run once with maven on PATH). Compare by CVE/GHSA id:
#   covered = snyk findings whose CVE/GHSA ∈ fad ids ; missed = the rest.
# Baseline: covered 156 / missed 46. (fad cve row id is TOP-LEVEL: row["id"], not row.cve.id.)
```

### Deterministic unit fixture to BUILD (so this is testable without the private projects)
Create `test/fixtures/maven-version-masking/` (a 2-module reactor) + cached POMs so the
transitive resolver runs offline:
- `parent/pom.xml`: `<dependencyManagement>` pinning `org.apache.poi:poi:5.4.1`.
- `module-a/pom.xml` (parent = parent): declares `poi` directly (gets 5.4.1).
- `module-b/pom.xml` (parent = parent, but does NOT inherit the poi pin OR is a sibling
  reactor module): declares a dep on `oldlib:1.0` whose **cached POM** declares
  `org.apache.poi:poi:3.11`.
- Seed `test/fixtures/poms-cache/` (or inject via `resolveTransitiveDeps`'s `fetcher`/
  `cacheDir` opts — both already supported) with `oldlib-1.0.pom` and `poi-3.11.pom`.
- **Assert:** after collection + transitive expansion, `resolvedDeps.get("org.apache.poi:poi").versions`
  contains **both** `5.4.1` and `3.11`; and `matchOne` against a fixture CVE affecting
  `[0,4.0)` flags the `3.11` occurrence.

This fixture is the red test to drive the fix TDD-style, with **zero network**.

---

## 7. Files in play
- `lib/cve-match.js` — `collectResolvedDeps` (global dedup + depMgmt-as-deps), `expandWithTransitives` (rootDepMgmt build + transitive merge), `matchOne` (scans `versions[]`).
- `lib/transitive.js` — `resolveTransitiveDeps` (BFS, nearest-wins), `effectivePom` (parent/BOM merge), `rootDepMgmt` force-override at the version-resolution step.
- `lib/maven-bom.js` — already resolves imported BOMs (`spring-boot-dependencies`) → managed-version map; reuse for per-module depMgmt + versionless-direct filling.
- Baseline snyk reference: `/tmp/snyk-melino.json` (regenerate via the cleaned `-t` tree + `snyk test --all-projects --json`).

## 8. What NOT to do
- Don't "fix" by widening the CVE index (structural, see §1).
- Don't propose Snyk/mvn as the answer (offline requirement).
- Don't replace the global transitive pass with naive per-module (regression, §4b).
- Don't globally drop `rootDepMgmt` force-override (breaks BOM-managed pins → FP flood).
