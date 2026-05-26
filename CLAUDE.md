# CLAUDE.md

Code-level orientation for contributors and Claude Code sessions on this repo.

## What this is

`fad-checker` — **Fucking Autonomous Dependency Checker**. Node.js CLI (`fad-checker`, or short alias `fad`) that:

1. Walks a multi-module Maven tree, removes private/excluded dependencies (regex on groupId), writes a parallel directory of "cleaned" POMs that can be fed to Snyk.
2. Walks every JS package (`package.json` + `package-lock.json` v1/v2/v3 or `yarn.lock` v1) in the same source tree.
3. Scans the union against:
   - the CVEProject `cvelistV5` Maven-relevant index (built locally),
   - OSV.dev (multi-ecosystem),
   - NIST NVD (enrichment: CVSS, CPE configurations, references),
   - retire.js (vendored JS signatures),
   - optionally Snyk (`--snyk`).
4. Cross-checks every match's NVD CPE configurations against the dep version (`lib/cpe.js`) to filter false positives.
5. Reports EOL frameworks (endoflife.date — Maven, npm, **and WebJars** `org.webjars*`: jQuery/Angular/AngularJS/Vue/React/Bootstrap), obsolete libs (curated Maven + npm-registry per-version `deprecated` field — authoritative, skips nothing), outdated libs (Maven Central + npm registry `dist-tags.latest`).
6. Produces a self-contained HTML report + Word-compatible `.doc`, organised by ecosystem and by defining manifest, with per-tool fix recipes and an executive summary.

No build tool (`mvn`, `npm install`, `yarn`) is required on PATH — `pom.xml` / `package-lock.json` / `yarn.lock` are parsed directly.

## Running

```bash
npm install
npm test                  # 96 unit tests via node --test

# basic cleanup workflow
node fad-checker.js -s ./proj                                        # read-only, full report
node fad-checker.js -s ./proj -t ../pom-clean -e "^client\\."        # write cleaned tree
node fad-checker.js -s ./proj -t ../pom-clean -e "^client\\." --snyk # also drive snyk

# read the full usage doc
cat docs/USAGE.md
```

Binary builds (requires `bun`):

```bash
npm run build:linux   # → dist/fad-checker-linux
npm run build:win     # → dist/fad-checker.exe
npm run build         # both
```

Guardrails enforced at startup:
- `--target` is required only when you want a cleaned POM tree. Without it the run is read-only.
- `--target` may not equal or be a subdirectory of `--src`.
- `--target` is `rimraf`'d before being rewritten — never point at anything precious.

## Architecture (one-liner per file)

```
fad-checker.js                 Thin CLI: commander parsing, orchestration only.
lib/core.js                  POM parsing, parent resolution, all-profile merge, rewrite.
lib/maven-version.js         Maven version parsing + range comparison (no external deps).
lib/cve-download.js          Bulk download of CVEProject/cvelistV5 + Maven-relevant index build.
lib/cve-match.js             Resolved-dep collection + 3-tier CVE matching with dedup.
lib/cve-report.js            Self-contained HTML and Word-compatible (.doc) report rendering.
lib/cpe.js                   CPE 2.3 parsing + NVD configurations evaluator (post-match refinement).
lib/outdated.js              EOL (endoflife.date), obsolete (curated), outdated (Maven Central).
lib/transitive.js            Maven Central POM walker (transitive resolution).
lib/osv.js                   OSV.dev batched query + per-vuln detail fetch.
lib/nvd.js                   NIST NVD enrichment (CVSS, references, CPE configurations).
lib/snyk.js                  `snyk test --all-projects --json` runner + merge.
lib/retire.js                retire.js (vendored-JS scanner) wrapper + cache + normaliser.
lib/scan-completeness.js     Warnings for deps fad-checker couldn't fully resolve.
lib/npm/parse.js             package.json, package-lock.json (v1/2/3), yarn.lock v1 parsers.
lib/npm/collect.js           Merge across JS manifests → unified resolvedDeps Map.
lib/npm/registry.js          npm registry packument query → per-version deprecation + dist-tags.latest (npm EOL feeds via lib/outdated.js).
lib/cache-archive.js         tar.gz / zip export & import of ~/.fad-checker/.
lib/config.js                Persistent user config in ~/.fad-checker/config.json (mode 0600).
data/                        known-obsolete.json, eol-mapping.json, cpe-coord-map.json, known-public-namespaces.json
completions/                 fad-checker.bash, fad-checker.zsh
test/                        node:test suite + fixtures (simple, complex-enterprise, monorepo-mixed, …).
```

For the deep dive — pipeline stages, the resolved-deps Map shape, report structure — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Important conventions

- **`coord()` always trims**: real-world POMs occasionally contain whitespace around `<artifactId>`. Every coord-derived lookup goes through `coord()` in `lib/core.js`.
- **`byId` keys are never polluted with `undefined`**: only indexed when both `groupId` and `artifactId` are present. Enforced by test.
- **All profiles are merged, never prompted for**: every profile's deps are unioned so Snyk sees every dep any profile could pull in. `activeByDefault` wins only for property value conflicts.
- **No `process.exit(1)` mid-pipeline**: a parse/rewrite failure for one POM logs and continues so the summary still prints.
- **HTML report is self-contained**: inline CSS, no external assets. The `.doc` variant is the same HTML with Office XML namespace meta tags — Word opens it natively.
- **Map keys are ecosystem-namespaced**: Maven uses `g:a`, npm uses `npm:name`. They never collide so they share one resolved-deps Map.
- **Lockfile-only npm**: `package.json` without sibling `package-lock.json`/`yarn.lock` is intentionally skipped (its ranges aren't queryable) and reported in chapter 0.
- **Source identifiers**: every match carries `source: "fad" | "osv" | "nvd" | "snyk" | "retire"` (or a `+`-joined combination).

## Testing

```bash
node --test test/*.test.js            # full suite (96 tests)
node --test test/core.test.js         # one file
```

Test fixtures live in `test/fixtures/`:
- `simple/` — 3 POMs with parent inheritance + property substitution
- `complex-enterprise/` — Spring Boot parent (external), local BOM via `scope=import`, three profiles
- `private-lib-detection/` — mixed public/private groupIds, external private parent
- `monorepo-mixed/` — Maven + npm (package-lock v3) + yarn.lock v1 + a no-lockfile package.json
- `cve-samples/` — small CVE / NVD JSON files for the matchers

## Gotchas / edge cases worth knowing

- CVE bundle from CVEProject is ~500 MB unpacked. Shells out to `curl + unzip` (fallback to `fetch()` + `unzip` / `Expand-Archive`). Extracted JSON deleted after index build. Ships as `cves.zip.zip` (nested zip) — `extractZip()` recurses up to 3 levels.
- `endoflife.date` API responses cached 7 days; Maven Central version lookups cached 24 hours. Cache lives in `~/.fad-checker/`.
- **Persistent config**: `~/.fad-checker/config.json` (mode 0600). Set NVD key via `fad-checker --set-nvd-key <KEY>` (free, instant from <https://nvd.nist.gov/developers/request-an-api-key> — bumps rate limit from 5/30s to 50/30s).
- **`--offline` umbrella flag**: skips every network call (CVE/OSV/NVD/Maven Central/endoflife/npm-registry/retire). Falls back to whatever is already cached. Per-source variants (`--cve-offline`, `--no-osv`, `--no-nvd`, `--no-retire`, `--no-transitive`, `--no-js`) still work independently. npm registry deprecation always runs when online; npm (and Maven) outdated is gated by `--no-all-libs`.
- `snyk` is not a hard dep — shells out via `execFile`. `snyk` exits 1 on findings; the JSON is still on stdout.
- The cleaned POM is the union of every profile's deps. Counts will be larger than the source POM. Intentional — don't "fix" that.
- Unresolved `${…}` Maven variables stay verbatim in the rewritten POM. `lib/cve-match.js` resolves them lazily via `resolveDepVersion()` when scanning. Deps that *still* can't be resolved (external BOM not in source tree) surface in chapter 0 as `unresolved-versions` warnings.
- **retire.js** doesn't like `--outputpath /dev/stdout`. We write to a temp file and read it back. Exit code 13 means "vulns found" — expected, not an error.

### Per-cache TTLs

| Cache | Location | TTL |
|---|---|---|
| CVEProject bulk index | `~/.fad-checker/cve-data/maven-cve-index.json` | 24 h |
| OSV per-dep stub list | `~/.fad-checker/osv-cache/<eco>__<g>__<a>__<v>.json` | 12 h |
| OSV vuln details | `~/.fad-checker/osv-cache/vuln_<id>.json` | 12 h |
| NVD CVE record | `~/.fad-checker/nvd-cache/<cveId>.json` | 7 d |
| endoflife.date cycles | `~/.fad-checker/eol-cache.json` | 7 d |
| Maven Central latest | `~/.fad-checker/version-cache.json` | 24 h |
| npm registry (deprecation + latest) | `~/.fad-checker/npm-registry-cache.json` | 24 h |
| Transitive POM | `~/.fad-checker/poms-cache/<g>__<a>__<v>.pom` | ∞ (immutable on Maven Central) |
| retire.js findings | `~/.fad-checker/retire-cache/<md5(src)>.json` | 24 h |
