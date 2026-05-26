# JS/npm EOL, Deprecated & Outdated detection

Date: 2026-05-26

## Problem

The report never shows end-of-life, obsolete/deprecated, or outdated **JS/npm**
dependencies. All three checks in `lib/outdated.js` are Maven-only:

- `checkEolDeps` skips npm outright (`if (dep.ecosystem === "npm") continue;`).
- `checkOutdatedDeps` filters `d.ecosystem !== "npm"`.
- `checkObsoleteDeps` looks up `${groupId}:${artifactId}`; for npm `groupId` is
  empty so the key is `:name`, and `known-obsolete.json` holds only Maven
  coordinates — nothing JS ever matches.

retire.js only covers known-vulnerable JS (CVEs), not end-of-support / deprecation
status. So an EOL framework (e.g. AngularJS) or a deprecated package (e.g.
`request`) is never reported.

## Principle

A professional tool must **skip nothing** and must rely on **authoritative online
sources**, not hand-maintained skip lists.

- EOL → endoflife.date (already used for Maven).
- Deprecated → the npm registry's per-version `deprecated` field (the same data
  that produces `npm WARN deprecated …`). Authoritative, per maintainer, per
  resolved version.
- Outdated → the npm registry `dist-tags.latest` (same fetch as deprecation).

## Design

### 1. EOL JS — endoflife.date

`data/eol-mapping.json` gains two npm sections. This is **name normalisation**
onto endoflife.date's fixed JS product set, not a skip list:

```jsonc
"by_npm_name": {
  "angular":   { "product": "angularjs", "label": "AngularJS" },  // npm "angular" == AngularJS 1.x
  "vue":       { "product": "vue",        "label": "Vue" },
  "react":     { "product": "react",      "label": "React" },
  "react-dom": { "product": "react",      "label": "React" },
  "jquery":    { "product": "jquery",     "label": "jQuery" },
  "bootstrap": { "product": "bootstrap",  "label": "Bootstrap" }
},
"by_npm_scope": {
  "@angular/": { "product": "angular",    "label": "Angular" }     // modern Angular == @angular/*
}
```

`lib/outdated.js`:
- `findEolProduct(dep)`: if `dep.ecosystem === "npm"`, resolve via `by_npm_name`
  first, else the longest matching `by_npm_scope` prefix; otherwise unchanged
  Maven logic.
- `checkEolDeps`: remove the npm `continue`. The rest (endoflife fetch, 7-day
  cache, `findCycleForVersion`, `isEol`, dedup) works unchanged.

### 2. Deprecated + Outdated JS — npm registry (new `lib/npm/registry.js`)

`checkNpmRegistryDeps(resolvedDeps, opts)` → `{ deprecated: [...], outdated: [...] }`

- For each npm dep, GET the packument `https://registry.npmjs.org/<encoded-name>`
  (scoped names encode the slash: `@angular%2Fcore`). One fetch yields both signals.
- **Deprecated**: `packument.versions[dep.version]?.deprecated` (non-empty string)
  → obsolete-shaped result `{ dep, severity: "MEDIUM", reason: <message>,
  replacement: <URL/hint parsed from message, else "see deprecation notice">,
  source: "npm" }`.
- **Outdated**: `packument["dist-tags"].latest`; if greater than `dep.version`
  (via `semverCompare`, exported from `lib/npm/collect.js`) →
  `{ dep, latest, releaseDate: packument.time?.[latest]?.slice(0,10) || null }`.
- Cache extracted `{ deprecated, latest, latestDate }` per `<name>@<version>` in
  `~/.fad-checker/npm-registry-cache.json`, TTL 24 h (aligned with Maven Central).
- Concurrency via `p-limit`; progress line mirroring `checkOutdatedDeps`.
- Respects `opts.offline` (no fetch, cache only).

### 3. Orchestration — `fad-checker.js`

After the existing Maven checks (around lines 451-470):

```js
const npmReg = await checkNpmRegistryDeps(resolved, { verbose, offline, allLibs: options.allLibs });
obsoleteResults = obsoleteResults.concat(npmReg.deprecated);
if (options.allLibs) outdatedResults = outdatedResults.concat(npmReg.outdated);
```

Merge **before** the existing `eolKeys`/`obsKeys` dedup (lines 468-470) so a dep
that is both deprecated/EOL and outdated is not double-reported. Deprecation
always runs when online (quality signal); outdated is gated by `--no-all-libs`,
mirroring Maven. Folded into the `--offline` umbrella.

### Rendering

No changes. `depDisplayName` already renders npm deps as `npm:<name>`, and the
EOL / Obsolete / Outdated tables consume the shared shapes.

## Out of scope

- No curated JS obsolete list (rejected: a static list skips by nature).
- Private npm registries (default to `registry.npmjs.org`).
- Yarn-Berry resolution (unchanged).

## Tests (no network)

- `test/outdated.test.js`: `findEolProduct` returns `angularjs` for npm `angular`,
  `angular` for `@angular/core`, `react` for `react-dom`, `null` for unknown npm
  package; Maven matches unchanged.
- `test/npm-registry.test.js`: pure extractor `packumentToFindings(packument, dep)`
  given manifests with / without `deprecated` and with a newer `dist-tags.latest`
  produces the correct deprecated / outdated results; no `deprecated` and
  up-to-date version → empty.

## Behaviour on the reference-project project

jQuery-UI / any deprecated package surfaces under Obsolete; version gaps under
Outdated; React 19 / jQuery 3.7 / Bootstrap 5.3 trigger no EOL (current) — correct,
not a false negative.

## Docs

Update `CLAUDE.md` (architecture one-liner for `lib/npm/registry.js`, the per-cache
TTL table, the offline note) and `docs/ARCHITECTURE.md`.
