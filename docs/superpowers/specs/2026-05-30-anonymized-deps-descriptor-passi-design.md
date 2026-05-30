# Anonymized dependency descriptor for PASSI offline→online→offline audits

**Date:** 2026-05-30
**Status:** Approved design — ready for implementation plan

## Problem

In a PASSI (ANSSI) audit the audited system is usually **air-gapped / confidential**.
fad-checker's vulnerability lookups (OSV, NVD, CVEProject index, Maven Central / npm
registry, endoflife.date) need the **network**, which the offline machine does not have.
We need a way to:

1. Export, **from the offline machine**, a *global, anonymized* descriptor of the
   resolved dependencies — public coordinates only, with **zero environment-identifying
   information** (no filesystem paths, no registry URLs, no hostnames / usernames).
2. Carry that descriptor to an **online machine**, run the network lookups there.
3. Produce the **full detailed report** (with real manifest paths / project structure)
   back **on the offline machine**, inside the secure enclave.

## Key insight that shapes the design

fad-checker's caches are keyed by **coordinate** or **vuln id**, never by filesystem
path, so they are **machine-independent**:

| Cache | Key |
|---|---|
| OSV stub | `<eco>__<g>__<a>__<v>.json` |
| OSV vuln details | `vuln_<id>.json` |
| NVD record | `<cveId>.json` |
| endoflife cycles | product |
| Maven Central / npm registry | coordinate / name |
| CVEProject maven index | global index |

Therefore we **reuse the existing `--export-cache` / `--import-cache`** machinery
instead of inventing a proprietary "findings" transfer format. The online phase simply
**warms the caches**; the offline phase re-runs the scan with `--offline` and gets
cache hits.

## Workflow (3 phases)

### Phase 1 — offline: export the descriptor
```
fad-checker -s ./proj -e "^client\." --export-anonymized deps.json
```
- Collects locally (respects `-e`, `--ignore-test`, `--ecosystem`, `--no-*`).
- Writes a **flat, anonymized JSON descriptor** to `deps.json`.
- **No network call, no report.** Exits 0.
- Private/public sorting is the auditor's responsibility via `-e` (offline we cannot
  check Maven Central to auto-classify) — whatever `-e` excludes is already absent from
  the collected map before serialization.

### Phase 2 — online: warm the caches
```
fad-checker --import-anonymized deps.json          # no -s
fad-checker --export-cache caches.tgz
```
- `--import-anonymized` loads the descriptor (no source tree needed), derives the active
  codecs from the ecosystems present, and runs the **scan + report flow online**.
  This warms every coordinate-keyed cache.
- It **also fetches the retire.js signature DB** into `~/.fad-checker/retire-signatures/`
  (see retire section) so vendored-JS scanning works offline later.
- The report it renders is **inherently anonymized** (the descriptor carries no paths).
- `--export-cache` then bundles the warmed `~/.fad-checker/` (incl. retire signatures).

### Phase 3 — offline: full report
```
fad-checker --import-cache caches.tgz
fad-checker -s ./proj --offline
```
- Re-collects the source tree **locally** (real paths, real manifests).
- Vulnerability data comes from the **warm cache** (hits, no network).
- retire.js runs **offline** against the local JS using the **warmed signatures**.
- Produces the **full detailed report with all local context**, fully inside the enclave.
- **No new code** beyond the retire offline change — uses existing `--import-cache` +
  `--offline`.

## New module: `lib/deps-descriptor.js`

Pure, I/O-free serialization (mirrors the codec parsers' "pure functions" style):

- `serializeDeps(resolvedMap, { generator, note }) -> descriptor`
- `deserializeDeps(descriptor) -> { resolved: Map<coordKey, depRecord>, activeIds, runMaven, runNpm }`

`deserializeDeps` rebuilds depRecords via `makeDepRecord` with **`manifestPath` empty**
(`manifestPaths: []`); `coordKey` is **recomputed** with `coordKeyFor` (never trusted
from the input). Maven `groupId`/`artifactId` are reconstructed from `namespace`/`name`.

Thin file I/O (`writeFileSync` pretty JSON / `readFileSync` + `JSON.parse`) lives in
`fad-checker.js` next to the existing `--export-cache` handling, or as small wrappers in
the module — implementer's choice, kept out of the pure functions.

## Descriptor schema (`fad-deps/1`)

Pretty-printed JSON so the auditee can **review exactly what leaves the air-gapped
machine** before transfer.

```json
{
  "schema": "fad-deps/1",
  "generator": "fad-checker 2.0.1",
  "generatedAt": "2026-05-30T12:00:00Z",
  "note": "Anonymized: public coordinates only — no paths, URLs, or host info. Review before transfer.",
  "summary": { "total": 42, "byEcosystem": { "npm": 30, "pypi": 8, "nuget": 4 } },
  "deps": [
    {
      "ecosystem": "npm", "ecosystemType": "npm",
      "namespace": "", "name": "lodash",
      "version": "4.17.21", "versions": ["4.17.21"],
      "scope": "prod", "isDev": false
    }
  ]
}
```

- **Kept** (required for scanning / report grouping): `ecosystem`, `ecosystemType`,
  `namespace`, `name`, `version`, `versions`, `scope`, `isDev`.
- **Stripped** (environment): `manifestPath` / `manifestPaths` / `pomPaths`, `resolved`
  (registry URL), `integrity`, `from` (parent chain), `depth`, `lockType`.
- **Anonymization guarantee:** the serialized document contains **no filesystem path,
  no URL, no hostname/username** — only public package coordinates + version + scope.

## CLI surface

| Flag | Phase | Requires `-s` | Effect |
|---|---|---|---|
| `--export-anonymized <file>` | 1 (offline) | yes | collect → write descriptor → exit; no network, no report |
| `--import-anonymized <file>` | 2 (online) | no | load descriptor → scan/report flow (warms caches) + warm retire signatures |

Naming is consistent with the existing `--export-cache` / `--import-cache`.

## retire.js changes (`lib/retire.js`)

Two problems found:
1. retire caches its **signature DB** in `--cachedir`, which defaults to
   `/tmp/.retire-cache` — **outside `~/.fad-checker/`**, so `--export-cache` does not
   carry it.
2. In `offline` mode `lib/retire.js` short-circuits to the findings cache and **never
   invokes the binary**, so phase 3 offline would not scan vendored JS even with
   signatures present.

Changes:
1. **Redirect the signature cache** into `~/.fad-checker/retire-signatures/` by passing
   `--cachedir <that dir>` on every retire invocation. It is then inside the exportable
   cache directory automatically.
2. **Allow offline retire to run** against the cached signatures: in `offline` mode, if
   there is no findings cache, still invoke the binary with `--cachedir` (a fresh cached
   DB means no network call). On any failure (missing signatures + no network) return
   `[]` gracefully, exactly as today.
3. **`warmRetireSignatures({ verbose })`** — new exported helper that fetches the
   signature DB into the cachedir **without scanning** (runs retire against a throwaway
   empty temp dir). Called by `--import-anonymized` (online). Skipped when `--offline`.

The retire findings cache stays path-keyed (`md5(srcDir)`); that is fine because retire
only ever runs offline on the **same machine / same source path** (phases 1 and 3).

## Error handling

- `--export-anonymized` without `-s` → error, exit 1.
- `--export-anonymized` with an empty resolved map → warn, still write a valid (empty)
  descriptor, exit 0.
- `--import-anonymized` with `-s` → warn that `-s` is ignored (descriptor wins).
- `--import-anonymized` file missing / invalid JSON → error, exit 1.
- descriptor `schema` !== `fad-deps/1` → error naming the found vs expected schema.
- `--import-anonymized --offline` → allowed but warned (caches will not warm; only useful
  to re-render from an already-warm cache); retire signature warming is skipped.

## Testing

`test/deps-descriptor.test.js`:
- `serializeDeps` strips every environment field — assert the **serialized JSON string**
  contains no `/`-path, no `http`, no `integrity`, and not a seeded sensitive path.
- round-trip `serialize → deserialize` preserves `ecosystem`, `ecosystemType`,
  `namespace`, `name`, `version`, `versions`, `scope`, `isDev`, and the recomputed
  `coordKey`.
- maven reconstruction: `groupId`/`artifactId` from `namespace`/`name`, bare `g:a`
  coordKey.
- multi-version (`versions` with >1 entry) preserved.
- `deserializeDeps` derives `activeIds` / `runMaven` / `runNpm` correctly.
- edge cases: empty map → valid schema + empty `deps`; unknown `schema` → throws;
  a `nuget`/`pypi`/`composer` coordinate also round-trips.

`test/retire.test.js` (or extend existing retire coverage):
- the signature cachedir constant is **under `FAD_CACHE_DIR`**.
- arg construction includes `--cachedir <sig dir>` (refactor the args into a pure
  `buildRetireArgs()` if needed to test without invoking the binary).
- `warmRetireSignatures` returns gracefully (no throw) when the binary is unavailable.

CLI-level (light, no network): `--export-anonymized` on a fixture dir → file exists,
parses, schema correct, contains no path fragments. (Full online round-trip is covered
by the already-tested `--export-cache`/`--import-cache` + `--offline` features.)

Docs to update on implementation: `README.md`, `CLAUDE.md` (gotchas + TTL table note
about retire signatures location), `docs/USAGE.md`.

## Alternative considered & rejected

A self-contained **"findings" file** transferred online→offline (phase 2 emits results,
phase 3 re-attaches them without using the cache). Rejected: more code, a proprietary
format to maintain and version, when the existing caches are already coordinate-keyed and
machine-independent. The cache round-trip reuses tested machinery.
