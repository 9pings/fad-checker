# Unmanaged / vendored dependencies — design

**Date:** 2026-06-02
**Status:** Approved (brainstorming) → ready for implementation plan

## Problem

`fad-checker` walks package-manager manifests (pom.xml, package-lock.json, …) and
reports CVE / EOL / obsolete / outdated / license findings per ecosystem. But real
source trees also carry **dependencies that no package manager governs**:

- committed `.jar` / `.war` / `.ear` archives (vendored libs, Spring-Boot fat-jars,
  shaded uber-jars) — already discovered by `lib/codecs/maven/jar-scan.js`,
- vendored JavaScript files — already flagged by retire.js,
- committed **native binaries** — `.dll` / `.exe` / `.so` / `.dylib` — not handled
  at all today.

Today these are scattered: embedded jars get CVE-only "chapter 1B", retire.js gets
"chapter 2", and embedded coords leak into the Maven EOL/obsolete/outdated/license
chapters mixed with declared deps. There is no single place that answers the two
questions an auditor actually has about vendored binaries:

1. **Integrity** — has this binary been *modified* relative to the official
   published artifact? (tampering / backdoor / silent recompile)
2. **Governance** — this is committed as a blob but it *exists in a registry*; it
   **should be a declared dependency** instead.

Version-for-CVE identification is **not** the goal of this feature (the existing
pipeline already does CVE matching for resolved coordinates).

## Goal

A single, dedicated **Part C — "Unmanaged / vendored dependencies"** in the report,
built from a unified **unmanaged-artifact inventory**. For every unmanaged file the
report shows:

- the file (path, size, hashes),
- the identity obtained **online by checksum** (`eco:name@version` or "unknown"),
- **integrity** status (pristine / modified / unverified / unknown),
- a **governance** flag when it should be a managed dependency,
- a **name-vs-checksum mismatch** warning (declared/filename name ≠ resolved name),
- a **no-online-info** warning (no source knows this file → suspicious),
- an opportunistic **free-malware** warning when an already-queried known-good
  source reports the file as malicious (zero extra calls — **not** an antivirus).

After this change the managed per-ecosystem chapters contain **only declared
dependencies** (`provenance === "manifest"`).

## Non-goals

- No dedicated malware / antivirus lane. No VirusTotal, MalwareBazaar, Team Cymru,
  etc. The only malware signal surfaced is the one that *already rides along* with a
  free known-good identity source (CIRCL `KnownMalicious`).
- No PE / ELF / Mach-O version-metadata parsing (LIEF etc.). Identity comes from
  **hash lookup**, integrity from **hash comparison** — parsing is unnecessary.
- No new offline behavior contract: new sources obey the existing `--offline`
  principle (read warmed cache, never block, never fabricate).

## Approach

Approach **C — inventory-first**: build a first-class unmanaged inventory data
structure during collection, then render Part C from it. Chosen over a
render-time-only partition because the inventory (file → hash → identity →
integrity → source) *is* the deliverable here, and it's the natural home for the
new native-binary source.

## Data sources (researched 2026-06-02)

**Identity lane — "what is this file?" (known-good, by checksum)**

- **deps.dev query-by-hash** — `GET https://api.deps.dev/v3/query?hash.type=<T>&hash.value=<base64>`.
  Returns the package `version`(s) whose published artifact matches the hash, across
  npm / Maven / NuGet / PyPI / RubyGems / Cargo. Free, no auth, responses cacheable
  (CC-BY, commercial-OK). Accepts MD5 / SHA1 / SHA256 / SHA512. *Primary identity
  source.* Caveat: it hashes the **published archive** (.jar/.tgz/.gem/…), so it
  matches a vendored copy of the whole artifact, not a single extracted `.so`.
- **CIRCL hashlookup** — `GET https://hashlookup.circl.lu/lookup/{sha1|sha256|md5}/<h>`
  (+ `POST /bulk/...`). Aggregates NSRL + Linux distros + CDNJS. Returns product /
  OS-package metadata, a `hashlookup:trust` score, and a `KnownMalicious` list.
  Free, no auth. **Offline option:** downloadable ~700 MB SHA-1 Bloom filter
  (`https://cra.circl.lu/hashlookup/hashlookup-full.bloom`) + DNS interface +
  self-hostable AGPL server → satisfies air-gapped operation. *Secondary identity
  source (OS / CDN / NSRL coverage) and the free malware signal.*

**Integrity lane — "is it unmodified?" (published-digest comparison)**

Once a coordinate is known, compare the file's hash to the registry's *own*
published digest. All free, no auth, commercial-OK, cacheable via existing
per-codec caches:

| Ecosystem | Oracle |
|---|---|
| Maven   | Maven Central SHA-1 search (`search.maven.org/solrsearch/select?q=1:"<sha1>"`) + per-artifact `.sha1` |
| npm     | packument `versions[v].dist.integrity` (SHA-512) / `dist.shasum` (SHA-1) |
| PyPI    | `pypi.org/pypi/<p>/<v>/json` → file `digests.{sha256,md5}` |
| RubyGems| `api/v1/versions/<gem>.json` → `sha` (SHA-256 of .gem) |
| crates  | index `cksum` (SHA-256 of .crate) |
| Go      | `sum.golang.org/lookup/<mod>@<ver>` — note `h1:` is a *dirhash*, not a file hash |
| NuGet   | catalog `packageHash` (SHA-512) — awkward API, weakest oracle |

## Components

- **`lib/codecs/binary.codec.js` + `lib/codecs/binary/scan.js`** — new codec. `detect`
  walks the source tree for candidate files; `collect` hashes each (SHA-1 + SHA-256)
  and emits a depRecord with `provenance:"binary"`, `hashes`, and `declaredName`
  (from the filename). No parsing. Toggle **`--no-binaries`** (mirrors `--no-jars`).

  **File selection — binaries + dependency archives ONLY, never assets.** A file is
  a candidate only if BOTH its extension is allowlisted AND its magic bytes confirm
  the type (extension alone is not trusted):
  - native binaries: `.dll`/`.exe` → PE `MZ` (`0x4D5A`); `.so` (incl. `.so.N`) →
    ELF (`0x7F 45 4C 46`); `.dylib` → Mach-O (`0xFEEDFACE`/`0xFEEDFACF`/`0xCAFEBABE`
    fat); `.a` static libs optional/later.
  - dependency archives (jar-style zips): `.jar`/`.war`/`.ear` (and extensible:
    `.aar`) → ZIP (`PK\x03\x04`). These overlap with `jar-scan.js`; the binary
    codec only takes archives `jar-scan.js` does not already claim.
  - **explicitly excluded** (never hashed/looked up): images (`.png`/`.jpg`/`.jpeg`/
    `.gif`/`.svg`/`.ico`/`.webp`/`.bmp`), fonts (`.woff`/`.woff2`/`.ttf`/`.otf`/
    `.eot`), media, documents, source, and any file whose magic bytes don't match a
    binary/archive signature — even if the extension matched.
  - standard skip dirs (`node_modules`, `.git`, build output) follow the existing
    walker conventions.
- **`lib/hash-id.js`** — shared identity service (sits alongside `osv.js`/`nvd.js`).
  Input: depRecords/inventory entries carrying `hashes`. Queries deps.dev then CIRCL,
  cached per-hash, `--offline`-aware (CIRCL via Bloom filter / warmed cache).
  Output: `identity { ecosystem, name, version, source, trust, knownMalicious }`.
- **`lib/integrity.js`** — shared integrity service. Input: an inventory entry with a
  resolved coordinate. Fetches the registry published digest (reusing each codec's
  registry/cache) and compares. Output: `integrity` ∈
  `pristine | modified | unverified | unknown`.
- **`lib/unmanaged.js`** — assembles the inventory: ingests embedded depRecords
  (`provenance:"embedded"`, from `jar-scan.js`), native-binary depRecords
  (`provenance:"binary"`), and retire findings; runs hash-id + integrity; derives the
  per-file warnings.

## Data model

depRecord additions:

- `hashes: { sha1, sha256 }`
- `declaredName` — self-declared identity: a jar's embedded `pom.properties`
  coordinate, else the filename stem.
- `identity` — `{ ecosystem, name, version, source, trust, knownMalicious }` or null.
- `integrity` — `pristine | modified | unverified | unknown`.

`provenance` value set becomes `manifest | embedded | binary`.

Derived per-file signals (computed in `unmanaged.js`):

- **nameMismatch** — `declaredName` resolves to a *different* product than `identity`
  (renamed / repackaged / spoofed). For jars: pom.properties coord ≠ resolved coord.
  For filenames: resolved product name not reflected in the filename.
- **noOnlineInfo** — `identity == null` after all sources (suspicious blob).
- **knownMalicious** — `identity.knownMalicious` truthy (free CIRCL signal).
- **shouldBeManaged** — `identity` resolves to a real registry package (it exists in
  a registry yet is committed as a blob).

## Report — Part C

A new top-level part rendered from the inventory, replacing scattered chapters:

1. **Inventory table** — file · size · SHA-1 · identity (`eco:name@ver` / "unknown") ·
   integrity · detection source.
2. **Integrity violations** (`modified`) — tamper red-flags, surfaced first.
3. **Name / checksum mismatches** — declared name ≠ resolved identity.
4. **Should-be-managed** — governance: "declare as `<eco>:<name>@<ver>`".
5. **CVEs in unmanaged artifacts** — folds today's chapter 1B.
6. **Unidentified blobs** — `noOnlineInfo`, plus any free `knownMalicious` warning.

Managed chapters (CVE / EOL / obsolete / outdated / license) filter to
`provenance === "manifest"`.

## Exports

SBOM / SARIF / JSON already carry `provenance`. Extend each unmanaged
component/result with `hashes`, `identity`, and `integrity` (SBOM properties under
the existing `fad:` namespace; SARIF result properties; JSON fields). No new export
formats.

## Offline / caching

Per the project's offline principle (read warmed cache, never block, never
fabricate):

- deps.dev — cached per-hash (24 h), like the other registry caches.
- CIRCL — online REST when allowed; `--offline` uses the warmed per-hash cache, or
  the downloaded Bloom filter for the "known at all?" bit. Never a network block.
- Registry digests — reuse each codec's existing cache (`version-cache.json`,
  `npm-registry-cache.json`, etc.).
- `--export-cache` / `--import-cache` bundle the new caches so the
  offline→online→offline PASSI round-trip still works.

New cache entries (add to the per-cache TTL table in CLAUDE.md):

| Cache | Location | TTL |
|---|---|---|
| deps.dev hash query | `~/.fad-checker/depsdev-cache.json` | 24 h |
| CIRCL hashlookup | `~/.fad-checker/circl-cache.json` | 24 h |
| CIRCL Bloom filter | `~/.fad-checker/hashlookup-full.bloom` | warmed online, reused offline |

## Flags

- `--no-binaries` — disable native-binary discovery (mirrors `--no-jars`).
- (existing `--offline` and per-source toggles continue to govern the new sources.)

## Out of scope (this iteration)

- Malware / known-bad lookups as a dedicated lane (designed-around, not built).
- PE / ELF / Mach-O metadata parsing.
- Per-extracted-file (.so inside a .nupkg) identity — deps.dev matches whole
  published archives; extracted-member attribution is a later refinement.

## Testing

- `binary/scan.js` — fixture tree with `.dll`/`.so` files → correct hashes,
  provenance, `declaredName`; `--no-binaries` skips it. **Asset-rejection test:** an
  image with a spoofed `.so` extension (PNG bytes) and a real `.png`/`.ttf` are NOT
  picked up; magic-byte mismatch wins over extension.
- `hash-id.js` — mocked deps.dev / CIRCL responses → identity mapping; offline path
  reads cache only and never throws on missing network.
- `integrity.js` — pristine (hash matches published digest), modified (mismatch),
  unverified (no digest available), unknown (no identity).
- `unmanaged.js` — inventory assembly + derived signals (nameMismatch, noOnlineInfo,
  shouldBeManaged) over a mixed fixture (embedded jar + native binary + retire).
- report — Part C renders; managed chapters exclude non-`manifest` provenance.
- New fixtures under `test/fixtures/` (e.g. `vendored-binaries/`).
