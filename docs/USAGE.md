# USAGE

Every flag, every common workflow, with copy-pasteable commands.

## Synopsis

```text
fad-checker -s <src> [-t <target>] [-e <regex>] [other options]
```

- `-s, --src <src>` — **required**. Root of the source tree to scan. Contains `pom.xml` and/or `package(-lock).json` / `yarn.lock`.
- `-t, --target <dir>` — optional. If given, write a parallel directory of "cleaned" POMs (private/excluded deps stripped) to `<dir>` — useful as Snyk input. Without `-t`, the run is read-only.

## Output

By default the HTML + Word reports land in `./fad-checker-report/`. Override with `--report-output <dir>`.

## Ecosystem selection

```bash
# Auto-detect (default): scan whatever pom.xml / package(-lock).json / yarn.lock exists
fad-checker -s .

# Pick ecosystems (codecs). --ecosystem is a list: auto (default) | all | comma list.
# Codec ids: maven, npm, yarn, composer, pypi, nuget, go, ruby.
fad-checker -s . --ecosystem maven            # Maven only
fad-checker -s . --ecosystem maven,npm,go     # several, even if only one is auto-detected
fad-checker -s . --ecosystem all              # every supported codec
fad-checker -s . --ecosystem both             # legacy alias for maven,npm

# Opt out of specific codecs (combine freely)
fad-checker -s . --no-npm                     # skip npm
fad-checker -s . --no-js                      # alias: skip npm + yarn (Maven-only)
fad-checker -s . --no-pypi --no-nuget         # skip Python + C#
fad-checker -s . --no-go --no-ruby            # skip Go + Ruby
fad-checker -s . --no-jars                    # skip embedded .jar/.war/.ear scanning
fad-checker -s . --no-binaries                # skip committed native-binary scanning
```

> **Embedded JARs**: committed `.jar`/`.war`/`.ear` archives (vendored libs, Spring-Boot fat-jars, shaded uber-jars) are unzipped in-memory and their Maven coordinates — read from `META-INF/maven/.../pom.properties`, then `MANIFEST.MF`, then the file name — are reported in their own **Embedded binaries** chapter (1B), grouped by containing archive. The chapter is a **full inventory** of every embedded coordinate — vulnerable or not (the JAR counterpart of the native-binary inventory 1C and the vendored-JS inventory 1D) — with a CVE-status column per coord and the full CVE detail for vulnerable ones. So a committed fat-jar shows up even when nothing inside it is currently vulnerable. Auto when archives are present; `--no-jars` disables it. Archives with no resolvable coordinate are listed in chapter 0.

> **Committed native binaries**: `.dll`/`.exe`/`.so`/`.dylib` files are detected by extension **and** magic-byte confirmation (PE/ELF/Mach-O — images/fonts/assets are rejected even with a spoofed extension), hashed (SHA-1 + SHA-256) and **identified by checksum** online: **deps.dev** maps the hash to an exact package coordinate (byte-identical to a published artifact → *pristine*, and a candidate to declare as a real dependency); **CIRCL hashlookup** recognises known OS/distro/CDN/NSRL files (*known-good*) and carries a free `KnownMalicious` flag. Files no source knows are *unknown*; a filename disagreeing with the resolved identity is *name≠checksum*. Reported in the **Unmanaged / vendored binaries** chapter (1C) and the JSON export (`unmanaged` array). Cached + `--offline`-aware; the binary scan is on by default in `auto` mode and disabled with `--no-binaries`. No malware/AV lane.

> **npm without a lockfile**: a `package.json` lacking a sibling
> `package-lock.json`/`yarn.lock` is now scanned **best-effort** — pinned exact
> versions are checked, ranges (`^1.0.0`) are skipped, and a `no-lockfile` warning
> flags the partial coverage. Run `npm install`/`yarn install` for full coverage.

## Filtering deps

`-e <regex>` filters out coords whose **groupId** (Maven) or **name** (npm) matches the regex. Useful for private/internal libs that you know aren't on a public registry.

```bash
fad-checker -s . -e "^(com\.acme|org\.private)\."
fad-checker -s . -e "^@acme/"
```

The excluded coords are listed at the end of the run so you can audit the regex.

### Ignoring sub-paths (`--exclude-path`)

`-e` drops *dependencies* by coordinate; `--exclude-path` prunes the directory **walk** itself — nothing under a matched path is read, for every ecosystem. Patterns are gitignore-style globs (via `minimatch`, `dot:true`) matched against the path **relative to `--src`**; a pattern matches both the directory and its whole subtree.

All patterns are **anchored to the `--src` root** — `truc`, `/truc` and `./truc` are equivalent (a leading `/` or `./` is stripped). To match a name at any depth, use `**/` (e.g. `**/fixtures/**`).

```bash
fad-checker -s . --exclude-path "packages/legacy/**" --exclude-path "**/fixtures/**"
fad-checker -s . --exclude-path "apps/*/e2e"          # repeatable
fad-checker -s . --no-default-excludes                # also walk node_modules/vendor/target/.git/…
```

| Flag | Effect |
| --- | --- |
| `--exclude-path <glob...>` | Prune matching sub-paths (relative to `--src`). Repeatable; also settable as `excludePath: [...]` in `.fad-env.json` and unioned across all config layers. |
| `--no-default-excludes` | Don't prune the built-in ignored dirs (`node_modules`, `bower_components`, `vendor`, `dist`, `build`, `out`, `target`, `.git`, `.gradle`, `__pycache__`, …). Walks everything — slower, but nothing is hidden. |

## Per-source toggles

Each data source can be disabled independently:

| Flag | Effect |
| --- | --- |
| `--no-report` | Write **no output files at all** (gate-only / CI mode) — the scan, terminal summary and `--fail-on` gate still run. See **Outputs** for the per-type `--report-*` flags |
| `--no-transitive` | Don't fetch transitive Maven deps from Maven Central |
| `--no-all-libs` | Don't query Maven Central for latest versions (skips chapter 6 Outdated and the "missing on Central" check) |
| `--no-osv` | Skip OSV.dev (Google + GitHub aggregated feed) |
| `--no-nvd` | Skip NVD enrichment (no full CVSS, no CPE refinement) |
| `--no-epss` | Skip EPSS (FIRST.org) exploit-prediction enrichment |
| `--no-kev` | Skip CISA KEV (known-exploited) enrichment |
| `--licenses` | Run license detection + the copyleft-policy chapter (**off by default**; legacy `--no-licenses` is a no-op) |
| `--no-retire` | Skip retire.js vendored-JS scan |
| `--no-vendored-js-inventory` | Keep only **vulnerable** vendored JS (chapter 2); skip the full **inventory** of all identified standalone JS libs (chapter 1D). The inventory is a cyber-hygiene constat — unmanaged third-party JS regardless of CVEs — on by default. |
| `--no-jars` | Skip scanning embedded `.jar`/`.war`/`.ear` binaries for Maven coordinates (chapter 1B) |
| `--no-binaries` | Skip scanning committed native binaries (`.dll`/`.exe`/`.so`/`.dylib`) — no checksum identity/integrity (chapter 1C) |
| `--ignore-test` | Drop test-scoped Maven deps and dev npm deps from the scan entirely (chapter 2 will be empty) |

## Outputs

Every output has its own `--report-<type>` flag, each taking an **optional** path. Give a path to write there; omit the path to use a default name under `--report-output` (default dir `./fad-checker-report`). **If you pass no `--report-*` flag at all, the HTML + `.doc` report is written by default** (the historical behaviour); pass `--no-report` to write nothing (gate-only / CI). Selecting any `--report-*` flag writes exactly that set — e.g. `--report-sbom` alone writes only the SBOM, no HTML.

| Flag | Default name | Effect |
| --- | --- | --- |
| `--report-html [file]` | `cve-report.html` | The self-contained HTML report (inline CSS, no external assets). |
| `--report-doc [file]` | `cve-report.doc` | The same report as a Word-compatible `.doc`. |
| `--report-sbom [file]` | `sbom.cdx.json` | A **CycloneDX 1.6** SBOM with `vulnerabilities` inline (a VDR). Components carry purls + detected licenses (+ `fad:provenance`/`fad:location` for embedded-jar coords); vulnerabilities carry CVSS ratings, CWEs, affected purls, and `fad:epss` / `fad:kev` / `fad:priorityBand` properties. |
| `--report-csaf [file]` | `csaf-vex.json` | A **CSAF 2.0 VEX** (`csaf_vex`) document: a `product_tree` of every dep (purl-identified) plus per-CVE `product_status.known_affected`, `cvss_v3` scores, a KEV `exploited` flag, and prioritization notes. |
| `--report-json [file]` | `findings.json` | A flat **findings JSON** (fad's own format): every chapter (CVE/EOL/obsolete/outdated/licenses/vendored) + an `unmanaged` array (native-binary inventory with identity/integrity/signals), an `embedded` array (every JAR/WAR/EAR coordinate, vuln or not, with `vulnCount`/`maxSeverity`), EOL entries carrying their `productSlug`/`via`/`viaKey` origin, + a summary, easy to diff between audits and post-process. |
| `--report-sarif [file]` | `fad.sarif` | A **SARIF 2.1.0** log for GitHub Code Scanning / GitLab: one rule per CVE with `security-severity` (drives GitHub's severity), KEV tags, and the manifest (or embedding jar) as the result location. |
| `--report-output <dir>` | `./fad-checker-report` | Base directory for any output left at its default name. |

```bash
# default: HTML + .doc into ./fad-checker-report
fad-checker -s ./proj

# only the machine artifacts, default names under a custom dir
fad-checker -s ./proj --report-output ./out --report-sbom --report-csaf --report-json --report-sarif

# explicit paths
fad-checker -s ./proj --report-sbom sbom.cdx.json --report-sarif fad.sarif
```

All honour `--offline` (they render from whatever the scan already resolved).

## CI gating & triage

| Flag | Effect |
| --- | --- |
| `--fail-on <level>` | Exit non-zero when a **production or embedded-binary** finding meets the level: `low`/`medium`/`high`/`critical` (severity) or `kev` (only CISA-known-exploited). Default `none`. Outputs are written first, so artifacts always land. An invalid level hard-fails (exit 2) rather than silently disabling the gate. |
| `--ignore <file>` | Suppress findings. One rule per line: `CVE-2021-44228` (anywhere), `CVE-… org.apache.*` (coord/purl glob), `* npm:lodash` (any CVE for a coord); text after `#` is the reason. |
| `--vex <file>` | Ingest a **CSAF VEX**: CVEs marked `known_not_affected` / `fixed` are suppressed (products mapped back to coords by purl — round-trips fad's own `--report-csaf`). |

Suppressed findings are dropped from the report chapters and from `--fail-on`, but kept (flagged `suppressed`) in the JSON/SBOM/CSAF/SARIF exports, and the count is noted in chapter 0.

```bash
# Fail the pipeline only on exploited-in-the-wild vulns, minus accepted risks
fad-checker -s . --fail-on kev --ignore .fadignore --report-sarif fad.sarif
```

## Offline / cache control

```bash
# Use cached data only, no network (works for everything)
fad-checker -s . --offline

# Per-source offline
fad-checker -s . --cve-offline                  # use cached CVE index only
fad-checker -s . --cve-refresh                  # force re-download of CVE bundle
fad-checker -s . --retire-refresh               # force re-scan with retire.js (ignore cache)

# Cache export / import (useful for air-gapped boxes)
fad-checker --export-cache fad-cache.tar.gz
fad-checker --export-cache fad-cache.tar.gz --include-config   # bundle NVD key too
fad-checker --import-cache fad-cache.tar.gz
fad-checker --import-cache fad-cache.tar.gz --force            # replace existing without backup
```

The cache archive bundles everything under `~/.fad-checker/` (except `config.json`),
including retire.js findings **and** the warmed retire.js signature DB, so an importing
machine can scan vendored JavaScript fully offline.

> **Compiled binary, no `node`/`retire` needed:** the bun-compiled single binary
> (`dist/fad-checker-linux`, `.exe`, `-macos`) statically bundles the retire.js CLI and
> re-execs itself to run it — so vendored-JS scanning (chapters 1D / 2) works from the
> lone binary on an air-gapped box with no Node.js and no `retire` on `PATH`. The only
> input it needs is the signature DB warmed in phase 2 (carried in the cache archive).
> If retire still can't run, the failure is reported as a chapter-0 warning (run `-v`
> for the exact reason) instead of an empty chapter.

## Anonymized descriptor (PASSI / air-gapped audits)

For an offline/confidential system that can't reach the vuln databases, split the scan
across machines while keeping **only public coordinates** off the secure enclave — no
paths, URLs, hostnames or usernames. The detailed report is produced **back offline**.

```bash
# Phase 1 — OFFLINE (audited machine): export the anonymized descriptor, then stop.
#   -e excludes private/internal packages (offline we can't classify private vs public).
fad-checker -s ./proj -e "^(client|internal)\." --export-anonymized deps.json
#   deps.json is plain JSON (schema "fad-deps/1") — review it before transfer.

# Phase 2 — ONLINE (any machine, NO --src): warm the coordinate-keyed caches.
fad-checker --import-anonymized deps.json     # OSV/NVD/CVE/registry/EOL + retire signatures
fad-checker --export-cache fad-cache.tar.gz   # carry the warmed caches back

# Phase 3 — OFFLINE (audited machine): full report with real paths/manifests.
fad-checker --import-cache fad-cache.tar.gz
fad-checker -s ./proj --offline               # re-collect locally + cache hits → full report
```

Why it works: fad-checker's caches are keyed by *coordinate* / *vuln id*, never by path,
so warming them online and replaying offline yields cache hits. The descriptor keeps
`ecosystem`/`ecosystemType`/`namespace`/`name`/`version`/`versions`/`scope`/`isDev` and
drops manifest paths, registry URLs, integrity hashes and parent chains. The phase-2
report is itself path-free; vendored-JS (retire.js) findings come from phase 3 (retire
needs the actual `.js` files), using the signature DB warmed in phase 2.

## Custom registries (private repos)

`fad-checker` queries each ecosystem's public registry by default. Register private ones for **`maven`, `npm`, `pypi`, `ruby`, `go`** so transitive resolution, outdated/deprecation and license lookups reach them. (NuGet & Composer private feeds are not supported yet.)

| Flag | Effect |
| --- | --- |
| `--add-repo <eco> <name> <url> [--auth user:pass] [--token TOK]` | Persist a registry (in `~/.fad-checker/config.json` under `registries.<eco>`). |
| `--remove-repo <eco> <name>` | Remove a persisted registry. |
| `--list-repos` | List configured registries, grouped by ecosystem (auth masked). |
| `--repo <eco>=<url>` | One-off, not persisted; **repeatable**; auth via inline `https://user:pass@host/`. |

```bash
fad-checker --add-repo maven nexus     https://nexus.acme.com/repository/maven-public/ --auth alice:s3cr3t
fad-checker --add-repo npm   verdaccio https://npm.acme.com/                            --token "$NPM_TOKEN"
fad-checker --list-repos
fad-checker -s ./proj --repo npm=https://npm.acme.com/ --repo maven=https://nexus.acme.com/repository/maven-public/
```

Registries are tried **in declared order, the public registry last** (first 2xx wins). `--auth user:pass` → `Basic <base64>`; `--token TOK` → `Bearer TOK`. Responses are cached per coordinate. **PyPI/Ruby** custom bases must expose the same JSON API as the public one (`<base>/<pkg>/json`, `<base>/<gem>.json`), not a bare PEP 503 simple index.

## Configuration file & environment

Reusable defaults come from (lowest priority first): **`~/.fad-checker/config.json`** (global) → **`FAD_CHECKER_ENV`** (a CLI-flag string) → **config file** (`--config <file.json>`, else `./.fad-env.json`, JSON) → **CLI flags** (always win). A file/env value only fills an option you did not pass on the CLI; `registries` are unioned across all layers.

```bash
fad-checker --config ./ci/fad-env.json                         # JSON file of defaults
FAD_CHECKER_ENV='--fail-on high --no-nuget' fad-checker -s ./proj   # flag string of defaults
```

```jsonc
// ./.fad-env.json — keys mirror the CLI options (camelCase)
{
  "source": "./my-project",            // alias of --src / "src"
  "exclude": "^(com\\.acme|client)\\.",
  "excludePath": ["packages/legacy/**", "**/fixtures/**"],
  "failOn": "high",
  "noNuget": true,
  "offline": true,
  "registries": {
    "npm":   [{ "name": "verdaccio", "url": "https://npm.acme.com/", "token": "…" }],
    "maven": [{ "name": "nexus", "url": "https://nexus.acme.com/repository/maven-public/", "auth": "user:pass" }]
  }
}
```

The source directory accepts `-s`, `--src`, `--source` and the JSON key `"source"`/`"src"` interchangeably.

## NVD API key

NVD's public rate limit is 5 requests / 30s without a key. The free key bumps it to 50 / 30s — **10× faster** for the enrichment step.

```bash
# Get a key in 30 seconds: https://nvd.nist.gov/developers/request-an-api-key
fad-checker --set-nvd-key YOUR_KEY      # stored in ~/.fad-checker/config.json (mode 0600)
fad-checker --show-config               # confirm it's persisted (key masked)
```

Or pass it ad-hoc via the `NVD_API_KEY` env var.

## Snyk integration

If you have `snyk` installed and authenticated, `fad-checker` can drive it:

```bash
fad-checker -s ./proj -t ../proj-clean -e "^com\.acme\." --snyk
```

This:
1. Generates the cleaned POM tree at `../proj-clean/`.
2. Runs `snyk test --all-projects --json` against it.
3. Merges Snyk's findings into the report — entries present in both `fad-checker` and Snyk are tagged `source: "both"`.

`--snyk` requires `-t` (Snyk needs a real POM tree to scan).

## Read-only vs write mode

| Mode | Trigger | Disk writes |
| --- | --- | --- |
| Read-only | `-t` omitted (default) | Only `~/.fad-checker/` caches and the report dir |
| Write | `-t <dir>` provided | Above + the cleaned POM tree at `<dir>` (and `<dir>` is `rimraf`'d first!) |

The `--target` guardrails refuse:
- empty `--src`
- `--target` equal to or a subdirectory of `--src`

## Verbosity

```bash
fad-checker -s . -v          # progress per source (OSV batches, NVD pages, retire scan, …)
```

## Shell completion

```bash
fad-checker --completion bash > /etc/bash_completion.d/fad-checker
fad-checker --completion zsh  > ~/.zsh/completions/_fad-checker
```

## All flags at a glance

```bash
fad-checker --help
```

## Recipes

### CI gate: fail the build on any CRITICAL prod CVE

`fad-checker` exits 0 even when CVEs are found (it's a reporter, not a gate). Wire your own:

```bash
fad-checker -s . --no-nvd > /dev/null
# Then grep the report or parse the structured output (planned).
```

(A `--fail-on critical` flag is a planned addition — track it in issues.)

### Diff two runs

Keep dated copies of the report:

```bash
fad-checker -s . --report-output reports/$(date +%F)
diff reports/2026-04-01/cve-report.html reports/2026-05-01/cve-report.html
```

### Air-gapped scan (anonymized descriptor — PASSI)

The robust way: export an anonymized descriptor offline, warm caches online from it,
re-scan offline. Only public coordinates ever leave the secure machine.

```bash
# OFFLINE (audited machine)
fad-checker -s ./real-project -e "^(client|internal)\." --export-anonymized deps.json

# ONLINE (connected machine, no source needed)
fad-checker --import-anonymized deps.json      # warms ~/.fad-checker/ caches from the coords
fad-checker --export-cache fad-cache.tar.gz

# OFFLINE again — full report with real paths
fad-checker --import-cache fad-cache.tar.gz
fad-checker -s ./real-project --offline
```

See the **Anonymized descriptor** section above for what the descriptor contains and why
the round-trip produces a complete report without leaking environment information.
