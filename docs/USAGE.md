# USAGE

Every flag, every common workflow, with copy-pasteable commands.

## Synopsis

```text
fad-check -s <src> [-t <target>] [-e <regex>] [other options]
```

- `-s, --src <src>` — **required**. Root of the source tree to scan. Contains `pom.xml` and/or `package(-lock).json` / `yarn.lock`.
- `-t, --target <dir>` — optional. If given, write a parallel directory of "cleaned" POMs (private/excluded deps stripped) to `<dir>` — useful as Snyk input. Without `-t`, the run is read-only.

## Output

By default the HTML + Word reports land in `./fad-check-report/`. Override with `--report-output <dir>`.

## Ecosystem selection

```bash
# Auto-detect (default): scan whatever pom.xml / package(-lock).json / yarn.lock exists
fad-check -s .

# Force one ecosystem
fad-check -s . --ecosystem maven
fad-check -s . --ecosystem npm
fad-check -s . --ecosystem both     # scan both even if only one is auto-detected

# Disable JS scanning entirely (Maven-only)
fad-check -s . --no-js
```

## Filtering deps

`-e <regex>` filters out coords whose **groupId** (Maven) or **name** (npm) matches the regex. Useful for private/internal libs that you know aren't on a public registry.

```bash
fad-check -s . -e "^(com\.acme|org\.private)\."
fad-check -s . -e "^@acme/"
```

The excluded coords are listed at the end of the run so you can audit the regex.

## Per-source toggles

Each data source can be disabled independently:

| Flag | Effect |
| --- | --- |
| `--no-report` | Skip the report flow entirely (just cleanup) |
| `--no-transitive` | Don't fetch transitive Maven deps from Maven Central |
| `--no-all-libs` | Don't query Maven Central for latest versions (skips chapter 6 Outdated and the "missing on Central" check) |
| `--no-osv` | Skip OSV.dev (Google + GitHub aggregated feed) |
| `--no-nvd` | Skip NVD enrichment (no full CVSS, no CPE refinement) |
| `--no-retire` | Skip retire.js vendored-JS scan |
| `--ignore-test` | Drop test-scoped Maven deps and dev npm deps from the scan entirely (chapter 2 will be empty) |

## Offline / cache control

```bash
# Use cached data only, no network (works for everything)
fad-check -s . --offline

# Per-source offline
fad-check -s . --cve-offline                  # use cached CVE index only
fad-check -s . --cve-refresh                  # force re-download of CVE bundle
fad-check -s . --retire-refresh               # force re-scan with retire.js (ignore cache)

# Cache export / import (useful for air-gapped boxes)
fad-check --export-cache fad-cache.tar.gz
fad-check --export-cache fad-cache.tar.gz --include-config   # bundle NVD key too
fad-check --import-cache fad-cache.tar.gz
fad-check --import-cache fad-cache.tar.gz --force            # replace existing without backup
```

## NVD API key

NVD's public rate limit is 5 requests / 30s without a key. The free key bumps it to 50 / 30s — **10× faster** for the enrichment step.

```bash
# Get a key in 30 seconds: https://nvd.nist.gov/developers/request-an-api-key
fad-check --set-nvd-key YOUR_KEY      # stored in ~/.fad-check/config.json (mode 0600)
fad-check --show-config               # confirm it's persisted (key masked)
```

Or pass it ad-hoc via the `NVD_API_KEY` env var.

## Snyk integration

If you have `snyk` installed and authenticated, `fad-check` can drive it:

```bash
fad-check -s ./proj -t ../proj-clean -e "^com\.acme\." --snyk
```

This:
1. Generates the cleaned POM tree at `../proj-clean/`.
2. Runs `snyk test --all-projects --json` against it.
3. Merges Snyk's findings into the report — entries present in both `fad-check` and Snyk are tagged `source: "both"`.

`--snyk` requires `-t` (Snyk needs a real POM tree to scan).

## Read-only vs write mode

| Mode | Trigger | Disk writes |
| --- | --- | --- |
| Read-only | `-t` omitted (default) | Only `~/.fad-check/` caches and the report dir |
| Write | `-t <dir>` provided | Above + the cleaned POM tree at `<dir>` (and `<dir>` is `rimraf`'d first!) |

The `--target` guardrails refuse:
- empty `--src`
- `--target` equal to or a subdirectory of `--src`

## Verbosity

```bash
fad-check -s . -v          # progress per source (OSV batches, NVD pages, retire scan, …)
```

## Shell completion

```bash
fad-check --completion bash > /etc/bash_completion.d/fad-check
fad-check --completion zsh  > ~/.zsh/completions/_fad-check
```

## All flags at a glance

```bash
fad-check --help
```

## Recipes

### CI gate: fail the build on any CRITICAL prod CVE

`fad-check` exits 0 even when CVEs are found (it's a reporter, not a gate). Wire your own:

```bash
fad-check -s . --no-nvd > /dev/null
# Then grep the report or parse the structured output (planned).
```

(A `--fail-on critical` flag is a planned addition — track it in issues.)

### Diff two runs

Keep dated copies of the report:

```bash
fad-check -s . --report-output reports/$(date +%F)
diff reports/2026-04-01/cve-report.html reports/2026-05-01/cve-report.html
```

### Air-gapped scan

On a connected machine:

```bash
fad-check -s ./dummy-empty-dir       # populates ~/.fad-check/ caches
fad-check --export-cache fad-cache.tar.gz --include-config
```

Move `fad-cache.tar.gz` to the air-gapped box, then:

```bash
fad-check --import-cache fad-cache.tar.gz
fad-check -s ./real-project --offline
```

### Monorepo with Maven + JS + vendored JS

The reference-project-style project (Java backend, React frontend in `web/`, vendored jQuery/PDF.js under `web/src/main/webapp/`):

```bash
fad-check -s . -e "^(com\.captcha|org\.voxaly|com\.voxaly)\."
# → finds CVE in Maven deps, in web/package-lock.json deps,
#   AND in the vendored .js files under webapp/.
```
