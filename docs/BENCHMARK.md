# Air-gapped recall benchmark

**Question.** With **zero network access**, how much of a project's known vulnerability set can a
scanner still find?

This is the one claim `fad-checker` makes that is hard to make: it resolves the Maven transitive
graph from cached POMs, so an air-gapped scan still sees the transitive dependency tree. Most
scanners disable transitive resolution when there is no network, and only direct dependencies
remain.

Everything below is reproducible on a public project. Run it yourself and tell me if the numbers
don't hold.

## Result

Target: **Apache Dubbo 2.7.8**, a 105-module Maven reactor
(`0be2a1bbbf9168490acecaf1eed1bd16cb8db402`).

Reference set: **OSV-Scanner's own online run**, 657 distinct
`(package@version | vulnerability)` pairs. Using the competitor's online output as the yardstick
avoids grading either tool against its own notion of a finding.

| Scanner, **no network at all** | Pairs recovered from the 657 | Wall clock |
| --- | --- | --- |
| **fad-checker 2.4.5** `--offline` | **575 (87.5%)** | 4.5 s |
| OSV-Scanner 2.4.0 `--offline` | **37 (5.6%)** | 0.8 s |

Both were run under `unshare -rn`, in a namespace with **no network interface**, not merely with
an offline flag. OSV-Scanner returns the identical 37 with and without the namespace, which is
the honest reading: it is behaving exactly as documented, not failing.

The mechanism is not in dispute, it is in OSV-Scanner's own documentation:

> "OSV-Scanner supports transitive dependency scanning for Maven pom.xml. This feature is enabled
> by default when scanning, but it can be disabled using the `--no-resolve` flag. **It is also
> disabled in the offline mode.**"
> — [supported languages and lockfiles](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)

Online, OSV-Scanner finds 92 vulnerable Maven packages on this project. Offline it finds 3. The
missing 89 are transitive.

## Reproducing it

```bash
# 1. The target, pinned
git clone --depth 1 --branch dubbo-2.7.8 https://github.com/apache/dubbo.git

# 2. Reference set: OSV-Scanner, online, transitive resolution on (its default)
osv-scanner scan source -r ./dubbo --format json --output osv-online.json

# 3. OSV-Scanner with no network
osv-scanner scan source -r ./dubbo --offline --download-offline-databases \
  --format json --output osv-offline.json          # fetches its local DB once
unshare -rn osv-scanner scan source -r ./dubbo --offline \
  --format json --output osv-airgap.json           # real air gap

# 4. fad-checker: one online run to warm the cache, then no network
fad-checker -s ./dubbo --report-json fad-online.json
unshare -rn fad-checker -s ./dubbo --offline --report-json fad-airgap.json
```

Compare on `(coordinate@version | vulnerability id)` pairs, restricted to Maven. Normalise two
things or the comparison is meaningless: map OSV `GHSA-*` ids to their `CVE-*` alias, and strip
Maven hard-pin brackets (`[1.2.3]` → `1.2.3`).

Environment for the numbers above: Node 24.14.0, Linux 6.6.87 (WSL2), fad-checker 2.4.5,
OSV-Scanner 2.4.0 (osv-scalibr 0.4.5).

## What fad-checker misses, and why

87.5% is not 100%. The 82 unrecovered pairs are **not** advisory-matching failures. Every one of
them is a coordinate that fad resolved to a *different version* than deps.dev did, or did not
resolve at all. They cluster in 9 coordinates:

| Coordinate | OSV resolved | fad resolved | Pairs missed |
| --- | --- | --- | --- |
| `com.fasterxml.jackson.core:jackson-databind` | 2.8.4 | 2.5.2, 2.9.4, 2.9.5, 2.9.9, 2.10.4 | 56 |
| `org.apache.commons:commons-compress` | 1.18 | 1.8.1 | 6 |
| `com.google.guava:guava` | 16.0.1, 18.0 | 16.0, 19.0, 20.0, 24.1.1-jre, 26.0-android, 27.1-jre | 6 |
| `org.hibernate:hibernate-validator` | 5.2.4.Final | 5.4.1.Final | 4 |
| `com.fasterxml.jackson.core:jackson-core` | 2.8.4 | 2.5.2, 2.8.6, 2.9.4, 2.9.5, 2.9.9, 2.10.4 | 4 |
| `org.springframework.boot:spring-boot` | 1.5.17.RELEASE | **not resolved** | 3 |
| `com.squareup.okhttp3:okhttp` | 3.11.0 | 3.12.2 | 1 |
| `com.squareup.okio:okio` | 1.14.0 | 1.15.0 | 1 |
| `org.springframework.boot:spring-boot-autoconfigure` | 1.5.17.RELEASE | **not resolved** | 1 |

Two distinct causes, worth separating:

1. **Version-mediation divergence** (most of them). Two resolvers walking the same graph pick
   different winners for the same coordinate. Neither is obviously wrong: fad applies Maven's
   own nearest-definition-wins semantics per module, deps.dev applies its own resolution. One
   coordinate, `jackson-databind`, accounts for 56 of the 82 on its own.
2. **Genuinely unresolved** (4 pairs). The two `spring-boot` coordinates were never resolved to
   a version, so they were never scanned. A real gap, still open.

## A bug this benchmark surfaced, and fixed

The first run of this benchmark reported 566/657 and 7 findings carrying a version string of the
form `[4.1.35.Final]`. That is Maven's *hard-pin* syntax, meaning exactly 4.1.35.Final, and
`io.grpc:grpc-netty:1.22.1` declares its netty dependency that way. fad kept the brackets
verbatim, so the coordinate was wrong in the report, in the purl, and in every export, and the
finding could not be joined with any other tool's output for the same dependency.

Fixed in `lib/maven-version.js#normalizeHardPin`, applied on both paths that produce a version
(`cve-match.js#resolveDepVersion` for declared deps, `transitive.js` for deps read out of
upstream POMs). A real range keeps its brackets: choosing a version out of `[1.0,2.0)` is
resolution, not normalisation, and it should keep surfacing as unresolved. Locked by four tests
in `test/cve-match.test.js`.

Effect on this benchmark: **566 → 575** recovered pairs, and zero corrupted versions in the
exports.

One consequence worth knowing, because it is a general property of the offline design: the OSV
cache is keyed by coordinate **and version**, so fixing a version string invalidates the entries
warmed under the old one. The air-gapped numbers above were measured after re-warming the cache
with the fixed code. A version-affecting change means a cache re-warm, not just a re-run.

## Honest caveats

- **`--offline` needs a warmed cache.** These numbers come from a cache warmed by one prior
  online run on the same project. On a cold cache the air-gapped run legitimately finds nothing.
  That is the intended air-gapped workflow (`--export-cache` / `--import-cache`), not a trick,
  but it means "87.5% with no network" is not the same as "87.5% from a standing start".
- **The machine had a populated `~/.m2` (287 MB).** It does not affect either tool here
  (OSV-Scanner resolves via deps.dev or Maven Central, not the local repository), but Trivy and
  Syft *do* consult it, so a comparison including them must control for it.
- **One project, one shape.** Dubbo is a large flat reactor with heavy transitive depth. A
  project whose vulnerabilities are mostly in direct dependencies would narrow the gap sharply,
  because direct dependencies are exactly what an offline scanner still sees.
- **This measures recall against one reference, not correctness.** fad also reports ~90 pairs that
  are not in OSV-Scanner's online output at all, because it additionally matches against the
  CVEProject index and NVD. Those are not counted as wins here, and they are not independently
  validated by this benchmark.

## Earlier private measurement

A previous run on a private 25-module Spring/JSF reactor measured 181/202 Snyk-corroborated
findings for fad-checker against OSV-Scanner v2.3.8's 64/202, and the per-module version
mediation overlay lifting coverage from 156 to 181. Those numbers are consistent with what this
public benchmark shows, but they are **not independently reproducible** and should not be quoted
without that qualification. Prefer the Dubbo numbers.
