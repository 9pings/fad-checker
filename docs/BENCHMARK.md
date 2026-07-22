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
| **fad-checker 2.4.8** `--offline` | **657 (100%)** | 4.5 s |
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

# 5. Trivy and Grype, same tree
trivy fs --scanners vuln --offline-scan --format json --output trivy.json ./dubbo
grype dir:./dubbo -o json --file grype.json
# Syft's transitive option is scoped to archives, so on a source tree it is a no-op.
# Verify rather than take my word for it — the result does not move:
SYFT_JAVA_RESOLVE_TRANSITIVE_DEPENDENCIES=true syft dir:./dubbo -o syft-json=s.json \
  && grype sbom:./s.json -o json --file grype-transitive.json
```

Compare on `(coordinate@version | vulnerability id)` pairs, restricted to Maven. Normalise two
things or the comparison is meaningless: map OSV `GHSA-*` ids to their `CVE-*` alias, and strip
Maven hard-pin brackets (`[1.2.3]` → `1.2.3`).

Environment for the numbers above: Node 24.14.0, Linux 6.6.87 (WSL2), fad-checker 2.4.8,
OSV-Scanner 2.4.0 (osv-scalibr 0.4.5).

## What fad-checker misses, and why

Nothing, on this project: **657 of 657**, with no network.

That is not a claim that fad finds everything everywhere. It means that on this reactor, every
`package@version | vulnerability` pair OSV-Scanner reports **with** network access, fad also
reports **without** any. The reference set is OSV-Scanner's, so this measures recall against one
tool's view, not absolute correctness — see the caveats below, which still apply in full.

The last gap to close was four pairs on `org.hibernate:hibernate-validator@5.2.4.Final`, and it
was not a resolution bug but a property-inheritance one. See "A fourth gap" below.

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

## A second gap this benchmark closed: the test classpath

The first version of this benchmark listed `org.springframework.boot:spring-boot` and
`spring-boot-autoconfigure` at 1.5.17.RELEASE as "not resolved", a real gap. It was.

Maven's scope matrix says `test → compile = test`: the compile dependencies of a test-scoped
dependency are on the test classpath, and so are theirs, recursively. Only `test → test` is
omitted. In Dubbo the chain is four hops long and `mvn dependency:tree` reports every node at
scope=test:

```
dubbo-registry-sofa
  └─ com.alipay.sofa:registry-test:5.2.0                      (test)
       └─ com.alipay.sofa:registry-server-integration:5.2.0   (compile → test)
            └─ org.springframework.boot:spring-boot-starter:1.5.17.RELEASE (compile → test)
                 └─ org.springframework.boot:spring-boot:1.5.17.RELEASE    (compile → test)
```

fad passed test-scoped roots into transitive resolution but then filtered accepted scopes to
compile/runtime/provided, so every child of a test root was discarded at the first hop. The dev
chapter only ever showed *directly declared* test dependencies, never their transitives.

Fixed, and the fix needed a second half that matters more than the first. Marking everything
under a test root as dev is wrong: a coordinate reachable from **both** a test root and a
compile root is on the compile classpath. The traversal dedupes by `g:a` and keeps the first
chain it walks, so BFS order alone decided the scope — the first cut of this fix silently moved
6 production findings (`spring-core`, `commons-lang` and 4 others) into the dev chapter, out of
the production count *and out of the `--fail-on` gate*. A false negative on the production
classpath is worse than the gap being fixed. Scope is now widened on revisit and never
narrowed.

Result on Dubbo: **575 → 579** recovered, production findings **unchanged at 650**, dev findings
7 → 11. Locked by 6 tests in `test/transitive-test-scope.test.js`, including the both-paths case.

## A third gap closed: test-scope versions the global pass masks

The previous round scanned the transitive closure of test-scoped dependencies, but the
per-module overlay still could not recover a **version** that only a test path holds. The
overlay exists precisely because the global pass dedupes by `g:a` across the whole reactor and
keeps one version per coordinate — yet it hardcoded
`includedScopes: ["compile","runtime","provided"]`, so a version reachable only through a
test-scoped dependency was structurally unreachable.

That single omission accounted for **every one** of the 78 findings OSV-Scanner reported and
fad missed. All verified against `mvn dependency:tree`: `jackson-databind:2.8.4:test` in
dubbo-registry-sofa, `hibernate-validator:5.2.4.Final:test` in dubbo-filter-validation,
`okhttp:3.11.0` / `okio:1.14.0` at test scope in dubbo-configcenter-apollo,
`commons-compress:1.18:test` in dubbo-remoting-etcd3.

Three separate correctness rules had to come with it, and each was found by a test that failed
first:

1. **A version is dev only when EVERY module resolving it does so at test scope.** On Dubbo,
   `jackson-databind:2.10.4` is test-scoped in dubbo-config-spring and **compile**-scoped in
   dubbo-configcenter-nacos. Reading the first recorded provenance called it dev and dropped a
   genuine production finding out of the count and out of `--fail-on`.
2. **Provenance is recorded per module even when the version is already known.** The overlay
   used to bail out on the first module to contribute a version, so the compile-scoped
   provenance in rule 1 was never recorded at all.
3. **A DECLARED version wins over any transitive provenance for the same version.**
   `xstream:1.4.10` is declared outright in dubbo-registry-eureka and *also* reached as a
   test-scoped transitive of dubbo-config-api. Letting the transitive win demoted 35 findings,
   one of them KEV, into the dev chapter.

Result on Dubbo: **579 → 653** recovered (88.1% → 99.4%), production findings **651**
(unchanged, +1), dev findings 11 → 147, zero production finding lost. Locked by 6 tests in
`test/version-overlay-test-scope.test.js` against a 4-module fixture.

## A fourth gap closed: an imported BOM's properties leaking

The reactor root sets `<hibernate_validator_version>5.2.4.Final</hibernate_validator_version>`.
`dubbo-dependencies-bom`, imported into that root's `<dependencyManagement>` with
`<scope>import</scope>`, redefines the same property to `5.4.1.Final`. Maven imports a BOM's
`<dependencyManagement>` and **nothing else** — the BOM resolves its managed versions in its own
property context, and its `<properties>` never become the importer's.

fad merged them, and merged them so the BOM *won*
(`{...merged.properties, ...imported.properties}`). So `dubbo-filter-validation`, which declares
`<version>${hibernate_validator_version}</version>`, resolved to 5.4.1.Final instead of the
5.2.4.Final it inherits from the root. A different version is a different CVE set.
`mvn dependency:tree` reports `hibernate-validator:jar:5.2.4.Final:test` for that module.

Fixed at the import boundary in `core.js`: the BOM's managed entries are interpolated against
the BOM's own properties there, and the properties are dropped
(`lib/transitive.js#effectivePom` already did the equivalent for *external* import BOMs).

One correctness rule shipped with it, symmetric to the masked-version rule above: **a version
declared only at test scope is dev**, even when the coordinate is production at another version.
`isDev` lives on the coord-wide record, so 5.2.4.Final was inheriting the production flag of
5.4.1.Final and would have counted toward the production total and the `--fail-on` gate.
Per-version scopes are now recorded next to per-version paths.

Result: **653 → 657 of 657 (100%)**, production 651, dev 147 → 151.

## Honest caveats

- **`--offline` needs a warmed cache.** These numbers come from a cache warmed by one prior
  online run on the same project. On a cold cache the air-gapped run legitimately finds nothing.
  That is the intended air-gapped workflow (`--export-cache` / `--import-cache`), not a trick,
  but it means "100% with no network" is not the same as "100% from a standing start".
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
