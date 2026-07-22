# Scanner benchmark: full capability, and with no network

Five scanners on one public project, measured two ways. Everything here is reproducible — the
target is pinned to a commit, the commands are below, and every number can be recomputed from
the tools' own JSON output. Run it and tell me if it doesn't hold.

Spoiler for the impatient, so nothing here reads as a sales pitch: **at full capability no tool
finds everything, fad-checker included** — it leads at 87% of the union and misses 118 pairs
Snyk found. Its actual differentiator is the second table: what survives when the network is
gone.

## Two different questions

A scanner comparison usually conflates two things. This one separates them, because the
answers are not the same.

1. **At full capability, what does each tool find?** Every scanner online, in its best
   configuration, with a populated `~/.m2`. This is the fair product comparison.
2. **With no network, what survives?** The narrower question fad-checker is built around.

Target for both: **Apache Dubbo 2.7.8**, a 105-module Maven reactor
(`0be2a1bbbf9168490acecaf1eed1bd16cb8db402`).

Unit: distinct `(coordinate@version | vulnerability)` pairs, Maven only, GHSA and `SNYK-*` ids
mapped to their CVE alias so every tool sits on one identifier space. Dubbo's **own**
`org.apache.dubbo` artifacts are excluded on every side: OSV-Scanner filters reactor modules as
"local/unscannable", so counting them would flatter whoever does scan them.

## 1. Full capability

Union of everything any tool found: **908** pairs.

| Scanner, best configuration | Found | Unique to it | % of union | Misses |
| --- | --- | --- | --- | --- |
| **fad-checker 2.4.8** | **790** | 125 | **87.0%** | 118 |
| OSV-Scanner 2.4.0 (online) | 657 | 0 | 72.4% | 251 |
| Snyk 1.1302.1 (`--all-projects`, mvn build) | 603 | **117** | 66.4% | 305 |
| Trivy 0.72.0 (populated `~/.m2`) | 546 | 0 | 60.1% | 362 |
| Grype 0.116.0 + Syft 1.49.0 | 45 | 0 | 5.0% | 863 |

**No tool finds everything, including this one.** fad leads on volume and misses 118 pairs that
another tool found. Every one of those 118 comes from Snyk: 30 carry a proprietary `SNYK-*` id
with no public CVE alias, so no tool matching public databases can have them — that is a genuine
advantage of a commercial feed, not a fad bug. The other **88 are public CVEs fad genuinely
misses** (`logback-classic@1.2.2`, `hessian-lite@3.2.8`, `nacos-common@1.3.1` …), and they are an
open gap, not a rounding error.

Read the other rows fairly too. Trivy and Grype are **container and SBOM scanners**; a raw Maven
source checkout is not the job they are built for. Snyk and Trivy at full capability both depend
on a real Maven build having happened — Snyk invokes `mvn`, and Trivy needs either network access
or a `~/.m2` that a previous build populated. fad-checker and OSV-Scanner read the tree without
building. That is a different starting assumption, not a better one, and it is the reason the
second table exists.

Two measured details worth stating rather than assuming. **Trivy's result is identical online and
with a fully populated `~/.m2`** (559 raw pairs either way) — the local repository fully
substitutes for the network. **Grype+Syft does not move at all**: 58 raw pairs with defaults, 58
with `java.use-network=true` and `java.resolve-transitive-dependencies=true`, because that option
is scoped to archives, not to `pom.xml` source scanning.

## 2. No network at all

Same tree, every scanner under `unshare -rn`, in a namespace with **no network interface** —
not merely an offline flag. Reference: OSV-Scanner's own **online** output, 657 pairs.

| Scanner, no network | Recovers | Wall clock |
| --- | --- | --- |
| **fad-checker 2.4.8** `--offline` | **657 (100%)** | 4.5 s |
| Grype + Syft (defaults) | 45 (6.8%) | 32 s |
| Trivy `--offline-scan`, cold `~/.m2` | 40 (6.1%) | 1.0 s |
| OSV-Scanner `--offline` | 37 (5.6%) | 0.8 s |

100% here means "recovers everything OSV-Scanner finds **with** network access", not "finds
everything that exists" — table 1 is the honest answer to that, and there fad sits at 87%.
OSV-Scanner returns the identical 37 with and without the namespace: it behaves exactly as
documented, it is not failing.

The mechanism is in OSV-Scanner's own documentation:

> "OSV-Scanner supports transitive dependency scanning for Maven pom.xml. This feature is enabled
> by default when scanning, but it can be disabled using the `--no-resolve` flag. **It is also
> disabled in the offline mode.**"
> — [supported languages and lockfiles](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)

Online, OSV-Scanner finds 92 vulnerable Maven packages on this project. Offline it finds 3. The
missing 89 are transitive.

Note the asymmetry between the two Trivy rows: 40 pairs on a cold `~/.m2`, 546 once a build has
populated it. Trivy's dependency is on *a resolved local repository*, which the network or a
prior build can supply. fad's cache is coordinate-keyed and travels
(`--export-cache` / `--import-cache`), which is what makes the air-gapped workflow work.

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

# 5. Snyk at full capability — it invokes mvn, so this also populates ~/.m2
cd dubbo && snyk test --all-projects --json > ../snyk.json; cd ..

# 6. Trivy at full capability. With ~/.m2 populated by step 5 this equals the online
#    result exactly (559 raw pairs either way), which is worth verifying yourself.
trivy fs --scanners vuln --offline-scan --format json --output trivy-full.json ./dubbo
trivy fs --scanners vuln --format json --output trivy-online.json ./dubbo

# 7. Grype + Syft at full capability. Syft's transitive option is scoped to ARCHIVES, so on
#    a pom.xml source tree it is a no-op — the result does not move, 58 pairs either way.
grype dir:./dubbo -o json --file grype.json
SYFT_JAVA_RESOLVE_TRANSITIVE_DEPENDENCIES=true SYFT_JAVA_USE_NETWORK=true \
  syft dir:./dubbo -o syft-json=s.json && grype sbom:./s.json -o json --file grype-full.json
```

**If Maven Central rate-limits you** (`429 Too Many Requests`), and running several of these
back to back will, point Trivy at a mirror instead of waiting it out. Trivy reads
`settings.xml`, honours `<mirrors>`, and `MAVEN_HOME` keeps it out of your real Maven config:

```bash
mkdir -p /tmp/mvnhome/conf && cat > /tmp/mvnhome/conf/settings.xml <<'XML'
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <localRepository>${user.home}/.m2/repository</localRepository>
  <mirrors><mirror>
    <id>gcs-central</id><mirrorOf>central</mirrorOf>
    <url>https://maven-central.storage-download.googleapis.com/maven2</url>
  </mirror></mirrors>
</settings>
XML
MAVEN_HOME=/tmp/mvnhome trivy fs --scanners vuln --format json -o trivy-online.json ./dubbo
```

That is how the online Trivy row here was obtained: the benchmark IP had been rate-limited by
the other scans, the penalty renewed on every retry, and the mirror is a different host serving
identical artifacts.

Compare on `(coordinate@version | vulnerability id)` pairs, restricted to Maven. Normalise two
things or the comparison is meaningless: map OSV `GHSA-*` ids to their `CVE-*` alias, and strip
Maven hard-pin brackets (`[1.2.3]` → `1.2.3`).

Environment for the numbers above: Node 24.14.0, Linux 6.6.87 (WSL2), fad-checker 2.4.8,
OSV-Scanner 2.4.0 (osv-scalibr 0.4.5).

## What fad-checker misses, and why

**At full capability: 118 pairs**, all of them found by Snyk and by no other tool.

- **30** carry a proprietary `SNYK-*` identifier with no public CVE alias. They exist in Snyk's
  commercial database and in no public one, so no tool matching CVEProject/OSV/NVD can find
  them. That is what a paid feed buys.
- **88 are public CVEs that fad genuinely misses** — `logback-classic@1.2.2`,
  `hessian-lite@3.2.8`, `nacos-common@1.3.1` and others. This is an open gap in fad's matching,
  not an artefact of the method, and it is not yet diagnosed.

**With no network: nothing**, on this project — 657 of 657 against OSV-Scanner's online output.
That is recall against one tool's view in one scenario, not a claim of completeness; the 118
above are the completeness answer.

Getting there took four bugs, each found by this benchmark and each documented below with the
`mvn dependency:tree` output that settled it.

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
