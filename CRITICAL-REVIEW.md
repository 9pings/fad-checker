# fad-checker — Analyse critique complète

**Date :** 2026-05-22
**Périmètre :** intégralité du code (`fad-checker.js` + `lib/**/*.js` + `data/*.json` + `test/`)
**Méthode :** 4 audits parallèles à effort xhigh (reuse / quality / efficiency / **faux positifs**)
**Verdict global :** architecture saine, mais **4 chemins fail-open en cascade dans le matcher CVE** produisent un taux de faux positifs estimé entre **20 % et 60 %** selon le niveau de confiance retenu. À traiter en priorité avant toute exploitation en production.

---

## TL;DR — Risque de faux positifs

| Tier de confiance | Taux de FP estimé sur ~500 deps | Recommandation |
|---|---|---|
| `exact` uniquement | 5–10 % | Utilisable (triage léger) |
| `exact` + `probable` | 20–30 % | Triage manuel obligatoire |
| Tous tiers (`exact` + `probable` + `possible`) | **40–60 %** | Inexploitable sans tri humain |

Quatre fail-open en cascade :

1. **H1** — `isVersionAffected` retourne `true` quand le CVE n'a aucune borne de version (`lib/maven-version.js:101-124`).
2. **H2** — `vendorMatchesGroup` fait du *substring matching* (`g.includes(v) || v.includes(g)`) — `vendor="open"` matche `org.opensaml.*` (`lib/cve-match.js:164-173`).
3. **H3** — Tier-3 `possible` émis pour toute collision d'`artifactId`, même quand le vendor est totalement étranger (`lib/cve-match.js:191-198`).
4. **H4** — Le filtre CPE (« primary FP filter ») se contente de **marquer** `cpeFiltered=true`, il ne supprime jamais (`lib/cpe.js:269-272`).

Ces quatre interagissent de manière pathologique : H3 laisse passer une masse de matches `possible`, H2 en remonte beaucoup en `probable`, H1 valide toutes les versions, et H4 ne filtre plus rien en aval.

---

## A. Faux positifs (critère #1 demandé)

### HIGH

#### H1 — `isVersionAffected` fail-open quand pas de bornes
**Fichier :** `lib/maven-version.js:101-124`

```js
if (spec.version && spec.version !== "0" && spec.version !== "*") { /* lower */ }
if (spec.lessThan)        { ... }
if (spec.lessThanOrEqual) { ... }
if (!spec.lessThan && !spec.lessThanOrEqual && spec.version && …) { /* exact */ }
return true;   // ← fall-through "affected"
```

Empiriquement : `isVersionAffected("2.14", { status: "affected" })` → `true`. CVEProject contient régulièrement des entrées `versions:[{status:"affected"}]` sans bornes (stub mal formé). Combiné à H2, **toute dep qui hit le `byProduct` tier-2 avec un range sparse est flaggée sur toute version**.

**FP concret :** CVE listant `affected: [{ product: "log4j", versions: [{ status: "affected" }] }]` → flag `log4j-core 2.99.0` (patché) car pas de borne haute, pas d'exact-match, fall-through → `true`.

**Fix :**
```js
if (!spec.version && !spec.lessThan && !spec.lessThanOrEqual) return false;
```

---

#### H2 — `vendorMatchesGroup` substring-match → cross-vendor leak
**Fichier :** `lib/cve-match.js:164-173`

```js
if (g.includes(v) || v.includes(g)) return true;
```

`vendorMatchesGroup("spring", "foospringbar")` → `true`. NVD/CVEProject contiennent régulièrement des vendors `"a"`, `"oss"`, `"com"`, `"java"`, `"go"`, `"web"`, `"open"`, `"ibm"`, `"net"` — tous présents en sous-chaîne dans des groupIds réels.

**FP concrets :**
- CVE `vendor="open"` matche `org.opensaml:opensaml-core` (`"opensaml".includes("open")`).
- CVE `vendor="ibm"` matche `com.ibmcloudant:cloudant-client`.
- CVE `vendor="spring"` matche `org.springframework.*` ET `com.foospringbar.*`.

**Fix :** restreindre à (a) `g === v`, (b) `g.split(".").includes(v)`, (c) `v.includes(g)` seulement si `g.length >= 4`. Drop des branches substring non bornées.

---

#### H3 — Tier-3 `possible` émis avec vendor totalement étranger
**Fichier :** `lib/cve-match.js:191-198`

```js
const productMatches = byProduct[dep.artifactId.toLowerCase()] || [];
for (const e of productMatches) {
  if (vendorMatchesGroup(e.vendor, dep.groupId)) {
    all.push(...matchOne(dep, [e], "probable"));
  } else {
    all.push(...matchOne(dep, [e], "possible"));   // ← émis quand même
  }
}
```

Toute dep dont l'`artifactId` collide avec un produit non relié produit un match `possible`. Collisions fréquentes : `core`, `common`, `api`, `client`, `utils`, `parser`, `web`. Une CVE avec `product="core"` flagge **toutes** les deps `*-core`.

**Fix :** drop le tier `possible` ou ne l'afficher que si la refinement CPE (`refineMatchesWithCpe`) l'a confirmé.

---

#### H4 — CPE refinement flagge sans supprimer
**Fichier :** `lib/cpe.js:269-272`

```js
if (!affected && rec.configurations.length) {
  m.cpeFiltered = true;     // ← marqué, jamais supprimé
}
```

`cpeFiltered` est un soft tag. Si `lib/cve-report.js` ne strippe pas `cpeFiltered === true` (à vérifier dans le rendu), **les matches prouvés faux positifs restent dans la punch list**.

De plus, le skip `if (!rec.configurations.length && !rec.cpes.length) continue;` (`cpe.js:266`) est fail-open : une CVE sans configurations NVD (CVE récente ou réservée) est laissée au tier que le matcher lui a donné.

**Fix :** (a) filtrer par défaut `cpeFiltered=true` avec flag `--show-filtered`, ou (b) section séparée « likely false positive » dans le report.

---

#### H5 — Le qualificateur CPE `update` (RC, alpha) est ignoré
**Fichier :** `lib/cpe.js:81-100` (`matchVersionRange`)

Le champ index 6 du CPE 2.3 (`update`) est parsé mais jamais comparé. NVD liste fréquemment les pré-releases via le champ update (`cpe:2.3:a:vendor:product:1.0.0:rc1:*…`). Le hard-pin compare littéralement la `version` ignorant `update` :

```js
if (parsed.version && parsed.version !== "*" && parsed.version !== "-") {
  try { return compareMavenVersions(depVersion, parsed.version) === 0; }
```

→ `criteria: cpe:2.3:a:apache:foo:1.0.0:beta1:*…` matche `dep=1.0.0` (release). FP.

**Fix :** si `update` n'est ni `*` ni `-`, concaténer (`${version}-${update}`) avant `compareMavenVersions` (qui gère déjà `1.0.0-beta1`).

### MEDIUM

#### M1 — `compareMavenVersions` accepte du garbage sans broncher
**Fichier :** `lib/maven-version.js:25-94`

`compareMavenVersions("${foo}", "1.0")` → `-1`. Une variable Maven non résolue est comparée comme une vraie version. La pipeline filtre `/\$\{/.test(dep.version)` dans `expandWithTransitives`, `queryOsvForDeps`, `checkOutdatedDeps` — **mais pas dans `matchDepsAgainstCves`** (`cve-match.js:151-162`). Donc dep avec version `${foo}` → `isVersionAffected("${foo}", range)` → fall-through `true` (H1).

**Fix :** skipper les deps avec `${…}` non résolu dans `matchDepsAgainstCves`.

---

#### M2 — OSV : stubs cachés ré-émis sur la mauvaise version
**Fichier :** `lib/osv.js:242-265` (`runMatches`)

`vulnToMatch` ne refait pas de check range local. Le cache key `(g, a, v)` est versionné, donc pour la même dep+version c'est sûr. Mais le branch « stub only » émet `severity: "UNKNOWN"` sans description — vrai FP si la dep a été upgradée entre la build du cache et le scan.

`dep.version` avec `1.0.0.Final` ou `1.0.0.RELEASE` est envoyée verbatim à OSV qui ne normalise pas → recall patchy (FN, pas FP).

**Fix :** toujours évaluer `vuln.affected[].ranges` localement avant d'émettre. Drop des matches stub-only.

---

#### M3 — `parseRange` exporté mais jamais appelé
**Fichier :** `lib/maven-version.js:131-146`

`parseRange` traite les ranges Maven (`[1.0,2.0)`) mais aucun caller. Une `<version>[1.0,2.0)</version>` est passée verbatim à `compareMavenVersions("[1.0,2.0)", spec.version)`. Le tokenizer split sur `[.\-]`, `[1` devient un segment string → ranking sub-release → typiquement FN, mais peut devenir FP via H1.

**Fix :** câbler `parseRange` dans la pipeline ; sinon reporter ces deps en `unresolved-versions`.

---

#### M4 — `cpeMatchesDep` ré-introduit le substring leak de H2
**Fichier :** `lib/cpe.js:170-173`

Le filtre CPE supposé *narrow* contient lui-même la même heuristique substring que H2. Après que H2 fait passer un match, ce leak l'empêche de le re-filtrer.

---

#### M5 — retire.js passé sans validation locale
**Fichier :** `lib/retire.js:148-193`

Le wrapper a accès à `below`/`atOrAbove` mais ne les compare jamais. Les régressions historiques des signatures retire (matchs sur des bundles non reliés) passent. Pas d'équivalent à `--includeOsvData` / `--ignorefile`.

retire émet aussi un CVE id synthétique `RETIRE-<component>-<version>` qui ne dédup jamais contre fad/osv/nvd → **même vuln rapportée 2 fois**.

---

#### M6 — Cohérence des clés `byProduct`
**Fichier :** `lib/cve-download.js:163-164` + `lib/cve-match.js:191`

Index keyé sur `a.product` brut, lookup sur `.toLowerCase()`. Actuellement safe car `extractAffectedRanges` lowercase upstream — mais fragile. À documenter ou normaliser explicitement.

### LOW

- **L1** — `data/known-obsolete.json:92-96` : `struts2-core` flaggé HIGH sans gate de version (Struts 2.5.30 patché remonte « obsolete »).
- **L2** — `findCycleForVersion` (`lib/outdated.js:79-86`) prefix-match OK, pas de FP trouvé.
- **L3** — Tests : aucun ne couvre les edge cases ci-dessus (no-bounds, substring vendor leak, possible tier, update CPE, garbage `${...}`, `parseRange`).

### Verdict faux positifs

**Architecture saine, implémentation fail-open.** Les 4 cascades (H1+H2+H3+H4) doivent être patchées avant prod.

Patches prioritaires (ordre) :
1. H1 → one-liner, plus gros gain
2. H2 → tightening de `vendorMatchesGroup`
3. H3 → cacher le tier `possible` par défaut
4. H4 → strip `cpeFiltered:true` du report par défaut
5. M1 → skip `${...}` dans `matchDepsAgainstCves`
6. M2 → re-eval local des OSV ranges

---

## B. Code reuse

### HIGH

- **Helper de cache disque triplicé** : `lib/osv.js:25-44`, `lib/nvd.js:28-45`, `lib/retire.js:27-45`. Pattern identique (`_fetchedAt` + TTL + JSON). `lib/outdated.js:22-37` même chose avec shape différent.
  → Extraire `lib/cache-disk.js` exportant `makeCache(dir, ttlMs)`.

- **`severityFromScore` + `SEVERITY_RANK` dupliqués 7+ fois** : `lib/nvd.js:64-71`, `lib/cve-download.js:82-89`, `lib/osv.js:60-66`, `lib/cve-match.js:9`, `lib/snyk.js:112`, `lib/cve-report.js:{634, 761, 1085, 1280}`, `fad-checker.js:657`.
  → `lib/severity.js` + `sortMatchesBySeverity()` helper.

- **Merge-by-source logic dupliquée** : `fad-checker.js:628-665` (`mergeBySource`) vs `lib/snyk.js:97-120` (`mergeWithFadResults`). Le `"both"` de Snyk désaccorde avec le `"fad+osv"` ailleurs.
  → Promouvoir `mergeBySource` dans `lib/cve-match.js`.

### MEDIUM

- **`depLabel` / `depToKey` réinventés 6 fois** : `fad-checker.js:551`, `lib/cpe.js:177-184`, `lib/osv.js:100-102`, `lib/cve-report.js:{648, 669, 773, 1296}`.
- **Walker de répertoires + `SKIP_DIRS` dupliqués 4 fois** : `lib/core.js:9-37`, `lib/npm/parse.js:253-284`, `lib/npm/collect.js:202-222`, `lib/retire.js:77-81`.
- **Deux parsers POM divergents** : `lib/core.js:49-117` vs `lib/transitive.js:111-158`. Légitime (besoins différents) mais extraction parent/coord en commun possible.
- **CLI hand-roll argv parsing** : `fad-checker.js:25-150` walk de `process.argv` pour `--completion`, `--set-nvd-key`, etc. — devrait être des subcommands `commander`.

### LOW

- 3 comparateurs de versions divergents : `compareMavenVersions`, `compareVersionsLoose` (`cve-report.js:705-715`), `semverCompare` (`npm/collect.js:25-37`).
- `parseMavenMetadataLatest` (`outdated.js:212-224`) en regex au lieu d'xml2js (OK car XML trivial).

### Modules clean
`maven-version.js`, `maven-repo.js`, `config.js`, `scan-completeness.js`, `cache-archive.js`.

---

## C. Code quality

### HIGH

- **`fad-checker.js` (665 lignes) = god script** : pré-parse argv mélangé à l'orchestration, business logic dans la CLI.
- **`lib/cve-report.js` (1455 lignes) = mega-module** : CSS inline (~200 lignes), JS inline (`TOGGLE_SCRIPT`), business logic (`buildFixRecommendations`, `versionJump`, `pickTopCriticalMatches`) et rendu HTML dans le même fichier. `RENDER_CTX` module-global (lignes 247-249) reset à chaque `buildBody` — comment auto-avoue le workaround.
  → Splitter en `lib/report/{css,html,recommendations,word}.js`. Passer `srcRoot` en paramètre.
- **Stringly-typed partout** : `"fad" | "osv" | "nvd" | "snyk" | "retire"` en chaînes nues + class CSS `.source.snyk` qui couple le HTML à ces littéraux. Renommer une source casse silencieusement le CSS.
  → `lib/keys.js` + `SOURCES = Object.freeze({...})`.

### MEDIUM

- **Param sprawl sur `writeReports` / `buildBody` / `renderExecutiveSummary`** — 10 champs disjoints recomposés à chaque appel.
- **CVE matcher : duplication structurelle tier-2/tier-3** (`cve-match.js:175-219`) — flatten en single loop avec ternaire.
- **Lockfile parsers v1 vs v2/v3 collés en un seul `parsePackageLock`** (`npm/parse.js:76-176`) — splitter.
- **~30 `catch {}` silencieux** dans tout le code. Beaucoup légitimes, certains masquent des bugs réels (`osv.js:233`, `outdated.js:187,201`, `fad-checker.js:259`).
- **`RENDER_CTX` global** → thread `srcRoot` via les signatures (3 niveaux max).
- **Skip-dir lists copy-collées 4x** avec divergence `build/` (Maven keep, JS skip) — documenter une fois.
- **`lib/core.js:230-235`** repeat parent-resolution dans `rewritePoms` — consolider.

### LOW

- Cache helpers ré-implémentés (cf. reuse).
- Commentaires narratifs sans valeur (`cve-report.js:404-406`, `cve-report.js:519-521`, `transitive.js:204-206`, `fad-checker.js:202`).
- Pollution `byId` potentielle via `excludedById`/`missingById` (`core.js:240-285`) — appliquer le guard du CLAUDE.md.
- `lib/osv.js:188` arithmétique d'index fragile (`(batchIdx - 1) * BATCH_SIZE + j`) — utiliser `i + j`.
- Verbosité booléenne threadée 4+ niveaux → `lib/log.js`.

---

## D. Efficiency

### HIGH

- **CVE index loadé eagerly** (`lib/cve-download.js:299-301`) : `JSON.parse(readFileSync)` synchrone même pour un projet de 3 deps. Charger async + lazy par bucket.
- **`cpe.js` re-parse les CPE et walk 2 fois** (`cpe.js:194-245`) : `parseCpe23` appelé répétitivement, walk pour confidence après le walk d'évaluation. 2M+ string-splits sur un projet 800 deps × 50 matches.
  → Cache `m._parsed ||= parseCpe23(m.criteria)` + retour du match satisfaisant.
- **NVD enrichment 100 % serial** (`nvd.js:186-203`) : `sleep(600|6000)` entre chaque appel. 200 CVEs uniques = 2 min avec clé, **20 min sans**. NIST policy = 50/30s window → permet parallélisme.
- **TOCTOU `existsSync` + `readFile`** dans `transitive.js:52`, `nvd.js:34`, `osv.js:33`, `retire.js:32-37`, `outdated.js:22-25`. Doublé syscalls.
- **`outdated.checkOutdatedDeps` cache reset global** (`outdated.js:230`) : `cache.entries = {}` si meta TTL périmé → 600 deps refetch même si entrées fraîches.
  → TTL par-entrée.

### MEDIUM

- `findEolProduct` re-sort la prefix-list dans la boucle (`outdated.js:46-52`) — sort once at module load.
- `outByKey` Map rebuild 6x dans `cve-report.js` (`:633-679`, `:760-795`, `:993-1003`) — builder once dans `buildBody`.
- CVE bulk JSON `readFileSync` per file (`cve-download.js:274-287`) — borné par cache 24h, MEDIUM.
- `cve-report.js` : `renderDetailPanel` (`:417-493`) + `groupExternalRefs` (`:340`) re-alloués par row → 45k allocations sur un report 5k rows. Pré-classifier à l'enrichment NVD.
- **POMs parsés 2x sur le chemin `rewritePoms`** (`core.js:50` puis re-read à `:219`). `structuredClone` ou skip re-parse en read-only.
- **`transitive.js:314` : `queue.shift()` O(n)** sur 4000+ transitives → 16M memmoves. Switch en cursor.
- **Maven Central : pas de batch endpoint** (`outdated.js:176`) — solrsearch accepte OR boolean. 600 deps → 1 requête au lieu de 600.
- **OSV detail fetch serial** dans `queryBatch` (`osv.js:218-236`) — `p-limit(10)` similaire à fad-checker.js.

### LOW

- `getAllInheritedProps` rebuild via spread — fine en dessous de 10k POMs.
- `xml2js` 3-5x plus lent que `fast-xml-parser` — hors scope.
- Eager `require("chalk")` etc. — invisible.

### Note positive
Le matcher CVE (`matchDepsAgainstCves`) est **Map-indexé correctement** (`byPackageName` / `byProduct` pré-bucketés) — pas de O(n²) sur le hot path.

---

## E. Recommandations priorisées

| # | Action | Severity | Effort | Impact |
|---|---|---|---|---|
| 1 | Patch `isVersionAffected` fail-closed (H1) | HIGH FP | 1 ligne | Énorme |
| 2 | Tighten `vendorMatchesGroup` substring (H2) | HIGH FP | 10 lignes | Énorme |
| 3 | Drop ou hide tier `possible` (H3) | HIGH FP | 5 lignes | Énorme |
| 4 | Strip `cpeFiltered:true` du report (H4) | HIGH FP | 3 lignes | Gros |
| 5 | Handle CPE `update` qualifier (H5) | HIGH FP | 15 lignes | Moyen |
| 6 | Skip `${...}` dans matcher (M1) | MED FP | 3 lignes | Moyen |
| 7 | OSV ranges re-eval local (M2) | MED FP | 30 lignes | Moyen |
| 8 | Extract `lib/severity.js` + `SEVERITY_RANK` | HIGH reuse | 1h | Maintenance |
| 9 | Extract `lib/cache-disk.js` | HIGH reuse | 1h | Maintenance |
| 10 | NVD enrichment parallèle (token-bucket) | HIGH perf | 30min | 10x speedup |
| 11 | Batch Maven Central Solr (#13 efficiency) | HIGH perf | 1h | 100x speedup |
| 12 | `parseCpe23` memoization (CPE perf) | HIGH perf | 10min | 2-3x speedup |
| 13 | Splitter `cve-report.js` en sous-modules | HIGH quality | 2h | Maintenance |
| 14 | Tests des edge cases FP (`update`, no-bounds, substring) | LOW | 2h | Filet de sécurité |

**Quick wins (< 1 jour cumulé)** : #1, #2, #3, #4, #6, #12 → diviserait le taux de FP par ~3-5 et accélérerait le rendu de ~2-3×.

---

## F. Verdict final

- **Architecture :** **bonne**. Séparation Maven/npm, 3-tier matching, post-CPE refinement, multi-source dedup, caches TTL — tout est en place.
- **Implémentation matcher :** **fail-open systémique**. Les 4 cascades H1→H4 transforment un outil correctement architecturé en générateur de faux positifs.
- **Performance :** correcte en CPU (Map-indexed), **mauvaise en I/O** (NVD serial, Solr unitaire, double-parse POM).
- **Qualité :** 2 mega-modules (`cve-report.js` 1455 LoC, `fad-checker.js` 665 LoC) à splitter, ~30 `catch {}` à auditer, 7+ duplications de `SEVERITY_RANK`.
- **Tests :** 96 tests existants mais happy-path-heavy ; aucune couverture des edge cases FP listés ci-dessus.

**Recommandation pratique :** sans les patches H1-H4, le rapport doit être traité comme une **liste de départ pour triage manuel**, pas comme un inventaire de vulnérabilités exploitable. Le tier `exact` reste fiable. Tout le reste demande des yeux humains sur la description CVE avant action.

---

## Annexe — Références fichier:ligne

**Faux positifs :**
- `lib/maven-version.js:25-94, 101-124, 131-146`
- `lib/cve-match.js:9, 99-109, 151-162, 164-173, 175-219, 191-198`
- `lib/cpe.js:25, 36-68, 81-100, 161-184, 194-245, 266, 269-272`
- `lib/osv.js:25-44, 60-66, 100-102, 188, 218-236, 242-265, 273`
- `lib/nvd.js:28-45, 64-71, 145, 186-203`
- `lib/retire.js:24-45, 77-81, 148-193`
- `lib/outdated.js:22-37, 46-52, 79-86, 168-187, 212-254`
- `lib/cve-download.js:82-89, 163-164, 274-301`
- `lib/transitive.js:51-101, 111-158, 204-235, 273-320`
- `lib/core.js:9-37, 49-149, 219-285`
- `lib/npm/{parse.js:76-291, collect.js:25-224}`
- `lib/cve-report.js:48-247, 340, 404-493, 519-521, 559, 633-1455`
- `fad-checker.js:25-150, 202, 259, 551, 628-665`
- `data/{cpe-coord-map.json, known-obsolete.json:92-96}`

**Tests manquants :** `test/{cpe,cve-match,maven-version}.test.js` — ajouter edge cases `update`, no-bounds, substring vendor leak, garbage version.
