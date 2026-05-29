# Plan A — Socle codec (foundation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extraire toute la logique spécifique-écosystème (Maven + npm/yarn) derrière une interface codec uniforme, généraliser le `depRecord`, et rendre OSV/NVD/CPE/EOL agnostiques — sans changer le comportement observable (sauf le fallback npm assumé), les 96 tests restant verts.

**Architecture:** Un registre de codecs (`lib/codecs/`) expose un codec par écosystème. Chaque codec implémente une interface commune (`detect`, `collect`, `coordKey`, `formatCoord`, `osvPackageName`, `checkRegistry`, `resolveEolProduct`, `recipe`, `nativeScanners`). L'orchestrateur de `fad-checker.js` boucle sur les codecs détectés au lieu de brancher `if (runMaven)/if (runNpm)`. La logique métier éprouvée (résolution POM/BOM de `lib/core.js`, walker `lib/transitive.js`, parsers `lib/npm/*`) est **déplacée, pas réécrite**.

**Tech Stack:** Node.js, `node --test`, commander, xml2js. Aucune nouvelle dépendance dans ce plan (smol-toml arrive au Plan C).

---

## File Structure

| Fichier | Rôle | Action |
|---|---|---|
| `lib/codecs/codec.interface.js` | Doc du contrat + `assertCodecShape()` (validation) | Créer |
| `lib/codecs/index.js` | Registre : `getCodec`, `allCodecs`, `detectCodecs` | Créer |
| `lib/codecs/maven.codec.js` | Codec Maven (enveloppe `core`, `transitive`, CVE-index) | Créer |
| `lib/codecs/npm.codec.js` | Codec npm (enveloppe `lib/npm/*`, retire.js) | Créer |
| `lib/codecs/yarn.codec.js` | Codec yarn (partage le gros de npm, `ecosystemType="yarn"`) | Créer |
| `lib/dep-record.js` | Builder `makeDepRecord()` + helpers `coordKeyFor`/`namespaceName` | Créer |
| `lib/cve-match.js` | `collectResolvedDeps` produit le depRecord généralisé | Modifier |
| `lib/npm/collect.js` | idem côté npm | Modifier |
| `lib/osv.js` | `osvPkgName`/`queryBatch` délèguent au codec | Modifier |
| `lib/cve-report.js` | `RECIPE_SPECS`/`ECO_LABELS`/`formatCoord` pilotés par codec | Modifier |
| `fad-checker.js` | Orchestration par boucle de codecs ; CLI `--ecosystem` liste + `--no-<id>` | Modifier |
| `test/codecs.test.js` | Contrat d'interface paramétré sur `allCodecs()` | Créer |
| `test/dep-record.test.js` | Builder depRecord | Créer |

**Invariant transversal :** `npm test` (96 tests) doit rester vert après chaque tâche (sauf Task 9 qui adapte volontairement le test `no-lockfile`).

---

### Task 1: Builder du depRecord généralisé

**Files:**
- Create: `lib/dep-record.js`
- Test: `test/dep-record.test.js`

- [ ] **Step 1: Écrire le test qui échoue**

```js
// test/dep-record.test.js
const test = require("node:test");
const assert = require("node:assert");
const { makeDepRecord, coordKeyFor } = require("../lib/dep-record");

test("maven depRecord builds namespaced coordKey and keeps groupId/artifactId aliases", () => {
  const d = makeDepRecord({ ecosystem: "maven", namespace: "org.apache", name: "log4j", version: "2.14.0", manifestPath: "/p/pom.xml", scope: "compile" });
  // DÉVIATION ACTÉE : clé Maven BRUTE "g:a" (pas "maven:g:a") — garde transitive.js
  // et ~12 tests existants intacts ; collision-free face aux préfixes des autres eco.
  assert.strictEqual(d.coordKey, "org.apache:log4j");
  assert.strictEqual(d.groupId, "org.apache");   // alias rétro-compat
  assert.strictEqual(d.artifactId, "log4j");      // alias rétro-compat
  assert.deepStrictEqual(d.versions, ["2.14.0"]);
  assert.strictEqual(d.isDev, false);
});

test("npm depRecord has empty namespace and npm-prefixed coordKey", () => {
  const d = makeDepRecord({ ecosystem: "npm", namespace: "", name: "lodash", version: "4.17.20", manifestPath: "/p/package-lock.json", scope: "prod" });
  assert.strictEqual(d.coordKey, "npm:lodash");
  assert.strictEqual(d.groupId, "");
  assert.strictEqual(d.artifactId, "lodash");
});

test("coordKeyFor composes ecosystem + namespace + name", () => {
  assert.strictEqual(coordKeyFor("composer", "guzzlehttp", "guzzle"), "composer:guzzlehttp/guzzle");
  assert.strictEqual(coordKeyFor("pypi", "", "requests"), "pypi:requests");
  assert.strictEqual(coordKeyFor("nuget", "", "Newtonsoft.Json"), "nuget:newtonsoft.json");
});
```

- [ ] **Step 2: Lancer le test pour vérifier l'échec**

Run: `node --test test/dep-record.test.js`
Expected: FAIL — `Cannot find module '../lib/dep-record'`

- [ ] **Step 3: Implémenter le builder**

```js
// lib/dep-record.js
// Contrat de données unifié partagé par tous les codecs.
// `coordKey` est la clé de la Map résolue ; elle ne collisionne jamais entre
// écosystèmes grâce au préfixe `ecosystem:`. `groupId`/`artifactId` sont
// conservés comme alias rétro-compat le temps de migrer tous les consommateurs.

// Séparateur namespace↔name : ":" pour maven (g:a), "/" pour composer (vendor/pkg),
// "" (concat avec scope @) sinon.
function joinNs(ecosystem, namespace, name) {
  if (!namespace) return name;
  if (ecosystem === "composer") return `${namespace}/${name}`;
  if (ecosystem === "maven") return `${namespace}:${name}`;
  // npm scope: namespace="@org" → "@org/name"
  return `${namespace}/${name}`;
}

// NuGet & Composer & PyPI sont case-insensitive : on normalise la clé en lower
// (l'affichage garde la casse d'origine via dep.name).
function normalizeForKey(ecosystem, s) {
  if (ecosystem === "nuget" || ecosystem === "composer" || ecosystem === "pypi") return String(s).toLowerCase();
  return s;
}

function coordKeyFor(ecosystem, namespace, name) {
  const joined = joinNs(ecosystem, normalizeForKey(ecosystem, namespace || ""), normalizeForKey(ecosystem, name || ""));
  return `${ecosystem}:${joined}`;
}

function makeDepRecord(input) {
  const { ecosystem, namespace = "", name, version = null, manifestPath, scope = "compile", isDev = false, ecosystemType } = input;
  const concrete = version && !/\$\{/.test(version) ? version : null;
  const manifestPaths = manifestPath ? [manifestPath] : [];
  return {
    ecosystem,
    ecosystemType: ecosystemType || ecosystem,
    namespace: namespace || "",
    name,
    version: version || null,
    versions: concrete ? [concrete] : [],
    coordKey: coordKeyFor(ecosystem, namespace, name),
    scope,
    isDev: !!isDev,
    manifestPaths,
    // Alias rétro-compat : CHAMPS DUPLIQUÉS RÉELS (pas des getters — les depRecords
    // sont spreadés dans des chemins chauds : cve-match.js:175, scan-completeness.js,
    // cve-report.js:1036, snyk.js:105 — un getter serait perdu au spread).
    // groupId/artifactId sont des strings jamais réassignées → pas de dérive.
    // pomPaths PARTAGE la référence de manifestPaths → les push restent synchrones.
    groupId: namespace || "",
    artifactId: name,
    pomPaths: manifestPaths,
  };
}

module.exports = { makeDepRecord, coordKeyFor };
```

- [ ] **Step 4: Lancer le test pour vérifier le succès**

Run: `node --test test/dep-record.test.js`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add lib/dep-record.js test/dep-record.test.js
git commit -m "Add generalized depRecord builder (codec foundation)"
```

> ✓ Décision : alias = champs dupliqués réels (vérifié : 4 sites spreadent les depRecords).
> `pomPaths` partage la référence de `manifestPaths`. Un `JSON.parse(JSON.stringify(dep))`
> casserait ce partage de référence, mais aucun chemin chaud ne sérialise/désérialise un
> depRecord (vérifié : aucun `JSON.parse(JSON.stringify(dep))` dans le code).

---

### Task 2: Interface codec + validation de forme

**Files:**
- Create: `lib/codecs/codec.interface.js`
- Test: `test/codecs.test.js` (créé ici, étendu en Task 6)

- [ ] **Step 1: Écrire le test qui échoue**

```js
// test/codecs.test.js
const test = require("node:test");
const assert = require("node:assert");
const { assertCodecShape, REQUIRED_KEYS } = require("../lib/codecs/codec.interface");

test("assertCodecShape accepts a complete codec stub", () => {
  const stub = {
    id: "x", label: "X", osvEcosystem: "npm",
    manifestNames: ["x.json"],
    detect: () => false,
    collect: async () => ({ deps: new Map(), warnings: [] }),
    coordKey: d => `x:${d.name}`,
    formatCoord: d => d.name,
    osvPackageName: d => d.name,
    checkRegistry: async () => ({ outdated: [], deprecated: [] }),
    resolveEolProduct: () => null,
    recipe: { label: "X", pinSection: "", pinIntro: () => "", snippet: () => "", directSection: "" },
    nativeScanners: [],
  };
  assert.doesNotThrow(() => assertCodecShape(stub));
});

test("assertCodecShape rejects a codec missing a required method", () => {
  assert.throws(() => assertCodecShape({ id: "y" }), /missing|y/i);
});
```

- [ ] **Step 2: Lancer le test pour vérifier l'échec**

Run: `node --test test/codecs.test.js`
Expected: FAIL — `Cannot find module '../lib/codecs/codec.interface'`

- [ ] **Step 3: Implémenter l'interface + validateur**

```js
// lib/codecs/codec.interface.js
// Contrat que tout codec doit respecter. Pas de classe imposée : un codec est
// un objet litéral exportant ces clés.
const REQUIRED_KEYS = [
  "id", "label", "osvEcosystem", "manifestNames",
  "detect", "collect", "coordKey", "formatCoord", "osvPackageName",
  "checkRegistry", "resolveEolProduct", "recipe", "nativeScanners",
];
const FUNCTION_KEYS = ["detect", "collect", "coordKey", "formatCoord", "osvPackageName", "checkRegistry", "resolveEolProduct"];

function assertCodecShape(codec) {
  if (!codec || typeof codec !== "object") throw new Error("codec must be an object");
  for (const k of REQUIRED_KEYS) {
    if (!(k in codec)) throw new Error(`codec "${codec.id || "?"}" missing required key: ${k}`);
  }
  for (const k of FUNCTION_KEYS) {
    if (typeof codec[k] !== "function") throw new Error(`codec "${codec.id}" key ${k} must be a function`);
  }
  if (!Array.isArray(codec.manifestNames)) throw new Error(`codec "${codec.id}" manifestNames must be an array`);
  if (!Array.isArray(codec.nativeScanners)) throw new Error(`codec "${codec.id}" nativeScanners must be an array`);
  return true;
}

module.exports = { REQUIRED_KEYS, FUNCTION_KEYS, assertCodecShape };
```

- [ ] **Step 4: Lancer le test pour vérifier le succès**

Run: `node --test test/codecs.test.js`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add lib/codecs/codec.interface.js test/codecs.test.js
git commit -m "Add codec interface contract + shape validator"
```

---

### Task 3: Codec Maven (extraction, pas réécriture)

**Files:**
- Create: `lib/codecs/maven.codec.js`
- Modify: `lib/cve-match.js:31-95` (`collectResolvedDeps` produit le depRecord généralisé via `makeDepRecord`)

- [ ] **Step 1: Écrire le test qui échoue**

```js
// ajout dans test/codecs.test.js
const path = require("path");
const maven = require("../lib/codecs/maven.codec");

test("maven codec detects the simple fixture and collects deps with namespaced coordKeys", async () => {
  const dir = path.join(__dirname, "fixtures", "simple");
  assert.strictEqual(maven.detect(dir), true);
  const { deps } = await maven.collect(dir, {});
  assert.ok(deps.size > 0);
  for (const [k, d] of deps) {
    assert.ok(k.startsWith("maven:"), `key ${k} should be maven-namespaced`);
    assert.strictEqual(d.ecosystem, "maven");
    assert.strictEqual(d.coordKey, k);
  }
});
```

- [ ] **Step 2: Lancer le test pour vérifier l'échec**

Run: `node --test test/codecs.test.js`
Expected: FAIL — `Cannot find module '../lib/codecs/maven.codec'`

- [ ] **Step 3a: Migrer `collectResolvedDeps` vers `makeDepRecord`**

Dans `lib/cve-match.js`, remplacer les deux `out.set(key, {...})` (lignes ~52 et ~86) par des appels à `makeDepRecord`, et le `key` par `coordKey`. Garder la logique de merge identique mais en s'appuyant sur `namespace`/`name`/`versions`/`manifestPaths`. Ajouter en tête : `const { makeDepRecord, coordKeyFor } = require("./dep-record");`

```js
// remplace la branche !existing (dep normale) :
const rec = makeDepRecord({ ecosystem: "maven", namespace: g, name: a, version: v || null, manifestPath: pomPath, scope, isDev });
out.set(rec.coordKey, rec);
// la branche existing reste, mais lit existing.versions / existing.manifestPaths / existing.namespace
// et le `key` devient coordKeyFor("maven", g, a)
```

Idem pour la branche parent (scope `parent`). Le reste du fichier (transitive, matching) lit déjà `dep.groupId`/`dep.artifactId` → fonctionne via les alias.

- [ ] **Step 3b: Écrire le codec Maven (enveloppe la logique existante)**

```js
// lib/codecs/maven.codec.js
const core = require("../core");
const { collectResolvedDeps, expandWithTransitives, matchDepsAgainstCves } = require("../cve-match");
const { coordKeyFor } = require("../dep-record");

// Scanner natif : CVE-index local cvelistV5. Reçoit (deps, opts) et renvoie des matches.
const cveIndexScanner = {
  id: "cve-index",
  async scan(deps, opts) {
    const { ensureCveIndex } = require("../cve-download");
    const idx = await ensureCveIndex({ force: opts.cveRefresh && !opts.offline, offline: opts.cveOffline || opts.offline, verbose: opts.verbose });
    return { matches: matchDepsAgainstCves(deps, idx), meta: { cveDataDate: idx?.meta?.builtAt || null } };
  },
};

module.exports = {
  id: "maven",
  label: "Maven",
  osvEcosystem: "Maven",
  manifestNames: ["pom.xml"],
  detect(dir) { return core.findPomFiles(dir).length > 0; },

  // collect enveloppe parse + inheritance + collectResolvedDeps existants.
  async collect(dir, opts) {
    const pomFiles = core.findPomFiles(dir);
    const store = core.newMetadataStore();
    const propsByPom = {};
    for (const pom of pomFiles) { try { await core.parsePom(pom, store); } catch { /* logged by caller */ } }
    for (const pom of Object.keys(store.byPath)) { try { await core.getAllInheritedProps(pom, store, propsByPom); } catch { /* logged */ } }
    const deps = collectResolvedDeps(store, propsByPom, { ignoreTest: opts.ignoreTest, deps2Exclude: opts.deps2Exclude });
    // On expose store/propsByPom pour que l'orchestrateur garde la phase rewrite POM.
    return { deps, warnings: [], _maven: { store, propsByPom, pomFiles } };
  },

  coordKey(d) { return coordKeyFor("maven", d.namespace || d.groupId, d.name || d.artifactId); },
  formatCoord(d) { return `${d.namespace || d.groupId}:${d.name || d.artifactId}`; },
  osvPackageName(d) { return `${d.namespace || d.groupId}:${d.name || d.artifactId}`; },

  async checkRegistry(deps, opts) {
    const outdated = require("../outdated");
    const out = opts.allLibs ? await outdated.checkOutdatedDeps(deps, opts) : [];
    const deprecated = outdated.checkObsoleteDeps(deps);
    return { outdated: out, deprecated };
  },
  resolveEolProduct(d) { return require("../outdated").findEolProduct(d); },
  recipe: require("./recipes").maven,   // extrait de RECIPE_SPECS en Task 7
  nativeScanners: [cveIndexScanner],
  expandTransitives: expandWithTransitives,   // utilisé par l'orchestrateur si --transitive
};
```

> Note : `findEolProduct` et `recipes` sont rendus requérables aux Tasks 5 et 7 ; jusque-là, le codec maven peut référencer des stubs. Pour garder le test de Task 3 vert sans dépendances avant, `recipe` peut pointer un objet inline temporaire et `resolveEolProduct` renvoyer `null` — remplacés en Task 5/7. **Décision : on inline un `recipe` minimal et `resolveEolProduct: () => null` ici, finalisés plus tard.**

- [ ] **Step 4: Lancer toute la suite**

Run: `npm test`
Expected: PASS — 96 tests existants + nouveaux tests codec. Le comportement de `collectResolvedDeps` est inchangé (clés `maven:g:a` au lieu de `g:a`, mais les consommateurs lisent via alias).

> ⚠️ Risque clé : des tests existants assertent peut-être des clés `g:a` brutes. Si `node --test test/cve-match.test.js` échoue sur des clés, adapter ces assertions vers `maven:g:a` (c'est le nouveau contrat de clé, attendu).

- [ ] **Step 5: Commit**

```bash
git add lib/codecs/maven.codec.js lib/cve-match.js test/codecs.test.js
git commit -m "Extract Maven codec; collectResolvedDeps emits generalized depRecord"
```

---

### Task 4: Codecs npm + yarn (extraction)

**Files:**
- Create: `lib/codecs/npm.codec.js`, `lib/codecs/yarn.codec.js`
- Modify: `lib/npm/collect.js` (`collectNpmDeps` produit le depRecord généralisé)

- [ ] **Step 1: Écrire le test qui échoue**

```js
// ajout dans test/codecs.test.js
const npm = require("../lib/codecs/npm.codec");

test("npm codec collects from monorepo-mixed with npm: coordKeys", async () => {
  const dir = path.join(__dirname, "fixtures", "monorepo-mixed");
  assert.strictEqual(npm.detect(dir), true);
  const { deps } = await npm.collect(dir, {});
  for (const [k, d] of deps) {
    assert.ok(k.startsWith("npm:"), `key ${k} should be npm-namespaced`);
    assert.strictEqual(d.ecosystem, "npm");
  }
});
```

- [ ] **Step 2: Lancer le test pour vérifier l'échec**

Run: `node --test test/codecs.test.js`
Expected: FAIL — `Cannot find module '../lib/codecs/npm.codec'`

- [ ] **Step 3a: Migrer `collectNpmDeps` vers `makeDepRecord`**

Dans `lib/npm/collect.js`, remplacer la construction du record (`out.set("npm:"+name, {...})`) par `makeDepRecord({ ecosystem:"npm", namespace: scopeOf(name), name, version, manifestPath, scope, isDev, ecosystemType })`. `namespace` = `@org` si nom scopé `@org/pkg`, sinon `""`. La clé devient `rec.coordKey` (toujours `npm:...`). Conserver `lockType/resolved/integrity` en les assignant après création (`rec.lockType = ...`). Préserver `out.warnings`.

- [ ] **Step 3b: Écrire les codecs npm et yarn**

```js
// lib/codecs/npm.codec.js
const { collectNpmDeps, hasJsManifests } = require("../npm/collect");
const { coordKeyFor } = require("../dep-record");

const retireScanner = {
  id: "retire",
  async scan(_deps, opts) {
    const { scanWithRetire } = require("../retire");
    const matches = await scanWithRetire(opts.src, { verbose: opts.verbose, force: opts.retireRefresh, offline: opts.offline });
    return { matches, meta: {} };
  },
};

const base = {
  osvEcosystem: "npm",
  manifestNames: ["package.json", "package-lock.json", "yarn.lock"],
  detect(dir) { return hasJsManifests(dir); },
  coordKey(d) { return coordKeyFor("npm", d.namespace || "", d.name || d.artifactId); },
  formatCoord(d) { return d.namespace ? `${d.namespace}/${d.name}` : (d.name || d.artifactId); },
  osvPackageName(d) { return d.namespace ? `${d.namespace}/${d.name}` : (d.name || d.artifactId); },
  async checkRegistry(deps, opts) {
    const { checkNpmRegistryDeps } = require("../npm/registry");
    const r = await checkNpmRegistryDeps(deps, opts);
    return { outdated: r.outdated, deprecated: r.deprecated };
  },
  resolveEolProduct(d) { return require("../outdated").findEolProduct(d); },
  nativeScanners: [retireScanner],
};

module.exports = {
  ...base,
  id: "npm",
  label: "npm",
  recipe: require("./recipes").npm,
  // collect renvoie TOUTES les deps JS ; l'orchestrateur ne charge npm.collect qu'une fois.
  async collect(dir, opts) {
    const deps = collectNpmDeps(dir, opts);
    return { deps, warnings: deps.warnings || [] };
  },
};
```

```js
// lib/codecs/yarn.codec.js — yarn partage tout sauf l'id/label/recette.
const npm = require("./npm.codec");
module.exports = {
  ...npm,
  id: "yarn",
  label: "Yarn",
  recipe: require("./recipes").yarn,
  // Pas de collect séparé : npm.collect ramasse déjà yarn.lock (ecosystemType="yarn").
  // Le registre des codecs ne fait PAS tourner yarn.collect (évite le double scan) ;
  // yarn n'est exposé que pour son label/recette dans le report.
  collect: async () => ({ deps: new Map(), warnings: [] }),
};
```

> Décision d'orchestration : un seul `collect` JS tourne (celui du codec npm), qui ramasse package-lock ET yarn.lock — chaque dep porte son `ecosystemType`. Le codec yarn n'existe que pour fournir `label`/`recipe` au report. Le registre marque yarn `collectViaSibling: "npm"` pour documenter ça.

- [ ] **Step 4: Lancer toute la suite**

Run: `npm test`
Expected: PASS — incl. nouveau test npm codec.

- [ ] **Step 5: Commit**

```bash
git add lib/codecs/npm.codec.js lib/codecs/yarn.codec.js lib/npm/collect.js test/codecs.test.js
git commit -m "Extract npm/yarn codecs; collectNpmDeps emits generalized depRecord"
```

---

### Task 5: Registre des codecs

**Files:**
- Create: `lib/codecs/index.js`
- Test: `test/codecs.test.js` (ajout)

- [ ] **Step 1: Écrire le test qui échoue**

```js
// ajout dans test/codecs.test.js
const { getCodec, allCodecs, detectCodecs } = require("../lib/codecs");

test("registry exposes maven/npm/yarn and validates their shape", () => {
  const ids = allCodecs().map(c => c.id).sort();
  assert.deepStrictEqual(ids, ["maven", "npm", "yarn"]);
  for (const c of allCodecs()) assertCodecShape(c);
});

test("detectCodecs finds maven+npm on monorepo-mixed", () => {
  const dir = path.join(__dirname, "fixtures", "monorepo-mixed");
  const detected = detectCodecs(dir).map(c => c.id);
  assert.ok(detected.includes("maven"));
  assert.ok(detected.includes("npm"));
});
```

- [ ] **Step 2: Lancer le test pour vérifier l'échec**

Run: `node --test test/codecs.test.js`
Expected: FAIL — `Cannot find module '../lib/codecs'`

- [ ] **Step 3: Implémenter le registre**

```js
// lib/codecs/index.js
const { assertCodecShape } = require("./codec.interface");
const maven = require("./maven.codec");
const npm = require("./npm.codec");
const yarn = require("./yarn.codec");

// Ordre stable pour le report.
const ORDER = ["maven", "npm", "yarn", "nuget", "composer", "pypi"];
const REGISTRY = new Map();
for (const c of [maven, npm, yarn]) { assertCodecShape(c); REGISTRY.set(c.id, c); }

function getCodec(id) { return REGISTRY.get(id) || null; }
function allCodecs() {
  return [...REGISTRY.values()].sort((a, b) => ORDER.indexOf(a.id) - ORDER.indexOf(b.id));
}
// yarn est détecté via npm (même arbre JS) ; on ne le renvoie pas en doublon de détection.
function detectCodecs(dir) {
  return allCodecs().filter(c => c.id !== "yarn" && c.detect(dir));
}

module.exports = { getCodec, allCodecs, detectCodecs, ORDER };
```

- [ ] **Step 4: Lancer toute la suite**

Run: `npm test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/codecs/index.js test/codecs.test.js
git commit -m "Add codec registry (getCodec/allCodecs/detectCodecs)"
```

---

### Task 6: Recettes de fix extraites (`lib/codecs/recipes.js`)

**Files:**
- Create: `lib/codecs/recipes.js`
- Modify: `lib/cve-report.js` (importer les recettes depuis les codecs au lieu du `RECIPE_SPECS` codé en dur ~664-715)

- [ ] **Step 1: Écrire le test qui échoue**

```js
// ajout dans test/codecs.test.js
const recipes = require("../lib/codecs/recipes");
test("each recipe exposes label + snippet function", () => {
  for (const key of ["maven", "npm", "yarn"]) {
    assert.strictEqual(typeof recipes[key].label, "string");
    assert.strictEqual(typeof recipes[key].snippet, "function");
  }
});
```

- [ ] **Step 2: Lancer le test pour vérifier l'échec**

Run: `node --test test/codecs.test.js`
Expected: FAIL — `Cannot find module '../lib/codecs/recipes'`

- [ ] **Step 3: Déplacer `RECIPE_SPECS` de `cve-report.js` vers `recipes.js`**

Couper l'objet `RECIPE_SPECS` (et les helpers `pomOverridesSnippet`/`npmOverridesSnippet`/`yarnResolutionsSnippet`) de `lib/cve-report.js`, les coller dans `lib/codecs/recipes.js`, exporter `{ maven, npm, yarn }`. Dans `cve-report.js`, remplacer par `const RECIPE_SPECS = require("./codecs/recipes");` (ou mieux : construire depuis `allCodecs()` — fait en Task 7). Mettre à jour les codecs maven/npm/yarn pour pointer `recipe: require("./recipes")[id]` (remplace les stubs de Task 3/4).

- [ ] **Step 4: Lancer toute la suite**

Run: `npm test`
Expected: PASS — le report génère les mêmes snippets qu'avant (vérifié par les tests de report existants).

- [ ] **Step 5: Commit**

```bash
git add lib/codecs/recipes.js lib/cve-report.js lib/codecs/maven.codec.js lib/codecs/npm.codec.js lib/codecs/yarn.codec.js test/codecs.test.js
git commit -m "Extract fix recipes into lib/codecs/recipes.js"
```

---

### Task 7: Rendre OSV agnostique via le codec

**Files:**
- Modify: `lib/osv.js:100-102` (`osvPkgName`), `:144-168` (`queryBatch` ecosystem mapping)
- Test: `test/osv.test.js` (ajout)

- [ ] **Step 1: Écrire le test qui échoue**

```js
// ajout dans test/osv.test.js
const { osvEcosystemFor, osvPkgName } = require("../lib/osv");
test("osvEcosystemFor maps codec ids to OSV ecosystem names", () => {
  assert.strictEqual(osvEcosystemFor({ ecosystem: "maven" }), "Maven");
  assert.strictEqual(osvEcosystemFor({ ecosystem: "npm" }), "npm");
  assert.strictEqual(osvEcosystemFor({ ecosystem: "nuget" }), "NuGet");
  assert.strictEqual(osvEcosystemFor({ ecosystem: "composer" }), "Packagist");
  assert.strictEqual(osvEcosystemFor({ ecosystem: "pypi" }), "PyPI");
});
```

- [ ] **Step 2: Lancer le test pour vérifier l'échec**

Run: `node --test test/osv.test.js`
Expected: FAIL — `osvEcosystemFor is not a function`

- [ ] **Step 3: Remplacer le ternaire codé en dur par une délégation codec**

Dans `lib/osv.js`, remplacer `osvPkgName` (ligne ~100) et le bloc `const ecosystem = d.ecosystem === "npm" ? "npm" : "Maven"` (ligne ~161) par :

```js
const { getCodec } = require("./codecs");
const OSV_ECO = { maven: "Maven", npm: "npm", yarn: "npm", nuget: "NuGet", composer: "Packagist", pypi: "PyPI" };
function osvEcosystemFor(dep) { return OSV_ECO[dep.ecosystem] || "Maven"; }
function osvPkgName(dep) {
  const c = getCodec(dep.ecosystem) || getCodec(dep.ecosystemType);
  if (c) return c.osvPackageName(dep);
  // fallback historique
  return dep.ecosystem === "npm" ? dep.artifactId : `${dep.groupId}:${dep.artifactId}`;
}
```

Dans `queryBatch`, remplacer les deux lignes par `const ecosystem = osvEcosystemFor(d); const pkgName = osvPkgName(d);`. Exporter `osvEcosystemFor`, `osvPkgName`.

- [ ] **Step 4: Lancer toute la suite**

Run: `npm test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/osv.js test/osv.test.js
git commit -m "OSV: derive ecosystem + package name from codec (agnostic)"
```

---

### Task 8: Report — sections et coordonnées pilotées par codec

**Files:**
- Modify: `lib/cve-report.js` (`formatCoord` ~352-357, groupage `byEco` ~792-803, `ECO_LABELS`/`ECO_MANIFEST_KIND` ~1462-1470)

- [ ] **Step 1: Écrire le test qui échoue**

```js
// ajout dans test/cve-report.test.js (ou nouveau bloc)
const { formatDepCoord } = require("../lib/cve-report");
test("formatDepCoord delegates to codec for npm and maven", () => {
  assert.strictEqual(formatDepCoord({ ecosystem: "maven", namespace: "org.apache", name: "log4j" }), "org.apache:log4j");
  assert.strictEqual(formatDepCoord({ ecosystem: "npm", namespace: "", name: "lodash" }), "lodash");
});
```

- [ ] **Step 2: Lancer le test pour vérifier l'échec**

Run: `node --test test/cve-report.test.js`
Expected: FAIL — `formatDepCoord is not a function`

- [ ] **Step 3: Centraliser le formatage + générer les labels depuis les codecs**

Dans `lib/cve-report.js` :
- Ajouter et exporter `function formatDepCoord(dep){ const c = require("./codecs").getCodec(dep.ecosystemType) || require("./codecs").getCodec(dep.ecosystem); return c ? c.formatCoord(dep) : (dep.ecosystem === "npm" ? \`npm:${dep.artifactId}\` : \`${dep.groupId}:${dep.artifactId}\`); }`
- Remplacer les `if (dep?.ecosystem === "npm") return ...` (lignes ~352-357) par un appel à `formatDepCoord`.
- Remplacer `ECO_LABELS`/`ECO_MANIFEST_KIND` codés en dur par une construction depuis `allCodecs()` : `const ECO_LABELS = Object.fromEntries(allCodecs().map(c => [c.id, c.label]))` et `ECO_MANIFEST_KIND` depuis `c.manifestNames[c.manifestNames.length-1]` (le lockfile représentatif) — conserver les libellés actuels via une petite table d'override (`npm → "npm (package-lock)"`, etc.) pour ne pas changer le texte du report.
- Le groupage `byEco` et `ecoOrder` lisent `require("./codecs").ORDER` au lieu de `["maven","npm","yarn"]`.

- [ ] **Step 4: Lancer toute la suite**

Run: `npm test`
Expected: PASS — texte du report inchangé.

- [ ] **Step 5: Commit**

```bash
git add lib/cve-report.js test/cve-report.test.js
git commit -m "Report: derive coord formatting + ecosystem labels from codecs"
```

---

### Task 9: Orchestrateur par boucle de codecs + CLI liste

**Files:**
- Modify: `fad-checker.js:250-401` (détection + collecte), `:160-196` (flags CLI)
- Modify: `lib/npm/collect.js` (fallback no-lockfile — changement de contrat assumé)
- Test: `test/cli-ecosystem.test.js` (créé), adaptation de `test/npm-collect.test.js` (no-lockfile)

- [ ] **Step 1: Écrire le test qui échoue (parsing du flag liste)**

```js
// test/cli-ecosystem.test.js
const test = require("node:test");
const assert = require("node:assert");
const { resolveActiveCodecs } = require("../lib/codecs/select");

test("resolveActiveCodecs parses comma list and 'all'", () => {
  const all = ["maven", "npm", "nuget", "composer", "pypi"];
  assert.deepStrictEqual(resolveActiveCodecs("maven,pypi", all, {}), ["maven", "pypi"]);
  assert.deepStrictEqual(resolveActiveCodecs("all", all, {}), all);
});

test("resolveActiveCodecs honors --no-<id> flags", () => {
  const all = ["maven", "npm", "nuget"];
  assert.deepStrictEqual(resolveActiveCodecs("all", all, { noCodecs: ["npm"] }), ["maven", "nuget"]);
});

test("--no-js aliases to npm+yarn", () => {
  const all = ["maven", "npm", "yarn", "nuget"];
  assert.deepStrictEqual(resolveActiveCodecs("all", all, { noJs: true }), ["maven", "nuget"]);
});
```

- [ ] **Step 2: Lancer le test pour vérifier l'échec**

Run: `node --test test/cli-ecosystem.test.js`
Expected: FAIL — `Cannot find module '../lib/codecs/select'`

- [ ] **Step 3a: Implémenter la sélection de codecs**

```js
// lib/codecs/select.js
// `requested` : "auto" | "all" | "maven,npm,..." ; `available` : ids détectés (auto) ou tous.
function resolveActiveCodecs(requested, available, flags = {}) {
  const { noCodecs = [], noJs = false } = flags;
  let active;
  const req = String(requested || "auto").toLowerCase();
  if (req === "auto") active = [...available];
  else if (req === "all") active = [...available];
  else active = req.split(",").map(s => s.trim()).filter(Boolean).filter(id => available.includes(id));
  const excluded = new Set(noCodecs);
  if (noJs) { excluded.add("npm"); excluded.add("yarn"); }
  return active.filter(id => !excluded.has(id));
}
module.exports = { resolveActiveCodecs };
```

- [ ] **Step 3b: Câbler les flags CLI**

Dans `fad-checker.js` (bloc commander ~160-196) : remplacer `--ecosystem <auto|maven|npm|both>` par `--ecosystem <list>` (défaut `"auto"`, doc : `auto|all|maven,npm,nuget,composer,pypi`). Ajouter `--no-maven --no-npm --no-yarn --no-nuget --no-composer --no-pypi`. Garder `--no-js`. Construire `flags.noCodecs` depuis les options `--no-*`.

- [ ] **Step 3c: Réécrire le bloc d'orchestration (250-401) en boucle de codecs**

```js
const { detectCodecs, allCodecs, getCodec } = require("./lib/codecs");
const { resolveActiveCodecs } = require("./lib/codecs/select");

const detected = (options.ecosystem === "auto" || !options.ecosystem)
  ? detectCodecs(options.src).map(c => c.id)
  : allCodecs().map(c => c.id);
const noCodecs = ["maven","npm","yarn","nuget","composer","pypi"].filter(id => options[`no${id[0].toUpperCase()+id.slice(1)}`] === true);
const activeIds = resolveActiveCodecs(options.ecosystem, detected, { noCodecs, noJs: !options.js });

const resolved = new Map();
let mavenCtx = null;        // {store, propsByPom, pomFiles} pour la phase rewrite POM
const allWarnings = [];
for (const id of activeIds) {
  if (id === "yarn") continue;   // ramassé par npm.collect
  const codec = getCodec(id);
  const { deps, warnings, _maven } = await codec.collect(options.src, { ignoreTest: !!options.ignoreTest, deps2Exclude, verbose });
  for (const [k, v] of deps) resolved.set(k, v);
  if (warnings?.length) allWarnings.push(...warnings);
  if (id === "maven") mavenCtx = _maven;
}
```

Conserver ensuite la phase rewrite POM (lignes 279-348) en la gardant sous `if (mavenCtx)` et en lisant `mavenCtx.store`/`mavenCtx.propsByPom`/`mavenCtx.pomFiles` au lieu des variables globales. Remplacer dans `runReportFlow` les appels nativeScanners/registry/EOL par une boucle sur `activeIds`/`getCodec(id).nativeScanners` et `getCodec(id).checkRegistry`. Les sections OSV/NVD/CPE restent telles quelles (déjà agnostiques après Task 7).

> ⚠️ Le dedup cross-section (`eolKeys`/`obsKeys`, lignes 479-484) utilise `${dep.groupId}:${dep.artifactId}`. Remplacer par `dep.coordKey` (déjà unique inter-eco). Idem `depLabel` ligne 568 → `formatDepCoord`.

- [ ] **Step 3d: Fallback no-lockfile (changement de contrat npm)**

Dans `lib/npm/collect.js`, là où un `package.json` sans lock pousse aujourd'hui un warning `no-lockfile` **et skippe** : désormais parser `package.json` (dependencies + devDependencies), ne garder que les versions épinglées exactes (pas `^`/`~`/`*`/ranges), créer des depRecords best-effort, et pousser le warning `no-lockfile — résultats partiels`. Les ranges → warning `unresolved-versions`.

- [ ] **Step 4a: Adapter le test no-lockfile existant**

Trouver le test qui vérifie le skip total (`test/npm-collect.test.js`, cas `no-lockfile`). Le réécrire pour vérifier : (a) un warning `no-lockfile` est émis, (b) les deps à version épinglée du `package.json` sont bien collectées, (c) les deps en range ne le sont pas.

- [ ] **Step 4b: Lancer toute la suite**

Run: `npm test`
Expected: PASS — incl. `cli-ecosystem.test.js` et le test no-lockfile adapté.

- [ ] **Step 4c: Smoke test bout-en-bout (offline)**

Run: `node fad-checker.js -s ./test/fixtures/monorepo-mixed --offline`
Expected: le run liste maven + npm, produit le report sans erreur, et `package.json` sans lock du fixture apparaît désormais en best-effort + warning (au lieu de skip total).

- [ ] **Step 5: Commit**

```bash
git add fad-checker.js lib/codecs/select.js lib/npm/collect.js test/cli-ecosystem.test.js test/npm-collect.test.js
git commit -m "Orchestrate pipeline as a codec loop; --ecosystem list + --no-<id>; npm no-lockfile fallback"
```

---

### Task 10: Mise à jour docs + completions

**Files:**
- Modify: `CLAUDE.md`, `docs/ARCHITECTURE.md`, `docs/USAGE.md`, `completions/fad-checker.bash`, `completions/fad-checker.zsh`

- [ ] **Step 1: Documenter l'abstraction codec**

Dans `docs/ARCHITECTURE.md` : ajouter une section « Codecs » décrivant l'interface, le registre, et que les services OSV/NVD/CPE/EOL sont agnostiques. Mettre à jour la « Module map ». Dans `CLAUDE.md` : ajouter `lib/codecs/*` à l'arbre, documenter le nouveau `--ecosystem <list>` + `--no-<id>`, et le changement de contrat npm no-lockfile.

- [ ] **Step 2: Mettre à jour les complétions**

Ajouter `--no-maven --no-nuget --no-composer --no-pypi` et la nouvelle forme de `--ecosystem` dans les deux fichiers de complétion.

- [ ] **Step 3: Vérifier**

Run: `npm test`
Expected: PASS (les docs n'affectent pas les tests ; on relance par sécurité).

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md docs/ARCHITECTURE.md docs/USAGE.md completions/
git commit -m "Docs + completions: codec abstraction, --ecosystem list, --no-<id>"
```

---

## Self-Review (effectuée)

**Couverture spec :**
- Interface codec → Task 2 ✓ ; depRecord généralisé → Task 1 ✓ ; registre → Task 5 ✓ ;
  extraction maven/npm/yarn → Tasks 3-4 ✓ ; OSV agnostique → Task 7 ✓ ;
  NVD/CPE agnostiques → déjà agnostiques (par CVE-id), confirmé Task 9 ✓ ;
  EOL agnostique → `findEolProduct` déjà dispatch sur ecosystem, exposé via codec Tasks 3-4 ✓ ;
  report dynamique → Task 8 ✓ ; CLI liste + `--no-<id>` → Task 9 ✓ ;
  changement de contrat npm → Task 9 (3d/4a) ✓ ; docs → Task 10 ✓.
- **Hors de ce plan (volontaire)** : les 3 nouveaux codecs (Plans B/C/D), les fixtures
  csharp/php/python, le parser TOML, le `data/eol-mapping.json` enrichi.

**Cohérence des types :** `coordKey` (string), `makeDepRecord(input)` signature stable,
`collect(dir,opts) → {deps,warnings}`, scanner `{id, scan(deps,opts)→{matches,meta}}`,
`checkRegistry → {outdated,deprecated}`. Noms alignés entre tâches.

**Point de vigilance reporté à l'exécution :** les getters alias (`groupId`/`artifactId`)
de `makeDepRecord` ne survivent pas au spread/clone. Task 3 Step 4 et Task 9 Step 4c
servent de filet (suite complète + smoke run). Si un chemin clone les records, migrer
ce chemin vers `namespace`/`name`.

## Plans suivants (à rédiger après A)

- **Plan B — composer** : codec `composer`, parse `composer.lock`/`composer.json`,
  registre Packagist (`abandoned`), EOL `by_composer_name`, recette, fixtures `php-app/`.
- **Plan C — pypi** : dép `smol-toml`, parse poetry.lock/Pipfile.lock/uv.lock/pdm.lock/
  requirements.txt, normalisation PEP 503, registre PyPI (`yanked`), EOL `by_pypi_name`.
- **Plan D — nuget** : parse .csproj/packages.lock.json/packages.config + CPM
  (`Directory.Packages.props`), registre NuGet (`deprecation`), EOL `by_nuget_name`/dotnet.
