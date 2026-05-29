# Plan B — Codec Composer (PHP) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Ajouter le codec `composer` (PHP) en parité complète — vuln (OSV/Packagist), abandoned (Packagist), outdated (Packagist), EOL (endoflife.date), recette de fix — sur l'interface codec figée par Plan A.

**Architecture:** `lib/composer/parse.js` parse `composer.lock` (et `composer.json` en fallback). `lib/composer/registry.js` interroge Packagist (latest stable + champ `abandoned`). `lib/codecs/composer.codec.js` assemble le tout. L'orchestrateur, déjà une boucle de codecs pour la collecte/OSV, gagne une boucle générique `codec.checkRegistry` pour les écosystèmes hors maven/npm. OSV (ecosystem `Packagist`) est déjà câblé (Plan A, Task 7).

**Tech Stack:** Node.js, node --test. Aucune dépendance nouvelle (composer.lock + composer.json sont du JSON).

---

## File Structure

| Fichier | Rôle | Action |
|---|---|---|
| `lib/composer/parse.js` | parse composer.lock (`packages[]`+`packages-dev[]`) + composer.json fallback | Créer |
| `lib/composer/registry.js` | Packagist : latest stable + `abandoned` | Créer |
| `lib/codecs/composer.codec.js` | codec composer | Créer |
| `lib/codecs/index.js` | enregistrer composer | Modifier |
| `lib/codecs/recipes.js` | recette composer | Modifier |
| `lib/outdated.js` | findEolProduct → branche composer ; checkOutdatedDeps → maven-only | Modifier |
| `data/eol-mapping.json` | `by_composer_name` (php, laravel, symfony, drupal…) | Modifier |
| `fad-checker.js` | boucle générique `codec.checkRegistry` (eco hors maven/npm) | Modifier |
| `test/fixtures/php-app/` | composer.json + composer.lock | Créer |
| `test/composer.test.js` | parse + codec + coordKey + fallback | Créer |

**Invariant :** `npm test` reste vert à chaque tâche.

---

### Task 1: Parser composer.lock + composer.json

**Files:**
- Create: `lib/composer/parse.js`, `test/fixtures/php-app/composer.lock`, `test/fixtures/php-app/composer.json`
- Test: `test/composer.test.js`

- [ ] **Step 1: Créer la fixture**

`test/fixtures/php-app/composer.json` :
```json
{
  "name": "acme/site",
  "require": { "guzzlehttp/guzzle": "^7.0", "monolog/monolog": "2.9.1" },
  "require-dev": { "phpunit/phpunit": "^10.0" }
}
```

`test/fixtures/php-app/composer.lock` :
```json
{
  "packages": [
    { "name": "guzzlehttp/guzzle", "version": "7.4.5" },
    { "name": "monolog/monolog", "version": "2.9.1" },
    { "name": "symfony/console", "version": "v6.2.10" }
  ],
  "packages-dev": [
    { "name": "phpunit/phpunit", "version": "10.1.0" }
  ]
}
```

- [ ] **Step 2: Écrire le test qui échoue**

```js
// test/composer.test.js
const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { parseComposerLock, parseComposerJson } = require("../lib/composer/parse");

const FIX = path.join(__dirname, "fixtures", "php-app");

test("parseComposerLock reads prod + dev packages, strips leading v", () => {
	const r = parseComposerLock(path.join(FIX, "composer.lock"));
	const byName = Object.fromEntries(r.deps.map(d => [d.name, d]));
	assert.strictEqual(byName["guzzlehttp/guzzle"].version, "7.4.5");
	assert.strictEqual(byName["guzzlehttp/guzzle"].scope, "prod");
	assert.strictEqual(byName["symfony/console"].version, "6.2.10");      // "v6.2.10" → "6.2.10"
	assert.strictEqual(byName["phpunit/phpunit"].scope, "dev");
	assert.strictEqual(byName["phpunit/phpunit"].isDev, true);
});

test("parseComposerJson reads require + require-dev with pinned-vs-range info", () => {
	const r = parseComposerJson(path.join(FIX, "composer.json"));
	const byName = Object.fromEntries(r.deps.map(d => [d.name, d]));
	assert.strictEqual(byName["monolog/monolog"].version, "2.9.1");
	assert.strictEqual(byName["guzzlehttp/guzzle"].version, "^7.0");
	assert.strictEqual(byName["phpunit/phpunit"].scope, "dev");
});
```

- [ ] **Step 3: Lancer (échec attendu)**

Run: `node --test test/composer.test.js`
Expected: FAIL — `Cannot find module '../lib/composer/parse'`

- [ ] **Step 4: Implémenter le parser**

```js
// lib/composer/parse.js
const fs = require("fs");

// Composer versions: "1.2.3", "v1.2.3", "dev-main", "1.0.x-dev". On ne garde la
// version brute que pour affichage ; on normalise le "v" de tête pour OSV/registre.
function normVersion(v) {
	if (!v) return null;
	return String(v).replace(/^v/, "");
}
function isConcrete(v) {
	return !!v && /^\d+(\.\d+)*([.\-+]\S+)?$/.test(String(v).replace(/^v/, ""));
}
// Composer name = "vendor/package" (case-insensitive ; lowercased par convention).
function splitName(full) {
	const i = full.indexOf("/");
	if (i < 0) return { vendor: "", pkg: full };
	return { vendor: full.slice(0, i), pkg: full.slice(i + 1) };
}

function parseComposerLock(filePath) {
	const json = JSON.parse(fs.readFileSync(filePath, "utf8"));
	const deps = [];
	const push = (arr, scope) => {
		for (const p of arr || []) {
			if (!p.name) continue;
			const { vendor, pkg } = splitName(p.name);
			deps.push({ name: p.name, vendor, pkg, version: normVersion(p.version), scope, isDev: scope === "dev" });
		}
	};
	push(json.packages, "prod");
	push(json["packages-dev"], "dev");
	return { manifestPath: filePath, manifestType: "composer.lock", deps };
}

function parseComposerJson(filePath) {
	const json = JSON.parse(fs.readFileSync(filePath, "utf8"));
	const deps = [];
	const push = (obj, scope) => {
		for (const [name, version] of Object.entries(obj || {})) {
			if (name === "php" || name.startsWith("ext-") || name.startsWith("lib-")) continue;  // platform reqs
			const { vendor, pkg } = splitName(name);
			deps.push({ name, vendor, pkg, version: String(version), scope, isDev: scope === "dev" });
		}
	};
	push(json.require, "prod");
	push(json["require-dev"], "dev");
	return { manifestPath: filePath, manifestType: "composer.json", deps };
}

module.exports = { parseComposerLock, parseComposerJson, normVersion, isConcrete, splitName };
```

- [ ] **Step 5: Lancer (succès)**

Run: `node --test test/composer.test.js`
Expected: PASS (2 tests)

- [ ] **Step 6: Commit**

```bash
git add lib/composer/parse.js test/composer.test.js test/fixtures/php-app/
git commit -m "composer: parse composer.lock + composer.json"
```

---

### Task 2: Registre Packagist (latest + abandoned)

**Files:**
- Create: `lib/composer/registry.js`
- Test: `test/composer.test.js` (ajout, sans réseau — on teste l'extraction pure)

- [ ] **Step 1: Écrire le test qui échoue**

```js
// ajout test/composer.test.js
const { packagistToFindings } = require("../lib/composer/registry");

test("packagistToFindings extracts latest stable + abandoned flag", () => {
	// Forme du endpoint packagist.org/packages/{vendor}/{pkg}.json (sous-ensemble)
	const pkg = {
		"abandoned": "psr/log",
		"versions": {
			"2.9.1": { "version": "2.9.1" },
			"3.0.0": { "version": "3.0.0" },
			"dev-main": { "version": "dev-main" },
			"2.8.0": { "version": "2.8.0" },
		},
	};
	const f = packagistToFindings(pkg, { version: "2.9.1" });
	assert.strictEqual(f.outdated.latest, "3.0.0");           // plus haute stable, dev-* ignorée
	assert.deepStrictEqual(f.abandoned, { replacement: "psr/log" });

	const f2 = packagistToFindings({ "abandoned": true, "versions": { "1.0.0": {} } }, { version: "1.0.0" });
	assert.deepStrictEqual(f2.abandoned, { replacement: null });   // abandoned sans remplaçant
	assert.strictEqual(f2.outdated, null);                          // déjà au latest
});
```

- [ ] **Step 2: Lancer (échec attendu)**

Run: `node --test test/composer.test.js`
Expected: FAIL — `packagistToFindings is not a function`

- [ ] **Step 3: Implémenter le registre**

```js
// lib/composer/registry.js
const fs = require("fs");
const path = require("path");
const os = require("os");
let pLimit; try { pLimit = require("p-limit"); } catch { pLimit = (n) => (fn) => fn(); }

const CACHE_DIR = path.join(os.homedir(), ".fad-checker");
const CACHE_PATH = path.join(CACHE_DIR, "packagist-cache.json");
const CACHE_MAX_AGE_MS = 24 * 3600 * 1000;
const API = "https://packagist.org/packages";

function loadCache() { try { return JSON.parse(fs.readFileSync(CACHE_PATH, "utf8")); } catch { return { entries: {}, meta: {} }; } }
function saveCache(d) { try { fs.mkdirSync(CACHE_DIR, { recursive: true }); fs.writeFileSync(CACHE_PATH, JSON.stringify(d)); } catch { /* ignore */ } }

function isStable(v) { return /^\d+(\.\d+)*$/.test(String(v || "").replace(/^v/, "")); }
function cmp(a, b) {
	const pa = a.replace(/^v/, "").split(/[.\-+]/).map(n => parseInt(n, 10) || 0);
	const pb = b.replace(/^v/, "").split(/[.\-+]/).map(n => parseInt(n, 10) || 0);
	for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d > 0 ? 1 : -1; }
	return 0;
}

// Extrait {abandoned, outdated} de la réponse packagist (package.versions + package.abandoned).
function packagistToFindings(pkg, { version }) {
	const out = { abandoned: null, outdated: null };
	if (pkg.abandoned === true) out.abandoned = { replacement: null };
	else if (typeof pkg.abandoned === "string") out.abandoned = { replacement: pkg.abandoned };
	const stable = Object.keys(pkg.versions || {}).map(v => v.replace(/^v/, "")).filter(isStable);
	if (stable.length) {
		const latest = stable.sort(cmp).at(-1);
		if (latest && cmp(latest, String(version).replace(/^v/, "")) > 0) out.outdated = { latest };
	}
	return out;
}

async function fetchPackage(name, { offline }) {
	if (offline) return null;
	try {
		const res = await fetch(`${API}/${name}.json`, { headers: { "User-Agent": "fad-checker-packagist" } });
		if (!res.ok) return { error: `HTTP ${res.status}` };
		const json = await res.json();
		return json.package || { error: "no package field" };
	} catch (e) { return { error: e.message }; }
}

// Mirror de checkNpmRegistryDeps : renvoie { deprecated:[], outdated:[] }.
async function checkComposerRegistryDeps(deps, opts = {}) {
	const { verbose, offline, allLibs = true, concurrency = 8 } = opts;
	const targets = [...deps.values()].filter(d => d.ecosystem === "composer" && d.version);
	const result = { deprecated: [], outdated: [] };
	if (!targets.length) return result;
	const cache = loadCache();
	const fresh = cache.meta?.fetchedAt && (Date.now() - cache.meta.fetchedAt) < CACHE_MAX_AGE_MS;
	if (!fresh && !offline) cache.entries = {};
	const limit = pLimit(concurrency);
	await Promise.all(targets.map(t => limit(async () => {
		const name = `${t.namespace}/${t.name}`.toLowerCase();
		const key = `${name}@${t.version}`;
		let ex = cache.entries[key];
		if (!ex) {
			const pkg = await fetchPackage(name, { offline });
			if (pkg && !pkg.error) { const f = packagistToFindings(pkg, { version: t.version }); ex = { abandoned: f.abandoned, latest: f.outdated?.latest || null }; cache.entries[key] = ex; }
			else ex = { abandoned: null, latest: null };
		}
		if (ex.abandoned) result.deprecated.push({ dep: t, severity: "MEDIUM", replacement: ex.abandoned.replacement, reason: "Package marked abandoned on Packagist", source: "packagist" });
		if (allLibs && ex.latest) result.outdated.push({ dep: t, latest: ex.latest, releaseDate: null });
	})));
	cache.meta = { fetchedAt: Date.now() }; saveCache(cache);
	return result;
}

module.exports = { packagistToFindings, checkComposerRegistryDeps };
```

- [ ] **Step 4: Lancer (succès)**

Run: `node --test test/composer.test.js`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add lib/composer/registry.js test/composer.test.js
git commit -m "composer: Packagist registry (latest stable + abandoned)"
```

---

### Task 3: Le codec composer + enregistrement + recette + EOL

**Files:**
- Create: `lib/codecs/composer.codec.js`
- Modify: `lib/codecs/index.js`, `lib/codecs/recipes.js`, `lib/outdated.js`, `data/eol-mapping.json`

- [ ] **Step 1: Écrire le test qui échoue**

```js
// ajout test/composer.test.js
const composer = require("../lib/codecs/composer.codec");
const { assertCodecShape } = require("../lib/codecs/codec.interface");

test("composer codec: shape, detect, collect with composer:vendor/pkg coordKeys", async () => {
	assertCodecShape(composer);
	assert.strictEqual(composer.detect(FIX), true);
	const { deps } = await composer.collect(FIX, {});
	const g = deps.get("composer:guzzlehttp/guzzle");
	assert.ok(g, "guzzle should be collected under composer:guzzlehttp/guzzle");
	assert.strictEqual(g.ecosystem, "composer");
	assert.strictEqual(g.namespace, "guzzlehttp");
	assert.strictEqual(g.name, "guzzle");
	assert.strictEqual(composer.osvPackageName(g), "guzzlehttp/guzzle");
	assert.strictEqual(composer.formatCoord(g), "guzzlehttp/guzzle");
});

test("composer collect falls back to composer.json (pinned only) with warning when no lock", async () => {
	const os2 = require("os"); const fs2 = require("fs"); const p2 = require("path");
	const dir = fs2.mkdtempSync(p2.join(os2.tmpdir(), "composer-nolock-"));
	fs2.writeFileSync(p2.join(dir, "composer.json"), JSON.stringify({ name: "x/y", require: { "a/pinned": "1.2.3", "b/range": "^2.0" } }));
	const { deps, warnings } = await composer.collect(dir, {});
	assert.ok(deps.has("composer:a/pinned"));
	assert.ok(!deps.has("composer:b/range"));
	assert.ok(warnings.find(w => w.type === "no-lockfile"));
});
```

- [ ] **Step 2: Lancer (échec attendu)**

Run: `node --test test/composer.test.js`
Expected: FAIL — `Cannot find module '../lib/codecs/composer.codec'`

- [ ] **Step 3a: Écrire le codec**

```js
// lib/codecs/composer.codec.js
const fs = require("fs");
const path = require("path");
const { makeDepRecord, coordKeyFor } = require("../dep-record");
const { parseComposerLock, parseComposerJson, isConcrete } = require("../composer/parse");

const SKIP = new Set(["vendor", ".git", ".idea", ".vscode", "node_modules", "dist", "build", "out"]);

function findComposerManifests(dir) {
	const groups = [];
	const stack = [dir];
	while (stack.length) {
		const cur = stack.pop();
		let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
		const names = new Set(entries.filter(e => e.isFile()).map(e => e.name));
		if (names.has("composer.json") || names.has("composer.lock")) {
			groups.push({
				dir: cur,
				composerJson: names.has("composer.json") ? path.join(cur, "composer.json") : null,
				composerLock: names.has("composer.lock") ? path.join(cur, "composer.lock") : null,
			});
		}
		for (const e of entries) if (e.isDirectory() && !SKIP.has(e.name)) stack.push(path.join(cur, e.name));
	}
	return groups;
}

module.exports = {
	id: "composer",
	label: "Composer",
	osvEcosystem: "Packagist",
	manifestNames: ["composer.json", "composer.lock"],

	detect(dir) { return findComposerManifests(dir).length > 0; },

	async collect(dir, opts = {}) {
		const { ignoreTest, deps2Exclude } = opts;
		const out = new Map();
		const warnings = [];
		for (const g of findComposerManifests(dir)) {
			if (g.composerLock) {
				const { deps } = parseComposerLock(g.composerLock);
				for (const d of deps) {
					if (ignoreTest && d.isDev) continue;
					if (deps2Exclude && deps2Exclude.test(d.name)) continue;
					out.set(coordKeyFor("composer", d.vendor, d.pkg),
						makeDepRecord({ ecosystem: "composer", namespace: d.vendor, name: d.pkg, version: d.version, manifestPath: g.composerLock, scope: d.scope, isDev: d.isDev }));
				}
			} else if (g.composerJson) {
				// no lock → best-effort: pinned exact versions only + warning
				const { deps } = parseComposerJson(g.composerJson);
				let pinned = 0, ranges = 0;
				for (const d of deps) {
					if (ignoreTest && d.isDev) continue;
					if (deps2Exclude && deps2Exclude.test(d.name)) continue;
					if (isConcrete(d.version)) {
						out.set(coordKeyFor("composer", d.vendor, d.pkg),
							makeDepRecord({ ecosystem: "composer", namespace: d.vendor, name: d.pkg, version: d.version.replace(/^v/, ""), manifestPath: g.composerJson, scope: d.scope, isDev: d.isDev }));
						pinned++;
					} else ranges++;
				}
				warnings.push({ type: "no-lockfile", manifestPath: g.composerJson, message: `composer.json without composer.lock — best-effort: ${pinned} pinned, ${ranges} range(s) skipped (run "composer install")` });
			}
		}
		return { deps: out, warnings };
	},

	coordKey(d) { return coordKeyFor("composer", d.namespace, d.name); },
	formatCoord(d) { return `${d.namespace}/${d.name}`; },
	osvPackageName(d) { return `${d.namespace}/${d.name}`; },

	async checkRegistry(deps, opts = {}) {
		const { checkComposerRegistryDeps } = require("../composer/registry");
		return checkComposerRegistryDeps(deps, opts);
	},
	resolveEolProduct(d) { return require("../outdated").findEolProduct(d); },
	recipe: require("./recipes").composer,
	nativeScanners: [],
};
```

- [ ] **Step 3b: Enregistrer le codec** — `lib/codecs/index.js`

```js
const composer = require("./composer.codec");
// …
for (const c of [maven, npm, yarn, composer]) { assertCodecShape(c); REGISTRY.set(c.id, c); }
```

- [ ] **Step 3c: Recette composer** — ajouter dans `lib/codecs/recipes.js`

```js
function composerRequireSnippet(items) {
	return items.map(it => `composer require ${it.groupId ? it.groupId + "/" : ""}${it.artifactId}:^${it.fixVersion}`).join("\n");
}
const composer = {
	label: "Composer",
	pinSection: "A. Update the abandoned/vulnerable packages",
	pinIntro: cnt => `Run for the ${cnt} affected package${cnt > 1 ? "s" : ""}:`,
	snippet: composerRequireSnippet,
	directSection: "B. Then commit the updated composer.lock",
};
module.exports = { maven, npm, yarn, composer, /* …existing exports… */ };
```

- [ ] **Step 3d: EOL composer** — `lib/outdated.js` `findEolProduct`, ajouter AVANT le bloc maven (`const key = ...`) :

```js
	if (dep.ecosystem === "composer") {
		const full = `${dep.namespace || dep.groupId}/${dep.name || dep.artifactId}`.toLowerCase();
		return EOL_MAPPING.by_composer_name?.[full] || null;
	}
```

- [ ] **Step 3e: `by_composer_name`** — `data/eol-mapping.json`, ajouter une clé top-level :

```json
"by_composer_name": {
  "laravel/framework": { "product": "laravel", "label": "Laravel" },
  "symfony/symfony": { "product": "symfony", "label": "Symfony" },
  "symfony/console": { "product": "symfony", "label": "Symfony" },
  "drupal/core": { "product": "drupal", "label": "Drupal" }
}
```

- [ ] **Step 4: Lancer (succès)**

Run: `node --test test/composer.test.js`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add lib/codecs/composer.codec.js lib/codecs/index.js lib/codecs/recipes.js lib/outdated.js data/eol-mapping.json test/composer.test.js
git commit -m "composer: codec + registry wiring + EOL mapping + recipe"
```

---

### Task 4: Câbler checkRegistry générique dans l'orchestrateur + fix Maven outdated

**Files:**
- Modify: `lib/outdated.js` (`checkOutdatedDeps` filtre maven-only), `fad-checker.js` (boucle `codec.checkRegistry` pour eco hors maven/npm)

- [ ] **Step 1: Fix du filtre Maven outdated** — `lib/outdated.js:248`

```js
	const list = [...resolvedDeps.values()].filter(d => d.version && !/\$\{|SNAPSHOT/i.test(d.version) && d.ecosystem === "maven");
```
(était `d.ecosystem !== "npm"` — laissait fuir composer/pypi/nuget vers Maven Central.)

- [ ] **Step 2: Boucle checkRegistry** — `fad-checker.js`, juste après le bloc npm-registry (étape 4a), ajouter :

```js
	// 4a-bis. Per-codec registry for non-maven/npm ecosystems (composer/pypi/nuget).
	// maven + npm are already covered above (outdated.js + npm registry).
	for (const id of activeIds) {
		if (id === "maven" || id === "npm" || id === "yarn") continue;
		const codec = getCodec(id);
		if (!codec?.checkRegistry) continue;
		try {
			const reg = await codec.checkRegistry(resolved, { verbose, offline, allLibs: options.allLibs });
			obsoleteResults = obsoleteResults.concat(reg.deprecated || []);
			outdatedResults = outdatedResults.concat(reg.outdated || []);
		} catch (err) { console.warn(chalk.yellow(`⚠️  ${id} registry check skipped:`), err.message); }
	}
```

> Placement : APRÈS la section `4a` (npm registry) et AVANT le dedup cross-section
> `eolKeys/obsKeys` (qui utilise `dep.coordKey`/`groupId:artifactId` — déjà compatible).
> Vérifier que `outdatedResults`/`obsoleteResults` sont `let` (ils le sont).

- [ ] **Step 3: Lancer la suite complète**

Run: `npm test`
Expected: PASS (tous + composer).

- [ ] **Step 4: Smoke test bout-en-bout (offline)**

Run: `node fad-checker.js -s ./test/fixtures/php-app --offline --report-output /tmp/fad-php`
Expected: détecte composer, liste les 4 packages, génère le report sans erreur, aucune requête Maven Central pour les deps composer.

- [ ] **Step 5: Commit**

```bash
git add lib/outdated.js fad-checker.js
git commit -m "Wire per-codec checkRegistry for non-maven/npm; Maven outdated maven-only"
```

---

### Task 5: Docs

**Files:** `CLAUDE.md`, `docs/ARCHITECTURE.md`

- [ ] **Step 1** : ajouter `lib/composer/*` + `composer.codec.js` aux cartes de modules ; mentionner Composer (PHP) dans la liste des écosystèmes supportés (point 2/3 de l'intro CLAUDE.md) ; ajouter `php-app/` aux fixtures.
- [ ] **Step 2** : `npm test` (sanity) puis commit.

```bash
git add CLAUDE.md docs/ARCHITECTURE.md
git commit -m "Docs: Composer (PHP) codec"
```

---

## Self-Review (effectuée)

- Vuln composer → OSV `Packagist` déjà câblé (Plan A Task 7) ✓ ; parse lock+json+fallback → Task 1 ✓ ;
  abandoned+outdated → Packagist Task 2 + wiring Task 4 ✓ ; EOL → findEolProduct + mapping Task 3 ✓ ;
  recette → Task 3c ✓ ; report (sections/labels/ordre) → déjà piloté par codec via le registre (Plan A Task 8),
  composer apparaît dès son enregistrement ✓ ; CLI `--no-composer`/`--ecosystem composer` → déjà géré par
  select.js + les flags `--no-<id>` de Plan A ✓.
- **Bug corrigé** : `checkOutdatedDeps` filtrait `!== "npm"` → aurait interrogé Maven Central pour des
  deps composer. Task 4 Step 1 le restreint à maven.
- **Cohérence types** : depRecord composer via makeDepRecord ; checkRegistry → {deprecated[], outdated[]}
  (même forme que npm) ; deprecated entry {dep,severity,replacement,reason,source}.
