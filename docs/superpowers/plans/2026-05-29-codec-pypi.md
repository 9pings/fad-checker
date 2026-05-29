# Plan C — Codec PyPI (Python) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Ajouter le codec `pypi` (Python) en parité complète — vuln (OSV PyPI), yanked/inactive (PyPI registry), outdated (PyPI), EOL (endoflife.date), recette — sur l'interface codec.

**Architecture:** `lib/python/parse.js` parse les 4 formats de lock (poetry.lock/uv.lock/pdm.lock via `smol-toml`, Pipfile.lock en JSON) + `requirements.txt` (pinned, fallback). `lib/python/registry.js` interroge PyPI JSON (latest + yanked + classifier inactif). `lib/codecs/pypi.codec.js` assemble. La boucle `codec.checkRegistry` (Plan B) et OSV `PyPI` (Plan A) sont déjà câblées — **aucune modif orchestrateur**. Noms normalisés PEP 503.

**Tech Stack:** Node.js, node --test, `smol-toml` (déjà installé).

---

## File Structure

| Fichier | Rôle | Action |
|---|---|---|
| `lib/python/parse.js` | pep503 + parsers poetry/pipfile/uv/pdm/requirements | Créer |
| `lib/python/registry.js` | PyPI JSON → latest + yanked + inactive | Créer |
| `lib/codecs/pypi.codec.js` | codec pypi | Créer |
| `lib/codecs/index.js` | enregistrer pypi | Modifier |
| `lib/codecs/recipes.js` | recette pypi | Modifier |
| `lib/outdated.js` | findEolProduct → branche pypi | Modifier |
| `data/eol-mapping.json` | `by_pypi_name` (django, numpy, fastapi…) | Modifier |
| `test/fixtures/python-*/` | un dossier par format | Créer |
| `test/pypi.test.js` | parsers + codec + PEP 503 + fallback | Créer |
| `CLAUDE.md`, `docs/ARCHITECTURE.md` | docs | Modifier |

**Invariant :** `npm test` reste vert à chaque tâche.

---

### Task 1: PEP 503 + parsers + fixtures

**Files:** Create `lib/python/parse.js`, fixtures, `test/pypi.test.js`.

- [ ] **Step 1: Fixtures** (un répertoire par format)

`test/fixtures/python-poetry/poetry.lock` :
```toml
[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "Flask-SQLAlchemy"
version = "3.0.5"
```

`test/fixtures/python-pipenv/Pipfile.lock` :
```json
{ "default": { "django": { "version": "==4.2.0" } }, "develop": { "pytest": { "version": "==7.4.0" } } }
```

`test/fixtures/python-uv/uv.lock` :
```toml
[[package]]
name = "numpy"
version = "1.26.0"
```

`test/fixtures/python-reqs/requirements.txt` :
```
# comment
fastapi==0.103.0
flask>=2.0          # range → skipped
-e .
urllib3==2.0.4
```

- [ ] **Step 2: Écrire le test qui échoue**

```js
// test/pypi.test.js
const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { pep503, parsePoetryLock, parsePipfileLock, parseUvLock, parseRequirementsTxt } = require("../lib/python/parse");

const F = n => path.join(__dirname, "fixtures", n);

test("pep503 normalizes names (lowercase, collapse separators to -)", () => {
	assert.strictEqual(pep503("Flask-SQLAlchemy"), "flask-sqlalchemy");
	assert.strictEqual(pep503("zope.interface"), "zope-interface");
	assert.strictEqual(pep503("My__Pkg"), "my-pkg");
});

test("parsePoetryLock returns PEP503 names + versions", () => {
	const r = parsePoetryLock(F("python-poetry/poetry.lock"));
	const m = Object.fromEntries(r.deps.map(d => [d.name, d.version]));
	assert.strictEqual(m["requests"], "2.31.0");
	assert.strictEqual(m["flask-sqlalchemy"], "3.0.5");   // normalized
});

test("parsePipfileLock splits default/develop, strips ==", () => {
	const r = parsePipfileLock(F("python-pipenv/Pipfile.lock"));
	const m = Object.fromEntries(r.deps.map(d => [d.name, d]));
	assert.strictEqual(m["django"].version, "4.2.0");
	assert.strictEqual(m["django"].scope, "prod");
	assert.strictEqual(m["pytest"].scope, "dev");
});

test("parseUvLock reads [[package]]", () => {
	const r = parseUvLock(F("python-uv/uv.lock"));
	assert.strictEqual(r.deps.find(d => d.name === "numpy").version, "1.26.0");
});

test("parseRequirementsTxt keeps == pins, skips ranges/flags/comments", () => {
	const r = parseRequirementsTxt(F("python-reqs/requirements.txt"));
	const names = r.deps.map(d => d.name).sort();
	assert.deepStrictEqual(names, ["fastapi", "urllib3"]);
	assert.strictEqual(r.skipped, 1);   // flask>=2.0
});
```

- [ ] **Step 3: Lancer (échec attendu)**

Run: `node --test test/pypi.test.js`
Expected: FAIL — `Cannot find module '../lib/python/parse'`

- [ ] **Step 4: Implémenter**

```js
// lib/python/parse.js
const fs = require("fs");
const TOML = require("smol-toml");

// PEP 503: lowercase + collapse runs of -, _, . to a single -.
function pep503(name) { return String(name || "").toLowerCase().replace(/[-_.]+/g, "-"); }

function stripOp(v) { return String(v || "").replace(/^[=~!<>]+/, "").trim(); }
function isPinned(spec) { return /^==\s*\d[\w.\-+!]*$/.test(String(spec || "").trim()); }
function isConcrete(v) { return /^\d+(\.\d+)*([.\-+]\S+)?$/.test(String(v || "")); }

// poetry.lock / uv.lock / pdm.lock all use [[package]] name/version arrays.
function parseTomlPackages(filePath, type) {
	const data = TOML.parse(fs.readFileSync(filePath, "utf8"));
	const pkgs = Array.isArray(data.package) ? data.package : [];
	const deps = [];
	for (const p of pkgs) {
		if (!p.name || !p.version) continue;
		// pdm marks groups; poetry/uv don't reliably → default prod.
		const groups = Array.isArray(p.groups) ? p.groups : null;
		const isDev = groups ? groups.every(g => g === "dev") : false;
		deps.push({ name: pep503(p.name), version: String(p.version), scope: isDev ? "dev" : "prod", isDev });
	}
	return { manifestPath: filePath, manifestType: type, deps };
}
const parsePoetryLock = f => parseTomlPackages(f, "poetry.lock");
const parseUvLock = f => parseTomlPackages(f, "uv.lock");
const parsePdmLock = f => parseTomlPackages(f, "pdm.lock");

function parsePipfileLock(filePath) {
	const json = JSON.parse(fs.readFileSync(filePath, "utf8"));
	const deps = [];
	const push = (obj, scope) => {
		for (const [name, meta] of Object.entries(obj || {})) {
			const v = stripOp(meta.version);
			if (!v) continue;
			deps.push({ name: pep503(name), version: v, scope, isDev: scope === "dev" });
		}
	};
	push(json.default, "prod");
	push(json.develop, "dev");
	return { manifestPath: filePath, manifestType: "Pipfile.lock", deps };
}

function parseRequirementsTxt(filePath) {
	const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
	const deps = [];
	let skipped = 0;
	for (let raw of lines) {
		const line = raw.replace(/#.*$/, "").trim();
		if (!line) continue;
		if (line.startsWith("-")) continue;                 // -e ., -r other.txt, --flags
		const m = line.match(/^([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(.*)$/);
		if (!m) continue;
		const name = pep503(m[1]);
		const spec = m[3].split(";")[0].trim();              // drop env markers
		if (isPinned(spec)) deps.push({ name, version: stripOp(spec), scope: "prod", isDev: false });
		else skipped++;
	}
	return { manifestPath: filePath, manifestType: "requirements.txt", deps, skipped };
}

module.exports = { pep503, isConcrete, parsePoetryLock, parseUvLock, parsePdmLock, parsePipfileLock, parseRequirementsTxt };
```

- [ ] **Step 5: Lancer (succès)** — `node --test test/pypi.test.js` → PASS (5).
- [ ] **Step 6: Commit** — `git add lib/python/parse.js test/pypi.test.js test/fixtures/python-* && git commit -m "pypi: PEP503 + poetry/pipfile/uv/pdm/requirements parsers"`

---

### Task 2: Registre PyPI (latest + yanked + inactive)

**Files:** Create `lib/python/registry.js`; add test.

- [ ] **Step 1: Test qui échoue**

```js
// ajout test/pypi.test.js
const { pypiToFindings } = require("../lib/python/registry");
test("pypiToFindings extracts latest, yanked-for-version, inactive classifier", () => {
	const data = {
		info: { version: "2.1.0", classifiers: ["Development Status :: 7 - Inactive"] },
		releases: { "2.0.4": [{ yanked: true, yanked_reason: "security" }], "2.1.0": [{ yanked: false }] },
	};
	const f = pypiToFindings(data, { version: "2.0.4" });
	assert.strictEqual(f.outdated.latest, "2.1.0");
	assert.strictEqual(f.yanked.reason, "security");
	assert.strictEqual(f.inactive, true);
	const f2 = pypiToFindings(data, { version: "2.1.0" });
	assert.strictEqual(f2.yanked, null);       // current version not yanked
	assert.strictEqual(f2.outdated, null);     // already latest
});
```

- [ ] **Step 2: Lancer (échec attendu)** — `pypiToFindings is not a function`.

- [ ] **Step 3: Implémenter**

```js
// lib/python/registry.js
const fs = require("fs");
const path = require("path");
const os = require("os");
let pLimit; try { pLimit = require("p-limit"); } catch { pLimit = () => (fn) => fn(); }

const CACHE_DIR = path.join(os.homedir(), ".fad-checker");
const CACHE_PATH = path.join(CACHE_DIR, "pypi-cache.json");
const CACHE_MAX_AGE_MS = 24 * 3600 * 1000;
const API = "https://pypi.org/pypi";

function loadCache() { try { return JSON.parse(fs.readFileSync(CACHE_PATH, "utf8")); } catch { return { entries: {}, meta: {} }; } }
function saveCache(d) { try { fs.mkdirSync(CACHE_DIR, { recursive: true }); fs.writeFileSync(CACHE_PATH, JSON.stringify(d)); } catch { /* ignore */ } }
function cmp(a, b) {
	const pa = String(a).split(/[.\-+]/).map(n => parseInt(n, 10) || 0);
	const pb = String(b).split(/[.\-+]/).map(n => parseInt(n, 10) || 0);
	for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d > 0 ? 1 : -1; }
	return 0;
}

function pypiToFindings(data, { version }) {
	const out = { outdated: null, yanked: null, inactive: false };
	const latest = data.info?.version;
	if (latest && cmp(latest, version) > 0) out.outdated = { latest };
	const rel = data.releases?.[version];
	if (Array.isArray(rel) && rel.length && rel.every(f => f.yanked)) {
		out.yanked = { reason: rel.find(f => f.yanked_reason)?.yanked_reason || null };
	}
	if ((data.info?.classifiers || []).some(c => /Development Status :: 7 - Inactive/i.test(c))) out.inactive = true;
	return out;
}

async function fetchProject(name, { offline }) {
	if (offline) return null;
	try {
		const res = await fetch(`${API}/${name}/json`, { headers: { "User-Agent": "fad-checker-pypi" } });
		if (!res.ok) return { error: `HTTP ${res.status}` };
		return await res.json();
	} catch (e) { return { error: e.message }; }
}

async function checkPypiRegistryDeps(deps, opts = {}) {
	const { verbose, offline, allLibs = true, concurrency = 8 } = opts;
	const targets = [...deps.values()].filter(d => d.ecosystem === "pypi" && d.version);
	const result = { deprecated: [], outdated: [] };
	if (!targets.length) return result;
	const cache = loadCache();
	const fresh = cache.meta?.fetchedAt && (Date.now() - cache.meta.fetchedAt) < CACHE_MAX_AGE_MS;
	if (!fresh && !offline) cache.entries = {};
	const limit = pLimit(concurrency);
	await Promise.all(targets.map(t => limit(async () => {
		const key = `${t.name}@${t.version}`;
		let ex = cache.entries[key];
		if (!ex) {
			const data = await fetchProject(t.name, { offline });
			if (data && !data.error) { const f = pypiToFindings(data, { version: t.version }); ex = { yanked: f.yanked, inactive: f.inactive, latest: f.outdated?.latest || null }; cache.entries[key] = ex; }
			else ex = { yanked: null, inactive: false, latest: null };
		}
		if (ex.yanked) result.deprecated.push({ dep: t, severity: "HIGH", replacement: null, reason: `Version yanked on PyPI${ex.yanked.reason ? `: ${ex.yanked.reason}` : ""}`, source: "pypi" });
		else if (ex.inactive) result.deprecated.push({ dep: t, severity: "LOW", replacement: null, reason: "Marked 'Development Status :: 7 - Inactive' on PyPI", source: "pypi" });
		if (allLibs && ex.latest) result.outdated.push({ dep: t, latest: ex.latest, releaseDate: null });
	})));
	cache.meta = { fetchedAt: Date.now() }; saveCache(cache);
	return result;
}

module.exports = { pypiToFindings, checkPypiRegistryDeps };
```

- [ ] **Step 4: Lancer (succès)** — PASS (6).
- [ ] **Step 5: Commit** — `git add lib/python/registry.js test/pypi.test.js && git commit -m "pypi: PyPI registry (latest + yanked + inactive)"`

---

### Task 3: Codec pypi + register + recipe + EOL

**Files:** Create `lib/codecs/pypi.codec.js`; modify `index.js`, `recipes.js`, `outdated.js`, `eol-mapping.json`, `codecs.test.js`.

- [ ] **Step 1: Test qui échoue**

```js
// ajout test/pypi.test.js
const pypi = require("../lib/codecs/pypi.codec");
const { assertCodecShape } = require("../lib/codecs/codec.interface");
test("pypi codec: shape, detect, collect, coordKey pypi:<name>", async () => {
	assertCodecShape(pypi);
	assert.strictEqual(pypi.detect(F("python-poetry")), true);
	const { deps } = await pypi.collect(F("python-poetry"), {});
	const r = deps.get("pypi:requests");
	assert.ok(r);
	assert.strictEqual(r.ecosystem, "pypi");
	assert.strictEqual(pypi.osvPackageName(r), "requests");
});
test("pypi collect: requirements.txt fallback warns + scans pins only", async () => {
	const { deps, warnings } = await pypi.collect(F("python-reqs"), {});
	assert.ok(deps.has("pypi:fastapi"));
	assert.ok(!deps.has("pypi:flask"));
	assert.ok(warnings.find(w => w.type === "no-lockfile"));
});
```
Also update the registry-count assertion in `test/codecs.test.js`:
`assert.deepStrictEqual(ids, ["composer", "maven", "npm", "pypi", "yarn"]);`

- [ ] **Step 2: Lancer (échec attendu)**.

- [ ] **Step 3a: Codec**

```js
// lib/codecs/pypi.codec.js
const fs = require("fs");
const path = require("path");
const { makeDepRecord, coordKeyFor } = require("../dep-record");
const P = require("../python/parse");

const SKIP = new Set([".git", ".idea", ".vscode", "node_modules", "dist", "build", "out", "target", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache"]);
// Lock precedence within a directory; if none, requirements.txt fallback.
const LOCKS = [
	["poetry.lock", P.parsePoetryLock],
	["Pipfile.lock", P.parsePipfileLock],
	["uv.lock", P.parseUvLock],
	["pdm.lock", P.parsePdmLock],
];

function findPyDirs(dir) {
	const groups = [];
	const stack = [dir];
	while (stack.length) {
		const cur = stack.pop();
		let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
		const names = new Set(entries.filter(e => e.isFile()).map(e => e.name));
		if ([...LOCKS.map(l => l[0]), "requirements.txt"].some(n => names.has(n))) groups.push({ dir: cur, names });
		for (const e of entries) if (e.isDirectory() && !SKIP.has(e.name)) stack.push(path.join(cur, e.name));
	}
	return groups;
}

module.exports = {
	id: "pypi",
	label: "PyPI",
	osvEcosystem: "PyPI",
	manifestNames: ["poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock", "requirements.txt"],

	detect(dir) { return findPyDirs(dir).length > 0; },

	async collect(dir, opts = {}) {
		const { ignoreTest, deps2Exclude } = opts;
		const out = new Map();
		const warnings = [];
		const add = (d, manifestPath) => {
			if (ignoreTest && d.isDev) return;
			if (deps2Exclude && deps2Exclude.test(d.name)) return;
			out.set(coordKeyFor("pypi", "", d.name), makeDepRecord({ ecosystem: "pypi", namespace: "", name: d.name, version: d.version, manifestPath, scope: d.scope, isDev: d.isDev }));
		};
		for (const g of findPyDirs(dir)) {
			const lock = LOCKS.find(([n]) => g.names.has(n));
			if (lock) {
				const { deps } = lock[1](path.join(g.dir, lock[0]));
				for (const d of deps) add(d, path.join(g.dir, lock[0]));
			} else if (g.names.has("requirements.txt")) {
				const fp = path.join(g.dir, "requirements.txt");
				const { deps, skipped } = P.parseRequirementsTxt(fp);
				for (const d of deps) add(d, fp);
				warnings.push({ type: "no-lockfile", manifestPath: fp, message: `requirements.txt (no lockfile) — best-effort: ${deps.length} pinned, ${skipped} range(s) skipped` });
			}
		}
		return { deps: out, warnings };
	},

	coordKey(d) { return coordKeyFor("pypi", "", d.name); },
	formatCoord(d) { return d.name; },
	osvPackageName(d) { return d.name; },

	async checkRegistry(deps, opts = {}) {
		const { checkPypiRegistryDeps } = require("../python/registry");
		return checkPypiRegistryDeps(deps, opts);
	},
	resolveEolProduct(d) { return require("../outdated").findEolProduct(d); },
	recipe: require("./recipes").pypi,
	nativeScanners: [],
};
```

- [ ] **Step 3b: Register** — `index.js`: `const pypi = require("./pypi.codec");` and add to `[maven, npm, yarn, composer, pypi]`.

- [ ] **Step 3c: Recipe** — `recipes.js`:
```js
function pipInstallSnippet(items) { return items.map(it => `pip install '${it.artifactId}>=${esc(it.fixVersion)}'`).join("\n"); }
const pypi = { label: "PyPI", pinSection: "A. Upgrade the affected packages", pinIntro: cnt => `Upgrade the ${cnt} affected package${cnt > 1 ? "s" : ""} and re-lock:`, snippet: pipInstallSnippet, directSection: "B. Then regenerate your lockfile (poetry lock / pip freeze)" };
module.exports = { …, pypi, pipInstallSnippet };
```

- [ ] **Step 3d: EOL** — `outdated.js` findEolProduct, add before maven block:
```js
	if (dep.ecosystem === "pypi") return EOL_MAPPING.by_pypi_name?.[(dep.name || dep.artifactId || "").toLowerCase()] || null;
```

- [ ] **Step 3e: Mapping** — `eol-mapping.json` add:
```json
"by_pypi_name": {
  "django": { "product": "django", "label": "Django" },
  "numpy": { "product": "numpy", "label": "NumPy" },
  "fastapi": { "product": "fastapi", "label": "FastAPI" }
}
```

- [ ] **Step 4: Lancer la suite complète** — `npm test` → PASS (tous + pypi).
- [ ] **Step 5: Smoke test** — `node fad-checker.js -s ./test/fixtures/python-poetry --offline` → détecte pypi, collecte requests + flask-sqlalchemy, report OK.
- [ ] **Step 6: Commit** — `git add -A && git commit -m "pypi: codec + registry wiring + EOL + recipe"`

---

### Task 4: Docs + dépendance

**Files:** `CLAUDE.md`, `docs/ARCHITECTURE.md` (+ `package.json` déjà mis à jour par `npm install smol-toml --save`).

- [ ] **Step 1** : module maps + liste écosystèmes (ajouter Python/PyPI) ; mentionner `smol-toml` (dépendance TOML) ; fixtures `python-*`.
- [ ] **Step 2** : `npm test` puis commit `git add CLAUDE.md docs/ARCHITECTURE.md package.json package-lock.json && git commit -m "Docs + smol-toml dep: PyPI (Python) codec"`.

---

## Self-Review (effectuée)

- Vuln pypi → OSV `PyPI` (Plan A) ✓ ; 4 formats lock + requirements fallback → Task 1 ✓ ;
  yanked/inactive + outdated → PyPI Task 2 + boucle checkRegistry (Plan B, déjà câblée) ✓ ;
  EOL → findEolProduct + mapping Task 3 ✓ ; recette → 3c ✓ ; report/CLI → automatiques via le
  registre (Plan A) ✓.
- **PEP 503** appliqué à tous les noms (clé/OSV/registre) — `Flask-SQLAlchemy`→`flask-sqlalchemy`.
- **Aucune modif orchestrateur** : la boucle générique `codec.checkRegistry` (Plan B) couvre pypi.
- **Cohérence types** : checkRegistry → {deprecated[], outdated[]} ; deprecated {dep,severity,replacement,reason,source}.
