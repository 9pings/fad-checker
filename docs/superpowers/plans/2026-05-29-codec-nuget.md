# Plan D — Codec NuGet (C#/.NET) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Ajouter le codec `nuget` (C#/.NET) en parité — vuln (OSV NuGet), deprecation (NuGet registration), outdated (NuGet), EOL (dotnet/aspnet), recette — sur l'interface codec.

**Architecture:** `lib/nuget/parse.js` parse `packages.lock.json` (JSON), `*.csproj` + `Directory.Packages.props` (XML via xml2js), `packages.config` (XML). `lib/nuget/registry.js` interroge la registration NuGet (latest + deprecation). `lib/codecs/nuget.codec.js` assemble. OSV `NuGet` (Plan A) + boucle `checkRegistry` (Plan B) déjà câblés — aucune modif orchestrateur. Noms NuGet case-insensitive (clé en lower, casse d'origine pour l'affichage).

**Tech Stack:** Node.js, node --test, `xml2js` (déjà dépendance).

---

## File Structure

| Fichier | Rôle | Action |
|---|---|---|
| `lib/nuget/parse.js` | packages.lock.json + .csproj (+CPM) + packages.config | Créer |
| `lib/nuget/registry.js` | NuGet registration → latest + deprecation | Créer |
| `lib/codecs/nuget.codec.js` | codec nuget | Créer |
| `lib/codecs/index.js` | enregistrer nuget | Modifier |
| `lib/codecs/recipes.js` | recette nuget | Modifier |
| `lib/outdated.js` | findEolProduct → branche nuget | Modifier |
| `data/eol-mapping.json` | `by_nuget_name` (.NET, aspnet, EF) | Modifier |
| `test/fixtures/csharp-*/` | lock + csproj+CPM + packages.config | Créer |
| `test/nuget.test.js` | parsers + codec + CPM + case-insensitive | Créer |
| `CLAUDE.md`, `docs/ARCHITECTURE.md` | docs | Modifier |

**Invariant :** `npm test` reste vert à chaque tâche.

---

### Task 1: Parsers + fixtures

- [ ] **Step 1: Fixtures**

`test/fixtures/csharp-lock/packages.lock.json` :
```json
{ "version": 1, "dependencies": {
  "net6.0": {
    "Newtonsoft.Json": { "type": "Direct", "resolved": "13.0.1" },
    "Serilog": { "type": "Direct", "resolved": "2.12.0" },
    "System.Buffers": { "type": "Transitive", "resolved": "4.5.1" }
  } } }
```

`test/fixtures/csharp-csproj/app.csproj` :
```xml
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="Floating" Version="1.*" />
    <PackageReference Include="Managed" />
  </ItemGroup>
</Project>
```
`test/fixtures/csharp-csproj/Directory.Packages.props` :
```xml
<Project>
  <ItemGroup>
    <PackageVersion Include="Managed" Version="6.0.0" />
  </ItemGroup>
</Project>
```

`test/fixtures/csharp-config/packages.config` :
```xml
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="EntityFramework" version="6.4.4" targetFramework="net48" />
</packages>
```

- [ ] **Step 2: Test qui échoue** — `test/nuget.test.js`

```js
const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { parsePackagesLockJson, parseCsproj, parsePackagesConfig, parseDirectoryPackagesProps } = require("../lib/nuget/parse");
const F = n => path.join(__dirname, "fixtures", n);

test("parsePackagesLockJson reads resolved versions + Direct/Transitive scope", async () => {
	const r = await parsePackagesLockJson(F("csharp-lock/packages.lock.json"));
	const m = Object.fromEntries(r.deps.map(d => [d.name, d]));
	assert.strictEqual(m["Newtonsoft.Json"].version, "13.0.1");
	assert.strictEqual(m["System.Buffers"].scope, "transitive");
});

test("parseDirectoryPackagesProps returns a name→version map (CPM)", async () => {
	const m = await parseDirectoryPackagesProps(F("csharp-csproj/Directory.Packages.props"));
	assert.strictEqual(m["managed"], "6.0.0");   // keyed lowercase
});

test("parseCsproj: pinned scanned, floating skipped, CPM resolved against props", async () => {
	const cpm = await parseDirectoryPackagesProps(F("csharp-csproj/Directory.Packages.props"));
	const r = await parseCsproj(F("csharp-csproj/app.csproj"), cpm);
	const m = Object.fromEntries(r.deps.map(d => [d.name, d.version]));
	assert.strictEqual(m["Newtonsoft.Json"], "13.0.1");
	assert.strictEqual(m["Managed"], "6.0.0");      // resolved via CPM
	assert.ok(!("Floating" in m));                   // "1.*" skipped
	assert.strictEqual(r.skipped, 1);
});

test("parsePackagesConfig reads legacy id/version", async () => {
	const r = await parsePackagesConfig(F("csharp-config/packages.config"));
	assert.strictEqual(r.deps.find(d => d.name === "EntityFramework").version, "6.4.4");
});
```

- [ ] **Step 3: Lancer (échec attendu)**.

- [ ] **Step 4: Implémenter**

```js
// lib/nuget/parse.js
const fs = require("fs");
const xml2js = require("xml2js");

function isConcrete(v) { return /^\d+(\.\d+)*([.\-+]\S+)?$/.test(String(v || "")); }   // rejects 1.*, [1.0,2.0)

async function parsePackagesLockJson(filePath) {
	const json = JSON.parse(fs.readFileSync(filePath, "utf8"));
	const deps = [];
	const seen = new Set();
	for (const fw of Object.values(json.dependencies || {})) {
		for (const [name, meta] of Object.entries(fw || {})) {
			const version = meta.resolved || null;
			if (!version) continue;
			const key = `${name.toLowerCase()}@${version}`;
			if (seen.has(key)) continue; seen.add(key);
			const scope = (meta.type === "Transitive") ? "transitive" : "prod";
			deps.push({ name, version, scope, isDev: false });
		}
	}
	return { manifestPath: filePath, manifestType: "packages.lock.json", deps };
}

async function parseDirectoryPackagesProps(filePath) {
	const xml = await xml2js.parseStringPromise(fs.readFileSync(filePath, "utf8"));
	const map = {};
	for (const ig of xml.Project?.ItemGroup || []) {
		for (const pv of ig.PackageVersion || []) {
			const id = pv.$?.Include; const v = pv.$?.Version;
			if (id && v) map[id.toLowerCase()] = v;
		}
	}
	return map;
}

async function parseCsproj(filePath, cpm = {}) {
	const xml = await xml2js.parseStringPromise(fs.readFileSync(filePath, "utf8"));
	const deps = [];
	let skipped = 0;
	for (const ig of xml.Project?.ItemGroup || []) {
		for (const pr of ig.PackageReference || []) {
			const name = pr.$?.Include; if (!name) continue;
			// Version may be an attribute or a child element; if absent, use CPM.
			let version = pr.$?.Version || (Array.isArray(pr.Version) ? pr.Version[0] : null) || cpm[name.toLowerCase()] || null;
			if (version && isConcrete(version)) deps.push({ name, version, scope: "prod", isDev: false });
			else skipped++;
		}
	}
	return { manifestPath: filePath, manifestType: "csproj", deps, skipped };
}

async function parsePackagesConfig(filePath) {
	const xml = await xml2js.parseStringPromise(fs.readFileSync(filePath, "utf8"));
	const deps = [];
	for (const p of xml.packages?.package || []) {
		const name = p.$?.id; const version = p.$?.version;
		if (name && version && isConcrete(version)) deps.push({ name, version, scope: "prod", isDev: false });
	}
	return { manifestPath: filePath, manifestType: "packages.config", deps };
}

module.exports = { isConcrete, parsePackagesLockJson, parseDirectoryPackagesProps, parseCsproj, parsePackagesConfig };
```

- [ ] **Step 5: Lancer (succès)** → PASS (4). **Step 6: Commit** `nuget: parse packages.lock.json + csproj (CPM) + packages.config`.

---

### Task 2: Registre NuGet (latest + deprecation)

- [ ] **Step 1: Test qui échoue**

```js
// ajout test/nuget.test.js
const { nugetRegistrationToFindings } = require("../lib/nuget/registry");
test("nugetRegistrationToFindings extracts latest stable + deprecation for version", () => {
	const reg = { items: [ { items: [
		{ catalogEntry: { version: "13.0.1", deprecation: { reasons: ["Legacy"], alternatePackage: { id: "NewPkg" } } } },
		{ catalogEntry: { version: "13.0.3" } },
		{ catalogEntry: { version: "14.0.0-preview" } },
	] } ] };
	const f = nugetRegistrationToFindings(reg, { version: "13.0.1" });
	assert.strictEqual(f.outdated.latest, "13.0.3");                 // preview ignored
	assert.deepStrictEqual(f.deprecated, { reason: "Legacy", replacement: "NewPkg" });
	const f2 = nugetRegistrationToFindings(reg, { version: "13.0.3" });
	assert.strictEqual(f2.deprecated, null);
	assert.strictEqual(f2.outdated, null);
});
```

- [ ] **Step 2: Lancer (échec attendu)**.

- [ ] **Step 3: Implémenter**

```js
// lib/nuget/registry.js
const fs = require("fs");
const path = require("path");
const os = require("os");
let pLimit; try { pLimit = require("p-limit"); } catch { pLimit = () => (fn) => fn(); }

const CACHE_DIR = path.join(os.homedir(), ".fad-checker");
const CACHE_PATH = path.join(CACHE_DIR, "nuget-cache.json");
const CACHE_MAX_AGE_MS = 24 * 3600 * 1000;
const REG = "https://api.nuget.org/v3/registration5-gz-semver2";

function loadCache() { try { return JSON.parse(fs.readFileSync(CACHE_PATH, "utf8")); } catch { return { entries: {}, meta: {} }; } }
function saveCache(d) { try { fs.mkdirSync(CACHE_DIR, { recursive: true }); fs.writeFileSync(CACHE_PATH, JSON.stringify(d)); } catch { /* ignore */ } }
function isStable(v) { return /^\d+(\.\d+)*$/.test(String(v || "")); }
function cmp(a, b) { const pa = String(a).split(/[.\-+]/).map(n => parseInt(n, 10) || 0); const pb = String(b).split(/[.\-+]/).map(n => parseInt(n, 10) || 0); for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d > 0 ? 1 : -1; } return 0; }

// Walk a registration index (inline items) → {outdated, deprecated}.
function nugetRegistrationToFindings(reg, { version }) {
	const entries = [];
	for (const page of reg.items || []) for (const leaf of page.items || []) if (leaf.catalogEntry) entries.push(leaf.catalogEntry);
	const out = { outdated: null, deprecated: null };
	const stable = entries.map(e => e.version).filter(isStable);
	if (stable.length) { const latest = stable.sort(cmp).at(-1); if (latest && cmp(latest, version) > 0) out.outdated = { latest }; }
	const mine = entries.find(e => String(e.version) === String(version));
	if (mine?.deprecation) out.deprecated = { reason: (mine.deprecation.reasons || []).join(", ") || "deprecated", replacement: mine.deprecation.alternatePackage?.id || null };
	return out;
}

async function fetchRegistration(name, { offline }) {
	if (offline) return null;
	try {
		const res = await fetch(`${REG}/${name.toLowerCase()}/index.json`, { headers: { "User-Agent": "fad-checker-nuget" } });
		if (!res.ok) return { error: `HTTP ${res.status}` };
		return await res.json();
	} catch (e) { return { error: e.message }; }
}

async function checkNugetRegistryDeps(deps, opts = {}) {
	const { verbose, offline, allLibs = true, concurrency = 8 } = opts;
	const targets = [...deps.values()].filter(d => d.ecosystem === "nuget" && d.version);
	const result = { deprecated: [], outdated: [] };
	if (!targets.length) return result;
	const cache = loadCache();
	const fresh = cache.meta?.fetchedAt && (Date.now() - cache.meta.fetchedAt) < CACHE_MAX_AGE_MS;
	if (!fresh && !offline) cache.entries = {};
	const limit = pLimit(concurrency);
	await Promise.all(targets.map(t => limit(async () => {
		const key = `${t.name.toLowerCase()}@${t.version}`;
		let ex = cache.entries[key];
		if (!ex) {
			const reg = await fetchRegistration(t.name, { offline });
			if (reg && !reg.error) { const f = nugetRegistrationToFindings(reg, { version: t.version }); ex = { deprecated: f.deprecated, latest: f.outdated?.latest || null }; cache.entries[key] = ex; }
			else ex = { deprecated: null, latest: null };
		}
		if (ex.deprecated) result.deprecated.push({ dep: t, severity: "MEDIUM", replacement: ex.deprecated.replacement, reason: ex.deprecated.reason, source: "nuget" });
		if (allLibs && ex.latest) result.outdated.push({ dep: t, latest: ex.latest, releaseDate: null });
	})));
	cache.meta = { fetchedAt: Date.now() }; saveCache(cache);
	return result;
}

module.exports = { nugetRegistrationToFindings, checkNugetRegistryDeps };
```

- [ ] **Step 4: Lancer (succès)** → PASS (5). **Step 5: Commit** `nuget: registration registry (latest + deprecation)`.

---

### Task 3: Codec nuget + register + recipe + EOL

- [ ] **Step 1: Test qui échoue**

```js
// ajout test/nuget.test.js
const nuget = require("../lib/codecs/nuget.codec");
const { assertCodecShape } = require("../lib/codecs/codec.interface");
test("nuget codec: shape, detect, collect lockfile, case-insensitive key", async () => {
	assertCodecShape(nuget);
	assert.strictEqual(nuget.detect(F("csharp-lock")), true);
	const { deps } = await nuget.collect(F("csharp-lock"), {});
	const j = deps.get("nuget:newtonsoft.json");     // key lowercased
	assert.ok(j);
	assert.strictEqual(j.name, "Newtonsoft.Json");   // display keeps original case
	assert.strictEqual(nuget.osvPackageName(j), "Newtonsoft.Json");
});
test("nuget codec: csproj uses CPM + skips floating with warning", async () => {
	const { deps, warnings } = await nuget.collect(F("csharp-csproj"), {});
	assert.ok(deps.has("nuget:newtonsoft.json"));
	assert.ok(deps.has("nuget:managed"));            // resolved via Directory.Packages.props
	assert.ok(!deps.has("nuget:floating"));
	assert.ok(warnings.find(w => w.type === "unresolved-versions" || w.type === "no-lockfile"));
});
```
Update `test/codecs.test.js` registry id list → `["composer","maven","npm","nuget","pypi","yarn"]`.

- [ ] **Step 2: Lancer (échec attendu)**.

- [ ] **Step 3a: Codec**

```js
// lib/codecs/nuget.codec.js
const fs = require("fs");
const path = require("path");
const { makeDepRecord, coordKeyFor } = require("../dep-record");
const N = require("../nuget/parse");

const SKIP = new Set([".git", ".idea", ".vscode", "node_modules", "dist", "build", "out", "bin", "obj", "target", "packages"]);

function findNugetDirs(dir) {
	const groups = [];
	const stack = [dir];
	while (stack.length) {
		const cur = stack.pop();
		let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
		const files = entries.filter(e => e.isFile()).map(e => e.name);
		const csprojs = files.filter(f => f.toLowerCase().endsWith(".csproj"));
		const has = files.includes("packages.lock.json") || files.includes("packages.config") || csprojs.length;
		if (has) groups.push({ dir: cur, files, csprojs });
		for (const e of entries) if (e.isDirectory() && !SKIP.has(e.name)) stack.push(path.join(cur, e.name));
	}
	return groups;
}

module.exports = {
	id: "nuget",
	label: "NuGet",
	osvEcosystem: "NuGet",
	manifestNames: ["packages.lock.json", "*.csproj", "packages.config"],

	detect(dir) { return findNugetDirs(dir).length > 0; },

	async collect(dir, opts = {}) {
		const { ignoreTest, deps2Exclude } = opts;
		const out = new Map();
		const warnings = [];
		const add = (d, manifestPath) => {
			if (deps2Exclude && deps2Exclude.test(d.name)) return;
			out.set(coordKeyFor("nuget", "", d.name), makeDepRecord({ ecosystem: "nuget", namespace: "", name: d.name, version: d.version, manifestPath, scope: d.scope, isDev: d.isDev }));
		};
		for (const g of findNugetDirs(dir)) {
			if (g.files.includes("packages.lock.json")) {
				const fp = path.join(g.dir, "packages.lock.json");
				const { deps } = await N.parsePackagesLockJson(fp);
				for (const d of deps) add(d, fp);
				continue;   // lock is authoritative for this dir
			}
			// No lock → best-effort from csproj (+CPM) and packages.config, with warning.
			let cpm = {};
			if (g.files.includes("Directory.Packages.props")) {
				try { cpm = await N.parseDirectoryPackagesProps(path.join(g.dir, "Directory.Packages.props")); } catch { /* ignore */ }
			}
			let pinned = 0, skipped = 0;
			for (const cs of g.csprojs) {
				const fp = path.join(g.dir, cs);
				const { deps, skipped: sk } = await N.parseCsproj(fp, cpm);
				for (const d of deps) { add(d, fp); pinned++; }
				skipped += sk;
			}
			if (g.files.includes("packages.config")) {
				const fp = path.join(g.dir, "packages.config");
				const { deps } = await N.parsePackagesConfig(fp);
				for (const d of deps) { add(d, fp); pinned++; }
			}
			if (g.csprojs.length || g.files.includes("packages.config")) {
				warnings.push({ type: "no-lockfile", manifestPath: g.dir, message: `no packages.lock.json — best-effort: ${pinned} pinned, ${skipped} floating/unresolved skipped (enable RestorePackagesWithLockFile)` });
			}
		}
		return { deps: out, warnings };
	},

	coordKey(d) { return coordKeyFor("nuget", "", d.name); },
	formatCoord(d) { return d.name; },
	osvPackageName(d) { return d.name; },

	async checkRegistry(deps, opts = {}) {
		const { checkNugetRegistryDeps } = require("../nuget/registry");
		return checkNugetRegistryDeps(deps, opts);
	},
	resolveEolProduct(d) { return require("../outdated").findEolProduct(d); },
	recipe: require("./recipes").nuget,
	nativeScanners: [],
};
```

- [ ] **Step 3b: Register** — `index.js`: add `nuget` to imports + `[…, pypi, nuget]`.
- [ ] **Step 3c: Recipe** — `recipes.js`:
```js
function dotnetAddSnippet(items) { return items.map(it => `dotnet add package ${it.artifactId} --version ${esc(it.fixVersion)}`).join("\n"); }
const nuget = { label: "NuGet", pinSection: "A. Update the affected packages", pinIntro: cnt => `Run for the ${cnt} affected package${cnt > 1 ? "s" : ""} (or bump Directory.Packages.props under CPM):`, snippet: dotnetAddSnippet, directSection: "B. Then restore + commit packages.lock.json" };
module.exports = { …, nuget, dotnetAddSnippet };
```
- [ ] **Step 3d: EOL** — `outdated.js` findEolProduct, add before maven block:
```js
	if (dep.ecosystem === "nuget") return EOL_MAPPING.by_nuget_name?.[(dep.name || dep.artifactId || "").toLowerCase()] || null;
```
- [ ] **Step 3e: Mapping** — `eol-mapping.json` add:
```json
"by_nuget_name": {
  "microsoft.aspnetcore.app": { "product": "aspnetcore", "label": "ASP.NET Core" },
  "microsoft.entityframeworkcore": { "product": "efcore", "label": "EF Core" },
  "microsoft.net.sdk": { "product": "dotnet", "label": ".NET" }
}
```

- [ ] **Step 4: `npm test`** → PASS. **Step 5: Smoke** `node fad-checker.js -s ./test/fixtures/csharp-lock --offline`. **Step 6: Commit** `nuget: codec + registry wiring + EOL + recipe`.

---

### Task 4: Docs

- [ ] module maps (+`lib/nuget/*`, `nuget.codec.js`) + liste écosystèmes (ajouter C#/.NET) + fixtures `csharp-*`. `npm test` + commit.

---

## Self-Review (effectuée)

- Vuln nuget → OSV `NuGet` (Plan A) ✓ ; packages.lock.json + csproj(+CPM) + packages.config → Task 1 ✓ ;
  deprecation + outdated → NuGet Task 2 + boucle checkRegistry (Plan B) ✓ ; EOL → Task 3 ✓ ; recette → 3c ✓ ;
  report/CLI → automatiques via le registre ✓.
- **CPM** : `Directory.Packages.props` lu comme table ; `PackageReference` sans Version résolu contre elle,
  sinon compté en skipped + warning.
- **Case-insensitive** : clé `nuget:<lower>` (dep-record), `name` garde la casse d'origine pour l'affichage/OSV.
- **Cohérence types** : checkRegistry → {deprecated[], outdated[]}.
