# Custom Registries + Layered Config — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Extend fad-checker's Maven-only private-repo support to npm/PyPI/Ruby/Go, and add layered configuration (`./.fad-env.json` / `--config` JSON + `FAD_CHECKER_ENV` CLI-flag string), with precedence CLI > config-file > env > global-config > defaults.

**Architecture:** A new `lib/registries.js` owns the per-ecosystem registry list (union across config layers, public registry appended last, Basic/Bearer auth). `lib/config.js` stores a `registries` map (no legacy `maven_repos`). A new `lib/options-env.js` resolves the config layers and merges them into commander options using `getOptionValueSource`. Each codec registry fetcher (`npm/pypi/ruby/go`) gains an `opts.registries` list and tries it before the public base. `fad-checker.js` rewires `--add-repo`/`--repo`/`--list-repos`/`--remove-repo`, adds `--source`/`--config`, and applies the layers.

**Tech Stack:** Node ≥20, commander, node:test, `fetch`.

**No backward compat:** `maven_repos` key and 2-arg `--add-repo` are removed.

---

## File structure

- Create `lib/registries.js` — ecosystem list, `SUPPORTED`, `PUBLIC_BASES`, `buildRegistryList`, `authHeaderFor`, `fetchFirstOk`, `mergeRegistryMaps`.
- Create `lib/options-env.js` — `loadConfigFile`, `parseEnvFlags`, `loadLayers`, `applyLayers`, `normalizeSource`.
- Modify `lib/config.js` — drop `*MavenRepo*`/`getMavenRepos`; add `getRegistryMap`/`getRegistries`/`addRegistry`/`removeRegistry`.
- Modify `lib/maven-repo.js` — `buildRepoList` reads from a maven registry list (callers pass `registries.maven`); behaviour otherwise unchanged.
- Modify `lib/codecs/npm/registry.js`, `lib/codecs/pypi/registry.js`, `lib/codecs/ruby/registry.js`, `lib/codecs/go/registry.js` — accept `opts.registries`, try them before the public base.
- Modify `fad-checker.js` — CLI options + pre-parse repo commands + layer application + per-eco registry lists threaded into passes.
- Create tests: `test/registries.test.js`, `test/options-env.test.js`, `test/codec-registries.test.js`, `test/cli-repos.test.js`.
- Docs (separate final task): `README.md`, `docs/index.html`, `docs/USAGE.md`, `CLAUDE.md`, `CHANGELOG.md`, assets.

---

## Task 1: `lib/registries.js` core

**Files:** Create `lib/registries.js`; Test `test/registries.test.js`

- [ ] **Step 1: Write the failing test**

```js
const { test } = require("node:test");
const assert = require("node:assert");
const R = require("../lib/registries");

test("SUPPORTED lists the five ecosystems", () => {
	assert.deepStrictEqual(R.SUPPORTED.sort(), ["go", "maven", "npm", "pypi", "ruby"]);
});

test("authHeaderFor: token → Bearer, auth → Basic, none → null", () => {
	assert.strictEqual(R.authHeaderFor({ token: "abc" }), "Bearer abc");
	assert.strictEqual(R.authHeaderFor({ auth: "u:p" }), "Basic " + Buffer.from("u:p").toString("base64"));
	assert.strictEqual(R.authHeaderFor({}), null);
});

test("buildRegistryList: unions layers, dedups by URL, splits inline auth, public NOT appended", () => {
	const list = R.buildRegistryList("npm", [
		[{ name: "a", url: "https://r1/" }],
		[{ name: "b", url: "https://u:p@r2" }, { name: "dup", url: "https://r1" }],
	]);
	assert.strictEqual(list.length, 2);
	assert.strictEqual(list[0].url, "https://r1/");
	assert.strictEqual(list[1].url, "https://r2/");
	assert.strictEqual(list[1].auth, "u:p");
});

test("withPublic appends the ecosystem public base last", () => {
	const bases = R.withPublic("npm", [{ name: "a", url: "https://r1/" }]);
	assert.strictEqual(bases.length, 2);
	assert.strictEqual(bases[1].url, R.PUBLIC_BASES.npm);
	assert.strictEqual(bases[1].name, "public");
});
```

- [ ] **Step 2: Run, expect FAIL** — `node --test test/registries.test.js` → "Cannot find module".

- [ ] **Step 3: Implement `lib/registries.js`**

```js
/**
 * lib/registries.js — per-ecosystem registry list assembly + auth + fan-out.
 *
 * Generalizes lib/maven-repo.js's list-building to npm/pypi/ruby/go. Custom
 * registries are tried first (declared order); callers append the public base
 * last via withPublic(). Lists are unioned across config layers, deduped by URL.
 *
 * Entry shape: { name?, url, auth?, token? }
 *   auth  "user:pass" → Authorization: Basic <base64>
 *   token "…"         → Authorization: Bearer <token>
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const SUPPORTED = ["maven", "npm", "pypi", "ruby", "go"];

const PUBLIC_BASES = {
	maven: "https://repo1.maven.org/maven2/",
	npm: "https://registry.npmjs.org/",
	pypi: "https://pypi.org/pypi/",
	ruby: "https://rubygems.org/api/v1/gems/",
	go: "https://proxy.golang.org/",
};

function normalise(url) {
	if (!url) return url;
	return url.endsWith("/") ? url : url + "/";
}

function splitUrlAuth(url) {
	if (!url) return { url, auth: null };
	try {
		const u = new URL(url);
		if (u.username || u.password) {
			const auth = decodeURIComponent(u.username) + ":" + decodeURIComponent(u.password);
			u.username = ""; u.password = "";
			return { url: u.toString(), auth };
		}
	} catch { /* not a URL */ }
	return { url, auth: null };
}

function authHeaderFor(entry) {
	if (!entry) return null;
	if (entry.token) return "Bearer " + entry.token;
	if (entry.auth) return "Basic " + Buffer.from(entry.auth).toString("base64");
	return null;
}

/** Union of registry entries from several layers (arrays). Dedup by URL, first wins. */
function buildRegistryList(_ecosystem, layers = []) {
	const out = [];
	const seen = new Set();
	for (const layer of layers) {
		for (const r of layer || []) {
			if (!r?.url) continue;
			const { url, auth } = splitUrlAuth(normalise(r.url));
			if (seen.has(url)) continue;
			seen.add(url);
			out.push({ name: r.name || url, url, auth: r.auth || auth || null, token: r.token || null });
		}
	}
	return out;
}

/** Append the ecosystem's public base (no auth) as the final fallback. */
function withPublic(ecosystem, list) {
	const pub = PUBLIC_BASES[ecosystem];
	const out = [...(list || [])];
	if (pub && !out.some(r => normalise(r.url) === pub)) out.push({ name: "public", url: pub, auth: null, token: null });
	return out;
}

/** Merge two registry maps (eco → entries[]) into one (concat per eco). */
function mergeRegistryMaps(...maps) {
	const out = {};
	for (const m of maps) {
		if (!m || typeof m !== "object") continue;
		for (const eco of Object.keys(m)) {
			if (!Array.isArray(m[eco])) continue;
			out[eco] = (out[eco] || []).concat(m[eco]);
		}
	}
	return out;
}

/**
 * Try each base in order; return the first response whose `res.ok` is true,
 * as { res, base, url }. Applies per-base auth. opts.fetcher for tests.
 */
async function fetchFirstOk(bases, buildUrl, opts = {}) {
	const { fetcher = globalThis.fetch, userAgent = "fad-checker", timeoutMs, onMiss } = opts;
	for (const base of bases) {
		const url = buildUrl(normalise(base.url));
		const headers = { "User-Agent": userAgent, Accept: "application/json" };
		const ah = authHeaderFor(base);
		if (ah) headers.Authorization = ah;
		let res;
		try {
			res = await fetcher(url, { headers, ...(timeoutMs ? { signal: AbortSignal.timeout(timeoutMs) } : {}) });
		} catch (err) { if (onMiss) onMiss(base, `network: ${err.message}`); continue; }
		if (res.ok) return { res, base, url };
		if (onMiss) onMiss(base, `HTTP ${res.status}`);
	}
	return null;
}

module.exports = {
	SUPPORTED, PUBLIC_BASES,
	normalise, splitUrlAuth, authHeaderFor,
	buildRegistryList, withPublic, mergeRegistryMaps, fetchFirstOk,
};
```

- [ ] **Step 4: Run, expect PASS** — `node --test test/registries.test.js`.

- [ ] **Step 5: Commit** — `git add lib/registries.js test/registries.test.js && git commit -m "feat(registries): per-ecosystem registry list + auth + fan-out helper"`

---

## Task 2: `lib/config.js` — registries store (drop maven_repos)

**Files:** Modify `lib/config.js`; Test `test/registries.test.js` (extend)

- [ ] **Step 1: Add failing test** (append to `test/registries.test.js`)

```js
const os = require("os"); const fs = require("fs"); const path = require("path");
test("config registries CRUD round-trips via a temp HOME", () => {
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-cfg-"));
	const prev = os.homedir; os.homedir = () => tmp;
	delete require.cache[require.resolve("../lib/config")];
	const config = require("../lib/config");
	try {
		config.addRegistry("npm", "verda", "https://npm.acme/", { token: "t" });
		config.addRegistry("maven", "nexus", "https://nexus.acme/m2/", { auth: "u:p" });
		assert.strictEqual(config.getRegistries("npm")[0].token, "t");
		assert.strictEqual(config.getRegistryMap().maven[0].auth, "u:p");
		assert.strictEqual(config.removeRegistry("npm", "verda"), true);
		assert.strictEqual(config.getRegistries("npm").length, 0);
	} finally { os.homedir = prev; delete require.cache[require.resolve("../lib/config")]; fs.rmSync(tmp, { recursive: true, force: true }); }
});
```

- [ ] **Step 2: Run, expect FAIL** — `config.addRegistry is not a function`.

- [ ] **Step 3: Edit `lib/config.js`** — replace the `getMavenRepos`/`setMavenRepos`/`addMavenRepo`/`removeMavenRepo` block (lines ~46-76) with:

```js
/**
 * Per-ecosystem custom registries (Nexus/Artifactory/Verdaccio/devpi/…).
 * Stored under config key `registries`: { <ecosystem>: [{name,url,auth?,token?}] }.
 * Public registries are NOT stored here — callers append them as the fallback.
 */
function getRegistryMap() {
	const m = get("registries");
	return (m && typeof m === "object" && !Array.isArray(m)) ? m : {};
}

function getRegistries(ecosystem) {
	const list = getRegistryMap()[ecosystem];
	return Array.isArray(list) ? list : [];
}

function setRegistryMap(map) {
	return set("registries", map && Object.keys(map).length ? map : null);
}

function addRegistry(ecosystem, name, url, { auth = null, token = null } = {}) {
	const map = getRegistryMap();
	const list = (map[ecosystem] || []).filter(r => r.name !== name);
	list.push({ name, url, ...(auth ? { auth } : {}), ...(token ? { token } : {}) });
	map[ecosystem] = list;
	setRegistryMap(map);
	return list;
}

function removeRegistry(ecosystem, name) {
	const map = getRegistryMap();
	const before = (map[ecosystem] || []).length;
	map[ecosystem] = (map[ecosystem] || []).filter(r => r.name !== name);
	if (!map[ecosystem].length) delete map[ecosystem];
	setRegistryMap(map);
	return before !== (map[ecosystem]?.length || 0);
}
```

Update `module.exports` to drop `getMavenRepos,setMavenRepos,addMavenRepo,removeMavenRepo` and add `getRegistryMap,getRegistries,setRegistryMap,addRegistry,removeRegistry`.

- [ ] **Step 4: Run, expect PASS** — `node --test test/registries.test.js`.

- [ ] **Step 5: Commit** — `git commit -am "feat(config): per-ecosystem registries store, drop maven_repos"`

---

## Task 3: `lib/maven-repo.js` reads `registries.maven`

**Files:** Modify `lib/maven-repo.js`; Test `test/maven-repo.test.js` (if exists) else inline in registries test.

- [ ] **Step 1: Add failing test** in `test/registries.test.js`:

```js
const { buildRepoList } = require("../lib/maven-repo");
test("maven buildRepoList still appends Central last and dedups", () => {
	const repos = buildRepoList([{ name: "nexus", url: "https://nexus/m2" }], [{ url: "https://nexus/m2" }]);
	assert.strictEqual(repos[repos.length - 1].name, "central");
	// nexus appears once despite being in both lists
	assert.strictEqual(repos.filter(r => r.name === "nexus").length, 1);
});
```

- [ ] **Step 2: Run** — if it already passes (buildRepoList unchanged), good; the only change is the *caller* in fad-checker.js (Task 7) now passes `config.getRegistries("maven")` instead of `getMavenRepos()`. No code change needed here beyond confirming. Mark step done.

- [ ] **Step 3: (no-op edit)** — confirm `buildRepoList` signature unchanged. Skip.

- [ ] **Step 4: Run, expect PASS**.

- [ ] **Step 5: Commit** (only if test added) — `git commit -am "test(maven-repo): confirm Central-last after registries refactor"`

---

## Task 4: `lib/options-env.js`

**Files:** Create `lib/options-env.js`; Test `test/options-env.test.js`

- [ ] **Step 1: Write failing test**

```js
const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("fs"); const os = require("os"); const path = require("path");
const { Command } = require("commander");
const OE = require("../lib/options-env");

function makeProgram() {
	const p = new Command();
	p.option("-s, --src <s>").option("--source <s>").option("-e, --exclude <e>")
	 .option("--fail-on <l>").option("--no-nuget").option("--repo <r...>");
	return p;
}

test("parseEnvFlags tokenizes quotes and returns only set options", () => {
	const p = makeProgram();
	const { options, repos } = OE.parseEnvFlags(`--fail-on high --exclude "^a b\\.c" --repo npm=https://r/`, p);
	assert.strictEqual(options.failOn, "high");
	assert.strictEqual(options.exclude, "^a b.c");
	assert.deepStrictEqual(repos, ["npm=https://r/"]);
	assert.strictEqual("nuget" in options, false); // not set → absent
});

test("applyLayers: CLI wins over file wins over env wins over global", () => {
	const p = makeProgram();
	p.parse(["node", "x", "--fail-on", "critical"]); // CLI sets failOn
	const eff = OE.applyLayers(p, {
		fileLayer: { failOn: "high", exclude: "^file" },
		envLayer: { exclude: "^env", src: "envsrc" },
	}, { /* global */ });
	assert.strictEqual(eff.failOn, "critical"); // CLI
	assert.strictEqual(eff.exclude, "^file");   // file beats env
	assert.strictEqual(eff.src, "envsrc");      // env fills unset
});

test("normalizeSource maps source/JSON-source to src", () => {
	assert.strictEqual(OE.normalizeSource({ source: "x" }).src, "x");
	assert.strictEqual(OE.normalizeSource({ src: "y", source: "z" }).src, "y"); // src wins
});

test("loadConfigFile: --config path beats ./.fad-env.json; malformed JSON throws", () => {
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-env-"));
	fs.writeFileSync(path.join(tmp, ".fad-env.json"), JSON.stringify({ failOn: "low" }));
	fs.writeFileSync(path.join(tmp, "alt.json"), JSON.stringify({ failOn: "high" }));
	assert.strictEqual(OE.loadLayers({ cwd: tmp }).fileLayer.failOn, "low");
	assert.strictEqual(OE.loadLayers({ cwd: tmp, configPath: path.join(tmp, "alt.json") }).fileLayer.failOn, "high");
	fs.writeFileSync(path.join(tmp, "bad.json"), "{ not json");
	assert.throws(() => OE.loadLayers({ cwd: tmp, configPath: path.join(tmp, "bad.json") }), /JSON|parse/i);
	fs.rmSync(tmp, { recursive: true, force: true });
});
```

- [ ] **Step 2: Run, expect FAIL** — module missing.

- [ ] **Step 3: Implement `lib/options-env.js`**

```js
/**
 * lib/options-env.js — layered option resolution.
 *
 * Layers (highest → lowest): CLI flags > config file (--config / ./.fad-env.json,
 * JSON) > FAD_CHECKER_ENV (a CLI-flag string) > global ~/.fad-checker/config.json
 * > commander defaults. Scalar options follow precedence; `registries` are unioned
 * elsewhere (lib/registries.js). The source flag has aliases (src/source).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const { Command } = require("commander");

/** Quote/escape-aware shell-ish tokenizer (single+double quotes, backslash). */
function tokenize(str) {
	const out = [];
	let cur = "", q = null, esc = false, has = false;
	for (const ch of String(str)) {
		if (esc) { cur += ch; esc = false; has = true; continue; }
		if (ch === "\\" && q !== "'") { esc = true; continue; }
		if (q) { if (ch === q) q = null; else cur += ch; has = true; continue; }
		if (ch === '"' || ch === "'") { q = ch; has = true; continue; }
		if (/\s/.test(ch)) { if (has) { out.push(cur); cur = ""; has = false; } continue; }
		cur += ch; has = true;
	}
	if (has) out.push(cur);
	return out;
}

function loadConfigFile(p) {
	const raw = fs.readFileSync(p, "utf8");
	try { return JSON.parse(raw); }
	catch (e) { throw new Error(`invalid JSON in config file ${p}: ${e.message}`); }
}

/** Map `source` → `src` (src wins if both present). Returns a NEW object. */
function normalizeSource(obj) {
	const o = { ...obj };
	if (o.source != null && o.src == null) o.src = o.source;
	delete o.source;
	return o;
}

/**
 * Parse a CLI-flag string into { options, repos } using a throwaway clone of the
 * real program. Only options whose source !== "default" are returned, so unset
 * flags don't clobber higher layers. `repos` (variadic --repo) returned separately.
 */
function parseEnvFlags(str, program) {
	const tokens = tokenize(str);
	if (!tokens.length) return { options: {}, repos: [] };
	const clone = new Command();
	clone.exitOverride().allowUnknownOption(true).configureOutput({ writeErr() {}, writeOut() {} });
	for (const o of program.options) clone.addOption(o);
	try { clone.parse(tokens, { from: "user" }); } catch { /* tolerate */ }
	const all = clone.opts();
	const options = {};
	for (const name of Object.keys(all)) {
		if (clone.getOptionValueSource(name) && clone.getOptionValueSource(name) !== "default") options[name] = all[name];
	}
	const repos = Array.isArray(options.repo) ? options.repo : [];
	delete options.repo;
	return { options: normalizeSource(options), repos };
}

/** Resolve { fileLayer, envLayer, envRepos }. */
function loadLayers({ cwd = process.cwd(), configPath = null, envStr = process.env.FAD_CHECKER_ENV, program = null } = {}) {
	let fileLayer = {};
	const chosen = configPath || path.join(cwd, ".fad-env.json");
	if (configPath) fileLayer = loadConfigFile(chosen);
	else if (fs.existsSync(chosen)) fileLayer = loadConfigFile(chosen);
	fileLayer = normalizeSource(fileLayer || {});
	let envLayer = {}, envRepos = [];
	if (envStr && program) {
		// If FAD_CHECKER_ENV points to a readable file, treat its content as flags too.
		let s = envStr;
		try { if (fs.existsSync(envStr) && fs.statSync(envStr).isFile()) s = fs.readFileSync(envStr, "utf8"); } catch { /* inline */ }
		const parsed = parseEnvFlags(s, program);
		envLayer = parsed.options; envRepos = parsed.repos;
	}
	return { fileLayer, envLayer, envRepos };
}

/**
 * Merge layers onto the parsed program. A file/env value fills an option ONLY
 * when the CLI did not set it (source default/undefined). Order: file > env >
 * global. Returns the effective options object (program.opts() mutated copy).
 */
function applyLayers(program, layers = {}, globalStore = {}) {
	const eff = normalizeSource(program.opts());
	const fileLayer = normalizeSource(layers.fileLayer || {});
	const envLayer = normalizeSource(layers.envLayer || {});
	const cliSet = name => {
		const s = program.getOptionValueSource(name);
		return s && s !== "default";
	};
	const candidates = new Set([...Object.keys(fileLayer), ...Object.keys(envLayer), ...Object.keys(globalStore || {})]);
	candidates.delete("registries"); // unioned separately
	candidates.delete("source");
	for (const name of candidates) {
		if (cliSet(name)) continue; // CLI wins
		if (name in fileLayer) eff[name] = fileLayer[name];
		else if (name in envLayer) eff[name] = envLayer[name];
		else if (globalStore && name in globalStore) eff[name] = globalStore[name];
	}
	return eff;
}

module.exports = { tokenize, loadConfigFile, normalizeSource, parseEnvFlags, loadLayers, applyLayers };
```

- [ ] **Step 4: Run, expect PASS** — `node --test test/options-env.test.js`.

- [ ] **Step 5: Commit** — `git commit -am "feat(options-env): layered config (file JSON + FAD_CHECKER_ENV flags) resolution"`

---

## Task 5: npm/pypi/ruby/go fetchers accept `opts.registries`

**Files:** Modify `lib/codecs/npm/registry.js`, `lib/codecs/pypi/registry.js`, `lib/codecs/ruby/registry.js`, `lib/codecs/go/registry.js`; Test `test/codec-registries.test.js`

- [ ] **Step 1: Write failing test** (`test/codec-registries.test.js`) — exercises the fetch-fallback via an injected fetcher for npm and pypi:

```js
const { test } = require("node:test");
const assert = require("node:assert");

test("npm fetchPackument tries custom registry first, falls back to public, sends auth", async () => {
	const { fetchPackument } = require("../lib/codecs/npm/registry");
	const seen = [];
	const fetcher = async (url, { headers }) => {
		seen.push({ url, auth: headers.Authorization || null });
		if (url.startsWith("https://priv/")) return { ok: false, status: 404 };
		return { ok: true, json: async () => ({ "dist-tags": { latest: "9.9.9" } }) };
	};
	const out = await fetchPackument("left-pad", {
		registries: [{ url: "https://priv/", token: "T" }],
		fetcher,
	});
	assert.strictEqual(out["dist-tags"].latest, "9.9.9");
	assert.strictEqual(seen[0].url, "https://priv/left-pad");
	assert.strictEqual(seen[0].auth, "Bearer T");
	assert.ok(seen[1].url.startsWith("https://registry.npmjs.org/"));
});

test("pypi fetchProject hits custom base then public", async () => {
	const { fetchProject } = require("../lib/codecs/pypi/registry");
	const seen = [];
	const fetcher = async (url) => { seen.push(url); return url.includes("priv") ? { ok: false, status: 500 } : { ok: true, json: async () => ({ info: { version: "2.0" } }) }; };
	const out = await fetchProject("flask", { registries: [{ url: "https://priv/pypi/" }], fetcher });
	assert.strictEqual(out.info.version, "2.0");
	assert.ok(seen[0].includes("priv"));
});
```

- [ ] **Step 2: Run, expect FAIL** — `fetchPackument`/`fetchProject` not exported / ignore registries.

- [ ] **Step 3a: Edit `lib/codecs/npm/registry.js`** — require registries helper and rewrite `fetchPackument` + thread `registries`:

```js
const { withPublic, authHeaderFor, normalise } = require("../../registries");
```
Replace `fetchPackument`:
```js
async function fetchPackument(name, opts = {}) {
	if (opts.offline) return null;
	const timeoutMs = opts.timeoutMs || 15000;
	const fetcher = opts.fetcher || globalThis.fetch;
	const bases = withPublic("npm", opts.registries || []);
	const enc = name.startsWith("@") ? name.replace("/", "%2F") : encodeURIComponent(name);
	let lastErr = null;
	for (const base of bases) {
		const url = normalise(base.url) + enc;
		const headers = { "User-Agent": "fad-checker-npm-registry", Accept: "application/json" };
		const ah = authHeaderFor(base);
		if (ah) headers.Authorization = ah;
		try {
			const res = await fetcher(url, { headers, signal: AbortSignal.timeout(timeoutMs) });
			if (res.ok) return await res.json();
			lastErr = `HTTP ${res.status}`;
		} catch (err) { lastErr = err.name === "TimeoutError" ? `timeout after ${timeoutMs}ms` : err.message; }
	}
	return { error: lastErr || "no data" };
}
```
In `checkNpmRegistryDeps`, read `const { registries = [] } = opts;` and pass `{ offline, registries }` into the `fetchPackument(npmName, …)` call. Remove the now-unused top-level `REGISTRY`/`packumentUrl` if no longer referenced (keep `packumentUrl` only if other code uses it — grep first; it is local, safe to delete). Export `fetchPackument`.

- [ ] **Step 3b: Edit `lib/codecs/pypi/registry.js`** — add `const { withPublic, authHeaderFor, normalise } = require("../../registries");` and rewrite `fetchProject`:

```js
async function fetchProject(name, { offline, registries = [], fetcher = globalThis.fetch } = {}) {
	if (offline) return null;
	const bases = withPublic("pypi", registries);
	let lastErr = null;
	for (const base of bases) {
		const url = normalise(base.url) + `${name}/json`;
		const headers = { "User-Agent": "fad-checker-pypi", Accept: "application/json" };
		const ah = authHeaderFor(base); if (ah) headers.Authorization = ah;
		try { const res = await fetcher(url, { headers }); if (res.ok) return await res.json(); lastErr = `HTTP ${res.status}`; }
		catch (e) { lastErr = e.message; }
	}
	return { error: lastErr || "no data" };
}
```
Thread `registries` from `checkPypiRegistryDeps` opts into the `fetchProject` call. Export `fetchProject`.

Note: public base `https://pypi.org/pypi/` + `${name}/json` = `https://pypi.org/pypi/flask/json` — identical to today. ✔

- [ ] **Step 3c: Edit `lib/codecs/ruby/registry.js`** — same pattern; rewrite `fetchGem`:

```js
const { withPublic, authHeaderFor, normalise } = require("../../registries");
async function fetchGem(name, { offline, registries = [], fetcher = globalThis.fetch } = {}) {
	if (offline) return null;
	const bases = withPublic("ruby", registries);
	let lastErr = null;
	for (const base of bases) {
		const url = normalise(base.url) + `${encodeURIComponent(name)}.json`;
		const headers = { "User-Agent": "fad-checker-rubygems", Accept: "application/json" };
		const ah = authHeaderFor(base); if (ah) headers.Authorization = ah;
		try { const res = await fetcher(url, { headers }); if (res.ok) return await res.json(); lastErr = `HTTP ${res.status}`; }
		catch (e) { lastErr = e.message; }
	}
	return { error: lastErr || "no data" };
}
```
Public base `https://rubygems.org/api/v1/gems/` + `<gem>.json` = today's URL. ✔ Thread `registries` from `checkRubyRegistryDeps` opts. Export `fetchGem`.

- [ ] **Step 3d: Edit `lib/codecs/go/registry.js`** — rewrite `fetchLatest`:

```js
const { withPublic, authHeaderFor, normalise } = require("../../registries");
async function fetchLatest(mod, { offline, registries = [], fetcher = globalThis.fetch } = {}) {
	if (offline) return null;
	const bases = withPublic("go", registries);
	let lastErr = null;
	for (const base of bases) {
		const url = normalise(base.url) + `${escapeModule(mod)}/@latest`;
		const headers = { "User-Agent": "fad-checker-go", Accept: "application/json" };
		const ah = authHeaderFor(base); if (ah) headers.Authorization = ah;
		try { const res = await fetcher(url, { headers }); if (res.ok) { const j = await res.json(); return { latest: (j.Version || "").replace(/^v/, "") || null }; } lastErr = `HTTP ${res.status}`; }
		catch (e) { lastErr = e.message; }
	}
	return { error: lastErr || "no data" };
}
```
Public base `https://proxy.golang.org/` + `<mod>/@latest` = today's URL. ✔ Thread `registries` from `checkGoRegistryDeps` opts. Export `fetchLatest`.

- [ ] **Step 4: Run, expect PASS** — `node --test test/codec-registries.test.js` AND the full suite `node --test test/*.test.js` (no regressions: default behaviour with empty registries hits the same public URLs).

- [ ] **Step 5: Commit** — `git commit -am "feat(codecs): npm/pypi/ruby/go registry fetchers honour custom registries + auth"`

---

## Task 6: codec `checkRegistry` passes `registries` through

**Files:** Modify `lib/codecs/pypi.codec.js`, `lib/codecs/ruby.codec.js`, `lib/codecs/go.codec.js` (npm handled directly by orchestrator); Test: covered by Task 5 + suite.

- [ ] **Step 1:** Inspect each `*.codec.js` `checkRegistry(deps, opts)` — confirm it forwards `opts` to `check<Eco>RegistryDeps(deps, opts)`. Grep: `grep -n "checkRegistry" lib/codecs/{pypi,ruby,go}.codec.js`.

- [ ] **Step 2:** If a codec hardcodes a subset of opts (e.g. `{ verbose, offline, allLibs }`), add `registries: opts.registries`. Most forward `opts` wholesale → no change.

- [ ] **Step 3:** Run `node --test test/*.test.js` — expect PASS.

- [ ] **Step 4: Commit (if changed)** — `git commit -am "feat(codecs): thread registries opt through checkRegistry"`

---

## Task 7: `fad-checker.js` — CLI options, repo commands, layer application

**Files:** Modify `fad-checker.js`

- [ ] **Step 1:** Replace the pre-parse `--add-repo/--remove-repo/--list-repos` block (lines ~72-115) with an ecosystem-aware version:

```js
if (process.argv.includes("--add-repo") || process.argv.includes("--remove-repo") || process.argv.includes("--list-repos")) {
	const config = require("./lib/config");
	const { SUPPORTED } = require("./lib/registries");
	const ecoErr = eco => {
		if (!SUPPORTED.includes(eco)) {
			console.error(chalk.red(`❌  unknown ecosystem "${eco}". Supported: ${SUPPORTED.join(", ")}`));
			process.exit(1);
		}
	};
	if (process.argv.includes("--list-repos")) {
		const map = config.getRegistryMap();
		const ecos = Object.keys(map).filter(e => (map[e] || []).length);
		if (!ecos.length) console.log(chalk.gray("No custom registries configured (public registries are always the fallback)."));
		else for (const eco of ecos) {
			console.log(chalk.bold(`${eco} (tried in order, then public):`));
			for (const r of map[eco]) console.log(`  • ${chalk.cyan(r.name)} → ${r.url}${(r.auth || r.token) ? chalk.yellow(" [auth]") : ""}`);
		}
		process.exit(0);
	}
	if (process.argv.includes("--add-repo")) {
		const idx = process.argv.indexOf("--add-repo");
		const [eco, name, url] = [process.argv[idx + 1], process.argv[idx + 2], process.argv[idx + 3]];
		if (!eco || !name || !url || [eco, name, url].some(a => a.startsWith("-"))) {
			console.error(chalk.red("❌  --add-repo requires <ecosystem> <name> <url>"));
			console.error("   Example: fad-checker --add-repo npm verdaccio https://npm.acme/ --token TOK");
			process.exit(1);
		}
		ecoErr(eco);
		const authIdx = process.argv.indexOf("--auth");
		const tokIdx = process.argv.indexOf("--token");
		config.addRegistry(eco, name, url, {
			auth: authIdx > -1 ? process.argv[authIdx + 1] : null,
			token: tokIdx > -1 ? process.argv[tokIdx + 1] : null,
		});
		console.log(chalk.green(`✅ Added ${eco} registry "${name}" → ${url}`));
		process.exit(0);
	}
	if (process.argv.includes("--remove-repo")) {
		const idx = process.argv.indexOf("--remove-repo");
		const [eco, name] = [process.argv[idx + 1], process.argv[idx + 2]];
		if (!eco || !name || [eco, name].some(a => a.startsWith("-"))) {
			console.error(chalk.red("❌  --remove-repo requires <ecosystem> <name>"));
			process.exit(1);
		}
		ecoErr(eco);
		const removed = config.removeRegistry(eco, name);
		console.log(removed ? chalk.green(`✅ Removed ${eco} registry "${name}"`) : chalk.yellow(`⚠️  No ${eco} registry named "${name}"`));
		process.exit(removed ? 0 : 1);
	}
}
```

Also fix the `--show-config` masking block (~line 64): replace the `masked.maven_repos` branch with masking `masked.registries` (mask `auth`/`token` per entry).

- [ ] **Step 2:** Update commander options. Change the `--repo` option (line 224) and add `--source`/`--config`:

```js
.option("-s, --src <src>", "root directory containing pom.xml files")
.option("--source <src>", "alias of --src")
.option("--config <file>", "load default options from a JSON config file (else ./.fad-env.json)")
```
Replace the old maven-only `--repo`/`--add-repo`/`--remove-repo`/`--list-repos` option lines (224-227) with:
```js
.option("--repo <eco=url...>", "extra registry as <ecosystem>=<url> (e.g. npm=https://npm.acme/). Repeatable. Supports https://user:pass@host/.")
.option("--add-repo <eco>", "persist a registry: --add-repo <ecosystem> <name> <url> [--auth user:pass] [--token TOK]")
.option("--remove-repo <eco>", "remove a persisted registry: --remove-repo <ecosystem> <name>")
.option("--list-repos", "list configured registries (grouped by ecosystem) and exit")
.option("--auth <user:pass>", "Basic auth for --add-repo")
.option("--token <token>", "Bearer token for --add-repo")
```

- [ ] **Step 3:** After `const options = program.opts();` (line 231) insert layer application + source normalize:

```js
const { loadLayers, applyLayers } = require("./lib/options-env");
const _layers = loadLayers({ cwd: process.cwd(), configPath: options.config, envStr: process.env.FAD_CHECKER_ENV, program });
const _globalStore = require("./lib/config").load();
Object.assign(options, applyLayers(program, _layers, _globalStore));
// --source alias → src (applyLayers already normalizes file/env; cover the CLI flag)
if (!options.src && options.source) options.src = options.source;
```
(Keep using `options.src` everywhere downstream — unchanged.)

- [ ] **Step 4:** Build the per-ecosystem registry map and lists where `mavenRepos` is built (line ~363). Replace:
```js
const { getMavenRepos } = require("./lib/config");
const { buildRepoList } = require("./lib/maven-repo");
const extraRepos = (options.repo || []).map(url => ({ url }));
const mavenRepos = buildRepoList(getMavenRepos(), extraRepos);
```
with:
```js
const { getRegistryMap } = require("./lib/config");
const { buildRepoList } = require("./lib/maven-repo");
const { buildRegistryList } = require("./lib/registries");
// Parse one-off --repo eco=url (from CLI + env layer), grouped by ecosystem.
const cliRepoMap = {};
for (const spec of [...(options.repo || []), ...(_layers.envRepos || [])]) {
	const m = /^([a-z]+)=(.+)$/i.exec(String(spec));
	if (!m) { console.error(chalk.red(`❌  --repo expects <ecosystem>=<url>, got "${spec}"`)); process.exit(1); }
	(cliRepoMap[m[1]] ||= []).push({ url: m[2] });
}
// File-layer registries map (JSON), global config map, CLI/env one-offs → union.
const fileRegMap = (_layers.fileLayer && _layers.fileLayer.registries) || {};
const globalRegMap = getRegistryMap();
const regMap = {};
for (const eco of new Set([...Object.keys(fileRegMap), ...Object.keys(globalRegMap), ...Object.keys(cliRepoMap)])) {
	regMap[eco] = buildRegistryList(eco, [globalRegMap[eco], fileRegMap[eco], cliRepoMap[eco]]);
}
const mavenRepos = buildRepoList(regMap.maven || [], []); // appends Central last
const registriesFor = eco => regMap[eco] || [];
```

- [ ] **Step 5:** Thread `registries` into the npm + per-codec passes:
  - npm pass (line ~712): add `registries: registriesFor("npm")` to the `checkNpmRegistryDeps(resolved, {...})` opts.
  - per-codec loop (line ~726): add `registries: registriesFor(id)` to the `codec.checkRegistry(resolved, {...})` opts.

- [ ] **Step 6:** Update the `repos` display line (~372) to also show non-maven registries count, e.g. after the maven line:
```js
const otherRegs = Object.keys(regMap).filter(e => e !== "maven" && regMap[e].length);
if (otherRegs.length) ui.kv("registries", chalk.white(otherRegs.map(e => `${e}:${regMap[e].length}`).join(" ")));
```

- [ ] **Step 7:** Run smoke test:
```bash
node fad-checker.js --add-repo npm verdaccio https://npm.example/ --token TOK
node fad-checker.js --list-repos
node fad-checker.js --remove-repo npm verdaccio
node fad-checker.js --help | grep -E "add-repo|--repo|--config|--source"
```
Expected: add/list/remove behave; help shows new flags.

- [ ] **Step 8: Commit** — `git commit -am "feat(cli): ecosystem-aware --add-repo/--repo, --source, --config, layered options"`

---

## Task 8: CLI parsing tests (end-to-end via child process)

**Files:** Test `test/cli-repos.test.js`

- [ ] **Step 1: Write tests** that spawn the CLI with a temp HOME + temp cwd:

```js
const { test } = require("node:test");
const assert = require("node:assert");
const { execFileSync } = require("child_process");
const fs = require("fs"); const os = require("os"); const path = require("path");
const CLI = path.join(__dirname, "..", "fad-checker.js");

function run(args, env = {}) {
	return execFileSync("node", [CLI, ...args], { env: { ...process.env, ...env }, encoding: "utf8" });
}

test("add-repo + list-repos + remove-repo round-trip (temp HOME)", () => {
	const home = fs.mkdtempSync(path.join(os.tmpdir(), "fad-home-"));
	const env = { HOME: home, USERPROFILE: home };
	run(["--add-repo", "npm", "verda", "https://npm.acme/", "--token", "T"], env);
	const list = run(["--list-repos"], env);
	assert.match(list, /npm/); assert.match(list, /verda/); assert.match(list, /\[auth\]/);
	const cfg = JSON.parse(fs.readFileSync(path.join(home, ".fad-checker", "config.json"), "utf8"));
	assert.strictEqual(cfg.registries.npm[0].token, "T");
	run(["--remove-repo", "npm", "verda"], env);
	assert.match(run(["--list-repos"], env), /No custom registries/);
	fs.rmSync(home, { recursive: true, force: true });
});

test("add-repo rejects unknown ecosystem", () => {
	const home = fs.mkdtempSync(path.join(os.tmpdir(), "fad-home-"));
	assert.throws(() => run(["--add-repo", "cargo", "x", "https://y/"], { HOME: home, USERPROFILE: home }));
	fs.rmSync(home, { recursive: true, force: true });
});
```

- [ ] **Step 2: Run, expect PASS** — `node --test test/cli-repos.test.js`.

- [ ] **Step 3: Run full suite** — `node --test test/*.test.js` → all green.

- [ ] **Step 4: Commit** — `git commit -am "test(cli): registry add/list/remove + bad-ecosystem rejection"`

---

## Task 9: User-style end-to-end verification

**Files:** none (manual run)

- [ ] **Step 1:** Run a real scan against a fixture with a bogus custom npm registry to prove fallback works (offline-safe: bogus host must 404/err then fall back to public, or run `--offline` to prove no crash):
```bash
node fad-checker.js -s test/fixtures/monorepo-mixed --no-report --no-transitive --no-all-libs
node fad-checker.js --source test/fixtures/monorepo-mixed --no-report --offline   # --source alias
echo '{"failOn":"medium","exclude":"^client\\.","source":"test/fixtures/monorepo-mixed"}' > /tmp/.fad-env.json
node fad-checker.js --config /tmp/.fad-env.json --no-report --offline             # config file drives source+excl
FAD_CHECKER_ENV='--no-report --offline' node fad-checker.js -s test/fixtures/simple  # env flags
```
Expected: each runs without error; `--source`/`--config`/`FAD_CHECKER_ENV` all resolve source/options; the run reports the registries line when customs are configured.

- [ ] **Step 2:** Confirm precedence: with `/tmp/.fad-env.json` setting `failOn:"medium"`, a CLI `--fail-on high` wins (inspect terminal/gate). 

- [ ] **Step 3: Commit** any fixups discovered.

---

## Task 10: Docs, gh-page, assets, CHANGELOG

**Files:** `README.md`, `docs/index.html`, `docs/USAGE.md`, `CLAUDE.md`, `CHANGELOG.md`, `docs/demo.tape`, `docs/assets/cli.png`, `docs/assets/report.png`

- [ ] **Step 1: README** — rewrite "Custom Maven repositories" → "Custom repositories & registries" (all 5 ecosystems, `--add-repo <eco> <name> <url>`, `--repo eco=url`, `--auth`/`--token`, public-last fallback, PyPI/Ruby JSON-API caveat). Add new "Configuration file & environment" section with the precedence table (`--config`/`.fad-env.json` JSON keys + `FAD_CHECKER_ENV` flag string). Add a **TL;DR** block atop "How it scans without any build tool" (3-4 sentences + one-line-per-ecosystem table), keep detailed bullets. Update "Common runs" with a `--source`/`--config` example.

- [ ] **Step 2: docs/index.html** — mirror the registries + config-file additions and the "how it scans" summary.

- [ ] **Step 3: docs/USAGE.md** — full flag docs: `--add-repo`/`--repo`/`--list-repos`/`--remove-repo`/`--auth`/`--token`/`--config`/`--source`, `.fad-env.json` schema, `FAD_CHECKER_ENV` examples, precedence.

- [ ] **Step 4: CLAUDE.md** — add convention bullets: per-ecosystem registries store (`registries` map, `lib/registries.js`), config layering + precedence (`lib/options-env.js`), `--source`/JSON `source`→`src` alias, no-backward-compat note.

- [ ] **Step 5: CHANGELOG.md** — new entry summarizing the feature.

- [ ] **Step 6: Assets** — regenerate:
  - `cli.png`: run `node fad-checker.js -s test/fixtures/monorepo-mixed --no-report --offline` (warm cache first if online) and capture the terminal. Try `freeze`/`termshot`/ANSI-to-PNG if available; else if VHS is installed render `docs/demo.tape` (update its `PROJECT`). 
  - `report.png`: generate an HTML report (`node fad-checker.js -s test/fixtures/complex-enterprise --report-html /tmp/r.html --offline`), screenshot via the webapp-testing (Playwright) skill.
  - If no renderer is available, refresh `docs/demo.tape` + regeneration notes and report that the binary PNGs were left unchanged.

- [ ] **Step 7:** Run full suite once more `node --test test/*.test.js`.

- [ ] **Step 8: Commit** — `git commit -am "docs: custom registries + config layering; refresh how-it-scans summary + assets"`

---

## Self-review notes

- Spec §1 store → Tasks 2,7. §1 fallback/auth/union → Tasks 1,5,7. §2 CLI → Tasks 7,8. §3 layering/precedence/parseEnvFlags → Task 4,7,9. §3a source alias → Tasks 4,7,9. §4 per-codec → Tasks 5,6. §5 docs/assets → Task 10. §6 tests → Tasks 1,2,4,5,8.
- Names consistent: `getRegistryMap`/`getRegistries`/`addRegistry`/`removeRegistry`, `buildRegistryList`/`withPublic`/`authHeaderFor`, `loadLayers`/`applyLayers`/`parseEnvFlags`/`normalizeSource`, `registriesFor(eco)`.
- No placeholders; every code step shows code.
```
