# Unmanaged Deps — Plan 2: Online identity & integrity

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Enrich hash-bearing unmanaged records (the `provenance:"binary"` records from Plan 1) with an online **identity** (deps.dev query-by-hash, then CIRCL hashlookup) and an **integrity** status (`pristine` / `known-good` / `unknown`), cached and `--offline`-aware, plus a free ride-along `knownMalicious` warning.

**Architecture:** Two pure-ish clients in `lib/hash-id.js` (deps.dev + CIRCL, each cache-backed, accepting an injectable `fetcher` for tests), and `lib/unmanaged.js#enrichUnmanaged()` that walks records with `.hashes` and sets `.identity` + `.integrity`. Wired into `fad-checker.js` after collection, behind `--offline`/cache, with a summary line.

**Tech Stack:** Node `node:test`, `globalThis.fetch` (injectable), `~/.fad-checker` JSON cache (kev.js pattern).

**Verified API shapes (2026-06-02):**
- deps.dev: `GET https://api.deps.dev/v3/query?hash.type=SHA1&hash.value=<base64(raw digest)>` → `{results:[{version:{versionKey:{system:"MAVEN"|"NPM"|…,name,version},isDeprecated,licenses,advisoryKeys}}]}`. No `results` / empty ⇒ unknown.
- CIRCL: `GET https://hashlookup.circl.lu/lookup/sha256/<hex>` → known: object with `FileName`/`ProductCode.ProductName`/`db`/optional `KnownMalicious`/`hashlookup:trust`; unknown: `{message:"Non existing SHA-256", …}`.

Scope: enrich records that carry `.hashes` (native binaries). Integrity "modified" detection for declared-coordinate embedded jars is a later refinement (noted in Plan 3). Spec: `docs/superpowers/specs/2026-06-02-unmanaged-vendored-dependencies-design.md`.

---

### Task 1: deps.dev + CIRCL clients (`lib/hash-id.js`)

**Files:** Create `lib/hash-id.js`; Test `test/hash-id.test.js`

- [ ] **Step 1: Write the failing test**

```js
// test/hash-id.test.js
const { test } = require("node:test");
const assert = require("node:assert");
const { sha1ToBase64, parseDepsDev, parseCircl, lookupHash } = require("../lib/hash-id");

test("sha1ToBase64 converts a hex digest to deps.dev's base64", () => {
	assert.equal(sha1ToBase64("ba55c13d7ac2fd44df9cc8074455719a33f375b9"), "ulXBPXrC/UTfnMgHRFVxmjPzdbk=");
});

test("parseDepsDev extracts the first coordinate, normalizing the ecosystem", () => {
	const body = { results: [{ version: { versionKey: { system: "MAVEN", name: "org.apache.logging.log4j:log4j-core", version: "2.15.0" } } }] };
	assert.deepEqual(parseDepsDev(body), { ecosystem: "maven", name: "org.apache.logging.log4j:log4j-core", version: "2.15.0", source: "deps.dev" });
	assert.equal(parseDepsDev({ results: [] }), null);
	assert.equal(parseDepsDev({}), null);
});

test("parseCircl reads product/db + knownMalicious, null for not-found", () => {
	const known = { FileName: "libz.so.1", ProductCode: { ProductName: "zlib", ProductVersion: "1.2.11" }, db: "nsrl_modern" };
	assert.deepEqual(parseCircl(known), { ecosystem: null, name: "zlib", version: "1.2.11", source: "circl:nsrl_modern", trust: null, knownMalicious: false });
	assert.equal(parseCircl({ message: "Non existing SHA-256" }), null);
	const bad = { FileName: "x", KnownMalicious: ["src"], "hashlookup:trust": 10 };
	assert.equal(parseCircl(bad).knownMalicious, true);
});

test("lookupHash prefers deps.dev, falls back to CIRCL, uses injected fetcher + cache", async () => {
	const calls = [];
	const fetcher = async (url) => {
		calls.push(url);
		if (url.includes("deps.dev")) return { ok: true, json: async () => ({ results: [] }) };
		return { ok: true, json: async () => ({ FileName: "libz.so.1", ProductCode: { ProductName: "zlib", ProductVersion: "1.2.11" }, db: "nsrl_modern" }) };
	};
	const cache = {};
	const id = await lookupHash({ sha1: "a".repeat(40), sha256: "b".repeat(64) }, { fetcher, cache });
	assert.equal(id.source, "circl:nsrl_modern");
	assert.ok(calls.some(u => u.includes("deps.dev")) && calls.some(u => u.includes("circl")));
	// second call served from the passed cache → no new fetches
	const before = calls.length;
	await lookupHash({ sha1: "a".repeat(40), sha256: "b".repeat(64) }, { fetcher, cache });
	assert.equal(calls.length, before);
});

test("lookupHash offline returns cached only, never calls the fetcher", async () => {
	let called = false;
	const fetcher = async () => { called = true; return { ok: true, json: async () => ({}) }; };
	const id = await lookupHash({ sha1: "c".repeat(40), sha256: "d".repeat(64) }, { fetcher, cache: {}, offline: true });
	assert.equal(id, null);
	assert.equal(called, false);
});
```

- [ ] **Step 2: Run → FAIL** (`Cannot find module '../lib/hash-id'`).

- [ ] **Step 3: Implement**

```js
// lib/hash-id.js
/**
 * lib/hash-id.js — identity-by-checksum for unmanaged artifacts.
 *
 * Two known-good sources, tried in order:
 *  1. deps.dev query-by-hash → exact package coordinate (whole published archive).
 *  2. CIRCL hashlookup → known OS/distro/CDN/NSRL file + free KnownMalicious flag.
 *
 * Cache-backed (~/.fad-checker/hash-id-cache.json, 24h) and --offline-aware: offline
 * reads cache only and never touches the network (project air-gapped principle).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");

const CACHE_DIR = path.join(os.homedir(), ".fad-checker");
const CACHE_PATH = path.join(CACHE_DIR, "hash-id-cache.json");
const CACHE_TTL_MS = 24 * 3600 * 1000;
const DEPSDEV = "https://api.deps.dev/v3/query";
const CIRCL = "https://hashlookup.circl.lu/lookup/sha256";

const SYSTEM_TO_ECO = { MAVEN: "maven", NPM: "npm", NUGET: "nuget", PYPI: "pypi", RUBYGEMS: "ruby", CARGO: "cargo", GO: "go" };

function sha1ToBase64(hex) { return Buffer.from(hex, "hex").toString("base64"); }

function parseDepsDev(body) {
	const vk = body?.results?.[0]?.version?.versionKey;
	if (!vk?.name) return null;
	return { ecosystem: SYSTEM_TO_ECO[vk.system] || (vk.system || "").toLowerCase() || null, name: vk.name, version: vk.version || null, source: "deps.dev" };
}

function parseCircl(body) {
	if (!body || body.message || !(body.FileName || body.ProductCode)) return null;
	const malicious = Array.isArray(body.KnownMalicious) ? body.KnownMalicious.length > 0 : !!body.KnownMalicious;
	return {
		ecosystem: null,
		name: body.ProductCode?.ProductName || body.FileName || null,
		version: body.ProductCode?.ProductVersion || null,
		source: `circl:${body.db || "hashlookup"}`,
		trust: body["hashlookup:trust"] != null ? body["hashlookup:trust"] : null,
		knownMalicious: malicious,
	};
}

function loadCache() { try { const d = JSON.parse(fs.readFileSync(CACHE_PATH, "utf8")); if (Date.now() - (d._fetchedAt || 0) < CACHE_TTL_MS) return d.entries || {}; } catch { /* ignore */ } return {}; }
function saveCache(entries) { try { fs.mkdirSync(CACHE_DIR, { recursive: true }); fs.writeFileSync(CACHE_PATH, JSON.stringify({ _fetchedAt: Date.now(), entries })); } catch { /* ignore */ } }

async function lookupHash(hashes, opts = {}) {
	const { fetcher = globalThis.fetch, offline = false, cache } = opts;
	const entries = cache || loadCache();
	const key = hashes.sha256 || hashes.sha1;
	if (!key) return null;
	if (Object.prototype.hasOwnProperty.call(entries, key)) return entries[key];
	if (offline) return null;

	let identity = null;
	// 1) deps.dev (SHA1 base64)
	if (hashes.sha1) {
		try {
			const r = await fetcher(`${DEPSDEV}?hash.type=SHA1&hash.value=${encodeURIComponent(sha1ToBase64(hashes.sha1))}`, { headers: { "User-Agent": "fad-checker-hashid" } });
			if (r.ok) identity = parseDepsDev(await r.json());
		} catch { /* ignore, try CIRCL */ }
	}
	// 2) CIRCL (SHA-256)
	if (!identity && hashes.sha256) {
		try {
			const r = await fetcher(`${CIRCL}/${hashes.sha256}`, { headers: { "User-Agent": "fad-checker-hashid", Accept: "application/json" } });
			if (r.ok) identity = parseCircl(await r.json());
		} catch { /* ignore */ }
	}
	entries[key] = identity;
	if (!cache) saveCache(entries);
	return identity;
}

module.exports = { sha1ToBase64, parseDepsDev, parseCircl, lookupHash, loadCache, saveCache, CACHE_PATH };
```

- [ ] **Step 4: Run → PASS.** `node --test test/hash-id.test.js`

- [ ] **Step 5: Commit** `feat(hash-id): deps.dev + CIRCL identity-by-checksum clients (cached, offline-aware)`

---

### Task 2: Enrichment over unmanaged records (`lib/unmanaged.js`)

**Files:** Create `lib/unmanaged.js`; Test `test/unmanaged.test.js`

- [ ] **Step 1: Write the failing test**

```js
// test/unmanaged.test.js
const { test } = require("node:test");
const assert = require("node:assert");
const { enrichUnmanaged } = require("../lib/unmanaged");
const { makeDepRecord } = require("../lib/dep-record");

function rec(name, hashes) { return makeDepRecord({ ecosystem: "binary", name, manifestPath: `/p/${name}`, provenance: "binary", hashes, declaredName: name }); }

test("enrichUnmanaged sets identity + integrity per record (deps.dev=pristine, circl=known-good, none=unknown)", async () => {
	const resolved = new Map();
	resolved.set("binary:/p/a.dll", rec("a.dll", { sha1: "a".repeat(40), sha256: "1".repeat(64) }));
	resolved.set("binary:/p/b.so", rec("b.so", { sha1: "b".repeat(40), sha256: "2".repeat(64) }));
	resolved.set("binary:/p/c.so", rec("c.so", { sha1: "c".repeat(40), sha256: "3".repeat(64) }));
	resolved.set("g:a", makeDepRecord({ ecosystem: "maven", namespace: "g", name: "a", version: "1.0", manifestPath: "/pom.xml" })); // untouched

	const fetcher = async (url) => {
		if (url.includes("deps.dev")) {
			if (url.includes(encodeURIComponent(Buffer.from("a".repeat(40), "hex").toString("base64")))) {
				return { ok: true, json: async () => ({ results: [{ version: { versionKey: { system: "NUGET", name: "A.Pkg", version: "2.0" } } }] }) };
			}
			return { ok: true, json: async () => ({ results: [] }) };
		}
		// CIRCL: b.so known, c.so unknown
		if (url.endsWith("2".repeat(64))) return { ok: true, json: async () => ({ FileName: "libb.so", ProductCode: { ProductName: "libb", ProductVersion: "1.1" }, db: "ubuntu" }) };
		return { ok: true, json: async () => ({ message: "Non existing SHA-256" }) };
	};

	const summary = await enrichUnmanaged(resolved, { fetcher, cache: {} });
	const a = resolved.get("binary:/p/a.dll"), b = resolved.get("binary:/p/b.so"), c = resolved.get("binary:/p/c.so");
	assert.deepEqual(a.identity, { ecosystem: "nuget", name: "A.Pkg", version: "2.0", source: "deps.dev" });
	assert.equal(a.integrity, "pristine");
	assert.equal(b.integrity, "known-good");
	assert.equal(b.identity.name, "libb");
	assert.equal(c.identity, null);
	assert.equal(c.integrity, "unknown");
	assert.equal(resolved.get("g:a").identity, undefined); // managed deps not touched
	assert.deepEqual(summary, { total: 3, identified: 2, pristine: 1, knownGood: 1, unknown: 1, malicious: 0 });
});

test("enrichUnmanaged offline does not call the fetcher", async () => {
	const resolved = new Map();
	resolved.set("binary:/p/a.dll", rec("a.dll", { sha1: "a".repeat(40), sha256: "1".repeat(64) }));
	let called = false;
	await enrichUnmanaged(resolved, { fetcher: async () => { called = true; return { ok: true, json: async () => ({}) }; }, cache: {}, offline: true });
	assert.equal(called, false);
	assert.equal(resolved.get("binary:/p/a.dll").integrity, "unknown");
});
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement**

```js
// lib/unmanaged.js
/**
 * lib/unmanaged.js — enrich unmanaged (hash-bearing) records with online identity
 * + an integrity classification.
 *
 *   integrity:
 *     "pristine"    — deps.dev matched: file is byte-identical to a PUBLISHED package
 *                     artifact (so it's unmodified, and ought to be a managed dep).
 *     "known-good"  — CIRCL matched: a known OS/distro/CDN/NSRL file.
 *     "unknown"     — no source recognises the hash (suspicious / vendored unknown).
 *
 * Records carrying a declared coordinate (embedded jars) gain a "modified" status in
 * a later refinement; Plan 2 covers the hash-bearing binary records.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { lookupHash, loadCache, saveCache } = require("./hash-id");

async function enrichUnmanaged(resolved, opts = {}) {
	const { fetcher, offline = false, cache, onProgress } = opts;
	const targets = [...resolved.values()].filter(d => d.hashes && (d.hashes.sha1 || d.hashes.sha256));
	const summary = { total: targets.length, identified: 0, pristine: 0, knownGood: 0, unknown: 0, malicious: 0 };
	if (!targets.length) return summary;
	const entries = cache || loadCache();
	let done = 0;
	for (const d of targets) {
		const id = await lookupHash(d.hashes, { fetcher, offline, cache: entries });
		d.identity = id || null;
		if (!id) d.integrity = "unknown";
		else if (id.source === "deps.dev") d.integrity = "pristine";
		else d.integrity = "known-good";
		if (id) summary.identified++;
		if (d.integrity === "pristine") summary.pristine++;
		else if (d.integrity === "known-good") summary.knownGood++;
		else summary.unknown++;
		if (id?.knownMalicious) summary.malicious++;
		if (onProgress) onProgress(++done, targets.length);
	}
	if (!cache && !offline) saveCache(entries);
	return summary;
}

module.exports = { enrichUnmanaged };
```

- [ ] **Step 4: Run → PASS.**

- [ ] **Step 5: Commit** `feat(unmanaged): enrichUnmanaged — identity + integrity over hash-bearing records`

---

### Task 3: Wire into the orchestrator + summary line

**Files:** Modify `fad-checker.js` (after the collection summary, before/within `runReportFlow` setup); Test: covered by the unit tests above + a manual smoke run.

- [ ] **Step 1:** In `fad-checker.js`, right after the collection-summary block (after the `binaryCount` line), add an enrichment pass (online unless `--offline`):

```js
	// Identify + integrity-check unmanaged binaries by checksum (deps.dev + CIRCL).
	if (binaryCount) {
		const { enrichUnmanaged } = require("./lib/unmanaged");
		const st = ui.progress ? ui.progress("identifying binaries") : null;
		try {
			const s = await enrichUnmanaged(resolved, { offline, onProgress: (p, t) => st && st.tick && st.tick(p, t) });
			const bits = [`${s.identified}/${s.total} identified`, s.pristine ? `${s.pristine} pristine` : null, s.unknown ? `${s.unknown} unknown` : null, s.malicious ? `${s.malicious} ⚠ malicious` : null].filter(Boolean).join(", ");
			if (st && st.done) st.done(bits); else ui.ok(`Binary id  ${bits}`);
		} catch (e) { if (st && st.done) st.done(`skipped: ${e.message}`); else ui.warn(`binary identify skipped: ${e.message}`); }
	}
```

> Match the exact `ui.progress`/`st.tick`/`st.done` API used elsewhere in `fad-checker.js` (grep `st.done(` / `ui.progress(` for the real signature; the EOL/outdated phases use it). If the helper differs, mirror that call shape; the `enrichUnmanaged` call + the summary string stay the same.

- [ ] **Step 2:** Confirm `offline` variable is in scope at that point (it's defined earlier for the report flow — grep `const offline =` / `offline =`). If it's only defined later, compute it the same way (`options.offline`).

- [ ] **Step 3: Run full suite** `node --test test/*.test.js` → PASS (no unit depends on the wiring).

- [ ] **Step 4: Manual smoke (online):**

```bash
T=$(mktemp -d); cp "$(find /usr/lib /lib -name 'libz.so*' -type f | head -1)" "$T/libz.so.1"
node fad-checker.js -s "$T" --no-report 2>&1 | grep -iE "Binary|identif|pristine|unknown"
rm -rf "$T"
```

Expected: a `Binary` count line + an identify line (likely `0/1 identified, 1 unknown` for a distro `.so` not on deps.dev, or `known-good` if CIRCL knows it). No crash; offline (`--offline`) prints `0/1 identified` without network.

- [ ] **Step 5: Commit** `feat(binary): identify + integrity-check binaries by checksum in the pipeline`

---

## Self-review
- deps.dev/CIRCL clients, cache, offline → Task 1. ✅
- identity + integrity per record, summary → Task 2. ✅
- orchestrator wiring + summary line → Task 3. ✅
- "modified" for declared-coordinate embedded jars → explicitly deferred (noted). 
- Placeholders: the two Task 3 hedges give exact greps to resolve the real `ui.progress`/`offline` API. ✅
- Types: `identity {ecosystem,name,version,source[,trust,knownMalicious]}` and `integrity` string consistent across Tasks 1–2 and used by Plan 3. ✅
