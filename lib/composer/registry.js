/**
 * lib/composer/registry.js — query Packagist for a package's latest stable
 * version and its `abandoned` flag (≈ npm `deprecated`).
 *
 * API: https://packagist.org/packages/{vendor}/{pkg}.json
 *   → { package: { abandoned: bool|string, versions: { "<v>": {...} } } }
 *
 * Cached in ~/.fad-checker/packagist-cache.json for 24h.
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
let pLimit; try { pLimit = require("p-limit"); } catch { pLimit = () => (fn) => fn(); }

const CACHE_DIR = path.join(os.homedir(), ".fad-checker");
const CACHE_PATH = path.join(CACHE_DIR, "packagist-cache.json");
const CACHE_MAX_AGE_MS = 24 * 3600 * 1000;
const API = "https://packagist.org/packages";

function loadCache() { try { return JSON.parse(fs.readFileSync(CACHE_PATH, "utf8")); } catch { return { entries: {}, meta: {} }; } }
function saveCache(d) { try { fs.mkdirSync(CACHE_DIR, { recursive: true }); fs.writeFileSync(CACHE_PATH, JSON.stringify(d)); } catch { /* ignore */ } }

function isStable(v) { return /^\d+(\.\d+)*$/.test(String(v || "").replace(/^v/, "")); }
function cmp(a, b) {
	const pa = String(a).replace(/^v/, "").split(/[.\-+]/).map(n => parseInt(n, 10) || 0);
	const pb = String(b).replace(/^v/, "").split(/[.\-+]/).map(n => parseInt(n, 10) || 0);
	for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d > 0 ? 1 : -1; }
	return 0;
}

// Extract {abandoned, outdated} from a Packagist `package` object.
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

// Mirror of checkNpmRegistryDeps: returns { deprecated:[], outdated:[] }.
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
			if (pkg && !pkg.error) {
				const f = packagistToFindings(pkg, { version: t.version });
				ex = { abandoned: f.abandoned, latest: f.outdated?.latest || null };
				cache.entries[key] = ex;
			} else {
				ex = { abandoned: null, latest: null };
			}
		}
		if (ex.abandoned) {
			result.deprecated.push({ dep: t, severity: "MEDIUM", replacement: ex.abandoned.replacement, reason: "Package marked abandoned on Packagist", source: "packagist" });
			if (verbose) process.stdout.write(`  abandoned: ${name}@${t.version}\n`);
		}
		if (allLibs && ex.latest) {
			result.outdated.push({ dep: t, latest: ex.latest, releaseDate: null });
			if (verbose) process.stdout.write(`  outdated: ${name} ${t.version} → ${ex.latest}\n`);
		}
	})));
	cache.meta = { fetchedAt: Date.now() };
	saveCache(cache);
	return result;
}

module.exports = { packagistToFindings, checkComposerRegistryDeps };
