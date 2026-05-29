/**
 * lib/nuget/registry.js — query the NuGet registration index for a package's
 * latest stable version and per-version deprecation.
 *
 * API: https://api.nuget.org/v3/registration5-gz-semver2/{lowerid}/index.json
 *   → { items: [ { items: [ { catalogEntry: { version, deprecation } } ] } ] }
 *
 * Cached in ~/.fad-checker/nuget-cache.json for 24h.
 */
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
function cmp(a, b) {
	const pa = String(a).split(/[.\-+]/).map(n => parseInt(n, 10) || 0);
	const pb = String(b).split(/[.\-+]/).map(n => parseInt(n, 10) || 0);
	for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d > 0 ? 1 : -1; }
	return 0;
}

// Walk a registration index (inline items) → { outdated, deprecated }.
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

// Mirror of checkNpmRegistryDeps: returns { deprecated:[], outdated:[] }.
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
			if (reg && !reg.error) {
				const f = nugetRegistrationToFindings(reg, { version: t.version });
				ex = { deprecated: f.deprecated, latest: f.outdated?.latest || null };
				cache.entries[key] = ex;
			} else {
				ex = { deprecated: null, latest: null };
			}
		}
		if (ex.deprecated) {
			result.deprecated.push({ dep: t, severity: "MEDIUM", replacement: ex.deprecated.replacement, reason: ex.deprecated.reason, source: "nuget" });
			if (verbose) process.stdout.write(`  deprecated: ${t.name}@${t.version}\n`);
		}
		if (allLibs && ex.latest) {
			result.outdated.push({ dep: t, latest: ex.latest, releaseDate: null });
			if (verbose) process.stdout.write(`  outdated: ${t.name} ${t.version} → ${ex.latest}\n`);
		}
	})));
	cache.meta = { fetchedAt: Date.now() };
	saveCache(cache);
	return result;
}

module.exports = { nugetRegistrationToFindings, checkNugetRegistryDeps };
