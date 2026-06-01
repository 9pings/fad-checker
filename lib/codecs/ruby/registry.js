/**
 * lib/codecs/ruby/registry.js — query RubyGems for latest version + licenses.
 *
 * API: https://rubygems.org/api/v1/gems/<gem>.json → { version, licenses[] }
 * One call yields both outdated (latest stable) and the SPDX-ish license list.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
let pLimit; try { pLimit = require("p-limit"); } catch { pLimit = () => (fn) => fn(); }

const CACHE_DIR = path.join(os.homedir(), ".fad-checker");
const CACHE_PATH = path.join(CACHE_DIR, "rubygems-cache.json");
const CACHE_MAX_AGE_MS = 24 * 3600 * 1000;
const API = "https://rubygems.org/api/v1/gems";

function loadCache() { try { return JSON.parse(fs.readFileSync(CACHE_PATH, "utf8")); } catch { return { entries: {}, meta: {} }; } }
function saveCache(d) { try { fs.mkdirSync(CACHE_DIR, { recursive: true }); fs.writeFileSync(CACHE_PATH, JSON.stringify(d)); } catch { /* ignore */ } }
function isStable(v) { return /^\d+(\.\d+)*$/.test(String(v || "")); }
function cmp(a, b) {
	const pa = String(a).split(/[.\-+]/).map(n => parseInt(n, 10) || 0);
	const pb = String(b).split(/[.\-+]/).map(n => parseInt(n, 10) || 0);
	for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d > 0 ? 1 : -1; }
	return 0;
}

// Pure extractor: RubyGems gem JSON → { latest, license }.
function gemToFindings(data) {
	const out = { latest: null, license: null };
	if (data?.version && isStable(data.version)) out.latest = data.version;
	const lic = data?.licenses;
	if (Array.isArray(lic) && lic.length) out.license = lic;
	return out;
}

async function fetchGem(name, { offline }) {
	if (offline) return null;
	try {
		const res = await fetch(`${API}/${encodeURIComponent(name)}.json`, { headers: { "User-Agent": "fad-checker-rubygems" } });
		if (!res.ok) return { error: `HTTP ${res.status}` };
		return await res.json();
	} catch (e) { return { error: e.message }; }
}

async function checkRubyRegistryDeps(deps, opts = {}) {
	const { verbose, offline, allLibs = true, concurrency = 8 } = opts;
	const targets = [...deps.values()].filter(d => d.ecosystem === "ruby" && d.version);
	const result = { deprecated: [], outdated: [], licensed: [] };
	if (!targets.length) return result;
	const cache = loadCache();
	const fresh = cache.meta?.fetchedAt && (Date.now() - cache.meta.fetchedAt) < CACHE_MAX_AGE_MS;
	if (!fresh && !offline) cache.entries = {};
	const limit = pLimit(concurrency);
	await Promise.all(targets.map(t => limit(async () => {
		const key = `${t.name}@${t.version}`;
		let ex = cache.entries[key];
		if (!ex) {
			const data = await fetchGem(t.name, { offline });
			ex = (data && !data.error) ? gemToFindings(data) : { latest: null, license: null };
			if (data && !data.error) cache.entries[key] = ex;
		}
		if (ex.license) result.licensed.push({ dep: t, licenses: ex.license, source: "rubygems" });
		if (allLibs && ex.latest && cmp(ex.latest, t.version) > 0) {
			result.outdated.push({ dep: t, latest: ex.latest, releaseDate: null });
			if (verbose) process.stdout.write(`  outdated: ${t.name} ${t.version} → ${ex.latest}\n`);
		}
	})));
	cache.meta = { fetchedAt: Date.now() };
	saveCache(cache);
	return result;
}

module.exports = { gemToFindings, checkRubyRegistryDeps };
