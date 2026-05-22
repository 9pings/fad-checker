/**
 * lib/outdated.js — EOL, obsolete, and outdated dependency checks.
 *
 * EOL data comes from endoflife.date (with on-disk cache).
 * Obsolete data is curated locally (data/known-obsolete.json).
 * Outdated comes from Maven Central's maven-metadata.xml.
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const { compareMavenVersions } = require("./maven-version");

const KNOWN_OBSOLETE = require("../data/known-obsolete.json");
const EOL_MAPPING = require("../data/eol-mapping.json");

const CACHE_DIR = path.join(os.homedir(), ".fad-check");
const EOL_CACHE_PATH = path.join(CACHE_DIR, "eol-cache.json");
const VERSION_CACHE_PATH = path.join(CACHE_DIR, "version-cache.json");
const EOL_CACHE_MAX_AGE_MS = 7 * 24 * 3600 * 1000; // 7 days
const VERSION_CACHE_MAX_AGE_MS = 24 * 3600 * 1000; // 1 day

function loadJsonCache(file) {
	try { return JSON.parse(fs.readFileSync(file, "utf8")); }
	catch { return { meta: { fetchedAt: 0 }, entries: {} }; }
}

function saveJsonCache(file, data) {
	try {
		fs.mkdirSync(CACHE_DIR, { recursive: true });
		fs.writeFileSync(file, JSON.stringify(data));
	} catch { /* ignore */ }
}

function isEolCacheFresh(maxAge = EOL_CACHE_MAX_AGE_MS) {
	const c = loadJsonCache(EOL_CACHE_PATH);
	return c.meta?.fetchedAt && (Date.now() - c.meta.fetchedAt) < maxAge;
}

// -------- EOL via endoflife.date --------

function findEolProduct(dep) {
	const key = `${dep.groupId}:${dep.artifactId}`;
	const direct = EOL_MAPPING.by_group_artifact?.[key];
	if (direct) return direct;
	// Match longest groupId prefix
	const prefixes = Object.keys(EOL_MAPPING.by_group_prefix || {})
		.sort((a, b) => b.length - a.length);
	for (const p of prefixes) {
		if (dep.groupId === p || dep.groupId.startsWith(p + ".")) {
			return EOL_MAPPING.by_group_prefix[p];
		}
	}
	return null;
}

async function fetchEndoflife(product, cache, opts = {}) {
	if (cache.entries[product]) return cache.entries[product];
	if (opts.offline) return null;
	try {
		const res = await fetch(`https://endoflife.date/api/${encodeURIComponent(product)}.json`, {
			headers: { "User-Agent": "fad-check-eol-checker" },
		});
		if (!res.ok) {
			cache.entries[product] = { error: `HTTP ${res.status}` };
			return cache.entries[product];
		}
		const cycles = await res.json();
		cache.entries[product] = cycles;
		return cycles;
	} catch (err) {
		cache.entries[product] = { error: err.message };
		return cache.entries[product];
	}
}

function findCycleForVersion(cycles, version) {
	if (!Array.isArray(cycles) || !version) return null;
	// Match by cycle prefix: e.g. version "2.7.18" → cycle "2.7"
	for (const c of cycles) {
		const cycle = String(c.cycle || "");
		if (!cycle) continue;
		if (version === cycle || version.startsWith(cycle + ".") || version.startsWith(cycle + "-")) {
			return c;
		}
	}
	return null;
}

function isEol(cycle) {
	if (!cycle) return false;
	if (cycle.eol === true) return true;
	if (typeof cycle.eol === "string") {
		const eolDate = new Date(cycle.eol);
		if (!isNaN(eolDate.getTime())) return eolDate.getTime() < Date.now();
	}
	return false;
}

async function checkEolDeps(resolvedDeps, opts = {}) {
	const { verbose, offline } = opts;
	const cache = loadJsonCache(EOL_CACHE_PATH);
	const fresh = isEolCacheFresh();
	const results = [];
	const seen = new Set();

	for (const dep of resolvedDeps.values()) {
		if (dep.ecosystem === "npm") continue; // EOL mapping is Maven-only for now
		const product = findEolProduct(dep);
		if (!product) continue;
		const dedupeKey = `${dep.groupId}:${dep.artifactId}|${product.product}`;
		if (seen.has(dedupeKey)) continue;
		seen.add(dedupeKey);

		const cycles = fresh && cache.entries[product.product]
			? cache.entries[product.product]
			: await fetchEndoflife(product.product, cache, { offline });

		if (!Array.isArray(cycles)) continue;
		const cycle = findCycleForVersion(cycles, dep.version);
		if (!cycle) continue;
		if (!isEol(cycle)) continue;

		results.push({
			dep,
			product: product.label || product.product,
			productSlug: product.product,
			cycle: cycle.cycle,
			eol: cycle.eol === true ? "true" : String(cycle.eol),
			latest: cycle.latest || null,
			notes: cycle.latestReleaseDate ? `Latest: ${cycle.latest} (${cycle.latestReleaseDate})` : "",
		});
		if (verbose) process.stdout.write(`  EOL: ${dep.groupId}:${dep.artifactId}:${dep.version} (${product.label})\n`);
	}

	cache.meta = { fetchedAt: Date.now() };
	saveJsonCache(EOL_CACHE_PATH, cache);
	return results;
}

// -------- Obsolete via curated list --------

function checkObsoleteDeps(resolvedDeps) {
	const results = [];
	const seen = new Set();
	for (const dep of resolvedDeps.values()) {
		const key = `${dep.groupId}:${dep.artifactId}`;
		if (seen.has(key)) continue;
		const entry = KNOWN_OBSOLETE[key];
		if (!entry) continue;
		seen.add(key);
		results.push({
			dep,
			severity: entry.severity || "MEDIUM",
			replacement: entry.replacement || null,
			reason: entry.reason || "",
		});
	}
	return results;
}

function checkObsolete(dep) {
	const entry = KNOWN_OBSOLETE[`${dep.groupId}:${dep.artifactId}`];
	return entry ? { dep, ...entry } : null;
}

// -------- Outdated via Maven Central --------

async function fetchLatestVersion(groupId, artifactId, cache, opts = {}) {
	const key = `${groupId}:${artifactId}`;
	if (cache.entries[key]) return cache.entries[key];
	if (opts.offline) return null;
	const url = `https://search.maven.org/solrsearch/select?q=g:%22${encodeURIComponent(groupId)}%22+AND+a:%22${encodeURIComponent(artifactId)}%22&core=gav&rows=1&wt=json`;
	try {
		const res = await fetch(url, { headers: { "User-Agent": "fad-check-outdated-checker" } });
		if (!res.ok) {
			cache.entries[key] = { error: `HTTP ${res.status}` };
			return cache.entries[key];
		}
		const json = await res.json();
		const doc = json?.response?.docs?.[0];
		const entry = doc
			? { latest: doc.v, releaseDate: doc.timestamp ? new Date(doc.timestamp).toISOString().slice(0, 10) : null }
			: { error: "not found" };
		cache.entries[key] = entry;
		return entry;
	} catch (err) {
		cache.entries[key] = { error: err.message };
		return cache.entries[key];
	}
}

async function checkOutdatedDeps(resolvedDeps, opts = {}) {
	const { verbose, offline, concurrency = 8 } = opts;
	const cache = loadJsonCache(VERSION_CACHE_PATH);
	const fresh = cache.meta?.fetchedAt && (Date.now() - cache.meta.fetchedAt) < VERSION_CACHE_MAX_AGE_MS;
	if (!fresh && !offline) cache.entries = {};
	const list = [...resolvedDeps.values()].filter(d => d.version && !/\$\{|SNAPSHOT/i.test(d.version) && d.ecosystem !== "npm");
	const results = [];

	// Simple p-limit style throttle without requiring p-limit here (already used in fad-check.js)
	let cursor = 0;
	const workers = Array.from({ length: concurrency }, async () => {
		while (cursor < list.length) {
			const dep = list[cursor++];
			const entry = await fetchLatestVersion(dep.groupId, dep.artifactId, cache, { offline });
			if (!entry?.latest) continue;
			try {
				if (compareMavenVersions(dep.version, entry.latest) < 0) {
					results.push({ dep, latest: entry.latest, releaseDate: entry.releaseDate || null });
					if (verbose) process.stdout.write(`  outdated: ${dep.groupId}:${dep.artifactId} ${dep.version} → ${entry.latest}\n`);
				}
			} catch { /* ignore comparison failure */ }
		}
	});
	await Promise.all(workers);

	cache.meta = { fetchedAt: Date.now() };
	saveJsonCache(VERSION_CACHE_PATH, cache);
	results.sort((a, b) => `${a.dep.groupId}:${a.dep.artifactId}`.localeCompare(`${b.dep.groupId}:${b.dep.artifactId}`));
	return results;
}

module.exports = {
	checkEolDeps,
	checkObsoleteDeps,
	checkObsolete,
	checkOutdatedDeps,
	findEolProduct,
	isEolCacheFresh,
	KNOWN_OBSOLETE,
};
