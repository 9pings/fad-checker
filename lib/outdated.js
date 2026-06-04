/**
 * lib/outdated.js — EOL, obsolete, and outdated dependency checks.
 *
 * EOL data comes from endoflife.date (with on-disk cache).
 * Obsolete data is curated locally (data/known-obsolete.json).
 * Outdated comes from Maven Central's maven-metadata.xml.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const { compareMavenVersions } = require("./maven-version");
const { webjarToNpm } = require("./codecs/npm/collect");

const KNOWN_OBSOLETE = require("../data/known-obsolete.json");
const EOL_MAPPING = require("../data/eol-mapping.json");

const CACHE_DIR = path.join(os.homedir(), ".fad-checker");
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

// Tag the matched mapping entry with HOW it matched (which rule + which key), so
// the report can show where an EOL verdict comes from. Returns a COPY — the shared
// EOL_MAPPING objects must never be mutated (they're reused across deps).
function withOrigin(entry, via, viaKey) {
	return entry ? { ...entry, via, viaKey } : null;
}

function findEolProduct(dep) {
	// npm packages — and WebJars, which are client-side JS shipped as Maven
	// artifacts — resolve by JS library name, not Maven coordinate. npm deps
	// use their name directly; WebJars are reduced to their npm-equivalent name
	// first (org.webjars:angularjs → "angularjs", org.webjars.npm:angular__core
	// → "@angular/core"). The npm package literally named "angular" is AngularJS
	// 1.x; modern Angular is the @angular/* scope — hence the name vs. scope maps.
	const isWebjar = dep.ecosystem !== "npm" && webjarToNpm(dep) != null;
	const npmName = dep.ecosystem === "npm" ? (dep.artifactId || "") : webjarToNpm(dep)?.name;
	if (npmName != null) {
		const byName = EOL_MAPPING.by_npm_name?.[npmName];
		if (byName) return withOrigin(byName, isWebjar ? "webjar" : "npm-name", npmName);
		const scopes = Object.keys(EOL_MAPPING.by_npm_scope || {})
			.sort((a, b) => b.length - a.length);
		for (const s of scopes) {
			if (npmName.startsWith(s)) return withOrigin(EOL_MAPPING.by_npm_scope[s], isWebjar ? "webjar" : "npm-scope", s);
		}
		return null;
	}
	if (dep.ecosystem === "composer") {
		const full = `${dep.namespace || dep.groupId || ""}/${dep.name || dep.artifactId}`.toLowerCase();
		return withOrigin(EOL_MAPPING.by_composer_name?.[full], "composer-name", full);
	}
	if (dep.ecosystem === "pypi") {
		const k = (dep.name || dep.artifactId || "").toLowerCase();
		return withOrigin(EOL_MAPPING.by_pypi_name?.[k], "pypi-name", k);
	}
	if (dep.ecosystem === "nuget") {
		const k = (dep.name || dep.artifactId || "").toLowerCase();
		return withOrigin(EOL_MAPPING.by_nuget_name?.[k], "nuget-name", k);
	}
	const key = `${dep.groupId}:${dep.artifactId}`;
	const direct = EOL_MAPPING.by_group_artifact?.[key];
	if (direct) return withOrigin(direct, "group-artifact", key);
	// Match longest groupId prefix
	const prefixes = Object.keys(EOL_MAPPING.by_group_prefix || {})
		.sort((a, b) => b.length - a.length);
	for (const p of prefixes) {
		if (dep.groupId === p || dep.groupId.startsWith(p + ".")) {
			return withOrigin(EOL_MAPPING.by_group_prefix[p], "group-prefix", p);
		}
	}
	return null;
}

async function fetchEndoflife(product, cache, opts = {}) {
	if (cache.entries[product]) return cache.entries[product];
	if (opts.offline) return null;
	try {
		const res = await fetch(`https://endoflife.date/api/${encodeURIComponent(product)}.json`, {
			headers: { "User-Agent": "fad-checker-eol-checker" },
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
			via: product.via || null,
			viaKey: product.viaKey || null,
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
	// Try Central's Solr first (fast), then fall back to maven-metadata.xml
	// in every configured private repo. The private fallback is what catches
	// internal Nexus/Artifactory artifacts that aren't on Central.
	try {
		const url = `https://search.maven.org/solrsearch/select?q=g:%22${encodeURIComponent(groupId)}%22+AND+a:%22${encodeURIComponent(artifactId)}%22&core=gav&rows=1&wt=json`;
		const res = await fetch(url, { headers: { "User-Agent": "fad-checker-outdated-checker" } });
		if (res.ok) {
			const json = await res.json();
			const doc = json?.response?.docs?.[0];
			if (doc) {
				const entry = { latest: doc.v, releaseDate: doc.timestamp ? new Date(doc.timestamp).toISOString().slice(0, 10) : null, source: "central" };
				cache.entries[key] = entry;
				return entry;
			}
		}
	} catch { /* fall through to repo metadata */ }

	if (Array.isArray(opts.repos) && opts.repos.length) {
		try {
			const { fetchMavenMetadata } = require("./maven-repo");
			const hit = await fetchMavenMetadata(opts.repos, groupId, artifactId, { userAgent: "fad-checker-outdated-checker" });
			if (hit?.body) {
				const latest = parseMavenMetadataLatest(hit.body);
				if (latest) {
					const entry = { latest, releaseDate: null, source: hit.repo.name || hit.repo.url };
					cache.entries[key] = entry;
					return entry;
				}
			}
		} catch { /* swallow */ }
	}
	cache.entries[key] = { error: "not found" };
	return cache.entries[key];
}

/**
 * Pull the "latest" version from a maven-metadata.xml body. Prefers
 * <versioning><release> (stable), falls back to <versioning><latest> and
 * then the highest entry in <versioning><versions>.
 */
function parseMavenMetadataLatest(xml) {
	if (!xml) return null;
	const release = xml.match(/<release>([^<]+)<\/release>/);
	if (release?.[1]) return release[1].trim();
	const latest = xml.match(/<latest>([^<]+)<\/latest>/);
	if (latest?.[1]) return latest[1].trim();
	const versions = [...xml.matchAll(/<version>([^<]+)<\/version>/g)].map(m => m[1].trim()).filter(Boolean);
	if (versions.length) {
		try { versions.sort((a, b) => compareMavenVersions(a, b)); return versions[versions.length - 1]; }
		catch { return versions[versions.length - 1]; }
	}
	return null;
}

async function checkOutdatedDeps(resolvedDeps, opts = {}) {
	const { verbose, offline, concurrency = 8, repos, onProgress } = opts;
	const cache = loadJsonCache(VERSION_CACHE_PATH);
	const fresh = cache.meta?.fetchedAt && (Date.now() - cache.meta.fetchedAt) < VERSION_CACHE_MAX_AGE_MS;
	if (!fresh && !offline) cache.entries = {};
	// Maven Central only — npm/composer/pypi/nuget have their own registries (codec.checkRegistry).
	const list = [...resolvedDeps.values()].filter(d => d.version && !/\$\{|SNAPSHOT/i.test(d.version) && d.ecosystem === "maven");
	const results = [];

	// Progress indicator — Maven Central can serve hundreds of deps in a few
	// seconds with 8-way concurrency, but on first run (cold cache) the user
	// would see total silence for 20-60s.
	const liveCount = offline ? 0 : list.filter(d => !cache.entries[`${d.groupId}:${d.artifactId}`]).length;
	if (liveCount && !offline && !onProgress) {
		console.log(`📅 Outdated: checking ${list.length} deps against Maven Central (${liveCount} live, ${list.length - liveCount} cached)…`);
	}

	let cursor = 0;
	let processed = 0;
	const startedAt = Date.now();
	const printOutdatedProgress = (final = false) => {
		if (onProgress) { onProgress(processed, list.length); return; }
		if (!liveCount) return;
		const elapsed = Math.round((Date.now() - startedAt) / 1000);
		const pct = Math.round((processed / list.length) * 100);
		const line = `   outdated: ${processed}/${list.length} (${pct}%) — ${elapsed}s`;
		if (process.stdout.isTTY) process.stdout.write(`\r${line}${final ? "\n" : "          "}`);
		else if (final) console.log(line);
	};
	const workers = Array.from({ length: concurrency }, async () => {
		while (cursor < list.length) {
			const dep = list[cursor++];
			const entry = await fetchLatestVersion(dep.groupId, dep.artifactId, cache, { offline, repos });
			processed++;
			if (processed % 10 === 0 || processed === list.length) printOutdatedProgress();
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
	if (liveCount) printOutdatedProgress(true);

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
	findCycleForVersion,
	isEol,
	isEolCacheFresh,
	EOL_MAPPING,
	EOL_CACHE_PATH,
	KNOWN_OBSOLETE,
	loadJsonCache,
	saveJsonCache,
	CACHE_DIR,
};
