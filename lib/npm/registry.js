/**
 * lib/npm/registry.js — npm registry queries for the npm half of the
 * EOL/obsolete/outdated story.
 *
 * Two authoritative, online signals come from one packument fetch:
 *   - deprecated: the maintainer's `deprecated` string on the *resolved*
 *     version (the same data behind `npm WARN deprecated …`).
 *   - outdated:   `dist-tags.latest` vs. the resolved version.
 *
 * The point of querying the registry rather than a curated list is to skip
 * nothing: every npm dep is checked against the source of truth.
 *
 * `packumentToFindings` is the pure extractor (unit-tested without network);
 * `checkNpmRegistryDeps` is the cached, concurrent driver.
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const pLimit = require("p-limit");
const { semverCompare } = require("./collect");

const CACHE_DIR = path.join(os.homedir(), ".fad-checker");
const CACHE_PATH = path.join(CACHE_DIR, "npm-registry-cache.json");
const CACHE_MAX_AGE_MS = 24 * 3600 * 1000; // 1 day, aligned with Maven Central
const REGISTRY = "https://registry.npmjs.org";

function loadCache() {
	try { return JSON.parse(fs.readFileSync(CACHE_PATH, "utf8")); }
	catch { return { meta: { fetchedAt: 0 }, entries: {} }; }
}

function saveCache(data) {
	try {
		fs.mkdirSync(CACHE_DIR, { recursive: true });
		fs.writeFileSync(CACHE_PATH, JSON.stringify(data));
	} catch { /* ignore */ }
}

/** Pull a recommended replacement out of a free-form deprecation message. */
function replacementFromMessage(msg) {
	if (!msg) return null;
	const url = msg.match(/https?:\/\/\S+/);
	if (url) return url[0].replace(/[).,]+$/, "");
	return "see deprecation notice";
}

/**
 * Extract { deprecated, outdated } findings for one dep from its packument.
 * Pure — no network, no cache. Either field is null when not applicable.
 */
function packumentToFindings(packument, dep) {
	const out = { deprecated: null, outdated: null };
	if (!packument || typeof packument !== "object") return out;

	const versionEntry = packument.versions?.[dep.version];
	const depMsg = versionEntry && typeof versionEntry.deprecated === "string"
		? versionEntry.deprecated.trim()
		: "";
	if (depMsg) {
		out.deprecated = {
			dep,
			severity: "MEDIUM",
			replacement: replacementFromMessage(depMsg),
			reason: depMsg,
			source: "npm",
		};
	}

	const latest = packument["dist-tags"]?.latest;
	if (latest && dep.version) {
		let behind = false;
		try { behind = semverCompare(dep.version, latest) < 0; }
		catch { behind = false; }
		if (behind) {
			const t = packument.time?.[latest];
			out.outdated = {
				dep,
				latest,
				releaseDate: typeof t === "string" ? t.slice(0, 10) : null,
			};
		}
	}
	return out;
}

/** registry.npmjs.org path-encodes a scoped name's slash. */
function packumentUrl(name) {
	return name.startsWith("@")
		? `${REGISTRY}/${name.replace("/", "%2F")}`
		: `${REGISTRY}/${encodeURIComponent(name)}`;
}

async function fetchPackument(name, opts = {}) {
	if (opts.offline) return null;
	try {
		const res = await fetch(packumentUrl(name), {
			headers: { "User-Agent": "fad-checker-npm-registry", Accept: "application/json" },
		});
		if (!res.ok) return { error: `HTTP ${res.status}` };
		return await res.json();
	} catch (err) {
		return { error: err.message };
	}
}

/**
 * Check every npm dep against the registry.
 *
 * Returns { deprecated: [obsolete-shaped], outdated: [outdated-shaped] }.
 * Deprecation always runs (online); outdated is only collected when allLibs
 * is set, mirroring the Maven Central outdated gate (--no-all-libs).
 *
 * opts: { verbose, offline, allLibs, concurrency = 8 }
 */
async function checkNpmRegistryDeps(resolvedDeps, opts = {}) {
	const { verbose, offline, allLibs = true, concurrency = 8 } = opts;
	const npmDeps = [...resolvedDeps.values()].filter(
		d => d.ecosystem === "npm" && d.version,
	);
	const result = { deprecated: [], outdated: [] };
	if (!npmDeps.length) return result;

	const cache = loadCache();
	const fresh = cache.meta?.fetchedAt && (Date.now() - cache.meta.fetchedAt) < CACHE_MAX_AGE_MS;
	if (!fresh && !offline) cache.entries = {};

	const liveCount = offline ? 0 : npmDeps.filter(d => !cache.entries[`${d.artifactId}@${d.version}`]).length;
	if (liveCount && !offline) {
		console.log(`📦 npm registry: checking ${npmDeps.length} packages for deprecation${allLibs ? " + outdated" : ""} (${liveCount} live, ${npmDeps.length - liveCount} cached)…`);
	}

	const limit = pLimit(concurrency);
	let processed = 0;
	await Promise.all(npmDeps.map(dep => limit(async () => {
		const key = `${dep.artifactId}@${dep.version}`;
		let extracted = cache.entries[key];
		if (!extracted) {
			const packument = await fetchPackument(dep.artifactId, { offline });
			if (packument && !packument.error) {
				const f = packumentToFindings(packument, dep);
				extracted = {
					deprecated: f.deprecated ? { reason: f.deprecated.reason, replacement: f.deprecated.replacement } : null,
					latest: f.outdated ? f.outdated.latest : null,
					latestDate: f.outdated ? f.outdated.releaseDate : null,
				};
				cache.entries[key] = extracted;
			} else {
				extracted = { deprecated: null, latest: null, latestDate: null, error: packument?.error || "no data" };
				if (!offline) cache.entries[key] = extracted;
			}
		}
		processed++;
		if (extracted.deprecated) {
			result.deprecated.push({
				dep,
				severity: "MEDIUM",
				replacement: extracted.deprecated.replacement,
				reason: extracted.deprecated.reason,
				source: "npm",
			});
			if (verbose) process.stdout.write(`  deprecated: npm:${dep.artifactId}@${dep.version}\n`);
		}
		if (allLibs && extracted.latest) {
			result.outdated.push({ dep, latest: extracted.latest, releaseDate: extracted.latestDate || null });
			if (verbose) process.stdout.write(`  outdated: npm:${dep.artifactId} ${dep.version} → ${extracted.latest}\n`);
		}
	})));

	cache.meta = { fetchedAt: Date.now() };
	saveCache(cache);

	result.deprecated.sort((a, b) => a.dep.artifactId.localeCompare(b.dep.artifactId));
	result.outdated.sort((a, b) => a.dep.artifactId.localeCompare(b.dep.artifactId));
	if (liveCount && !offline) console.log(`   npm registry: ${result.deprecated.length} deprecated, ${result.outdated.length} outdated`);
	return result;
}

module.exports = { packumentToFindings, checkNpmRegistryDeps, replacementFromMessage };
