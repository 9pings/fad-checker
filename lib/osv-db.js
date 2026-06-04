/**
 * lib/osv-db.js — offline-COMPLETE OSV matching from a locally imported OSV database
 * (the per-ecosystem `all.zip` exports OSV.dev publishes on its public GCS bucket).
 *
 * Why this exists alongside lib/osv.js: the latter queries the OSV.dev API *per
 * dependency* and caches each response (12 h TTL). Offline, that only covers the deps
 * that happened to be queried online before — a cold dep has NO OSV data. This module
 * imports the FULL OSV database once while online (Maven = 9 MB zip, ~6.6 k advisories)
 * and matches EVERY dep against it offline, deterministically, regardless of the per-dep
 * cache. That is exactly the model OSV-Scanner uses for air-gapped scans
 * (`--download-offline-databases`), and it makes fad's offline Maven recall complete and
 * cache-independent for a PASSI engagement.
 *
 * Maven only for now: range matching needs the ecosystem's version ordering, and fad has
 * a robust Maven comparator (lib/maven-version). npm/PyPI/etc. are a documented follow-up
 * (they need semver/PEP-440 ordering). The OSV records are full OSV-schema vuln objects —
 * identical to the API — so lib/osv.js#vulnToMatch is reused verbatim.
 *
 * Online (download+index) + cached (~/.fad-checker/osv-db, 24 h) + offline-aware (loads a
 * present index, never blocks). The index travels in the cache archive automatically.
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const { unzipSync } = require("fflate");
const { compareMavenVersions } = require("./maven-version");
const { vulnToMatch } = require("./osv");

const OSV_DB_DIR = path.join(os.homedir(), ".fad-checker", "osv-db");
const BUCKET = "https://osv-vulnerabilities.storage.googleapis.com";
const TTL_MS = 24 * 3600 * 1000;
// OSV ecosystem export name per fad codec id. Maven only for now (version ordering).
const ECO = { maven: "Maven" };
const indexPath = eco => path.join(OSV_DB_DIR, `${eco}-index.json`);

/** Keep only what vulnToMatch + matching need, so the cached index stays compact. */
function trimVuln(vuln, affForPkg) {
	return {
		id: vuln.id,
		aliases: vuln.aliases || [],
		summary: vuln.summary || "",
		details: (vuln.details || "").slice(0, 2000),
		severity: vuln.severity || [],
		...(vuln.database_specific?.severity ? { database_specific: { severity: vuln.database_specific.severity } } : {}),
		references: (vuln.references || []).slice(0, 20),
		published: vuln.published || null,
		modified: vuln.modified || null,
		affected: affForPkg.map(a => ({ package: a.package, ranges: a.ranges || [], versions: a.versions || [] })),
	};
}

/** Build { byPackage: { "g:a"(lower): [trimmedVuln] }, … } from an all.zip buffer. */
function buildIndexFromZip(buf, ecosystemName) {
	const files = unzipSync(new Uint8Array(buf));
	const dec = new TextDecoder();
	const byPackage = {};
	let count = 0;
	for (const name of Object.keys(files)) {
		let vuln;
		try { vuln = JSON.parse(dec.decode(files[name])); } catch { continue; }
		if (!vuln || vuln.withdrawn) continue;
		// A vuln can list several packages; index it under each (with that package's affected slice).
		const byPkg = new Map();
		for (const a of (vuln.affected || [])) {
			if (a.package?.ecosystem !== ecosystemName) continue;
			const nm = a.package?.name;
			if (!nm) continue;
			if (!byPkg.has(nm)) byPkg.set(nm, []);
			byPkg.get(nm).push(a);
		}
		for (const [nm, affs] of byPkg) {
			const key = nm.toLowerCase();
			(byPackage[key] = byPackage[key] || []).push(trimVuln(vuln, affs));
			count++;
		}
	}
	return { _builtAt: Date.now(), ecosystem: ecosystemName, count, packages: Object.keys(byPackage).length, byPackage };
}

/**
 * Ensure the local OSV DB index for an ecosystem. Downloads + (re)builds when online and
 * stale/missing; offline (or on any network failure) loads whatever is present, else null.
 */
async function ensureOsvDb(opts = {}) {
	const { offline, refresh, verbose, fetcher = globalThis.fetch, ecosystem = "maven" } = opts;
	const ecoName = ECO[ecosystem];
	if (!ecoName) return null;
	const ip = indexPath(ecosystem);
	const loadAny = () => { try { return JSON.parse(fs.readFileSync(ip, "utf8")); } catch { return null; } };
	const loadFresh = () => { const j = loadAny(); return j && (Date.now() - (j._builtAt || 0) < TTL_MS) ? j : null; };

	if (offline) return loadAny();
	if (!refresh) { const f = loadFresh(); if (f) return f; }
	try {
		const res = await fetcher(`${BUCKET}/${ecoName}/all.zip`, { headers: { "User-Agent": "fad-checker-osv-db" } });
		if (!res || !res.ok) { if (verbose) console.warn(`osv-db: HTTP ${res?.status}`); return loadAny(); }
		const buf = Buffer.from(await res.arrayBuffer());
		const index = buildIndexFromZip(buf, ecoName);
		fs.mkdirSync(OSV_DB_DIR, { recursive: true });
		fs.writeFileSync(ip, JSON.stringify(index));
		return index;
	} catch (e) { if (verbose) console.warn(`osv-db: ${e.message}`); return loadAny(); }
}

// ---- OSV range evaluation over Maven version ordering ----
function inInterval(v, intro, upper, inclusive) {
	if (intro != null && intro !== "0" && compareMavenVersions(v, intro) < 0) return false;
	const c = compareMavenVersions(v, upper);
	return inclusive ? c <= 0 : c < 0;
}
function rangeAffects(version, range) {
	if (!range || range.type === "GIT") return false;
	let intro = null;
	for (const e of (range.events || [])) {
		if (e.introduced !== undefined) intro = e.introduced;
		else if (e.fixed !== undefined) { if (inInterval(version, intro, e.fixed, false)) return true; intro = null; }
		else if (e.last_affected !== undefined) { if (inInterval(version, intro, e.last_affected, true)) return true; intro = null; }
	}
	if (intro !== null) { // open interval [introduced, ∞)
		if (intro === "0" || compareMavenVersions(version, intro) >= 0) return true;
	}
	return false;
}
function vulnAffectsVersion(version, trimmedVuln) {
	for (const a of (trimmedVuln.affected || [])) {
		if ((a.versions || []).includes(version)) return true;
		for (const r of (a.ranges || [])) if (rangeAffects(version, r)) return true;
	}
	return false;
}

/**
 * Match resolved Maven deps against a local OSV DB index. Returns vulnToMatch-shaped
 * matches (source 'osv'), one per (coord, version, vuln). Scans every distinct version.
 */
function matchOsvDbDeps(resolvedDeps, index) {
	if (!index || !index.byPackage) return [];
	const out = [];
	const seen = new Set();
	for (const dep of resolvedDeps.values()) {
		if (dep.ecosystem !== "maven") continue;
		if (dep.provenance === "embedded" || dep.provenance === "binary") continue;
		const recs = index.byPackage[`${dep.groupId}:${dep.artifactId}`.toLowerCase()];
		if (!recs || !recs.length) continue;
		const versions = (dep.versions && dep.versions.length) ? dep.versions : [dep.version];
		for (const ver of versions) {
			if (!ver || /\$\{/.test(String(ver))) continue;
			for (const rec of recs) {
				if (!vulnAffectsVersion(ver, rec)) continue;
				const key = `${dep.groupId}:${dep.artifactId}:${ver}|${rec.id}`;
				if (seen.has(key)) continue;
				seen.add(key);
				out.push(vulnToMatch(ver === dep.version ? dep : { ...dep, version: ver }, rec));
			}
		}
	}
	return out;
}

module.exports = { ensureOsvDb, buildIndexFromZip, matchOsvDbDeps, rangeAffects, vulnAffectsVersion, OSV_DB_DIR };
