/**
 * lib/packagist-audit.js — the Packagist security-advisories lane for Composer deps.
 *
 * `composer audit` (Composer ≥ 2.4) queries `https://packagist.org/api/security-advisories/`
 * — the advisory database Packagist builds from GitHub advisories and FriendsOfPHP, keyed
 * by composer package and version constraint. fad's OSV lane misses advisories that OSV
 * carries only as CVEProject entries without Packagist coordinates (GIT/CPE ranges only):
 * measured on the real-instance corpus (2026-09-23), twig/twig CVE-2026-46636 and
 * CVE-2026-46627 (drupal 8.5.0 @1.35.0, symfony-demo @3.10.3) and knplabs/knp-snappy
 * CVE-2026-46643 (BookStack @1.4.2) were found by `composer audit` and not by OSV — this
 * lane closes that class with the official source's own data.
 *
 * Only package NAMES travel to packagist.org (never versions), exactly like the existing
 * Packagist registry pass in lib/codecs/composer/registry.js. Under `--offline` this lane
 * reads the warm cache and makes zero network calls; a dead packagist.org aborts the run
 * through the shared source-health guard.
 *
 * Advisories are cached per package in ~/.fad-checker/packagist-advisories/ (24 h TTL;
 * offline ignores the TTL, same rule as OSV/NVD: the warmed cache is the only source on
 * an air-gapped box).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");

const PACKAGIST_AUDIT_API = "https://packagist.org/api/security-advisories/";
const DEFAULT_CACHE_DIR = path.join(os.homedir(), ".fad-checker", "packagist-advisories");
const CACHE_TTL_MS = 24 * 3600 * 1000;
const BATCH_SIZE = 100;      // composer audit sends 100 packages per request; stay aligned

// "1.35.0" → { nums: [1,35,0], pre: null }; "v1.7.0-beta2" → { nums: [1,7,0], pre: "beta2" }.
// Prerelease sorts BELOW its release (semver): 1.7.0-beta2 < 1.7.0. Anything unparsable → null.
function parseComposerVersion(value) {
	const m = /^v?(\d+(?:\.\d+)*)()(?:(?:-|\.?)(alpha|beta|rc|dev)\d*|(?:[-.](\w+)))?$/i.exec(String(value ?? "").trim());
	if (!m) return null;
	const pre = (m[3] || m[4] || null) ? String(m[3] || m[4]).toLowerCase() : null;
	return { nums: m[1].split(".").map(Number), pre };
}

function cmpComposerVersions(a, b) {
	const left = parseComposerVersion(a), right = parseComposerVersion(b);
	if (!left || !right) return null;
	for (let i = 0; i < Math.max(left.nums.length, right.nums.length); i++) {
		const d = (left.nums[i] || 0) - (right.nums[i] || 0);
		if (d) return Math.sign(d);
	}
	// Branch-length padding: "1.35" == "1.35.0" for equality purposes.
	if (left.pre === right.pre) return 0;
	if (left.pre == null) return 1;   // release > prerelease
	if (right.pre == null) return -1;
	return left.pre < right.pre ? -1 : 1;
}

// The version interval a caret/tilde/wildcard/partial token covers: { min, max, kind }
// where kind "<" means max-exclusive. min is always inclusive.
function intervalOf(token) {
	let m;
	if ((m = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?$/.exec(token))) {        // bare version (maybe partial)
		if (m[3] != null) return { min: [Number(m[1]), Number(m[2]), Number(m[3])], max: [Number(m[1]), Number(m[2]), Number(m[3])], kind: "<=" };
		if (m[2] != null) return { min: [Number(m[1]), Number(m[2]), 0], max: [Number(m[1]), Number(m[2]) + 1, 0], kind: "<" };
		return { min: [Number(m[1]), 0, 0], max: [Number(m[1]) + 1, 0, 0], kind: "<" };
	}
	if ((m = /^(\d+)(?:\.(\d+))?\.\*$/.exec(token))) {                // 11.2.* / 7.*
		if (m[2] != null) return { min: [Number(m[1]), Number(m[2]), 0], max: [Number(m[1]), Number(m[2]) + 1, 0], kind: "<" };
		return { min: [Number(m[1]), 0, 0], max: [Number(m[1]) + 1, 0, 0], kind: "<" };
	}
	if ((m = /^\^(.+)$/.exec(token))) {
		const v = parseComposerVersion(m[1]);
		if (!v) return null;
		// Composer's caret advances the first nonzero specified part. In particular,
		// ^0.0.3 ends at 0.0.4, not 0.1.0.
		const bound = [...v.nums];
		const significant = bound.findIndex(n => n !== 0);
		const index = significant < 0 ? bound.length - 1 : significant;
		bound[index]++;
		for (let i = index + 1; i < bound.length; i++) bound[i] = 0;
		return { min: v.nums, max: bound, kind: "<" };
	}
	if ((m = /^~(.+)$/.exec(token))) {
		const v = parseComposerVersion(m[1]);
		if (!v) return null;
		return { min: v.nums, max: v.nums.length > 2 ? [v.nums[0], v.nums[1] + 1, 0] : [v.nums[0] + 1, 0, 0], kind: "<" };
	}
	return null;
}

// Evaluate ONE AND-group. Returns true | false | null (undecidable — never a verdict
// built on an unparsable token).
function satisfiesGroup(version, tokens) {
	let satisfied = true;
	for (const raw of tokens) {
		const tok = String(raw || "").replace(/@\w+$/i, "").trim();
		if (!tok) continue;
		if (tok === "*") continue;                       // matches everything
		let m;
		if ((m = /^(!=)\s*(.+)$/.exec(tok))) {
			const c = cmpComposerVersions(version, m[2]);
			if (c == null) return null;
			if (c === 0) satisfied = false;
			continue;
		}
		if ((m = /^(>=|<=|>|<|==|=)\s*(.+)$/.exec(tok))) {
			const c = cmpComposerVersions(version, m[2]);
			if (c == null) return null;
			const op = m[1];
			if (!(op === ">=" ? c >= 0 : op === ">" ? c > 0 : op === "<=" ? c <= 0 : op === "<" ? c < 0 : c === 0)) return false;
			continue;
		}
		if (/^[\^~]/.test(tok) || /^\d[\d.]*(?:\.\*)?$/.test(tok)) {   // ^x | ~x | exact | partial | wildcard
			const exact = /^\d+(?:\.\d+){2}$/.test(tok);               // a full version is equality
			if (exact) {
				const c = cmpComposerVersions(version, tok);
				if (c == null) return null;
				if (c !== 0) return false;
				continue;
			}
			const iv = intervalOf(tok);
			if (!iv) return null;
			const cMin = cmpComposerVersions(version, iv.min.join("."));
			const cMax = cmpComposerVersions(version, iv.max.join("."));
			if (cMin == null || cMax == null) return null;
			if (cMin < 0 || cMax > 0 || (cMax === 0 && iv.kind === "<")) return false;
			continue;
		}
		return null;                                      // unknown token: undecidable, never guessed
	}
	return satisfied;
}

/**
 * Does a concrete composer version satisfy a Packagist `affectedVersions` constraint
 * (OR of `|`/`||` branches, AND of `,`/space tokens)? → true | false | null.
 */
function satisfiesComposerConstraint(version, constraint) {
	const s = String(constraint ?? "").trim();
	if (!s) return null;
	let sawUndecidable = false;
	for (const branch of s.split(/\s*(?:\|\||\|)\s*/)) {
		const b = branch.trim();
		if (!b) continue;
		let verdict;
		const hy = /^(\S+)\s+-\s+(\S+)$/.exec(b);                     // "1.0 - 2.0" hyphen range
		if (hy) {
			const lo = cmpComposerVersions(version, hy[1]);
			const partial = /^\d+(?:\.\d+){0,1}$/.test(hy[2]);
			const upper = partial ? intervalOf(hy[2])?.max.join(".") : hy[2];
			const hi = cmpComposerVersions(version, upper);
			if (lo == null || hi == null) { sawUndecidable = true; continue; }
			verdict = lo >= 0 && (partial ? hi < 0 : hi <= 0);
		} else {
			verdict = satisfiesGroup(version, b.split(/[\s,]+/).filter(Boolean));
		}
		if (verdict === true) return true;
		if (verdict === null) sawUndecidable = true;
	}
	return sawUndecidable ? null : false;
}

/**
 * The fix version implied for `version` by the constraint: the smallest STRICT `<`
 * bound of the satisfied branch that lies above the version. `<=` and wildcards name no
 * next release — null, not a fabricated version.
 */
function fixVersionFromConstraint(version, constraint) {
	const s = String(constraint ?? "").trim();
	if (!s) return null;
	const fixes = [];
	for (const branch of s.split(/\s*(?:\|\||\|)\s*/)) {
		const b = branch.trim();
		if (!b) continue;
		if (satisfiesComposerConstraint(version, b) !== true) continue;
		for (const raw of b.split(/[\s,]+/).filter(Boolean)) {
			const m = /^<\s*(.+)$/.exec(String(raw).replace(/@\w+$/i, "").trim());
			if (!m) continue;
			const c = cmpComposerVersions(version, m[1]);
			if (c != null && c < 0) fixes.push(m[1].trim());
		}
	}
	if (!fixes.length) return null;
	return fixes.sort((x, y) => cmpComposerVersions(x, y))[0];
}

const SEVERITY_ALIASES = { moderate: "MEDIUM", important: "HIGH", severe: "HIGH", info: "LOW" };
function normalizeSeverity(raw) {
	const up = String(raw || "").trim().toUpperCase();
	return SEVERITY_ALIASES[up.toLowerCase()] || (["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(up) ? up : "UNKNOWN");
}

function cacheFileName(name) {
	const safe = String(name).toLowerCase().replace(/\/+/g, "__").replace(/[^a-z0-9._-]+/g, "%");
	return `${safe}.json`;
}

function readCache(cacheDir, name, { ignoreTtl = false } = {}) {
	const p = path.join(cacheDir, cacheFileName(name));
	try {
		const data = JSON.parse(fs.readFileSync(p, "utf8"));
		// Legacy empty entries may have come from omitted packages or malformed
		// responses, so they cannot establish a clean answer after the schema fix.
		if (Array.isArray(data.body) && (data._schema === 2 || data.body.length) &&
			(ignoreTtl || Date.now() - data._fetchedAt < CACHE_TTL_MS)) return data.body;
	} catch { /* miss */ }
	return null;
}

function writeCache(cacheDir, name, body) {
	try {
		fs.mkdirSync(cacheDir, { recursive: true });
		fs.writeFileSync(path.join(cacheDir, cacheFileName(name)), JSON.stringify({ _schema: 2, _fetchedAt: Date.now(), body }));
	} catch { /* a cache write failure must never kill the scan */ }
}

// Concrete = a resolvable version, never a range ("1.2.*", "^1.2", "dev-main", ">=5").
function isConcreteVersion(v) {
	return !!/^v?\d+(\.\d+)*$/i.test(String(v || "").trim());
}

function belongsToOtherComposerRegistry(depRecord) {
	const name = `${depRecord.namespace || ""}/${depRecord.name}`.toLowerCase();
	// Adobe distributes its product and bundled Magento packages through
	// repo.magento.com, which requires credentials. An absent Packagist record for
	// them is expected and must not be interpreted as an empty advisory list.
	return name.startsWith("magento/") || (depRecord.occurrences || [])
		.some(occurrence => occurrence.distHost === "repo.magento.com");
}

/** The best finding id: CVE over remote GHSA over the Packagist advisoryId. */
function advisoryPrimaryId(adv) {
	if (/^CVE-\d{4}-\d{4,}$/i.test(String(adv.cve || ""))) return adv.cve;
	const ghsa = advisoryAliases(adv).find(id => /^GHSA-[a-z0-9-]+$/i.test(id));
	if (ghsa) return ghsa;
	return adv.advisoryId || null;
}

function advisoryAliases(adv) {
	return [...new Set([adv.advisoryId, adv.remoteId, adv.cve,
		...(Array.isArray(adv.sources) ? adv.sources.map(source => source?.remoteId) : [])]
		.filter(value => typeof value === "string" && value.trim()))];
}

/** One advisory → a fad-checker match (the shape mergeBySource consumes). */
function advisoryToMatch(depRecord, adv) {
	const id = advisoryPrimaryId(adv);
	if (!id) return null;
	const aliases = advisoryAliases(adv);
	const ghsa = aliases.find(alias => /^GHSA-[a-z0-9-]+$/i.test(alias)) || null;
	const refs = [];
	if (/^https?:\/\//i.test(String(adv.link || ""))) refs.push({ type: "ADVISORY", url: adv.link });
	return {
		dep: depRecord,
		cve: {
			id,
			severity: normalizeSeverity(adv.severity),
			score: null,
			description: String(adv.title || "").trim(),
			summary: String(adv.title || "").trim(),
			fixVersion: fixVersionFromConstraint(depRecord.version, adv.affectedVersions),
			ghsa,
			published: adv.reportedAt || null,
			osvRefs: refs,
			aliases,
		},
		source: "packagist",
		confidence: "exact",
	};
}

/**
 * Pure: evaluate a per-package advisory map against the resolved composer deps.
 * `advisoriesByPkg` is keyed by lowercase `vendor/name` (the API response's advisories map).
 */
function collectPackagistMatches(resolvedDeps, advisoriesByPkg) {
	const matches = [];
	if (!resolvedDeps || !advisoriesByPkg) return matches;
	const byPkg = new Map();
	for (const [name, list] of Object.entries(advisoriesByPkg)) {
		if (Array.isArray(list)) byPkg.set(String(name).toLowerCase(), list);
	}
	for (const depRecord of resolvedDeps.values()) {
		if (depRecord.ecosystem !== "composer") continue;
		const pkgName = `${depRecord.namespace || ""}/${depRecord.name}`.toLowerCase();
		const advisories = byPkg.get(pkgName);
		if (!advisories || !advisories.length) continue;
		const versions = (depRecord.versions && depRecord.versions.length ? depRecord.versions : [depRecord.version])
			.filter(isConcreteVersion);
		for (const ver of versions) {
			const perVersion = { ...depRecord, version: ver };
			for (const adv of advisories) {
				if (!adv || typeof adv.affectedVersions !== "string") continue;
				if (satisfiesComposerConstraint(ver, adv.affectedVersions) !== true) continue;
				const match = advisoryToMatch(perVersion, adv);
				if (match) matches.push(match);
			}
		}
	}
	return matches;
}

/**
 * Query the Packagist security-advisories endpoint for every resolved composer dep's
 * package names, then evaluate the returned constraints per concrete version.
 * Returns fad-checker-shape matches (source: "packagist").
 */
async function queryPackagistAudit(resolvedDeps, opts = {}) {
	const { verbose, offline, fetcher = globalThis.fetch, cacheDir = DEFAULT_CACHE_DIR, onProgress, onSkipped, onUnknown } = opts;
	const advisoriesByPkg = {};
	const names = new Set();
	const skipped = new Set();
	const unknown = new Set();
	for (const depRecord of (resolvedDeps ? resolvedDeps.values() : [])) {
		if (depRecord.ecosystem !== "composer") continue;
		if (belongsToOtherComposerRegistry(depRecord)) {
			skipped.add(`${depRecord.namespace || ""}/${depRecord.name}`.toLowerCase());
			continue;
		}
		const versions = (depRecord.versions && depRecord.versions.length ? depRecord.versions : [depRecord.version]);
		if (!versions.some(isConcreteVersion)) continue;
		names.add(`${depRecord.namespace || ""}/${depRecord.name}`.toLowerCase());
	}
	if (skipped.size && onSkipped) onSkipped([...skipped].sort());
	if (!names.size) return [];

	const missing = [];
	for (const name of names) {
		const hit = readCache(cacheDir, name, { ignoreTtl: !!offline });
		if (hit !== null) advisoriesByPkg[name] = hit;
		else missing.push(name);
	}

	if (missing.length && !offline) {
		const batches = [];
		for (let i = 0; i < missing.length; i += BATCH_SIZE) batches.push(missing.slice(i, i + BATCH_SIZE));
		for (let i = 0; i < batches.length; i++) {
			if (onProgress) onProgress(i + 1, batches.length);
			else if (verbose && batches.length > 1) console.log(`   Packagist audit batch ${i + 1}/${batches.length} (${batches[i].length} packages)…`);
			const url = `${PACKAGIST_AUDIT_API}?${batches[i].map(n => `packages[]=${encodeURIComponent(n)}`).join("&")}`;
			try {
				const res = await require("./providers").getResource("packagist", "advisories", { packages: batches[i] },
					{ fetcher, headers: { "User-Agent": "fad-checker-packagist-audit", Accept: "application/json" } });
				if (!res.ok) throw new Error(`Packagist audit HTTP ${res.status}`);
				const data = await res.json();
				const got = data?.advisories;
				// PHP serializes an empty advisory map as [] when no queried package is
				// known. A non-empty list remains an invalid response.
				if (!got || typeof got !== "object" || (Array.isArray(got) && got.length))
					throw new Error("Packagist audit response is missing its advisories object");
				const byName = new Map(Object.entries(got).map(([name, list]) => [name.toLowerCase(), list]));
				// Packagist documents an omitted package as "no data". Preserve that
				// coverage gap in the report; never cache it as a clean result.
				for (const name of batches[i]) {
					if (!byName.has(name)) { unknown.add(name); continue; }
					if (!Array.isArray(byName.get(name)))
						throw new Error(`Packagist audit has invalid advisory list for ${name}`);
					if (byName.get(name).some(adv => !adv || typeof adv.advisoryId !== "string" ||
						typeof adv.affectedVersions !== "string"))
						throw new Error(`Packagist audit has invalid advisory records for ${name}`);
				}
				for (const name of batches[i]) {
					if (!byName.has(name)) continue;
					advisoriesByPkg[name] = byName.get(name);
					writeCache(cacheDir, name, advisoriesByPkg[name]);
				}
			} catch (err) {
				throw new Error(`Packagist audit batch ${i + 1}/${batches.length} failed: ${err.message}`, { cause: err });
			}
		}
	}
	if (unknown.size && onUnknown) onUnknown([...unknown].sort());

	return collectPackagistMatches(resolvedDeps, advisoriesByPkg);
}

module.exports = {
	satisfiesComposerConstraint,
	cmpComposerVersions,
	fixVersionFromConstraint,
	collectPackagistMatches,
	queryPackagistAudit,
	belongsToOtherComposerRegistry,
	PACKAGIST_AUDIT_API,
	DEFAULT_CACHE_DIR,
};
