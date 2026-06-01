/**
 * lib/cpe.js — CPE 2.3 parsing + matching of NVD configuration trees.
 *
 * CPE 2.3 URI binding:
 *   cpe:2.3:part:vendor:product:version:update:edition:language:
 *           sw_edition:target_sw:target_hw:other
 * Each field can be a literal, "*" (ANY) or "-" (NA). Some characters
 * are percent-encoded, we only need to undo "\:" and "\\" for the
 * fields we read.
 *
 * Used in two directions:
 *   1. Given a NVD-enriched match (cve.cpes[] + cve.configurations[]),
 *      decide whether a dep is _truly_ affected (version range check)
 *      and whether we can upgrade the match confidence.
 *   2. Given a dep coord, find CVEs in the index whose CPE configurations
 *      it satisfies. (Future use — kept compatible with the data shape.)
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { compareMavenVersions } = require("./maven-version");

let CPE_COORD_MAP_CACHE = null;
function loadCpeCoordMap() {
	if (CPE_COORD_MAP_CACHE) return CPE_COORD_MAP_CACHE;
	try {
		CPE_COORD_MAP_CACHE = require("../data/cpe-coord-map.json");
	} catch {
		CPE_COORD_MAP_CACHE = { byVendorProduct: {}, byProduct: {} };
	}
	return CPE_COORD_MAP_CACHE;
}

/**
 * Parse a CPE 2.3 URI. Returns null on malformed input.
 * Field order: cpe:2.3:part:vendor:product:version:update:edition:language:
 *              sw_edition:target_sw:target_hw:other
 */
function parseCpe23(uri) {
	if (typeof uri !== "string") return null;
	if (!uri.startsWith("cpe:2.3:")) return null;
	// Split on `:` but respect backslash escaping.
	const fields = [];
	let buf = "";
	for (let i = 0; i < uri.length; i++) {
		const c = uri[i];
		if (c === "\\" && i + 1 < uri.length) {
			buf += uri[i + 1]; i++;
		} else if (c === ":") {
			fields.push(buf); buf = "";
		} else {
			buf += c;
		}
	}
	fields.push(buf);
	// fields = ["cpe","2.3","a","vendor","product","version","update","edition","language","sw_edition","target_sw","target_hw","other"]
	if (fields.length < 7) return null;
	return {
		part:        fields[2] || "*",
		vendor:      fields[3] || "*",
		product:     fields[4] || "*",
		version:     fields[5] || "*",
		update:      fields[6] || "*",
		edition:     fields[7] || "*",
		language:    fields[8] || "*",
		sw_edition:  fields[9] || "*",
		target_sw:   fields[10] || "*",
		target_hw:   fields[11] || "*",
		other:       fields[12] || "*",
	};
}

// Memoize parseCpe23 on the cpeMatch object so subsequent passes (the
// confidence walk inside evaluateCveForDep) don't re-tokenize the same URI.
// `_parsedCpe` uses `null` (parse failed) vs `undefined` (not yet parsed) to
// distinguish empty result from missing cache.
function parseCpe23Cached(cpeMatch) {
	if (!cpeMatch || typeof cpeMatch !== "object") return parseCpe23(cpeMatch?.criteria || "");
	if (cpeMatch._parsedCpe !== undefined) return cpeMatch._parsedCpe;
	cpeMatch._parsedCpe = parseCpe23(cpeMatch.criteria || "");
	return cpeMatch._parsedCpe;
}

/**
 * Match a dep version against a single NVD cpeMatch entry.
 * The entry has the shape:
 *   { criteria: "cpe:2.3:a:vendor:product:version:...",
 *     vulnerable: true,
 *     versionStartIncluding, versionStartExcluding,
 *     versionEndIncluding,   versionEndExcluding }
 *
 * Returns true if `depVersion` is in range. If the CPE itself pins a
 * concrete version (criteria's version field != "*"/"-"), that pin wins.
 */
function matchVersionRange(depVersion, cpeMatch) {
	if (!cpeMatch) return false;
	if (!depVersion) return true; // unknown version → assume affected
	const parsed = parseCpe23Cached(cpeMatch);
	if (!parsed) return false;

	// Hard pin in the criteria URI itself
	if (parsed.version && parsed.version !== "*" && parsed.version !== "-") {
		// CPE 2.3 update field qualifies the version (`:1.0.0:beta1:` ≡ `1.0.0-beta1`).
		// Without folding it in, a release like 1.0.0 would incorrectly match a pin
		// of 1.0.0:rc1 — see H5 in CRITICAL-REVIEW.md.
		const pinned = (parsed.update && parsed.update !== "*" && parsed.update !== "-")
			? `${parsed.version}-${parsed.update}`
			: parsed.version;
		try { return compareMavenVersions(depVersion, pinned) === 0; }
		catch { return false; }
	}

	try {
		if (cpeMatch.versionStartIncluding && compareMavenVersions(depVersion, cpeMatch.versionStartIncluding) < 0) return false;
		if (cpeMatch.versionStartExcluding && compareMavenVersions(depVersion, cpeMatch.versionStartExcluding) <= 0) return false;
		if (cpeMatch.versionEndIncluding && compareMavenVersions(depVersion, cpeMatch.versionEndIncluding) > 0) return false;
		if (cpeMatch.versionEndExcluding && compareMavenVersions(depVersion, cpeMatch.versionEndExcluding) >= 0) return false;
	} catch { return false; }
	return true;
}

/**
 * Evaluate a node (OR/AND of cpeMatch entries). For our use we only care
 * about the `vulnerable` matches — "AND runs on Windows" runtime context
 * is ignored on purpose: we assume the library is being _used_, so any
 * vulnerable-marked CPE that matches the dep version is a real hit.
 *
 * Returns true if any vulnerable cpeMatch in the node matches the dep.
 */
function nodeAffectsDep(node, dep, cpeCoordMap) {
	if (!node) return false;
	const matches = node.cpeMatch || node.cpe_match || [];
	for (const m of matches) {
		if (m.vulnerable === false) continue;
		const parsed = parseCpe23Cached(m);
		if (!parsed) continue;
		if (!cpeMatchesDep(parsed, dep, cpeCoordMap)) continue;
		if (!matchVersionRange(dep.version, m)) continue;
		return true;
	}
	// Recurse into children (NVD nests AND/OR nodes)
	if (Array.isArray(node.children)) {
		for (const child of node.children) {
			if (nodeAffectsDep(child, dep, cpeCoordMap)) return true;
		}
	}
	return false;
}

/**
 * A node is "context-only" when it carries no vulnerable cpeMatch (recursively) —
 * e.g. the "…AND runs on linux_kernel" platform node, whose CPEs are all
 * `vulnerable: false`. In an AND configuration those nodes are runtime context we
 * deliberately ignore (we assume the library is in use), so they must NOT be
 * required for the config to count as affecting the dep.
 */
function nodeIsContextOnly(node) {
	if (!node) return true;
	const matches = node.cpeMatch || node.cpe_match || [];
	if (matches.some(m => m.vulnerable !== false)) return false;
	if (Array.isArray(node.children) && node.children.some(c => !nodeIsContextOnly(c))) return false;
	return true;
}

/**
 * Decide whether a CPE (parsed) refers to the same artifact as a dep.
 * Lookup order:
 *   1. Curated map `byVendorProduct["vendor:product"]` — array of dep keys
 *      (maven "g:a" or "npm:name"). Exact, high confidence.
 *   2. Curated map `byProduct[product]` — same shape, used when vendor is
 *      ambiguous (Apache wraps several groupIds).
 *   3. Heuristic: vendor token appears in groupId, or groupId/artifactId
 *      equals/contains product. Same logic as cve-match.vendorMatchesGroup
 *      but kept local here so cpe.js is standalone.
 */
function cpeMatchesDep(cpe, dep, cpeCoordMap) {
	if (!cpe || !dep) return false;
	if (cpe.part !== "a" && cpe.part !== "*") return false; // we only care about apps
	const map = cpeCoordMap || loadCpeCoordMap();
	const vp = `${cpe.vendor}:${cpe.product}`.toLowerCase();
	const depKey = depToKey(dep).toLowerCase();
	const altKey = altDepKey(dep).toLowerCase();

	const inList = arr => Array.isArray(arr) && arr.some(k => {
		const lk = String(k).toLowerCase();
		return lk === depKey || lk === altKey;
	});

	if (inList(map.byVendorProduct?.[vp])) return true;
	if (inList(map.byProduct?.[cpe.product?.toLowerCase()])) return true;

	// Heuristic fallback
	if (dep.ecosystem === "npm") {
		const name = (dep.artifactId || "").toLowerCase();
		if (cpe.product?.toLowerCase() === name) return true;
		// scoped packages: @scope/name → CPE vendor="scope", product="name"
		const m = name.match(/^@([^/]+)\/(.+)$/);
		if (m && cpe.vendor?.toLowerCase() === m[1] && cpe.product?.toLowerCase() === m[2]) return true;
	} else {
		const g = (dep.groupId || "").toLowerCase();
		const a = (dep.artifactId || "").toLowerCase();
		const v = (cpe.vendor || "").toLowerCase();
		const p = (cpe.product || "").toLowerCase();
		if (p !== a) return false;
		if (g === v) return true;
		// Mirrors vendorMatchesGroup: dot-segment membership only, no substring
		// fallback. Unbounded substring matching leaked FPs (M4 in CRITICAL-REVIEW.md).
		if (g.split(".").includes(v)) return true;
	}
	return false;
}

function depToKey(dep) {
	if (dep.ecosystem === "npm") return `npm:${dep.artifactId}`;
	return `${dep.groupId}:${dep.artifactId}`;
}
function altDepKey(dep) {
	// For artifactId-only matching against curated lists keyed by artifact-only.
	return dep.ecosystem === "npm" ? `npm:${dep.artifactId}` : dep.artifactId || "";
}

/**
 * Run the CPE configurations of `cveRecord` against `dep`.
 * `cveRecord.configurations` follows NVD's shape. Returns:
 *   { affected: boolean, confidence: "exact" | "probable" | null }
 *
 * - "exact" when a curated mapping confirms vendor:product → dep
 * - "probable" when only heuristic matched
 */
function evaluateCveForDep(cveRecord, dep, cpeCoordMap) {
	const map = cpeCoordMap || loadCpeCoordMap();
	const configs = cveRecord?.configurations || [];
	let bestConfidence = null;
	const note = c => {
		if (c === "exact" || bestConfidence === "exact") bestConfidence = "exact";
		else if (c === "probable") bestConfidence = bestConfidence || "probable";
	};

	for (const cfg of configs) {
		const nodes = cfg.nodes || [];
		const op = (cfg.operator || "OR").toUpperCase();
		let passes;
		if (op === "AND") {
			// AND configs are typically (vulnerable software) AND (platform/runtime
			// context). We assume the library is in use, so context-only nodes are not
			// required — only the vulnerable node(s) must match the dep version. Without
			// this, a "vulnerable:false" platform node makes .every() false and the real
			// finding is wrongly dropped as a CPE false-positive.
			const vulnNodes = nodes.filter(n => !nodeIsContextOnly(n));
			passes = vulnNodes.length > 0 && vulnNodes.every(n => nodeAffectsDep(n, dep, map));
		} else {
			passes = nodes.some(n => nodeAffectsDep(n, dep, map));
		}
		if (passes) {
			// Determine confidence: scan vulnerable cpeMatches that hit
			for (const n of nodes) {
				for (const m of n.cpeMatch || n.cpe_match || []) {
					if (m.vulnerable === false) continue;
					const parsed = parseCpe23Cached(m);
					if (!parsed) continue;
					if (!cpeMatchesDep(parsed, dep, map)) continue;
					if (!matchVersionRange(dep.version, m)) continue;
					const vp = `${parsed.vendor}:${parsed.product}`.toLowerCase();
					const depKey = depToKey(dep).toLowerCase();
					const curated = (map.byVendorProduct?.[vp] || []).some(k => String(k).toLowerCase() === depKey);
					note(curated ? "exact" : "probable");
				}
			}
		}
	}

	// Fallback: no configurations[] (some NVD records only have cpes[]).
	// We accept a hit if any CPE string matches the dep coord — but with no
	// version range info, we can only say "possible" (caller's existing
	// confidence stays unless we can prove version match).
	if (!configs.length && Array.isArray(cveRecord?.cpes)) {
		for (const uri of cveRecord.cpes) {
			const parsed = parseCpe23(uri);
			if (!parsed) continue;
			if (cpeMatchesDep(parsed, dep, map)) {
				note("probable");
				break;
			}
		}
	}

	return { affected: bestConfidence !== null, confidence: bestConfidence };
}

/**
 * Walk an enriched matches list and refine each entry using NVD CPE data.
 * Mutates each match in place:
 *   - sets m.cpeConfidence = "exact" | "probable" | null
 *   - if NVD configurations include version ranges that the dep version does NOT
 *     satisfy AND no other configuration places it in scope, sets
 *     m.cpeFiltered = true so the report can mark it as "likely false positive".
 *   - upgrades m.confidence from "possible" → "probable", "probable" → "exact"
 *     when the CPE side confirms with curated mapping.
 *
 * Note: m.cve.configurations is only present on NVD-enriched records. If
 * absent, we still try m.cve.cpes[] (URI list) for vendor:product matching.
 */
function refineMatchesWithCpe(matches, opts = {}) {
	const map = opts.cpeCoordMap || loadCpeCoordMap();
	for (const m of matches) {
		const cve = m.cve || {};
		// Build a tiny record shape that evaluateCveForDep accepts
		const rec = { configurations: cve.configurations || [], cpes: cve.cpes || [] };
		if (!rec.configurations.length && !rec.cpes.length) continue;
		const { affected, confidence } = evaluateCveForDep(rec, m.dep, map);
		m.cpeConfidence = confidence;
		if (!affected && rec.configurations.length) {
			// Configurations exist but version doesn't satisfy any → likely FP
			m.cpeFiltered = true;
		}
		if (affected && confidence === "exact" && m.confidence !== "exact") m.confidence = "exact";
		else if (affected && confidence === "probable" && m.confidence === "possible") m.confidence = "probable";
	}
	return matches;
}

module.exports = {
	parseCpe23,
	matchVersionRange,
	cpeMatchesDep,
	nodeAffectsDep,
	evaluateCveForDep,
	refineMatchesWithCpe,
	loadCpeCoordMap,
};
