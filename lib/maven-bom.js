/**
 * lib/maven-bom.js — resolve EXTERNAL import-scope BOMs (e.g. spring-boot-dependencies)
 * from Maven Central and backfill the versions of declared deps that the BOM manages.
 *
 * core.js follows LOCAL `<scope>import</scope>` BOMs (their POM is in the source tree)
 * but cannot enumerate an external BOM's managed-version table without fetching it. So
 * in a typical Spring Boot project every `spring-boot-starter-*` (declared without a
 * version, version pinned by the imported BOM) ends up unresolved — flooding chapter 0
 * and dropping out of the CVE/EOL/outdated scans.
 *
 * This module fetches each external import BOM via transitive.js#effectivePom (which
 * already merges the parent chain, resolves `${properties}` and recursively expands
 * nested import BOMs), builds a g:a → version map, and fills it into the versionless
 * declared deps. Network + cached (poms-cache, immutable) + offline-aware (the caller
 * skips it offline). Pure except for the injected/real effectivePom fetch.
 */
const transitive = require("./transitive");

/**
 * Extract the distinct external import-BOM coordinates from the parsed poms' merged
 * dependencyManagement. `version` is resolved against each pom's property map; entries
 * that stay unresolved (`${…}`) or lack a g/a are skipped.
 * @param propsByPom map pomPath → { properties, dependencyManagement } (xml2js-shaped)
 * @returns [{ groupId, artifactId, version }] deduped by g:a:v
 */
function collectImportBoms(propsByPom) {
	const seen = new Set();
	const out = [];
	for (const pom of Object.keys(propsByPom || {})) {
		const entry = propsByPom[pom];
		if (!entry) continue;
		const props = entry.properties || {};
		for (const d of (entry.dependencyManagement || [])) {
			if (d?.scope?.[0] !== "import") continue;
			const g = transitive.resolveProps(d.groupId?.[0], props);
			const a = transitive.resolveProps(d.artifactId?.[0], props);
			const v = transitive.resolveProps(d.version?.[0], props);
			if (!g || !a || !v || /\$\{/.test(String(v))) continue;
			const k = `${g}:${a}:${v}`;
			if (seen.has(k)) continue;
			seen.add(k);
			out.push({ groupId: g, artifactId: a, version: v });
		}
	}
	return out;
}

/**
 * Resolve each import BOM to its managed-version table and merge them into one map.
 * First BOM to manage a given g:a wins (mirrors Maven's declaration-order precedence).
 */
async function resolveBomManagedVersions(boms, opts = {}) {
	const effectivePom = opts.effectivePom || transitive.effectivePom;
	const map = new Map();
	for (const bom of boms) {
		let eff = null;
		try { eff = await effectivePom(bom.groupId, bom.artifactId, bom.version, opts); }
		catch { eff = null; }
		if (!eff || !eff.depMgmt) continue;
		for (const d of eff.depMgmt) {
			if (!d.groupId || !d.artifactId) continue;
			const k = `${d.groupId}:${d.artifactId}`;
			if (map.has(k)) continue;
			if (d.version && !/\$\{/.test(String(d.version))) map.set(k, String(d.version));
		}
	}
	return map;
}

/**
 * Fill the version of every Maven dep that has no concrete version (null or `${…}`)
 * from the BOM-managed map. Mutates the resolvedDeps Map entries in place.
 * @returns number of deps filled
 */
function backfillVersions(resolvedDeps, mgmtMap) {
	let filled = 0;
	for (const dep of resolvedDeps.values()) {
		if (dep.ecosystem !== "maven") continue;
		if (dep.provenance === "embedded" || dep.provenance === "binary") continue;
		if (dep.version && !/\$\{/.test(String(dep.version))) continue; // already concrete
		const v = mgmtMap.get(`${dep.groupId}:${dep.artifactId}`);
		if (!v) continue;
		dep.version = v;
		if (!Array.isArray(dep.versions)) dep.versions = [];
		if (!dep.versions.includes(v)) dep.versions.push(v);
		filled++;
	}
	return filled;
}

/**
 * One-shot: collect external import BOMs from the poms, resolve their managed versions
 * online, and backfill the versionless declared deps.
 * @returns { boms, filled, mgmtSize }
 */
async function resolveAndBackfill(propsByPom, resolvedDeps, opts = {}) {
	const boms = collectImportBoms(propsByPom);
	if (!boms.length) return { boms: 0, filled: 0, mgmtSize: 0 };
	const map = await resolveBomManagedVersions(boms, opts);
	const filled = backfillVersions(resolvedDeps, map);
	return { boms: boms.length, filled, mgmtSize: map.size };
}

module.exports = { collectImportBoms, resolveBomManagedVersions, backfillVersions, resolveAndBackfill };
