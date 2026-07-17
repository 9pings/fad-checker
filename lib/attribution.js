/**
 * lib/attribution.js — attribute each MATCH to the manifest/module that actually
 * resolves the version it was matched on.
 *
 * A depRecord is COORD-WIDE: the collectors merge every occurrence of a g:a across the
 * whole scan root into ONE record, so `versions[]` and `manifestPaths[]` are both
 * coord-wide sets with no link between them, and `scope` is a single merged value. A
 * MATCH, by contrast, carries exactly ONE version (matchOne clones the record per
 * version). Left alone that clone inherits the coord-wide manifest list and the merged
 * scope — so every version is reported against every manifest holding the coord.
 *
 * Invisible on a single reactor; wrong on the real-world shape fad is pointed at: an
 * audit root holding SEVERAL INDEPENDENT projects (each pom with its own external
 * parent, no shared reactor). Project A pins jackson-databind 2.15.3, project B pins
 * 2.17.0 → both projects get reported as holding BOTH versions, and each version's CVEs
 * land on both. Same class of error for a version the per-module overlay recovered: it
 * is a TRANSITIVE of one module, not the direct declaration the record describes —
 * unattributed it tops the exec summary's "direct production dependencies" pointing at
 * the very pom that pins the fixed version.
 *
 * Two provenance sources, checked per match:
 *   - `maskedVersions[]` (lib/version-overlay) — the version is a transitive of ONE
 *     module: re-stamp scope/via/depth and file it under that module.
 *   - `versionPaths{}` (lib/dep-record, maintained by the collectors) — the version is
 *     DECLARED in a known subset of manifests: narrow the match to that subset.
 * A version with neither (e.g. a global-pass transitive) is left untouched.
 *
 * Runs ONCE, after every match source is merged (CVE index, OSV, snyk) and before
 * anything reads scope/paths (exec summary, charts, chapters, exports, gate).
 * Pure w.r.t. the scan set: replaces `m.dep` with a clone, never mutating the shared
 * record — other matches still reference it.
 */

/** manifestPaths and pomPaths must stay the SAME array (dep-record.js invariant). */
function withPaths(dep, paths) {
	const p = paths.slice();
	return { ...dep, manifestPaths: p, pomPaths: p };
}

function sameList(a, b) {
	const x = a || [], y = b || [];
	return x.length === y.length && x.every((v, i) => v === y[i]);
}

/**
 * @param matches the merged match set (mutated: each m.dep may be replaced by a clone)
 * @returns number of matches re-attributed
 */
function attributeMatchOrigins(matches) {
	let fixed = 0;
	for (const m of matches || []) {
		const dep = m && m.dep;
		if (!dep || !dep.version) continue;
		const ver = String(dep.version);

		// 1. Recovered by the per-module overlay → a transitive of ONE module.
		const masked = dep.scope !== "transitive" && Array.isArray(dep.maskedVersions)
			? dep.maskedVersions.find(x => String(x.version) === ver)
			: null;
		if (masked) {
			m.dep = {
				...withPaths(dep, masked.module ? [masked.module] : []),
				scope: "transitive",
				via: masked.via || [],
				viaPaths: masked.viaPaths || (masked.via ? [masked.via] : []),
				depth: masked.depth,
			};
			fixed++;
			continue;
		}

		// 2. Declared → narrow to the manifest(s) that declare THIS version.
		const declared = dep.versionPaths && dep.versionPaths[ver];
		if (Array.isArray(declared) && declared.length && !sameList(declared, dep.manifestPaths)) {
			m.dep = withPaths(dep, declared);
			fixed++;
		}
	}
	return fixed;
}

module.exports = { attributeMatchOrigins };
