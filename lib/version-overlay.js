/**
 * lib/version-overlay.js — recover transitive dependency versions that Maven's
 * PER-MODULE mediation keeps but fad's GLOBAL transitive pass masks.
 *
 * The problem: `expandWithTransitives` (cve-match.js) resolves the whole reactor as
 * ONE tree with ONE global `rootDepMgmt` (the highest version of every coord seen
 * anywhere). So a `<dependencyManagement>` pin in module A is force-applied to a
 * transitive of the unrelated module B — e.g. `controller` pins poi 5.4.1 and the
 * stress-tests island's `jmeter → poi 3.11` gets rewritten to 5.4.1, hiding
 * CVE-2017-12626. Maven applies depMgmt only inside the subtree that declares it.
 *
 * The fix (additive overlay): keep the global pass UNCHANGED as the base (no
 * regression), then re-resolve EACH module independently with ONLY that module's
 * own effective depMgmt (its local parent chain + its external parent/import-BOMs),
 * and APPEND any (g:a, version) it finds that isn't already in the coord's
 * `versions[]`. Never removes, never reseeds — so it can only ADD coverage, and the
 * per-module version it finds is the one genuinely on that module's classpath
 * (so it's a true positive, not a force-elevated one).
 *
 * Offline-aware (cache-first via transitive.js#fetchPom) and memoised across modules
 * with a shared `effCache` so 25 modules stay fast.
 */
const core = require("./core");
const { resolveTransitiveDeps, effectivePom } = require("./transitive");
const { resolveDepVersion } = require("./cve-match");

const coord = core.coord;
const isConcrete = v => v != null && !/\$\{/.test(String(v));

/** xml2js dependency node → flat descriptor (groupId/artifactId/version/scope/…). */
function flattenDep(d) {
	return {
		groupId: coord(d.groupId?.[0]),
		artifactId: coord(d.artifactId?.[0]),
		rawVersion: coord(d.version?.[0]),
		scope: coord(d.scope?.[0]) || "compile",
		optional: d.optional?.[0] === "true",
		isImport: d.scope?.[0] === "import",
		exclusions: (d.exclusions?.[0]?.exclusion || []).map(e => ({
			groupId: coord(e.groupId?.[0]),
			artifactId: coord(e.artifactId?.[0]),
		})),
	};
}

/**
 * Walk a module's LOCAL parent chain (child first). Stops at the first external
 * parent (one not present in the source tree) and reports it separately, so the
 * caller can resolve its managed table from Maven Central.
 * @returns { chain: [pomPath, parentPath, …], externalParent: {groupId,artifactId,version}|null }
 */
function localChain(pomPath, store) {
	const chain = [];
	const seen = new Set();
	let cur = pomPath;
	let externalParent = null;
	while (cur && !seen.has(cur)) {
		seen.add(cur);
		chain.push(cur);
		const meta = store.byPath[cur];
		if (!meta) break;
		const parentPath = core.resolveParentPath(cur, meta.parentInfo, store);
		if (!parentPath) {
			const p = meta.parentInfo;
			if (p?.groupId && p?.artifactId && p?.version) externalParent = { groupId: p.groupId, artifactId: p.artifactId, version: p.version };
			break;
		}
		cur = parentPath;
	}
	return { chain, externalParent };
}

/**
 * Build the EFFECTIVE managed-version map for ONE module — exactly the depMgmt that
 * Maven would apply when resolving THIS module's dependencies, and no other module's.
 * Closest-declared pin wins (set-if-absent while climbing child → parent).
 *
 * Sources, in precedence order:
 *   1. each local pom in the parent chain's own <dependencyManagement> (local
 *      scope=import BOMs are already expanded inline by core.getAllInheritedProps);
 *   2. the chain's external <parent> (e.g. spring-boot-starter-parent) managed table;
 *   3. external scope=import BOMs (e.g. spring-boot-dependencies) declared in the chain.
 * @returns Map<"g:a", version>
 */
async function buildModuleManagement(pomPath, store, propsByPom, opts = {}) {
	const map = new Map();
	const setIf = (k, v) => { if (k && isConcrete(v) && !map.has(k)) map.set(k, String(v)); };
	const { chain, externalParent } = localChain(pomPath, store);
	const externalBoms = [];

	for (const pom of chain) {
		const entry = propsByPom[pom];
		if (!entry) continue;
		const props = entry.properties || {};
		for (const node of entry.dependencyManagement || []) {
			// Interpolate ${…} in the coordinate (e.g. ${project.groupId}) like the version.
			const g = resolveDepVersion(coord(node.groupId?.[0]), props);
			const a = resolveDepVersion(coord(node.artifactId?.[0]), props);
			if (!g || !a) continue;
			const v = resolveDepVersion(coord(node.version?.[0]), props);
			if (node.scope?.[0] === "import") {
				// Local import BOMs are already expanded inline by getAllInheritedProps;
				// only chase EXTERNAL ones (not present in the source tree).
				const local = (v && store.byId[`${g}:${a}:${v}`]) || store.byId[`${g}:${a}`];
				if (!local && isConcrete(v)) externalBoms.push({ groupId: g, artifactId: a, version: v });
				continue;
			}
			setIf(`${g}:${a}`, v);
		}
	}

	// External parent + external import BOMs: pull their managed tables from Maven
	// Central (cache-first, memoised). Closest local pins already set win.
	const externals = externalParent ? [externalParent, ...externalBoms] : externalBoms;
	for (const ext of externals) {
		let eff = null;
		try { eff = await effectivePom(ext.groupId, ext.artifactId, ext.version, opts); } catch { eff = null; }
		if (eff?.depMgmt) for (const d of eff.depMgmt) setIf(`${d.groupId}:${d.artifactId}`, d.version);
	}
	return map;
}

/**
 * The direct dependencies of ONE module, with concrete versions resolved (own
 * ${properties} → module's managed map → the global resolved version). These seed
 * the per-module transitive walk.
 *
 * Includes the <dependencies> INHERITED from the local parent chain. Maven inherits
 * them into the child, where they stay DIRECT (depth-0) deps and therefore beat any
 * transitive of the same coord — but core.js#getAllInheritedProps deliberately does
 * NOT merge parent <dependencies> into propsByPom[child] (collectResolvedDeps merges
 * them globally by g:a instead). Reading only the module's own <dependencies> would
 * hide a parent-declared remediation (e.g. commons-compress:1.27.1 overriding the
 * vulnerable 1.24.0 that minio pulls in) and let the overlay "recover" the very
 * version that declaration overrides — fabricating CVEs against a version no
 * classpath holds.
 *
 * Chain is child-first, so the closest declaration of a g:a wins, like Maven. `props`
 * is the child's merged map (parent props as base, child overrides on top), which is
 * the right context for a parent-declared dep too.
 */
function buildModuleDirects(pomPath, store, propsByPom, moduleMgmt, resolvedDeps, opts = {}) {
	const entry = propsByPom[pomPath];
	if (!entry) return [];
	const props = entry.properties || {};
	const out = [];
	const seen = new Set();
	const chain = store ? localChain(pomPath, store).chain : [pomPath];
	for (const pom of chain) {
		for (const node of (propsByPom[pom] || {}).dependencies || []) {
			const d = flattenSafe(node);
			if (!d || !d.groupId || !d.artifactId || d.optional || d.isImport) continue;
			if (d.scope === "test" && !opts.includeTestDeps) continue;
			if (d.scope === "system" || d.scope === "import") continue;
			// Interpolate ${…} in the coordinate (e.g. ${project.groupId}) like the version.
			const gid = resolveDepVersion(d.groupId, props);
			const aid = resolveDepVersion(d.artifactId, props);
			const key = `${gid}:${aid}`;
			if (seen.has(key)) continue;
			let v = resolveDepVersion(d.rawVersion, props);
			if (!isConcrete(v)) v = moduleMgmt.get(key) || resolvedDeps.get(key)?.version || null;
			if (!isConcrete(v)) continue;
			seen.add(key);
			out.push({ groupId: gid, artifactId: aid, version: String(v), scope: d.scope, exclusions: d.exclusions });
		}
	}
	return out;
}
// flattenSafe guards against malformed nodes (xml2js can yield odd shapes).
function flattenSafe(node) { try { return flattenDep(node); } catch { return null; } }

/**
 * Additive per-module overlay. Mutates `resolvedDeps`: for every coord already in
 * the scan set, appends any concrete version found by a faithful per-module
 * resolution that the global pass masked. Returns a small diagnostics object incl.
 * the (g:a, version) pairs recovered (used for the false-positive measurement).
 */
async function expandPerModuleOverlay(resolvedDeps, store, propsByPom, opts = {}) {
	if (!store || !propsByPom) return { appended: 0, modules: 0, recovered: [] };
	const effCache = opts.effCache || new Map();
	const tOpts = { ...opts, effCache };
	const recovered = [];
	let modules = 0;

	for (const pomPath of Object.keys(propsByPom)) {
		const moduleMgmt = await buildModuleManagement(pomPath, store, propsByPom, tOpts);
		const directs = buildModuleDirects(pomPath, store, propsByPom, moduleMgmt, resolvedDeps, tOpts);
		if (!directs.length) continue;
		modules++;

		let trans;
		try {
			trans = await resolveTransitiveDeps(directs, {
				...tOpts,
				rootDepMgmt: moduleMgmt,
				maxDepth: opts.maxDepth || 6,
				includedScopes: ["compile", "runtime", "provided"],
			});
		} catch { continue; }

		for (const [key, t] of trans) {
			const v = t.version;
			if (!isConcrete(v)) continue;
			const existing = resolvedDeps.get(key);
			if (!existing) continue;                               // additive to coords already scanned
			if (existing.provenance === "embedded" || existing.provenance === "binary") continue;
			if (!Array.isArray(existing.versions)) existing.versions = isConcrete(existing.version) ? [existing.version] : [];
			if (existing.versions.includes(String(v))) continue;   // already scanned this version
			existing.versions.push(String(v));
			existing.maskedVersions = existing.maskedVersions || [];
			existing.maskedVersions.push({ version: String(v), via: t.via, viaPaths: t.viaPaths, module: pomPath, depth: t.depth });
			recovered.push({ coord: key, version: String(v), module: pomPath, had: existing.version });
		}
	}
	return { appended: recovered.length, modules, recovered };
}

/**
 * Re-attribute the matches whose VERSION this overlay recovered.
 *
 * `versions[]` is tree-wide per coord, but a match carries exactly ONE version. When
 * that version came from the overlay it lives in `maskedVersions[]`, which means it is
 * a TRANSITIVE of one specific module — not the direct declaration the shared record
 * describes. Left alone, such a match inherits the record's direct scope and pomPaths,
 * so a scan spanning several independent projects reports e.g. commons-compress 1.24.0
 * (really a transitive of poi-ooxml in project B) as a DIRECT dep of project A's pom —
 * the very pom that pins 1.27.1 to remediate it. The finding is real for B, but the
 * exec summary ("top critical DIRECT production dependencies") and the group-by-manifest
 * chapters both point the reader at the one manifest where it is already fixed.
 *
 * Re-stamping scope/via/depth/pomPaths from the maskedVersions entry makes every
 * consumer (exec summary, charts, chapters, exports, gate) attribute it to the module
 * that actually resolves it, and `depCell` then renders the real "transitive dN via …"
 * chain. Runs after every match source (CVE index, OSV, snyk) so all agree.
 *
 * Pure w.r.t. the scan set: replaces `m.dep` with a re-stamped clone, never mutating
 * the shared resolvedDeps record (other matches still reference it).
 * @returns number of matches re-attributed
 */
function attributeMaskedMatches(matches) {
	let fixed = 0;
	for (const m of matches || []) {
		const dep = m && m.dep;
		if (!dep || dep.scope === "transitive" || !Array.isArray(dep.maskedVersions)) continue;
		const masked = dep.maskedVersions.find(x => String(x.version) === String(dep.version));
		if (!masked) continue;   // this match is on the record's own declared version
		m.dep = {
			...dep,
			scope: "transitive",
			via: masked.via || [],
			viaPaths: masked.viaPaths || (masked.via ? [masked.via] : []),
			depth: masked.depth,
			// The module whose build actually resolves this version — so the
			// group-by-manifest chapters file it under B, not under A.
			pomPaths: masked.module ? [masked.module] : [],
			manifestPaths: masked.module ? [masked.module] : [],
		};
		fixed++;
	}
	return fixed;
}

module.exports = { expandPerModuleOverlay, buildModuleManagement, buildModuleDirects, localChain, attributeMaskedMatches };
