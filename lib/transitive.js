/**
 * lib/transitive.js — resolve transitive dependencies for a set of direct deps
 * by walking POMs fetched from Maven Central.
 *
 * Implements a pragmatic subset of Maven's resolution rules:
 *   - parent POM chain (recursive)
 *   - <dependencyManagement> from parent + BOM imports (scope=import)
 *   - property substitution with project.version / project.groupId
 *   - scope propagation: compile/runtime/provided → compile/runtime/provided,
 *     test → not propagated, system → not propagated
 *   - <exclusion> blocks
 *   - <optional>true</optional> stops propagation
 *   - nearest-wins dependency mediation (BFS guarantees this naturally)
 *   - root-level dependencyManagement overrides transitive versions
 *
 * Out of scope (for simplicity / accuracy tradeoff):
 *   - <profile> activation inside transitive POMs (assumed dormant)
 *   - <relocation> handling (rare in modern artifacts)
 *   - non-central repositories (everything fetched from repo1.maven.org)
 *   - SNAPSHOT version resolution (we just return the literal version)
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const { parseStringPromise } = require("xml2js");

const POM_CACHE_DIR = path.join(os.homedir(), ".fad-checker", "poms-cache");
const MAVEN_CENTRAL = "https://repo1.maven.org/maven2";

// Maven's scope-propagation matrix (rows: direct dep scope, cols: transitive scope)
// Value is the resulting scope for the transitive, or null = not included.
const SCOPE_MATRIX = {
	compile:  { compile: "compile",  provided: null,        runtime: "runtime", test: null, system: null },
	provided: { compile: "provided", provided: null,        runtime: "provided", test: null, system: null },
	runtime:  { compile: "runtime",  provided: null,        runtime: "runtime", test: null, system: null },
	test:     { compile: "test",     provided: null,        runtime: "test",    test: null, system: null },
};

function coord(v) { return v == null ? null : String(v).trim() || null; }

function pomPath(g, a, v) {
	const gPath = g.replace(/\./g, "/");
	return `${MAVEN_CENTRAL}/${gPath}/${a}/${v}/${a}-${v}.pom`;
}

function cachePath(g, a, v, dir = POM_CACHE_DIR) {
	return path.join(dir, `${g.replace(/[/\\]/g, "_")}__${a}__${v}.pom`);
}

async function fetchPom(g, a, v, opts = {}) {
	const { verbose, offline, fetcher = globalThis.fetch, cacheDir = POM_CACHE_DIR, repos } = opts;
	const cf = cachePath(g, a, v, cacheDir);
	if (fs.existsSync(cf)) {
		const xml = await fs.promises.readFile(cf, "utf8");
		if (xml === "__NOT_FOUND__") return null;
		return xml;
	}
	if (offline) return null;
	// Multi-repo path: try every user-configured repo, fall back to Maven
	// Central via lib/maven-repo. Falling back to the legacy single-URL
	// fetch only when no repos array is passed (keeps existing tests green).
	if (Array.isArray(repos)) {
		try {
			const { fetchPomFromRepos } = require("./maven-repo");
			const hit = await fetchPomFromRepos(repos, g, a, v, { fetcher, userAgent: "fad-checker-transitive" });
			if (hit?.body) {
				await fs.promises.mkdir(cacheDir, { recursive: true });
				await fs.promises.writeFile(cf, hit.body);
				return hit.body;
			}
			await fs.promises.mkdir(cacheDir, { recursive: true });
			await fs.promises.writeFile(cf, "__NOT_FOUND__");
			if (verbose) console.warn(`   not found in any repo: ${g}:${a}:${v}`);
			return null;
		} catch (err) {
			if (verbose) console.warn(`   multi-repo fetch failed: ${g}:${a}:${v} — ${err.message}`);
			return null;
		}
	}
	const url = pomPath(g, a, v);
	try {
		const res = await fetcher(url, { headers: { "User-Agent": "fad-checker-transitive" } });
		if (res.status === 404) {
			await fs.promises.mkdir(cacheDir, { recursive: true });
			await fs.promises.writeFile(cf, "__NOT_FOUND__");
			if (verbose) console.warn(`   404: ${g}:${a}:${v}`);
			return null;
		}
		if (!res.ok) {
			if (verbose) console.warn(`   HTTP ${res.status}: ${g}:${a}:${v}`);
			return null;
		}
		const xml = await res.text();
		await fs.promises.mkdir(cacheDir, { recursive: true });
		await fs.promises.writeFile(cf, xml);
		return xml;
	} catch (err) {
		if (verbose) console.warn(`   fetch failed: ${g}:${a}:${v} — ${err.message}`);
		return null;
	}
}

/**
 * Parse a POM XML into a minimal descriptor.
 * Returns: { groupId, artifactId, version, parent, properties, deps, depMgmt }
 *   parent : { groupId, artifactId, version } | null
 *   deps   : array of { groupId, artifactId, version, scope, optional, exclusions: [{g,a}] }
 *   depMgmt: same shape as deps
 *   properties: { key: value }  (no resolution yet)
 */
async function parsePomXml(xml) {
	let json;
	try { json = await parseStringPromise(xml); }
	catch { return null; }
	const project = json?.project || {};
	const parent = project.parent?.[0];
	const parentRef = parent ? {
		groupId: coord(parent.groupId?.[0]),
		artifactId: coord(parent.artifactId?.[0]),
		version: coord(parent.version?.[0]),
	} : null;

	const groupId = coord(project.groupId?.[0]) || parentRef?.groupId || null;
	const artifactId = coord(project.artifactId?.[0]);
	const version = coord(project.version?.[0]) || parentRef?.version || null;

	const properties = {};
	const propsNode = project.properties?.[0];
	if (propsNode && typeof propsNode !== "string") {
		for (const [k, v] of Object.entries(propsNode)) {
			properties[k] = Array.isArray(v) ? v[0] : v;
		}
	}

	const readDeps = (depsBlock) => {
		if (!depsBlock?.dependency) return [];
		return depsBlock.dependency.map(d => ({
			groupId: coord(d.groupId?.[0]),
			artifactId: coord(d.artifactId?.[0]),
			version: coord(d.version?.[0]),
			scope: coord(d.scope?.[0]) || "compile",
			optional: d.optional?.[0] === "true",
			type: coord(d.type?.[0]) || "jar",
			exclusions: (d.exclusions?.[0]?.exclusion || []).map(e => ({
				groupId: coord(e.groupId?.[0]),
				artifactId: coord(e.artifactId?.[0]),
			})),
		})).filter(d => d.groupId && d.artifactId);
	};

	return {
		groupId, artifactId, version,
		parent: parentRef,
		properties,
		deps: readDeps(project.dependencies?.[0]),
		depMgmt: readDeps(project.dependencyManagement?.[0]?.dependencies?.[0]),
	};
}

/**
 * Resolve ${prop} substitutions in a string using a properties map.
 * Implements project.groupId/artifactId/version as built-ins.
 * Loops if a property references another property.
 */
function resolveProps(value, props, builtins, depth = 0) {
	if (value == null || depth > 10) return value;
	const out = String(value).replace(/\$\{\s*([\w._-]+)\s*\}/g, (m, k) => {
		if (builtins && Object.prototype.hasOwnProperty.call(builtins, k)) return builtins[k];
		if (props && Object.prototype.hasOwnProperty.call(props, k)) return resolveProps(props[k], props, builtins, depth + 1);
		return m;
	});
	return out;
}

/**
 * Build the "effective" POM for a g:a:v by walking the parent chain.
 * Merges properties, depMgmt, and deps (child overrides parent).
 * BOM imports inside depMgmt are recursively expanded.
 */
async function effectivePom(g, a, v, opts = {}, seen = new Set()) {
	const key = `${g}:${a}:${v}`;
	if (seen.has(key)) return null;
	seen.add(key);

	const xml = await fetchPom(g, a, v, opts);
	if (!xml) return null;
	const pom = await parsePomXml(xml);
	if (!pom) return null;

	let merged = {
		groupId: pom.groupId,
		artifactId: pom.artifactId,
		version: pom.version,
		properties: { ...pom.properties },
		depMgmt: [...pom.depMgmt],
		deps: [...pom.deps],
	};

	if (pom.parent) {
		const parentEff = await effectivePom(pom.parent.groupId, pom.parent.artifactId, pom.parent.version, opts, seen);
		if (parentEff) {
			merged.properties = { ...parentEff.properties, ...merged.properties };
			merged.depMgmt = [...parentEff.depMgmt, ...merged.depMgmt];
			// We do NOT inherit parent's <dependencies> declarations here — they're
			// brought in transitively when we walk the parent ITSELF if needed. But
			// Maven actually does inherit parent <dependencies>; do that:
			merged.deps = [...parentEff.deps, ...merged.deps];
		}
	}

	// Resolve property references in depMgmt and deps now that the property map
	// is finalised (child + parent merged).
	const builtins = {
		"project.groupId": merged.groupId,
		"project.artifactId": merged.artifactId,
		"project.version": merged.version,
		"pom.groupId": merged.groupId,
		"pom.artifactId": merged.artifactId,
		"pom.version": merged.version,
	};
	const resolveDep = d => ({
		...d,
		groupId: resolveProps(d.groupId, merged.properties, builtins),
		artifactId: resolveProps(d.artifactId, merged.properties, builtins),
		version: resolveProps(d.version, merged.properties, builtins),
	});
	merged.depMgmt = merged.depMgmt.map(resolveDep);
	merged.deps = merged.deps.map(resolveDep);

	// Expand BOM imports inside depMgmt: any entry with scope=import + type=pom
	// is replaced by the depMgmt entries from that imported POM.
	const expanded = [];
	for (const dm of merged.depMgmt) {
		if (dm.scope === "import") {
			const imported = await effectivePom(dm.groupId, dm.artifactId, dm.version, opts, new Set(seen));
			if (imported) expanded.push(...imported.depMgmt);
		} else {
			expanded.push(dm);
		}
	}
	merged.depMgmt = expanded;

	return merged;
}

/**
 * Build a map of managed versions from a list of depMgmt entries.
 * Keyed by "g:a"; value is the entry (we use its version + scope).
 */
function buildMgmt(depMgmt) {
	const m = new Map();
	for (const d of depMgmt) {
		if (d.groupId && d.artifactId) m.set(`${d.groupId}:${d.artifactId}`, d);
	}
	return m;
}

/**
 * BFS the transitive graph from a set of root deps.
 *
 * directDeps : iterable of { groupId, artifactId, version, scope, exclusions? }
 * opts:
 *   rootDepMgmt    — Map<g:a, managedEntry>  for the project root depMgmt (highest priority)
 *   maxDepth       — default 6
 *   parallelism    — default 8
 *   verbose
 *   includedScopes — defaults to ["compile", "runtime", "provided"]
 *
 * Returns Map<g:a, { groupId, artifactId, version, scope, depth, via: [g:a,...] }>
 *   `via` is the path from a root direct dep down to (but not including) this node.
 *   The set EXCLUDES the original direct deps (caller already has those).
 */
async function resolveTransitiveDeps(directDeps, opts = {}) {
	const {
		rootDepMgmt = new Map(),
		maxDepth = 6,
		verbose = false,
		offline = false,
		includedScopes = ["compile", "runtime", "provided"],
		concurrency = 8,
		fetcher,                    // optional injected fetch (used by tests)
		cacheDir,                   // optional override of disk cache dir (used by tests)
		repos,                      // optional repo list (lib/maven-repo). Falls back to repo1.maven.org alone.
	} = opts;
	const fetchOpts = { verbose, offline, fetcher, cacheDir, repos };

	const visited = new Map();   // g:a -> { ...entry, depth }
	const queue = [];
	// Index cursor instead of `queue.shift()` — shift() is O(n) per call which
	// turns the BFS into O(n²) on large dep trees. The cursor is safe across
	// concurrent workers because `head++` is atomic in single-threaded JS.
	let head = 0;

	// Seed: every direct dep (we won't return them, but we walk their children).
	for (const dep of directDeps) {
		if (!dep.groupId || !dep.artifactId || !dep.version) continue;
		queue.push({
			groupId: dep.groupId,
			artifactId: dep.artifactId,
			version: dep.version,
			scope: dep.scope || "compile",
			depth: 0,
			via: [],
			rootExclusions: dep.exclusions || [],
		});
		visited.set(`${dep.groupId}:${dep.artifactId}`, { isDirect: true });
	}

	// out: Map<g:a, { ...entry, viaPaths: [[chain1], [chain2], ...] }>
	// Multiple chains to the same transitive are accumulated; the BFS only
	// walks deeper from the FIRST chain (nearest-wins) but records every
	// alternate path so the report can show "brought in by X, Y, Z".
	const out = new Map();

	// Worker pool
	const workers = Array.from({ length: concurrency }, async () => {
		while (head < queue.length) {
			const node = queue[head++];
			if (!node) break;
			if (node.depth >= maxDepth) continue;

			let eff;
			try { eff = await effectivePom(node.groupId, node.artifactId, node.version, fetchOpts); }
			catch { continue; }
			if (!eff) continue;

			const mgmt = buildMgmt(eff.depMgmt);

			for (const dep of eff.deps) {
				if (!dep.groupId || !dep.artifactId) continue;
				if (dep.optional) continue;

				const childKey = `${dep.groupId}:${dep.artifactId}`;

				// Exclusion check against ancestors
				if (node.rootExclusions?.some(e =>
					(!e.groupId || e.groupId === dep.groupId || e.groupId === "*") &&
					(!e.artifactId || e.artifactId === dep.artifactId || e.artifactId === "*"))) continue;

				// Scope propagation
				const propagated = SCOPE_MATRIX[node.scope]?.[dep.scope || "compile"];
				if (!propagated || !includedScopes.includes(propagated)) continue;

				// Version resolution: root depMgmt > effective depMgmt > declared
				let resolvedVersion = dep.version;
				if (rootDepMgmt.has(childKey)) {
					resolvedVersion = rootDepMgmt.get(childKey).version;
				} else if (!resolvedVersion && mgmt.has(childKey)) {
					resolvedVersion = mgmt.get(childKey).version;
				} else if (mgmt.has(childKey) && !dep.version) {
					resolvedVersion = mgmt.get(childKey).version;
				}
				if (!resolvedVersion) continue;
				// Drop unresolved ${...} placeholders
				if (/\$\{/.test(resolvedVersion)) continue;

				const via = [...node.via, `${node.groupId}:${node.artifactId}`];

				// Nearest-wins for version & BFS continuation: if already visited
				// we don't recurse again, but we DO record the alternate via path
				// so the report can show all chains that bring this transitive in.
				if (visited.has(childKey)) {
					const existing = out.get(childKey);
					if (existing) {
						existing.viaPaths = existing.viaPaths || [existing.via];
						// Deduplicate by stringified chain
						const sig = via.join("→");
						if (!existing.viaPaths.some(p => p.join("→") === sig)) {
							existing.viaPaths.push(via);
						}
					}
					continue;
				}
				visited.set(childKey, { depth: node.depth + 1 });

				out.set(childKey, {
					groupId: dep.groupId,
					artifactId: dep.artifactId,
					version: resolvedVersion,
					scope: propagated,
					depth: node.depth + 1,
					via,
					viaPaths: [via],
				});

				queue.push({
					groupId: dep.groupId,
					artifactId: dep.artifactId,
					version: resolvedVersion,
					scope: propagated,
					depth: node.depth + 1,
					via,
					rootExclusions: [...(node.rootExclusions || []), ...(dep.exclusions || [])],
				});
			}
			// Progress visible whenever stdout is a TTY — transitive resolution
			// dominates wall-clock time on first run and used to look like a hang.
			// On non-TTY (pipes, CI, tests) we skip the \r-overwrite spam.
			if (verbose && process.stdout.isTTY) process.stdout.write(`\r   resolved ${out.size} transitives, queue=${queue.length - head}          `);
		}
	});
	await Promise.all(workers);
	if (verbose && process.stdout.isTTY) process.stdout.write(`\r   resolved ${out.size} transitives                              \n`);
	else if (verbose && out.size) console.log(`   resolved ${out.size} transitives`);

	return out;
}

module.exports = {
	resolveTransitiveDeps,
	effectivePom,
	parsePomXml,
	fetchPom,
	resolveProps,
	buildMgmt,
	POM_CACHE_DIR,
	SCOPE_MATRIX,
};
