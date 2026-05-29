/**
 * lib/npm/collect.js — walk a JS project root, parse every manifest /
 * lockfile, and produce a Map<key, depRecord> matching the shape that
 * lib/cve-match.collectResolvedDeps produces for Maven.
 *
 *   key:        "npm:<name>"   (deliberately namespaced so it never
 *                                collides with Maven "g:a" keys)
 *   depRecord:  { groupId: "", artifactId: name, version, scope, pomPaths,
 *                 ecosystem: "npm", resolved, integrity, lockType,
 *                 manifestPaths: [absolute paths of files mentioning it] }
 *
 * Conflict resolution between manifests for the same package:
 *   - lockfile entries WIN over package.json range specs (concrete version)
 *   - if two lockfiles disagree, keep the highest semver-comparable version
 *   - dev/optional/peer downgrade to prod if any manifest puts the dep in prod
 */
const path = require("path");
const fs = require("fs");
const { parsePackageJson, parsePackageLock, parseYarnLockV1, findJsManifests } = require("./parse");
const { makeDepRecord } = require("../dep-record");

const SCOPE_RANK = { prod: 4, peer: 3, optional: 2, dev: 1, transitive: 0 };

function rankScope(s) { return SCOPE_RANK[s] || 0; }

function semverCompare(a, b) {
	// Lightweight semver compare — good enough for "keep highest"; not
	// canonical (doesn't fully implement build metadata ordering). For CVE
	// matching we'll defer to ecosystem-aware comparators when needed.
	const norm = v => String(v || "").replace(/^[v=]+/, "").split(/[-+]/)[0].split(".").map(n => parseInt(n, 10) || 0);
	const ax = norm(a), bx = norm(b);
	const n = Math.max(ax.length, bx.length);
	for (let i = 0; i < n; i++) {
		const d = (ax[i] || 0) - (bx[i] || 0);
		if (d !== 0) return d > 0 ? 1 : -1;
	}
	return 0;
}

function isResolvedVersion(v) {
	// Reject ranges/specifiers like "^1.0.0", "~2.0", ">=1.0.0", "*", "latest", "git+..."
	if (!v) return false;
	if (/^[\^~>=<*]/.test(v)) return false;
	if (/^(latest|next|workspace:|git\+|file:|link:|http)/i.test(v)) return false;
	// Bare semver-ish strings only (digits and at most one dash for prerelease tag)
	return /^\d+\.\d+(\.\d+)?([.\-+]\S+)?$/.test(v) || /^\d+$/.test(v);
}

function upsert(out, dep, manifestPath, lockType) {
	const key = `npm:${dep.name}`;
	const existing = out.get(key);
	// ecosystemType narrows "ecosystem" to the tool that produced the lockfile:
	//   "npm"  for package-lock.json
	//   "yarn" for yarn.lock
	// Used by the report to split sections per tool.
	const ecosystemType = (lockType || "").startsWith("package-lock") ? "npm"
		: (lockType || "").startsWith("yarn") ? "yarn"
		: "npm";
	const record = makeDepRecord({
		ecosystem: "npm",
		ecosystemType,
		namespace: "",
		name: dep.name,
		version: dep.version || null,
		manifestPath,
		scope: dep.scope || "prod",
		isDev: !!dep.isDev,
	});
	// npm-specific extras (not part of the shared depRecord contract)
	record.lockType = lockType;
	record.depth = dep.depth ?? null;
	record.resolved = dep.resolved || null;
	record.integrity = dep.integrity || null;
	record.from = dep.from || null;
	if (!existing) {
		out.set(key, record);
		return;
	}
	// Merge. NB: pomPaths shares the manifestPaths array reference (makeDepRecord),
	// so we push once — pushing to both would duplicate the entry.
	if (!existing.manifestPaths.includes(manifestPath)) {
		existing.manifestPaths.push(manifestPath);
	}
	// Prefer the resolved (lockfile) version over a range from package.json
	const incoming = record.version;
	const have = existing.version;
	if (isResolvedVersion(incoming) && !isResolvedVersion(have)) {
		existing.version = incoming;
	} else if (isResolvedVersion(incoming) && isResolvedVersion(have)) {
		if (semverCompare(incoming, have) > 0) existing.version = incoming;
	} else if (!have && incoming) {
		existing.version = incoming;
	}
	// Stronger scope wins (prod > peer > optional > dev)
	if (rankScope(record.scope) > rankScope(existing.scope)) existing.scope = record.scope;
	// A dep is "dev" overall only if every occurrence is dev. Any prod use → not dev.
	if (!record.isDev) existing.isDev = false;
	// First non-null resolved/integrity wins
	if (!existing.resolved && record.resolved) existing.resolved = record.resolved;
	if (!existing.integrity && record.integrity) existing.integrity = record.integrity;
}

/**
 * Walk `rootDir`, parse every manifest, return { deps, warnings }.
 *
 * Returns:
 *   {
 *     deps:     Map<key, depRecord>,   // unchanged shape from before
 *     warnings: [                       // surfaced into console + report
 *       { type: "no-lockfile", manifestPath, message }, ...
 *     ],
 *   }
 *
 * Lockfile policy: we ONLY collect deps from a lockfile (package-lock.json or
 * yarn.lock). A package.json without a sibling lockfile is intentionally
 * skipped — its values are ranges ("^1.0.0") that can't be queried against
 * OSV and create false negatives. The caller is warned so they can either
 * run `npm install` / `yarn install` to generate a lock, or accept the gap.
 *
 * opts:
 *   ignoreTest    — skip dev / optional dependencies (mirrors Maven's --ignore-test)
 *   deps2Exclude  — RegExp tested against the npm name (covers private @scope/* packages)
 *   verbose
 */
function collectNpmDeps(rootDir, opts = {}) {
	const { ignoreTest, deps2Exclude, verbose } = opts;
	const out = new Map();
	const warnings = [];
	const manifestGroups = findJsManifests(rootDir);
	let parsedCount = 0;

	for (const group of manifestGroups) {
		const pj = group.packageJson ? safeParse(parsePackageJson, group.packageJson, verbose) : null;
		const pl = group.packageLock ? safeParse(parsePackageLock, group.packageLock, verbose) : null;
		const yl = group.yarnLock ? safeParse(parseYarnLockV1, group.yarnLock, verbose) : null;
		const hasLock = !!(pl || yl);

		// package.json without lockfile → warning, skip dep collection.
		if (pj && !hasLock) {
			warnings.push({
				type: "no-lockfile",
				manifestPath: group.packageJson,
				packageName: pj.packageName || null,
				message: `package.json without lockfile — skipped (run "npm install" or "yarn install" to generate one)`,
			});
			if (verbose) console.warn(`⚠️  ${group.packageJson}: no lockfile, skipped (${pj.deps.length} ranges in package.json)`);
		}

		// Yarn-Berry lockfile detected but unsupported → warning, skip.
		if (yl?.unsupported === "yarn-berry") {
			warnings.push({
				type: "yarn-berry-unsupported",
				manifestPath: group.yarnLock,
				message: `yarn 2+/Berry lockfile not yet supported — skipped`,
			});
			if (verbose) console.warn(`⚠️  ${group.yarnLock}: yarn-berry not supported, skipped`);
		}

		// Used only as a source of scope info — never emits deps on its own.
		const directScopes = pj ? new Map(pj.deps.map(d => [d.name, d.scope])) : null;

		if (pl) {
			parsedCount++;
			for (const d of pl.deps) {
				// In v1 npm dev/optional propagate; in v2/v3 the `dev` flag is reliable
				const explicit = directScopes?.get(d.name);
				const scope = explicit || d.scope || "prod";
				if (ignoreTest && (scope === "dev" || scope === "optional")) continue;
				if (deps2Exclude && deps2Exclude.test(d.name)) continue;
				upsert(out, { ...d, scope }, group.packageLock, `package-lock-v${pl.lockfileVersion}`);
			}
		}
		if (yl) {
			parsedCount++;
			// yarn-berry warning already pushed above; only emit deps for v1
			if (yl.unsupported !== "yarn-berry") {
				for (const d of yl.deps) {
					const explicit = directScopes?.get(d.name);
					const scope = explicit || "prod";
					if (ignoreTest && (scope === "dev" || scope === "optional")) continue;
					if (deps2Exclude && deps2Exclude.test(d.name)) continue;
					upsert(out, { ...d, scope }, group.yarnLock, "yarn-v1");
				}
			}
		}
	}

	if (verbose) console.log(`📦 npm/yarn: parsed ${parsedCount} manifests, ${out.size} unique packages${warnings.length ? `, ${warnings.length} warnings` : ""}`);
	// Backward compat: the Map carries the warnings under a non-enumerable prop
	// so existing callers that iterate `for (const [k,v] of map)` still work.
	Object.defineProperty(out, "warnings", { value: warnings, enumerable: false });
	return out;
}

function safeParse(fn, file, verbose) {
	try { return fn(file); }
	catch (e) {
		if (verbose) console.warn(`⚠️  parse failed: ${file} — ${e.message}`);
		return null;
	}
}

/**
 * WebJars are client-side JS libraries shipped as Maven artifacts. Derive the
 * upstream npm coordinate from a WebJar dep so it can flow through the npm
 * pipeline (registry deprecation/outdated + endoflife EOL) instead of being
 * special-cased.
 *
 *   org.webjars.npm  — deterministic npm mirror. artifactId == npm name;
 *                      a scoped "@scope/name" is encoded as "scope__name".
 *   org.webjars      — hand-curated catalogue; artifactId is the JS lib name
 *                      (mostly aligned with npm, e.g. jquery/bootstrap).
 *   org.webjars.bower* — Bower mirrors; best-effort name match.
 *
 * Versions match the upstream package. Returns { name, version } or null for a
 * non-WebJar coordinate.
 */
function webjarToNpm(dep) {
	const g = dep.groupId || "";
	if (g !== "org.webjars" && !g.startsWith("org.webjars.")) return null;
	let name = dep.artifactId || "";
	if (!name) return null;
	if (name.includes("__")) name = "@" + name.replace(/__/g, "/");
	return { name, version: dep.version || null };
}

function hasJsManifests(rootDir) {
	try {
		const stack = [rootDir];
		const skip = new Set([
			"node_modules", "bower_components", "jspm_packages",
			".git", ".idea", ".vscode", ".gradle", ".mvn",
			"dist", "build", "out", "target", "coverage", ".next", ".nuxt",
		]);
		while (stack.length) {
			const cur = stack.pop();
			let entries;
			try { entries = fs.readdirSync(cur, { withFileTypes: true }); }
			catch { continue; }
			for (const e of entries) {
				if (e.isFile() && (e.name === "package.json" || e.name === "package-lock.json" || e.name === "yarn.lock")) return true;
				if (e.isDirectory() && !skip.has(e.name)) stack.push(path.join(cur, e.name));
			}
		}
	} catch { /* ignore */ }
	return false;
}

module.exports = { collectNpmDeps, hasJsManifests, semverCompare, webjarToNpm };
