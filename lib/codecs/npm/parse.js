/**
 * lib/npm/parse.js — parse package.json, package-lock.json (v1/v2/v3),
 * and yarn.lock v1. Pure functions: no I/O scheduling, no console output.
 *
 * The shape returned by each parser is normalised to:
 *   {
 *     manifestPath,           // absolute path to the parsed file
 *     manifestType,           // "package.json" | "package-lock" | "yarn.lock"
 *     packageName,            // top-level project name (if known)
 *     packageVersion,         // top-level project version (if known)
 *     deps: [                 // every package present (direct + transitive)
 *       {
 *         name,               // "lodash" | "@scope/pkg"
 *         version,            // resolved (lockfile) or range (package.json)
 *         scope,              // "prod" | "dev" | "peer" | "optional"
 *         depth,              // 0 for top-level; >0 for transitive in lockfile tree
 *         from,               // for transitives in npm v1 lockfile: parent chain
 *       },
 *     ],
 *   }
 *
 * The collector (lib/npm/collect.js) is responsible for merging across
 * files and applying exclusion rules.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const yaml = require("js-yaml");

function isWorkspaceVersion(v) {
	// npm v9+ uses "*" / "" for workspace-local refs; yarn uses "workspace:*"
	if (!v) return true;
	return v === "*" || v === "" || String(v).startsWith("workspace:") || String(v).startsWith("file:") || String(v).startsWith("link:");
}

function pickName(pkgKey) {
	// npm v2/v3 lockfile keys look like "node_modules/foo" or "node_modules/foo/node_modules/bar"
	const parts = pkgKey.split("node_modules/");
	const last = parts[parts.length - 1];
	return last || null;
}

function depthFromKey(pkgKey) {
	// "node_modules/a/node_modules/b" → depth 2
	const n = (pkgKey.match(/node_modules\//g) || []).length;
	return Math.max(0, n - 1);
}

/* -------- package.json ---------- */
function parsePackageJson(filePath) {
	const raw = fs.readFileSync(filePath, "utf8");
	let json;
	try { json = JSON.parse(raw); }
	catch (e) { throw new Error(`package.json parse failed (${filePath}): ${e.message}`); }
	const deps = [];
	const push = (obj, scope) => {
		for (const [name, version] of Object.entries(obj || {})) {
			if (isWorkspaceVersion(version)) continue;
			const isDev = scope === "dev" || scope === "optional";
			deps.push({ name, version: String(version), scope, isDev, depth: 0 });
		}
	};
	push(json.dependencies, "prod");
	push(json.devDependencies, "dev");
	push(json.peerDependencies, "peer");
	push(json.optionalDependencies, "optional");
	return {
		manifestPath: filePath,
		manifestType: "package.json",
		packageName: json.name || null,
		packageVersion: json.version || null,
		workspaces: Array.isArray(json.workspaces) ? json.workspaces : (json.workspaces?.packages || []),
		deps,
	};
}

/* -------- package-lock.json (v1, v2, v3) ---------- */
function parsePackageLock(filePath) {
	const raw = fs.readFileSync(filePath, "utf8");
	let json;
	try { json = JSON.parse(raw); }
	catch (e) { throw new Error(`package-lock parse failed (${filePath}): ${e.message}`); }

	const lockfileVersion = json.lockfileVersion || 1;
	const out = {
		manifestPath: filePath,
		manifestType: "package-lock",
		packageName: json.name || null,
		packageVersion: json.version || null,
		lockfileVersion,
		deps: [],
	};

	if (lockfileVersion >= 2 && json.packages) {
		// v2/v3: flat `packages` map keyed by relative path.
		// The empty-string key is the root project; node_modules/foo → installed dep.
		const root = json.packages[""] || {};
		const directProd = root.dependencies || {};
		const directDev = root.devDependencies || {};
		const directOpt = root.optionalDependencies || {};
		const directPeer = root.peerDependencies || {};
		const isDirect = (name, scope) => {
			if (scope === "prod" && Object.prototype.hasOwnProperty.call(directProd, name)) return true;
			if (scope === "dev" && Object.prototype.hasOwnProperty.call(directDev, name)) return true;
			if (scope === "optional" && Object.prototype.hasOwnProperty.call(directOpt, name)) return true;
			if (scope === "peer" && Object.prototype.hasOwnProperty.call(directPeer, name)) return true;
			return false;
		};
		const isAnyDirect = name =>
			Object.prototype.hasOwnProperty.call(directProd, name) ||
			Object.prototype.hasOwnProperty.call(directDev, name) ||
			Object.prototype.hasOwnProperty.call(directOpt, name) ||
			Object.prototype.hasOwnProperty.call(directPeer, name);

		for (const [pkgKey, entry] of Object.entries(json.packages)) {
			if (pkgKey === "") continue;                  // root
			if (!pkgKey.includes("node_modules/")) continue; // workspace member, not a dep
			if (entry.link) continue;                     // symlink to workspace
			const name = pickName(pkgKey);
			if (!name) continue;
			const depth = depthFromKey(pkgKey);
			// scope inference. npm v3+ flattens transitives into the top-level
			// node_modules/, so depth===0 alone doesn't mean "direct". An entry
			// is direct iff it appears in the root project's dependency lists.
			let scope = "prod";
			if (entry.dev || entry.devOptional) scope = "dev";
			else if (entry.optional) scope = "optional";
			else if (entry.peer) scope = "peer";
			const isDirectDep = depth === 0 && isAnyDirect(name);
			if (isDirectDep) {
				if (isDirect(name, "dev")) scope = "dev";
				else if (isDirect(name, "optional")) scope = "optional";
				else if (isDirect(name, "peer")) scope = "peer";
				else scope = "prod";
			} else if (depth > 0 || !isAnyDirect(name)) {
				// Flattened-but-not-direct = transitive. Keep dev/optional flags
				// for filtering, but record it as a transitive.
				scope = "transitive";
			}
			// isDev flag survives the scope reclassification: a flattened
			// transitive of a dev-only dep is still dev-only.
			const isDev = !!(entry.dev || entry.devOptional || (isDirectDep && isDirect(name, "dev")));
			out.deps.push({
				name,
				version: entry.version || null,
				scope,
				isDev,
				depth,
				resolved: entry.resolved || null,
				integrity: entry.integrity || null,
			});
		}
	} else if (json.dependencies) {
		// v1: nested `dependencies` tree
		const walk = (node, depth, parentChain, parentIsDev) => {
			for (const [name, entry] of Object.entries(node)) {
				let scope = "prod";
				if (entry.dev) scope = "dev";
				else if (entry.optional) scope = "optional";
				const isDev = !!entry.dev || parentIsDev;
				out.deps.push({
					name,
					version: entry.version || null,
					scope,
					isDev,
					depth,
					from: parentChain.length ? parentChain.join(" > ") : null,
					resolved: entry.resolved || null,
					integrity: entry.integrity || null,
				});
				if (entry.dependencies) walk(entry.dependencies, depth + 1, [...parentChain, name], isDev);
			}
		};
		walk(json.dependencies, 0, [], false);
	}

	return out;
}

/* -------- yarn.lock v1 ----------
   Format example:
     "lodash@^4.17.0":
       version "4.17.21"
       resolved "https://registry.yarnpkg.com/..."
       integrity sha512-...
       dependencies:
         "another-pkg" "^1.0.0"
   Each block starts at column 0 with one or more comma-separated specifiers,
   ending with ":". Indented lines hold key-value pairs and dependency blocks.
*/
function parseYarnLockV1(filePath) {
	const raw = fs.readFileSync(filePath, "utf8");
	if (raw.includes("__metadata:")) {
		// Berry / yarn 2+ uses YAML — parse it with js-yaml.
		return parseYarnBerry(raw, filePath);
	}
	const out = {
		manifestPath: filePath,
		manifestType: "yarn.lock",
		lockfileVersion: 1,
		deps: [],
	};
	const lines = raw.split(/\r?\n/);
	let i = 0;
	// Track unique (name, version) so we don't emit duplicate entries for
	// every range spec that resolves to the same version.
	const seen = new Set();
	while (i < lines.length) {
		const line = lines[i];
		if (!line || /^#/.test(line)) { i++; continue; }
		if (line[0] === " " || line[0] === "\t") { i++; continue; }
		// Header line: one or more comma-separated specifiers ending with ":"
		const header = line.replace(/:\s*$/, "");
		const specifiers = header.split(",").map(s => s.trim().replace(/^"|"$/g, ""));
		// Each specifier is "name@range". Names may contain "@" for scoped pkgs.
		const names = new Set();
		for (const spec of specifiers) {
			const at = spec.lastIndexOf("@");
			if (at <= 0) continue; // malformed
			names.add(spec.slice(0, at));
		}
		i++;
		// Read the indented body until the next non-indented line
		let version = null;
		let resolved = null;
		while (i < lines.length && (lines[i].startsWith("  ") || lines[i].startsWith("\t") || lines[i] === "")) {
			const body = lines[i].trim();
			if (body.startsWith("version ")) {
				version = body.slice("version ".length).replace(/^"|"$/g, "");
			} else if (body.startsWith("resolved ")) {
				resolved = body.slice("resolved ".length).replace(/^"|"$/g, "");
			}
			i++;
		}
		for (const name of names) {
			if (!version) continue;
			const k = `${name}@${version}`;
			if (seen.has(k)) continue;
			seen.add(k);
			out.deps.push({ name, version, scope: "prod", depth: 0, resolved });
		}
	}
	return out;
}

/* -------- yarn.lock v2+ (Berry) ----------
   Berry lockfiles are YAML. Top-level keys are comma-separated descriptor lists
   ("lodash@npm:^4.17.0, lodash@npm:^4.17.21:") whose value carries `version` and
   `resolution`. The workspace's own packages resolve to "@workspace:" — skipped.
*/
function identFromDescriptor(d) {
	const s = String(d || "").trim().replace(/^"|"$/g, "");
	const scoped = s.startsWith("@");
	const at = s.indexOf("@", scoped ? 1 : 0);   // the @ before the range/protocol
	if (at <= 0) return null;
	return s.slice(0, at);
}

function parseYarnBerry(raw, filePath) {
	const out = { manifestPath: filePath, manifestType: "yarn.lock", lockfileVersion: "berry", deps: [] };
	let doc;
	try { doc = yaml.load(raw) || {}; }
	catch (e) { out.parseError = e.message; return out; }
	const seen = new Set();
	for (const [key, val] of Object.entries(doc)) {
		if (key === "__metadata") continue;
		if (!val || typeof val !== "object" || !val.version) continue;
		if (/@workspace:/.test(val.resolution || "")) continue;   // the local package itself
		const version = String(val.version);
		const names = new Set();
		for (const desc of String(key).split(",")) {
			const name = identFromDescriptor(desc);
			if (name) names.add(name);
		}
		for (const name of names) {
			const k = `${name}@${version}`;
			if (seen.has(k)) continue; seen.add(k);
			out.deps.push({ name, version, scope: "prod", depth: 0, resolved: val.resolution || null });
		}
	}
	return out;
}

/* -------- pnpm-lock.yaml ----------
   YAML. The full resolved set lives in `packages` (v5/v6) and `snapshots` (v9);
   `importers.*` carry the per-workspace direct deps with dev classification.
   Package keys vary by lockfileVersion:
     v9:  "name@1.2.3"            / "@scope/name@1.2.3"
     v6:  "/name@1.2.3(peers)"    / "/@scope/name@1.2.3(peers)"
     v5:  "/name/1.2.3"           / "/@scope/name/1.2.3"
*/
function pnpmNameVersion(key) {
	let k = String(key || "");
	if (k.startsWith("/")) k = k.slice(1);
	const paren = k.indexOf("(");           // strip peer-deps suffix
	if (paren !== -1) k = k.slice(0, paren);
	const at = k.lastIndexOf("@");          // @-form (v6/v9)
	if (at > 0 && /^\d/.test(k.slice(at + 1))) return { name: k.slice(0, at), version: k.slice(at + 1) };
	const slash = k.lastIndexOf("/");       // slash-form (v5)
	if (slash > 0 && /^\d/.test(k.slice(slash + 1))) return { name: k.slice(0, slash), version: k.slice(slash + 1) };
	return null;
}

function parsePnpmLock(filePath) {
	const raw = fs.readFileSync(filePath, "utf8");
	let doc;
	try { doc = yaml.load(raw) || {}; }
	catch (e) { throw new Error(`pnpm-lock parse failed (${filePath}): ${e.message}`); }
	const out = { manifestPath: filePath, manifestType: "pnpm-lock", lockfileVersion: doc.lockfileVersion || null, deps: [] };
	const seen = new Set();
	const push = (name, version, scope, isDev) => {
		if (!name || !version) return;
		const v = String(version).split("(")[0];          // peer-resolved suffix
		if (!/^\d/.test(v)) return;
		const k = `${name}@${v}`;
		if (seen.has(k)) return; seen.add(k);
		out.deps.push({ name, version: v, scope: scope || "prod", isDev: !!isDev, depth: 0 });
	};
	// Direct deps from importers FIRST (v6/v9) — these carry the authoritative
	// dev/optional classification. In v9 the `packages` section has no dev flag,
	// so seeding dev/optional here (dedup by name@version) keeps the right scope.
	const importers = doc.importers || ((doc.dependencies || doc.devDependencies) ? { ".": doc } : null);
	if (importers && typeof importers === "object") {
		const readDir = (obj, scope, isDev) => {
			for (const [name, spec] of Object.entries(obj || {})) {
				const version = typeof spec === "string" ? spec : (spec && (spec.version || spec.specifier));
				push(name, version, scope, isDev);
			}
		};
		for (const imp of Object.values(importers)) {
			if (!imp || typeof imp !== "object") continue;
			readDir(imp.devDependencies, "dev", true);
			readDir(imp.optionalDependencies, "optional", false);
			readDir(imp.dependencies, "prod", false);
		}
	}
	// Full resolved set (direct + transitive) fills in anything not already seen.
	for (const sec of [doc.packages, doc.snapshots]) {
		if (!sec || typeof sec !== "object") continue;
		for (const [key, entry] of Object.entries(sec)) {
			const nv = pnpmNameVersion(key);
			if (!nv) continue;
			const name = (entry && entry.name) || nv.name;
			const version = (entry && entry.version) || nv.version;
			const isDev = !!(entry && entry.dev);          // v6 carries a dev flag
			push(name, version, isDev ? "dev" : "prod", isDev);
		}
	}
	return out;
}

/* -------- discovery ---------- */
// Dirs that hold packaged / generated content — never our own source.
// Conservative list: only well-known build-output / package-cache dirs.
const DEFAULT_JS_SKIP_DIRS = new Set([
	"node_modules", "bower_components", "jspm_packages",
	".git", ".idea", ".vscode", ".gradle", ".mvn",
	"dist", "build", "out", "target", "coverage", ".next", ".nuxt",
]);

function findJsManifests(rootDir, opts = {}) {
	const { skipDirs = DEFAULT_JS_SKIP_DIRS } = opts;
	const found = [];
	const stack = [rootDir];
	while (stack.length) {
		const cur = stack.pop();
		let entries;
		try { entries = fs.readdirSync(cur, { withFileTypes: true }); }
		catch { continue; }
		// Group lockfile per directory so we can prefer lock > package.json
		const here = { dir: cur, packageJson: null, packageLock: null, yarnLock: null, pnpmLock: null };
		for (const e of entries) {
			const p = path.join(cur, e.name);
			if (e.isDirectory()) {
				if (skipDirs.has(e.name)) continue;
				stack.push(p);
			} else if (e.isFile()) {
				if (e.name === "package.json") here.packageJson = p;
				else if (e.name === "package-lock.json") here.packageLock = p;
				else if (e.name === "yarn.lock") here.yarnLock = p;
				else if (e.name === "pnpm-lock.yaml") here.pnpmLock = p;
			}
		}
		if (here.packageJson || here.packageLock || here.yarnLock || here.pnpmLock) found.push(here);
	}
	return found;
}

// Parallel equivalent of findJsManifests — concurrent readdir so the walk isn't
// serialized one round-trip at a time on a high-latency filesystem.
async function findJsManifestsAsync(rootDir, opts = {}) {
	const { skipDirs = DEFAULT_JS_SKIP_DIRS } = opts;
	const { walkDirs } = require("../../parallel-walk");
	const found = [];
	await walkDirs(rootDir, {
		skipDir: name => skipDirs.has(name),
		onDir: (cur, entries) => {
			const here = { dir: cur, packageJson: null, packageLock: null, yarnLock: null, pnpmLock: null };
			for (const e of entries) {
				if (!e.isFile()) continue;
				const p = path.join(cur, e.name);
				if (e.name === "package.json") here.packageJson = p;
				else if (e.name === "package-lock.json") here.packageLock = p;
				else if (e.name === "yarn.lock") here.yarnLock = p;
				else if (e.name === "pnpm-lock.yaml") here.pnpmLock = p;
			}
			if (here.packageJson || here.packageLock || here.yarnLock || here.pnpmLock) found.push(here);
		},
	});
	return found;
}

module.exports = {
	parsePackageJson,
	parsePackageLock,
	parseYarnLockV1,
	parseYarnBerry,
	parsePnpmLock,
	findJsManifests,
	findJsManifestsAsync,
};
