/**
 * lib/codecs/nuget.codec.js — codec C#/.NET (NuGet).
 *
 * Vuln scanning is OSV (ecosystem "NuGet", wired in Plan A). This codec adds
 * collection (packages.lock.json, else .csproj + Directory.Packages.props CPM,
 * else packages.config), NuGet registration registry (deprecation + outdated),
 * and EOL. NuGet ids are case-insensitive: the key is lowercased, dep.name keeps
 * the original casing for display / OSV.
 */
const fs = require("fs");
const path = require("path");
const { makeDepRecord, coordKeyFor } = require("../dep-record");
const N = require("./nuget/parse");

const SKIP = new Set([".git", ".idea", ".vscode", "node_modules", "dist", "build", "out", "bin", "obj", "target", "packages"]);
// MSBuild project files share the same <PackageReference> schema — C#, F#, VB.
const PROJ_RE = /\.(csproj|fsproj|vbproj)$/i;

function findNugetDirs(dir) {
	const groups = [];
	const stack = [dir];
	while (stack.length) {
		const cur = stack.pop();
		let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
		const files = entries.filter(e => e.isFile()).map(e => e.name);
		const csprojs = files.filter(f => PROJ_RE.test(f));
		if (files.includes("packages.lock.json") || files.includes("packages.config") || csprojs.length) {
			groups.push({ dir: cur, files, csprojs });
		}
		for (const e of entries) if (e.isDirectory() && !SKIP.has(e.name)) stack.push(path.join(cur, e.name));
	}
	return groups;
}

module.exports = {
	id: "nuget",
	label: "NuGet",
	osvEcosystem: "NuGet",
	manifestNames: ["packages.lock.json", "*.csproj", "*.fsproj", "*.vbproj", "packages.config"],

	detect(dir) { return findNugetDirs(dir).length > 0; },

	async collect(dir, opts = {}) {
		const { deps2Exclude } = opts;
		const out = new Map();
		const warnings = [];
		const add = (d, manifestPath) => {
			if (deps2Exclude && deps2Exclude.test(d.name)) return;
			out.set(coordKeyFor("nuget", "", d.name), makeDepRecord({ ecosystem: "nuget", namespace: "", name: d.name, version: d.version, manifestPath, scope: d.scope, isDev: d.isDev }));
		};
		for (const g of findNugetDirs(dir)) {
			if (g.files.includes("packages.lock.json")) {
				const fp = path.join(g.dir, "packages.lock.json");
				try { const { deps } = await N.parsePackagesLockJson(fp); for (const d of deps) add(d, fp); }
				catch (e) { warnings.push({ type: "parse-error", manifestPath: fp, message: `packages.lock.json parse failed: ${e.message}` }); }
				continue;   // lockfile is authoritative for this directory
			}
			// No lockfile → best-effort from .csproj (+CPM) and packages.config + warning.
			let cpm = {};
			if (g.files.includes("Directory.Packages.props")) {
				try { cpm = await N.parseDirectoryPackagesProps(path.join(g.dir, "Directory.Packages.props")); } catch { /* ignore */ }
			}
			let pinned = 0, skipped = 0;
			for (const cs of g.csprojs) {
				const fp = path.join(g.dir, cs);
				try {
					const { deps, skipped: sk } = await N.parseCsproj(fp, cpm);
					for (const d of deps) { add(d, fp); pinned++; }
					skipped += sk;
				} catch { /* ignore unparsable csproj */ }
			}
			if (g.files.includes("packages.config")) {
				const fp = path.join(g.dir, "packages.config");
				try { const { deps } = await N.parsePackagesConfig(fp); for (const d of deps) { add(d, fp); pinned++; } } catch { /* ignore */ }
			}
			if (g.csprojs.length || g.files.includes("packages.config")) {
				warnings.push({ type: "no-lockfile", manifestPath: g.dir, message: `no packages.lock.json — best-effort: ${pinned} pinned, ${skipped} floating/unresolved skipped (enable RestorePackagesWithLockFile)` });
			}
		}
		return { deps: out, warnings };
	},

	coordKey(d) { return coordKeyFor("nuget", "", d.name); },
	formatCoord(d) { return d.name; },
	osvPackageName(d) { return d.name; },

	async checkRegistry(deps, opts = {}) {
		const { checkNugetRegistryDeps } = require("./nuget/registry");
		return checkNugetRegistryDeps(deps, opts);
	},
	resolveEolProduct(d) { return require("../outdated").findEolProduct(d); },
	recipe: require("./recipes").nuget,
	nativeScanners: [],
};
