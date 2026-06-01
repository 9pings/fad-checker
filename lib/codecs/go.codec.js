/**
 * lib/codecs/go.codec.js — codec Go (modules).
 *
 * Reads go.mod (authoritative on Go ≥1.17 — lists the full pruned graph) and
 * falls back to go.sum. Vuln recall via OSV (ecosystem "Go"); outdated via the
 * Go module proxy. The full module path is the dep name (namespace = "").
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const { makeDepRecord, coordKeyFor } = require("../dep-record");
const G = require("./go/parse");

const SKIP = new Set([".git", ".idea", ".vscode", "node_modules", "dist", "build", "out", "target", "vendor", "testdata"]);

function findGoDirs(dir) {
	const groups = [];
	const stack = [dir];
	while (stack.length) {
		const cur = stack.pop();
		let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
		const names = new Set(entries.filter(e => e.isFile()).map(e => e.name));
		if (names.has("go.mod") || names.has("go.sum")) groups.push({ dir: cur, names });
		for (const e of entries) if (e.isDirectory() && !SKIP.has(e.name)) stack.push(path.join(cur, e.name));
	}
	return groups;
}

module.exports = {
	id: "go",
	label: "Go",
	osvEcosystem: "Go",
	manifestNames: ["go.mod", "go.sum"],

	detect(dir) { return findGoDirs(dir).length > 0; },

	async collect(dir, opts = {}) {
		const { deps2Exclude } = opts;
		const out = new Map();
		const warnings = [];
		const add = (d, manifestPath) => {
			if (deps2Exclude && deps2Exclude.test(d.name)) return;
			out.set(coordKeyFor("go", "", d.name), makeDepRecord({ ecosystem: "go", namespace: "", name: d.name, version: d.version, manifestPath, scope: d.scope, isDev: false }));
		};
		for (const g of findGoDirs(dir)) {
			if (g.names.has("go.mod")) {
				const fp = path.join(g.dir, "go.mod");
				try {
					const r = G.parseGoModFile(fp);
					if (r.deps.length) { for (const d of r.deps) add(d, fp); continue; }
					// go.mod with no require list (rare / very old) → fall through to go.sum.
				} catch (e) { warnings.push({ type: "parse-error", manifestPath: fp, message: `go.mod parse failed: ${e.message}` }); }
			}
			if (g.names.has("go.sum")) {
				const fp = path.join(g.dir, "go.sum");
				try { const r = G.parseGoSumFile(fp); for (const d of r.deps) add(d, fp); }
				catch (e) { warnings.push({ type: "parse-error", manifestPath: fp, message: `go.sum parse failed: ${e.message}` }); }
			}
		}
		return { deps: out, warnings };
	},

	coordKey(d) { return coordKeyFor("go", "", d.name); },
	formatCoord(d) { return d.version ? `${d.name}@${d.version}` : d.name; },
	osvPackageName(d) { return d.name; },

	async checkRegistry(deps, opts = {}) {
		const { checkGoRegistryDeps } = require("./go/registry");
		return checkGoRegistryDeps(deps, opts);
	},
	resolveEolProduct() { return null; },
	recipe: require("./recipes").go,
	nativeScanners: [],
};
