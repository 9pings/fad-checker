/**
 * lib/codecs/pypi.codec.js — codec Python/PyPI.
 *
 * Vuln scanning is OSV (ecosystem "PyPI", wired in Plan A). This codec adds
 * collection (poetry.lock/Pipfile.lock/uv.lock/pdm.lock, requirements.txt
 * fallback), PyPI registry (yanked/inactive + outdated), and EOL.
 * Per-directory precedence: a lockfile wins; else requirements.txt best-effort.
 */
const fs = require("fs");
const path = require("path");
const { makeDepRecord, coordKeyFor } = require("../dep-record");
const P = require("../python/parse");

const SKIP = new Set([".git", ".idea", ".vscode", "node_modules", "dist", "build", "out", "target", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", "site-packages"]);
const LOCKS = [
	["poetry.lock", P.parsePoetryLock],
	["Pipfile.lock", P.parsePipfileLock],
	["uv.lock", P.parseUvLock],
	["pdm.lock", P.parsePdmLock],
];

function findPyDirs(dir) {
	const groups = [];
	const stack = [dir];
	while (stack.length) {
		const cur = stack.pop();
		let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
		const names = new Set(entries.filter(e => e.isFile()).map(e => e.name));
		if ([...LOCKS.map(l => l[0]), "requirements.txt"].some(n => names.has(n))) groups.push({ dir: cur, names });
		for (const e of entries) if (e.isDirectory() && !SKIP.has(e.name)) stack.push(path.join(cur, e.name));
	}
	return groups;
}

module.exports = {
	id: "pypi",
	label: "PyPI",
	osvEcosystem: "PyPI",
	manifestNames: ["poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock", "requirements.txt"],

	detect(dir) { return findPyDirs(dir).length > 0; },

	async collect(dir, opts = {}) {
		const { ignoreTest, deps2Exclude } = opts;
		const out = new Map();
		const warnings = [];
		const add = (d, manifestPath) => {
			if (ignoreTest && d.isDev) return;
			if (deps2Exclude && deps2Exclude.test(d.name)) return;
			out.set(coordKeyFor("pypi", "", d.name), makeDepRecord({ ecosystem: "pypi", namespace: "", name: d.name, version: d.version, manifestPath, scope: d.scope, isDev: d.isDev }));
		};
		for (const g of findPyDirs(dir)) {
			const lock = LOCKS.find(([n]) => g.names.has(n));
			if (lock) {
				const fp = path.join(g.dir, lock[0]);
				const { deps } = lock[1](fp);
				for (const d of deps) add(d, fp);
			} else if (g.names.has("requirements.txt")) {
				const fp = path.join(g.dir, "requirements.txt");
				const { deps, skipped } = P.parseRequirementsTxt(fp);
				for (const d of deps) add(d, fp);
				warnings.push({ type: "no-lockfile", manifestPath: fp, message: `requirements.txt (no lockfile) — best-effort: ${deps.length} pinned, ${skipped} range(s) skipped` });
			}
		}
		return { deps: out, warnings };
	},

	coordKey(d) { return coordKeyFor("pypi", "", d.name); },
	formatCoord(d) { return d.name; },
	osvPackageName(d) { return d.name; },

	async checkRegistry(deps, opts = {}) {
		const { checkPypiRegistryDeps } = require("../python/registry");
		return checkPypiRegistryDeps(deps, opts);
	},
	resolveEolProduct(d) { return require("../outdated").findEolProduct(d); },
	recipe: require("./recipes").pypi,
	nativeScanners: [],
};
