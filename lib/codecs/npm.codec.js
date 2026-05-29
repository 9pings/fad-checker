/**
 * lib/codecs/npm.codec.js — codec npm.
 *
 * Enveloppe les parsers lib/npm/parse.js + le collecteur lib/npm/collect.js
 * (package-lock v1/2/3, yarn.lock v1) et le scanner natif retire.js.
 * Aucune logique nouvelle : extraction derrière l'interface codec.
 *
 * npm.collect ramasse package-lock ET yarn.lock — chaque dep porte son
 * `ecosystemType` ("npm" | "yarn"). Le codec yarn (yarn.codec.js) n'existe que
 * pour fournir son label/recette au report ; il ne re-scanne pas.
 */
const { collectNpmDeps, hasJsManifests } = require("../npm/collect");
const { coordKeyFor } = require("../dep-record");

// Scanner natif : retire.js (JS vendored sans lockfile). scan(deps,opts) → {matches,meta}.
const retireScanner = {
	id: "retire",
	async scan(_deps, opts = {}) {
		const { scanWithRetire } = require("../retire");
		const matches = await scanWithRetire(opts.src, { verbose: opts.verbose, force: !!opts.retireRefresh, offline: !!opts.offline });
		return { matches, meta: {} };
	},
};

const base = {
	osvEcosystem: "npm",
	manifestNames: ["package.json", "package-lock.json", "yarn.lock"],
	detect(dir) { return hasJsManifests(dir); },
	coordKey(d) { return coordKeyFor("npm", "", d.name || d.artifactId); },
	formatCoord(d) { return d.name || d.artifactId; },
	osvPackageName(d) { return d.name || d.artifactId; },
	async checkRegistry(deps, opts = {}) {
		const { checkNpmRegistryDeps } = require("../npm/registry");
		const r = await checkNpmRegistryDeps(deps, opts);
		return { outdated: r.outdated || [], deprecated: r.deprecated || [] };
	},
	resolveEolProduct(d) { return require("../outdated").findEolProduct(d); },
	nativeScanners: [retireScanner],
};

module.exports = {
	...base,
	id: "npm",
	label: "npm",
	recipe: require("./recipes").npm,
	// collect ramasse TOUTES les deps JS (package-lock + yarn.lock).
	async collect(dir, opts = {}) {
		const deps = collectNpmDeps(dir, opts);
		return { deps, warnings: deps.warnings || [] };
	},
};
