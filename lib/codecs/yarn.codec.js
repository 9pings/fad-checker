/**
 * lib/codecs/yarn.codec.js — codec Yarn.
 *
 * Yarn partage tout avec npm (même registre npmjs, même OSV ecosystem "npm",
 * mêmes coordKeys "npm:<name>"). Il n'existe que pour fournir son label et sa
 * recette (`resolutions`) au report. Le scan JS est fait UNE SEULE FOIS par le
 * codec npm (qui ramasse package-lock ET yarn.lock) — yarn.collect est un no-op
 * pour éviter le double scan ; le registre des codecs ne l'appelle pas.
 */
const npm = require("./npm.codec");

// Recette inline temporaire — remplacée par require("./recipes").yarn en Task 6.
const yarnRecipe = {
	label: "Yarn",
	pinSection: "A. Pin vulnerable transitives via yarn resolutions",
	pinIntro: () => "Add to the root package.json and run yarn install.",
	snippet: () => "",
	directSection: "B. Or update the direct dependencies (and run yarn install)",
};

module.exports = {
	...npm,
	id: "yarn",
	label: "Yarn",
	recipe: yarnRecipe,
	collectViaSibling: "npm",   // documente que le scan est fait par le codec npm
	collect: async () => ({ deps: new Map(), warnings: [] }),
};
