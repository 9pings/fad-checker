/**
 * lib/codecs/index.js — registre des codecs.
 *
 * getCodec(id)      → le codec, ou null
 * allCodecs()       → tous les codecs enregistrés, dans l'ordre report stable
 * detectCodecs(dir) → les codecs dont detect() est vrai sur ce répertoire
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { assertCodecShape } = require("./codec.interface");
const maven = require("./maven.codec");
const npm = require("./npm.codec");
const yarn = require("./yarn.codec");
const composer = require("./composer.codec");
const pypi = require("./pypi.codec");
const nuget = require("./nuget.codec");

// Ordre stable pour le report (maven, npm, yarn, puis les nouveaux écosystèmes).
const ORDER = ["maven", "npm", "yarn", "nuget", "composer", "pypi"];

const REGISTRY = new Map();
for (const c of [maven, npm, yarn, composer, pypi, nuget]) {
	assertCodecShape(c);
	REGISTRY.set(c.id, c);
}

function getCodec(id) { return REGISTRY.get(id) || null; }

function allCodecs() {
	return [...REGISTRY.values()].sort((a, b) => ORDER.indexOf(a.id) - ORDER.indexOf(b.id));
}

// yarn est détecté via le même arbre JS que npm ; on ne le renvoie pas en
// doublon de détection (npm.collect ramasse déjà yarn.lock).
function detectCodecs(dir) {
	return allCodecs().filter(c => c.id !== "yarn" && c.detect(dir));
}

module.exports = { getCodec, allCodecs, detectCodecs, ORDER };
