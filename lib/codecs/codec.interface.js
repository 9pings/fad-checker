/**
 * lib/codecs/codec.interface.js — contrat que tout codec doit respecter.
 *
 * Pas de classe imposée : un codec est un objet litéral exportant ces clés.
 * Voir docs/superpowers/specs/2026-05-29-codecs-multi-ecosystem-design.md.
 */
const REQUIRED_KEYS = [
	"id", "label", "osvEcosystem", "manifestNames",
	"detect", "collect", "coordKey", "formatCoord", "osvPackageName",
	"checkRegistry", "resolveEolProduct", "recipe", "nativeScanners",
];
const FUNCTION_KEYS = ["detect", "collect", "coordKey", "formatCoord", "osvPackageName", "checkRegistry", "resolveEolProduct"];

function assertCodecShape(codec) {
	if (!codec || typeof codec !== "object") throw new Error("codec must be an object");
	for (const k of REQUIRED_KEYS) {
		if (!(k in codec)) throw new Error(`codec "${codec.id || "?"}" missing required key: ${k}`);
	}
	for (const k of FUNCTION_KEYS) {
		if (typeof codec[k] !== "function") throw new Error(`codec "${codec.id}" key ${k} must be a function`);
	}
	if (!Array.isArray(codec.manifestNames)) throw new Error(`codec "${codec.id}" manifestNames must be an array`);
	if (!Array.isArray(codec.nativeScanners)) throw new Error(`codec "${codec.id}" nativeScanners must be an array`);
	return true;
}

module.exports = { REQUIRED_KEYS, FUNCTION_KEYS, assertCodecShape };
