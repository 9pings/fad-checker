/**
 * lib/codecs/select.js — résout la liste des codecs actifs depuis le flag
 * --ecosystem et les flags --no-<id>.
 *
 *   requested  : "auto" | "all" | "maven" | "maven,npm,pypi" | (legacy "both"|"npm")
 *   available  : ids candidats — pour "auto", les codecs détectés ; sinon tous.
 *   flags      : { noCodecs: ["npm", ...], noJs: bool }
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
function resolveActiveCodecs(requested, available, flags = {}) {
	const { noCodecs = [], noJs = false } = flags;
	const req = String(requested || "auto").toLowerCase();
	let active;
	if (req === "auto" || req === "all") {
		active = [...available];
	} else if (req === "both") {
		// rétro-compat : "both" == maven + npm/yarn
		active = available.filter(id => ["maven", "npm", "yarn"].includes(id));
	} else {
		const wanted = req.split(",").map(s => s.trim()).filter(Boolean);
		active = available.filter(id => wanted.includes(id));
	}
	const excluded = new Set(noCodecs);
	if (noJs) { excluded.add("npm"); excluded.add("yarn"); }
	return active.filter(id => !excluded.has(id));
}

module.exports = { resolveActiveCodecs };
