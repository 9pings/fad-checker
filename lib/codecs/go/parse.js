/**
 * lib/codecs/go/parse.js — parse go.mod (authoritative for selected versions on
 * Go ≥1.17, which lists the full pruned module graph) with go.sum as fallback.
 *
 * Versions are stored WITHOUT the leading "v" (OSV's Go ecosystem and our
 * version comparisons expect bare semver; the purl layer re-adds context).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const { compareMavenVersions } = require("../../maven-version");

function stripV(v) { return String(v || "").replace(/^v/, ""); }

/** Parse go.mod → { module, deps: [{ name, version, scope, isDev }] }. */
function parseGoMod(text) {
	const out = { module: null, deps: [] };
	const lines = String(text || "").split(/\r?\n/);
	let inRequire = false;
	const seen = new Set();
	const addReq = (name, ver, indirect) => {
		if (!name || !ver) return;
		const key = `${name}@${ver}`;
		if (seen.has(key)) return;
		seen.add(key);
		out.deps.push({ name, version: stripV(ver), scope: indirect ? "transitive" : "compile", isDev: false });
	};
	for (let raw of lines) {
		const noComment = raw.split("//")[0].trim();
		const indirect = /\/\/\s*indirect/.test(raw);
		if (noComment.startsWith("module ")) { out.module = noComment.slice(7).trim(); continue; }
		if (noComment === "require (") { inRequire = true; continue; }
		if (inRequire && noComment === ")") { inRequire = false; continue; }
		if (inRequire) {
			const m = noComment.match(/^(\S+)\s+(\S+)/);
			if (m) addReq(m[1], m[2], indirect);
			continue;
		}
		const single = noComment.match(/^require\s+(\S+)\s+(\S+)/);
		if (single) addReq(single[1], single[2], indirect);
	}
	return out;
}

/** Parse go.sum → deps (fallback when go.mod has no require list). Highest version per module. */
function parseGoSum(text) {
	const byMod = new Map();
	for (const raw of String(text || "").split(/\r?\n/)) {
		const m = raw.trim().match(/^(\S+)\s+(v\S+?)(\/go\.mod)?\s+h1:/);
		if (!m) continue;
		const name = m[1];
		const ver = stripV(m[2]);
		// go.sum lists every version in the module graph; keep the highest (the
		// comment promised this but the code kept the first one encountered).
		const prev = byMod.get(name);
		if (!prev || compareMavenVersions(ver, prev) > 0) byMod.set(name, ver);
	}
	return { deps: [...byMod.entries()].map(([name, version]) => ({ name, version, scope: "transitive", isDev: false })) };
}

function parseGoModFile(fp) { return parseGoMod(fs.readFileSync(fp, "utf8")); }
function parseGoSumFile(fp) { return parseGoSum(fs.readFileSync(fp, "utf8")); }

module.exports = { parseGoMod, parseGoSum, parseGoModFile, parseGoSumFile, stripV };
