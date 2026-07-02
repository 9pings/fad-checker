/**
 * lib/nuget/parse.js — parse .NET/NuGet manifests.
 *
 *   packages.lock.json     — JSON, { dependencies: { "<tfm>": { "<id>": { type, resolved } } } }
 *                            type "Direct"|"Transitive"; resolved = concrete version.
 *   *.csproj               — XML, <PackageReference Include Version>. Version may be an
 *                            attribute, a child element, or absent (Central Package Management).
 *   Directory.Packages.props — XML CPM, <PackageVersion Include Version> → name→version table.
 *   packages.config        — XML legacy, <package id version targetFramework />.
 *
 * NuGet ids are case-insensitive (lowercased for the key; original case kept for display).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const xml2js = require("xml2js");

// Concrete = starts with a digit and only [\w.+-] — rejects floating "1.*",
// range "[1.0,2.0)", and wildcard/comma/bracket specifiers.
function isConcrete(v) { const s = String(v || ""); return /^\d/.test(s) && /^[\w.+-]+$/.test(s); }

// "[1.2.3]" is NuGet's EXACT-version pin (a single-version range, common in
// csproj) — unwrap it to the inner concrete version instead of rejecting it.
function concreteVersion(v) {
	let s = String(v || "").trim();
	const exact = /^\[\s*([^,\[\]]+)\s*\]$/.exec(s);
	if (exact) s = exact[1].trim();
	return isConcrete(s) ? s : null;
}

async function parsePackagesLockJson(filePath) {
	const json = JSON.parse(fs.readFileSync(filePath, "utf8"));
	const deps = [];
	const seen = new Set();
	for (const fw of Object.values(json.dependencies || {})) {
		for (const [name, meta] of Object.entries(fw || {})) {
			const version = meta.resolved || null;
			if (!version) continue;
			const key = `${name.toLowerCase()}@${version}`;
			if (seen.has(key)) continue; seen.add(key);
			const scope = (meta.type === "Transitive") ? "transitive" : "prod";
			deps.push({ name, version, scope, isDev: false });
		}
	}
	return { manifestPath: filePath, manifestType: "packages.lock.json", deps };
}

async function parseDirectoryPackagesProps(filePath) {
	const xml = await xml2js.parseStringPromise(fs.readFileSync(filePath, "utf8"));
	const map = {};
	for (const ig of xml.Project?.ItemGroup || []) {
		for (const pv of ig.PackageVersion || []) {
			const id = pv.$?.Include; const v = pv.$?.Version;
			if (id && v) map[id.toLowerCase()] = v;
		}
	}
	return map;
}

async function parseCsproj(filePath, cpm = {}) {
	const xml = await xml2js.parseStringPromise(fs.readFileSync(filePath, "utf8"));
	const deps = [];
	let skipped = 0;
	for (const ig of xml.Project?.ItemGroup || []) {
		for (const pr of ig.PackageReference || []) {
			const name = pr.$?.Include; if (!name) continue;
			// Version: VersionOverride (CPM per-project override) wins, then the
			// attribute, then a child element, then the Directory.Packages.props pin.
			const raw = pr.$?.VersionOverride
				|| (Array.isArray(pr.VersionOverride) ? pr.VersionOverride[0] : null)
				|| pr.$?.Version
				|| (Array.isArray(pr.Version) ? pr.Version[0] : null)
				|| cpm[name.toLowerCase()] || null;
			const version = concreteVersion(raw);
			if (version) deps.push({ name, version, scope: "prod", isDev: false });
			else skipped++;
		}
	}
	return { manifestPath: filePath, manifestType: "csproj", deps, skipped };
}

async function parsePackagesConfig(filePath) {
	const xml = await xml2js.parseStringPromise(fs.readFileSync(filePath, "utf8"));
	const deps = [];
	for (const p of xml.packages?.package || []) {
		const name = p.$?.id; const version = concreteVersion(p.$?.version);
		if (name && version) deps.push({ name, version, scope: "prod", isDev: false });
	}
	return { manifestPath: filePath, manifestType: "packages.config", deps };
}

module.exports = { isConcrete, concreteVersion, parsePackagesLockJson, parseDirectoryPackagesProps, parseCsproj, parsePackagesConfig };
