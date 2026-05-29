/**
 * lib/composer/parse.js — parse PHP Composer manifests.
 *
 *   composer.lock — { packages: [{name, version}], "packages-dev": [...] }
 *                   versions are concrete (resolved) — the ideal source.
 *   composer.json — { require: {name: range}, "require-dev": {...} }
 *                   used only as a no-lock fallback (pinned exact versions).
 *
 * Composer names are "vendor/package", case-insensitive (lowercased by convention).
 */
const fs = require("fs");

// "1.2.3" | "v1.2.3" | "dev-main" | "1.0.x-dev". Strip a leading "v" for OSV/registry.
function normVersion(v) {
	if (!v) return null;
	return String(v).replace(/^v/, "");
}
function isConcrete(v) {
	if (!v) return false;
	return /^\d+(\.\d+)*([.\-+]\S+)?$/.test(String(v).replace(/^v/, ""));
}
function splitName(full) {
	const i = full.indexOf("/");
	if (i < 0) return { vendor: "", pkg: full };
	return { vendor: full.slice(0, i), pkg: full.slice(i + 1) };
}

function parseComposerLock(filePath) {
	const json = JSON.parse(fs.readFileSync(filePath, "utf8"));
	const deps = [];
	const push = (arr, scope) => {
		for (const p of arr || []) {
			if (!p.name) continue;
			const { vendor, pkg } = splitName(p.name);
			deps.push({ name: p.name, vendor, pkg, version: normVersion(p.version), scope, isDev: scope === "dev" });
		}
	};
	push(json.packages, "prod");
	push(json["packages-dev"], "dev");
	return { manifestPath: filePath, manifestType: "composer.lock", deps };
}

function parseComposerJson(filePath) {
	const json = JSON.parse(fs.readFileSync(filePath, "utf8"));
	const deps = [];
	const push = (obj, scope) => {
		for (const [name, version] of Object.entries(obj || {})) {
			// Platform requirements aren't packages.
			if (name === "php" || name.startsWith("ext-") || name.startsWith("lib-")) continue;
			const { vendor, pkg } = splitName(name);
			deps.push({ name, vendor, pkg, version: String(version), scope, isDev: scope === "dev" });
		}
	};
	push(json.require, "prod");
	push(json["require-dev"], "dev");
	return { manifestPath: filePath, manifestType: "composer.json", deps };
}

module.exports = { parseComposerLock, parseComposerJson, normVersion, isConcrete, splitName };
