/**
 * lib/codecs/composer.codec.js — codec PHP/Composer.
 *
 * Vuln scanning is OSV (ecosystem "Packagist", wired in Plan A). This codec adds
 * collection (composer.lock, composer.json fallback), Packagist registry
 * (abandoned + outdated), and EOL via endoflife.date.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const { makeDepRecord, coordKeyFor } = require("../dep-record");
const { parseComposerLock, parseComposerJson, isConcrete } = require("./composer/parse");

const SKIP = new Set(["vendor", ".git", ".idea", ".vscode", "node_modules", "dist", "build", "out", "target"]);

function findComposerManifests(dir, skipDir = (child, name) => SKIP.has(name)) {
	const groups = [];
	const stack = [dir];
	while (stack.length) {
		const cur = stack.pop();
		let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
		const names = new Set(entries.filter(e => e.isFile()).map(e => e.name));
		if (names.has("composer.json") || names.has("composer.lock")) {
			groups.push({
				dir: cur,
				composerJson: names.has("composer.json") ? path.join(cur, "composer.json") : null,
				composerLock: names.has("composer.lock") ? path.join(cur, "composer.lock") : null,
			});
		}
		for (const e of entries) if (e.isDirectory() && !skipDir(path.join(cur, e.name), e.name)) stack.push(path.join(cur, e.name));
	}
	return groups;
}

function dirFilter(dir, opts) {
	return require("../path-filter").makeDirFilter({ srcRoot: opts.srcRoot || dir, defaultSkip: SKIP, excludePath: opts.excludePath, useDefaults: opts.defaultExcludes !== false });
}

module.exports = {
	id: "composer",
	label: "Composer",
	osvEcosystem: "Packagist",
	manifestNames: ["composer.json", "composer.lock"],

	detect(dir) { return findComposerManifests(dir).length > 0; },

	async collect(dir, opts = {}) {
		const { ignoreTest, deps2Exclude } = opts;
		const out = new Map();
		const warnings = [];
		for (const g of findComposerManifests(dir, dirFilter(dir, opts))) {
			if (g.composerLock) {
				let parsed;
				try { parsed = parseComposerLock(g.composerLock); }
				catch (e) { warnings.push({ type: "parse-error", manifestPath: g.composerLock, message: `composer.lock parse failed: ${e.message}` }); continue; }
				const { deps } = parsed;
				for (const d of deps) {
					if (ignoreTest && d.isDev) continue;
					if (deps2Exclude && deps2Exclude.test(d.name)) continue;
					out.set(coordKeyFor("composer", d.vendor, d.pkg),
						makeDepRecord({ ecosystem: "composer", namespace: d.vendor, name: d.pkg, version: d.version, manifestPath: g.composerLock, scope: d.scope, isDev: d.isDev }));
				}
			} else if (g.composerJson) {
				// No lockfile → best-effort: pinned exact versions only + warning.
				let parsed;
				try { parsed = parseComposerJson(g.composerJson); }
				catch (e) { warnings.push({ type: "parse-error", manifestPath: g.composerJson, message: `composer.json parse failed: ${e.message}` }); continue; }
				const { deps } = parsed;
				let pinned = 0, ranges = 0;
				for (const d of deps) {
					if (ignoreTest && d.isDev) continue;
					if (deps2Exclude && deps2Exclude.test(d.name)) continue;
					if (isConcrete(d.version)) {
						out.set(coordKeyFor("composer", d.vendor, d.pkg),
							makeDepRecord({ ecosystem: "composer", namespace: d.vendor, name: d.pkg, version: String(d.version).replace(/^v/, ""), manifestPath: g.composerJson, scope: d.scope, isDev: d.isDev }));
						pinned++;
					} else {
						ranges++;
					}
				}
				warnings.push({ type: "no-lockfile", manifestPath: g.composerJson, message: `composer.json without composer.lock — best-effort: ${pinned} pinned, ${ranges} range(s) skipped (run "composer install")` });
			}
		}
		return { deps: out, warnings };
	},

	coordKey(d) { return coordKeyFor("composer", d.namespace || "", d.name); },
	formatCoord(d) { return `${d.namespace || ""}/${d.name}`; },
	osvPackageName(d) { return `${d.namespace || ""}/${d.name}`; },

	async checkRegistry(deps, opts = {}) {
		const { checkComposerRegistryDeps } = require("./composer/registry");
		return checkComposerRegistryDeps(deps, opts);
	},
	resolveEolProduct(d) { return require("../outdated").findEolProduct(d); },
	recipe: require("./recipes").composer,
	nativeScanners: [],
};
