/**
 * lib/codecs/gradle/parse.js — Gradle manifest parsers (lockfile-first, best-effort DSL).
 *
 *   gradle.lockfile            → authoritative `g:a:v=conf,conf` (resolved, transitives incl.)
 *   gradle.properties          → `key=value` (used to resolve `$var` versions)
 *   build.gradle / .kts        → best-effort regex over `dependencies { … }`:
 *                                string notation, map notation, version-catalog accessors
 *                                (`libs.foo.bar`), and `platform(...)` BOMs (surfaced
 *                                separately for the import-BOM backfill, NOT as a dep).
 *
 * A Gradle dependency IS a Maven coordinate, so the codec emits ecosystem "maven" records;
 * this module only turns the various Gradle surfaces into {group,name,version} tuples.
 * Versions that can't be resolved statically (programmatic constructs, missing var) come
 * back null — never assumed-vulnerable — and are listed in `unresolved` for a warning.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { resolveLibraryAccessor, findCatalogVersion } = require("./catalog");

const COORD = "[A-Za-z0-9_.\\-]+";

// Function/keyword call sites that look like a configuration but are NOT external deps.
const DENY = new Set([
	"id", "kotlin", "version", "project", "exclude", "platform", "enforcedPlatform",
	"files", "fileTree", "gradleApi", "localGroovy", "because", "create", "named",
	"register", "maven", "url", "uri", "from", "into", "extendsFrom", "add", "plugin",
	"apply", "alias", "set", "property", "the", "get", "named", "dependencies",
]);

function isTestConfig(c) { return /test/i.test(String(c || "")); }

function depScope(config) {
	const isDev = isTestConfig(config);
	return { scope: isDev ? "test" : "compile", isDev };
}

// Read the version expression that begins at s[i] (right after `g:a:` in a coord string).
// Handles a `${ … }` template (balanced braces — so a nested findVersion("x") with its own
// quotes/parens is captured whole), a bare `$var`, or a plain literal up to the closing quote.
function readVersionExpr(s, i) {
	if (s[i] === "$" && s[i + 1] === "{") {
		let depth = 0;
		for (let j = i + 1; j < s.length; j++) {
			if (s[j] === "{") depth++;
			else if (s[j] === "}" && --depth === 0) return s.slice(i, j + 1);
		}
		return s.slice(i);
	}
	if (s[i] === "$") { const m = s.slice(i).match(/^\$[\w.]+/); return m ? m[0] : null; }
	const m = s.slice(i).match(/^[^"'\s)]+/);
	return m ? m[0] : null;
}

/** Resolve a (possibly `$var` / catalog-backed) version expression → concrete string or null. */
function resolveVer(raw, ctx) {
	if (raw == null) return null;
	const v = String(raw).trim();
	if (!v) return null;
	if (v.includes("$")) {
		let m = v.match(/findVersion\(\s*["']([^"']+)["']\s*\)/);
		if (m) return findCatalogVersion(ctx.catalog, m[1]) || null;
		m = v.match(/libs\.versions\.([\w.]+?)(?:\.get\(\))?[\s}"')]*$/);
		if (m) { const r = findCatalogVersion(ctx.catalog, m[1]); if (r) return r; }
		m = v.match(/\$\{?([\w.]+)\}?/);
		if (m) {
			const k = m[1];
			if (ctx.localVars && ctx.localVars[k] != null) return ctx.localVars[k];
			if (ctx.properties && ctx.properties[k] != null) return ctx.properties[k];
		}
		return null;
	}
	const m = v.match(/[\w][\w.\-]*/);
	return m ? m[0] : null;
}

/** Parse the inner content of a `platform( … )` call → {group,name,version} or null. */
function parsePlatformCoord(content, ctx) {
	const c = String(content || "").trim();
	const head = c.match(new RegExp(`["']?\\s*(${COORD}):(${COORD}):`));
	if (head) {
		const tail = c.slice(c.indexOf(head[0]) + head[0].length);
		return { group: head[1], name: head[2], version: resolveVer(tail, ctx) || null };
	}
	const ga = c.match(new RegExp(`["']\\s*(${COORD}):(${COORD})\\s*["']`));
	if (ga) return { group: ga[1], name: ga[2], version: null };
	const lib = c.match(/libs\.([\w.]+)/);
	if (lib && ctx.catalog) {
		const e = resolveLibraryAccessor(ctx.catalog, lib[1]);
		if (e && e.group && e.name) return { group: e.group, name: e.name, version: e.version || null };
	}
	return null;
}

/** Parse a gradle.lockfile → { deps: [{group,name,version,scope,isDev,configurations}] }. */
function parseGradleLockfile(text) {
	const deps = [];
	for (const raw of String(text || "").split(/\r?\n/)) {
		const line = raw.trim();
		if (!line || line.startsWith("#")) continue;
		const eq = line.indexOf("=");
		if (eq < 0) continue;
		const coord = line.slice(0, eq).trim();
		if (coord === "empty") continue;
		const configurations = line.slice(eq + 1).split(",").map(s => s.trim()).filter(Boolean);
		const parts = coord.split(":");
		if (parts.length < 3 || !parts[0] || !parts[1] || !parts[2]) continue;
		const isDev = configurations.length > 0 && configurations.every(isTestConfig);
		deps.push({ group: parts[0], name: parts[1], version: parts[2], scope: isDev ? "test" : "compile", isDev, configurations });
	}
	return { deps };
}

/** Parse a gradle.properties → { key: value }. */
function parseGradleProperties(text) {
	const out = {};
	for (const raw of String(text || "").split(/\r?\n/)) {
		const line = raw.trim();
		if (!line || line.startsWith("#") || line.startsWith("!")) continue;
		const eq = line.indexOf("=");
		if (eq < 0) continue;
		const k = line.slice(0, eq).trim();
		if (k) out[k] = line.slice(eq + 1).trim();
	}
	return out;
}

/**
 * Best-effort parse of a build.gradle / build.gradle.kts.
 * @param opts { catalog, properties, kotlin } — catalog from parseVersionCatalog, properties
 *   from parseGradleProperties; `kotlin` is informational (the regexes accept both DSLs).
 * @returns { deps: [{group,name,version,configuration,scope,isDev}], platformBoms, unresolved }
 */
function parseBuildScript(text, opts = {}) {
	const src = String(text || "");
	const ctx = { catalog: opts.catalog || null, properties: opts.properties || {}, localVars: {} };
	for (const m of src.matchAll(/\b(?:val|def)\s+(\w+)\s*=\s*["']([^"']*)["']/g)) ctx.localVars[m[1]] = m[2];

	const deps = [];
	const platformBoms = [];
	const unresolved = [];
	const seen = new Set();
	const addDep = (group, name, versionRaw, config) => {
		if (!group || !name) return;
		const key = `${group}:${name}`;
		if (seen.has(key)) return;
		seen.add(key);
		const version = resolveVer(versionRaw, ctx) || null;
		if (versionRaw != null && /\$/.test(String(versionRaw)) && !version) unresolved.push({ group, name, raw: String(versionRaw), reason: "unresolved-variable" });
		deps.push({ group, name, version, configuration: config, ...depScope(config) });
	};

	// 1. platform()/enforcedPlatform() — balanced-paren scan (handles nested ${...} templates
	//    with their own quotes/parens), then blank the span so the inner coord isn't re-read.
	const platSpans = [];
	const re = /(?:enforced)?[Pp]latform\s*\(/g;
	let pm;
	while ((pm = re.exec(src))) {
		const open = src.indexOf("(", pm.index + pm[0].length - 1);
		if (open < 0) continue;
		let depth = 0, end = -1;
		for (let i = open; i < src.length; i++) {
			if (src[i] === "(") depth++;
			else if (src[i] === ")") { if (--depth === 0) { end = i; break; } }
		}
		if (end <= open) continue;
		const coord = parsePlatformCoord(src.slice(open + 1, end), ctx);
		if (coord && coord.group && coord.name && !platformBoms.some(b => b.group === coord.group && b.name === coord.name)) platformBoms.push(coord);
		platSpans.push([pm.index, end + 1]);
	}
	let work = src;
	if (platSpans.length) {
		let out = "", last = 0;
		for (const [s, e] of platSpans) { out += src.slice(last, s) + " ".repeat(e - s); last = e; }
		work = out + src.slice(last);
	}

	// 2. map notation: conf group: 'x', name: 'y'[, version: 'z']
	for (const m of work.matchAll(/\b(\w+)\s*\(?\s*group:\s*(["'])([^"']+)\2\s*,\s*name:\s*(["'])([^"']+)\4(?:\s*,\s*version:\s*(["'])([^"']+)\6)?/g)) {
		if (DENY.has(m[1])) continue;
		addDep(m[3], m[5], m[7] || null, m[1]);
	}
	// 3. string notation: conf("g:a[:v]") | conf 'g:a[:v]'. We match only the opening
	//    `conf("g:a` + optional `:` and then read the version expression manually, so a
	//    version like `${libs.findVersion("x").get()}` (nested quotes) isn't truncated.
	const strRe = new RegExp(`\\b(\\w+)\\s*(?:\\(\\s*)?(["'])(${COORD}):(${COORD})(:?)`, "g");
	let sm;
	while ((sm = strRe.exec(work))) {
		if (DENY.has(sm[1])) continue;
		const versionRaw = sm[5] === ":" ? readVersionExpr(work, sm.index + sm[0].length) : null;
		addDep(sm[3], sm[4], versionRaw, sm[1]);
	}
	// 4. version-catalog accessor: conf(libs.foo.bar)
	for (const m of work.matchAll(/\b(\w+)\s*(?:\(\s*)?libs\.([\w.]+)/g)) {
		if (DENY.has(m[1]) || m[1] === "libs") continue;
		const accessor = m[2];
		if (/^(versions|findVersion|bundles|plugins)\b/.test(accessor)) continue;
		const lib = resolveLibraryAccessor(ctx.catalog, accessor);
		if (lib && lib.group && lib.name) addDep(lib.group, lib.name, lib.version, m[1]);
	}
	return { deps, platformBoms, unresolved };
}

module.exports = { parseGradleLockfile, parseGradleProperties, parseBuildScript, resolveVer, depScope, isTestConfig };
