/**
 * lib/codecs/gradle.codec.js — codec Gradle.
 *
 * A Gradle dependency IS a Maven coordinate resolved from Maven repositories, so records
 * are emitted with `ecosystem: "maven"` (bare `g:a` coordKey → the Maven CVE-index, OSV
 * "Maven", transitive resolution, import-BOM backfill, outdated and EOL all treat them
 * unchanged) but `ecosystemType: "gradle"` so the report gives them a dedicated "Gradle"
 * chapter and a Gradle fix recipe (cve-report's codecFor() resolves by ecosystemType).
 *
 * Parsing is lockfile-first (gradle.lockfile = resolved, authoritative) and otherwise
 * best-effort over the build scripts + version catalog (see ./gradle/parse.js). `platform()`
 * BOMs are surfaced in `_gradle.platformBoms` for the orchestrator to feed into the existing
 * lib/maven-bom.js backfill, mirroring Maven's `<scope>import</scope>` BOMs.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const { makeDepRecord, coordKeyFor } = require("../dep-record");
const { parseGradleLockfile, parseGradleProperties, parseBuildScript } = require("./gradle/parse");
const { parseVersionCatalog } = require("./gradle/catalog");

const SKIP = new Set([".git", ".idea", ".vscode", "node_modules", "dist", "out", "target", "build", ".gradle", ".mvn", "bin"]);
const BUILD_FILES = new Set(["build.gradle", "build.gradle.kts"]);
const SETTINGS_FILES = new Set(["settings.gradle", "settings.gradle.kts"]);
const DETECT_HITS = new Set([...BUILD_FILES, ...SETTINGS_FILES, "gradle.lockfile", "libs.versions.toml"]);

function readSafe(fp) { try { return fs.readFileSync(fp, "utf8"); } catch { return ""; } }
function inBuildSrc(fp) { return /(^|[\\/])buildSrc[\\/]/.test(fp); }

function dirFilter(dir, opts) {
	return require("../path-filter").makeDirFilter({ srcRoot: opts.srcRoot || dir, defaultSkip: SKIP, excludePath: opts.excludePath, useDefaults: opts.defaultExcludes !== false });
}

// One walk → classify every relevant Gradle file.
function walkGradle(dir, skipDir) {
	const buildFiles = [], catalogFiles = [], propsFiles = [];
	const lockByDir = new Map();
	const stack = [dir];
	while (stack.length) {
		const cur = stack.pop();
		let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
		for (const e of entries) {
			const p = path.join(cur, e.name);
			if (e.isDirectory()) { if (!skipDir(p, e.name)) stack.push(p); continue; }
			if (!e.isFile()) continue;
			if (BUILD_FILES.has(e.name)) buildFiles.push(p);
			else if (SETTINGS_FILES.has(e.name)) { /* structure only; not a dep source */ }
			else if (e.name === "gradle.lockfile") lockByDir.set(cur, p);
			else if (e.name === "libs.versions.toml" || e.name.endsWith(".versions.toml")) catalogFiles.push(p);
			else if (e.name === "gradle.properties") propsFiles.push(p);
			else if (e.name.endsWith(".gradle.kts") || e.name.endsWith(".gradle")) buildFiles.push(p); // precompiled convention plugins (buildSrc)
		}
	}
	return { buildFiles, catalogFiles, propsFiles, lockByDir };
}

// Merge every version catalog in the tree into one resolution table (root + buildSrc).
function mergeCatalogs(files) {
	const merged = { versions: {}, libraries: {}, plugins: {}, _byAccessor: {} };
	for (const f of files) {
		const c = parseVersionCatalog(readSafe(f));
		Object.assign(merged.versions, c.versions);
		Object.assign(merged.libraries, c.libraries);
		Object.assign(merged.plugins, c.plugins);
		Object.assign(merged._byAccessor, c._byAccessor);
	}
	return merged;
}

module.exports = {
	id: "gradle",
	label: "Gradle",
	osvEcosystem: "Maven",
	manifestNames: ["build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradle.lockfile", "*.versions.toml"],

	detect(dir) {
		const skipDir = (p, name) => SKIP.has(name);
		const stack = [dir];
		while (stack.length) {
			const cur = stack.pop();
			let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
			for (const e of entries) {
				if (e.isFile() && (DETECT_HITS.has(e.name) || e.name.endsWith(".versions.toml"))) return true;
				if (e.isDirectory() && !skipDir(path.join(cur, e.name), e.name)) stack.push(path.join(cur, e.name));
			}
		}
		return false;
	},

	async collect(dir, opts = {}) {
		const { deps2Exclude } = opts;
		const skipDir = dirFilter(dir, opts);
		const { buildFiles, catalogFiles, propsFiles, lockByDir } = walkGradle(dir, skipDir);

		const catalog = mergeCatalogs(catalogFiles);
		const properties = {};
		for (const f of propsFiles) Object.assign(properties, parseGradleProperties(readSafe(f)));

		const out = new Map();
		const warnings = [];
		const platformBoms = [];

		const addRec = (d, manifestPath) => {
			if (!d.group || !d.name) return;
			if (deps2Exclude && deps2Exclude.test(d.name)) return;
			const rec = makeDepRecord({ ecosystem: "maven", ecosystemType: "gradle", namespace: d.group, name: d.name, version: d.version, manifestPath, scope: d.scope, isDev: d.isDev });
			const existing = out.get(rec.coordKey);
			if (!existing) { out.set(rec.coordKey, rec); return; }
			for (const p of rec.manifestPaths) if (!existing.manifestPaths.includes(p)) existing.manifestPaths.push(p);
			for (const v of rec.versions) if (!existing.versions.includes(v)) existing.versions.push(v);
			if (!existing.version && rec.version) existing.version = rec.version;
			if (rec.isDev === false) existing.isDev = false; // prod scope wins over dev
		};

		// gradle.lockfile = authoritative resolved versions (transitives incl.) for its project.
		const lockedDirs = new Set(lockByDir.keys());
		for (const [, fp] of lockByDir) {
			for (const d of parseGradleLockfile(readSafe(fp)).deps) addRec(d, fp);
		}

		// Build scripts: best-effort deps (skipped for a lock-governed top-level project) +
		// platform() BOMs (always collected — they drive the import-BOM backfill).
		for (const fp of buildFiles) {
			const d = path.dirname(fp);
			const r = parseBuildScript(readSafe(fp), { catalog, properties, kotlin: fp.endsWith(".kts") });
			for (const b of r.platformBoms) if (b.group && b.name && !platformBoms.some(x => x.group === b.group && x.name === b.name)) platformBoms.push(b);
			const lockGoverned = lockedDirs.has(d) && !inBuildSrc(fp);
			if (lockGoverned) continue; // lockfile already provided resolved deps for this dir
			for (const dep of r.deps) addRec(dep, fp);
			if (!inBuildSrc(fp)) warnings.push({ type: "gradle-no-lockfile", manifestPath: fp, message: `no gradle.lockfile next to ${path.relative(dir, fp) || path.basename(fp)} — versions resolved best-effort from the build script + version catalog (dynamic/programmatic deps may be missed). Enable Gradle dependency locking for exact coverage.` });
			for (const u of r.unresolved) warnings.push({ type: "unresolved-versions", manifestPath: fp, message: `could not resolve the version variable for ${u.group}:${u.name} (${u.raw}) — excluded from CVE matching` });
		}

		const parsedManifests = [...buildFiles, ...lockByDir.values(), ...catalogFiles, ...propsFiles];
		return { deps: out, warnings, parsedManifests, _gradle: { platformBoms } };
	},

	coordKey(d) { return coordKeyFor("maven", d.namespace || d.groupId, d.name || d.artifactId); },
	formatCoord(d) { return `${d.namespace || d.groupId}:${d.name || d.artifactId}`; },
	osvPackageName(d) { return `${d.namespace || d.groupId}:${d.name || d.artifactId}`; },

	async checkRegistry(deps, opts = {}) {
		const outdated = require("../outdated");
		const out = opts.allLibs ? await outdated.checkOutdatedDeps(deps, opts) : [];
		const deprecated = outdated.checkObsoleteDeps(deps);
		return { outdated: out, deprecated };
	},
	resolveEolProduct(d) { return require("../outdated").findEolProduct(d); },

	recipe: require("./recipes").gradle,

	nativeScanners: [],
};
