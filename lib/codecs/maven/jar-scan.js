/**
 * lib/codecs/maven/jar-scan.js — discover Maven coordinates from embedded JARs.
 *
 * Many projects ship binary archives committed straight into the tree — a
 * vendored `lib/*.jar`, a Spring-Boot fat-jar under `BOOT-INF/lib/`, an uber-jar
 * with shaded dependencies, or jars inside a `.war`/`.ear`. None of those appear
 * in a `pom.xml`, so the manifest-based scan misses them. This module walks the
 * tree, reads every archive IN MEMORY (via fflate — a nested jar is just a zip
 * Buffer, so recursion needs no temp files and there is no zip-slip risk because
 * nothing is ever written to disk), and extracts each artifact's coordinate from,
 * in order of trust:
 *   1. META-INF/maven/<groupId>/<artifactId>/pom.properties  (authoritative)
 *   2. META-INF/MANIFEST.MF  (Implementation-* / OSGi Bundle-* headers)
 *   3. the file name  (commons-lang3-3.12.0.jar → commons-lang3 @ 3.12.0)
 * An archive whose coordinate can't be determined is reported as a warning, not
 * scanned blindly.
 *
 * Output deps carry provenance:"embedded" + a manifestPath using the `!/` nesting
 * notation (e.g. dist/app.jar!/BOOT-INF/lib/log4j-core-2.14.0.jar) so the report
 * can group them under their containing archive.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const { unzipSync, strFromU8 } = require("fflate");
const { makeDepRecord } = require("../../dep-record");

const ARCHIVE_RE = /\.(jar|war|ear)$/i;
const SKIP_DIRS = new Set(["node_modules", ".git", "target", "build", "out", "dist-newstyle", ".gradle", ".m2"]);
// A fat-jar can be large; cap what we read into memory and how deep we recurse.
const MAX_ARCHIVE_BYTES = 512 * 1024 * 1024;
const MAX_DEPTH = 8;

/** Parse a META-INF/maven/.../pom.properties body → { groupId, artifactId, version } | null. */
function coordFromPomProperties(text) {
	const get = re => (String(text || "").match(re) || [])[1]?.trim();
	const groupId = get(/^groupId=(.+)$/m);
	const artifactId = get(/^artifactId=(.+)$/m);
	const version = get(/^version=(.+)$/m);
	if (groupId && artifactId && version) return { groupId, artifactId, version };
	return null;
}

/**
 * Parse a MANIFEST.MF body → { groupId, artifactId, version } | null.
 * Tries Implementation-* first, then OSGi Bundle-*. groupId is best-effort: the
 * manifest rarely carries it, so we fall back to the OSGi symbolic name or "".
 */
function coordFromManifest(text) {
	// MANIFEST.MF folds long lines with a leading space on continuation lines.
	const unfolded = String(text || "").replace(/\r?\n /g, "");
	const h = name => (unfolded.match(new RegExp(`^${name}:\\s*(.+)$`, "im")) || [])[1]?.trim();
	const title = h("Implementation-Title") || h("Bundle-Name");
	const implVer = h("Implementation-Version") || h("Bundle-Version") || h("Specification-Version");
	const symbolic = h("Bundle-SymbolicName");
	const vendor = h("Implementation-Vendor-Id") || h("Implementation-Vendor");
	// OSGi symbolic name (org.apache.commons.lang3) is the most coordinate-like.
	let groupId = "", artifactId = title || symbolic;
	if (symbolic && symbolic.includes(".")) {
		const parts = symbolic.split(";")[0].split(".");
		artifactId = parts.pop();
		groupId = parts.join(".");
	} else if (vendor && vendor.includes(".")) {
		groupId = vendor;
	}
	if (artifactId && implVer) return { groupId: groupId || vendor || "", artifactId, version: implVer };
	return null;
}

/**
 * Parse an archive file name → { groupId:"", artifactId, version } | null.
 * Handles `name-1.2.3.jar`, `name-1.2.3-SNAPSHOT.jar`, `name-1.2.3-classifier.jar`.
 * The version token is the first dash-separated segment that starts with a digit.
 */
function coordFromFilename(fileName) {
    const base = String(fileName || "").replace(ARCHIVE_RE, "");
    const m = base.match(/^(.+?)-(\d[\w.]*(?:-[A-Za-z0-9]+)?)$/);
    if (!m) return null;
    return { groupId: "", artifactId: m[1], version: m[2] };
}

/** Read the named entries from an in-memory zip buffer. Returns {} on a corrupt zip. */
function readEntries(buf, filter) {
	try {
		return unzipSync(buf, filter ? { filter: f => filter(f.name) } : undefined);
	} catch {
		return null; // not a valid zip / unsupported (e.g. ZIP64 edge) — caller warns
	}
}

/**
 * Resolve a single archive's own coordinate + confidence from its entries.
 * Returns { coord, source } | null. `source` ∈ pom.properties|manifest|filename.
 */
function coordForArchive(entries, fileName) {
	// 1. pom.properties (there may be several in a fat-jar; the archive's OWN is the
	//    one whose path matches its identity — but for the top artifact we take the
	//    first. Nested libs are handled separately as their own archives.)
	for (const name of Object.keys(entries)) {
		if (/^META-INF\/maven\/[^/]+\/[^/]+\/pom\.properties$/.test(name)) {
			const coord = coordFromPomProperties(strFromU8(entries[name]));
			if (coord) return { coord, source: "pom.properties" };
		}
	}
	const mf = entries["META-INF/MANIFEST.MF"];
	if (mf) {
		const coord = coordFromManifest(strFromU8(mf));
		if (coord) return { coord, source: "manifest" };
	}
	const coord = coordFromFilename(fileName);
	if (coord) return { coord, source: "filename" };
	return null;
}

/**
 * Recursively scan one archive buffer. Pushes embedded depRecords into `out` and
 * warnings into `warnings`. `displayPath` is the `!/`-joined logical path.
 */
function scanArchiveBuffer(buf, displayPath, fileName, out, warnings, depth) {
	if (depth > MAX_DEPTH) { warnings.push({ type: "embedded-jar", message: `nesting too deep, skipped: ${displayPath}` }); return; }
	if (buf.length > MAX_ARCHIVE_BYTES) { warnings.push({ type: "embedded-jar", message: `archive too large (${Math.round(buf.length / 1048576)}MB), skipped: ${displayPath}` }); return; }

	// Read only what we need: this archive's identity files + any nested archives.
	const entries = readEntries(buf, name =>
		/^META-INF\/maven\/[^/]+\/[^/]+\/pom\.properties$/.test(name) ||
		name === "META-INF/MANIFEST.MF" ||
		ARCHIVE_RE.test(name));
	if (entries === null) { warnings.push({ type: "embedded-jar", message: `could not read archive (corrupt/unsupported): ${displayPath}` }); return; }

	const resolved = coordForArchive(entries, fileName);
	if (resolved) {
		const { coord, source } = resolved;
		out.push(makeDepRecord({
			ecosystem: "maven",
			namespace: coord.groupId || "",
			name: coord.artifactId,
			version: coord.version,
			manifestPath: displayPath,
			scope: "embedded",
			provenance: "embedded",
		}));
	} else {
		warnings.push({ type: "embedded-jar", message: `embedded archive with no resolvable Maven coordinate (not scanned): ${displayPath}` });
	}

	// Recurse into nested archives (fat-jar libs).
	for (const name of Object.keys(entries)) {
		if (!ARCHIVE_RE.test(name)) continue;
		const nestedBuf = entries[name];
		if (!nestedBuf || !nestedBuf.length) continue;
		scanArchiveBuffer(Buffer.from(nestedBuf), `${displayPath}!/${name}`, path.basename(name), out, warnings, depth + 1);
	}
}

/** Recursively list archive file paths under `dir`. */
function findArchives(dir, acc = []) {
	let entries;
	try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
	catch { return acc; }
	for (const e of entries) {
		if (e.isDirectory && e.isDirectory()) {
			if (SKIP_DIRS.has(e.name) || e.name.startsWith(".")) continue;
			findArchives(path.join(dir, e.name), acc);
		} else if (e.isFile() && ARCHIVE_RE.test(e.name)) {
			acc.push(path.join(dir, e.name));
		}
	}
	return acc;
}

/**
 * Scan `rootDir` for embedded JAR/WAR/EAR coordinates.
 * @returns { deps: depRecord[], warnings: [{type,message}] }
 */
function scanEmbeddedJars(rootDir, opts = {}) {
	const out = [];
	const warnings = [];
	const archives = findArchives(rootDir);
	for (const abs of archives) {
		let buf;
		try { buf = fs.readFileSync(abs); }
		catch (e) { warnings.push({ type: "embedded-jar", message: `could not read ${abs}: ${e.message}` }); continue; }
		const rel = opts.srcRoot ? path.relative(opts.srcRoot, abs) : abs;
		scanArchiveBuffer(buf, rel.split(path.sep).join("/"), path.basename(abs), out, warnings, 0);
	}
	return { deps: out, warnings };
}

module.exports = {
	scanEmbeddedJars,
	findArchives,
	coordFromPomProperties,
	coordFromManifest,
	coordFromFilename,
	coordForArchive,
	scanArchiveBuffer,
};
