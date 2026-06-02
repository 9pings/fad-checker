const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { zipSync, strToU8 } = require("fflate");
const {
	scanEmbeddedJars,
	coordFromPomProperties,
	coordFromManifest,
	coordFromFilename,
} = require("../lib/codecs/maven/jar-scan");

test("coordFromPomProperties extracts g:a:v", () => {
	const c = coordFromPomProperties("groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.0\n");
	assert.deepEqual(c, { groupId: "org.apache.logging.log4j", artifactId: "log4j-core", version: "2.14.0" });
	assert.equal(coordFromPomProperties("artifactId=x\n"), null); // incomplete → null
});

test("coordFromManifest reads Implementation-* and OSGi Bundle-*", () => {
	assert.deepEqual(
		coordFromManifest("Implementation-Title: myapp\nImplementation-Version: 1.0.0\n"),
		{ groupId: "", artifactId: "myapp", version: "1.0.0" });
	const osgi = coordFromManifest("Bundle-SymbolicName: org.apache.commons.lang3\nBundle-Version: 3.12.0\n");
	assert.equal(osgi.artifactId, "lang3");
	assert.equal(osgi.groupId, "org.apache.commons");
	assert.equal(osgi.version, "3.12.0");
});

test("coordFromFilename splits name-version", () => {
	assert.deepEqual(coordFromFilename("commons-lang3-3.12.0.jar"), { groupId: "", artifactId: "commons-lang3", version: "3.12.0" });
	assert.deepEqual(coordFromFilename("guava-31.1-jre.jar"), { groupId: "", artifactId: "guava", version: "31.1-jre" });
	assert.equal(coordFromFilename("no-version.jar"), null);
});

test("scanEmbeddedJars finds fat-jar libs, recurses, warns on unidentifiable, skips node_modules", async () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-jarscan-"));
	const inner = zipSync({ "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties": strToU8("groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.0\n") });
	const outer = zipSync({
		"META-INF/MANIFEST.MF": strToU8("Manifest-Version: 1.0\nImplementation-Title: myapp\nImplementation-Version: 1.0.0\n"),
		"BOOT-INF/lib/log4j-core-2.14.0.jar": inner,
		"BOOT-INF/lib/commons-text-1.9.jar": zipSync({ "x.class": strToU8("x") }),
		"BOOT-INF/lib/mystery.jar": zipSync({ "com/x/Foo.class": strToU8("x") }),
	});
	fs.writeFileSync(path.join(dir, "app.jar"), Buffer.from(outer));
	fs.mkdirSync(path.join(dir, "node_modules"));
	fs.writeFileSync(path.join(dir, "node_modules", "ignore.jar"), Buffer.from(outer));

	const { deps, warnings } = await scanEmbeddedJars(dir, { srcRoot: dir });
	const byName = Object.fromEntries(deps.map(d => [d.name, d]));

	// fat-jar's own coord (from MANIFEST), nested lib from pom.properties + from filename
	assert.equal(byName["myapp"].version, "1.0.0");
	assert.equal(byName["log4j-core"].namespace, "org.apache.logging.log4j");
	assert.equal(byName["log4j-core"].version, "2.14.0");
	assert.equal(byName["commons-text"].version, "1.9");
	// every embedded record is tagged + uniquely keyed by its physical path
	assert.ok(deps.every(d => d.provenance === "embedded"));
	assert.ok(deps.every(d => d.coordKey.startsWith("embedded:")));
	assert.match(byName["log4j-core"].manifestPaths[0], /app\.jar!\/BOOT-INF\/lib\/log4j-core-2\.14\.0\.jar$/);
	// unidentifiable jar → warning, not a silent skip
	assert.ok(warnings.some(w => /mystery\.jar/.test(w.message)));
	// node_modules ignored
	assert.ok(!deps.some(d => d.manifestPaths[0].includes("node_modules")));

	fs.rmSync(dir, { recursive: true, force: true });
});

test("scanEmbeddedJars warns (does not throw) on a corrupt archive", async () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-jarscan-"));
	fs.writeFileSync(path.join(dir, "broken.jar"), Buffer.from("not a zip at all"));
	const { deps, warnings } = await scanEmbeddedJars(dir, { srcRoot: dir });
	assert.equal(deps.length, 0);
	assert.ok(warnings.some(w => /broken\.jar/.test(w.message)));
	fs.rmSync(dir, { recursive: true, force: true });
});

test("scanEmbeddedJars reads only the coordinate, not the whole jar (lazy central-dir read)", async () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-jarscan-"));
	// 16MB of incompressible data → a genuinely large on-disk jar whose bulk is .class.
	const big = crypto.randomBytes(16 * 1024 * 1024);
	const jar = zipSync({
		"META-INF/maven/com.acme/widget/pom.properties": strToU8("groupId=com.acme\nartifactId=widget\nversion=4.5.6\n"),
		"com/acme/Huge.class": big,
	});
	const jp = path.join(dir, "widget-4.5.6.jar");
	fs.writeFileSync(jp, Buffer.from(jar));
	const fileSize = fs.statSync(jp).size;

	let bytesRead = 0;
	const orig = fs.readSync;
	fs.readSync = function (...args) { const n = orig.apply(this, args); bytesRead += n; return n; };
	let deps;
	try { ({ deps } = await scanEmbeddedJars(dir, { srcRoot: dir })); }
	finally { fs.readSync = orig; }

	assert.equal(deps.length, 1);
	assert.equal(deps[0].name, "widget");
	assert.equal(deps[0].version, "4.5.6");
	// The .class bytes must never be touched: total reads stay a tiny fraction of the file.
	assert.ok(fileSize > 8 * 1024 * 1024, "fixture jar should be large");
	assert.ok(bytesRead < fileSize / 50, `expected to read <2% of ${fileSize} bytes, read ${bytesRead}`);
	fs.rmSync(dir, { recursive: true, force: true });
});

test("scanEmbeddedJars reports progress for every archive, nested ones included", async () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-jarscan-"));
	const inner = zipSync({ "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties": strToU8("groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.0\n") });
	const fat = zipSync({ "BOOT-INF/lib/log4j-core-2.14.0.jar": inner, "BOOT-INF/classes/App.class": strToU8("x") });
	fs.writeFileSync(path.join(dir, "app.jar"), Buffer.from(fat));

	const events = [];
	await scanEmbeddedJars(dir, { srcRoot: dir, onProgress: e => events.push(e) });

	assert.equal(events[0].phase, "start");
	assert.equal(events.at(-1).phase, "done");
	const scanned = events.filter(e => e.phase === "scan");
	// One event for the outer app.jar, one for the nested log4j-core jar.
	assert.equal(scanned.length, 2);
	assert.ok(scanned.some(e => /^app\.jar$/.test(e.path)));
	assert.ok(scanned.some(e => /app\.jar!\/BOOT-INF\/lib\/log4j-core-2\.14\.0\.jar$/.test(e.path)));
	fs.rmSync(dir, { recursive: true, force: true });
});
