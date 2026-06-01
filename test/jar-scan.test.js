const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
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

test("scanEmbeddedJars finds fat-jar libs, recurses, warns on unidentifiable, skips node_modules", () => {
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

	const { deps, warnings } = scanEmbeddedJars(dir, { srcRoot: dir });
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

test("scanEmbeddedJars warns (does not throw) on a corrupt archive", () => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-jarscan-"));
	fs.writeFileSync(path.join(dir, "broken.jar"), Buffer.from("not a zip at all"));
	const { deps, warnings } = scanEmbeddedJars(dir, { srcRoot: dir });
	assert.equal(deps.length, 0);
	assert.ok(warnings.some(w => /broken\.jar/.test(w.message)));
	fs.rmSync(dir, { recursive: true, force: true });
});
