const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { zipSync, strToU8 } = require("fflate");
const mavenCodec = require("../lib/codecs/maven.codec");
const { buildCycloneDx } = require("../lib/sbom-export");
const { generateHtmlReport } = require("../lib/cve-report");
const { makeDepRecord } = require("../lib/dep-record");

function projectWithEmbeddedJar() {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-emb-"));
	fs.writeFileSync(path.join(dir, "pom.xml"),
		'<project><modelVersion>4.0.0</modelVersion><groupId>com.acme</groupId><artifactId>svc</artifactId><version>1.0.0</version></project>');
	const inner = zipSync({ "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties": strToU8("groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.0\n") });
	fs.mkdirSync(path.join(dir, "dist"));
	fs.writeFileSync(path.join(dir, "dist", "app.jar"), Buffer.from(zipSync({ "BOOT-INF/lib/log4j-core-2.14.0.jar": inner })));
	return dir;
}

test("maven codec collect() discovers embedded jar coords (default on)", async () => {
	const dir = projectWithEmbeddedJar();
	const { deps } = await mavenCodec.collect(dir, { srcRoot: dir });
	const embedded = [...deps.values()].filter(d => d.provenance === "embedded");
	assert.ok(embedded.some(d => d.name === "log4j-core" && d.version === "2.14.0"));
	assert.ok(embedded.every(d => d.coordKey.startsWith("embedded:")));
	fs.rmSync(dir, { recursive: true, force: true });
});

test("maven codec collect() skips jar scan when scanJars:false (--no-jars)", async () => {
	const dir = projectWithEmbeddedJar();
	const { deps } = await mavenCodec.collect(dir, { srcRoot: dir, scanJars: false });
	assert.equal([...deps.values()].filter(d => d.provenance === "embedded").length, 0);
	fs.rmSync(dir, { recursive: true, force: true });
});

test("HTML report renders the embedded-binaries chapter for embedded matches", () => {
	const dep = makeDepRecord({ ecosystem: "maven", namespace: "org.apache.logging.log4j", name: "log4j-core", version: "2.14.0", manifestPath: "dist/app.jar!/BOOT-INF/lib/log4j-core-2.14.0.jar", provenance: "embedded" });
	const html = generateHtmlReport({
		cveMatches: [], devCveMatches: [],
		embeddedMatches: [{ dep, source: "osv", cve: { id: "CVE-2021-44228", severity: "CRITICAL", score: 10 } }],
		retireMatches: [], eolResults: [], obsoleteResults: [], outdatedResults: [], licenseResults: {},
		resolvedDeps: new Map([[dep.coordKey, dep]]),
		projectInfo: { name: "svc", src: "/x", generatedAt: "now" },
		warnings: [],
	});
	assert.match(html, /1B\. Embedded binaries/);
	assert.match(html, /dist\/app\.jar/);
	assert.match(html, /CVE-2021-44228/);
});

test("SBOM gives an embedded copy a bom-ref distinct from the declared same-coord dep", () => {
	const declared = makeDepRecord({ ecosystem: "maven", namespace: "org.apache.logging.log4j", name: "log4j-core", version: "2.14.0", manifestPath: "pom.xml" });
	const embedded = makeDepRecord({ ecosystem: "maven", namespace: "org.apache.logging.log4j", name: "log4j-core", version: "2.14.0", manifestPath: "dist/app.jar!/BOOT-INF/lib/log4j-core-2.14.0.jar", provenance: "embedded" });
	const resolved = new Map([[declared.coordKey, declared], [embedded.coordKey, embedded]]);
	const bom = buildCycloneDx(resolved, []);
	const refs = bom.components.map(c => c["bom-ref"]);
	assert.equal(new Set(refs).size, refs.length, "bom-refs are unique");
	const embComp = bom.components.find(c => (c.properties || []).some(p => p.name === "fad:provenance" && p.value === "embedded"));
	assert.ok(embComp, "embedded component carries fad:provenance");
	assert.ok((embComp.properties || []).some(p => p.name === "fad:location"));
});
