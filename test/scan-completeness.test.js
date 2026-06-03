const { test } = require("node:test");
const assert = require("node:assert");
const { detectScanCompletenessWarnings } = require("../lib/scan-completeness");

function mapOf(...deps) {
	const m = new Map();
	deps.forEach((d, i) => m.set(d.coordKey || `k${i}`, d));
	return m;
}

test("flags a Maven dep with no concrete version", () => {
	const w = detectScanCompletenessWarnings(mapOf(
		{ ecosystem: "maven", groupId: "org.acme", artifactId: "lib", version: null },
	));
	assert.strictEqual(w.length, 1);
	assert.strictEqual(w[0].type, "unresolved-versions");
	assert.match(w[0].items[0], /org\.acme:lib/);
});

test("flags an unresolved ${property} version", () => {
	const w = detectScanCompletenessWarnings(mapOf(
		{ ecosystem: "maven", groupId: "g", artifactId: "a", version: "${jackson.version}" },
	));
	assert.strictEqual(w.length, 1);
});

test("does NOT flag native binaries (provenance:binary, no version by design)", () => {
	const w = detectScanCompletenessWarnings(mapOf(
		{ ecosystem: "binary", provenance: "binary", groupId: "", artifactId: "libeay32.dll", version: null },
		{ ecosystem: "binary", provenance: "binary", groupId: "", artifactId: "openssl.exe", version: null },
	));
	assert.strictEqual(w.length, 0);
});

test("does NOT flag non-Maven ecosystems or resolved Maven deps", () => {
	const w = detectScanCompletenessWarnings(mapOf(
		{ ecosystem: "npm", name: "left-pad", version: null },
		{ ecosystem: "pypi", name: "flask", version: null },
		{ ecosystem: "maven", groupId: "g", artifactId: "ok", version: "1.2.3" },
		{ ecosystem: "maven", scope: "import", groupId: "g", artifactId: "bom", version: null },
	));
	assert.strictEqual(w.length, 0);
});
