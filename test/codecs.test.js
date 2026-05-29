const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { assertCodecShape } = require("../lib/codecs/codec.interface");

const COMPLETE_STUB = {
	id: "x", label: "X", osvEcosystem: "npm",
	manifestNames: ["x.json"],
	detect: () => false,
	collect: async () => ({ deps: new Map(), warnings: [] }),
	coordKey: d => `x:${d.name}`,
	formatCoord: d => d.name,
	osvPackageName: d => d.name,
	checkRegistry: async () => ({ outdated: [], deprecated: [] }),
	resolveEolProduct: () => null,
	recipe: { label: "X", pinSection: "", pinIntro: () => "", snippet: () => "", directSection: "" },
	nativeScanners: [],
};

test("assertCodecShape accepts a complete codec stub", () => {
	assert.doesNotThrow(() => assertCodecShape(COMPLETE_STUB));
});

test("assertCodecShape rejects a codec missing a required method", () => {
	assert.throws(() => assertCodecShape({ id: "y" }), /missing|y/i);
});

const maven = require("../lib/codecs/maven.codec");

test("maven codec detects the simple fixture and collects deps with bare g:a coordKeys", async () => {
	const dir = path.join(__dirname, "fixtures", "simple");
	assert.strictEqual(maven.detect(dir), true);
	const { deps } = await maven.collect(dir, {});
	assert.ok(deps.size > 0);
	for (const [k, d] of deps) {
		assert.strictEqual(d.ecosystem, "maven");
		assert.strictEqual(d.coordKey, k);
		assert.ok(!k.startsWith("npm:") && !k.startsWith("nuget:"), `maven key ${k} must stay bare`);
	}
});

const npm = require("../lib/codecs/npm.codec");

test("npm codec collects from monorepo-mixed with npm: coordKeys", async () => {
	const dir = path.join(__dirname, "fixtures", "monorepo-mixed");
	assert.strictEqual(npm.detect(dir), true);
	const { deps } = await npm.collect(dir, {});
	assert.ok(deps.size > 0);
	for (const [k, d] of deps) {
		assert.ok(k.startsWith("npm:"), `key ${k} should be npm-namespaced`);
		assert.strictEqual(d.ecosystem, "npm");
		assert.strictEqual(d.coordKey, k);
	}
});

test("yarn codec is a no-op collector (npm codec does the JS scan)", async () => {
	const yarn = require("../lib/codecs/yarn.codec");
	assert.strictEqual(yarn.id, "yarn");
	const { deps } = await yarn.collect("/whatever", {});
	assert.strictEqual(deps.size, 0);
});

const { getCodec, allCodecs, detectCodecs } = require("../lib/codecs");

test("registry exposes maven/npm/yarn and validates their shape", () => {
	const ids = allCodecs().map(c => c.id).sort();
	assert.deepStrictEqual(ids, ["maven", "npm", "yarn"]);
	for (const c of allCodecs()) assertCodecShape(c);
	assert.strictEqual(getCodec("maven").id, "maven");
	assert.strictEqual(getCodec("nope"), null);
});

test("detectCodecs finds maven+npm on monorepo-mixed, not yarn duplicate", () => {
	const dir = path.join(__dirname, "fixtures", "monorepo-mixed");
	const detected = detectCodecs(dir).map(c => c.id);
	assert.ok(detected.includes("maven"));
	assert.ok(detected.includes("npm"));
	assert.ok(!detected.includes("yarn"));
});

const recipes = require("../lib/codecs/recipes");

test("each codec recipe exposes label + snippet function", () => {
	for (const c of allCodecs()) {
		assert.strictEqual(typeof c.recipe.label, "string");
		assert.strictEqual(typeof c.recipe.snippet, "function");
	}
	// snippet output matches the legacy format
	const xml = recipes.maven.snippet([{ groupId: "g", artifactId: "a", fixVersion: "1.0" }]);
	assert.match(xml, /<dependencyManagement>/);
	assert.match(xml, /<artifactId>a<\/artifactId>/);
});
