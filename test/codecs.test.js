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
