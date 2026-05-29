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
