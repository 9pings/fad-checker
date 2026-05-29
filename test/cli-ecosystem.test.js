const test = require("node:test");
const assert = require("node:assert");
const { resolveActiveCodecs } = require("../lib/codecs/select");

test("resolveActiveCodecs parses comma list and 'all'", () => {
	const all = ["maven", "npm", "nuget", "composer", "pypi"];
	assert.deepStrictEqual(resolveActiveCodecs("maven,pypi", all, {}), ["maven", "pypi"]);
	assert.deepStrictEqual(resolveActiveCodecs("all", all, {}), all);
	assert.deepStrictEqual(resolveActiveCodecs("auto", all, {}), all);
});

test("resolveActiveCodecs honors --no-<id> flags", () => {
	const all = ["maven", "npm", "nuget"];
	assert.deepStrictEqual(resolveActiveCodecs("all", all, { noCodecs: ["npm"] }), ["maven", "nuget"]);
});

test("--no-js aliases to npm+yarn", () => {
	const all = ["maven", "npm", "yarn", "nuget"];
	assert.deepStrictEqual(resolveActiveCodecs("all", all, { noJs: true }), ["maven", "nuget"]);
});

test("legacy 'both' maps to maven+npm/yarn only", () => {
	const all = ["maven", "npm", "yarn", "nuget", "pypi"];
	assert.deepStrictEqual(resolveActiveCodecs("both", all, {}), ["maven", "npm", "yarn"]);
});

test("explicit list intersects with available (auto-detect)", () => {
	const detected = ["maven"];   // only maven detected on this tree
	assert.deepStrictEqual(resolveActiveCodecs("maven,npm", detected, {}), ["maven"]);
});
