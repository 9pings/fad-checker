const { test } = require("node:test");
const assert = require("node:assert");
const { resolveActiveCodecs } = require("../lib/codecs/select");

test("--no-binaries removes the binary codec from the active set", () => {
	const available = ["maven", "binary"];
	assert.deepEqual(resolveActiveCodecs("auto", available, { noCodecs: ["binary"] }), ["maven"]);
	assert.deepEqual(resolveActiveCodecs("auto", available, { noCodecs: [] }), ["maven", "binary"]);
});
