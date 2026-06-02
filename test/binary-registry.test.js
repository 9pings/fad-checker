const { test } = require("node:test");
const assert = require("node:assert");
const { getCodec, allCodecs, ORDER } = require("../lib/codecs");

test("binary codec is registered and ordered last", () => {
	assert.ok(getCodec("binary"));
	assert.ok(ORDER.includes("binary"));
	assert.equal(ORDER[ORDER.length - 1], "binary");
	assert.ok(allCodecs().some(c => c.id === "binary"));
});
