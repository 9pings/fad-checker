const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { assertCodecShape } = require("../lib/codecs/codec.interface");
const codec = require("../lib/codecs/binary.codec");

function tmp() {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-bc-"));
	fs.writeFileSync(path.join(root, "user32.dll"), Buffer.concat([Buffer.from([0x4d, 0x5a]), Buffer.alloc(62)]));
	return root;
}

test("binary codec satisfies the codec contract", () => {
	assert.ok(assertCodecShape(codec));
	assert.equal(codec.id, "binary");
});

test("detect() is true when a confirmed binary exists, false otherwise", () => {
	const root = tmp();
	assert.equal(codec.detect(root), true);
	assert.equal(codec.detect(fs.mkdtempSync(path.join(os.tmpdir(), "fad-empty-"))), false);
});

test("collect() returns provenance:binary records with hashes", async () => {
	const root = tmp();
	const { deps } = await codec.collect(root);
	const recs = [...deps.values()];
	assert.equal(recs.length, 1);
	assert.equal(recs[0].provenance, "binary");
	assert.equal(recs[0].ecosystem, "binary");
	assert.equal(recs[0].name, "user32.dll");
	assert.match(recs[0].hashes.sha256, /^[0-9a-f]{64}$/);
	assert.equal(recs[0].coordKey, `binary:${path.join(root, "user32.dll")}`);
});
