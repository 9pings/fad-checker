const { test } = require("node:test");
const assert = require("node:assert");
const path = require("node:path");
const { scanBinaries } = require("../lib/codecs/binary/scan");

test("fixture tree: picks the two real binaries, rejects png + spoofed .so", () => {
	const root = path.join(__dirname, "fixtures", "vendored-binaries");
	const names = scanBinaries(root).map(r => path.basename(r.path)).sort();
	assert.deepEqual(names, ["libfoo.so.2", "native.dll"]);
});
