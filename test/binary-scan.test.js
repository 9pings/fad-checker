const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { scanBinaries } = require("../lib/codecs/binary/scan");

function tmpTree() {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-bin-"));
	// real ELF .so (magic + padding)
	fs.writeFileSync(path.join(root, "libssl.so.1.1"), Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(60)]));
	// real PE .dll
	fs.writeFileSync(path.join(root, "user32.dll"), Buffer.concat([Buffer.from([0x4d, 0x5a]), Buffer.alloc(62)]));
	// PNG renamed .so → must be REJECTED (magic mismatch)
	fs.writeFileSync(path.join(root, "spoof.so"), Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47]), Buffer.alloc(60)]));
	// genuine image → rejected (extension not allowlisted)
	fs.writeFileSync(path.join(root, "logo.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47]));
	// nested + a skip dir
	fs.mkdirSync(path.join(root, "node_modules"));
	fs.writeFileSync(path.join(root, "node_modules", "ignored.dll"), Buffer.from([0x4d, 0x5a, 0x00, 0x00]));
	fs.mkdirSync(path.join(root, "sub"));
	fs.writeFileSync(path.join(root, "sub", "libz.so"), Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(60)]));
	return root;
}

test("scanBinaries finds only magic-confirmed binaries, skips assets + skip-dirs", () => {
	const root = tmpTree();
	const out = scanBinaries(root).sort((a, b) => a.path.localeCompare(b.path));
	const names = out.map(r => path.basename(r.path)).sort();
	assert.deepEqual(names, ["libssl.so.1.1", "libz.so", "user32.dll"]);   // no spoof.so, no logo.png, no node_modules
});

test("scanBinaries records kind, size, hashes, declaredName", () => {
	const root = tmpTree();
	const dll = scanBinaries(root).find(r => path.basename(r.path) === "user32.dll");
	assert.equal(dll.kind, "pe");
	assert.equal(dll.size, 64);
	assert.match(dll.sha1, /^[0-9a-f]{40}$/);
	assert.match(dll.sha256, /^[0-9a-f]{64}$/);
	assert.equal(dll.declaredName, "user32.dll");
});
