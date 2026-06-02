const { test } = require("node:test");
const assert = require("node:assert");
const { sniffKind, extKind } = require("../lib/codecs/binary/sniff");

test("sniffKind detects PE / ELF / Mach-O / ZIP from leading bytes", () => {
	assert.equal(sniffKind(Buffer.from([0x4d, 0x5a, 0x90, 0x00])), "pe");          // "MZ"
	assert.equal(sniffKind(Buffer.from([0x7f, 0x45, 0x4c, 0x46])), "elf");          // \x7FELF
	assert.equal(sniffKind(Buffer.from([0xce, 0xfa, 0xed, 0xfe])), "macho");        // 0xFEEDFACE LE
	assert.equal(sniffKind(Buffer.from([0xcf, 0xfa, 0xed, 0xfe])), "macho");        // 0xFEEDFACF LE
	assert.equal(sniffKind(Buffer.from([0xca, 0xfe, 0xba, 0xbe])), "macho");        // fat 0xCAFEBABE
	assert.equal(sniffKind(Buffer.from([0x50, 0x4b, 0x03, 0x04])), "zip");          // "PK\x03\x04"
});

test("sniffKind returns null for non-binary content (PNG, text)", () => {
	assert.equal(sniffKind(Buffer.from([0x89, 0x50, 0x4e, 0x47])), null);           // PNG
	assert.equal(sniffKind(Buffer.from("hello world")), null);
	assert.equal(sniffKind(Buffer.alloc(0)), null);
});

test("extKind maps allowlisted extensions, rejects assets", () => {
	assert.equal(extKind("user32.dll"), "pe");
	assert.equal(extKind("app.exe"), "pe");
	assert.equal(extKind("libssl.so"), "elf");
	assert.equal(extKind("libssl.so.1.1"), "elf");   // versioned soname
	assert.equal(extKind("libfoo.dylib"), "macho");
	assert.equal(extKind("logo.png"), null);
	assert.equal(extKind("font.ttf"), null);
	assert.equal(extKind("notes.txt"), null);
});
