/**
 * lib/codecs/binary/sniff.js — file-type confirmation for the binary codec.
 *
 * Two gates: extKind() (extension allowlist) AND sniffKind() (magic bytes). A
 * candidate is accepted only when both agree, so an image renamed `.so` (PNG
 * magic) is rejected. We never trust the extension alone.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

// Magic-byte signatures → family. Mach-O has four (32/64-bit + fat, both endian).
function sniffKind(buf) {
	if (!buf || buf.length < 4) return null;
	const b0 = buf[0], b1 = buf[1], b2 = buf[2], b3 = buf[3];
	if (b0 === 0x4d && b1 === 0x5a) return "pe";                                   // MZ
	if (b0 === 0x7f && b1 === 0x45 && b2 === 0x4c && b3 === 0x46) return "elf";    // \x7FELF
	if (b0 === 0x50 && b1 === 0x4b && b2 === 0x03 && b3 === 0x04) return "zip";    // PK\x03\x04
	const be = ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0;
	const le = ((b3 << 24) | (b2 << 16) | (b1 << 8) | b0) >>> 0;
	const machO = new Set([0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcafebabf]);
	if (machO.has(be) || machO.has(le)) return "macho";
	return null;
}

const EXT_PE = /\.(dll|exe)$/i;
const EXT_MACHO = /\.dylib$/i;
const EXT_ELF = /\.so(\.\d+)*$/i;   // .so, .so.1, .so.1.2.3

function extKind(name) {
	if (EXT_PE.test(name)) return "pe";
	if (EXT_MACHO.test(name)) return "macho";
	if (EXT_ELF.test(name)) return "elf";
	return null;
}

module.exports = { sniffKind, extKind };
