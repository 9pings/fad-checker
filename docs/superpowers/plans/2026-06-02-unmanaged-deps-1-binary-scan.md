# Unmanaged Deps — Plan 1: Binary discovery & hashing

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Discover committed native binaries (`.dll`/`.exe`/`.so`/`.dylib`) in the source tree — and ONLY real binaries, never images/fonts/assets — hashing each (SHA-1 + SHA-256) into `provenance:"binary"` dep-records, behind a `--no-binaries` toggle.

**Architecture:** A new `binary` codec (`lib/codecs/binary.codec.js` + `lib/codecs/binary/`) plugged into the existing codec registry. File selection requires BOTH an allowlisted extension AND a confirming magic-byte signature (PE `MZ`, ELF `\x7FELF`, Mach-O `0xFEEDFAC*`/`0xCAFEBAB*`), so an image renamed `.so` is rejected. Records carry no coordinate yet (identity comes in Plan 2), so the existing CVE/OSV/EOL/outdated stages skip `provenance:"binary"`.

**Tech Stack:** Node.js, `node:test`, `node:crypto` (hashing), `fflate` already vendored (not needed here), existing codec interface (`lib/codecs/codec.interface.js`).

This is Plan 1 of 3. Plan 2 adds online identity (deps.dev/CIRCL) + integrity (registry digests). Plan 3 adds the unified inventory, the Part C report, and export fields. Spec: `docs/superpowers/specs/2026-06-02-unmanaged-vendored-dependencies-design.md`.

---

### Task 1: Magic-byte sniffer (pure)

**Files:**
- Create: `lib/codecs/binary/sniff.js`
- Test: `test/binary-sniff.test.js`

- [ ] **Step 1: Write the failing test**

```js
// test/binary-sniff.test.js
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/binary-sniff.test.js`
Expected: FAIL — `Cannot find module '../lib/codecs/binary/sniff'`.

- [ ] **Step 3: Write minimal implementation**

```js
// lib/codecs/binary/sniff.js
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
	const be = (b0 << 24 >>> 0) | (b1 << 16) | (b2 << 8) | b3;
	const le = (b3 << 24 >>> 0) | (b2 << 16) | (b1 << 8) | b0;
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/binary-sniff.test.js`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add lib/codecs/binary/sniff.js test/binary-sniff.test.js
git commit -m "feat(binary): magic-byte + extension sniffer for binary codec

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Binary scanner (walk + hash + magic gate)

**Files:**
- Create: `lib/codecs/binary/scan.js`
- Test: `test/binary-scan.test.js`

- [ ] **Step 1: Write the failing test**

```js
// test/binary-scan.test.js
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/binary-scan.test.js`
Expected: FAIL — `Cannot find module '../lib/codecs/binary/scan'`.

- [ ] **Step 3: Write minimal implementation**

```js
// lib/codecs/binary/scan.js
/**
 * lib/codecs/binary/scan.js — walk a source tree for committed NATIVE binaries
 * (.dll/.exe/.so/.dylib) and hash each. Dependency archives (.jar/.war/.ear) are
 * owned by the Maven codec's jar-scan.js, not here.
 *
 * Selection requires BOTH an allowlisted extension AND a confirming magic byte
 * (sniff.js), so images/fonts/assets — even with a spoofed extension — are never
 * hashed or reported.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { sniffKind, extKind } = require("./sniff");

// Same skip set the other codecs use; never a place vendored binaries we own live.
const SKIP = new Set([
	".git", ".idea", ".vscode", "node_modules", "dist", "build", "out",
	"target", "vendor", "testdata", ".svn", ".hg", ".gradle", ".cache",
]);

const MAGIC_BYTES = 8;   // enough for every signature we sniff

function hashFile(fp) {
	const buf = fs.readFileSync(fp);
	return {
		size: buf.length,
		sha1: crypto.createHash("sha1").update(buf).digest("hex"),
		sha256: crypto.createHash("sha256").update(buf).digest("hex"),
	};
}

function readMagic(fp) {
	let fd;
	try {
		fd = fs.openSync(fp, "r");
		const buf = Buffer.alloc(MAGIC_BYTES);
		const n = fs.readSync(fd, buf, 0, MAGIC_BYTES, 0);
		return buf.subarray(0, n);
	} catch { return Buffer.alloc(0); }
	finally { if (fd !== undefined) try { fs.closeSync(fd); } catch { /* ignore */ } }
}

/** Walk `dir`, return [{ path, kind, size, sha1, sha256, declaredName }]. */
function scanBinaries(dir, opts = {}) {
	const { onProgress } = opts;
	const out = [];
	const stack = [dir];
	while (stack.length) {
		const cur = stack.pop();
		let entries; try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
		for (const e of entries) {
			const fp = path.join(cur, e.name);
			if (e.isDirectory()) { if (!SKIP.has(e.name)) stack.push(fp); continue; }
			if (!e.isFile()) continue;
			const ext = extKind(e.name);
			if (!ext) continue;                          // not an allowlisted extension
			if (sniffKind(readMagic(fp)) !== ext) continue;  // magic must confirm the extension
			if (onProgress) onProgress(fp);
			const h = hashFile(fp);
			out.push({ path: fp, kind: ext, size: h.size, sha1: h.sha1, sha256: h.sha256, declaredName: e.name });
		}
	}
	return out;
}

module.exports = { scanBinaries };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/binary-scan.test.js`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add lib/codecs/binary/scan.js test/binary-scan.test.js
git commit -m "feat(binary): tree scanner — magic-gated native binary discovery + hashing

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Extend `makeDepRecord` for `provenance:"binary"`

**Files:**
- Modify: `lib/dep-record.js:37-71`
- Test: `test/dep-record.test.js` (create if absent; otherwise append)

- [ ] **Step 1: Write the failing test**

```js
// test/dep-record.test.js  (append, or create with the require + test wrapper)
const { test } = require("node:test");
const assert = require("node:assert");
const { makeDepRecord } = require("../lib/dep-record");

test("binary provenance is keyed by physical path and carries hashes + declaredName", () => {
	const d = makeDepRecord({
		ecosystem: "binary", name: "libssl.so.1.1", manifestPath: "/p/libssl.so.1.1",
		provenance: "binary", hashes: { sha1: "a".repeat(40), sha256: "b".repeat(64) },
		declaredName: "libssl.so.1.1",
	});
	assert.equal(d.coordKey, "binary:/p/libssl.so.1.1");
	assert.equal(d.provenance, "binary");
	assert.deepEqual(d.hashes, { sha1: "a".repeat(40), sha256: "b".repeat(64) });
	assert.equal(d.declaredName, "libssl.so.1.1");
	assert.deepEqual(d.manifestPaths, ["/p/libssl.so.1.1"]);
});

test("manifest provenance is unchanged (no hashes field bleed)", () => {
	const d = makeDepRecord({ ecosystem: "maven", namespace: "g", name: "a", version: "1.0", manifestPath: "/p/pom.xml" });
	assert.equal(d.coordKey, "g:a");
	assert.equal(d.provenance, "manifest");
	assert.equal(d.hashes, null);
	assert.equal(d.declaredName, null);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/dep-record.test.js`
Expected: FAIL — `coordKey` is `binary:...` expected but got the eco-keyed value; `hashes`/`declaredName` undefined.

- [ ] **Step 3: Write minimal implementation**

In `lib/dep-record.js`, change the destructure and the `coordKey` computation, and add the two fields to the returned object:

```js
	const { ecosystem, namespace = "", name, version = null, manifestPath, scope = "compile", isDev = false, ecosystemType, provenance = "manifest", hashes = null, declaredName = null } = input;
```

Replace the embedded-only key special-case with one that also covers `binary`:

```js
	// Embedded binaries (a dep discovered INSIDE a .jar/.war/.ear) and standalone
	// committed native binaries (.dll/.so/…) must not share the Map key of a declared
	// dep with the same coordinate — they'd merge and the unmanaged report chapter
	// would lose them. Key them by their unique physical location instead.
	const byLocation = (provenance === "embedded" || provenance === "binary") && manifestPath;
	const coordKey = byLocation
		? `${provenance}:${manifestPath}`
		: coordKeyFor(ecosystem, namespace, name);
```

In the returned object literal, add after `provenance,`:

```js
		hashes,
		declaredName,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/dep-record.test.js`
Expected: PASS (2 tests).

- [ ] **Step 5: Run the existing embedded test to confirm no regression**

Run: `node --test test/*.test.js 2>&1 | tail -5`
Expected: full suite PASS (embedded coordKey `embedded:<path>` still holds — the new branch produces the identical string for embedded).

- [ ] **Step 6: Commit**

```bash
git add lib/dep-record.js test/dep-record.test.js
git commit -m "feat(dep-record): binary provenance keyed by path; hashes + declaredName fields

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: The `binary` codec

**Files:**
- Create: `lib/codecs/binary.codec.js`
- Modify: `lib/codecs/recipes.js` (add a `binary` recipe stub)
- Test: `test/binary-codec.test.js`

- [ ] **Step 1: Write the failing test**

```js
// test/binary-codec.test.js
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/binary-codec.test.js`
Expected: FAIL — `Cannot find module '../lib/codecs/binary.codec'`.

- [ ] **Step 3: Add the recipe**

`recipes.js` defines each recipe as a top-level `const` with the shape
`{ label, pinSection, pinIntro(cnt), snippet(items), directSection }` and exports
them via a single `module.exports = { maven, npm, …, dependencyManagementSnippet, … }`
object literal (line 135). Add a `binary` const (place it near the `ruby` const,
before `module.exports`):

```js
const binary = {
	label: "Binaries",
	pinSection: "A. Replace or remove the vendored binary",
	pinIntro: cnt => `Replace ${cnt} committed binar${cnt > 1 ? "ies" : "y"} with a managed dependency, or verify their provenance/checksum:`,
	snippet: () => "",
	directSection: "B. Prefer declaring these through a package manager (Maven/npm/NuGet/…)",
};
```

Then add `binary` to the export object — change the start of line 135 from
`module.exports = { maven, npm, yarn, composer, pypi, nuget, go, ruby, dependencyManagementSnippet,`
to `module.exports = { maven, npm, yarn, composer, pypi, nuget, go, ruby, binary, dependencyManagementSnippet,`
(insert `binary, ` after `ruby, `).

- [ ] **Step 4: Write the codec**

```js
// lib/codecs/binary.codec.js
/**
 * lib/codecs/binary.codec.js — codec for committed NATIVE binaries
 * (.dll/.exe/.so/.dylib) that no package manager governs.
 *
 * Plan 1 scope: discover + hash only. The records carry no resolved coordinate
 * (just a filename); Plan 2's hash-id service fills `identity`, Plan 3 builds the
 * unmanaged inventory + report. Until then the records are `provenance:"binary"`
 * and the CVE/OSV/EOL/outdated stages skip them (no coordinate to query).
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { makeDepRecord } = require("../dep-record");
const { scanBinaries } = require("./binary/scan");

module.exports = {
	id: "binary",
	label: "Binaries",
	osvEcosystem: null,                                   // no OSV ecosystem until identified
	manifestNames: ["*.dll", "*.exe", "*.so", "*.dylib"], // lets detectCodecs include us in auto mode

	detect(dir) {
		try { return scanBinaries(dir, { onProgress: null }).length > 0; }
		catch { return false; }
	},

	async collect(dir, opts = {}) {
		const out = new Map();
		const warnings = [];
		let records;
		try { records = scanBinaries(dir, { onProgress: opts.onBinaryProgress }); }
		catch (e) { return { deps: out, warnings: [{ type: "scan-error", message: `binary scan failed: ${e.message}` }] }; }
		for (const r of records) {
			out.set(`binary:${r.path}`, makeDepRecord({
				ecosystem: "binary",
				name: r.declaredName,
				version: null,
				manifestPath: r.path,
				provenance: "binary",
				hashes: { sha1: r.sha1, sha256: r.sha256 },
				declaredName: r.declaredName,
			}));
		}
		return { deps: out, warnings };
	},

	coordKey(d) { return `binary:${d.manifestPaths?.[0] || d.name}`; },
	formatCoord(d) { return d.declaredName || d.name; },
	osvPackageName() { return null; },
	async checkRegistry() { return { deprecated: [], outdated: [], licensed: [] }; },
	resolveEolProduct() { return null; },
	recipe: require("./recipes").binary,
	nativeScanners: [],
};
```

- [ ] **Step 5: Run test to verify it passes**

Run: `node --test test/binary-codec.test.js`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add lib/codecs/binary.codec.js lib/codecs/recipes.js test/binary-codec.test.js
git commit -m "feat(binary): binary codec (discover + hash, provenance:binary)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Register the codec

**Files:**
- Modify: `lib/codecs/index.js:24,27` (ORDER + REGISTRY)
- Test: `test/binary-registry.test.js`

- [ ] **Step 1: Write the failing test**

```js
// test/binary-registry.test.js
const { test } = require("node:test");
const assert = require("node:assert");
const { getCodec, allCodecs, ORDER } = require("../lib/codecs");

test("binary codec is registered and ordered last", () => {
	assert.ok(getCodec("binary"));
	assert.ok(ORDER.includes("binary"));
	assert.equal(ORDER[ORDER.length - 1], "binary");
	assert.ok(allCodecs().some(c => c.id === "binary"));
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/binary-registry.test.js`
Expected: FAIL — `getCodec("binary")` is null.

- [ ] **Step 3: Implement**

In `lib/codecs/index.js`:
- After `const ruby = require("./ruby.codec");` add: `const binary = require("./binary.codec");`
- Change `const ORDER = ["maven", "npm", "yarn", "nuget", "composer", "pypi", "go", "ruby"];` to append `, "binary"`.
- Change the registry loop array `for (const c of [maven, npm, yarn, composer, pypi, nuget, go, ruby]) {` to append `, binary`.

- [ ] **Step 4: Run test + full suite**

Run: `node --test test/binary-registry.test.js && node --test test/*.test.js 2>&1 | tail -5`
Expected: PASS. (No regression — the binary codec's `manifestNames` globs only add detection of binary files.)

- [ ] **Step 5: Commit**

```bash
git add lib/codecs/index.js test/binary-registry.test.js
git commit -m "feat(binary): register binary codec in the registry (ordered last)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Skip `provenance:"binary"` in the Maven CVE-index matcher

**Files:**
- Modify: `lib/cve-match.js:229` (inside `matchDepsAgainstCves`), and `lib/cve-match.js:128,135` (transitive guards, for cleanliness)
- Test: `test/binary-pipeline-skip.test.js`

**Why:** A binary record has no resolved coordinate yet (Plan 2 fills it). In
`matchDepsAgainstCves`, `matchOne` treats a dep with no version as "affected" for any
index entry (`cve-match.js:186` — `if (!ver) return r.status === "affected"`), so a
binary named e.g. `openssl.dll` could spuriously match. We skip it exactly as npm is
skipped one line above (`cve-match.js:229`). OSV already skips these for free — it
requires a concrete version (`osv.js:365` `if (!ver …) continue;`) and binary records
have none — and transitive resolution already skips no-version deps; no OSV change
needed, but we tighten the transitive guards too for clarity.

- [ ] **Step 1: Write the failing test**

```js
// test/binary-pipeline-skip.test.js
const { test } = require("node:test");
const assert = require("node:assert");
const { matchDepsAgainstCves } = require("../lib/cve-match");
const { makeDepRecord } = require("../lib/dep-record");

test("binary-provenance deps are skipped by the Maven CVE-index matcher", () => {
	const deps = new Map();
	deps.set("binary:/openssl.dll", makeDepRecord({
		ecosystem: "binary", name: "openssl.dll", manifestPath: "/openssl.dll",
		provenance: "binary", hashes: { sha1: "a".repeat(40), sha256: "b".repeat(64) },
	}));
	// An index entry that WOULD match a versionless dep by product name (worst case).
	const cveIndex = {
		byPackageName: {},
		byProduct: { "openssl.dll": [{ id: "CVE-0000-0001", severity: "HIGH", vendor: "openssl", product: "openssl.dll", ranges: [{ status: "affected" }] }] },
	};
	const matches = matchDepsAgainstCves(deps, cveIndex, { includePossibleTier: true });
	assert.equal(matches.length, 0);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/binary-pipeline-skip.test.js`
Expected: FAIL — `matches.length` is 1 (the spurious possible-tier match) instead of 0.

- [ ] **Step 3: Implement**

In `lib/cve-match.js`, inside `matchDepsAgainstCves`, right after the npm skip
(`if (dep.ecosystem === "npm") continue;`, ~line 229) add:

```js
		if (dep.provenance === "binary") continue; // no resolved coordinate yet (Plan 2 identifies it)
```

Also broaden the two transitive-resolution guards (cleanliness — binary deps have no
version so they're already excluded, but make intent explicit):
- `if (dep.provenance === "embedded") continue;` → `if (dep.provenance === "embedded" || dep.provenance === "binary") continue;`
- `.filter(d => d.provenance !== "embedded")` → `.filter(d => d.provenance !== "embedded" && d.provenance !== "binary")`

- [ ] **Step 4: Run test + full suite**

Run: `node --test test/binary-pipeline-skip.test.js && node --test test/*.test.js 2>&1 | tail -5`
Expected: PASS, no regressions.

- [ ] **Step 5: Commit**

```bash
git add lib/cve-match.js test/binary-pipeline-skip.test.js
git commit -m "fix(binary): skip provenance:binary in Maven CVE-index matcher

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: `--no-binaries` flag + collection summary

**Files:**
- Modify: `fad-checker.js:221` area (option), `fad-checker.js:408` (noCodecs list), `fad-checker.js:425` (pass `onBinaryProgress`), `fad-checker.js:437-448` (summary)
- Test: `test/select-binary.test.js`

- [ ] **Step 1: Write the failing test**

```js
// test/select-binary.test.js
const { test } = require("node:test");
const assert = require("node:assert");
const { resolveActiveCodecs } = require("../lib/codecs/select");

test("--no-binaries removes the binary codec from the active set", () => {
	const available = ["maven", "binary"];
	assert.deepEqual(resolveActiveCodecs("auto", available, { noCodecs: ["binary"] }), ["maven"]);
	assert.deepEqual(resolveActiveCodecs("auto", available, { noCodecs: [] }), ["maven", "binary"]);
});
```

- [ ] **Step 2: Run test to verify it passes already** (select.js is generic)

Run: `node --test test/select-binary.test.js`
Expected: PASS — `resolveActiveCodecs` already honors any id in `noCodecs`. This test locks the contract the flag wiring relies on.

- [ ] **Step 3: Wire the flag**

In `fad-checker.js`:
- Near the `--no-jars` option (~line 221) add:
  ```js
  .option("--no-binaries", "skip scanning committed native binaries (.dll/.exe/.so/.dylib)")
  ```
- In the `noCodecs` builder (~line 408), append `"binary"` to the id list:
  ```js
  const noCodecs = ["maven", "npm", "yarn", "nuget", "composer", "pypi", "go", "ruby", "binary"].filter(id => options[id] === false);
  ```
  (Commander maps `--no-binaries` to `options.binaries === false`, matching the existing `--no-maven` → `options.maven` convention.)
- In the collect call (~line 425), add `onBinaryProgress` to the opts object so the codec can report progress:
  ```js
  onBinaryProgress: null,
  ```

- [ ] **Step 4: Add the collection summary line**

In `fad-checker.js`, in the collection-summary block (~437-448), count binary records and print a line. After the `embeddedCount` handling add:

```js
	let binaryCount = 0;
	for (const d of resolved.values()) if (d.provenance === "binary") binaryCount++;
	if (binaryCount) ui.ok(`${chalk.bold("Binary".padEnd(8))} ${binaryCount} native lib(s) (.dll/.exe/.so/.dylib)`);
```

(Place the loop next to the existing `embeddedCount` loop, or merge into it — keep one pass if trivial. The existing loop at ~438 already skips `embedded`; add a branch `else if (d.provenance === "binary") { binaryCount++; continue; }`.)

- [ ] **Step 5: Run the full suite**

Run: `node --test test/*.test.js 2>&1 | tail -5`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add fad-checker.js test/select-binary.test.js
git commit -m "feat(binary): --no-binaries flag + collection summary line

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Committed fixture + real-condition test

**Files:**
- Create: `test/fixtures/vendored-binaries/` (tiny magic-only stub files)
- Create: `test/binary-fixture.test.js`

- [ ] **Step 1: Create the fixture (magic bytes only — no real/huge binaries committed)**

```bash
mkdir -p test/fixtures/vendored-binaries/lib test/fixtures/vendored-binaries/assets
printf 'MZ\0\0\0\0\0\0' > test/fixtures/vendored-binaries/lib/native.dll
printf '\x7fELF\0\0\0\0' > test/fixtures/vendored-binaries/lib/libfoo.so.2
printf '\x89PNG\r\n\x1a\n' > test/fixtures/vendored-binaries/assets/logo.png
printf '\x89PNG\r\n\x1a\n' > test/fixtures/vendored-binaries/assets/spoof.so
```

- [ ] **Step 2: Write the test**

```js
// test/binary-fixture.test.js
const { test } = require("node:test");
const assert = require("node:assert");
const path = require("node:path");
const { scanBinaries } = require("../lib/codecs/binary/scan");

test("fixture tree: picks the two real binaries, rejects png + spoofed .so", () => {
	const root = path.join(__dirname, "fixtures", "vendored-binaries");
	const names = scanBinaries(root).map(r => path.basename(r.path)).sort();
	assert.deepEqual(names, ["libfoo.so.2", "native.dll"]);
});
```

- [ ] **Step 3: Run test**

Run: `node --test test/binary-fixture.test.js`
Expected: PASS.

- [ ] **Step 4: Real-condition smoke test (manual — record the output)**

Pick a real local project that contains native binaries AND images (e.g. an Electron/JNI/.NET checkout). Run:

```bash
node fad-checker.js -s <real-project> --no-report 2>&1 | grep -iE "Binary|native lib"
```

Expected: a `Binary  N native lib(s)` line where N matches the real `.dll/.so/.dylib` count, and NO images/fonts counted. Sanity-check N against:

```bash
find <real-project> -type f \( -name '*.dll' -o -name '*.so' -o -name '*.so.*' -o -name '*.dylib' -o -name '*.exe' \) -not -path '*/node_modules/*' | wc -l
```

(The scanner count may be ≤ the find count when some matches fail magic confirmation — that's the guardrail working. If it's wildly off, investigate before proceeding.)

- [ ] **Step 5: Run the FULL suite and confirm green**

Run: `node --test test/*.test.js 2>&1 | tail -8`
Expected: all tests pass (the suite count grows by the new tests).

- [ ] **Step 6: Commit**

```bash
git add test/fixtures/vendored-binaries test/binary-fixture.test.js
git commit -m "test(binary): vendored-binaries fixture + asset-rejection coverage

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-review (against the spec)

- **Spec "new binary codec, hash-only, no parsing"** → Tasks 1–5. ✅
- **Spec "File selection — binaries + dep archives ONLY, never assets; extension allowlist AND magic bytes"** → Tasks 1–2, fixture Task 8 (PNG + spoofed `.so` rejected). ✅ (Dependency archives `.jar/.war/.ear` are intentionally NOT re-scanned here — owned by `maven/jar-scan.js`; the inventory unifies them in Plan 3.)
- **Spec "`provenance:binary`, `hashes`, `declaredName`"** → Task 3. ✅
- **Spec "`--no-binaries` toggle"** → Task 7. ✅
- **Spec "records skipped by managed pipeline until identified"** → Task 6. ✅
- **Spec offline/caching, identity, integrity, inventory, report Part C, exports** → deferred to Plans 2–3 (out of scope for Plan 1). Noted at top.
- **Placeholder scan:** none — every code step has complete code; the one conditional ("if `collectResolvedDeps` isn't the exact name") gives the exact grep to resolve it. ✅
- **Type consistency:** `scanBinaries` record shape `{ path, kind, size, sha1, sha256, declaredName }` is identical across Tasks 2, 4, 8; `makeDepRecord` `hashes: {sha1, sha256}` consistent across Tasks 3, 4, 6. ✅
