# Unmanaged Deps — Plan 3: Inventory, Part C report & JSON export

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Surface the enriched unmanaged binaries as a dedicated inventory: a `buildInventory()` with derived per-file signals (name-vs-checksum mismatch, no-online-info, should-be-managed, known-malicious), a new **Part C** chapter in the HTML/.doc report, an `unmanaged` block in the JSON export, and a terminal results section.

**Architecture:** `lib/unmanaged.js#buildInventory(resolved)` (pure) turns `provenance:"binary"` records (already carrying `.identity`/`.integrity` from Plan 2) into inventory entries with signals. `cve-report.js` derives the inventory from `resolvedDeps` it already receives and renders chapter "1C". `json-export.js` adds an `unmanaged` array. `fad-checker.js` prints a results section.

**Tech Stack:** Node `node:test`, existing report/export modules.

Spec: `docs/superpowers/specs/2026-06-02-unmanaged-vendored-dependencies-design.md`.
Deferred (noted): moving embedded-jar EOL/outdated/license entries out of the managed chapters; SBOM/SARIF/CSAF unmanaged fields; integrity "modified" for declared-coordinate embedded jars.

---

### Task 1: `buildInventory` + derived signals

**Files:** Modify `lib/unmanaged.js`; Test `test/unmanaged-inventory.test.js`

- [ ] **Step 1: Write the failing test**

```js
// test/unmanaged-inventory.test.js
const { test } = require("node:test");
const assert = require("node:assert");
const { buildInventory, nameMatches } = require("../lib/unmanaged");
const { makeDepRecord } = require("../lib/dep-record");

function bin(name, identity, integrity) {
	const d = makeDepRecord({ ecosystem: "binary", name, manifestPath: `/p/${name}`, provenance: "binary", hashes: { sha1: "a".repeat(40), sha256: "b".repeat(64) }, declaredName: name });
	d.identity = identity; d.integrity = integrity; return d;
}

test("nameMatches is lenient on lib-prefix/version, catches clear mismatches", () => {
	assert.equal(nameMatches("libssl.so.1.1", "openssl"), true);
	assert.equal(nameMatches("evil.dll", "openssl"), false);
	assert.equal(nameMatches("commons-lang3.jar", "org.apache.commons:commons-lang3"), true);
});

test("buildInventory derives signals per record and ignores managed deps", () => {
	const resolved = new Map();
	resolved.set("binary:/p/a.dll", bin("a.dll", { ecosystem: "nuget", name: "A.Pkg", version: "2.0", source: "deps.dev" }, "pristine"));
	resolved.set("binary:/p/libssl.so", bin("libssl.so", { ecosystem: null, name: "openssl", version: "3.0", source: "circl:nsrl_modern", knownMalicious: false }, "known-good"));
	resolved.set("binary:/p/x.so", bin("x.so", null, "unknown"));
	resolved.set("binary:/p/evil.dll", bin("evil.dll", { ecosystem: "npm", name: "leftpad", version: "1.0", source: "deps.dev" }, "pristine"));
	resolved.set("g:a", makeDepRecord({ ecosystem: "maven", namespace: "g", name: "a", version: "1.0", manifestPath: "/pom.xml" }));

	const inv = buildInventory(resolved);
	assert.equal(inv.length, 4);
	const a = inv.find(e => e.declaredName === "a.dll");
	assert.equal(a.shouldBeManaged, true);          // deps.dev coord with ecosystem
	assert.equal(a.noOnlineInfo, false);
	const ssl = inv.find(e => e.declaredName === "libssl.so");
	assert.equal(ssl.shouldBeManaged, false);       // CIRCL OS file, ecosystem null
	assert.equal(ssl.nameMismatch, false);
	const x = inv.find(e => e.declaredName === "x.so");
	assert.equal(x.noOnlineInfo, true);
	const evil = inv.find(e => e.declaredName === "evil.dll");
	assert.equal(evil.nameMismatch, true);          // "evil" vs "leftpad"
});
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement (append to `lib/unmanaged.js`, before `module.exports`)**

```js
function normName(s) {
	return String(s || "").toLowerCase()
		.replace(/\.(dll|exe|so|dylib)(\.\d+)*$/, "")  // drop binary extension (+ soname version)
		.replace(/^lib/, "")                            // libssl → ssl
		.replace(/[-_.]?\d[\d.]*$/, "")                 // trailing version
		.replace(/[^a-z0-9]/g, "");
}

/** Lenient compare of a filename to an online identity name (last :/ segment). */
function nameMatches(declared, identityName) {
	const a = normName(declared);
	const b = normName(String(identityName).split(/[:/]/).pop());
	if (!a || !b) return true;        // can't compare → don't raise a false alarm
	return a.includes(b) || b.includes(a);
}

/** Turn the unmanaged (hash-bearing) records into an inventory with derived signals. */
function buildInventory(resolved) {
	const out = [];
	for (const d of resolved.values()) {
		if (!d.hashes || !(d.provenance === "binary" || d.provenance === "embedded")) continue;
		const identity = d.identity || null;
		out.push({
			path: d.manifestPaths?.[0] || d.declaredName || null,
			declaredName: d.declaredName || d.name || null,
			provenance: d.provenance,
			hashes: d.hashes,
			identity,
			integrity: d.integrity || "unknown",
			noOnlineInfo: !identity,
			shouldBeManaged: !!(identity && identity.ecosystem),
			nameMismatch: !!(identity && identity.name && !nameMatches(d.declaredName || d.name, identity.name)),
			knownMalicious: !!(identity && identity.knownMalicious),
		});
	}
	out.sort((a, b) => String(a.path).localeCompare(String(b.path)));
	return out;
}
```

Add `buildInventory, nameMatches` to `module.exports`.

- [ ] **Step 4: Run → PASS.** `node --test test/unmanaged-inventory.test.js`
- [ ] **Step 5: Commit** `feat(unmanaged): buildInventory + derived signals (mismatch/should-be-managed/unknown)`

---

### Task 2: Part C chapter in the HTML/.doc report

**Files:** Modify `lib/cve-report.js` (require buildInventory; add `renderUnmanagedInventory`; insert chapter "1C"; TOC entry); Test `test/unmanaged-report.test.js`

- [ ] **Step 1: Write the failing test**

```js
// test/unmanaged-report.test.js
const { test } = require("node:test");
const assert = require("node:assert");
const { generateHtmlReport } = require("../lib/cve-report");
const { makeDepRecord } = require("../lib/dep-record");

test("report renders a Part C inventory chapter for unmanaged binaries", () => {
	const resolved = new Map();
	const d = makeDepRecord({ ecosystem: "binary", name: "libssl.so.1.1", manifestPath: "/p/libssl.so.1.1", provenance: "binary", hashes: { sha1: "a".repeat(40), sha256: "b".repeat(64) }, declaredName: "libssl.so.1.1" });
	d.identity = { ecosystem: null, name: "openssl", version: "3.0", source: "circl:nsrl_modern" }; d.integrity = "known-good";
	resolved.set("binary:/p/libssl.so.1.1", d);
	const html = generateHtmlReport({ cveMatches: [], devCveMatches: [], embeddedMatches: [], retireMatches: [], eolResults: [], obsoleteResults: [], outdatedResults: [], licenseResults: null, resolvedDeps: resolved, projectInfo: { name: "t", src: "/p" }, warnings: [] });
	assert.match(html, /Unmanaged/);
	assert.match(html, /libssl\.so\.1\.1/);
	assert.match(html, /openssl/);
});
```

> Confirm the exact export name (`generateHtmlReport` vs `buildHtml`): `grep -n "module.exports" lib/cve-report.js`. Use the function that returns the full HTML string from a payload (same one `test/codec-integration.test.js` uses — grep `generateHtmlReport(` in test/). Adjust the require/call if needed; assertions stay.

- [ ] **Step 2: Run → FAIL** (no "Unmanaged" chapter yet).

- [ ] **Step 3: Implement in `lib/cve-report.js`**

Near the other requires at the top, add:
```js
const { buildInventory } = require("./unmanaged");
```

Add a renderer (next to `renderEmbeddedChapter`):
```js
function renderUnmanagedInventory(inventory, srcRoot) {
	if (!inventory.length) return `<div class="empty">No committed native binaries found.</div>`;
	const intro = `<div class="fp-intro">Committed native binaries (<code>.dll</code>/<code>.exe</code>/<code>.so</code>/<code>.dylib</code>) — not governed by any package manager. Identified by checksum (deps.dev + CIRCL). <strong>Should-be-managed</strong> = a published package committed as a blob; <strong>name≠checksum</strong> = the filename disagrees with what the hash resolves to; <strong>unknown</strong> = no source recognises the file.</div>`;
	const rows = inventory.map(e => {
		const rel = srcRoot ? (() => { try { return require("path").relative(srcRoot, e.path); } catch { return e.path; } })() : e.path;
		const id = e.identity ? `${esc(e.identity.ecosystem ? e.identity.ecosystem + ":" : "")}${esc(e.identity.name || "")}${e.identity.version ? "@" + esc(e.identity.version) : ""} <span class="dim">(${esc(e.identity.source || "")})</span>` : `<span class="dim">unknown</span>`;
		const flags = [
			e.knownMalicious ? `<span class="sev-CRITICAL">⚠ malicious</span>` : null,
			e.integrity === "pristine" ? `<span class="dim">pristine</span>` : (e.integrity === "known-good" ? `<span class="dim">known-good</span>` : `<span class="sev-MEDIUM">unknown</span>`),
			e.shouldBeManaged ? `<span class="sev-MEDIUM">should-be-managed</span>` : null,
			e.nameMismatch ? `<span class="sev-HIGH">name≠checksum</span>` : null,
		].filter(Boolean).join(" ");
		return `<tr><td><code class="path">${esc(rel)}</code></td><td>${id}</td><td>${flags}</td><td><code class="dim">${esc((e.hashes.sha256 || "").slice(0, 16))}…</code></td></tr>`;
	}).join("\n");
	return intro + `<table><thead><tr><th>File</th><th>Identity (by checksum)</th><th>Status</th><th>SHA-256</th></tr></thead><tbody>${rows}</tbody></table>`;
}
```

In `buildBody`, derive the inventory (near where `embeddedContent` is computed):
```js
	const unmanagedInventory = buildInventory(resolvedDeps || new Map());
	const unmanagedContent = renderUnmanagedInventory(unmanagedInventory, projectInfo?.src);
```

Insert the chapter right after the "1B" line:
```js
		${unmanagedInventory.length ? majorSection(`1C. Unmanaged / vendored binaries (${unmanagedInventory.length})`, unmanagedContent, { open: unmanagedInventory.length <= 50, id: "ch1c" }) : ""}
```

In `renderToc`, after the embedded entry, add (guard on the count param — thread `unmanagedTotal` through the `renderToc({...})` call and the destructure, mirroring `embeddedTotal`):
```js
	if (unmanagedTotal) entries.push({ id: "ch1c", label: `1C. Unmanaged (${unmanagedTotal})` });
```
and pass `unmanagedTotal: unmanagedInventory.length` in the `renderToc({...})` call + add `unmanagedTotal` to its destructured params.

- [ ] **Step 4: Run → PASS.** Then full suite `node --test test/*.test.js`.
- [ ] **Step 5: Commit** `feat(report): Part C — unmanaged/vendored binaries inventory chapter`

---

### Task 3: JSON export + terminal results section

**Files:** Modify `lib/json-export.js`, `fad-checker.js`; Test `test/unmanaged-json.test.js`

- [ ] **Step 1: Write the failing test**

```js
// test/unmanaged-json.test.js
const { test } = require("node:test");
const assert = require("node:assert");
const { buildFindings } = require("../lib/json-export");
const { makeDepRecord } = require("../lib/dep-record");

test("JSON export includes an unmanaged inventory + summary count", () => {
	const resolved = new Map();
	const d = makeDepRecord({ ecosystem: "binary", name: "x.so", manifestPath: "/p/x.so", provenance: "binary", hashes: { sha1: "a".repeat(40), sha256: "b".repeat(64) }, declaredName: "x.so" });
	d.identity = null; d.integrity = "unknown";
	resolved.set("binary:/p/x.so", d);
	const doc = buildFindings({ resolvedDeps: resolved, projectInfo: {} });
	assert.equal(doc.summary.unmanaged, 1);
	assert.equal(doc.unmanaged.length, 1);
	assert.equal(doc.unmanaged[0].declaredName, "x.so");
	assert.equal(doc.unmanaged[0].integrity, "unknown");
});
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement** in `lib/json-export.js`:
- Top: `const { buildInventory } = require("./unmanaged");`
- In `buildFindings`, compute `const unmanaged = resolvedDeps ? buildInventory(resolvedDeps) : [];`
- Add `unmanaged: unmanaged.length` to the `summary` object.
- Add `unmanaged,` to the returned document object.

- [ ] **Step 4:** In `fad-checker.js`, add a terminal results section after the embedded-CVE block (~line 905, after `if (embeddedActive.length) {...}`):

```js
	{
		const { buildInventory } = require("./lib/unmanaged");
		const inv = buildInventory(resolved);
		if (inv.length) {
			heading("Unmanaged binaries", inv.length);
			for (const e of inv.slice(0, 10)) {
				const id = e.identity ? `${e.identity.ecosystem ? e.identity.ecosystem + ":" : ""}${e.identity.name || ""}${e.identity.version ? "@" + e.identity.version : ""}` : chalk.dim("unknown");
				const flags = [e.knownMalicious ? chalk.bgRed.white(" malicious ") : null, e.nameMismatch ? chalk.yellow("name≠checksum") : null, e.shouldBeManaged ? chalk.cyan("should-be-managed") : null, e.noOnlineInfo ? chalk.dim("unknown") : null].filter(Boolean).join(" ");
				console.log("    " + chalk.white(path.basename(String(e.path))) + "  " + chalk.dim(id) + (flags ? "  " + flags : ""));
			}
			if (inv.length > 10) console.log(chalk.dim(`    …and ${inv.length - 10} more (see report ch.1C)`));
		}
	}
```

> Confirm `heading`, `chalk`, `path` are in scope at that point (they're used by the surrounding results section). If `heading` is local to the function, this block must be inside the same function — place it immediately after the `embeddedActive` block.

- [ ] **Step 5: Run full suite + syntax** `node -c fad-checker.js && node --test test/*.test.js`
- [ ] **Step 6: Commit** `feat(unmanaged): JSON export block + terminal results section`

---

### Task 4: Real-condition end-to-end

- [ ] **Step 1:** Build a mixed tree (real binaries + image) and generate an HTML report:

```bash
T=$(mktemp -d); O=$(mktemp -d)
cp "$(find /usr/lib -maxdepth 3 -name 'libz.so*' -type f 2>/dev/null | head -1)" "$T/libz.so.1"
cp "$(find /usr/lib -maxdepth 3 -name 'libcrypto.so*' -type f 2>/dev/null | head -1)" "$T/libcrypto.so" 2>/dev/null
printf '\x89PNG\r\n\x1a\n' > "$T/logo.png"
node fad-checker.js -s "$T" --report-html "$O/r.html" --report-json "$O/r.json" 2>&1 | grep -iE "Binary|Unmanaged|identif"
echo "--- HTML has Part C? ---"; grep -c "Unmanaged / vendored binaries" "$O/r.html"
echo "--- JSON unmanaged count ---"; node -e "console.log(require('$O/r.json').summary.unmanaged)"
rm -rf "$T" "$O"
```

Expected: a `Binary`/`Unmanaged binaries` terminal section listing the two `.so` (not the PNG), `Part C` present in the HTML, JSON `summary.unmanaged === 2`.

- [ ] **Step 2: Commit** anything outstanding.

---

## Self-review
- inventory + signals (nameMismatch/noOnlineInfo/shouldBeManaged/knownMalicious) → Task 1. ✅
- Part C HTML chapter + TOC → Task 2. ✅
- JSON export + terminal → Task 3. ✅
- real-condition E2E → Task 4. ✅
- Deferred (noted): managed-chapter re-partition for embedded jars; SBOM/SARIF/CSAF fields; embedded-jar "modified" integrity.
- Placeholders: Task 2/3 hedges give exact greps for `generateHtmlReport`/`heading` scope. ✅
