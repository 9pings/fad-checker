const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const os = require("os");
const R = require("../lib/retire");

test("retire signature cache lives INSIDE ~/.fad-checker/ (so --export-cache carries it)", () => {
	const fadDir = path.join(os.homedir(), ".fad-checker");
	assert.ok(R.RETIRE_SIG_DIR.startsWith(fadDir), `${R.RETIRE_SIG_DIR} should be under ${fadDir}`);
	assert.ok(R.RETIRE_SIG_FILE.startsWith(R.RETIRE_SIG_DIR));
	assert.ok(R.RETIRE_CACHE_DIR.startsWith(fadDir));
});

test("buildRetireArgs adds --jsrepo only when a local signature file is given", () => {
	const withRepo = R.buildRetireArgs({ srcDir: "/s", outPath: "/o.json", ignoredDirs: "node_modules", jsRepo: "/sig.json" });
	assert.deepStrictEqual(withRepo, ["--verbose", "--outputformat", "json", "--outputpath", "/o.json", "--jspath", "/s", "--ignore", "node_modules", "--jsrepo", "/sig.json"]);
	const withoutRepo = R.buildRetireArgs({ srcDir: "/s", outPath: "/o.json", ignoredDirs: "x" });
	assert.ok(!withoutRepo.includes("--jsrepo"));
	assert.ok(withoutRepo.includes("--verbose"), "--verbose listed so retire reports ALL identified libs, not just vulnerable");
	assert.deepStrictEqual(withoutRepo.slice(0, 5), ["--verbose", "--outputformat", "json", "--outputpath", "/o.json"]);
});

test("ensureSignatures offline never reaches the network — returns existence boolean", async () => {
	const fs = require("fs");
	const present = fs.existsSync(R.RETIRE_SIG_FILE);
	const r = await R.ensureSignatures({ offline: true });
	assert.strictEqual(typeof r, "boolean");
	assert.strictEqual(r, present);   // offline only reports what's already on disk
});

test("extractVendoredInventory lists ALL identified libs (vulnerable or not), sorted by severity", () => {
	const raw = { data: [
		{ file: "/proj/web/js/jquery-3.7.1.min.js", results: [{ component: "jquery", version: "3.7.1", detection: "filename", vulnerabilities: [] }] },
		{ file: "/proj/web/js/jquery-1.6.1.min.js", results: [{ component: "jquery", version: "1.6.1", detection: "filename", vulnerabilities: [{ severity: "medium" }, { severity: "high" }] }] },
		{ file: "/proj/web/bootstrap.min.js", results: [{ component: "bootstrap", version: "5.3.3", detection: "filecontent", vulnerabilities: [] }] },
	] };
	const inv = R.extractVendoredInventory(raw, "/proj");
	assert.strictEqual(inv.length, 3);
	// vulnerable jquery sorts first (max severity HIGH)
	assert.strictEqual(inv[0].component, "jquery");
	assert.strictEqual(inv[0].version, "1.6.1");
	assert.strictEqual(inv[0].vulnerable, true);
	assert.strictEqual(inv[0].vulnCount, 2);
	assert.strictEqual(inv[0].maxSeverity, "HIGH");
	assert.strictEqual(inv[0].file, "web/js/jquery-1.6.1.min.js");   // relative to srcDir
	// non-vulnerable libs are present (the whole point)
	const safe = inv.filter(e => !e.vulnerable).map(e => e.component).sort();
	assert.deepStrictEqual(safe, ["bootstrap", "jquery"]);
});

test("extractVendoredInventory tolerates empty / missing input", () => {
	assert.deepStrictEqual(R.extractVendoredInventory(null, "/p"), []);
	assert.deepStrictEqual(R.extractVendoredInventory({ data: [] }, "/p"), []);
});
