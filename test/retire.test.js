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

test("vendored paths are relative to --src even when -s is a relative path", () => {
	const cwd = process.cwd();
	const abs = path.join(cwd, "sub", "rel-src");
	const raw = { data: [
		{ file: path.join(abs, "web/js/jquery-1.6.1.min.js"), results: [{ component: "jquery", version: "1.6.1", detection: "filename", vulnerabilities: [{ severity: "high", identifiers: { CVE: ["CVE-X"] } }] }] },
	] };
	// relative srcDir (what -s ./sub/rel-src yields)
	const relSrc = path.join("sub", "rel-src");
	const inv = R.extractVendoredInventory(raw, relSrc);
	assert.strictEqual(inv[0].file, path.join("web", "js", "jquery-1.6.1.min.js"));
	const matches = R.normaliseRetireResults(raw, relSrc);
	assert.strictEqual(matches[0].dep.vendoredFile, path.join("web", "js", "jquery-1.6.1.min.js"));
});

test("retire findings cache is versioned: legacy entry (no _schema) is a cache MISS, _schema:2 round-trips", () => {
	const fs = require("fs");
	// Unique src path so the md5 cache key never collides with a real run.
	const srcDir = "/tmp/fad-cache-version-test-" + process.pid;
	const cachePath = path.join(R.RETIRE_CACHE_DIR, R.cacheKey(srcDir));
	const body = { data: [{ file: "/x/jquery.js", results: [{ component: "jquery", version: "3.7.1", vulnerabilities: [] }] }] };
	try {
		// (1) A legacy entry written by a pre-verbose version: fresh timestamp, NO _schema.
		fs.mkdirSync(R.RETIRE_CACHE_DIR, { recursive: true });
		fs.writeFileSync(cachePath, JSON.stringify({ _fetchedAt: Date.now(), body }));
		assert.strictEqual(R.readCache(srcDir), null, "legacy (no _schema) entry must be a cache miss");

		// (2) writeCache stamps _schema:2 and the entry round-trips.
		R.writeCache(srcDir, body);
		const onDisk = JSON.parse(fs.readFileSync(cachePath, "utf8"));
		assert.strictEqual(onDisk._schema, 2, "writeCache stamps _schema:2");
		assert.deepStrictEqual(R.readCache(srcDir), body, "_schema:2 entry round-trips");
	} finally {
		try { fs.unlinkSync(cachePath); } catch { /* best effort */ }
	}
});

test("scanWithRetireFull surfaces a scan failure instead of silently returning empty", async () => {
	const fs = require("fs");
	// Needs local signatures to actually reach the scan path (offline). Mirrors the
	// conditional style of the ensureSignatures test above.
	if (!fs.existsSync(R.RETIRE_SIG_FILE)) return;
	// A non-existent source dir makes retire crash (walkdir ENOENT) → empty output.
	// That must be reported, not turned into a clean "nothing found" (the bug that
	// hid a vendored-JS chapter when the scan actually died).
	const r = await R.scanWithRetireFull("/no/such/path-" + process.pid + "-" + process.ppid, { offline: true, force: true });
	assert.strictEqual(r.inventory.length, 0);
	assert.strictEqual(r.matches.length, 0);
	assert.ok(r.error, "a retire scan failure must be reported in the result, not swallowed");
});

test("retireFailureReason extracts the meaningful error line, not a stack frame", () => {
	const stderr = [
		"Exception caught:  Error: error reading first path in the walk /proj/cnaps",
		"Error: ENOENT: no such file or directory, lstat '/proj/cnaps'",
		"    at EventEmitter.<anonymous> (/x/walkdir.js:265:28)",
		"    at FSReqCallback.oncomplete (node:fs:195:21)",
	].join("\n");
	const reason = R.retireFailureReason(stderr, "fallback");
	assert.match(reason, /ENOENT|no such file/i);
	assert.ok(!/^\s*at /.test(reason), "must not be a stack frame");
	// Empty stderr → fallback.
	assert.strictEqual(R.retireFailureReason("", "the-fallback"), "the-fallback");
	assert.strictEqual(R.retireFailureReason("   \n  \n", "fb"), "fb");
});

test("chooseRetireLauncher: node uses local bin, compiled binary self-invokes, else PATH", () => {
	// node dev (node_modules present) → run the local retire CLI directly, no env flag.
	assert.deepStrictEqual(
		R.chooseRetireLauncher({ localBin: "/p/node_modules/.bin/retire", isBun: false, execPath: "/usr/bin/node" }),
		{ cmd: "/p/node_modules/.bin/retire", env: null });
	// compiled bun binary (no node_modules) → re-exec THIS binary in retire mode.
	assert.deepStrictEqual(
		R.chooseRetireLauncher({ localBin: null, isBun: true, execPath: "/usr/local/bin/fad" }),
		{ cmd: "/usr/local/bin/fad", env: { __FAD_RETIRE__: "1" } });
	// last resort: retire on PATH.
	assert.deepStrictEqual(
		R.chooseRetireLauncher({ localBin: null, isBun: false, execPath: "/usr/bin/node" }),
		{ cmd: "retire", env: null });
});
