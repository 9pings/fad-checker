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
	assert.deepStrictEqual(withRepo, ["--outputformat", "json", "--outputpath", "/o.json", "--jspath", "/s", "--ignore", "node_modules", "--jsrepo", "/sig.json"]);
	const withoutRepo = R.buildRetireArgs({ srcDir: "/s", outPath: "/o.json", ignoredDirs: "x" });
	assert.ok(!withoutRepo.includes("--jsrepo"));
	assert.deepStrictEqual(withoutRepo.slice(0, 4), ["--outputformat", "json", "--outputpath", "/o.json"]);
});

test("ensureSignatures offline never reaches the network — returns existence boolean", async () => {
	const fs = require("fs");
	const present = fs.existsSync(R.RETIRE_SIG_FILE);
	const r = await R.ensureSignatures({ offline: true });
	assert.strictEqual(typeof r, "boolean");
	assert.strictEqual(r, present);   // offline only reports what's already on disk
});
