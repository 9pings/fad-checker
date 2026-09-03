const { test } = require("node:test");
const assert = require("node:assert/strict");
const { phpCeiling, highestCycleUnder } = require("../lib/codecs/composer/platform");

// endoflife.date/php, trimmed; dates as published in 2026-09.
const PHP = [
	{ cycle: "8.4", eol: "2028-12-31", support: "2026-12-31", latest: "8.4.12" },
	{ cycle: "8.3", eol: "2027-12-31", support: "2025-12-31", latest: "8.3.26" },
	{ cycle: "8.0", eol: "2023-11-26", support: "2022-11-26", latest: "8.0.30" },
	{ cycle: "7.4", eol: "2022-11-28", support: "2021-11-28", latest: "7.4.33" },
];
const top = c => highestCycleUnder(phpCeiling(c), PHP)?.cycle ?? null;

test("phpCeiling: caret / tilde / wildcard / exact / explicit bounds / hyphen range", () => {
	assert.deepEqual(phpCeiling("^7.4"), { max: [8, 0, 0], inclusive: false });        // >=7.4 <8.0
	assert.deepEqual(phpCeiling("^7.4.0"), { max: [8, 0, 0], inclusive: false });
	assert.deepEqual(phpCeiling("~7.4"), { max: [8, 0, 0], inclusive: false });        // ~X.Y   → <(X+1).0
	assert.deepEqual(phpCeiling("~7.4.2"), { max: [7, 5, 0], inclusive: false });      // ~X.Y.Z → <X.(Y+1)
	assert.deepEqual(phpCeiling("7.4.*"), { max: [7, 5, 0], inclusive: false });
	assert.deepEqual(phpCeiling("7.*"), { max: [8, 0, 0], inclusive: false });
	assert.deepEqual(phpCeiling("7.4.33"), { max: [7, 4, 33], inclusive: true });       // exact pin
	assert.deepEqual(phpCeiling("=7.4.33"), { max: [7, 4, 33], inclusive: true });
	assert.deepEqual(phpCeiling(">=7.4 <8.0"), { max: [8, 0, 0], inclusive: false });
	assert.deepEqual(phpCeiling(">=7.4, <=7.4.33"), { max: [7, 4, 33], inclusive: true });
	assert.deepEqual(phpCeiling("<8.0"), { max: [8, 0, 0], inclusive: false });
	assert.deepEqual(phpCeiling("7.2 - 7.4"), { max: [7, 5, 0], inclusive: false });   // hyphen: partial upper → next minor
	assert.deepEqual(phpCeiling("^7.4@dev"), { max: [8, 0, 0], inclusive: false });    // stability flag stripped
});

test("phpCeiling: OR takes the highest branch; ANY unbounded branch makes the whole constraint unbounded", () => {
	assert.deepEqual(phpCeiling("^7.2.5 || ^8.0"), { max: [9, 0, 0], inclusive: false });
	assert.deepEqual(phpCeiling("^7.4 | ^8.1"), { max: [9, 0, 0], inclusive: false });
	assert.equal(phpCeiling(">=7.2.5"), null);
	assert.equal(phpCeiling(">7.4"), null);
	assert.equal(phpCeiling("*"), null);
	assert.equal(phpCeiling("^7.4 || >=8.1"), null);
	assert.equal(phpCeiling(""), null);
	assert.equal(phpCeiling(null), null);
	assert.equal(phpCeiling("garbage"), null);
});

test("highestCycleUnder: the newest PHP cycle the constraint still allows", () => {
	assert.equal(top("^7.4"), "7.4");
	assert.equal(top("7.4.33"), "7.4");
	assert.equal(top("<8.0"), "7.4");
	assert.equal(top("^7.2.5 || ^8.0"), "8.4");
	assert.equal(top("8.3.*"), "8.3");
	assert.equal(top("<=8.0.30"), "8.0");
	assert.equal(top(">=7.2.5"), null, "unbounded → no cycle");
	assert.equal(top("<7.0"), null, "nothing known satisfies it");
	assert.equal(highestCycleUnder({ max: [8, 0, 0], inclusive: false }, null), null);
});

const fs = require("fs");
const os = require("os");
const path = require("path");
const { readPlatformPhp, evaluatePhpRuntime } = require("../lib/codecs/composer/platform");
const codec = require("../lib/codecs/composer.codec");

const NOW = Date.parse("2026-09-02T00:00:00Z");
const FIX54 = path.join(__dirname, "fixtures", "php-symfony54");
const FIXOPEN = path.join(__dirname, "fixtures", "php-open-platform");
const pl = (constraint, source = "lock:platform", manifestPath = "/p/composer.lock") => ({ constraint, source, manifestPath });

test("readPlatformPhp: precedence platform-overrides > config.platform > lock platform > json require", () => {
	assert.deepEqual(readPlatformPhp(path.join(FIX54, "composer.lock"), path.join(FIX54, "composer.json")),
		{ constraint: "^7.4", source: "lock:platform", manifestPath: path.join(FIX54, "composer.lock") });

	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-php-"));
	const lock = path.join(dir, "composer.lock"), json = path.join(dir, "composer.json");
	fs.writeFileSync(lock, JSON.stringify({ packages: [], "platform-overrides": { php: "7.4.33" }, platform: { php: "^7.4" } }));
	fs.writeFileSync(json, JSON.stringify({ require: { php: ">=7.2.5" }, config: { platform: { php: "8.1.0" } } }));
	assert.deepEqual(readPlatformPhp(lock, json), { constraint: "7.4.33", source: "lock:platform-overrides", manifestPath: lock });
	assert.deepEqual(readPlatformPhp(null, json), { constraint: "8.1.0", source: "json:config.platform", manifestPath: json });
	fs.writeFileSync(json, JSON.stringify({ require: { php: ">=7.2.5" } }));
	assert.deepEqual(readPlatformPhp(null, json), { constraint: ">=7.2.5", source: "json:require", manifestPath: json });
	fs.writeFileSync(json, JSON.stringify({ require: { "monolog/monolog": "^2" } }));
	assert.equal(readPlatformPhp(null, json), null, "no php requirement → null");
	assert.equal(readPlatformPhp(null, null), null);
	assert.equal(readPlatformPhp(path.join(dir, "missing.lock"), null), null, "unreadable file → null, no throw");
	fs.rmSync(dir, { recursive: true, force: true });
});

test("evaluatePhpRuntime: ^7.4 proves an EOL runtime → a finding (not a dependency)", () => {
	const r = evaluatePhpRuntime([pl("^7.4")], PHP, { now: NOW });
	assert.equal(r.warnings.length, 0);
	assert.equal(r.findings.length, 1);
	const f = r.findings[0];
	assert.equal(f.product, "PHP");
	assert.equal(f.productSlug, "php");
	assert.equal(f.cycle, "7.4");
	assert.equal(f.status, "eol");
	assert.equal(f.eol, "2022-11-28");
	assert.equal(f.support, "2021-11-28");
	assert.equal(f.latest, "7.4.33");
	assert.equal(f.via, "composer-platform");
	assert.equal(f.viaKey, "lock:platform");
	assert.ok(f.notes.includes('"^7.4"'));
	assert.equal(f.dep.ecosystem, "composer");
	assert.equal(f.dep.name, "php");
	assert.equal(f.dep.version, "7.4");
	assert.equal(f.dep.provenance, "platform");
	assert.equal(f.dep.scope, "runtime");
	assert.deepEqual(f.dep.manifestPaths, ["/p/composer.lock"]);
});

test("evaluatePhpRuntime: an exact pin is a certain verdict", () => {
	const r = evaluatePhpRuntime([pl("7.4.33", "lock:platform-overrides")], PHP, { now: NOW });
	assert.equal(r.findings.length, 1);
	assert.equal(r.findings[0].cycle, "7.4");
});

test("evaluatePhpRuntime: an open constraint is a chapter-0 note, never a finding", () => {
	const r = evaluatePhpRuntime([pl(">=7.2.5", "json:require", "/p/composer.json")], PHP, { now: NOW });
	assert.equal(r.findings.length, 0);
	assert.equal(r.warnings.length, 1);
	assert.equal(r.warnings[0].type, "php-runtime-undetermined");
	assert.equal(r.warnings[0].manifestPath, "/p/composer.json");
	assert.ok(r.warnings[0].message.includes(">=7.2.5"));
	assert.ok(r.warnings[0].message.includes("json:require"));
});

test("evaluatePhpRuntime: a constraint that allows a supported PHP is a note", () => {
	const r = evaluatePhpRuntime([pl("^7.2.5 || ^8.0")], PHP, { now: NOW });
	assert.equal(r.findings.length, 0);
	assert.equal(r.warnings.length, 1);
	assert.ok(r.warnings[0].message.includes("PHP 8.4"), "names the newest cycle it allows");
});

test("evaluatePhpRuntime: out-of-active-support PHP (8.3.*) is a finding ONLY with eolSupport", () => {
	assert.equal(evaluatePhpRuntime([pl("8.3.*")], PHP, { now: NOW }).findings.length, 0);
	const r = evaluatePhpRuntime([pl("8.3.*")], PHP, { now: NOW, eolSupport: true });
	assert.equal(r.findings.length, 1);
	assert.equal(r.findings[0].status, "unsupported");
	assert.equal(r.findings[0].support, "2025-12-31");
});

test("evaluatePhpRuntime: no PHP cycle data (offline, cold cache) → a note, never a verdict", () => {
	const r = evaluatePhpRuntime([pl("^7.4")], null, { now: NOW });
	assert.equal(r.findings.length, 0);
	assert.equal(r.warnings.length, 1);
	assert.ok(/offline|cache/i.test(r.warnings[0].message));
});

test("evaluatePhpRuntime: empty input → nothing", () => {
	assert.deepEqual(evaluatePhpRuntime([], PHP), { findings: [], warnings: [] });
	assert.deepEqual(evaluatePhpRuntime(null, PHP), { findings: [], warnings: [] });
});

test("composer codec: collect exposes _composer.platforms and the fixture's deps", async () => {
	const res = await codec.collect(FIX54, {});
	assert.deepEqual(res._composer.platforms, [{ constraint: "^7.4", source: "lock:platform", manifestPath: path.join(FIX54, "composer.lock") }]);
	assert.ok(res.deps.has("composer:symfony/framework-bundle"));
	assert.equal(res.deps.get("composer:symfony/monolog-bundle").version, "3.10.0");
	assert.equal(res.deps.get("composer:symfony/phpunit-bridge").isDev, true);
	assert.ok(!res.deps.has("composer:php"), "the php platform requirement is never a dep");

	const open = await codec.collect(FIXOPEN, {});
	assert.deepEqual(open._composer.platforms, [{ constraint: ">=7.2.5", source: "lock:platform", manifestPath: path.join(FIXOPEN, "composer.lock") }]);
});

test("composer codec: formatCoord renders a vendor-less name (the php platform) without a leading slash", () => {
	assert.equal(codec.formatCoord({ namespace: "", name: "php" }), "php");
	assert.equal(codec.formatCoord({ namespace: "symfony", name: "yaml" }), "symfony/yaml");
});
