const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { parseComposerLock, parseComposerJson } = require("../lib/codecs/composer/parse");

const FIX = path.join(__dirname, "fixtures", "php-app");

test("parseComposerLock reads prod + dev packages, strips leading v", () => {
	const r = parseComposerLock(path.join(FIX, "composer.lock"));
	const byName = Object.fromEntries(r.deps.map(d => [d.name, d]));
	assert.strictEqual(byName["guzzlehttp/guzzle"].version, "7.4.5");
	assert.strictEqual(byName["guzzlehttp/guzzle"].scope, "prod");
	assert.strictEqual(byName["symfony/console"].version, "6.2.10");      // "v6.2.10" → "6.2.10"
	assert.strictEqual(byName["phpunit/phpunit"].scope, "dev");
	assert.strictEqual(byName["phpunit/phpunit"].isDev, true);
});

test("parseComposerJson reads require + require-dev with pinned-vs-range info", () => {
	const r = parseComposerJson(path.join(FIX, "composer.json"));
	const byName = Object.fromEntries(r.deps.map(d => [d.name, d]));
	assert.strictEqual(byName["monolog/monolog"].version, "2.9.1");
	assert.strictEqual(byName["guzzlehttp/guzzle"].version, "^7.0");
	assert.strictEqual(byName["phpunit/phpunit"].scope, "dev");
});

const { packagistToFindings } = require("../lib/codecs/composer/registry");

test("packagistToFindings extracts latest stable + abandoned flag", () => {
	const pkg = {
		"abandoned": "psr/log",
		"versions": {
			"2.9.1": { "version": "2.9.1" },
			"3.0.0": { "version": "3.0.0" },
			"dev-main": { "version": "dev-main" },
			"2.8.0": { "version": "2.8.0" },
		},
	};
	const f = packagistToFindings(pkg, { version: "2.9.1" });
	assert.strictEqual(f.outdated.latest, "3.0.0");
	assert.deepStrictEqual(f.abandoned, { replacement: "psr/log" });

	const f2 = packagistToFindings({ "abandoned": true, "versions": { "1.0.0": {} } }, { version: "1.0.0" });
	assert.deepStrictEqual(f2.abandoned, { replacement: null });
	assert.strictEqual(f2.outdated, null);
});

const composer = require("../lib/codecs/composer.codec");
const { assertCodecShape } = require("../lib/codecs/codec.interface");

test("composer codec: shape, detect, collect with composer:vendor/pkg coordKeys", async () => {
	assertCodecShape(composer);
	assert.strictEqual(composer.detect(FIX), true);
	const { deps } = await composer.collect(FIX, {});
	const g = deps.get("composer:guzzlehttp/guzzle");
	assert.ok(g, "guzzle should be collected under composer:guzzlehttp/guzzle");
	assert.strictEqual(g.ecosystem, "composer");
	assert.strictEqual(g.namespace, "guzzlehttp");
	assert.strictEqual(g.name, "guzzle");
	assert.strictEqual(composer.osvPackageName(g), "guzzlehttp/guzzle");
	assert.strictEqual(composer.formatCoord(g), "guzzlehttp/guzzle");
});

test("composer collect falls back to composer.json (pinned only) with warning when no lock", async () => {
	const os2 = require("os"); const fs2 = require("fs"); const p2 = require("path");
	const dir = fs2.mkdtempSync(p2.join(os2.tmpdir(), "composer-nolock-"));
	fs2.writeFileSync(p2.join(dir, "composer.json"), JSON.stringify({ name: "x/y", require: { "a/pinned": "1.2.3", "b/range": "^2.0" } }));
	const { deps, warnings } = await composer.collect(dir, {});
	assert.ok(deps.has("composer:a/pinned"));
	assert.ok(!deps.has("composer:b/range"));
	assert.ok(warnings.find(w => w.type === "no-lockfile"));
});
