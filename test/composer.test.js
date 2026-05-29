const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { parseComposerLock, parseComposerJson } = require("../lib/composer/parse");

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
