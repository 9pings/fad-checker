const { test } = require("node:test");
const assert = require("node:assert/strict");
const { findEolProduct, COMPOSER_FRAMEWORKS } = require("../lib/outdated");

const c = (ns, name) => ({ ecosystem: "composer", namespace: ns, name, groupId: ns, artifactId: name });

test("composer_frameworks data: symfony/laravel core lists carry their anchors and the monorepo package", () => {
	const sf = COMPOSER_FRAMEWORKS.symfony;
	assert.equal(sf.product, "symfony");
	assert.equal(sf.label, "Symfony");
	for (const n of ["symfony/framework-bundle", "symfony/http-kernel", "symfony/console", "symfony/security-guard", "symfony/yaml", "symfony/monolog-bridge", "symfony/symfony"]) {
		assert.ok(sf.components.includes(n), `${n} must be a symfony core component`);
	}
	for (const a of sf.anchors) assert.ok(sf.components.includes(a), `anchor ${a} must itself be a component`);
	assert.deepEqual(sf.components, [...sf.components].sort(), "components are sorted (stable diffs)");

	const lv = COMPOSER_FRAMEWORKS.laravel;
	assert.equal(lv.product, "laravel");
	for (const n of ["laravel/framework", "illuminate/support", "illuminate/database", "illuminate/contracts"]) {
		assert.ok(lv.components.includes(n), `${n} must be a laravel core component`);
	}
	for (const a of lv.anchors) assert.ok(lv.components.includes(a), `anchor ${a} must itself be a component`);
});

test("zero-FP guard: independently-versioned symfony/* packages are NOT framework components and map to NO product", () => {
	// Each of these ships its own version line (monolog-bundle 3.x, phpunit-bridge 6.4 inside a
	// 5.4 app, contracts 2.x/3.x, polyfills 1.x, flex 1.x/2.x). Mapping any of them to the
	// "symfony" product would match a wrong endoflife cycle — a false positive.
	for (const n of [
		"symfony/monolog-bundle", "symfony/phpunit-bridge", "symfony/deprecation-contracts", "symfony/service-contracts",
		"symfony/event-dispatcher-contracts", "symfony/http-client-contracts", "symfony/translation-contracts", "symfony/cache-contracts",
		"symfony/polyfill-mbstring", "symfony/polyfill-php80", "symfony/flex", "symfony/maker-bundle", "symfony/webpack-encore-bundle",
		"symfony/runtime", "symfony/apache-pack", "symfony/ux-twig-component",
	]) {
		assert.ok(!COMPOSER_FRAMEWORKS.symfony.components.includes(n), `${n} must not be a core component`);
		const [ns, name] = n.split("/");
		assert.equal(findEolProduct(c(ns, name)), null, `${n} must not map to any EOL product`);
	}
});

test("findEolProduct: a framework component maps via composer-framework and carries frameworkId", () => {
	const r = findEolProduct(c("symfony", "framework-bundle"));
	assert.equal(r.product, "symfony");
	assert.equal(r.label, "Symfony");
	assert.equal(r.via, "composer-framework");
	assert.equal(r.viaKey, "symfony/framework-bundle");
	assert.equal(r.frameworkId, "symfony");
	assert.equal(findEolProduct(c("Symfony", "Security-Guard")).frameworkId, "symfony", "case-insensitive");
	assert.equal(findEolProduct(c("illuminate", "support")).frameworkId, "laravel");
	assert.equal(findEolProduct(c("laravel", "framework")).frameworkId, "laravel");
});

test("findEolProduct: by_composer_name still serves non-framework entries (drupal/core) without frameworkId", () => {
	const r = findEolProduct(c("drupal", "core"));
	assert.equal(r.product, "drupal");
	assert.equal(r.via, "composer-name");
	assert.equal(r.frameworkId, undefined);
});
