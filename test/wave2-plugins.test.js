const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { allApplicationPlugins } = require("../lib/application-plugins");
const { runApplicationPlugins } = require("../lib/application-plugins/runner");
const composer = require("../lib/codecs/composer.codec");

function fixture(fn) {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-wave2-"));
	return Promise.resolve().then(() => fn(root)).finally(() => fs.rmSync(root, { recursive: true, force: true }));
}
function put(root, relative, content) {
	const file = path.join(root, relative);
	fs.mkdirSync(path.dirname(file), { recursive: true });
	fs.writeFileSync(file, typeof content === "string" ? content : JSON.stringify(content));
}
async function scan(root, selection, scanContext = "source") {
	const { deps } = await composer.collect(root);
	return runApplicationPlugins(root, { plugins: allApplicationPlugins(), selection,
		resolvedDeps: deps, activeCodecIds: ["composer"], scanContext });
}
function assertAdvisoriesNotRun(result, pluginId) {
	assert.equal(result.applications[0].type, pluginId);
	const advisory = result.coverage.find(c => c.capability === "advisories");
	assert.equal(advisory.execution, "not-run");
	// prestashop/typo3 have a qualified publisher lane: unconfigured stays honest about
	// what would have run; joomla/magento have no machine feed to qualify yet.
	assert.equal(advisory.diagnostic,
		["prestashop", "typo3"].includes(pluginId) ? "CMS_PROVIDER_UNCONFIGURED" : "CMS_ADVISORY_NOT_QUALIFIED");
	assert.deepEqual(result.findings, []);
}

test("Joomla recognizes a site and its typed XML extension manifests without treating installer compatibility as a package version", () => fixture(async root => {
	put(root, "administrator/manifests/files/joomla.xml", '<extension type="file"><name>Joomla!</name><version>5.4.1</version></extension>');
	put(root, "libraries/src/Version.php", "<?php class Version {}\n");
	put(root, "components/com_shop/shop.xml", '<extension type="component" version="5.0"><name>Shop</name><version>2.1.0</version></extension>');
	put(root, "plugins/system/demo/demo.xml", '<extension type="plugin"><name>Demo</name><version>1.2.0</version></extension>');
	put(root, "components/com_fake/fake.xml", '<extension type="module"><name>Wrong kind</name><version>8</version></extension>');
	const result = await scan(root, "joomla");
	assert.equal(result.applications.length, 1);
	assert.equal(result.inventory.find(c => c.kind === "core").version, "5.4.1");
	assert.equal(result.inventory.find(c => c.kind === "component").version, "2.1.0");
	assert.equal(result.inventory.find(c => c.kind === "plugin").version, "1.2.0");
	assert.equal(result.inventory.length, 3);
	assertAdvisoriesNotRun(result, "joomla");
}));

test("PrestaShop reads an installed core version and module/theme versions, while detecting a source-version conflict", () => fixture(async root => {
	put(root, "composer.json", { name: "prestashop/prestashop", type: "project" });
	put(root, "config/config.inc.php", "<?php // marker\n");
	put(root, "config/settings.inc.php", "<?php define('_PS_VERSION_', '8.2.1');\n");
	put(root, "install-dev/install_version.php", "<?php define('_PS_INSTALL_VERSION_', '8.2.2');\n");
	put(root, "modules/ps_banner/ps_banner.php", "<?php class Ps_Banner extends PaymentModule { function __construct() { $this->name = 'ps_banner'; $this->version = '2.0.3'; } }");
	put(root, "themes/classic/config/theme.yml", "name: Classic\nversion: 1.7.0\n");
	const result = await scan(root, "prestashop");
	assert.equal(result.inventory.find(c => c.kind === "core").version, "8.2.1");
	assert.equal(result.inventory.find(c => c.kind === "module").version, "2.0.3");
	assert.equal(result.inventory.find(c => c.kind === "theme").version, "1.7.0");
	assert.ok(result.diagnostics.some(d => d.code === "CMS_VERSION_CONFLICT"));
	assertAdvisoriesNotRun(result, "prestashop");
}));

test("TYPO3 uses the locked cms-core version and merges a classic extension with its Composer identity", () => fixture(async root => {
	put(root, "composer.json", { name: "example/site", require: { "typo3/cms-core": "^13.4" } });
	put(root, "composer.lock", { packages: [
		{ name: "typo3/cms-core", version: "13.4.2" },
		{ name: "acme/news", version: "1.2.3", type: "typo3-cms-extension" },
	], "packages-dev": [] });
	put(root, "public/index.php", "<?php // marker\n");
	put(root, "typo3conf/ext/news/composer.json", { name: "acme/news", type: "typo3-cms-extension",
		extra: { "typo3/cms": { "extension-key": "news", version: "1.2.3" } } });
	put(root, "typo3conf/ext/news/ext_emconf.php", "<?php $EM_CONF[$_EXTKEY] = ['version' => '1.2.3'];\n");
	const result = await scan(root, "typo3");
	assert.equal(result.inventory.find(c => c.kind === "core").version, "13.4.2");
	const extension = result.inventory.find(c => c.coord === "acme/news" && c.applicationId === "typo3:.");
	assert.equal(extension.version, "1.2.3");
	assert.equal(extension.path, "typo3conf/ext/news");
	assertAdvisoriesNotRun(result, "typo3");
}));

test("TYPO3 source inventory includes versioned system extensions without inventing a Composer lock", () => fixture(async root => {
	put(root, "composer.json", { name: "typo3/cms", type: "typo3-cms-core" });
	put(root, "typo3/sysext/core/ext_emconf.php", "<?php $EM_CONF[$_EXTKEY] = ['version' => '13.4.2'];");
	put(root, "typo3/sysext/seo/composer.json", { name: "typo3/cms-seo", type: "typo3-cms-framework" });
	put(root, "typo3/sysext/seo/ext_emconf.php", "<?php $EM_CONF[$_EXTKEY] = ['version' => '13.4.2'];");
	const result = await scan(root, "typo3");
	assert.equal(result.inventory.find(c => c.kind === "core").version, "13.4.2");
	const seo = result.inventory.find(c => c.coord === "typo3/cms-seo");
	assert.equal(seo.kind, "framework-component");
	assert.equal(seo.version, "13.4.2");
	assert.equal(result.coverage.find(c => c.capability === "inventory").diagnostic, "CMS_LOCKFILE_MISSING");
}));

test("Magento distinguishes Adobe Commerce from Open Source and preserves the exact -pN product version", () => fixture(async root => {
	put(root, "composer.json", { name: "acme/shop", require: { "magento/product-enterprise-edition": "^2.4" } });
	put(root, "composer.lock", { packages: [
		{ name: "magento/product-enterprise-edition", version: "2.4.7-p3" },
		{ name: "acme/module-pay", version: "1.2.3", type: "magento2-module" },
	], "packages-dev": [] });
	put(root, "bin/magento", "<?php // marker\n");
	put(root, "app/bootstrap.php", "<?php // marker\n");
	put(root, "app/code/Acme/Pay/etc/module.xml", '<config><module name="Acme_Pay" setup_version="0.1.0"/></config>');
	put(root, "app/code/Acme/Pay/registration.php", "<?php ComponentRegistrar::register(ComponentRegistrar::MODULE, 'Acme_Pay', __DIR__);\n");
	put(root, "app/code/Acme/Pay/composer.json", { name: "acme/module-pay", type: "magento2-module", version: "1.2.3" });
		const result = await scan(root, "magento");
		assert.equal(result.applications[0].edition, "adobe-commerce");
		const core = result.inventory.find(c => c.kind === "core");
	assert.equal(core.name, "Adobe Commerce");
	assert.equal(core.version, "2.4.7-p3");
	const mod = result.inventory.find(c => c.coord === "acme/module-pay");
	assert.equal(mod.version, "1.2.3");
	assert.notEqual(mod.version, "0.1.0", "module schema version is not the package version");
	assertAdvisoriesNotRun(result, "magento");
}));

test("auto inventories a recognized wave-two layout and unrelated PHP packages never become applications", () => fixture(async root => {
	put(root, "composer.json", { name: "acme/library", require: { "typo3/cms-core": "^13.4" } });
	const none = await scan(root, "all");
	assert.equal(none.applications.length, 0, "a require constraint alone is not an application");
	put(root, "administrator/manifests/files/joomla.xml", '<extension type="file"><name>Joomla!</name><version>5.4.1</version></extension>');
	put(root, "libraries/src/Version.php", "<?php class Version {}\n");
	const auto = await scan(root, "auto");
	assert.equal(auto.applications.length, 1, "a present CMS is activated by the default auto selection");
	assert.equal(auto.applications[0].type, "joomla");
	assert.equal(auto.inventory.find(c => c.kind === "core").version, "5.4.1");
	assert.ok(!auto.diagnostics.some(d => d.code === "CMS_PLUGIN_UNQUALIFIED"));
}));

test("Joomla reports disagreement between its runtime constants and package manifest", () => fixture(async root => {
	put(root, "administrator/manifests/files/joomla.xml", '<extension type="file"><name>files_joomla</name><version>5.4.1</version></extension>');
	put(root, "libraries/src/Version.php", "<?php final class Version { public const MAJOR_VERSION = 5; public const MINOR_VERSION = 4; public const PATCH_VERSION = 2; public const EXTRA_VERSION = ''; }");
	const result = await scan(root, "joomla");
	assert.equal(result.inventory[0].version, "5.4.2");
	assert.ok(result.diagnostics.some(d => d.code === "CMS_VERSION_CONFLICT"));
	assert.equal(result.coverage.find(c => c.capability === "inventory").execution, "partial");
}));

test("component context recognizes each wave-two extension without inventing a CMS core", async () => {
	for (const [id, files, kind] of [
		["joomla", { "demo.xml": '<extension type="plugin"><name>Demo</name><version>1.0.0</version></extension>' }, "plugin"],
		["prestashop", { "demo.php": "<?php class Demo extends Module { function __construct() { $this->name = 'demo'; $this->version = '1.0.0'; } }" }, "module"],
		["typo3", { "ext_emconf.php": "<?php $EM_CONF[$_EXTKEY] = ['version' => '1.0.0'];" }, "module"],
		["magento", { "etc/module.xml": '<config><module name="Acme_Demo"/></config>',
			"registration.php": "<?php ComponentRegistrar::register(ComponentRegistrar::MODULE, 'Acme_Demo', __DIR__);" }, "module"],
	]) await fixture(async root => {
		for (const [file, content] of Object.entries(files)) put(root, file, content);
		const result = await scan(root, id, "component");
		assert.equal(result.applications.length, 1, id);
		assert.equal(result.inventory.length, 1, id);
		assert.equal(result.inventory[0].kind, kind, id);
		assert.equal(result.inventory.some(c => c.kind === "core"), false, id);
		assertAdvisoriesNotRun(result, id);
	});
});

// Reduced from the publishers' real GitHub advisory records (2026-09-23): PrestaShop
// GHSA-xrwj-pq6w-f8m4 (two-branch range, no CVE) and the 2020-era CVE-2020-5293 record
// whose package identity is empty in the official feed; TYPO3 GHSA-8jw7-8qw5-gqr3
// (spaceless hyphen interval on typo3/cms-lowlevel).
const GH_FEED = [
	{ ghsa_id: "GHSA-xrwj-pq6w-f8m4", cve_id: null, summary: "SSRF through image URLs in the CSV import",
		severity: "high", cvss: { vector_string: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:L", score: 8.2 },
		vulnerabilities: [
			{ package: { ecosystem: "composer", name: "prestashop/prestashop" },
				vulnerable_version_range: ">= 9.0.0, < 9.1.5", patched_versions: "9.1.5", vulnerable_functions: [] },
			{ package: { ecosystem: "composer", name: "prestashop/prestashop" },
				vulnerable_version_range: ">= 8.0.0, < 8.2.8", patched_versions: "8.2.8", vulnerable_functions: [] }],
		published_at: "2026-08-18T12:48:34Z", updated_at: "2026-08-18T12:48:34Z",
		html_url: "https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-xrwj-pq6w-f8m4" },
	{ ghsa_id: "GHSA-cvjj-grfv-f56w", cve_id: "CVE-2020-5293", summary: "Improper access control on product page",
		severity: "moderate", cvss: { vector_string: null, score: null },
		vulnerabilities: [{ package: { ecosystem: "", name: "" },
			vulnerable_version_range: "> 1.7.0.0", patched_versions: "1.7.6.5", vulnerable_functions: [] }],
		published_at: "2020-06-23T14:17:39Z", updated_at: "2020-06-23T14:17:39Z",
		html_url: "https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-cvjj-grfv-f56w" },
	{ ghsa_id: "GHSA-8jw7-8qw5-gqr3", cve_id: "CVE-2026-85400", summary: "Missing Authorization in lowlevel commands",
		severity: "high", cvss: { vector_string: null, score: null },
		vulnerabilities: [{ package: { ecosystem: "composer", name: "typo3/cms-lowlevel" },
			vulnerable_version_range: "14.2.0-14.3.6", patched_versions: "14.3.7", vulnerable_functions: [] }],
		published_at: "2026-09-08T09:33:31Z", updated_at: "2026-09-08T09:33:31Z",
		html_url: "https://github.com/TYPO3/typo3/security/advisories/GHSA-8jw7-8qw5-gqr3" },
];

test("PrestaShop evaluates the publisher's Github advisory feed against its observed core version", () => fixture(async root => {
	put(root, "composer.json", { name: "prestashop/prestashop", type: "project" });
	put(root, "config/config.inc.php", "<?php // marker\n");
	put(root, "config/settings.inc.php", "<?php define('_PS_VERSION_', '8.2.1');\n");
	const snapshotFile = path.join(root, "prestashop-advisories.json");
	put(root, "prestashop-advisories.json", { advisories: GH_FEED,
		_fadSnapshot: { collectedAt: "2026-09-23T10:00:00Z", completeness: "tool-fetched" } });
	const { deps } = await composer.collect(root);
	const result = await runApplicationPlugins(root, { plugins: allApplicationPlugins(), selection: "prestashop",
		resolvedDeps: deps, activeCodecIds: ["composer"], prestashopAdvisoriesPath: snapshotFile,
		requiredProviderIds: ["github-prestashop-advisories"] });
	assert.equal(result.findings.length, 1);
	assert.equal(result.findings[0].cve.id, "GHSA-xrwj-pq6w-f8m4");
	assert.equal(result.findings[0].cve.fixVersion, "8.2.8");
	assert.equal(result.findings[0].source, "github-prestashop-advisories");
	const advisory = result.coverage.find(c => c.capability === "advisories");
	assert.equal(advisory.sourceId, "github-prestashop-advisories");
	assert.equal(advisory.execution, "completed");
	assert.equal(advisory.result, "affected");
	assert.equal(advisory.sourceSnapshot.completeness, "operator-declared");
	assert.ok(advisory.sourceSnapshot.collectedAt, "the declared collection date travels with the coverage");
	assert.ok(!result.coverage.some(c => c.sourceId === "application-advisories"),
		"the generic not-qualified lane no longer claims PrestaShop advisories");
}));

test("a PrestaShop source version above every patched release is not flagged by the lossy 2020 records", () => fixture(async root => {
	put(root, "composer.json", { name: "prestashop/prestashop", type: "project" });
	put(root, "config/config.inc.php", "<?php // marker\n");
	put(root, "config/settings.inc.php", "<?php define('_PS_VERSION_', '9.2.0');\n");
	const snapshotFile = path.join(root, "prestashop-advisories.json");
	put(root, "prestashop-advisories.json", { advisories: [GH_FEED[1]] });
	const { deps } = await composer.collect(root);
	const result = await runApplicationPlugins(root, { plugins: allApplicationPlugins(), selection: "prestashop",
		resolvedDeps: deps, activeCodecIds: ["composer"], prestashopAdvisoriesPath: snapshotFile });
	assert.deepEqual(result.findings, []);
	const advisory = result.coverage.find(c => c.capability === "advisories");
	assert.equal(advisory.result, "no-match");
}));

test("TYPO3 evaluates the publisher's Github advisory feed per composer coordinate", () => fixture(async root => {
	put(root, "composer.json", { name: "example/site", require: { "typo3/cms-core": "^13.4" } });
	put(root, "composer.lock", { packages: [
		{ name: "typo3/cms-core", version: "13.4.2" },
		{ name: "typo3/cms-lowlevel", version: "14.3.6", type: "typo3-cms-framework" },
	], "packages-dev": [] });
	put(root, "public/index.php", "<?php // marker\n");
	const snapshotFile = path.join(root, "typo3-advisories.json");
	put(root, "typo3-advisories.json", { advisories: [GH_FEED[2]] });
	const { deps } = await composer.collect(root);
	const result = await runApplicationPlugins(root, { plugins: allApplicationPlugins(), selection: "typo3",
		resolvedDeps: deps, activeCodecIds: ["composer"], typo3AdvisoriesPath: snapshotFile,
		requiredProviderIds: ["github-typo3-advisories"] });
	assert.equal(result.findings.length, 1);
	assert.equal(result.findings[0].cve.id, "CVE-2026-85400");
	assert.equal(result.findings[0].dep.coordKey, "composer:typo3/cms-lowlevel");
	const bySource = result.coverage.filter(c => c.capability === "advisories");
	assert.equal(bySource.length, 2, "one coverage row per inventoried composer component");
	assert.ok(bySource.every(c => c.sourceId === "github-typo3-advisories"));
	const lowlevel = bySource.find(c => (c.occurrenceId || "").includes("cms-lowlevel"));
	assert.equal(lowlevel.result, "affected");
	const core = bySource.find(c => !((c.occurrenceId || "").includes("cms-lowlevel")));
	assert.equal(core.result, "no-match");
}));
