const { test } = require("node:test");
const assert = require("node:assert/strict");
const { lifecycleStatus, isEol } = require("../lib/outdated");

// Fixed clock so the date comparisons never drift. 2026-09-02 = the day this was designed.
const NOW = Date.parse("2026-09-02T00:00:00Z");

test("lifecycleStatus: eol polarity — true means IS end-of-life, false means not yet", () => {
	assert.equal(lifecycleStatus({ eol: true, support: false }, NOW), "eol");
	assert.equal(lifecycleStatus({ eol: false, support: true }, NOW), "ok");
});

test("lifecycleStatus: support polarity — true means STILL supported, false means support ended", () => {
	assert.equal(lifecycleStatus({ eol: false, support: true }, NOW), "ok");
	assert.equal(lifecycleStatus({ eol: false, support: false }, NOW), "unsupported");
});

test("lifecycleStatus: dates are compared against `now`", () => {
	assert.equal(lifecycleStatus({ eol: "2022-11-28", support: "2021-11-28" }, NOW), "eol");          // PHP 7.4
	assert.equal(lifecycleStatus({ eol: "2029-02-28", support: "2024-11-30" }, NOW), "unsupported");  // Symfony 5.4 LTS
	assert.equal(lifecycleStatus({ eol: "2027-11-30", support: "2026-11-30" }, NOW), "ok");           // Symfony 6.4 LTS
	assert.equal(lifecycleStatus({ eol: false, support: "2024-12-05" }, NOW), "unsupported");         // React 18: never declared EOL
});

test("lifecycleStatus: eol wins over support", () => {
	assert.equal(lifecycleStatus({ eol: "2021-11-30", support: "2020-11-30" }, NOW), "eol");
	assert.equal(lifecycleStatus({ eol: true, support: true }, NOW), "eol");
});

test("lifecycleStatus: missing / unparsable data is conservative (ok)", () => {
	assert.equal(lifecycleStatus(null, NOW), "ok");
	assert.equal(lifecycleStatus({}, NOW), "ok");
	assert.equal(lifecycleStatus({ eol: "not-a-date", support: "soon" }, NOW), "ok");
});

test("isEol is lifecycleStatus === 'eol' (back-compat)", () => {
	assert.equal(isEol({ eol: true }), true);
	assert.equal(isEol({ eol: "2000-01-01" }), true);
	assert.equal(isEol({ eol: false, support: false }), false);
	assert.equal(isEol(null), false);
});

const { checkEolDeps } = require("../lib/outdated");
const { makeDepRecord } = require("../lib/dep-record");

// Real endoflife.date shapes (values as of 2026-09), trimmed.
const SYMFONY = [
	{ cycle: "7.3", eol: "2026-01-31", support: "2026-01-31", latest: "7.3.11", lts: false },
	{ cycle: "6.4", eol: "2027-11-30", support: "2026-11-30", latest: "6.4.42", lts: true },
	{ cycle: "5.4", eol: "2029-02-28", support: "2024-11-30", latest: "5.4.53", lts: true },
	{ cycle: "3.4", eol: "2021-11-30", support: "2020-11-30", latest: "3.4.49", lts: true },
];

function dep(ns, name, version, manifestPath = "/proj/composer.lock") {
	return makeDepRecord({ ecosystem: "composer", namespace: ns, name, version, manifestPath, scope: "prod" });
}

test("checkEolDeps: a default run never returns unsupported findings (no regression)", async () => {
	const resolved = new Map([["composer:symfony/console", dep("symfony", "console", "5.4.47")]]);
	const r = await checkEolDeps(resolved, { cycles: { symfony: SYMFONY }, now: NOW });
	assert.deepEqual(r, []);
});

test("checkEolDeps: --eol-support surfaces Symfony 5.4 as unsupported, carrying both dates", async () => {
	const resolved = new Map([["composer:symfony/console", dep("symfony", "console", "5.4.47")]]);
	const r = await checkEolDeps(resolved, { cycles: { symfony: SYMFONY }, now: NOW, eolSupport: true });
	assert.equal(r.length, 1);
	assert.equal(r[0].status, "unsupported");
	assert.equal(r[0].cycle, "5.4");
	assert.equal(r[0].support, "2024-11-30");
	assert.equal(r[0].eol, "2029-02-28");
	assert.equal(r[0].latest, "5.4.53");
	assert.equal(r[0].productSlug, "symfony");
});

test("checkEolDeps: an EOL cycle is returned with status 'eol' in both modes", async () => {
	const resolved = new Map([["composer:symfony/console", dep("symfony", "console", "3.4.49")]]);
	for (const eolSupport of [false, true]) {
		const r = await checkEolDeps(resolved, { cycles: { symfony: SYMFONY }, now: NOW, eolSupport });
		assert.equal(r.length, 1, `eolSupport=${eolSupport}`);
		assert.equal(r[0].status, "eol");
		assert.equal(r[0].eol, "2021-11-30");
	}
});

test("checkEolDeps: a supported cycle is never a finding", async () => {
	const resolved = new Map([["composer:symfony/console", dep("symfony", "console", "6.4.42")]]);
	const r = await checkEolDeps(resolved, { cycles: { symfony: SYMFONY }, now: NOW, eolSupport: true });
	assert.deepEqual(r, []);
});
