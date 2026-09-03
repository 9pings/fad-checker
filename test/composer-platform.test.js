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
