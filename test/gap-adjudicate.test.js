/**
 * Adjudicating a "tool X found it, fad didn't" pair against authoritative OSV data.
 *
 * The whole point: a claimed miss is only a real miss if the public record actually
 * binds that vulnerability to that coordinate AND that version. Everything else is
 * either unreachable (no public record) or the other tool being wrong — and building
 * recall against those manufactures false positives.
 */
const test = require("node:test");
const assert = require("node:assert");
const { classifyPair, VERDICT, summarize, mergeRecords } = require("../lib/gap-adjudicate");

// GHSA-gm62-rw4g-vrc4 (CVE-2023-6481), reduced to the fields that decide the verdict.
const LOGBACK = {
	id: "GHSA-gm62-rw4g-vrc4",
	aliases: ["CVE-2023-6481"],
	affected: [
		{ package: { name: "ch.qos.logback:logback-core", ecosystem: "Maven" },
		  ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "1.2.12" }, { fixed: "1.2.13" }] }],
		  versions: ["1.2.12"] },
	],
};

test("a version BELOW the introduced bound is not a miss — it is the other tool being wrong", () => {
	const v = classifyPair({ coord: "ch.qos.logback:logback-core", version: "1.2.2" }, LOGBACK);
	assert.strictEqual(v.verdict, VERDICT.OUT_OF_RANGE);
});

test("a different artifact of the same project is not a miss either", () => {
	// logback-classic is not logback-core; the advisory binds only the latter.
	const v = classifyPair({ coord: "ch.qos.logback:logback-classic", version: "1.2.12" }, LOGBACK);
	assert.strictEqual(v.verdict, VERDICT.WRONG_ARTIFACT);
	assert.deepStrictEqual(v.boundCoords, ["ch.qos.logback:logback-core"]);
});

test("coordinate AND version inside a declared range is a REAL miss", () => {
	const v = classifyPair({ coord: "ch.qos.logback:logback-core", version: "1.2.12" }, LOGBACK);
	assert.strictEqual(v.verdict, VERDICT.CONFIRMED_MISS);
});

test("an enumerated `versions` entry counts as affected, like OSV says", () => {
	const enumerated = { id: "X", affected: [{ package: { name: "g:a", ecosystem: "Maven" }, versions: ["1.0.0"] }] };
	assert.strictEqual(classifyPair({ coord: "g:a", version: "1.0.0" }, enumerated).verdict, VERDICT.CONFIRMED_MISS);
	assert.strictEqual(classifyPair({ coord: "g:a", version: "0.9.0" }, enumerated).verdict, VERDICT.OUT_OF_RANGE);
});

test("an advisory with only a GIT range carries no ecosystem binding — unreachable, not a miss", () => {
	const gitOnly = {
		id: "CVE-2023-6481",
		affected: [{ ranges: [{ type: "GIT", repo: "https://github.com/qos-ch/logback",
			events: [{ introduced: "a388193" }, { last_affected: "7ee000a" }] }], versions: ["1.2.12"] }],
	};
	const v = classifyPair({ coord: "ch.qos.logback:logback-classic", version: "1.2.2" }, gitOnly);
	assert.strictEqual(v.verdict, VERDICT.NO_MAVEN_BINDING);
});

test("no public record at all (a vendor-proprietary id) is its own class", () => {
	const v = classifyPair({ coord: "g:a", version: "1.0.0" }, null);
	assert.strictEqual(v.verdict, VERDICT.NO_PUBLIC_RECORD);
});

test("a GIT-range advisory whose `versions` list is mistaken for fix versions stays OUT_OF_RANGE", () => {
	// The regression this whole module exists for: OSV `versions` are AFFECTED versions.
	// Reading them as "fixed in" would make 1.2.2 affected and invent a finding.
	const bound = { id: "Y", affected: [{ package: { name: "g:a", ecosystem: "Maven" },
		versions: ["1.2.12", "1.3.13", "1.4.13"] }] };
	assert.strictEqual(classifyPair({ coord: "g:a", version: "1.2.2" }, bound).verdict, VERDICT.OUT_OF_RANGE);
});

test("summarize counts each verdict and isolates the real gap", () => {
	const rows = [
		{ verdict: VERDICT.CONFIRMED_MISS }, { verdict: VERDICT.CONFIRMED_MISS },
		{ verdict: VERDICT.OUT_OF_RANGE }, { verdict: VERDICT.WRONG_ARTIFACT },
		{ verdict: VERDICT.NO_PUBLIC_RECORD },
	];
	const s = summarize(rows);
	assert.strictEqual(s.total, 5);
	assert.strictEqual(s.realGap, 2);
	assert.strictEqual(s.counts[VERDICT.OUT_OF_RANGE], 1);
});

test("Maven ordering is used, not string compare (1.10 > 1.9)", () => {
	const r = { id: "Z", affected: [{ package: { name: "g:a", ecosystem: "Maven" },
		ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "1.9" }, { fixed: "1.11" }] }] }] };
	assert.strictEqual(classifyPair({ coord: "g:a", version: "1.10" }, r).verdict, VERDICT.CONFIRMED_MISS);
});

test("mergeRecords unions the affected sets — the Maven binding lives in the GHSA, not the CVE", () => {
	// OSV holds BOTH: the CVE-converted record (GIT range only) and its GHSA alias
	// (properly bound to Maven). Looking at the CVE alone sees no ecosystem binding and
	// would wrongly call every pair "unreachable".
	const cveRecord = { id: "CVE-2023-6481", aliases: ["GHSA-gm62-rw4g-vrc4"],
		affected: [{ ranges: [{ type: "GIT", repo: "https://github.com/qos-ch/logback", events: [] }] }] };
	const merged = mergeRecords([cveRecord, LOGBACK]);
	assert.strictEqual(classifyPair({ coord: "ch.qos.logback:logback-core", version: "1.2.12" }, merged).verdict,
		VERDICT.CONFIRMED_MISS);
	// and the same pair against the CVE record alone is the misleading answer we avoid
	assert.strictEqual(classifyPair({ coord: "ch.qos.logback:logback-core", version: "1.2.12" }, cveRecord).verdict,
		VERDICT.NO_MAVEN_BINDING);
});

test("mergeRecords of nothing is null, which classifies as NO_PUBLIC_RECORD", () => {
	assert.strictEqual(mergeRecords([]), null);
	assert.strictEqual(classifyPair({ coord: "g:a", version: "1" }, mergeRecords([])).verdict, VERDICT.NO_PUBLIC_RECORD);
});
