const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const {
	parseCpe23,
	matchVersionRange,
	cpeMatchesDep,
	evaluateCveForDep,
	refineMatchesWithCpe,
} = require("../lib/cpe");

const FIX = path.join(__dirname, "fixtures", "cve-samples");

test("parseCpe23 splits all 13 fields and handles escaping", () => {
	const c = parseCpe23("cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*");
	assert.equal(c.part, "a");
	assert.equal(c.vendor, "apache");
	assert.equal(c.product, "log4j");
	assert.equal(c.version, "2.14.0");
});

test("parseCpe23 returns null for malformed URI", () => {
	assert.equal(parseCpe23("not a cpe"), null);
	assert.equal(parseCpe23("cpe:2.3:a:vendor"), null);
	assert.equal(parseCpe23(42), null);
});

test("parseCpe23 handles backslash-escaped colons (e.g. eclipse:vert\\.x)", () => {
	const c = parseCpe23("cpe:2.3:a:vendor:weird\\:name:1.0:*:*:*:*:*:*:*");
	assert.equal(c.product, "weird:name");
});

test("matchVersionRange honours versionStartIncluding + versionEndExcluding", () => {
	const m = {
		criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
		vulnerable: true,
		versionStartIncluding: "2.0.0",
		versionEndExcluding: "2.15.0",
	};
	assert.equal(matchVersionRange("2.14.1", m), true);
	assert.equal(matchVersionRange("2.0.0", m), true);    // lower-inclusive
	assert.equal(matchVersionRange("2.15.0", m), false);  // upper-exclusive
	assert.equal(matchVersionRange("1.9.0", m), false);
	assert.equal(matchVersionRange("2.17.0", m), false);
});

test("matchVersionRange honours hard-pinned criteria version", () => {
	const m = { criteria: "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*", vulnerable: true };
	assert.equal(matchVersionRange("2.14.0", m), true);
	assert.equal(matchVersionRange("2.14.1", m), false);
});

test("matchVersionRange returns true for unknown dep version (conservative)", () => {
	const m = { criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", vulnerable: true, versionEndExcluding: "2.15.0" };
	assert.equal(matchVersionRange(null, m), true);
});

test("cpeMatchesDep — curated map exact maven coord", () => {
	const cpe = parseCpe23("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*");
	const dep = { groupId: "org.apache.logging.log4j", artifactId: "log4j-core", ecosystem: "maven" };
	assert.equal(cpeMatchesDep(cpe, dep), true);
});

test("cpeMatchesDep — heuristic vendor token in groupId", () => {
	const cpe = parseCpe23("cpe:2.3:a:apache:commons-totally-novel:*:*:*:*:*:*:*:*");
	const dep = { groupId: "org.apache.commons", artifactId: "commons-totally-novel", ecosystem: "maven" };
	assert.equal(cpeMatchesDep(cpe, dep), true);
});

test("cpeMatchesDep — npm bare name", () => {
	const cpe = parseCpe23("cpe:2.3:a:lodash:lodash:*:*:*:*:*:node.js:*:*");
	const dep = { groupId: "", artifactId: "lodash", ecosystem: "npm" };
	assert.equal(cpeMatchesDep(cpe, dep), true);
});

test("cpeMatchesDep — npm scoped package via vendor split", () => {
	const cpe = parseCpe23("cpe:2.3:a:scope:pkg:*:*:*:*:*:*:*:*");
	const dep = { groupId: "", artifactId: "@scope/pkg", ecosystem: "npm" };
	assert.equal(cpeMatchesDep(cpe, dep), true);
});

test("cpeMatchesDep — wrong artifact does not match", () => {
	const cpe = parseCpe23("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*");
	const dep = { groupId: "org.apache.commons", artifactId: "commons-io", ecosystem: "maven" };
	assert.equal(cpeMatchesDep(cpe, dep), false);
});

test("evaluateCveForDep — Log4Shell NVD record matches vulnerable log4j-core", () => {
	const cve = JSON.parse(fs.readFileSync(path.join(FIX, "nvd-log4shell.json"), "utf8"));
	const dep = { groupId: "org.apache.logging.log4j", artifactId: "log4j-core", version: "2.14.0", ecosystem: "maven" };
	const { affected, confidence } = evaluateCveForDep(cve, dep);
	assert.equal(affected, true);
	assert.equal(confidence, "exact");
});

test("evaluateCveForDep — patched log4j is not affected (version out of range)", () => {
	const cve = JSON.parse(fs.readFileSync(path.join(FIX, "nvd-log4shell.json"), "utf8"));
	const dep = { groupId: "org.apache.logging.log4j", artifactId: "log4j-core", version: "2.17.1", ecosystem: "maven" };
	const { affected } = evaluateCveForDep(cve, dep);
	assert.equal(affected, false);
});

test("evaluateCveForDep — unrelated maven dep is not affected", () => {
	const cve = JSON.parse(fs.readFileSync(path.join(FIX, "nvd-log4shell.json"), "utf8"));
	const dep = { groupId: "com.google.guava", artifactId: "guava", version: "31.0", ecosystem: "maven" };
	const { affected } = evaluateCveForDep(cve, dep);
	assert.equal(affected, false);
});

test("evaluateCveForDep — npm lodash matches the lodash CVE", () => {
	const cve = JSON.parse(fs.readFileSync(path.join(FIX, "nvd-npm-lodash.json"), "utf8"));
	const dep = { groupId: "", artifactId: "lodash", version: "4.17.10", ecosystem: "npm" };
	const { affected, confidence } = evaluateCveForDep(cve, dep);
	assert.equal(affected, true);
	assert.equal(confidence, "exact");
});

test("evaluateCveForDep — patched npm lodash is not affected", () => {
	const cve = JSON.parse(fs.readFileSync(path.join(FIX, "nvd-npm-lodash.json"), "utf8"));
	const dep = { groupId: "", artifactId: "lodash", version: "4.17.20", ecosystem: "npm" };
	const { affected } = evaluateCveForDep(cve, dep);
	assert.equal(affected, false);
});

test("refineMatchesWithCpe upgrades possible→exact when curated map confirms", () => {
	const cve = JSON.parse(fs.readFileSync(path.join(FIX, "nvd-log4shell.json"), "utf8"));
	const matches = [{
		dep: { groupId: "org.apache.logging.log4j", artifactId: "log4j-core", version: "2.14.0", ecosystem: "maven" },
		cve: { id: cve.id, configurations: cve.configurations, severity: "HIGH" },
		confidence: "possible",
	}];
	refineMatchesWithCpe(matches);
	assert.equal(matches[0].confidence, "exact");
	assert.equal(matches[0].cpeConfidence, "exact");
	assert.equal(matches[0].cpeFiltered, undefined);
});

test("refineMatchesWithCpe flags out-of-range version as likely FP", () => {
	const cve = JSON.parse(fs.readFileSync(path.join(FIX, "nvd-log4shell.json"), "utf8"));
	const matches = [{
		dep: { groupId: "org.apache.logging.log4j", artifactId: "log4j-core", version: "2.17.1", ecosystem: "maven" },
		cve: { id: cve.id, configurations: cve.configurations, severity: "HIGH" },
		confidence: "probable",
	}];
	refineMatchesWithCpe(matches);
	assert.equal(matches[0].cpeFiltered, true);
});
