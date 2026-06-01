const { test } = require("node:test");
const assert = require("node:assert/strict");
const { buildSarif, sarifLevel } = require("../lib/sarif-export");
const { makeDepRecord } = require("../lib/dep-record");

test("sarifLevel maps severity to SARIF levels", () => {
	assert.equal(sarifLevel("CRITICAL"), "error");
	assert.equal(sarifLevel("HIGH"), "error");
	assert.equal(sarifLevel("MEDIUM"), "warning");
	assert.equal(sarifLevel("LOW"), "note");
	assert.equal(sarifLevel("UNKNOWN"), "note");
});

test("buildSarif emits a valid 2.1.0 log with rules + results", () => {
	const dep = makeDepRecord({ ecosystem: "maven", namespace: "org.apache.logging.log4j", name: "log4j-core", version: "2.14.1", manifestPath: "/proj/pom.xml" });
	const matches = [{
		dep,
		cve: { id: "CVE-2021-44228", severity: "CRITICAL", score: 10, cwes: ["CWE-502"], kev: true, epssPercentile: 0.99, priority: { band: "exploited" } },
		source: "osv+nvd",
	}];
	const doc = buildSarif(matches, { projectInfo: { src: "/proj" }, toolVersion: "2.0.2" });

	assert.equal(doc.version, "2.1.0");
	const run = doc.runs[0];
	assert.equal(run.tool.driver.name, "fad-checker");
	assert.equal(run.tool.driver.rules.length, 1);
	const rule = run.tool.driver.rules[0];
	assert.equal(rule.id, "CVE-2021-44228");
	assert.equal(rule.properties["security-severity"], "10"); // GitHub reads this
	assert.ok(rule.properties.tags.includes("cisa-kev"));

	assert.equal(run.results.length, 1);
	const r = run.results[0];
	assert.equal(r.ruleId, "CVE-2021-44228");
	assert.equal(r.level, "error");
	assert.equal(r.locations[0].physicalLocation.artifactLocation.uri, "pom.xml"); // relative to src
	assert.equal(r.properties.kev, true);
	assert.equal(r.properties.purl, "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
	assert.equal(r.partialFingerprints.fadKey, "org.apache.logging.log4j:log4j-core@2.14.1|CVE-2021-44228");
});

test("buildSarif dedups rules across multiple matches of the same CVE", () => {
	const d1 = makeDepRecord({ ecosystem: "npm", name: "a", version: "1.0.0", manifestPath: "package.json" });
	const d2 = makeDepRecord({ ecosystem: "npm", name: "b", version: "2.0.0", manifestPath: "package.json" });
	const doc = buildSarif([
		{ dep: d1, cve: { id: "CVE-X", severity: "HIGH", score: 7 } },
		{ dep: d2, cve: { id: "CVE-X", severity: "HIGH", score: 7 } },
	], {});
	assert.equal(doc.runs[0].tool.driver.rules.length, 1);
	assert.equal(doc.runs[0].results.length, 2);
});
