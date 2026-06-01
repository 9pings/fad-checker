const { test } = require("node:test");
const assert = require("node:assert/strict");
const { buildFindings } = require("../lib/json-export");
const { makeDepRecord } = require("../lib/dep-record");

test("buildFindings produces a flat findings document with summary counts", () => {
	const log4j = makeDepRecord({ ecosystem: "maven", namespace: "org.apache.logging.log4j", name: "log4j-core", version: "2.14.1", manifestPath: "/proj/pom.xml" });
	const lodash = makeDepRecord({ ecosystem: "npm", name: "lodash", version: "4.17.20", manifestPath: "/proj/package.json" });
	const resolvedDeps = new Map([[log4j.coordKey, log4j], [lodash.coordKey, lodash]]);

	const doc = buildFindings({
		cveMatches: [
			{ dep: log4j, cve: { id: "CVE-2021-44228", severity: "CRITICAL", score: 10, kev: true }, source: "osv" },
			{ dep: lodash, cve: { id: "CVE-2020-8203", severity: "HIGH", score: 7.4 }, cpeFiltered: true },
		],
		eolResults: [{ product: "log4j", eol: true, dep: log4j }],
		outdatedResults: [{ dep: lodash, latest: "4.17.21" }],
		licenseResults: { assessed: [{ dep: lodash, ids: ["MIT"], raw: [], category: "permissive" }], flagged: [] },
		resolvedDeps,
		projectInfo: { name: "demo", src: "/proj", generatedAt: "2026-06-01T00:00:00Z" },
		toolVersion: "2.0.2",
	});

	assert.equal(doc.tool.name, "fad-checker");
	assert.equal(doc.summary.dependencies, 2);
	assert.equal(doc.summary.cve.critical, 1);
	assert.equal(doc.summary.cve.kev, 1);
	assert.equal(doc.summary.cve.total, 1); // cpeFiltered excluded from total
	assert.equal(doc.summary.eol, 1);
	assert.equal(doc.summary.outdated, 1);

	assert.equal(doc.cve.length, 2);
	const c = doc.cve[0];
	assert.equal(c.id, "CVE-2021-44228");
	assert.equal(c.kev, true);
	assert.equal(c.dep.purl, "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
	assert.equal(doc.cve[1].cpeFiltered, true);

	assert.equal(doc.licenses[0].licenses[0], "MIT");
});

test("buildFindings counts suppressed matches separately", () => {
	const dep = makeDepRecord({ ecosystem: "npm", name: "x", version: "1.0.0", manifestPath: "p" });
	const doc = buildFindings({
		cveMatches: [
			{ dep, cve: { id: "CVE-A", severity: "HIGH", score: 7 }, suppressed: true, suppressedReason: "accepted risk" },
			{ dep, cve: { id: "CVE-B", severity: "LOW", score: 2 } },
		],
		resolvedDeps: new Map([[dep.coordKey, dep]]),
	});
	assert.equal(doc.summary.suppressed, 1);
	assert.equal(doc.summary.cve.total, 1); // suppressed excluded
	assert.equal(doc.cve.find(c => c.id === "CVE-A").suppressed, true);
});
