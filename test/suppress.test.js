const { test } = require("node:test");
const assert = require("node:assert/strict");
const { parseIgnoreFile, parseVex, applySuppressions } = require("../lib/suppress");
const { makeDepRecord } = require("../lib/dep-record");

const log4j = makeDepRecord({ ecosystem: "maven", namespace: "org.apache.logging.log4j", name: "log4j-core", version: "2.14.1", manifestPath: "pom.xml" });
const lodash = makeDepRecord({ ecosystem: "npm", name: "lodash", version: "4.17.20", manifestPath: "package.json" });

test("parseIgnoreFile parses cve / coord / reason and comments", () => {
	const rules = parseIgnoreFile(`
# a comment line
CVE-2021-44228               # accepted: not reachable
CVE-1111-2222 org.apache.*   # only this coord
* npm:lodash
`);
	assert.equal(rules.length, 3);
	assert.equal(rules[0].cve, "CVE-2021-44228");
	assert.equal(rules[0].coord, null);
	assert.equal(rules[0].reason, "accepted: not reachable");
	assert.equal(rules[1].coord, "org.apache.*");
	assert.equal(rules[2].cve, "*");
});

test("applySuppressions marks a global CVE rule across deps", () => {
	const matches = [
		{ dep: log4j, cve: { id: "CVE-2021-44228" } },
		{ dep: lodash, cve: { id: "CVE-2021-44228" } },
		{ dep: lodash, cve: { id: "CVE-OTHER" } },
	];
	const n = applySuppressions(matches, parseIgnoreFile("CVE-2021-44228 # accepted"));
	assert.equal(n, 2);
	assert.equal(matches[0].suppressed, true);
	assert.equal(matches[0].suppressedReason, "accepted");
	assert.equal(matches[2].suppressed, undefined);
});

test("coord-scoped rule only suppresses the matching dependency", () => {
	const matches = [
		{ dep: log4j, cve: { id: "CVE-X" } },
		{ dep: lodash, cve: { id: "CVE-X" } },
	];
	applySuppressions(matches, parseIgnoreFile("CVE-X org.apache.logging.log4j:log4j-core"));
	assert.equal(matches[0].suppressed, true);
	assert.equal(matches[1].suppressed, undefined);
});

test("glob on coord matches a family", () => {
	const matches = [{ dep: log4j, cve: { id: "CVE-Y" } }];
	applySuppressions(matches, parseIgnoreFile("* org.apache.*"));
	assert.equal(matches[0].suppressed, true);
});

test("parseVex suppresses CVEs marked not_affected/fixed, mapped by purl", () => {
	const csaf = {
		product_tree: { full_product_names: [
			{ product_id: "PROD-0", name: "log4j", product_identification_helper: { purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" } },
		] },
		vulnerabilities: [
			{ cve: "CVE-2021-44228", product_status: { known_not_affected: ["PROD-0"] } },
			{ cve: "CVE-GLOBAL", product_status: { fixed: [] } },
		],
	};
	const rules = parseVex(csaf);
	const matches = [
		{ dep: log4j, cve: { id: "CVE-2021-44228" } },
		{ dep: lodash, cve: { id: "CVE-2021-44228" } }, // different coord → not suppressed
		{ dep: lodash, cve: { id: "CVE-GLOBAL" } },     // global rule → suppressed
	];
	applySuppressions(matches, rules);
	assert.equal(matches[0].suppressed, true);
	assert.equal(matches[1].suppressed, undefined);
	assert.equal(matches[2].suppressed, true);
});

// Regression: a VEX product_id with no purl in the product_tree must NOT become a
// global (coordRe:null) rule that suppresses the CVE for every dependency. (#4)
test("VEX with an unmappable product_id does not suppress unrelated deps", () => {
	const csaf = { product_tree: { full_product_names: [] }, vulnerabilities: [
		{ cve: "CVE-2021-44228", product_status: { known_not_affected: ["CSAFPID-1"] } },
	] };
	const rules = parseVex(csaf);
	assert.equal(rules.length, 0);
	const unrelated = makeDepRecord({ ecosystem: "maven", namespace: "org.unrelated", name: "thing", version: "1.0.0", manifestPath: "pom.xml" });
	const matches = [{ cve: { id: "CVE-2021-44228" }, dep: unrelated }];
	assert.equal(applySuppressions(matches, rules), 0);
});
