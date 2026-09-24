const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
	cweByCriticality,
	vulnSubdepsByDep,
	unattributedSubdeps,
	directVsTransitive,
	fixPriority,
	renderCharts,
	mostVulnerableComponents,
} = require("../lib/charts");

const m = (g, a, scope, sev, cwes, extra = {}) => ({
	dep: { groupId: g, artifactId: a, version: "1.0", scope, ecosystem: "maven", ecosystemType: "maven", namespace: g, name: a, coordKey: `${g}:${a}`, ...(extra.dep || {}) },
	cve: { id: extra.id || `CVE-${a}`, severity: sev, score: extra.score, cwes, kev: extra.kev, epssPercentile: extra.epss },
});

test("cweByCriticality: DIRECT vulns only, stacked by severity, multi-CWE counted under each CWE", () => {
	const rows = cweByCriticality([
		m("a", "b", "compile", "CRITICAL", ["CWE-79", "CWE-89"]),
		m("c", "d", "compile", "HIGH", ["CWE-79"]),
		m("e", "f", "transitive", "CRITICAL", ["CWE-79"]),   // transitive → excluded
	]);
	const byKey = Object.fromEntries(rows.map(r => [r.key, r]));
	assert.ok(byKey["CWE-79"], "CWE-79 present");
	// CWE-79: one critical (a:b) + one high (c:d) — the transitive e:f is NOT counted
	assert.equal(byKey["CWE-79"].segments.critical, 1);
	assert.equal(byKey["CWE-79"].segments.high, 1);
	assert.equal(byKey["CWE-79"].total, 2);
	// CWE-89 only on the critical a:b
	assert.equal(byKey["CWE-89"].segments.critical, 1);
	assert.equal(byKey["CWE-89"].total, 1);
	// sorted by total desc → CWE-79 first
	assert.equal(rows[0].key, "CWE-79");
});

test("vulnSubdepsByDep: counts sub-dep CVEs per root dep, each CVE in its own severity bucket", () => {
	const t = (root, sub, sev) => m("x", sub, "transitive", sev, [], { dep: { via: [root] } });
	const rows = vulnSubdepsByDep([
		t("org.spring:boot", "tomcat", "CRITICAL"),
		t("org.spring:boot", "tomcat", "LOW"),       // same sub-dep, 2nd CVE → a SEPARATE count
		t("org.spring:boot", "jackson", "HIGH"),
		t("com.acme:app", "guava", "MEDIUM"),
		m("d", "direct", "compile", "CRITICAL", []),  // direct → not a sub-dep, excluded
	]);
	const byKey = Object.fromEntries(rows.map(r => [r.key, r]));
	// boot has 3 sub-dep CVEs: tomcat(critical) + tomcat(low) + jackson(high)
	assert.equal(byKey["org.spring:boot"].total, 3);
	assert.equal(byKey["org.spring:boot"].segments.critical, 1);
	assert.equal(byKey["org.spring:boot"].segments.high, 1);
	assert.equal(byKey["org.spring:boot"].segments.low, 1, "each CVE counted in its own severity");
	assert.equal(byKey["com.acme:app"].total, 1);
});

test("vulnSubdepsByDep excludes transitives with no resolved root; they are counted separately", () => {
	const withRoot = m("x", "tomcat", "transitive", "HIGH", [], { dep: { via: ["org.spring:boot"] } });
	const noRoot1 = m("y", "lodash", "transitive", "HIGH", [], { dep: { via: [] } });        // npm-style: no root chain
	const noRoot2 = m("y", "minimist", "transitive", "CRITICAL", []);                          // no via at all
	const rows = vulnSubdepsByDep([withRoot, noRoot1, noRoot2]);
	assert.equal(rows.length, 1, "only the attributable root becomes a bar");
	assert.equal(rows[0].key, "org.spring:boot");
	assert.ok(!rows.some(r => /unknown/i.test(r.label)), "no bogus 'unknown root' bar");
	assert.equal(unattributedSubdeps([withRoot, noRoot1, noRoot2]), 2, "the two rootless transitives are counted");
});

test("vulnSubdepsByDep labels are the readable artifact/package name (not truncated to gibberish)", () => {
	const t = m("g", "x", "transitive", "HIGH", [], { dep: { via: ["org.springframework.boot:spring-boot-starter-web"] } });
	const rows = vulnSubdepsByDep([t], { formatDep: d => d.artifactId });
	assert.equal(rows[0].label, "spring-boot-starter-web", "shows the readable artifact name");
});

test("directVsTransitive: two slices (direct / transitive), each carrying its per-severity summary", () => {
	const rows = directVsTransitive([
		m("a", "b", "compile", "CRITICAL", []),
		m("a", "c", "compile", "HIGH", []),
		m("x", "t1", "transitive", "CRITICAL", []),
		m("x", "t2", "transitive", "HIGH", []),
		m("x", "t3", "transitive", "MEDIUM", []),
	]);
	const byKey = Object.fromEntries(rows.map(r => [r.key, r]));
	assert.equal(byKey["direct"].value, 2);
	assert.equal(byKey["transitive"].value, 3);
	assert.match(byKey["direct"].name, /1C/);       // severity breakdown in the legend label
	assert.match(byKey["direct"].name, /1H/);
	assert.match(byKey["transitive"].name, /1M/);
	assert.ok(byKey["direct"].color && byKey["transitive"].color && byKey["direct"].color !== byKey["transitive"].color, "direct and transitive use distinct colours");
});

test("directVsTransitive: drops a side with no findings", () => {
	const rows = directVsTransitive([m("a", "b", "compile", "HIGH", [])]);
	assert.equal(rows.length, 1);
	assert.equal(rows[0].key, "direct");
});

test("fixPriority: bands from composite priority — KEV lands in the exploited band", () => {
	const rows = fixPriority([
		m("a", "b", "compile", "CRITICAL", [], { kev: true }),     // → exploited
		m("c", "d", "compile", "CRITICAL", [], { score: 9.8 }),    // → critical
		m("e", "f", "compile", "MEDIUM", [], { score: 5 }),        // → medium
	]);
	const byKey = Object.fromEntries(rows.map(r => [r.key, r.value]));
	assert.equal(byKey["exploited"], 1);
	assert.equal(byKey["critical"], 1);
	assert.equal(byKey["medium"], 1);
});

test("fixPriority includes unknown signal in the chart total", () => {
	const rows = fixPriority([m("a", "unknown", "compile", "UNKNOWN", [], { score: null })]);
	assert.deepEqual(rows.map(r => [r.key, r.value]), [["unknown", 1]]);
});

test("renderCharts: emits 4 SVG charts in one row, each with a copy button", () => {
	const html = renderCharts({
		prodMatches: [
			m("a", "b", "compile", "CRITICAL", ["CWE-79"], { kev: true }),
			m("c", "d", "compile", "HIGH", ["CWE-502"]),
			m("x", "tomcat", "transitive", "HIGH", ["CWE-89"], { dep: { via: ["org.spring:boot"] } }),
		],
		embeddedMatches: [],
		prodTotal: 2, devTotal: 0, vendoredJsTotal: 0, embeddedTotal: 0,
		eolTotal: 1, obsoleteTotal: 0, outdatedTotal: 0, nativeBinaryCount: 0,
	}, { formatDep: d => `${d.groupId}:${d.artifactId}` });
	assert.equal((html.match(/<svg\b/g) || []).length, 4, "four SVG charts");
	assert.equal((html.match(/<svg class="chart-svg"[^>]*height="250"/g) || []).length, 4,
		"each exportable SVG keeps a 250px canvas");
	assert.ok((html.match(/chart-copy/g) || []).length >= 4, "a copy button per chart");
	assert.match(html, /class="charts-row"/, "single-row container");
	assert.ok(html.includes("CWE-79"), "CWE chart legend rendered");
	assert.ok(html.includes("Cross-site Scripting"), "CWE legend shows the human title, not just the id");
	assert.match(html, /<path[^>]*\bd="M/, "pie/donut slices drawn as SVG paths");
});

test("renderCharts: returns empty string when there is nothing to chart", () => {
	const html = renderCharts({ prodMatches: [], embeddedMatches: [], prodTotal: 0, devTotal: 0, vendoredJsTotal: 0, embeddedTotal: 0, eolTotal: 0, obsoleteTotal: 0, outdatedTotal: 0, nativeBinaryCount: 0 }, {});
	assert.equal(html, "");
});

/* ---------------- Most vulnerable components ---------------- */


const names = new Map([
	["/p/api/pom.xml", "acme-api"],
	["/p/web/pom.xml", "acme-web"],
	["/p/legacy/pom.xml", "legacy/pom.xml"],   // no declared name → path, as resolveModuleNames does
]);
const hit = (sev, paths) => ({ cve: { severity: sev }, dep: { manifestPaths: paths, coordKey: "g:a" } });

test("components are ranked by critical+high only, and only the project's own modules appear", () => {
	const rows = mostVulnerableComponents([
		hit("CRITICAL", ["/p/api/pom.xml"]),
		hit("HIGH", ["/p/api/pom.xml"]),
		hit("HIGH", ["/p/web/pom.xml"]),
		hit("MEDIUM", ["/p/web/pom.xml"]),   // medium is not "major" — excluded
		hit("LOW", ["/p/web/pom.xml"]),
	], names);
	assert.deepEqual(rows.map(r => [r.label, r.value]), [["acme-api", 2], ["acme-web", 1]]);
	assert.equal(rows[0].color, "#7c0008", "worst severity in that module drives the colour (critical)");
	assert.equal(rows[1].color, "#c92a2a", "high");
});

test("a module with no declared name is labelled by its relative path", () => {
	const rows = mostVulnerableComponents([hit("CRITICAL", ["/p/legacy/pom.xml"])], names);
	assert.deepEqual(rows.map(r => r.label), ["legacy/pom.xml"]);
});

test("a finding declared in several modules counts in each — they are all affected", () => {
	const rows = mostVulnerableComponents([hit("CRITICAL", ["/p/api/pom.xml", "/p/web/pom.xml"])], names);
	assert.deepEqual(rows.map(r => [r.label, r.value]).sort(), [["acme-api", 1], ["acme-web", 1]]);
});

test("a path with no entry in the name map still charts, under the path itself", () => {
	const rows = mostVulnerableComponents([hit("CRITICAL", ["/p/unknown/pom.xml"])], new Map());
	assert.deepEqual(rows.map(r => r.label), ["/p/unknown/pom.xml"]);
});

test("findings with no manifest path at all are skipped rather than charted as a phantom module", () => {
	assert.deepEqual(mostVulnerableComponents([hit("CRITICAL", [])], names), []);
	assert.deepEqual(mostVulnerableComponents([{ cve: { severity: "CRITICAL" }, dep: {} }], names), []);
	assert.deepEqual(mostVulnerableComponents([], names), []);
	assert.deepEqual(mostVulnerableComponents(null, names), []);
});

test("no critical or high anywhere → no chart data (the card falls back to a note)", () => {
	assert.deepEqual(mostVulnerableComponents([hit("MEDIUM", ["/p/api/pom.xml"]), hit("LOW", ["/p/web/pom.xml"])], names), []);
});

test("the list is capped and the remainder folded into a single '+N more'", () => {
	const many = [];
	for (let i = 0; i < 12; i++) for (let k = 0; k <= i; k++) many.push(hit("HIGH", [`/p/m${i}/pom.xml`]));
	const rows = mostVulnerableComponents(many, new Map(), { topN: 7 });
	assert.equal(rows.length, 8);
	assert.equal(rows[7].label, "+5 more");
	assert.equal(rows[0].value, 12, "highest count first");
	const charted = rows.reduce((a, r) => a + r.value, 0);
	assert.equal(charted, many.length, "nothing is silently dropped");
});

test("ties break alphabetically so a re-scan renders the same chart", () => {
	const rows = mostVulnerableComponents([hit("HIGH", ["/p/web/pom.xml"]), hit("HIGH", ["/p/api/pom.xml"])], names);
	assert.deepEqual(rows.map(r => r.label), ["acme-api", "acme-web"]);
});

/* ---------------- which card is shown ---------------- */


test("several descriptors → the components chart replaces direct-vs-transitive", () => {
	const html = renderCharts({
		prodMatches: [hit("CRITICAL", ["/p/api/pom.xml"]), hit("HIGH", ["/p/web/pom.xml"])],
		moduleNames: names,
		descriptorCount: 3,
	}, { interactive: false });
	assert.match(html, /Most vulnerable components/);
	assert.doesNotMatch(html, /Direct vs transitive/);
	assert.match(html, /acme-api/);
});

test("a single descriptor keeps the existing direct-vs-transitive chart", () => {
	// Ranking one module against itself says nothing; the scope split still does.
	const html = renderCharts({
		prodMatches: [hit("CRITICAL", ["/p/api/pom.xml"])],
		moduleNames: names,
		descriptorCount: 1,
	}, { interactive: false });
	assert.match(html, /Direct vs transitive/);
	assert.doesNotMatch(html, /Most vulnerable components/);
});

test("several descriptors but no critical/high → the components card renders its empty note", () => {
	const html = renderCharts({
		prodMatches: [hit("MEDIUM", ["/p/api/pom.xml"])],
		moduleNames: names,
		descriptorCount: 4,
	}, { interactive: false });
	assert.match(html, /Most vulnerable components/);
	assert.match(html, /No critical or high/i);
});

test("application scans rank exposed instances, counting shared occurrences in each", () => {
	const { mostVulnerableApplications } = require("../lib/charts");
	const apps = [
		{ id: "wordpress:site-a", type: "wordpress", root: "site-a" },
		{ id: "drupal:site-b", type: "drupal", root: "site-b" },
	];
	// one shared finding (both instances), one site-a-only finding, one low (excluded)
	const shared = { ...m("v", "lib", "compile", "CRITICAL", []), findingId: "f1",
		applicationIds: ["wordpress:site-a", "drupal:site-b"], applicationRelation: "direct" };
	const only = { ...m("v", "lib2", "compile", "HIGH", []), findingId: "f2",
		applicationIds: ["wordpress:site-a"], applicationRelation: "indirect" };
	const low = { ...m("v", "lib3", "compile", "LOW", []), findingId: "f3",
		applicationIds: ["wordpress:site-a"] };
	const coverage = [
		{ applicationId: "wordpress:site-a", capability: "advisories", execution: "not-run" },
		{ applicationId: "drupal:site-b", capability: "advisories", execution: "completed" },
		{ applicationId: "drupal:site-b", capability: "inventory", execution: "partial" },
	];
	const chart = mostVulnerableApplications([shared, only, low], apps, coverage);
	const byLabel = Object.fromEntries(chart.rows.map(r => [r.label, r]));
	assert.equal(byLabel["wordpress · site-a"].value, 2);
	assert.equal(byLabel["drupal · site-b"].value, 1);
	// the slice total counts exposures; the distinct findings stay visible for the center
	assert.equal(chart.unique, 2);
	// coverage of the advisories capability is carried with the chart
	assert.equal(chart.incomplete, 1);
});

test("application scans render the instances chart, not the modules or scope chart", () => {
	const apps = [{ id: "wordpress:site-a", type: "wordpress", root: "site-a" }];
	const shared = { ...m("v", "lib", "compile", "CRITICAL", []), findingId: "f1",
		applicationIds: ["wordpress:site-a"], applicationRelation: "direct" };
	const html = renderCharts({ prodMatches: [shared], applications: apps,
		coverage: [{ applicationId: "wordpress:site-a", capability: "advisories", execution: "not-run" }] });
	assert.match(html, /chart-instances/);
	assert.match(html, /Most vulnerable instances/);
	assert.match(html, /wordpress · site-a/);
	// The donut legend shows per-instance exposure counts; the note explains overlap.
	assert.match(html, /a shared[\s\S]*?occurrence counts in each/);
	assert.match(html.slice(html.indexOf('id="chart-instances"'), html.indexOf('id="chart-priority"')), /<circle\s+cx=/);
	assert.match(html, /1 advisory check\(s\) incomplete/);
	assert.doesNotMatch(html, /chart-components/);
	assert.doesNotMatch(html, /chart-scope/);
	// no critical/high application finding → the empty card says so
	const empty = renderCharts({ prodMatches: [{ ...m("v", "lib", "compile", "LOW", []),
		applicationIds: ["wordpress:site-a"] }], applications: apps, coverage: [] });
	assert.match(empty, /No critical or high application CVE\./);
});

test("application scans chart the CWEs of DIRECT application findings only", () => {
	const { cweByCriticality } = require("../lib/charts");
	const apps = [{ id: "wp", type: "wordpress", root: "wp" }];
	const coreDirect = { ...m("v", "lib", "compile", "CRITICAL", ["CWE-79"]),
		applicationIds: ["wp"], applicationRelation: "direct" };
	const libIndirect = { ...m("v", "lib2", "compile", "HIGH", ["CWE-89"]),
		applicationIds: ["wp"], applicationRelation: "indirect" };
	const nonApp = m("x", "y", "compile", "HIGH", ["CWE-22"]);
	const html = renderCharts({ prodMatches: [coreDirect, libIndirect, nonApp], applications: apps, coverage: [] });
	// the CWE chart carries the application-direct lane only: never the indirect
	// libraries (chart 2's lane) nor the non-application findings (a different axis)
	assert.match(html, /chart-cwe[\s\S]*?CWE-79/);
	assert.doesNotMatch(html, /chart-cwe[\s\S]*?CWE-89/);
	assert.doesNotMatch(html, /chart-cwe[\s\S]*?CWE-22/);
	assert.equal(cweByCriticality([coreDirect, libIndirect, nonApp]).length, 3, "non-app aggregator unchanged");
});

test("application scans group indirect CVEs by their introducing component", () => {
	const { vulnByApplicationOrigin } = require("../lib/charts");
	const apps = [{ id: "wp", type: "wordpress", root: "wp" }];
	const inventory = [
		{ id: "wp:core", kind: "core", name: "WordPress", applicationId: "wp" },
		{ id: "wp:plugin:acme", kind: "plugin", name: "Acme", applicationId: "wp" },
	];
	const indirect = owner => ({ ...m("v", "lib", "compile", "HIGH", []),
		applicationIds: ["wp"], applicationRelation: "indirect",
		applicationExposures: [{ applicationId: "wp", ownerComponentIds: [owner], applicationRelation: "indirect", dependencyPaths: [] }] });
	const unknown = { ...m("v", "loose", "compile", "HIGH", []), applicationIds: ["wp"], applicationRelation: "unknown" };
	const chart = vulnByApplicationOrigin([indirect("wp:core"), indirect("wp:plugin:acme"), unknown], inventory);
	const byLabel = Object.fromEntries(chart.rows.map(r => [r.label, r]));
	assert.equal(byLabel["core WordPress"].total, 1);
	assert.equal(byLabel["plugin Acme"].total, 1);
	assert.equal(chart.unknown, 1, "unattributed indirect CVEs are counted, never invented an origin for");
	const html = renderCharts({ prodMatches: [indirect("wp:core"), indirect("wp:plugin:acme"), unknown],
		applications: apps, applicationInventory: inventory, coverage: [] });
	assert.match(html, /Indirect CVEs per direct dependency/);
	assert.match(html, /plugin Acme/);
	assert.match(html, /core WordPress/);
	assert.match(html, /1 indirect CVE\(s\) with no proven origin/);
});
