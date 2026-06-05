const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
	cweByCriticality,
	vulnSubdepsByDep,
	unattributedSubdeps,
	directVsTransitive,
	fixPriority,
	renderCharts,
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
