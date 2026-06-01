const test = require("node:test");
const assert = require("node:assert");
const { osvEcosystemFor, osvPkgName, severityFromOsv, vulnToMatch } = require("../lib/osv");

test("osvEcosystemFor maps codec ids to OSV ecosystem names", () => {
	assert.strictEqual(osvEcosystemFor({ ecosystem: "maven" }), "Maven");
	assert.strictEqual(osvEcosystemFor({ ecosystem: "npm" }), "npm");
	assert.strictEqual(osvEcosystemFor({ ecosystem: "yarn" }), "npm");
	assert.strictEqual(osvEcosystemFor({ ecosystem: "nuget" }), "NuGet");
	assert.strictEqual(osvEcosystemFor({ ecosystem: "composer" }), "Packagist");
	assert.strictEqual(osvEcosystemFor({ ecosystem: "pypi" }), "PyPI");
});

test("osvPkgName delegates to codec for maven (g:a) and npm (bare name)", () => {
	assert.strictEqual(osvPkgName({ ecosystem: "maven", namespace: "org.apache", name: "log4j", groupId: "org.apache", artifactId: "log4j" }), "org.apache:log4j");
	assert.strictEqual(osvPkgName({ ecosystem: "npm", namespace: "", name: "lodash", artifactId: "lodash" }), "lodash");
});

const { queryOsvForDeps, OSV_CACHE_DIR } = require("../lib/osv");
const { makeDepRecord } = require("../lib/dep-record");
const fs = require("fs");

// Regression: queryOsvForDeps must send the codec's package name + ecosystem to
// OSV for EVERY ecosystem. A prior bug cherry-picked only groupId/artifactId when
// rebuilding per-version deps, so composer/pypi/nuget queried name=undefined.
test("queryOsvForDeps sends correct package name + ecosystem per codec (mock fetcher)", async () => {
	// Purge sentinel cache entries so the mock fetcher is always exercised
	// (queryBatch writes a per-dep cache after a live batch — would self-poison).
	try {
		for (const f of fs.readdirSync(OSV_CACHE_DIR)) {
			if (f.includes("9.9.9-fadtest")) fs.unlinkSync(require("path").join(OSV_CACHE_DIR, f));
		}
	} catch { /* dir may not exist yet */ }
	const captured = [];
	const fetcher = async (url, opts) => {
		if (url.includes("/querybatch")) {
			const body = JSON.parse(opts.body);
			captured.push(...body.queries);
			return { ok: true, json: async () => ({ results: body.queries.map(() => ({ vulns: [] })) }) };
		}
		return { ok: true, json: async () => ({}) };
	};
	const deps = new Map();
	for (const [eco, ns, name, ver, expName, expEco] of [
		["pypi", "", "django", "9.9.9-fadtest", "django", "PyPI"],
		["composer", "guzzlehttp", "guzzle", "9.9.9-fadtest", "guzzlehttp/guzzle", "Packagist"],
		["nuget", "", "Newtonsoft.Json", "9.9.9-fadtest", "Newtonsoft.Json", "NuGet"],
		["maven", "org.apache", "log4j-core", "9.9.9-fadtest", "org.apache:log4j-core", "Maven"],
		["npm", "", "lodash", "9.9.9-fadtest", "lodash", "npm"],
	]) {
		const r = makeDepRecord({ ecosystem: eco, namespace: ns, name, version: ver, manifestPath: "x" });
		r._exp = { name: expName, eco: expEco };
		deps.set(r.coordKey, r);
	}
	await queryOsvForDeps(deps, { fetcher });
	for (const d of deps.values()) {
		const q = captured.find(c => c.package.name === d._exp.name);
		assert.ok(q, `expected an OSV query with package.name="${d._exp.name}" (${d.ecosystem})`);
		assert.strictEqual(q.package.ecosystem, d._exp.eco, `ecosystem for ${d._exp.name}`);
		assert.strictEqual(q.version, d.version);
	}
});

// Regression: OSV stores the CVSS *vector* in severity[].score — we must compute
// the base score, not extract the version "3.1" as the score. (audit fix #A)
test("severityFromOsv computes the v3 base score from the vector, not the version", () => {
	const mk = v => ({ severity: [{ type: "CVSS_V3", score: v }] });
	assert.deepEqual(severityFromOsv(mk("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")), { severity: "CRITICAL", score: 9.8 });
	// reflected-XSS reference vector → 6.1
	assert.deepEqual(severityFromOsv(mk("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")), { severity: "MEDIUM", score: 6.1 });
	// a CVSS v4 vector can't be scored here → null (lets NVD fill it in), never 4.0
	assert.equal(severityFromOsv(mk("CVSS:4.0/AV:N/AC:L")).score, null);
	// a bare numeric score is taken as-is
	assert.equal(severityFromOsv(mk("7.5")).score, 7.5);
});

test("vulnToMatch carries the CVSS vector + version from OSV severity", () => {
	const m = vulnToMatch({ ecosystem: "npm", name: "x", version: "1.0.0", coordKey: "npm:x" },
		{ id: "GHSA-aaaa", severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] });
	assert.equal(m.cve.score, 9.8);
	assert.equal(m.cve.cvssVersion, "CVSS:3.1");
	assert.ok(m.cve.cvssVector.startsWith("CVSS:3.1/"));
});
