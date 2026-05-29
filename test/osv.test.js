const test = require("node:test");
const assert = require("node:assert");
const { osvEcosystemFor, osvPkgName } = require("../lib/osv");

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
