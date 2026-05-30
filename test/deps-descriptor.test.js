const test = require("node:test");
const assert = require("node:assert");
const { serializeDeps, deserializeDeps, SCHEMA } = require("../lib/deps-descriptor");
const { makeDepRecord } = require("../lib/dep-record");

// Build a resolved map carrying sensitive environment fields.
function sampleMap() {
	const m = new Map();
	const npm = makeDepRecord({ ecosystem: "npm", namespace: "", name: "lodash", version: "4.17.21", manifestPath: "/home/secretuser/proj-x/package-lock.json", scope: "prod" });
	npm.resolved = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz";
	npm.integrity = "sha512-SECRETHASH";
	npm.from = "root>app>lodash";
	npm.lockType = "package-lock-v3";
	m.set(npm.coordKey, npm);

	const mvn = makeDepRecord({ ecosystem: "maven", namespace: "org.apache.commons", name: "commons-lang3", version: "3.12.0", manifestPath: "/home/secretuser/proj-x/pom.xml", scope: "compile" });
	mvn.versions = ["3.12.0", "3.13.0"];          // multi-version
	m.set(mvn.coordKey, mvn);

	const pypi = makeDepRecord({ ecosystem: "pypi", namespace: "", name: "requests", version: "2.31.0", manifestPath: "/x/requirements.txt", scope: "dev", isDev: true });
	m.set(pypi.coordKey, pypi);
	return m;
}

test("serializeDeps produces the fad-deps/1 schema with per-ecosystem summary", () => {
	const d = serializeDeps(sampleMap(), { generator: "fad-checker test", generatedAt: "2026-01-01T00:00:00Z" });
	assert.strictEqual(d.schema, SCHEMA);
	assert.strictEqual(d.generatedAt, "2026-01-01T00:00:00Z");
	assert.strictEqual(d.summary.total, 3);
	assert.deepStrictEqual(d.summary.byEcosystem, { npm: 1, maven: 1, pypi: 1 });
});

test("serializeDeps strips ALL environment-identifying fields (anonymization guarantee)", () => {
	const json = JSON.stringify(serializeDeps(sampleMap(), {}));
	assert.ok(!/\/home/.test(json), "no filesystem paths");
	assert.ok(!/secretuser/.test(json), "no usernames");
	assert.ok(!/proj-x/.test(json), "no project dir names");
	assert.ok(!/https?:\/\//.test(json), "no URLs");
	assert.ok(!/integrity|sha512|SECRETHASH/.test(json), "no integrity hashes");
	assert.ok(!/manifestPath|pomPaths|lockType|"from"/.test(json), "no path/lock/parent fields");
	// kept fields ARE present
	const d = JSON.parse(json);
	const keys = Object.keys(d.deps[0]).sort();
	assert.deepStrictEqual(keys, ["ecosystem", "ecosystemType", "isDev", "name", "namespace", "scope", "version", "versions"]);
});

test("round-trip serialize → deserialize preserves coordinates, versions, scope", () => {
	const d = serializeDeps(sampleMap(), {});
	const { resolved } = deserializeDeps(d);
	assert.strictEqual(resolved.size, 3);
	const lod = resolved.get("npm:lodash");
	assert.strictEqual(lod.version, "4.17.21");
	assert.strictEqual(lod.scope, "prod");
	assert.strictEqual(lod.ecosystem, "npm");
	const req = resolved.get("pypi:requests");
	assert.strictEqual(req.isDev, true);
	assert.strictEqual(req.scope, "dev");
});

test("deserialize rebuilds maven groupId/artifactId + bare g:a coordKey, multi-version", () => {
	const { resolved } = deserializeDeps(serializeDeps(sampleMap(), {}));
	const mvn = resolved.get("org.apache.commons:commons-lang3");
	assert.ok(mvn, "maven dep keyed by bare g:a");
	assert.strictEqual(mvn.groupId, "org.apache.commons");
	assert.strictEqual(mvn.artifactId, "commons-lang3");
	assert.deepStrictEqual(mvn.versions, ["3.12.0", "3.13.0"]);
});

test("deserialize yields empty manifestPaths/pomPaths (paths never travelled)", () => {
	const { resolved } = deserializeDeps(serializeDeps(sampleMap(), {}));
	for (const dep of resolved.values()) {
		assert.deepStrictEqual(dep.manifestPaths, []);
		assert.deepStrictEqual(dep.pomPaths, []);
	}
});

test("deserialize derives activeIds / runMaven / runNpm", () => {
	const r = deserializeDeps(serializeDeps(sampleMap(), {}));
	assert.deepStrictEqual(r.activeIds.sort(), ["maven", "npm", "pypi"]);
	assert.strictEqual(r.runMaven, true);
	assert.strictEqual(r.runNpm, true);
});

test("runNpm is true when only a yarn ecosystemType is present", () => {
	const m = new Map();
	const y = makeDepRecord({ ecosystem: "npm", ecosystemType: "yarn", namespace: "", name: "chalk", version: "4.1.2", manifestPath: "/x/yarn.lock", scope: "prod" });
	m.set(y.coordKey, y);
	const r = deserializeDeps(serializeDeps(m, {}));
	assert.strictEqual(r.runNpm, true);
	assert.strictEqual(r.runMaven, false);
});

test("empty map → valid descriptor with zero deps; round-trips", () => {
	const d = serializeDeps(new Map(), {});
	assert.strictEqual(d.summary.total, 0);
	assert.deepStrictEqual(d.deps, []);
	const r = deserializeDeps(d);
	assert.strictEqual(r.resolved.size, 0);
	assert.deepStrictEqual(r.activeIds, []);
});

test("deserialize throws on schema mismatch", () => {
	assert.throws(() => deserializeDeps({ schema: "fad-deps/999", deps: [] }), /unsupported descriptor schema/);
	assert.throws(() => deserializeDeps(null), /invalid descriptor/);
});

test("serializeDeps output is stably ordered (reproducible for review/diff)", () => {
	const a = JSON.stringify(serializeDeps(sampleMap(), { generatedAt: "x" }).deps);
	const b = JSON.stringify(serializeDeps(sampleMap(), { generatedAt: "x" }).deps);
	assert.strictEqual(a, b);
});

test("nuget/composer coordinates round-trip (case-insensitive key)", () => {
	const m = new Map();
	const ng = makeDepRecord({ ecosystem: "nuget", namespace: "", name: "Newtonsoft.Json", version: "13.0.1", manifestPath: "/x/a.csproj", scope: "prod" });
	m.set(ng.coordKey, ng);
	const cp = makeDepRecord({ ecosystem: "composer", namespace: "symfony", name: "console", version: "6.0.0", manifestPath: "/x/composer.lock", scope: "prod" });
	m.set(cp.coordKey, cp);
	const { resolved } = deserializeDeps(serializeDeps(m, {}));
	assert.ok(resolved.get("nuget:newtonsoft.json"));
	assert.strictEqual(resolved.get("nuget:newtonsoft.json").name, "Newtonsoft.Json");   // display case kept
	assert.ok(resolved.get("composer:symfony/console"));
});
