const test = require("node:test");
const assert = require("node:assert");
const { makeDepRecord, coordKeyFor } = require("../lib/dep-record");

test("maven depRecord builds bare g:a coordKey and keeps groupId/artifactId aliases", () => {
	const d = makeDepRecord({ ecosystem: "maven", namespace: "org.apache", name: "log4j", version: "2.14.0", manifestPath: "/p/pom.xml", scope: "compile" });
	assert.strictEqual(d.coordKey, "org.apache:log4j");   // clé Maven brute (pas de préfixe)
	assert.strictEqual(d.groupId, "org.apache");   // alias rétro-compat
	assert.strictEqual(d.artifactId, "log4j");      // alias rétro-compat
	assert.deepStrictEqual(d.versions, ["2.14.0"]);
	assert.strictEqual(d.isDev, false);
});

test("npm depRecord has empty namespace and npm-prefixed coordKey", () => {
	const d = makeDepRecord({ ecosystem: "npm", namespace: "", name: "lodash", version: "4.17.20", manifestPath: "/p/package-lock.json", scope: "prod" });
	assert.strictEqual(d.coordKey, "npm:lodash");
	assert.strictEqual(d.groupId, "");
	assert.strictEqual(d.artifactId, "lodash");
});

test("coordKeyFor composes ecosystem + namespace + name", () => {
	assert.strictEqual(coordKeyFor("composer", "guzzlehttp", "guzzle"), "composer:guzzlehttp/guzzle");
	assert.strictEqual(coordKeyFor("pypi", "", "requests"), "pypi:requests");
	assert.strictEqual(coordKeyFor("nuget", "", "Newtonsoft.Json"), "nuget:newtonsoft.json");
});

test("pomPaths shares the manifestPaths array reference (push stays in sync)", () => {
	const d = makeDepRecord({ ecosystem: "maven", namespace: "g", name: "a", version: "1.0", manifestPath: "/p/pom.xml" });
	d.manifestPaths.push("/q/pom.xml");
	assert.deepStrictEqual(d.pomPaths, ["/p/pom.xml", "/q/pom.xml"]);
});
