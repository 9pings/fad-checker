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
