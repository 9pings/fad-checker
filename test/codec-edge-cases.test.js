/**
 * Advanced edge-case + robustness tests for the composer/pypi/nuget codecs.
 * Uses temp dirs so we can throw malformed inputs at the collectors.
 */
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const composer = require("../lib/codecs/composer.codec");
const pypi = require("../lib/codecs/pypi.codec");
const nuget = require("../lib/codecs/nuget.codec");
const { parseRequirementsTxt, pep503 } = require("../lib/codecs/pypi/parse");

function tmp(prefix, files) {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
	for (const [name, content] of Object.entries(files)) {
		const fp = path.join(dir, name);
		fs.mkdirSync(path.dirname(fp), { recursive: true });
		fs.writeFileSync(fp, content);
	}
	return dir;
}

/* ---------------- composer ---------------- */

test("composer: ignoreTest drops dev packages; deps2Exclude filters by name", async () => {
	const dir = tmp("comp-edge-", {
		"composer.lock": JSON.stringify({
			packages: [{ name: "guzzlehttp/guzzle", version: "7.4.5" }, { name: "acme/private", version: "1.0.0" }],
			"packages-dev": [{ name: "phpunit/phpunit", version: "10.0.0" }],
		}),
	});
	const noDev = await composer.collect(dir, { ignoreTest: true });
	assert.ok(!noDev.deps.has("composer:phpunit/phpunit"), "dev dep dropped with ignoreTest");
	assert.ok(noDev.deps.has("composer:guzzlehttp/guzzle"));
	const excl = await composer.collect(dir, { deps2Exclude: /^acme\// });
	assert.ok(!excl.deps.has("composer:acme/private"), "excluded by regex");
});

test("composer: malformed composer.lock does not throw, emits parse-error warning", async () => {
	const dir = tmp("comp-bad-", { "composer.lock": "{ not valid json ]" });
	const { deps, warnings } = await composer.collect(dir, {});
	assert.strictEqual(deps.size, 0);
	assert.ok(warnings.find(w => w.type === "parse-error"));
});

/* ---------------- pypi ---------------- */

test("pypi: requirements.txt handles extras, env markers, -r/-e/comments", () => {
	const dir = tmp("py-req-", {
		"requirements.txt": [
			"# header",
			"requests[security]==2.31.0",          // extras → still pinned
			'django==4.2 ; python_version >= "3.8"', // env marker dropped
			"flask>=2.0",                            // range → skip
			"-r other.txt",                          // include → skip
			"-e .",                                  // editable → skip
			"",
		].join("\n"),
	});
	const r = parseRequirementsTxt(path.join(dir, "requirements.txt"));
	const names = r.deps.map(d => d.name).sort();
	assert.deepStrictEqual(names, ["django", "requests"]);
	assert.strictEqual(r.deps.find(d => d.name === "requests").version, "2.31.0");
	assert.strictEqual(r.skipped, 1);   // only flask>=2.0 counts as a skipped requirement spec
});

test("pypi: pep503 collapses mixed separators and casing", () => {
	assert.strictEqual(pep503("Jinja2"), "jinja2");
	assert.strictEqual(pep503("ruamel.yaml"), "ruamel-yaml");
	assert.strictEqual(pep503("backports.zoneinfo"), "backports-zoneinfo");
});

test("pypi: lockfile wins over requirements.txt in the same directory", async () => {
	const dir = tmp("py-prec-", {
		"poetry.lock": '[[package]]\nname = "requests"\nversion = "2.31.0"\n',
		"requirements.txt": "requests==1.0.0\n",
	});
	const { deps } = await pypi.collect(dir, {});
	assert.strictEqual(deps.get("pypi:requests").version, "2.31.0", "poetry.lock should win over requirements.txt");
});

test("pypi: malformed poetry.lock does not throw", async () => {
	const dir = tmp("py-bad-", { "poetry.lock": "this is = not [ valid toml" });
	const { deps, warnings } = await pypi.collect(dir, {});
	assert.strictEqual(deps.size, 0);
	assert.ok(warnings.find(w => w.type === "parse-error"));
});

/* ---------------- nuget ---------------- */

test("nuget: packages.lock.json dedups the same id across target frameworks", async () => {
	const dir = tmp("nuget-multi-tfm-", {
		"packages.lock.json": JSON.stringify({
			version: 1,
			dependencies: {
				"net6.0": { "Newtonsoft.Json": { type: "Direct", resolved: "13.0.1" } },
				"net8.0": { "Newtonsoft.Json": { type: "Direct", resolved: "13.0.1" } },
			},
		}),
	});
	const { deps } = await nuget.collect(dir, {});
	assert.strictEqual(deps.size, 1, "same id+version across TFMs collapses to one entry");
	assert.ok(deps.has("nuget:newtonsoft.json"));
});

test("nuget: Version as a child element is read", async () => {
	const dir = tmp("nuget-child-", {
		"app.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Serilog"><Version>2.12.0</Version></PackageReference></ItemGroup></Project>`,
	});
	const { deps } = await nuget.collect(dir, {});
	assert.strictEqual(deps.get("nuget:serilog").version, "2.12.0");
});

test("nuget: packages.config collected via codec", async () => {
	const dir = tmp("nuget-cfg-", {
		"packages.config": `<?xml version="1.0"?><packages><package id="EntityFramework" version="6.4.4" /></packages>`,
	});
	const { deps } = await nuget.collect(dir, {});
	assert.ok(deps.has("nuget:entityframework"));
	assert.strictEqual(deps.get("nuget:entityframework").name, "EntityFramework");
});

test("nuget: malformed packages.lock.json does not throw", async () => {
	const dir = tmp("nuget-bad-", { "packages.lock.json": "{ broken" });
	const { deps, warnings } = await nuget.collect(dir, {});
	assert.strictEqual(deps.size, 0);
	assert.ok(warnings.find(w => w.type === "parse-error"));
});
