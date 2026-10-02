/**
 * packages.lock.json dependency `type`s — what each one means for the scan.
 *
 * NuGet writes four types (NuGet.Client PackagesLockFileBuilder / PackagesLockFileFormat):
 *   Direct            — a <PackageReference> of this project; carries requested+resolved.
 *   Transitive        — pulled in by a package; carries resolved.
 *   CentralTransitive — Central Package Management (Directory.Packages.props) pins the
 *                       version of a TRANSITIVE dependency; carries requested+resolved,
 *                       but the project never references it — a direct does.
 *   Project           — a <ProjectReference> inside the same solution; NuGet sets no
 *                       ResolvedVersion, so no `resolved` key is ever written.
 */
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { parsePackagesLockJson } = require("../lib/codecs/nuget/parse");
const nuget = require("../lib/codecs/nuget.codec");

function tmpDir() { return fs.mkdtempSync(path.join(os.tmpdir(), "fad-nuget-types-")); }
function writeLock(dir, json) {
	fs.mkdirSync(dir, { recursive: true });
	const fp = path.join(dir, "packages.lock.json");
	fs.writeFileSync(fp, JSON.stringify(json, null, 2));
	return fp;
}

// Shape of a real `dotnet restore --use-lock-file` output on a CPM solution with
// RestoreEnableCentralPackageTransitivePinning + a project reference.
const CPM_LOCK = {
	version: 2,
	dependencies: {
		"net8.0": {
			"Serilog": { type: "Direct", requested: "[3.1.1, )", resolved: "3.1.1", contentHash: "x" },
			"System.Buffers": { type: "Transitive", resolved: "4.5.1", contentHash: "x" },
			"System.Text.Json": { type: "CentralTransitive", requested: "[8.0.4, )", resolved: "8.0.4", contentHash: "x" },
			"mycompany.core": { type: "Project", dependencies: { "Serilog": "[3.1.1, )" } },
		},
	},
};

test("CentralTransitive is recorded as a TRANSITIVE dependency, not a direct one", async () => {
	const dir = tmpDir();
	try {
		const r = await parsePackagesLockJson(writeLock(dir, CPM_LOCK));
		const m = Object.fromEntries(r.deps.map(d => [d.name, d]));
		assert.strictEqual(m["System.Text.Json"].version, "8.0.4");
		assert.strictEqual(m["System.Text.Json"].scope, "transitive");
		// The two pre-existing types are unchanged.
		assert.strictEqual(m["Serilog"].scope, "prod");
		assert.strictEqual(m["System.Buffers"].scope, "transitive");
		// NuGet has no dev notion in the lockfile: nothing becomes dev.
		assert.ok(r.deps.every(d => d.isDev === false));
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("a Project reference (first-party code) is never scanned as a NuGet package", async () => {
	const dir = tmpDir();
	try {
		const r = await parsePackagesLockJson(writeLock(dir, CPM_LOCK));
		assert.ok(!r.deps.some(d => d.name.toLowerCase() === "mycompany.core"));
		const { deps } = await nuget.collect(dir);
		assert.ok(!deps.has("nuget:mycompany.core"));
		assert.deepStrictEqual([...deps.keys()].sort(),
			["nuget:serilog", "nuget:system.buffers", "nuget:system.text.json"]);
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("a package that is Direct in ANY target framework is direct, whichever TFM comes first", async () => {
	const dir = tmpDir();
	try {
		const r = await parsePackagesLockJson(writeLock(dir, {
			version: 1,
			dependencies: {
				"net6.0": { "Polly": { type: "Transitive", resolved: "7.2.4" } },
				"net8.0": { "Polly": { type: "Direct", requested: "[7.2.4, )", resolved: "7.2.4" } },
			},
		}));
		const polly = r.deps.filter(d => d.name === "Polly");
		assert.strictEqual(polly.length, 1);
		assert.strictEqual(polly[0].scope, "prod");
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("codec merge: Direct in one project wins over CentralTransitive in another", async () => {
	const dir = tmpDir();
	try {
		writeLock(path.join(dir, "Lib"), { version: 2, dependencies: { "net8.0": {
			"System.Text.Json": { type: "CentralTransitive", requested: "[8.0.4, )", resolved: "8.0.4" } } } });
		writeLock(path.join(dir, "App"), { version: 2, dependencies: { "net8.0": {
			"System.Text.Json": { type: "Direct", requested: "[8.0.4, )", resolved: "8.0.4" } } } });
		const { deps } = await nuget.collect(dir);
		assert.strictEqual(deps.get("nuget:system.text.json").scope, "prod");
	} finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
