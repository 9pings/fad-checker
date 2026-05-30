const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { parsePackagesLockJson, parseCsproj, parsePackagesConfig, parseDirectoryPackagesProps } = require("../lib/codecs/nuget/parse");
const F = n => path.join(__dirname, "fixtures", n);

test("parsePackagesLockJson reads resolved versions + Direct/Transitive scope", async () => {
	const r = await parsePackagesLockJson(F("csharp-lock/packages.lock.json"));
	const m = Object.fromEntries(r.deps.map(d => [d.name, d]));
	assert.strictEqual(m["Newtonsoft.Json"].version, "13.0.1");
	assert.strictEqual(m["System.Buffers"].scope, "transitive");
});

test("parseDirectoryPackagesProps returns a name→version map (CPM)", async () => {
	const m = await parseDirectoryPackagesProps(F("csharp-csproj/Directory.Packages.props"));
	assert.strictEqual(m["managed"], "6.0.0");   // keyed lowercase
});

test("parseCsproj: pinned scanned, floating skipped, CPM resolved against props", async () => {
	const cpm = await parseDirectoryPackagesProps(F("csharp-csproj/Directory.Packages.props"));
	const r = await parseCsproj(F("csharp-csproj/app.csproj"), cpm);
	const m = Object.fromEntries(r.deps.map(d => [d.name, d.version]));
	assert.strictEqual(m["Newtonsoft.Json"], "13.0.1");
	assert.strictEqual(m["Managed"], "6.0.0");      // resolved via CPM
	assert.ok(!("Floating" in m));                   // "1.*" skipped
	assert.strictEqual(r.skipped, 1);
});

test("parsePackagesConfig reads legacy id/version", async () => {
	const r = await parsePackagesConfig(F("csharp-config/packages.config"));
	assert.strictEqual(r.deps.find(d => d.name === "EntityFramework").version, "6.4.4");
});

const { nugetRegistrationToFindings } = require("../lib/codecs/nuget/registry");
test("nugetRegistrationToFindings extracts latest stable + deprecation for version", () => {
	const reg = { items: [ { items: [
		{ catalogEntry: { version: "13.0.1", deprecation: { reasons: ["Legacy"], alternatePackage: { id: "NewPkg" } } } },
		{ catalogEntry: { version: "13.0.3" } },
		{ catalogEntry: { version: "14.0.0-preview" } },
	] } ] };
	const f = nugetRegistrationToFindings(reg, { version: "13.0.1" });
	assert.strictEqual(f.outdated.latest, "13.0.3");
	assert.deepStrictEqual(f.deprecated, { reason: "Legacy", replacement: "NewPkg" });
	const f2 = nugetRegistrationToFindings(reg, { version: "13.0.3" });
	assert.strictEqual(f2.deprecated, null);
	assert.strictEqual(f2.outdated, null);
});

const nuget = require("../lib/codecs/nuget.codec");
const { assertCodecShape } = require("../lib/codecs/codec.interface");
test("nuget codec: shape, detect, collect lockfile, case-insensitive key", async () => {
	assertCodecShape(nuget);
	assert.strictEqual(nuget.detect(F("csharp-lock")), true);
	const { deps } = await nuget.collect(F("csharp-lock"), {});
	const j = deps.get("nuget:newtonsoft.json");     // key lowercased
	assert.ok(j);
	assert.strictEqual(j.name, "Newtonsoft.Json");   // display keeps original case
	assert.strictEqual(nuget.osvPackageName(j), "Newtonsoft.Json");
});
test("nuget codec: csproj uses CPM + skips floating with warning", async () => {
	const { deps, warnings } = await nuget.collect(F("csharp-csproj"), {});
	assert.ok(deps.has("nuget:newtonsoft.json"));
	assert.ok(deps.has("nuget:managed"));            // resolved via Directory.Packages.props
	assert.ok(!deps.has("nuget:floating"));
	assert.ok(warnings.find(w => w.type === "no-lockfile"));
});
test("nuget codec: detects + collects .fsproj (F#), attr + child Version, skips floating", async () => {
	assert.strictEqual(nuget.detect(F("csharp-fsproj")), true);
	const { deps } = await nuget.collect(F("csharp-fsproj"), {});
	assert.strictEqual(deps.get("nuget:fsharp.core")?.version, "8.0.100");   // attribute Version
	assert.strictEqual(deps.get("nuget:serilog")?.version, "3.1.1");         // child <Version>
	assert.ok(!deps.has("nuget:floatingpkg"));                                // "2.*" skipped
});
test("nuget codec: detects + collects .vbproj (VB.NET)", async () => {
	assert.strictEqual(nuget.detect(F("csharp-vbproj")), true);
	const { deps } = await nuget.collect(F("csharp-vbproj"), {});
	assert.strictEqual(deps.get("nuget:dapper")?.version, "2.1.24");
});
