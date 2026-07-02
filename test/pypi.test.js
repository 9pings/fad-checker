const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { pep503, splitPep508, parsePoetryLock, parsePipfileLock, parseUvLock, parseRequirementsTxt, parsePyprojectToml } = require("../lib/codecs/pypi/parse");

const F = n => path.join(__dirname, "fixtures", n);

test("pep503 normalizes names (lowercase, collapse separators to -)", () => {
	assert.strictEqual(pep503("Flask-SQLAlchemy"), "flask-sqlalchemy");
	assert.strictEqual(pep503("zope.interface"), "zope-interface");
	assert.strictEqual(pep503("My__Pkg"), "my-pkg");
});

test("parsePoetryLock returns PEP503 names + versions", () => {
	const r = parsePoetryLock(F("python-poetry/poetry.lock"));
	const m = Object.fromEntries(r.deps.map(d => [d.name, d.version]));
	assert.strictEqual(m["requests"], "2.31.0");
	assert.strictEqual(m["flask-sqlalchemy"], "3.0.5");   // normalized
});

test("parsePipfileLock splits default/develop, strips ==", () => {
	const r = parsePipfileLock(F("python-pipenv/Pipfile.lock"));
	const m = Object.fromEntries(r.deps.map(d => [d.name, d]));
	assert.strictEqual(m["django"].version, "4.2.0");
	assert.strictEqual(m["django"].scope, "prod");
	assert.strictEqual(m["pytest"].scope, "dev");
});

test("parseUvLock reads [[package]]", () => {
	const r = parseUvLock(F("python-uv/uv.lock"));
	assert.strictEqual(r.deps.find(d => d.name === "numpy").version, "1.26.0");
});

test("parseRequirementsTxt keeps == pins, skips ranges/flags/comments", () => {
	const r = parseRequirementsTxt(F("python-reqs/requirements.txt"));
	const names = r.deps.map(d => d.name).sort();
	assert.deepStrictEqual(names, ["fastapi", "urllib3"]);
	assert.strictEqual(r.skipped, 1);   // flask>=2.0
});

/* ---- pyproject.toml fallback (PEP 621 + poetry) ---- */
test("splitPep508 extracts name, drops extras + env markers", () => {
	assert.deepStrictEqual(splitPep508("django[bcrypt]==4.2.1 ; python_version>='3.10'"), { name: "django", spec: "==4.2.1" });
	assert.deepStrictEqual(splitPep508("requests"), { name: "requests", spec: "" });
});

test("parsePyprojectToml (PEP 621): == pins scanned, ranges skipped, groups classified", () => {
	const r = parsePyprojectToml(F("python-pyproject/pyproject.toml"));
	const m = Object.fromEntries(r.deps.map(d => [d.name, d]));
	assert.strictEqual(m["requests"].version, "2.31.0");
	assert.strictEqual(m["zope-interface"].version, "6.0");          // PEP 503 normalized
	assert.strictEqual(m["django"].version, "4.2.1");               // extras + marker stripped
	assert.strictEqual(m["pytest"].scope, "dev");                  // optional-deps "dev" group
	assert.strictEqual(m["sphinx"].scope, "dev");                  // "docs" group → dev
	assert.strictEqual(m["numpy"].scope, "prod");                  // "extra" group → prod
	assert.ok(!("flask" in m) && !("black" in m));                 // ranges skipped
	assert.strictEqual(r.skipped, 2);
});

test("parsePyprojectToml (poetry): bare version == exact, caret skipped, python ignored", () => {
	const r = parsePyprojectToml(F("python-poetry-src/pyproject.toml"));
	const m = Object.fromEntries(r.deps.map(d => [d.name, d]));
	assert.strictEqual(m["requests"].version, "2.28.1");           // bare "2.28.1" == exact
	assert.strictEqual(m["django"].version, "4.1.0");             // { version = "==4.1.0" }
	assert.strictEqual(m["pytest"].scope, "dev");                 // [tool.poetry.group.dev]
	assert.strictEqual(m["black"].scope, "dev");                  // legacy dev-dependencies
	assert.ok(!("python" in m) && !("urllib3" in m));            // python ignored; caret skipped
	assert.strictEqual(r.skipped, 1);                            // only urllib3 (python not counted)
});

/* ---- requirements.txt recursive -r/-c includes ---- */
test("parseRequirementsTxt follows -r includes recursively (incl. nested)", () => {
	const r = parseRequirementsTxt(F("python-reqs-includes/requirements.txt"));
	const m = Object.fromEntries(r.deps.map(d => [d.name, d.version]));
	assert.strictEqual(m["urllib3"], "2.0.4");        // from base.txt
	assert.strictEqual(m["certifi"], "2023.7.22");    // from base.txt -> more.txt (nested)
	assert.strictEqual(m["django"], "4.2.1");         // top-level pin
});

test("parseRequirementsTxt: -c constraint pins a range; constraint-only pkgs not added", () => {
	const r = parseRequirementsTxt(F("python-reqs-includes/requirements.txt"));
	const m = Object.fromEntries(r.deps.map(d => [d.name, d.version]));
	assert.strictEqual(m["requests"], "2.31.0");      // requests>=2.0 pinned by constraints.txt
	assert.ok(!("numpy" in m));                        // numpy is only in constraints → NOT a dep
	assert.ok(!("flask" in m));                        // range with no constraint → skipped
	assert.strictEqual(r.skipped, 1);                 // flask only
});

test("parseRequirementsTxt: missing -r include is reported, other pins still scanned", () => {
	const r = parseRequirementsTxt(F("python-reqs-broken/requirements.txt"));
	assert.strictEqual(r.deps.find(d => d.name === "django")?.version, "4.2.1");
	assert.strictEqual(r.missing.length, 1);
	assert.match(r.missing[0], /nonexistent\.txt$/);
});

const { pypiToFindings } = require("../lib/codecs/pypi/registry");
test("pypiToFindings extracts latest, yanked-for-version, inactive classifier", () => {
	const data = {
		info: { version: "2.1.0", classifiers: ["Development Status :: 7 - Inactive"] },
		releases: { "2.0.4": [{ yanked: true, yanked_reason: "security" }], "2.1.0": [{ yanked: false }] },
	};
	const f = pypiToFindings(data, { version: "2.0.4" });
	assert.strictEqual(f.outdated.latest, "2.1.0");
	assert.strictEqual(f.yanked.reason, "security");
	assert.strictEqual(f.inactive, true);
	const f2 = pypiToFindings(data, { version: "2.1.0" });
	assert.strictEqual(f2.yanked, null);
	assert.strictEqual(f2.outdated, null);
});

const pypi = require("../lib/codecs/pypi.codec");
const { assertCodecShape } = require("../lib/codecs/codec.interface");
test("pypi codec: shape, detect, collect, coordKey pypi:<name>", async () => {
	assertCodecShape(pypi);
	assert.strictEqual(pypi.detect(F("python-poetry")), true);
	const { deps } = await pypi.collect(F("python-poetry"), {});
	const r = deps.get("pypi:requests");
	assert.ok(r);
	assert.strictEqual(r.ecosystem, "pypi");
	assert.strictEqual(pypi.osvPackageName(r), "requests");
});
test("pypi collect: requirements.txt fallback warns + scans pins only", async () => {
	const { deps, warnings } = await pypi.collect(F("python-reqs"), {});
	assert.ok(deps.has("pypi:fastapi"));
	assert.ok(!deps.has("pypi:flask"));
	assert.ok(warnings.find(w => w.type === "no-lockfile"));
});
test("pypi collect reports EVERY parsed descriptor, incl. range-only files that contribute nothing", async () => {
	const path = require("path");
	const { parsedManifests } = await pypi.collect(F("python-reqs-pinned"), {});
	const names = (parsedManifests || []).map(p => path.basename(p));
	// requirements.txt here is ranges-only → 0 scannable deps, but must still be listed as parsed
	assert.ok(names.includes("requirements.txt"), "range-only requirements.txt is still reported as parsed");
	assert.ok(names.includes("requirements-pinned.txt"), "the pinned file is reported too");
});

test("pypi collect: scans the whole requirements-*.txt family (pip-compile pinned file)", async () => {
	// securesystemslib shape: requirements.txt = ranges only, requirements-pinned.txt = the real pins.
	const { deps } = await pypi.collect(F("python-reqs-pinned"), {});
	assert.equal(deps.get("pypi:cryptography")?.version, "46.0.5"); // from requirements-pinned.txt
	assert.equal(deps.get("pypi:asn1crypto")?.version, "1.5.1");
	assert.equal(deps.get("pypi:cffi")?.version, "2.0.0");
	assert.equal(deps.get("pypi:cryptography")?.isDev, false);      // prod (not a -test/-dev file)
	assert.equal(deps.get("pypi:coverage")?.isDev, true);           // requirements-test.txt → dev
});
test("pypi codec: detects + collects pyproject.toml (no lockfile)", async () => {
	assert.strictEqual(pypi.detect(F("python-pyproject")), true);
	const { deps, warnings } = await pypi.collect(F("python-pyproject"), {});
	assert.ok(deps.has("pypi:requests"));
	assert.ok(deps.has("pypi:django"));
	assert.ok(!deps.has("pypi:flask"));                                   // range skipped
	const w = warnings.find(x => x.type === "no-lockfile");
	assert.ok(w && /pyproject\.toml/.test(w.message));
});
test("pypi codec: --ignore-test drops dev groups from pyproject", async () => {
	const { deps } = await pypi.collect(F("python-pyproject"), { ignoreTest: true });
	assert.ok(deps.has("pypi:requests"));
	assert.ok(!deps.has("pypi:pytest"));                                  // dev optional group
});
test("pypi codec: poetry pyproject still detected when lockfile present (lock wins)", async () => {
	// python-poetry has poetry.lock; the pyproject change must not break lock precedence.
	const { deps, warnings } = await pypi.collect(F("python-poetry"), {});
	assert.ok(deps.has("pypi:requests"));
	assert.ok(!warnings.find(w => w.type === "no-lockfile"));             // lockfile is authoritative
});

// Regression: classic poetry.lock (≤1.4) marks dev deps via `category = "dev"`,
// not `groups` — those were wrongly classified prod. (audit fix #F)
test("parsePoetryLock honours classic category=dev", () => {
	const fs = require("fs"), os = require("os");
	const f = path.join(os.tmpdir(), `fad-poetry-${process.pid}.lock`);
	fs.writeFileSync(f, '[[package]]\nname="pytest"\nversion="7.0.0"\ncategory="dev"\n\n[[package]]\nname="flask"\nversion="2.0.0"\ncategory="main"\n');
	const deps = parsePoetryLock(f).deps;
	const by = Object.fromEntries(deps.map(d => [d.name, d]));
	assert.equal(by.pytest.isDev, true);
	assert.equal(by.flask.isDev, false);
	fs.rmSync(f, { force: true });
});

/* ---- pip-compile --generate-hashes output (backslash continuations) ---- */
// Regression: the trailing " \" made isPinned() reject the spec, so a
// hash-pinned requirements file (the pip-compile default in hardened shops)
// contributed ZERO deps to the scan.
test("parseRequirementsTxt handles hash-pinned pip-compile output", () => {
	const fs = require("fs");
	const os = require("os");
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-reqhash-"));
	fs.writeFileSync(path.join(dir, "requirements.txt"), [
		"requests==2.31.0 \\",
		"    --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1 \\",
		"    --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f",
		"urllib3==2.0.7 --hash=sha256:abc123",
		"flask>=2.0",
	].join("\n"));
	const r = parseRequirementsTxt(path.join(dir, "requirements.txt"));
	const m = Object.fromEntries(r.deps.map(d => [d.name, d.version]));
	assert.strictEqual(m["requests"], "2.31.0", "backslash-continued pin parsed");
	assert.strictEqual(m["urllib3"], "2.0.7", "inline --hash option stripped");
	assert.strictEqual(r.skipped, 1);
	fs.rmSync(dir, { recursive: true, force: true });
});

/* ---- uv.lock root project exclusion ---- */
test("parseUvLock skips the project's own virtual/editable package entry", () => {
	const fs = require("fs");
	const os = require("os");
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-uvroot-"));
	fs.writeFileSync(path.join(dir, "uv.lock"), [
		'version = 1',
		'[[package]]',
		'name = "my-app"',
		'version = "0.1.0"',
		'[package.source]',
		'virtual = "."',
		'[[package]]',
		'name = "requests"',
		'version = "2.31.0"',
		'[package.source]',
		'registry = "https://pypi.org/simple"',
	].join("\n"));
	const r = parseUvLock(path.join(dir, "uv.lock"));
	assert.strictEqual(r.deps.find(d => d.name === "my-app"), undefined, "root project not inventoried");
	assert.strictEqual(r.deps.find(d => d.name === "requests").version, "2.31.0");
	fs.rmSync(dir, { recursive: true, force: true });
});

/* ---- multi-version scanning across manifests ---- */
// Same convention as Maven: when two files pin DIFFERENT versions of the same
// package, EVERY distinct version is scanned, not just the first encountered.
test("pypi codec keeps every distinct pinned version in versions[]", async () => {
	const fs = require("fs");
	const os = require("os");
	const pypi = require("../lib/codecs/pypi.codec");
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-pymulti-"));
	fs.mkdirSync(path.join(dir, "svc-a"));
	fs.mkdirSync(path.join(dir, "svc-b"));
	fs.writeFileSync(path.join(dir, "svc-a", "requirements.txt"), "django==4.2.0\n");
	fs.writeFileSync(path.join(dir, "svc-b", "requirements.txt"), "django==3.2.0\n");
	const { deps } = await pypi.collect(dir);
	const d = deps.get("pypi:django");
	assert.ok(d, "django collected");
	assert.deepStrictEqual([...d.versions].sort(), ["3.2.0", "4.2.0"], "both pinned versions scanned");
	fs.rmSync(dir, { recursive: true, force: true });
});
