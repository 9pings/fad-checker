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
