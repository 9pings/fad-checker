const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { pep503, parsePoetryLock, parsePipfileLock, parseUvLock, parseRequirementsTxt } = require("../lib/codecs/pypi/parse");

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
