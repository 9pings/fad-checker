const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { pep503, parsePoetryLock, parsePipfileLock, parseUvLock, parseRequirementsTxt } = require("../lib/python/parse");

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
