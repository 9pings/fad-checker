const { test } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { makeDirFilter, compileGlobs } = require("../lib/path-filter");

const root = "/proj";
const abs = rel => path.join(root, rel);

test("default skip set prunes by basename", () => {
	const skip = makeDirFilter({ srcRoot: root, defaultSkip: new Set(["node_modules", "target"]) });
	assert.strictEqual(skip(abs("a/node_modules")), true);
	assert.strictEqual(skip(abs("target")), true);
	assert.strictEqual(skip(abs("src/main")), false);
});

test("useDefaults=false ignores the default skip set", () => {
	const skip = makeDirFilter({ srcRoot: root, defaultSkip: new Set(["node_modules"]), useDefaults: false });
	assert.strictEqual(skip(abs("node_modules")), false);
});

test("exclude-path glob matches the relative path AND its subtree", () => {
	const skip = makeDirFilter({ srcRoot: root, excludePath: ["packages/legacy/**", "**/fixtures/**", "vendored"] });
	assert.strictEqual(skip(abs("packages/legacy")), true);          // the dir itself
	assert.strictEqual(skip(abs("packages/legacy/sub")), true);      // subtree
	assert.strictEqual(skip(abs("apps/web/fixtures/data")), true);   // **/ middle
	assert.strictEqual(skip(abs("vendored")), true);                 // bare name as path
	assert.strictEqual(skip(abs("vendored/x")), true);               // bare name subtree
	assert.strictEqual(skip(abs("packages/active")), false);
	assert.strictEqual(skip(abs("src")), false);
});

test("globs combine with default skips", () => {
	const skip = makeDirFilter({ srcRoot: root, defaultSkip: new Set([".git"]), excludePath: ["e2e/**"] });
	assert.strictEqual(skip(abs(".git")), true);
	assert.strictEqual(skip(abs("e2e/specs")), true);
	assert.strictEqual(skip(abs("lib")), false);
});

test("compileGlobs trims and drops empties", () => {
	assert.strictEqual(compileGlobs([" a ", "", null, "b"]).length, 2);
});
