/**
 * test/cli-safety.test.js — guards on the two CLI behaviours whose failure is
 * destructive or silently disables CI gating. These spawn the real binary.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const CLI = path.join(__dirname, "..", "fad-checker.js");

function run(args, opts = {}) {
	return spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", ...opts });
}

// The catastrophic case: --target is a PARENT of --src. --target is rimraf'd
// before being rewritten, so this would delete the source tree + siblings.
test("--target that is a parent of --src is rejected (and deletes nothing)", () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "fad-safety-"));
	const src = path.join(root, "src", "inner");
	fs.mkdirSync(src, { recursive: true });
	fs.writeFileSync(path.join(root, "IMPORTANT.txt"), "precious");
	fs.writeFileSync(path.join(src, "pom.xml"),
		"<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>");

	const res = run(["-s", src, "-t", root, "--no-report", "--offline"]);
	assert.notEqual(res.status, 0, "must exit non-zero");
	assert.match(res.stderr, /must not overlap/i);
	assert.ok(fs.existsSync(path.join(root, "IMPORTANT.txt")), "source tree must be untouched");
	assert.ok(fs.existsSync(path.join(src, "pom.xml")));
	fs.rmSync(root, { recursive: true, force: true });
});

test("--target equal to --src is rejected", () => {
	const src = fs.mkdtempSync(path.join(os.tmpdir(), "fad-safety-"));
	fs.writeFileSync(path.join(src, "pom.xml"),
		"<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>");
	const res = run(["-s", src, "-t", src, "--no-report", "--offline"]);
	assert.notEqual(res.status, 0);
	assert.match(res.stderr, /must not overlap/i);
	fs.rmSync(src, { recursive: true, force: true });
});

// An unrecognised --fail-on (CI typo) must hard-fail, never silently pass.
test("invalid --fail-on hard-fails instead of disabling the gate", () => {
	const src = path.join(__dirname, "fixtures", "simple");
	const res = run(["-s", src, "--offline", "--no-report", "--fail-on", "hgih"]);
	assert.equal(res.status, 2);
	assert.match(res.stderr, /invalid --fail-on/i);
});

test("a valid --fail-on level is accepted", () => {
	const src = path.join(__dirname, "fixtures", "simple");
	const res = run(["-s", src, "--offline", "--no-report", "--fail-on", "none"]);
	assert.equal(res.status, 0);
});

// --no-report writes NO files, but the scan + CI gate still run.
test("--no-report still runs the gate (and fails on a high finding)", () => {
	const src = path.join(__dirname, "fixtures", "polyglot");
	const res = run(["-s", src, "--offline", "--no-report", "--fail-on", "high"]);
	assert.equal(res.status, 1);
});

test("--no-report writes no files at all", () => {
	const src = path.join(__dirname, "fixtures", "polyglot");
	const out = fs.mkdtempSync(path.join(os.tmpdir(), "fad-noreport-"));
	const res = run(["-s", src, "--offline", "--no-report", "--report-output", out], { env: { ...process.env, FORCE_COLOR: "0" } });
	assert.equal(res.status, 0);
	assert.ok(!fs.existsSync(out) || fs.readdirSync(out).length === 0, "no output files written");
	fs.rmSync(out, { recursive: true, force: true });
});

// Selecting any --report-* flag overrides the default HTML+doc set: only the
// chosen outputs are written (each to its given path or its default name).
test("--report-sbom alone writes only the SBOM (no HTML/doc)", () => {
	const src = path.join(__dirname, "fixtures", "polyglot");
	const out = fs.mkdtempSync(path.join(os.tmpdir(), "fad-report-"));
	const res = run(["-s", src, "--offline", "--report-output", out, "--report-sbom"], { env: { ...process.env, FORCE_COLOR: "0" } });
	assert.equal(res.status, 0);
	assert.ok(fs.existsSync(path.join(out, "sbom.cdx.json")), "SBOM written to default name");
	assert.ok(!fs.existsSync(path.join(out, "cve-report.html")), "no HTML when a --report-* is selected");
	fs.rmSync(out, { recursive: true, force: true });
});

test("--report-html with an explicit path writes there", () => {
	const src = path.join(__dirname, "fixtures", "polyglot");
	const out = fs.mkdtempSync(path.join(os.tmpdir(), "fad-report-"));
	const target = path.join(out, "nested", "my.html");
	const res = run(["-s", src, "--offline", "--report-html", target], { env: { ...process.env, FORCE_COLOR: "0" } });
	assert.equal(res.status, 0);
	assert.ok(fs.existsSync(target), "HTML written to the explicit (nested) path");
	fs.rmSync(out, { recursive: true, force: true });
});
