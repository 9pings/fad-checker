const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("fs"); const os = require("os"); const path = require("path");
const { Command } = require("commander");
const OE = require("../lib/options-env");

function makeProgram() {
	const p = new Command();
	p.option("-s, --src <s>").option("--source <s>").option("-e, --exclude <e>")
	 .option("--fail-on <l>").option("--no-nuget").option("--repo <r...>");
	return p;
}

test("tokenize handles single/double quotes and escapes", () => {
	assert.deepStrictEqual(OE.tokenize(`a "b c" 'd e' f\\ g`), ["a", "b c", "d e", "f g"]);
});

test("parseEnvFlags tokenizes quotes and returns only set options", () => {
	const p = makeProgram();
	const { options, repos } = OE.parseEnvFlags(`--fail-on high --exclude "^a b\\.c" --repo npm=https://r/`, p);
	assert.strictEqual(options.failOn, "high");
	assert.strictEqual(options.exclude, "^a b.c");
	assert.deepStrictEqual(repos, ["npm=https://r/"]);
	assert.strictEqual("nuget" in options, false);
});

test("applyLayers: CLI wins over file wins over env wins over global", () => {
	const p = makeProgram();
	p.parse(["node", "x", "--fail-on", "critical"]);
	const eff = OE.applyLayers(p, {
		fileLayer: { failOn: "high", exclude: "^file" },
		envLayer: { exclude: "^env", src: "envsrc" },
	}, {});
	assert.strictEqual(eff.failOn, "critical");
	assert.strictEqual(eff.exclude, "^file");
	assert.strictEqual(eff.src, "envsrc");
});

test("normalizeSource maps source/JSON-source to src", () => {
	assert.strictEqual(OE.normalizeSource({ source: "x" }).src, "x");
	assert.strictEqual(OE.normalizeSource({ src: "y", source: "z" }).src, "y");
});

test("loadLayers: --config path beats ./.fad-env.json; malformed JSON throws", () => {
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fad-env-"));
	fs.writeFileSync(path.join(tmp, ".fad-env.json"), JSON.stringify({ failOn: "low" }));
	fs.writeFileSync(path.join(tmp, "alt.json"), JSON.stringify({ failOn: "high" }));
	assert.strictEqual(OE.loadLayers({ cwd: tmp }).fileLayer.failOn, "low");
	assert.strictEqual(OE.loadLayers({ cwd: tmp, configPath: path.join(tmp, "alt.json") }).fileLayer.failOn, "high");
	fs.writeFileSync(path.join(tmp, "bad.json"), "{ not json");
	assert.throws(() => OE.loadLayers({ cwd: tmp, configPath: path.join(tmp, "bad.json") }), /JSON|parse/i);
	fs.rmSync(tmp, { recursive: true, force: true });
});
