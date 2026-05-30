const test = require("node:test");
const assert = require("node:assert");
const ui = require("../lib/ui");

// Capture everything written to stdout while running `fn`.
function capture(fn) {
	const chunks = [];
	const origWrite = process.stdout.write;
	const origLog = console.log;
	process.stdout.write = (s) => { chunks.push(String(s)); return true; };
	console.log = (...a) => { chunks.push(a.join(" ") + "\n"); };
	try { fn(); } finally { process.stdout.write = origWrite; console.log = origLog; }
	// strip ANSI for assertions
	return chunks.join("").replace(/\x1b\[[0-9;]*m/g, "");
}

test("sevColor maps severities to distinct chalk fns", () => {
	assert.strictEqual(typeof ui.sevColor("CRITICAL"), "function");
	assert.notStrictEqual(ui.sevColor("CRITICAL"), ui.sevColor("LOW"));
	// applying it returns a string containing the input
	assert.match(ui.sevColor("HIGH")("HIGH"), /HIGH/);
});

test("banner / section / ok / warn / info render without throwing", () => {
	const out = capture(() => {
		ui.banner();
		ui.section("Collection");
		ui.ok("done");
		ui.warn("careful");
		ui.info("note");
		ui.kv("source", "/x");
	});
	assert.match(out, /fad-checker/);
	assert.match(out, /▸ Collection/);
	assert.match(out, /done/);
});

test("Progress emits [n/N] step lines finalized with ✓ / ⊘ (non-TTY)", () => {
	const out = capture(() => {
		const p = new ui.Progress(2);
		const a = p.start("first"); a.tick(1, 2); a.done("ok");
		const b = p.start("second"); b.skip("nope");
	});
	assert.match(out, /\[1\/2\][^\n]*✓[^\n]*first[^\n]*ok/);
	assert.match(out, /\[2\/2\][^\n]*⊘[^\n]*second[^\n]*nope/);
});

test("Progress.fail marks a step with ✗ and the message", () => {
	const out = capture(() => {
		const p = new ui.Progress(1);
		p.start("boom").fail("kaboom");
	});
	assert.match(out, /\[1\/1\][^\n]*✗[^\n]*boom[^\n]*kaboom/);
});
