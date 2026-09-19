// script(1) classic capture  ->  asciicast v2
// Real output, real inter-chunk timings. The only synthesised part is the prompt line
// being typed, which is how the viewer learns the command; the run itself is untouched.
const fs = require("fs");
const { StringDecoder } = require("string_decoder");
const [raw, tim, out, colsS, rowsS] = process.argv.slice(2);
const cols = +colsS, rows = +rowsS;
let buf = fs.readFileSync(raw);
// script(1) appends its own "Script done on <date> [COMMAND_EXIT_CODE=...]" footer to the
// log. It is the harness talking, not the tool — drop it so the recording ends on the run.
const foot = buf.lastIndexOf(Buffer.from("\nScript done on "));
if (foot !== -1) buf = buf.subarray(0, foot + 1);
const timings = fs.readFileSync(tim, "utf8").trim().split("\n")
	.map(l => l.trim().split(/\s+/)).filter(p => p.length === 2)
	.map(([d, n]) => ({ d: parseFloat(d), n: parseInt(n, 10) }));

const CMD = "fad -s test/fixtures/private-lib-detection --offline --no-report";
const PROMPT = "\u001b[38;5;114m❯\u001b[0m ";
const ev = [];
let t = 0;
const push = (dt, s) => { t += dt; ev.push([+t.toFixed(6), "o", s]); };

push(0.4, PROMPT);
for (const ch of CMD) push(0.032 + Math.random() * 0.028, ch);   // typing
push(0.55, "\r\n");                                               // Enter

// A chunk boundary can land mid-UTF-8 (the box-drawing banner, ⚠, ▸, ·), so decode
// across chunks instead of per chunk.
const dec = new StringDecoder("utf8");
let off = 0;
for (const { d, n } of timings) {
	if (off >= buf.length) break;
	const chunk = buf.subarray(off, Math.min(off + n, buf.length)); off += n;
	if (!chunk.length) continue;
	const s = dec.write(chunk);
	if (s) push(Math.min(d, 0.25), s);
}
const tail = dec.write(off < buf.length ? buf.subarray(off) : Buffer.alloc(0)) + dec.end();
if (tail) push(0.02, tail);

// Tokyo Night — the palette the previous demo.gif used.
const THEME = {
	fg: "#c0caf5", bg: "#1a1b26",
	palette: ["#15161e", "#f7768e", "#9ece6a", "#e0af68", "#7aa2f7", "#bb9af7", "#7dcfff", "#a9b1d6",
		"#414868", "#f7768e", "#9ece6a", "#e0af68", "#7aa2f7", "#bb9af7", "#7dcfff", "#c0caf5"].join(":"),
};
const header = { version: 2, width: cols, height: rows, timestamp: Math.floor(Date.now() / 1000), theme: THEME, env: { TERM: "xterm-256color", SHELL: "/bin/bash" } };
fs.writeFileSync(out, JSON.stringify(header) + "\n" + ev.map(e => JSON.stringify(e)).join("\n") + "\n", "utf8");
console.log(`events=${ev.length} duration=${t.toFixed(2)}s bytes=${off}/${buf.length}`);
