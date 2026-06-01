/**
 * lib/ui.js — shared CLI presentation: banner, section headers, severity colors,
 * and a global step progress indicator for the cache/database update phase.
 *
 * The Progress indicator renders a "[n/N] <spinner> label — summary" checklist.
 * TTY: one animated line per step, rewritten in place, finalized with ✓/⊘/✗.
 * Non-TTY (pipes, CI, files): a single plain line per finished step, no escapes.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const chalk = require("chalk");

const isTTY = !!(process.stdout && process.stdout.isTTY) && process.env.TERM !== "dumb";
const SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

const TITLE_A = "fad-checker";
const TITLE_B = "Autonomous Dependency Checker";

function banner() {
	const raw = `${TITLE_A} · ${TITLE_B}`;
	const bar = "─".repeat(raw.length + 2);
	console.log(chalk.cyan(`\n╭${bar}╮`));
	console.log(chalk.cyan("│ ") + chalk.bold.white(TITLE_A) + chalk.cyan(" · ") + chalk.whiteBright(TITLE_B) + chalk.cyan(" │"));
	console.log(chalk.cyan(`╰${bar}╯`));
}

function section(title) {
	console.log(chalk.bold.cyan("\n▸ ") + chalk.bold(title));
}

// "  label   value" aligned key/value line under a section.
function kv(label, value, { pad = 10 } = {}) {
	console.log("  " + chalk.dim(String(label).padEnd(pad)) + " " + value);
}

function ok(msg) { console.log("  " + chalk.green("✓") + " " + msg); }
function warn(msg) { console.log("  " + chalk.yellow("⚠") + " " + msg); }
function info(msg) { console.log("  " + chalk.dim("·") + " " + msg); }

function sevColor(sev) {
	switch (String(sev || "").toUpperCase()) {
		case "CRITICAL": return chalk.bold.red;
		case "HIGH": return chalk.red;
		case "MEDIUM": return chalk.yellow;
		case "LOW": return chalk.blue;
		default: return chalk.gray;
	}
}

class Step {
	constructor(n, total, label) {
		this.n = n; this.total = total; this.label = label;
		this.live = ""; this.frame = 0; this.timer = null; this.ended = false;
		this.prefix = chalk.dim(`[${n}/${total}]`);
		if (isTTY) {
			this._render();
			this.timer = setInterval(() => { this.frame++; this._render(); }, 80);
			if (this.timer.unref) this.timer.unref();
		}
	}
	_render() {
		if (!isTTY || this.ended) return;
		const sp = chalk.cyan(SPINNER[this.frame % SPINNER.length]);
		const live = this.live ? chalk.dim(" " + this.live) : chalk.dim(" …");
		process.stdout.write(`\r  ${this.prefix} ${sp} ${this.label}${live}\x1b[K`);
	}
	tick(processed, total) {
		this.live = total ? `${processed}/${total}` : String(processed || "");
		// rendering is driven by the timer; nothing to print on non-TTY
	}
	_finalize(symbol, color, summary) {
		if (this.ended) return;
		this.ended = true;
		if (this.timer) { clearInterval(this.timer); this.timer = null; }
		const line = `  ${this.prefix} ${color(symbol)} ${this.label}` + (summary ? chalk.dim(" — " + summary) : "");
		if (isTTY) process.stdout.write(`\r${line}\x1b[K\n`);
		else console.log(line);
	}
	done(summary) { this._finalize("✓", chalk.green, summary); }
	skip(reason) { this._finalize("⊘", chalk.gray, reason); }
	fail(msg) { this._finalize("✗", chalk.red, msg); }
}

class Progress {
	constructor(total) { this.total = total || 0; this.n = 0; }
	start(label) { this.n += 1; return new Step(this.n, this.total, label); }
}

module.exports = { banner, section, kv, ok, warn, info, sevColor, Progress, isTTY };
