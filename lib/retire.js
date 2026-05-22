/**
 * lib/retire.js — wrap retire.js (the CLI) to find vulnerable
 * vendored JavaScript libraries living in the source tree as
 * unmanaged .js / .min.js files (no package-lock to back them).
 *
 * retire ships its own signature DB updated weekly; we just shell
 * out to it and normalise the output to fad-check match shape so the
 * report can render it like any other CVE source.
 *
 * Cache: ~/.fad-check/retire-cache/<md5(src)>.json, 24 h TTL.
 *
 * The CLI is expected at node_modules/.bin/retire (declared in
 * package.json deps). When bundled with bun, we also try `retire`
 * on PATH as a fallback.
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { execFile } = require("child_process");
const { promisify } = require("util");
const execFileP = promisify(execFile);

const RETIRE_CACHE_DIR = path.join(os.homedir(), ".fad-check", "retire-cache");
const RETIRE_CACHE_TTL_MS = 24 * 3600 * 1000;

function cacheKey(srcDir) {
	return crypto.createHash("md5").update(path.resolve(srcDir)).digest("hex") + ".json";
}

function readCache(srcDir) {
	const p = path.join(RETIRE_CACHE_DIR, cacheKey(srcDir));
	if (!fs.existsSync(p)) return null;
	try {
		const data = JSON.parse(fs.readFileSync(p, "utf8"));
		if (Date.now() - data._fetchedAt < RETIRE_CACHE_TTL_MS) return data.body;
	} catch { /* ignore */ }
	return null;
}

function writeCache(srcDir, body) {
	fs.mkdirSync(RETIRE_CACHE_DIR, { recursive: true });
	fs.writeFileSync(path.join(RETIRE_CACHE_DIR, cacheKey(srcDir)),
		JSON.stringify({ _fetchedAt: Date.now(), body }));
}

function findRetireBin() {
	const local = path.join(__dirname, "..", "node_modules", ".bin", "retire");
	if (fs.existsSync(local)) return local;
	return "retire"; // fall back to PATH
}

/**
 * Run retire.js against `srcDir`. Returns the parsed JSON output (an array
 * of file-level findings) or null if retire is unavailable.
 *
 * `--outputformat json` is the structured form; `--ignore` takes a list of
 * dirs to skip; we add the standard suspects to keep runtime bounded.
 */
async function runRetire(srcDir, opts = {}) {
	const { verbose, force, offline } = opts;
	if (offline) {
		const cached = readCache(srcDir);
		if (cached) return cached;
		if (verbose) console.warn("retire: --offline and no cache — skipped");
		return null;
	}
	if (!force) {
		const cached = readCache(srcDir);
		if (cached) {
			if (verbose) console.log("retire: using cached results (<24h)");
			return cached;
		}
	}

	const bin = findRetireBin();
	const ignoredDirs = [
		"node_modules", "bower_components", "jspm_packages",
		".git", ".idea", ".vscode", ".gradle", ".mvn",
		"target", "dist", "build", "build-output", "out", "coverage", ".next", ".nuxt",
	].join(",");

	// retire.js refuses to write to /dev/stdout, so we use a real temp file
	// and read it back. Falls back to stdout if --outputpath is rejected.
	const tmpOut = path.join(os.tmpdir(), `fad-check-retire-${process.pid}-${Date.now()}.json`);
	const args = [
		"--outputformat", "json",
		"--outputpath", tmpOut,
		"--jspath", srcDir,
		"--ignore", ignoredDirs,
	];
	if (verbose) console.log(`retire: scanning ${srcDir}…`);

	try {
		// retire.js exits with code 13 when it finds vulnerabilities — that's
		// expected. Catch and ignore the non-zero exit; the JSON file is still
		// produced.
		await execFileP(bin, args, { maxBuffer: 1024 * 1024 * 64 });
	} catch (err) {
		// exit code 13 (or anything where the output file exists) is OK
		if (!fs.existsSync(tmpOut)) {
			if (verbose) console.warn(`retire: failed to run — ${err.message}`);
			return null;
		}
	}

	let parsed;
	try {
		const body = fs.readFileSync(tmpOut, "utf8");
		parsed = JSON.parse(body);
	} catch (err) {
		if (verbose) console.warn(`retire: could not parse output — ${err.message}`);
		return null;
	} finally {
		try { fs.unlinkSync(tmpOut); } catch { /* best effort */ }
	}
	writeCache(srcDir, parsed);
	return parsed;
}

/**
 * Normalise a retire.js result tree to fad-check match shape.
 *
 * retire output (jsonsimple-ish):
 *   {
 *     data: [
 *       {
 *         file: "/abs/path/jquery-1.4.4.min.js",
 *         results: [
 *           {
 *             component: "jquery",
 *             version:   "1.4.4",
 *             vulnerabilities: [
 *               {
 *                 severity: "high",
 *                 identifiers: { CVE: ["CVE-…"], summary: "…", issue?: "…" },
 *                 info:      ["https://…"],
 *                 below?:    "1.6.3",
 *                 atOrAbove?: "1.4.0",
 *               },
 *             ],
 *           },
 *         ],
 *       },
 *     ],
 *   }
 */
function normaliseRetireResults(raw, srcDir) {
	const out = [];
	if (!raw) return out;
	const files = Array.isArray(raw) ? raw : (raw.data || []);
	for (const f of files) {
		const file = f.file;
		const relFile = srcDir && file?.startsWith(srcDir) ? path.relative(srcDir, file) : file;
		for (const res of f.results || []) {
			const component = res.component;
			const version = res.version;
			for (const v of res.vulnerabilities || []) {
				const ids = v.identifiers || {};
				const cveIds = Array.isArray(ids.CVE) && ids.CVE.length ? ids.CVE : [ids.issue || ids.summary || `RETIRE-${component}-${version}`];
				const severity = (v.severity || "medium").toUpperCase();
				const description = ids.summary || v.info?.[0] || "";
				const refs = (v.info || []).map(u => ({ type: "WEB", url: u }));
				for (const cveId of cveIds) {
					out.push({
						dep: {
							groupId: "",
							artifactId: component,
							version,
							scope: "vendored",
							ecosystem: "npm",
							ecosystemType: "retire",
							pomPaths: file ? [file] : [],
							manifestPaths: file ? [file] : [],
							vendoredFile: relFile,
						},
						cve: {
							id: cveId,
							severity,
							score: null,
							description,
							fixVersion: v.below || null,
							osvRefs: refs,
						},
						source: "retire",
						confidence: "exact",
					});
				}
			}
		}
	}
	return out;
}

/**
 * Public entry point. Returns an array of match objects or [] if retire
 * couldn't run or found nothing.
 */
async function scanWithRetire(srcDir, opts = {}) {
	const raw = await runRetire(srcDir, opts);
	if (!raw) return [];
	return normaliseRetireResults(raw, srcDir);
}

module.exports = {
	scanWithRetire,
	runRetire,
	normaliseRetireResults,
	findRetireBin,
	RETIRE_CACHE_DIR,
};
