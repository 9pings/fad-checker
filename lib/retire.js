/**
 * lib/retire.js — wrap retire.js (the CLI) to find vulnerable
 * vendored JavaScript libraries living in the source tree as
 * unmanaged .js / .min.js files (no package-lock to back them).
 *
 * retire ships its own signature DB updated weekly; we just shell
 * out to it and normalise the output to fad-checker match shape so the
 * report can render it like any other CVE source.
 *
 * Cache: ~/.fad-checker/retire-cache/<md5(src)>.json, 24 h TTL.
 *
 * The CLI is expected at node_modules/.bin/retire (declared in
 * package.json deps). When bundled with bun, we also try `retire`
 * on PATH as a fallback.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { execFile } = require("child_process");
const { promisify } = require("util");
const execFileP = promisify(execFile);

const RETIRE_CACHE_DIR = path.join(os.homedir(), ".fad-checker", "retire-cache");
const RETIRE_CACHE_TTL_MS = 24 * 3600 * 1000;

// retire's own signature DB. By default retire caches it in /tmp/.retire-cache
// (outside ~/.fad-checker/, with a 1h TTL → a network refetch on expiry). For the
// PASSI offline workflow we instead keep a stable local copy INSIDE ~/.fad-checker/
// so `--export-cache` carries it, and feed it to retire via `--jsrepo <file>`
// (loaded from file, never the network — no TTL).
const RETIRE_SIG_DIR = path.join(os.homedir(), ".fad-checker", "retire-signatures");
const RETIRE_SIG_FILE = path.join(RETIRE_SIG_DIR, "jsrepository-v5.json");
const RETIRE_REPO_URL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v5.json";

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
 * Fetch retire's signature DB to a stable file inside ~/.fad-checker/ so it can
 * be bundled by --export-cache and reused offline via --jsrepo. Network call —
 * online only. Returns { ok, path } | { ok:false, error }. Never throws.
 */
async function warmRetireSignatures(opts = {}) {
	const { verbose, force } = opts;
	if (!force && fs.existsSync(RETIRE_SIG_FILE)) {
		if (verbose) console.log(`retire: signatures already present (${RETIRE_SIG_FILE})`);
		return { ok: true, path: RETIRE_SIG_FILE, cached: true };
	}
	try {
		const res = await fetch(RETIRE_REPO_URL);
		if (!res.ok) throw new Error(`HTTP ${res.status}`);
		const text = await res.text();
		JSON.parse(text);   // validate it's the repo JSON before persisting
		fs.mkdirSync(RETIRE_SIG_DIR, { recursive: true });
		fs.writeFileSync(RETIRE_SIG_FILE, text);
		if (verbose) console.log(`retire: signatures warmed → ${RETIRE_SIG_FILE}`);
		return { ok: true, path: RETIRE_SIG_FILE };
	} catch (e) {
		if (verbose) console.warn(`retire: signature warm failed — ${e.message}`);
		return { ok: false, error: e.message };
	}
}

// Ensure a local signature file exists. Online: fetch it if missing. Offline:
// only report whether it's already there (no network).
async function ensureSignatures({ verbose, offline } = {}) {
	if (fs.existsSync(RETIRE_SIG_FILE)) return true;
	if (offline) return false;
	const r = await warmRetireSignatures({ verbose });
	return !!r.ok;
}

// Pure: build the retire CLI argv. `jsRepo` (a local signature file) is added
// when available so retire loads signatures from disk instead of the network.
function buildRetireArgs({ srcDir, outPath, ignoredDirs, jsRepo }) {
	const args = [
		// --verbose makes retire list EVERY identified library, not just the
		// vulnerable ones (its own wording: "by default only vulnerable files are
		// shown"). We need the full set for the vendored-JS inventory chapter;
		// vulnerable findings are still flagged in each result's `vulnerabilities`.
		"--verbose",
		"--outputformat", "json",
		"--outputpath", outPath,
		"--jspath", srcDir,
		"--ignore", ignoredDirs,
	];
	if (jsRepo) { args.push("--jsrepo", jsRepo); }
	return args;
}

const SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, none: 1 };

/**
 * Extract the full inventory of identified vendored JS libraries (vulnerable or
 * not) from retire's --verbose output. Each entry: the standalone library, where
 * it lives, how retire identified it, and whether it carries known vulns.
 * This is a governance/cyber-hygiene signal: third-party code no package manager
 * governs (unknown provenance, integrity, patch story) — the JS twin of the
 * native-binary inventory (chapter 1C).
 */
function extractVendoredInventory(raw, srcDir) {
	const out = [];
	if (!raw) return out;
	const files = Array.isArray(raw) ? raw : (raw.data || []);
	for (const f of files) {
		const file = f.file;
		const relFile = srcDir && file?.startsWith(srcDir) ? path.relative(srcDir, file) : file;
		for (const res of f.results || []) {
			if (!res.component) continue;
			const vulns = res.vulnerabilities || [];
			let maxSeverity = null;
			for (const v of vulns) {
				const s = (v.severity || "").toLowerCase();
				if (!maxSeverity || (SEV_RANK[s] || 0) > (SEV_RANK[maxSeverity] || 0)) maxSeverity = s;
			}
			out.push({
				component: res.component,
				version: res.version || null,
				file: relFile || null,
				detection: res.detection || null,
				vulnerable: vulns.length > 0,
				vulnCount: vulns.length,
				maxSeverity: maxSeverity ? maxSeverity.toUpperCase() : null,
			});
		}
	}
	// Vulnerable first (by severity), then by component/version/file for stability.
	out.sort((a, b) =>
		(SEV_RANK[(b.maxSeverity || "").toLowerCase()] || 0) - (SEV_RANK[(a.maxSeverity || "").toLowerCase()] || 0)
		|| String(a.component).localeCompare(String(b.component))
		|| String(a.version).localeCompare(String(b.version))
		|| String(a.file).localeCompare(String(b.file)));
	return out;
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
	// No source tree (e.g. --import-anonymized) → nothing to scan for vendored JS.
	if (!srcDir) { if (verbose) console.warn("retire: no source dir — skipped"); return null; }
	// Findings-cache fast path (path-keyed). Works online and offline.
	if (!force) {
		const cached = readCache(srcDir);
		if (cached) {
			if (verbose) console.log("retire: using cached results (<24h)");
			return cached;
		}
	}

	// No findings cache → we must scan. We need a signature DB. Offline, we can
	// only proceed if a local signature file was previously warmed (and bundled
	// via --export-cache / --import-cache); otherwise honor --offline and skip.
	const haveSig = await ensureSignatures({ verbose, offline });
	if (offline && !haveSig) {
		if (verbose) console.warn("retire: --offline, no findings cache and no local signatures — skipped");
		return null;
	}

	const bin = findRetireBin();
	const ignoredDirs = [
		"node_modules", "bower_components", "jspm_packages",
		".git", ".idea", ".vscode", ".gradle", ".mvn",
		"target", "dist", "build", "build-output", "out", "coverage", ".next", ".nuxt",
	].join(",");

	// retire.js refuses to write to /dev/stdout, so we use a real temp file
	// and read it back. Falls back to stdout if --outputpath is rejected.
	const tmpOut = path.join(os.tmpdir(), `fad-checker-retire-${process.pid}-${Date.now()}.json`);
	const args = buildRetireArgs({ srcDir, outPath: tmpOut, ignoredDirs, jsRepo: haveSig ? RETIRE_SIG_FILE : null });
	if (verbose) console.log(`retire: scanning ${srcDir}…${haveSig ? " (local signatures)" : ""}`);

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
 * Normalise a retire.js result tree to fad-checker match shape.
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

/**
 * Like scanWithRetire but returns BOTH the vulnerable matches (chapter "Vendored
 * JS") and the full identified-library inventory (chapter "Unmanaged / vendored
 * JavaScript"). One retire run feeds both.
 */
async function scanWithRetireFull(srcDir, opts = {}) {
	const raw = await runRetire(srcDir, opts);
	if (!raw) return { matches: [], inventory: [] };
	return {
		matches: normaliseRetireResults(raw, srcDir),
		inventory: extractVendoredInventory(raw, srcDir),
	};
}

module.exports = {
	scanWithRetire,
	scanWithRetireFull,
	extractVendoredInventory,
	runRetire,
	normaliseRetireResults,
	findRetireBin,
	warmRetireSignatures,
	ensureSignatures,
	buildRetireArgs,
	RETIRE_CACHE_DIR,
	RETIRE_SIG_DIR,
	RETIRE_SIG_FILE,
	RETIRE_REPO_URL,
};
