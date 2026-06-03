#!/usr/bin/env node
/**
 * Fucking Autonomous Dependency Checker — CLI entry point.
 *
 * Thin wrapper around lib/* modules. The heavy lifting lives in:
 *   lib/core.js          POM parsing & rewriting
 *   lib/cve-download.js  CVE bulk download + index build
 *   lib/cve-match.js     dependency collection + CVE matching
 *   lib/cve-report.js    HTML / Word report generation
 *   lib/outdated.js      EOL + obsolete + outdated checks
 *   lib/snyk.js          optional Snyk integration
 */
const fs = require("fs");
const path = require("path");
const { rimraf } = require("rimraf");
const chalk = require("chalk");
const pLimit = require("p-limit");
const { program } = require("commander");
const ui = require("./lib/ui");

const core = require("./lib/core");

// require() (not fs.readFileSync) so bun --compile statically bundles package.json
// into the binary — otherwise the compiled exe tries to read it off disk at runtime
// (from $bunfs/root) and crashes with ENOENT. Keeps the bun builds fully standalone.
const pkg = require("./package.json");

// -------- bash/zsh completion shortcut (must run before required-options parse) --------
if (process.argv.includes("--completion")) {
	const shellIdx = process.argv.indexOf("--completion") + 1;
	const shell = process.argv[shellIdx] && !process.argv[shellIdx].startsWith("-")
		? process.argv[shellIdx]
		: "bash";
	const completionPath = path.join(__dirname, "completions", `fad-checker.${shell}`);
	try {
		process.stdout.write(fs.readFileSync(completionPath, "utf8"));
		process.exit(0);
	} catch (_) {
		console.error(`Completion for ${shell} not available.`);
		process.exit(1);
	}
}

// -------- --set-nvd-key shortcut (must run before required-options parse) --------
if (process.argv.includes("--set-nvd-key")) {
	const config = require("./lib/config");
	const idx = process.argv.indexOf("--set-nvd-key");
	const key = process.argv[idx + 1];
	if (!key || key.startsWith("-")) {
		console.error(chalk.red("❌  --set-nvd-key requires a key argument"));
		console.error("   Get one (free, instant) at https://nvd.nist.gov/developers/request-an-api-key");
		process.exit(1);
	}
	config.set("nvd_api_key", key);
	console.log(chalk.green("✅ NVD API key saved to") + " " + chalk.cyan(config.CONFIG_PATH));
	console.log(chalk.gray("   Rate limit: 50 req / 30 s instead of 5 req / 30 s."));
	process.exit(0);
}
if (process.argv.includes("--show-config")) {
	const config = require("./lib/config");
	const cfg = config.load();
	const masked = { ...cfg };
	if (masked.nvd_api_key) masked.nvd_api_key = masked.nvd_api_key.slice(0, 8) + "…" + masked.nvd_api_key.slice(-4);
	if (masked.registries && typeof masked.registries === "object") {
		masked.registries = Object.fromEntries(Object.entries(masked.registries).map(([eco, list]) =>
			[eco, (list || []).map(r => ({ ...r, auth: r.auth ? "***" : undefined, token: r.token ? "***" : undefined }))]));
	}
	console.log(JSON.stringify(masked, null, 2));
	console.log(chalk.gray("Config file: " + config.CONFIG_PATH));
	process.exit(0);
}

// -------- --add-repo / --remove-repo / --list-repos (run before program.parse) --------
if (process.argv.includes("--add-repo") || process.argv.includes("--remove-repo") || process.argv.includes("--list-repos")) {
	const config = require("./lib/config");
	const { SUPPORTED } = require("./lib/registries");
	const ecoErr = eco => {
		if (!SUPPORTED.includes(eco)) {
			console.error(chalk.red(`❌  unknown ecosystem "${eco}". Supported: ${SUPPORTED.join(", ")}`));
			process.exit(1);
		}
	};
	if (process.argv.includes("--list-repos")) {
		const map = config.getRegistryMap();
		const ecos = Object.keys(map).filter(e => (map[e] || []).length);
		if (!ecos.length) {
			console.log(chalk.gray("No custom registries configured (public registries are always the fallback)."));
		} else {
			for (const eco of ecos) {
				console.log(chalk.bold(`${eco} (tried in order, then public):`));
				for (const r of map[eco]) {
					const authMark = (r.auth || r.token) ? chalk.yellow(" [auth]") : "";
					console.log(`  • ${chalk.cyan(r.name)} → ${r.url}${authMark}`);
				}
			}
		}
		process.exit(0);
	}
	if (process.argv.includes("--add-repo")) {
		const idx = process.argv.indexOf("--add-repo");
		const [eco, name, url] = [process.argv[idx + 1], process.argv[idx + 2], process.argv[idx + 3]];
		if (!eco || !name || !url || [eco, name, url].some(a => a.startsWith("-"))) {
			console.error(chalk.red("❌  --add-repo requires <ecosystem> <name> <url>"));
			console.error("   Example: fad-checker --add-repo npm verdaccio https://npm.acme/ --token TOK");
			console.error("   Maven:   fad-checker --add-repo maven nexus https://nexus.acme/maven-public/ --auth user:pass");
			process.exit(1);
		}
		ecoErr(eco);
		const authIdx = process.argv.indexOf("--auth");
		const tokIdx = process.argv.indexOf("--token");
		config.addRegistry(eco, name, url, {
			auth: authIdx > -1 ? process.argv[authIdx + 1] : null,
			token: tokIdx > -1 ? process.argv[tokIdx + 1] : null,
		});
		console.log(chalk.green(`✅ Added ${eco} registry "${name}" → ${url}`));
		process.exit(0);
	}
	if (process.argv.includes("--remove-repo")) {
		const idx = process.argv.indexOf("--remove-repo");
		const [eco, name] = [process.argv[idx + 1], process.argv[idx + 2]];
		if (!eco || !name || [eco, name].some(a => a.startsWith("-"))) {
			console.error(chalk.red("❌  --remove-repo requires <ecosystem> <name>"));
			process.exit(1);
		}
		ecoErr(eco);
		const removed = config.removeRegistry(eco, name);
		console.log(removed ? chalk.green(`✅ Removed ${eco} registry "${name}"`) : chalk.yellow(`⚠️  No ${eco} registry named "${name}"`));
		process.exit(removed ? 0 : 1);
	}
}

// -------- --export-cache / --import-cache (handled before program.parse) --------
if (process.argv.includes("--export-cache") || process.argv.includes("--import-cache")) {
	(async () => {
		const { exportCache, importCache, FAD_CACHE_DIR } = require("./lib/cache-archive");
		const verbose = process.argv.includes("-v") || process.argv.includes("--verbose");
		const exportIdx = process.argv.indexOf("--export-cache");
		const importIdx = process.argv.indexOf("--import-cache");
		try {
			if (exportIdx !== -1) {
				const dest = process.argv[exportIdx + 1];
				if (!dest || dest.startsWith("-")) {
					console.error(chalk.red("❌  --export-cache requires a destination path (e.g. fad-checker-cache.tar.gz)"));
					process.exit(1);
				}
				const includeConfig = process.argv.includes("--include-config");
				const { path: out, size, excluded } = await exportCache(dest, { verbose, includeConfig });
				const mb = (size / 1024 / 1024).toFixed(2);
				console.log(chalk.green(`✅ Cache exported (${mb} MB) → ${out}`));
				console.log(chalk.gray(`   Source: ${FAD_CACHE_DIR}`));
				if (excluded?.length) console.log(chalk.gray(`   Excluded (pass --include-config to ship them too): ${excluded.join(", ")}`));
			} else {
				const src = process.argv[importIdx + 1];
				if (!src || src.startsWith("-")) {
					console.error(chalk.red("❌  --import-cache requires a source path"));
					process.exit(1);
				}
				const force = process.argv.includes("--force");
				const { dir } = await importCache(src, { verbose, force });
				console.log(chalk.green(`✅ Cache imported → ${dir}`));
			}
			process.exit(0);
		} catch (err) {
			console.error(chalk.red(`❌  ${err.message}`));
			process.exit(1);
		}
	})();
	return;
}

const USAGE = `
(1) fad-checker -s ./proj                                              # read-only: full report (CVE + EOL + obsolete + outdated + transitive)
(2) fad-checker -s ./proj -e "^(org.private|client)"                   # same, with regex exclusion of private deps
(3) fad-checker -s ./proj -t ../pom-clean -e "^(org.private|client)"   # write cleaned POMs + full report
(4) fad-checker -s ./proj --no-transitive --no-all-libs                # faster, only direct deps, no Maven Central queries
(5) fad-checker -s ./proj -t ../pom-clean -e "^..." --snyk             # also run snyk and merge findings
`;

program
	.name(pkg.name)
	.version(pkg.version)
	.showHelpAfterError()
	.usage(USAGE)
	.option("-t, --target <target>", "output directory (will be rm before written). If omitted, the run is read-only.")
	// Not a requiredOption: --import-anonymized scans a descriptor with no source tree.
	.option("-s, --src <src>", "root directory containing pom.xml files")
	.option("--source <src>", "alias of --src (also the JSON config key 'source')")
	.option("--config <file>", "load default options from a JSON config file (else ./.fad-env.json)")
	.option("-e, --exclude <exclude>", "regex of groupId/name to exclude, e.g. '^(client|private)\\.'")
	.option("--exclude-path <glob...>", "ignore sub-paths during the walk (gitignore-style glob, relative to --src). Repeatable. e.g. 'packages/legacy/**' '**/fixtures/**'")
	.option("--no-default-excludes", "don't prune the built-in ignored dirs (node_modules, vendor, target, .git, …) — walk everything")
	.option("-v, --verbose", "verbose")
	// Defaults: report + transitive + allLibs all ON. Use --no-* to disable.
	.option("--no-report", "write NO output files at all — the scan, terminal summary and --fail-on gate still run (gate-only / CI mode)")
	.option("--no-transitive", "skip transitive dependency resolution")
	.option("--no-all-libs", "skip Maven Central queries (outdated check + missing-on-central check)")
	.option("--no-osv", "skip OSV.dev (Google/GitHub aggregated Maven CVE feed)")
	.option("--no-nvd", "skip NIST NVD enrichment of matched CVEs")
	.option("--no-epss", "skip EPSS (FIRST.org exploit-prediction) enrichment")
	.option("--no-kev", "skip CISA KEV (known-exploited) enrichment")
	// Output family: each --report-<type> takes an OPTIONAL path (omit → default name
	// under --report-output). With NO --report-* flag at all, HTML + .doc are written
	// by default. --no-report writes nothing (scan + gate only).
	.option("--report-html [file]", "write the self-contained HTML report (default: <report-output>/cve-report.html)")
	.option("--report-doc [file]", "write the Word-compatible .doc report (default: <report-output>/cve-report.doc)")
	.option("--report-sbom [file]", "write a CycloneDX 1.6 SBOM, vulnerabilities inline (default: <report-output>/sbom.cdx.json)")
	.option("--report-csaf [file]", "write a CSAF 2.0 VEX document (default: <report-output>/csaf-vex.json)")
	.option("--report-json [file]", "write a flat machine-readable findings JSON (default: <report-output>/findings.json)")
	.option("--report-sarif [file]", "write a SARIF 2.1.0 log for GitHub/GitLab code scanning (default: <report-output>/fad.sarif)")
	.option("--fail-on <level>", "exit non-zero if a production finding meets <level>: low|medium|high|critical|kev|none", "none")
	.option("--ignore <file>", "suppress findings listed in <file> (CVE ids / coords / globs, one per line)")
	.option("--vex <file>", "ingest a CSAF VEX: suppress CVEs marked not_affected/fixed")
	.option("--no-licenses", "skip license detection + copyleft policy check")
	.option("--offline", "no network: use cached CVE/OSV/NVD/EPSS/KEV/POM data only")
	.option("--set-nvd-key <key>", "save NVD API key to ~/.fad-checker/config.json (10× faster NVD enrichment)")
	.option("--show-config", "print the persisted ~/.fad-checker/config.json")
	.option("--export-cache <file>", "tar.gz/zip the ~/.fad-checker/ caches to <file> (excludes config.json by default)")
	.option("--import-cache <file>", "restore ~/.fad-checker/ from a previously exported archive (existing dir is moved to .bak unless --force)")
	.option("--include-config", "with --export-cache: also bundle config.json (contains the NVD API key)")
	.option("--export-anonymized <file>", "offline: write an anonymized dependency descriptor (public coordinates only, no paths/URLs) for PASSI audits, then exit")
	.option("--import-anonymized <file>", "online: scan an anonymized descriptor (no --src) to warm the caches; pair with --export-cache for offline reporting")
	.option("--force", "with --import-cache: replace ~/.fad-checker/ without backup")
	.option("--report-output <dir>", "report output directory", "./fad-checker-report")
	.option("--ignore-test", "skip test-scoped dependencies in report")
	.option("--cve-refresh", "force re-download of CVE database")
	.option("--cve-offline", "use cached CVE index only (no download)")
	.option("--snyk", "run snyk on cleaned POMs and merge into report (requires --target)")
	.option("--no-retire", "skip retire.js vendored-JS scan")
	.option("--retire-refresh", "ignore retire cache and re-scan")
	.option("--transitive-depth <n>", "max transitive depth", "6")
	.option("--ecosystem <list>", "codecs to run: auto|all|<comma list> e.g. maven,npm,nuget,composer,pypi,go,ruby (default: auto = detected)", "auto")
	.option("--no-maven", "skip the Maven codec")
	.option("--no-npm", "skip the npm codec")
	.option("--no-yarn", "skip the Yarn codec")
	.option("--no-nuget", "skip the NuGet (C#/.NET) codec")
	.option("--no-composer", "skip the Composer (PHP) codec")
	.option("--no-pypi", "skip the PyPI (Python) codec")
	.option("--no-go", "skip the Go codec")
	.option("--no-ruby", "skip the Ruby (Bundler) codec")
	.option("--no-binaries", "skip scanning committed native binaries (.dll/.exe/.so/.dylib)")
	.option("--no-jars", "skip scanning embedded .jar/.war/.ear binaries for Maven coordinates")
	.option("--no-js", "alias: skip JS/npm/yarn manifests even if present (Maven-only)")
	.option("--repo <eco=url...>", "extra registry as <ecosystem>=<url> (e.g. npm=https://npm.acme/) tried before the public one. Repeatable. Supports https://user:pass@host/.")
	.option("--add-repo <eco>", "persist a registry: --add-repo <ecosystem> <name> <url> [--auth user:pass] [--token TOK]")
	.option("--remove-repo <eco>", "remove a persisted registry: --remove-repo <ecosystem> <name>")
	.option("--list-repos", "list configured registries (grouped by ecosystem) and exit")
	.option("--auth <user:pass>", "Basic auth for --add-repo")
	.option("--token <token>", "Bearer token for --add-repo")
	.option("--completion <shell>", "print shell completion script (bash|zsh)");
program.parse(process.argv);

const options = program.opts();
// Layered config: CLI flags > config file (--config / ./.fad-env.json, JSON) >
// FAD_CHECKER_ENV (a CLI-flag string) > global ~/.fad-checker/config.json >
// commander defaults. A file/env value fills an option only if the CLI didn't
// set it. `registries` are unioned separately (below). Source has src/source aliases.
const { loadLayers, applyLayers } = require("./lib/options-env");
let _layers = { fileLayer: {}, envLayer: {}, envRepos: [] };
try {
	_layers = loadLayers({ cwd: process.cwd(), configPath: options.config, envStr: process.env.FAD_CHECKER_ENV, program });
} catch (err) {
	console.error(chalk.red(`❌  ${err.message}`));
	process.exit(1);
}
Object.assign(options, applyLayers(program, _layers, require("./lib/config").load()));
// --source CLI alias → src (applyLayers already maps the file/env JSON 'source' key).
if (!options.src && options.source) options.src = options.source;

const deps2Exclude = options.exclude ? new RegExp(options.exclude) : null;
const verbose = !!options.verbose;

// Validate --fail-on early: an unrecognised value (typo like "hgih", wrong case)
// must HARD-FAIL, never silently disable the CI gate.
if (options.failOn) {
	const FAIL_ON_LEVELS = ["none", "low", "medium", "high", "critical", "kev"];
	const lvl = String(options.failOn).toLowerCase();
	if (!FAIL_ON_LEVELS.includes(lvl)) {
		console.error(chalk.red(`❌  invalid --fail-on "${options.failOn}" — expected one of: ${FAIL_ON_LEVELS.join(", ")}`));
		process.exit(2);
	}
	options.failOn = lvl;
}
// Read-only when no target is given. No need for an explicit --test flag.
const readOnly = !options.target;

// --src is required for every mode except --import-anonymized (which scans a
// descriptor and has no source tree).
if (!options.src && !options.importAnonymized) {
	console.error(chalk.red("❌  required option '-s, --src <src>' not specified"));
	process.exit(1);
}
if (options.src && options.importAnonymized) {
	console.warn(chalk.yellow("⚠️  --import-anonymized ignores --src (the descriptor is the source of deps)"));
}

if (options.src && options.target) {
	// --target is rimraf'd before being rewritten, so it must NOT overlap --src in
	// EITHER direction: not the same dir, not a subdir of --src, and — the
	// catastrophic case — not a PARENT of --src (which would delete the source tree
	// and everything beside it).
	const srcAbs = path.resolve(options.src);
	const tgtAbs = path.resolve(options.target);
	const relFromSrc = path.relative(srcAbs, tgtAbs); // target as seen from src
	const relToSrc = path.relative(tgtAbs, srcAbs);   // src as seen from target
	const targetInsideSrc = !relFromSrc || (!relFromSrc.startsWith("..") && !path.isAbsolute(relFromSrc));
	const srcInsideTarget = !relToSrc || (!relToSrc.startsWith("..") && !path.isAbsolute(relToSrc));
	if (targetInsideSrc || srcInsideTarget) {
		console.error(chalk.red("❌  --target must not overlap --src (it cannot be the same as, a subdirectory of, or a parent of --src) — it is deleted before being rewritten"));
		process.exit(1);
	}
}

// Maven Central presence cache (~/.fad-checker/maven-exists-cache.json) — keyed by
// "g:a", value true (on a repo) / false (absent → likely private). Persisted so an
// online warm-up populates it, --export-cache ships it, and an --offline air-gapped
// run reads it instead of probing the network. Returns:
//   true  → present on a configured repo
//   false → absent (likely private)
//   null  → unknown (offline + not cached, or probe error) — caller must NOT guess
const MAVEN_EXISTS_CACHE_PATH = require("path").join(require("./lib/outdated").CACHE_DIR, "maven-exists-cache.json");
const MAVEN_EXISTS_MAX_AGE_MS = 7 * 24 * 3600 * 1000; // 7 days

async function checkMavenLibExist(groupId, artifactId, repos, cache, opts = {}) {
	const g = core.coord(groupId);
	const a = core.coord(artifactId);
	if (!g || !a) return null;
	const key = `${g}:${a}`;
	if (cache && Object.prototype.hasOwnProperty.call(cache.entries, key)) return cache.entries[key];
	if (opts.offline) return null;  // air-gapped + not warmed: honestly unknown, never network
	const p = `${g.replace(/\./g, "/")}/${a}/maven-metadata.xml`;
	const { existsInAny } = require("./lib/maven-repo");
	try {
		const hit = await existsInAny(repos, p, { userAgent: "fad-checker-existence" });
		if (cache) cache.entries[key] = !!hit;
		if (!hit && verbose) console.log(chalk.dim(`   not on any repo: ${g}:${a}`));
		return !!hit;
	} catch (err) {
		if (verbose) console.info(chalk.dim(`   error querying repos: ${g}:${a} — ${err.message}`));
		return null;  // probe failed → unknown, don't poison the cache or mislabel as private
	}
}

/**
 * Build an onProgress callback for the embedded-JAR scan so the user sees what's
 * happening — the scan reads + unzips archives synchronously and can block for a
 * while on big or numerous fat-jars (incl. the silent recursion through a fat-jar's
 * bundled libs). The scanner reports EVERY archive (top-level + nested):
 *   - On a TTY: one transient line, rewritten in place, naming the archive being
 *     read right now (so a long pause clearly points at the culprit). Cleared at end.
 *   - Off a TTY (CI/pipe): a throttled line every ~250 archives so logs show forward
 *     motion without being spammed, plus a start and a final summary line.
 * Returns a fresh closure per codec.
 */
function makeJarProgress() {
	let total = 0, lastLogged = 0;
	const STEP = 250;
	return (ev) => {
		if (!ev) return;
		if (ev.phase === "start") {
			total = ev.total || 0;
			if (total && !ui.isTTY) ui.info(chalk.dim(`scanning ${total} embedded archive(s) (.jar/.war/.ear)…`));
		} else if (ev.phase === "scan" && total) {
			if (ui.isTTY) {
				const head = total ? `${ev.scanned}/${total}+` : String(ev.scanned);
				process.stdout.write(`\r  ${chalk.dim("·")} ${chalk.dim(`reading embedded JARs (${head})`)} ${chalk.dim(ev.path)}\x1b[K`);
			} else if (ev.scanned - lastLogged >= STEP) {
				lastLogged = ev.scanned;
				ui.info(chalk.dim(`… ${ev.scanned} archive(s) read (current: ${ev.path})`));
			}
		} else if (ev.phase === "done") {
			if (total && ui.isTTY) process.stdout.write("\r\x1b[K");
			else if (total && !ui.isTTY) ui.info(chalk.dim(`scanned ${ev.scanned} archive(s) → ${ev.found} embedded coord(s)`));
		}
	};
}

/**
 * Run `fn` (sync or async) while telling the user which phase is in flight, so a
 * long pause is attributable instead of a silent hang. TTY: a transient line that's
 * cleared when done. Non-TTY: a plain "· <label> …" line. Either way, a phase that
 * takes >3s prints "· <label> took Ns" so slow steps self-report even without -v.
 */
async function timedPhase(label, fn) {
	if (ui.isTTY) process.stdout.write(`  ${chalk.dim("·")} ${chalk.dim(label + " …")}\x1b[K`);
	else ui.info(chalk.dim(label + " …"));
	const t0 = Date.now();
	try {
		return await fn();
	} finally {
		const ms = Date.now() - t0;
		if (ui.isTTY) process.stdout.write("\r\x1b[K");
		if (ms > 3000) ui.info(chalk.dim(`${label} took ${(ms / 1000).toFixed(1)}s`));
		else if (verbose) ui.info(chalk.dim(`${label} done in ${ms}ms`));
	}
}

(async function main() {
	ui.banner();

	// Build the Maven repo list once: persisted repos (from ~/.fad-checker/config.json)
	// + ad-hoc --repo URLs + Maven Central as final fallback. Used by transitive
	// resolution, outdated-version check, and existence check.
	const { getRegistryMap } = require("./lib/config");
	const { buildRepoList } = require("./lib/maven-repo");
	const { buildRegistryList } = require("./lib/registries");
	// One-off --repo eco=url (from the CLI and the env layer), grouped by ecosystem.
	const cliRepoMap = {};
	for (const spec of [...(options.repo || []), ...(_layers.envRepos || [])]) {
		const m = /^([a-z]+)=(.+)$/i.exec(String(spec));
		if (!m) { console.error(chalk.red(`❌  --repo expects <ecosystem>=<url>, got "${spec}"`)); process.exit(1); }
		(cliRepoMap[m[1]] ||= []).push({ url: m[2] });
	}
	// Union the registry sources: global config + config-file JSON + CLI/env one-offs.
	const fileRegMap = (_layers.fileLayer && _layers.fileLayer.registries) || {};
	const globalRegMap = getRegistryMap();
	const regMap = {};
	for (const eco of new Set([...Object.keys(globalRegMap), ...Object.keys(fileRegMap), ...Object.keys(cliRepoMap)])) {
		regMap[eco] = buildRegistryList(eco, [globalRegMap[eco], fileRegMap[eco], cliRepoMap[eco]]);
	}
	const registriesFor = eco => regMap[eco] || [];
	const mavenRepos = buildRepoList(regMap.maven || [], []); // appends Maven Central last

	// Walk-pruning: union --exclude-path globs across every config layer (CLI + file
	// + env + global), like registries. `defaultExcludes` (a scalar, false via
	// --no-default-excludes) already flowed through applyLayers.
	const excludePath = [...new Set([
		...(options.excludePath || []),
		...((_layers.fileLayer && _layers.fileLayer.excludePath) || []),
		...((_layers.envLayer && _layers.envLayer.excludePath) || []),
		...(require("./lib/config").get("excludePath") || []),
	].filter(Boolean))];
	const defaultExcludes = options.defaultExcludes !== false;
	const walkOpts = { excludePath, defaultExcludes };
	const runMode = options.importAnonymized ? "import descriptor" : (options.offline ? "offline" : "online");
	if (options.src) ui.kv("source", chalk.white(options.src));
	if (mavenRepos.length > 1) ui.kv("repos", chalk.white(mavenRepos.map(r => r.name).join(chalk.dim(" → "))));
	const otherRegs = Object.keys(regMap).filter(e => e !== "maven" && regMap[e].length);
	if (otherRegs.length) ui.kv("registries", chalk.white(otherRegs.map(e => `${e}:${regMap[e].length}`).join(" ")));
	if (excludePath.length) ui.kv("exclude-path", chalk.white(excludePath.join(chalk.dim(", "))));
	if (!defaultExcludes) ui.kv("default-excludes", chalk.yellow("off (walking node_modules/vendor/.git/…)"));
	ui.kv("mode", chalk.white(runMode));

	let wrotePom = 0;

	// --- PASSI phase 2: import an anonymized descriptor instead of collecting ---
	// Scans the descriptor's public coordinates online to WARM the coordinate-keyed
	// caches (OSV/NVD/CVE/registry/EOL) + retire signatures. Pair with --export-cache.
	if (options.importAnonymized) {
		const { deserializeDeps } = require("./lib/deps-descriptor");
		let descriptor;
		try { descriptor = JSON.parse(fs.readFileSync(options.importAnonymized, "utf8")); }
		catch (e) { console.error(chalk.red(`❌  could not read --import-anonymized file: ${e.message}`)); process.exit(1); }
		let imported;
		try { imported = deserializeDeps(descriptor); }
		catch (e) { console.error(chalk.red(`❌  invalid descriptor: ${e.message}`)); process.exit(1); }
		const { resolved, activeIds, runMaven, runNpm } = imported;
		ui.section("Anonymized descriptor");
		ui.ok(`imported ${chalk.bold(resolved.size)} dep(s) across ${activeIds.join(", ") || "—"}`);
		if (options.offline) ui.warn("--offline: caches won't warm; only useful to re-render from an already-warm cache");
		if (!resolved.size) { ui.warn("descriptor has no dependencies — nothing to scan"); process.exit(0); }
		// Warm retire signatures (online) so --export-cache carries them for offline JS scanning.
		if (runNpm && !options.offline && options.retire !== false) {
			const { warmRetireSignatures } = require("./lib/retire");
			await warmRetireSignatures({ verbose });
		}
		await runReportFlow(resolved, { activeIds, runMaven, runNpm, privateLibIds: [], mavenRepos, regMap, collectWarnings: [] });
		return;
	}

	// --- Codec detection + selection ---
	const { detectCodecs, allCodecs, getCodec } = require("./lib/codecs");
	const { resolveActiveCodecs } = require("./lib/codecs/select");
	const eco = (options.ecosystem || "auto").toLowerCase();
	const detected = (eco === "auto")
		? (await timedPhase("detecting ecosystems", () => detectCodecs(options.src, walkOpts))).map(c => c.id)
		: allCodecs().map(c => c.id);
	// The binary scanner is a cross-cutting catch-all (committed native libs in ANY
	// project), and detectCodecs' manifest-glob matcher misses versioned sonames
	// (libz.so.1). Always make it a candidate in auto mode; --no-binaries removes it.
	if (eco === "auto" && !detected.includes("binary")) detected.push("binary");
	const noCodecs = ["maven", "npm", "yarn", "nuget", "composer", "pypi", "go", "ruby"].filter(id => options[id] === false);
	// `--no-binaries` maps to options.binaries (plural) but the codec id is `binary`.
	if (options.binaries === false) noCodecs.push("binary");
	const activeIds = resolveActiveCodecs(eco, detected, { noCodecs, noJs: !options.js });
	const runMaven = activeIds.includes("maven");
	const runNpm = activeIds.includes("npm") || activeIds.includes("yarn");

	// --- Collect deps from every active codec into one Map (coordKeys never collide) ---
	// Section header first so the embedded-JAR scan can print live progress under it
	// (the scan reads + unzips archives synchronously and would otherwise block silently).
	ui.section("Collection");
	const resolved = new Map();
	let mavenCtx = null;
	const collectWarnings = [];
	for (const id of activeIds) {
		if (id === "yarn") continue;   // the npm codec already collects yarn.lock
		const codec = getCodec(id);
		let res;
		try {
			res = await timedPhase(`collecting ${codec.label || id}`, () => codec.collect(options.src, { ignoreTest: !!options.ignoreTest, deps2Exclude, verbose, scanJars: options.jars !== false, srcRoot: options.src, excludePath, defaultExcludes, onJarProgress: makeJarProgress(), onBinaryProgress: null }));
		} catch (err) {
			console.warn(chalk.red(`❌  ${id} collect failed:`), chalk.dim(err.message));
			continue;
		}
		for (const [k, v] of res.deps) resolved.set(k, v);
		if (res.warnings?.length) collectWarnings.push(...res.warnings);
		if (id === "maven") mavenCtx = res._maven;
	}

	// --- Collection summary ---
	const ecoCount = {};
	let embeddedCount = 0;
	let binaryCount = 0;
	for (const d of resolved.values()) {
		if (d.provenance === "embedded") { embeddedCount++; continue; } // counted separately below
		if (d.provenance === "binary") { binaryCount++; continue; }     // committed native libs, no manifest
		ecoCount[d.ecosystem] = (ecoCount[d.ecosystem] || 0) + 1;
	}
	if (runMaven) ui.ok(`${chalk.bold("Maven".padEnd(8))} ${mavenCtx ? mavenCtx.pomFiles.length + " module(s) · " : ""}${ecoCount.maven || 0} direct dep(s)`);
	if (runNpm)   ui.ok(`${chalk.bold("npm/yarn".padEnd(8))} ${ecoCount.npm || 0} dep(s)`);
	for (const [id, n] of Object.entries(ecoCount)) {
		if (id === "maven" || id === "npm") continue;
		ui.ok(`${chalk.bold(((getCodec(id)?.label) || id).padEnd(8))} ${n} dep(s)`);
	}
	if (embeddedCount) ui.ok(`${chalk.bold("Embedded".padEnd(8))} ${embeddedCount} coord(s) in .jar/.war/.ear`);
	if (binaryCount) ui.ok(`${chalk.bold("Binary".padEnd(8))} ${binaryCount} native lib(s) (.dll/.exe/.so/.dylib)`);
	if (!ecoCount.maven && !ecoCount.npm && !Object.keys(ecoCount).length) ui.warn("no dependencies found in the source tree");
	if (collectWarnings.length) {
		ui.warn(`${collectWarnings.length} manifest warning(s) — best-effort / no lockfile:`);
		for (const w of collectWarnings.slice(0, 5)) ui.info(chalk.dim(w.message));
		if (collectWarnings.length > 5) ui.info(chalk.dim(`…and ${collectWarnings.length - 5} more`));
	}

	// --- PASSI phase 1: export an anonymized descriptor and exit (no network, no report) ---
	if (options.exportAnonymized) {
		const { serializeDeps } = require("./lib/deps-descriptor");
		const pkgVersion = require("./package.json").version;
		const descriptor = serializeDeps(resolved, { generator: `fad-checker ${pkgVersion}` });
		try { fs.writeFileSync(options.exportAnonymized, JSON.stringify(descriptor, null, 2) + "\n"); }
		catch (e) { console.error(chalk.red(`❌  could not write --export-anonymized file: ${e.message}`)); process.exit(1); }
		const ecoSummary = Object.entries(descriptor.summary.byEcosystem).map(([k, v]) => `${k}:${v}`).join(", ");
		ui.section("Anonymized export");
		ui.ok(`${chalk.bold(descriptor.summary.total)} dep(s) (${ecoSummary || "none"}) → ${chalk.white(options.exportAnonymized)}`);
		ui.info(chalk.dim("public coordinates only — no paths/URLs/host info. Review before transfer."));
		if (!descriptor.summary.total) ui.warn("no dependencies collected — descriptor is empty");
		return;
	}

	if (!readOnly) {
		try { await rimraf(options.target); } catch (_) { /* fresh dir */ }
	}

	// Maven POM rewrite (cleanup feature). Parse + inheritance already happened
	// inside the maven codec's collect(); we reuse its metadata store here.
	if (runMaven && mavenCtx) {
		const { store, propsByPom, pomFiles } = mavenCtx;
		const rewriteOpts = { srcRoot: options.src, targetRoot: options.target, deps2Exclude, verbose, readOnly };
		for (const pom of pomFiles) {
			try {
				if (await core.rewritePoms(pom, store, propsByPom, rewriteOpts)) wrotePom++;
			} catch (err) {
				console.error(chalk.red(`  ✗ rewrite failed for ${pom}:`), err.message);
			}
		}
	}

	// ---------- Maven POM analysis summary (parents missing / excluded) ----------
	let privateLibIds = [];
	if (runMaven && mavenCtx) {
		const allPomMetadata = mavenCtx.store;   // reuse the codec's parsed metadata
		ui.section("Maven POM analysis");

		const missingParents = Object.keys(allPomMetadata.missingById)
			.filter(id => {
				const parts = id.split(":");
				if (parts.length === 2) return false;
				return !(allPomMetadata.byId[id] || allPomMetadata.byId[`${parts[0]}:${parts[1]}`]);
			});
		if (missingParents.length) {
			ui.warn(`${missingParents.length} missing parent POM(s) — Snyk will fail if these are private:`);
			for (const id of missingParents.slice(0, 10)) ui.info(chalk.yellow(id));
			if (missingParents.length > 10) ui.info(chalk.dim(`…and ${missingParents.length - 10} more`));
		} else {
			ui.ok("no missing Maven parent POMs");
		}

		// Private-lib detection asks each configured repo whether a missing coord
		// exists (→ absent = likely private). Results are cached + bundled, so an
		// --offline run reads the online-warmed cache instead of probing the network.
		// A coord that's neither cached nor probeable (offline + cold) stays UNKNOWN —
		// we never fake it as "private", which is what made offline both wrong and slow.
		if (options.allLibs) {
			const { loadJsonCache, saveJsonCache } = require("./lib/outdated");
			const existsCache = loadJsonCache(MAVEN_EXISTS_CACHE_PATH);
			const fresh = existsCache.meta?.fetchedAt && (Date.now() - existsCache.meta.fetchedAt) < MAVEN_EXISTS_MAX_AGE_MS;
			if (!fresh && !options.offline) existsCache.entries = {};   // refresh stale probes when online
			if (!existsCache.entries) existsCache.entries = {};

			const anyMissingLibs = Object.keys(allPomMetadata.anyMissingById)
				.filter(id => {
					const parts = id.split(":");
					if (parts.length === 3) return false;
					return !(allPomMetadata.byId[id] || allPomMetadata.byId[`${parts[0]}:${parts[1]}`]);
				});
			const limit = pLimit(10);
			const results = await Promise.all(anyMissingLibs.map(id => {
				const [g, a] = id.split(":");
				return limit(async () => ({ id, found: await checkMavenLibExist(g, a, mavenRepos, existsCache, { offline: options.offline }) }));
			}));
			let unknown = 0;
			for (const r of results) {
				if (r.found === false) privateLibIds.push(r.id);
				else if (r.found === null) unknown++;
			}
			if (!options.offline) { existsCache.meta = { fetchedAt: Date.now() }; saveJsonCache(MAVEN_EXISTS_CACHE_PATH, existsCache); }
			if (privateLibIds.length) {
				ui.warn(`${privateLibIds.length} lib(s) absent from Maven Central (likely private):`);
				for (const id of privateLibIds.slice(0, 10)) ui.info(chalk.magenta(id));
				if (privateLibIds.length > 10) ui.info(chalk.dim(`…and ${privateLibIds.length - 10} more`));
			}
			if (unknown) ui.info(chalk.dim(`${unknown} lib(s) not in the presence cache — run online once (or --export-cache from an online host) to classify them`));
		}

		if (deps2Exclude) {
			const excludedLibs = Object.keys(allPomMetadata.excludedById)
				.filter(id => {
					const parts = id.split(":");
					if (parts.length === 2) return false;
					return !(allPomMetadata.byId[id] || allPomMetadata.byId[`${parts[0]}:${parts[1]}`]);
				});
			if (excludedLibs.length) {
				ui.warn(`${excludedLibs.length} excluded-and-missing library(ies):`);
				for (const id of excludedLibs.slice(0, 10)) ui.info(chalk.magenta(id));
				if (excludedLibs.length > 10) ui.info(chalk.dim(`…and ${excludedLibs.length - 10} more`));
			} else {
				ui.ok("no excluded-and-missing libraries");
			}
		}

		if (!readOnly) ui.ok(`${chalk.bold(wrotePom)} cleaned POM(s) written → ${chalk.white(options.target)}`);
		else ui.info(chalk.dim(`${wrotePom} POM(s) cleanable (read-only — pass -t <dir> to write them)`));
	}

	// ---------- Scan flow (CVE / EOL / Obsolete) ----------
	// The scan always runs — it feeds the terminal summary, the file outputs and the
	// CI gate. Which files get written is decided by the --report-* family inside
	// (HTML + .doc by default; --no-report writes nothing).
	await runReportFlow(resolved, { activeIds, runMaven, runNpm, privateLibIds, mavenRepos, regMap, collectWarnings });
	if (!readOnly) {
		ui.section("Next step");
		ui.info(`run Snyk on the cleaned tree:`);
		console.log("    " + chalk.white(`cd ${options.target} && snyk test --json --all-projects | snyk-to-html -o ../snyk-deps-check.html`));
	}
})();

async function runReportFlow(resolved, ecoFlags = {}) {
	const { activeIds = [], runMaven = true, runNpm = false, privateLibIds = [], mavenRepos = [], regMap = {}, collectWarnings = [] } = ecoFlags;
	const registriesFor = eco => regMap[eco] || [];
	const { expandWithTransitives } = require("./lib/cve-match");
	const { writeReports, computeStats } = require("./lib/cve-report");
	const { getCodec } = require("./lib/codecs");
	const outdated = require("./lib/outdated");
	const { getNvdApiKey } = require("./lib/config");
	const offline = !!options.offline;

	// Collection counts already shown in the "Collection" section by main();
	// for --import-anonymized they were shown in the "Anonymized descriptor" section.
	const npmWarnings = collectWarnings || [];
	let scanWarnings = [];
	const directCount = resolved.size;

	// Scan-completeness signals: BOMs and unresolved-version deps mean fad-checker
	// has gone as far as it can without running Maven/Snyk itself.
	if (runMaven) {
		const { detectScanCompletenessWarnings } = require("./lib/scan-completeness");
		scanWarnings = detectScanCompletenessWarnings(resolved, { ranSnyk: !!options.snyk, ranTransitive: !!options.transitive });
	}

	// ---- Vulnerability database update (global step progress) ----
	ui.section("Vulnerability database update");
	if (offline) ui.info(chalk.dim("--offline: cached data only, no network"));

	const hasNvdKey = !!getNvdApiKey();
	if (options.nvd && !offline && !hasNvdKey) {
		ui.warn(chalk.yellow("No NVD API key — enrichment throttled to 5 req/30s (slow)."));
		ui.info(chalk.dim("Free & instant key: https://nvd.nist.gov/developers/request-an-api-key"));
		ui.info(chalk.dim("then: fad-checker --set-nvd-key <KEY>"));
	}

	// Decide which update steps will run (from flags) so the [n/N] counter is accurate.
	const cveScanner = runMaven ? (getCodec("maven").nativeScanners || []).find(s => s.kind === "cve") : null;
	const cveIndexExists = fs.existsSync(require("./lib/cve-download").CVE_INDEX_PATH);
	const otherRegistryIds = activeIds.filter(id => id !== "maven" && id !== "npm" && id !== "yarn" && getCodec(id)?.checkRegistry);
	const willCve = !!cveScanner && (!(options.cveOffline || offline) || cveIndexExists);
	const willTransitive = !!(options.transitive && runMaven);
	const willOsv = !!options.osv;
	const willOutdated = !!options.allLibs;
	const willNvd = !!options.nvd;
	const willEpss = !!options.epss;
	const willKev = !!options.kev;
	const willLicenses = !!options.licenses;
	const willRetire = !!options.retire;
	// Identify committed native binaries by checksum (deps.dev + CIRCL) when present.
	const willBinaryId = [...resolved.values()].some(d => d.provenance === "binary");
	// License detection piggybacks on the registry passes (same fetched metadata),
	// so it adds no progress step of its own.
	const totalSteps = [willTransitive, willCve, /*EOL*/ true, willOutdated, /*npm reg*/ true, ...otherRegistryIds.map(() => true), willOsv, willNvd, willEpss, willKev, willRetire, willBinaryId].filter(Boolean).length;
	const progress = new ui.Progress(totalSteps);

	if (willTransitive) {
		const st = progress.start("Transitive resolution (Maven Central)");
		await expandWithTransitives(resolved, {
			verbose,
			offline,
			maxDepth: parseInt(options.transitiveDepth, 10) || 6,
			includeTestDeps: !options.ignoreTest,
			repos: mavenRepos,
		});
		st.done(`+${resolved.size - directCount} transitive (total ${resolved.size})`);
	}

	// 1. CVE — native scanner contributed by the maven codec (local cvelistV5 index).
	let cveMatches = [];
	let cveDataDate = null;
	if (willCve) {
		const st = progress.start("CVE index (CVEProject)");
		try {
			const r = await cveScanner.scan(resolved, { cveRefresh: !!options.cveRefresh, cveOffline: !!options.cveOffline, offline, verbose });
			cveMatches = r.matches || [];
			cveDataDate = r.meta?.cveDataDate || null;
			st.done(`${cveMatches.length} match(es)${cveDataDate ? ` · ${String(cveDataDate).slice(0, 10)}` : ""}`);
		} catch (err) {
			st.fail(err.message);
		}
	}

	// 1c. Identify committed native binaries by checksum (deps.dev → CIRCL).
	if (willBinaryId) {
		const st = progress.start("Binary identification (deps.dev + CIRCL)");
		try {
			const { enrichUnmanaged } = require("./lib/unmanaged");
			const s = await enrichUnmanaged(resolved, { offline, onProgress: (p, t) => st.tick(p, t) });
			const bits = [`${s.identified}/${s.total} identified`, s.pristine ? `${s.pristine} pristine` : null, s.unknown ? `${s.unknown} unknown` : null, s.malicious ? `${s.malicious} ⚠ malicious` : null].filter(Boolean).join(", ");
			st.done(bits);
		} catch (err) { st.fail(err.message); }
	}

	// 2. EOL frameworks (endoflife.date) — always a step.
	let eolResults = [];
	{
		const st = progress.start("EOL frameworks (endoflife.date)");
		try { eolResults = await outdated.checkEolDeps(resolved, { verbose, offline }); st.done(`${eolResults.length} EOL`); }
		catch (err) { st.fail(err.message); }
	}

	// License findings accumulate from each registry pass (same fetched metadata)
	// plus Maven's cached POMs — assessed against the copyleft policy below.
	let licenseFindings = [];

	// 3. Obsolete / deprecated — local curated list, instant (no network step).
	let obsoleteResults = [];
	try { obsoleteResults = outdated.checkObsoleteDeps(resolved); }
	catch (err) { ui.warn(`obsolete check skipped: ${err.message}`); }

	// 4. Outdated (latest Maven Central) — gated by --all-libs.
	let outdatedResults = [];
	if (willOutdated) {
		const st = progress.start("Maven Central (outdated)");
		try {
			outdatedResults = await outdated.checkOutdatedDeps(resolved, { verbose, offline, repos: mavenRepos, onProgress: (p, t) => st.tick(p, t) });
			st.done(`${outdatedResults.length} outdated`);
		} catch (err) { st.fail(err.message); }
	}

	// 4a. npm registry — deprecation (always, authoritative) + outdated (with --all-libs).
	// Covers npm deps and WebJars, so it runs even in Maven-only mode.
	{
		const st = progress.start("npm registry");
		try {
			const { checkNpmRegistryDeps } = require("./lib/codecs/npm/registry");
			const npmReg = await checkNpmRegistryDeps(resolved, { verbose, offline, allLibs: options.allLibs, registries: registriesFor("npm"), onProgress: (p, t) => st.tick(p, t) });
			obsoleteResults = obsoleteResults.concat(npmReg.deprecated);
			outdatedResults = outdatedResults.concat(npmReg.outdated);
			licenseFindings = licenseFindings.concat(npmReg.licensed || []);
			st.done(`${npmReg.deprecated.length} deprecated, ${npmReg.outdated.length} outdated`);
		} catch (err) { st.fail(err.message); }
	}

	// 4b. Per-codec registry for ecosystems beyond maven/npm (composer/pypi/nuget).
	for (const id of otherRegistryIds) {
		const codec = getCodec(id);
		const st = progress.start(`${codec.label || id} registry`);
		try {
			const reg = await codec.checkRegistry(resolved, { verbose, offline, allLibs: options.allLibs, registries: registriesFor(id), onProgress: (p, t) => st.tick(p, t) });
			obsoleteResults = obsoleteResults.concat(reg.deprecated || []);
			outdatedResults = outdatedResults.concat(reg.outdated || []);
			licenseFindings = licenseFindings.concat(reg.licensed || []);
			st.done(`${(reg.deprecated || []).length} deprecated, ${(reg.outdated || []).length} outdated`);
		} catch (err) { st.fail(err.message); }
	}

	// Cross-section dedup: drop entries from outdated that already appear in EOL/Obsolete
	const eolKeys = new Set(eolResults.map(r => `${r.dep.groupId}:${r.dep.artifactId}`));
	const obsKeys = new Set(obsoleteResults.map(r => `${r.dep.groupId}:${r.dep.artifactId}`));
	outdatedResults = outdatedResults.filter(r => {
		const k = `${r.dep.groupId}:${r.dep.artifactId}`;
		return !eolKeys.has(k) && !obsKeys.has(k);
	});

	// 4b. OSV.dev — Maven-native CVE+GHSA feed (huge recall win over raw CVEProject)
	if (willOsv) {
		const st = progress.start("OSV.dev");
		try {
			const { queryOsvForDeps } = require("./lib/osv");
			const osvMatches = await queryOsvForDeps(resolved, { verbose, offline, onProgress: (p, t) => st.tick(p, t) });
			const before = cveMatches.length;
			cveMatches = mergeBySource(cveMatches, osvMatches);
			st.done(`${osvMatches.length} vulns · +${cveMatches.length - before} after merge`);
		} catch (err) {
			st.fail(err.message);
		}
	}

	// 4c. NVD enrichment — canonical description + full CVSS for matched CVEs.
	if (willNvd) {
		const st = progress.start("NVD enrichment");
		if (!cveMatches.length) {
			st.skip("no CVE to enrich");
		} else {
			try {
				const { enrichMatches } = require("./lib/nvd");
				await enrichMatches(cveMatches, { verbose, offline, onProgress: (p, t) => st.tick(p, t) });
				// 4d. CPE refinement — use NVD's CPE configurations to upgrade match
				// confidence and flag likely false positives (version outside CPE range).
				let filtered = 0;
				try {
					const { refineMatchesWithCpe } = require("./lib/cpe");
					refineMatchesWithCpe(cveMatches);
					filtered = cveMatches.filter(m => m.cpeFiltered).length;
				} catch (err) { ui.warn(`CPE refinement skipped: ${err.message}`); }
				const uniqueCves = new Set(cveMatches.map(m => m.cve?.id)).size;
				st.done(`${uniqueCves} CVE${filtered ? ` · ${filtered} false-positive(s) filtered` : ""}${hasNvdKey ? "" : " · no key (slow)"}`);
			} catch (err) { st.fail(err.message); }
		}
	}

	// 4e. EPSS — exploit-prediction percentile for each matched CVE (FIRST.org).
	if (willEpss) {
		const st = progress.start("EPSS (FIRST.org)");
		if (!cveMatches.length) { st.skip("no CVE"); }
		else {
			try {
				const { enrichEpss } = require("./lib/epss");
				await enrichEpss(cveMatches, { verbose, offline, onProgress: (p, t) => st.tick(p, t) });
				const scored = cveMatches.filter(m => m.cve?.epssPercentile != null).length;
				st.done(`${scored} scored`);
			} catch (err) { st.fail(err.message); }
		}
	}

	// 4f. CISA KEV — flag CVEs known to be exploited in the wild.
	if (willKev) {
		const st = progress.start("CISA KEV");
		if (!cveMatches.length) { st.skip("no CVE"); }
		else {
			try {
				const { enrichKev } = require("./lib/kev");
				await enrichKev(cveMatches, { verbose, offline });
				const kevd = cveMatches.filter(m => m.cve?.kev).length;
				st.done(`${kevd} known-exploited`);
			} catch (err) { st.fail(err.message); }
		}
	}

	// 4g. Composite priority (KEV > EPSS-weighted CVSS). Always — cheap, pure.
	try {
		const { attachPriority } = require("./lib/priority");
		attachPriority(cveMatches);
	} catch (err) { ui.warn(`priority scoring skipped: ${err.message}`); }

	// 5. retire.js — native "vendored" scanner contributed by the npm codec. Scans
	//    vendored JS files (jquery copies, bootstrap, pdf.js, …) that live in the
	//    source tree without any lockfile to back them.
	// Not gated by an active npm ecosystem: retire scans the source tree for
	// vendored .js (which can live in a Maven project's resources too). The
	// scanner is owned by the npm codec but runs whenever --retire is on.
	let retireMatches = [];
	if (willRetire) {
		const st = progress.start("retire.js (vendored JS)");
		const sc = (getCodec("npm").nativeScanners || []).find(s => s.kind === "vendored");
		if (!sc) { st.skip("scanner unavailable"); }
		else if (!options.src) { st.skip("no source tree (descriptor import)"); }
		else {
			try {
				const r = await sc.scan(resolved, { src: options.src, verbose, retireRefresh: !!options.retireRefresh, offline });
				retireMatches = r.matches || [];
				st.done(`${retireMatches.length} finding(s)`);
			} catch (err) { st.fail(err.message); }
		}
	}

	// 6. Snyk (optional)
	let snykMatches = [];
	if (options.snyk) {
		if (!options.target) {
			ui.warn("--snyk requires --target (snyk runs on cleaned POMs)");
		} else {
			const snyk = require("./lib/snyk");
			try {
				const raw = await snyk.runSnykTest(options.target, { verbose });
				snykMatches = snyk.parseSnykResults(raw);
				cveMatches = snyk.mergeWithFadResults(cveMatches, snykMatches);
				ui.ok(`Snyk: ${snykMatches.length} findings merged`);
			} catch (err) {
				ui.warn(`Snyk run failed: ${err.message}`);
			}
		}
	}

	// Split prod vs dev based on the dep's isDev flag (set at collection time
	// from Maven scope=test/provided and npm dev/devOptional/optional). Keep the
	// full per-bucket list (including cpeFiltered) so the HTML report can render
	// its "Likely false positives" appendix — only the CLI headline excludes
	// cpeFiltered to avoid alarming on triaged-out matches.
	// Triage — suppress accepted-risk / false-positive findings (--ignore / --vex).
	// Marked in place; kept in the machine exports (flagged) but dropped from the
	// human report's active chapters and from CI gating.
	let suppressedCount = 0;
	if (options.ignore || options.vex) {
		try {
			const { parseIgnoreFile, parseVex, applySuppressions } = require("./lib/suppress");
			const rules = [];
			if (options.ignore) rules.push(...parseIgnoreFile(fs.readFileSync(options.ignore, "utf8")));
			if (options.vex) rules.push(...parseVex(JSON.parse(fs.readFileSync(options.vex, "utf8"))));
			suppressedCount = applySuppressions(cveMatches, rules);
			const via = [options.ignore && "--ignore", options.vex && "--vex"].filter(Boolean).join(" + ");
			if (suppressedCount) ui.info(chalk.dim(`triage: ${suppressedCount} finding(s) suppressed by ${via}`));
		} catch (err) { ui.warn(`suppression skipped: ${err.message}`); }
	}

	const { sortByPriority } = require("./lib/priority");
	const isEmbedded  = m => m.dep?.provenance === "embedded";
	// Embedded-binary findings get their own chapter, so keep them out of the
	// declared prod/dev sets (a coord that's both declared AND embedded yields two
	// distinct records — one in each — which is the intended, audit-useful split).
	const prodMatches     = cveMatches.filter(m => !m.dep?.isDev && !m.suppressed && !isEmbedded(m));
	const devMatches      = cveMatches.filter(m =>  m.dep?.isDev && !m.suppressed && !isEmbedded(m));
	const embeddedMatches = cveMatches.filter(m => isEmbedded(m) && !m.suppressed);
	const prodActive  = sortByPriority(prodMatches.filter(m => !m.cpeFiltered));
	const devActive   = sortByPriority(devMatches.filter(m => !m.cpeFiltered));
	const embeddedActive = sortByPriority(embeddedMatches.filter(m => !m.cpeFiltered));
	const kevCount    = prodActive.filter(m => m.cve?.kev).length;
	const cpeFilteredCount = (prodMatches.length - prodActive.length) + (devMatches.length - devActive.length);

	const stats = computeStats(prodActive);
	const devStats = computeStats(devActive);
	const sev = ui.sevColor;
	const depLabel = d => d.ecosystem === "npm" ? `npm:${d.artifactId}` : `${d.groupId}:${d.artifactId}`;
	const coordOf = depLabel;   // npm deps show as "npm:name", others as "g:a"
	// Where a finding's dependency was declared — the pom.xml / package.json / jar
	// (embedded jars carry a "app.jar!/BOOT-INF/lib/…" manifestPath). Shown so EOL /
	// obsolete / outdated entries point at the file the reader has to edit.
	const definedInOf = d => {
		const paths = (d?.manifestPaths?.length ? d.manifestPaths : d?.pomPaths?.length ? d.pomPaths : []);
		if (!paths.length) return "";
		const rel = paths.map(p => { try { return path.relative(options.src, p); } catch { return p; } });
		return chalk.dim(`  ← ${rel[0]}${rel.length > 1 ? ` (+${rel.length - 1})` : ""}`);
	};
	const fmtStats = s => [
		s.critical ? sev("CRITICAL")(`${s.critical} critical`) : null,
		s.high ? sev("HIGH")(`${s.high} high`) : null,
		s.medium ? sev("MEDIUM")(`${s.medium} medium`) : null,
		s.low ? sev("LOW")(`${s.low} low`) : null,
		s.unknown ? chalk.gray(`${s.unknown} unknown`) : null,
	].filter(Boolean).join("  ") || chalk.gray("none");
	const heading = (label, n, extra = "") => console.log("\n  " + chalk.bold(label) + chalk.dim(`  (${n})`) + (extra ? "  " + extra : ""));

	ui.section("Results");

	heading("CVE · production", prodActive.length, fmtStats(stats) + (kevCount ? "  " + chalk.bgRed.white(` ${kevCount} KEV `) : ""));
	for (const m of prodActive.slice(0, 12)) {
		const epss = m.cve?.epssPercentile != null ? chalk.dim(` epss ${Math.round(m.cve.epssPercentile * 100)}%`) : "";
		const kev = m.cve?.kev ? " " + chalk.bgRed.white(" KEV ") : "";
		console.log("    " + sev(m.cve.severity)((m.cve.severity || "UNKNOWN").padEnd(8)) + " " + chalk.white(m.cve.id) + "  " + chalk.dim(`${depLabel(m.dep)}:${m.dep.version}`) + epss + kev);
	}
	if (prodActive.length > 12) console.log(chalk.dim(`    …and ${prodActive.length - 12} more (see report)`));
	if (cpeFilteredCount) console.log(chalk.dim(`    ${cpeFilteredCount} likely false positive(s) → report appendix`));

	heading("CVE · dev", devActive.length, devActive.length ? fmtStats(devStats) : "");

	if (embeddedActive.length) {
		heading("CVE · embedded binaries", embeddedActive.length, fmtStats(computeStats(embeddedActive)));
		for (const m of embeddedActive.slice(0, 8)) {
			const top = (m.dep.manifestPaths?.[0] || "").split("!/")[0];
			console.log("    " + sev(m.cve.severity)((m.cve.severity || "UNKNOWN").padEnd(8)) + " " + chalk.white(m.cve.id) + "  " + chalk.dim(`${depLabel(m.dep)}:${m.dep.version}`) + chalk.dim(`  ⊂ ${top}`));
		}
		if (embeddedActive.length > 8) console.log(chalk.dim(`    …and ${embeddedActive.length - 8} more (see report ch.1B)`));
	}

	{
		const { buildInventory } = require("./lib/unmanaged");
		const inv = buildInventory(resolved);
		if (inv.length) {
			heading("Unmanaged binaries", inv.length);
			for (const e of inv.slice(0, 10)) {
				const id = e.identity ? `${e.identity.ecosystem ? e.identity.ecosystem + ":" : ""}${e.identity.name || ""}${e.identity.version ? "@" + e.identity.version : ""}` : chalk.dim("unknown");
				const flags = [e.knownMalicious ? chalk.bgRed.white(" malicious ") : null, e.nameMismatch ? chalk.yellow("name≠checksum") : null, e.shouldBeManaged ? chalk.cyan("should-be-managed") : null, (e.noOnlineInfo ? chalk.dim("unknown") : null)].filter(Boolean).join(" ");
				console.log("    " + chalk.white(path.basename(String(e.path))) + "  " + chalk.dim(id) + (flags ? "  " + flags : ""));
			}
			if (inv.length > 10) console.log(chalk.dim(`    …and ${inv.length - 10} more (see report ch.1C)`));
		}
	}

	heading("EOL frameworks", eolResults.length);
	for (const e of eolResults.slice(0, 8)) console.log("    " + chalk.yellow(e.product.padEnd(18)) + " " + chalk.dim(`${coordOf(e.dep)}:${e.dep.version}`) + " " + chalk.dim(e.eol === true ? "EOL" : String(e.eol)) + definedInOf(e.dep));
	if (eolResults.length > 8) console.log(chalk.dim(`    …and ${eolResults.length - 8} more`));

	heading("Obsolete / deprecated", obsoleteResults.length);
	for (const o of obsoleteResults.slice(0, 8)) console.log("    " + chalk.dim(`${coordOf(o.dep)}:${o.dep.version}`) + " → " + (o.replacement || chalk.dim("n/a")) + definedInOf(o.dep));
	if (obsoleteResults.length > 8) console.log(chalk.dim(`    …and ${obsoleteResults.length - 8} more`));

	heading("Outdated", outdatedResults.length, options.allLibs ? "" : chalk.dim("pass -a/--allLibs to query registries"));
	for (const o of outdatedResults.slice(0, 8)) console.log("    " + chalk.dim(coordOf(o.dep)) + ` ${o.dep.version} → ${chalk.green(o.latest)}` + definedInOf(o.dep));
	if (outdatedResults.length > 8) console.log(chalk.dim(`    …and ${outdatedResults.length - 8} more`));

	if (retireMatches.length) {
		heading("Vendored JS (retire.js)", retireMatches.length);
		for (const m of retireMatches.slice(0, 8)) console.log("    " + sev(m.cve.severity)((m.cve.severity || "?").padEnd(8)) + " " + chalk.white(m.cve.id) + " " + chalk.dim(`${m.dep.artifactId}@${m.dep.version}`));
		if (retireMatches.length > 8) console.log(chalk.dim(`    …and ${retireMatches.length - 8} more`));
	}

	if (scanWarnings.length) {
		console.log();
		ui.warn(`${scanWarnings.length} scan-completeness note(s) — a real Maven/Snyk run may surface more:`);
		for (const w of scanWarnings) {
			ui.info(chalk.dim(`[${w.type}] ${w.message}`));
			for (const it of (w.items || []).slice(0, 4)) console.log("      " + chalk.dim(`· ${it}`));
			if ((w.items || []).length > 4) console.log("      " + chalk.dim(`· …and ${w.items.length - 4} more`));
		}
	}

	// License assessment — Maven licenses come (network-free) from cached POMs;
	// the registry passes already filled licenseFindings for the other ecosystems.
	let licenseResults = null;
	if (willLicenses) {
		try {
			if (runMaven) {
				const { collectMavenLicenses } = require("./lib/maven-license");
				licenseFindings = licenseFindings.concat(collectMavenLicenses(resolved));
			}
			const { assessLicenses } = require("./lib/license-policy");
			licenseResults = assessLicenses(licenseFindings);
			const flaggedN = licenseResults.flagged.length;
			heading("Licenses", licenseResults.assessed.length, flaggedN ? chalk.yellow(`${flaggedN} to review`) : "");
			for (const e of licenseResults.flagged.slice(0, 8)) {
				console.log("    " + chalk.yellow((e.category).padEnd(16)) + " " + chalk.dim(`${coordOf(e.dep)}`) + " " + chalk.dim((e.ids.concat(e.raw)).join(", ") || "—"));
			}
			if (licenseResults.flagged.length > 8) console.log(chalk.dim(`    …and ${licenseResults.flagged.length - 8} more`));
		} catch (err) { ui.warn(`license assessment skipped: ${err.message}`); }
	}

	const reportDir = options.reportOutput || "./fad-checker-report";
	// --import-anonymized has no source tree; keep the report path-free (consistent
	// with the anonymized descriptor it was fed).
	const srcResolved = options.src ? path.resolve(options.src) : null;
	const projectInfo = {
		name: srcResolved ? path.basename(srcResolved) : "anonymized-descriptor",
		src: srcResolved || "(anonymized descriptor — source path withheld)",
		generatedAt: new Date().toISOString(),
		toolVersion: pkg.version,
		cveDataDate,
	};

	// --- Output target resolution -------------------------------------------------
	// One --report-<type> flag per output, each taking an OPTIONAL path: a string is
	// an explicit path, `true` means "use the default name under --report-output",
	// undefined means "not requested". If NO --report-* flag is given at all, fall
	// back to the historical default set (HTML + .doc). --no-report suppresses ALL
	// file outputs (the scan, terminal summary and --fail-on gate still ran).
	const DEFAULT_NAMES = { html: "cve-report.html", doc: "cve-report.doc", sbom: "sbom.cdx.json", csaf: "csaf-vex.json", json: "findings.json", sarif: "fad.sarif" };
	const sel = { html: options.reportHtml, doc: options.reportDoc, sbom: options.reportSbom, csaf: options.reportCsaf, json: options.reportJson, sarif: options.reportSarif };
	const anySpecified = Object.values(sel).some(v => v !== undefined);
	const resolveOut = key => {
		const v = sel[key];
		if (v === undefined) return (!anySpecified && (key === "html" || key === "doc")) ? path.join(reportDir, DEFAULT_NAMES[key]) : null;
		return (v === true) ? path.join(reportDir, DEFAULT_NAMES[key]) : v;
	};
	const out = options.report === false
		? { html: null, doc: null, sbom: null, csaf: null, json: null, sarif: null }
		: { html: resolveOut("html"), doc: resolveOut("doc"), sbom: resolveOut("sbom"), csaf: resolveOut("csaf"), json: resolveOut("json"), sarif: resolveOut("sarif") };
	const ensureDir = async p => { if (p) await fs.promises.mkdir(path.dirname(path.resolve(p)), { recursive: true }); };

	const reportWarnings = [
		...(suppressedCount ? [{
			type: "suppressed",
			count: suppressedCount,
			message: `${suppressedCount} finding(s) suppressed via triage (--ignore/--vex) — excluded from the chapters above and from CI gating, but retained (flagged) in the JSON/SBOM/CSAF exports.`,
		}] : []),
		...npmWarnings,
		...scanWarnings,
		...(privateLibIds.length ? [{
			type: "private-libs",
			count: privateLibIds.length,
			items: privateLibIds.map(id => {
				const dep = resolved.get(id);
				const paths = (dep?.pomPaths || []).map(p => path.relative(options.src, p));
				return { id, manifestPaths: paths };
			}),
			message: `${privateLibIds.length} Maven coord(s) not found on Maven Central — they are private/internal libraries. Their CVEs (if any) cannot be detected by fad-checker; if you have an internal CVE feed, audit them separately.`,
		}] : []),
	];

	const wrote = [];
	if (out.html || out.doc) {
		await ensureDir(out.html); await ensureDir(out.doc);
		const { htmlPath, docPath } = await writeReports({
			cveMatches: prodMatches, devCveMatches: devMatches, embeddedMatches, retireMatches,
			eolResults, obsoleteResults, outdatedResults, licenseResults,
			resolvedDeps: resolved, projectInfo, warnings: reportWarnings,
			htmlPath: out.html, docPath: out.doc,
		});
		if (htmlPath) wrote.push(["HTML report", htmlPath]);
		if (docPath) wrote.push(["Word .doc", docPath]);
	}

	// Machine-readable exports. Use the full match set (prod + dev + cpe-filtered) so
	// the artifacts are complete; cpeFiltered is marked as a property/flag, not dropped.
	if (out.sbom) {
		try {
			const { writeCycloneDx } = require("./lib/sbom-export");
			await ensureDir(out.sbom);
			writeCycloneDx(resolved, cveMatches, out.sbom, { projectInfo, toolVersion: pkg.version, timestamp: projectInfo.generatedAt, licenseResults });
			wrote.push(["CycloneDX SBOM", out.sbom]);
		} catch (err) { ui.warn(`SBOM export failed: ${err.message}`); }
	}
	if (out.csaf) {
		try {
			const { writeCsaf } = require("./lib/csaf-export");
			await ensureDir(out.csaf);
			writeCsaf(resolved, cveMatches, out.csaf, { projectInfo, toolVersion: pkg.version, timestamp: projectInfo.generatedAt });
			wrote.push(["CSAF 2.0 VEX", out.csaf]);
		} catch (err) { ui.warn(`CSAF export failed: ${err.message}`); }
	}
	if (out.json) {
		try {
			const { writeFindings } = require("./lib/json-export");
			await ensureDir(out.json);
			writeFindings({ cveMatches, retireMatches, eolResults, obsoleteResults, outdatedResults, licenseResults, resolvedDeps: resolved, projectInfo, toolVersion: pkg.version }, out.json);
			wrote.push(["Findings JSON", out.json]);
		} catch (err) { ui.warn(`JSON export failed: ${err.message}`); }
	}
	if (out.sarif) {
		try {
			const { writeSarif } = require("./lib/sarif-export");
			await ensureDir(out.sarif);
			writeSarif(cveMatches.filter(m => !m.suppressed), out.sarif, { projectInfo, toolVersion: pkg.version });
			wrote.push(["SARIF", out.sarif]);
		} catch (err) { ui.warn(`SARIF export failed: ${err.message}`); }
	}

	if (wrote.length) {
		ui.section("Output");
		for (const [label, p] of wrote) ui.ok(`${label} → ${chalk.white(p)}`);
	} else if (options.report === false) {
		ui.info(chalk.dim("--no-report: no files written (scan + gate only)"));
	}
	console.log();

	// CI gating — set a non-zero exit code (after all reports/exports are written)
	// when a production finding meets the --fail-on threshold.
	if (options.failOn && options.failOn !== "none") {
		const { evaluateGate } = require("./lib/gate");
		// Embedded-binary findings are real production risk → gate on them too.
		const gate = evaluateGate([...prodActive, ...embeddedActive], options.failOn);
		if (gate.failed) {
			ui.section("Gate");
			console.log(chalk.red(`✗ --fail-on ${options.failOn}: ${gate.reason}`));
			process.exitCode = 1;
		} else if (verbose) {
			ui.info(chalk.dim(`--fail-on ${options.failOn}: no blocking finding`));
		}
	}
}

/**
 * Merge two match arrays, dedup by (dep, cve.id). When both sides have the
 * same finding, the result keeps the existing record but its `source` is
 * upgraded so the report can show which engine(s) saw it.
 */
function mergeBySource(existing, additions) {
	const byKey = new Map();
	// coordKey keeps embedded-binary findings distinct from a same-g:a:v declared dep
	// (see cve-match dedup). Falls back to g:a for any match lacking a coordKey.
	const k = m => `${m.dep.coordKey || (m.dep.groupId + ":" + m.dep.artifactId)}:${m.dep.version}|${m.cve.id}`;
	for (const m of existing || []) byKey.set(k(m), { ...m, source: m.source || "fad" });
	for (const m of additions || []) {
		const key = k(m);
		if (byKey.has(key)) {
			const prev = byKey.get(key);
			const sources = new Set([prev.source, m.source].filter(Boolean));
			// merge fields: prefer non-empty values, keep first severity if defined
			byKey.set(key, {
				...prev,
				source: sources.size > 1 ? [...sources].sort().join("+") : [...sources][0],
				cve: {
					...prev.cve,
					...m.cve,
					// keep highest non-null score
					score: Math.max(prev.cve.score ?? 0, m.cve.score ?? 0) || prev.cve.score || m.cve.score,
					// prefer non-UNKNOWN severity
					severity: (prev.cve.severity && prev.cve.severity !== "UNKNOWN") ? prev.cve.severity : m.cve.severity,
					// prefer the longer description
					description: ((prev.cve.description || "").length > (m.cve.description || "").length) ? prev.cve.description : m.cve.description,
				},
			});
		} else {
			byKey.set(key, { ...m, source: m.source || "osv" });
		}
	}
	const merged = [...byKey.values()];
	const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0, UNKNOWN: 0 };
	merged.sort((a, b) => {
		const sa = rank[(a.cve.severity || "UNKNOWN").toUpperCase()] || 0;
		const sb = rank[(b.cve.severity || "UNKNOWN").toUpperCase()] || 0;
		if (sb !== sa) return sb - sa;
		return (a.cve.id || "").localeCompare(b.cve.id || "");
	});
	return merged;
}
