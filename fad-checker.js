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

const core = require("./lib/core");

const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "package.json"), "utf8"));

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
	if (Array.isArray(masked.maven_repos)) {
		masked.maven_repos = masked.maven_repos.map(r => ({ ...r, auth: r.auth ? "***" : undefined }));
	}
	console.log(JSON.stringify(masked, null, 2));
	console.log(chalk.gray("Config file: " + config.CONFIG_PATH));
	process.exit(0);
}

// -------- --add-repo / --remove-repo / --list-repos (run before program.parse) --------
if (process.argv.includes("--add-repo") || process.argv.includes("--remove-repo") || process.argv.includes("--list-repos")) {
	const config = require("./lib/config");
	if (process.argv.includes("--list-repos")) {
		const repos = config.getMavenRepos();
		if (!repos.length) {
			console.log(chalk.gray("No custom Maven repos configured (Maven Central is always used as fallback)."));
		} else {
			console.log(chalk.bold("Configured Maven repos (tried in order, then Central):"));
			for (const r of repos) {
				const authMark = r.auth ? chalk.yellow(" [auth]") : "";
				console.log(`  • ${chalk.cyan(r.name)} → ${r.url}${authMark}`);
			}
		}
		process.exit(0);
	}
	if (process.argv.includes("--add-repo")) {
		const idx = process.argv.indexOf("--add-repo");
		const name = process.argv[idx + 1];
		const url = process.argv[idx + 2];
		if (!name || name.startsWith("-") || !url || url.startsWith("-")) {
			console.error(chalk.red("❌  --add-repo requires <name> <url>"));
			console.error("   Example: fad-checker --add-repo nexus https://nexus.acme.com/repository/maven-public/");
			console.error("   Optional auth: --add-repo nexus https://nexus.acme.com/repository/maven-public/ --auth user:pass");
			process.exit(1);
		}
		const authIdx = process.argv.indexOf("--auth");
		const auth = authIdx > -1 ? process.argv[authIdx + 1] : null;
		config.addMavenRepo(name, url, auth);
		console.log(chalk.green(`✅ Added Maven repo "${name}" → ${url}${auth ? " (with auth)" : ""}`));
		process.exit(0);
	}
	if (process.argv.includes("--remove-repo")) {
		const idx = process.argv.indexOf("--remove-repo");
		const name = process.argv[idx + 1];
		if (!name || name.startsWith("-")) {
			console.error(chalk.red("❌  --remove-repo requires <name>"));
			process.exit(1);
		}
		const removed = config.removeMavenRepo(name);
		console.log(removed ? chalk.green(`✅ Removed Maven repo "${name}"`) : chalk.yellow(`⚠️  No Maven repo named "${name}"`));
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
	.requiredOption("-s, --src <src>", "root directory containing pom.xml files")
	.option("-e, --exclude <exclude>", "regex of groupId to exclude, e.g. '^(client|private)\\.'")
	.option("-v, --verbose", "verbose")
	// Defaults: report + transitive + allLibs all ON. Use --no-* to disable.
	.option("--no-report", "skip the CVE / EOL / obsolete report")
	.option("--no-transitive", "skip transitive dependency resolution")
	.option("--no-all-libs", "skip Maven Central queries (outdated check + missing-on-central check)")
	.option("--no-osv", "skip OSV.dev (Google/GitHub aggregated Maven CVE feed)")
	.option("--no-nvd", "skip NIST NVD enrichment of matched CVEs")
	.option("--offline", "no network: use cached CVE/OSV/NVD/POM data only")
	.option("--set-nvd-key <key>", "save NVD API key to ~/.fad-checker/config.json (10× faster NVD enrichment)")
	.option("--show-config", "print the persisted ~/.fad-checker/config.json")
	.option("--export-cache <file>", "tar.gz/zip the ~/.fad-checker/ caches to <file> (excludes config.json by default)")
	.option("--import-cache <file>", "restore ~/.fad-checker/ from a previously exported archive (existing dir is moved to .bak unless --force)")
	.option("--include-config", "with --export-cache: also bundle config.json (contains the NVD API key)")
	.option("--force", "with --import-cache: replace ~/.fad-checker/ without backup")
	.option("--report-output <dir>", "report output directory", "./fad-checker-report")
	.option("--ignore-test", "skip test-scoped dependencies in report")
	.option("--cve-refresh", "force re-download of CVE database")
	.option("--cve-offline", "use cached CVE index only (no download)")
	.option("--snyk", "run snyk on cleaned POMs and merge into report (requires --target)")
	.option("--no-retire", "skip retire.js vendored-JS scan")
	.option("--retire-refresh", "ignore retire cache and re-scan")
	.option("--transitive-depth <n>", "max transitive depth", "6")
	.option("--ecosystem <list>", "codecs to run: auto|all|<comma list> e.g. maven,npm,nuget,composer,pypi (default: auto = detected)", "auto")
	.option("--no-maven", "skip the Maven codec")
	.option("--no-npm", "skip the npm codec")
	.option("--no-yarn", "skip the Yarn codec")
	.option("--no-nuget", "skip the NuGet (C#/.NET) codec")
	.option("--no-composer", "skip the Composer (PHP) codec")
	.option("--no-pypi", "skip the PyPI (Python) codec")
	.option("--no-js", "alias: skip JS/npm/yarn manifests even if present (Maven-only)")
	.option("--repo <url...>", "extra Maven repository URL(s) to try before Maven Central. Supports https://user:pass@host/path/. Repeatable.")
	.option("--add-repo <name>", "persist a Maven repo: --add-repo <name> <url> [--auth user:pass]")
	.option("--remove-repo <name>", "remove a persisted Maven repo by name")
	.option("--list-repos", "list configured Maven repos and exit")
	.option("--completion <shell>", "print shell completion script (bash|zsh)");
program.parse(process.argv);

const options = program.opts();
const deps2Exclude = options.exclude ? new RegExp(options.exclude) : null;
const verbose = !!options.verbose;
// Read-only when no target is given. No need for an explicit --test flag.
const readOnly = !options.target;

if (options.src && options.target) {
	const rel = path.relative(path.resolve(options.src), path.resolve(options.target));
	const isSubdir = !rel || (!rel.startsWith("..") && !path.isAbsolute(rel));
	if (isSubdir) {
		console.error(chalk.red("❌  --target cannot be the same as or a subdirectory of --src"));
		process.exit(1);
	}
}

async function checkMavenLibExist(groupId, artifactId, repos) {
	const g = core.coord(groupId);
	const a = core.coord(artifactId);
	if (!g || !a) return false;
	const p = `${g.replace(/\./g, "/")}/${a}/maven-metadata.xml`;
	const { existsInAny } = require("./lib/maven-repo");
	try {
		const hit = await existsInAny(repos, p, { userAgent: "fad-checker-existence" });
		if (hit) return true;
		console.log(`❌  NOT found on any repo: ${g}:${a}`);
		return false;
	} catch (err) {
		console.info(`error querying repos: ${g}:${a} — ${err.message}`);
		return false;
	}
}

(async function main() {
	console.log(chalk.bold.cyan("\n🚀 Fucking Autonomous Dependency Checker\n") + chalk.gray("─────────────────────────────"));

	// Build the Maven repo list once: persisted repos (from ~/.fad-checker/config.json)
	// + ad-hoc --repo URLs + Maven Central as final fallback. Used by transitive
	// resolution, outdated-version check, and existence check.
	const { getMavenRepos } = require("./lib/config");
	const { buildRepoList } = require("./lib/maven-repo");
	const extraRepos = (options.repo || []).map(url => ({ url }));
	const mavenRepos = buildRepoList(getMavenRepos(), extraRepos);
	if (mavenRepos.length > 1) {
		console.log(chalk.gray(`📦 Maven repos: ${mavenRepos.map(r => r.name).join(" → ")}`));
	}

	let wrotePom = 0;

	// --- Codec detection + selection ---
	const { detectCodecs, allCodecs, getCodec } = require("./lib/codecs");
	const { resolveActiveCodecs } = require("./lib/codecs/select");
	const eco = (options.ecosystem || "auto").toLowerCase();
	const detected = (eco === "auto") ? detectCodecs(options.src).map(c => c.id) : allCodecs().map(c => c.id);
	const noCodecs = ["maven", "npm", "yarn", "nuget", "composer", "pypi"].filter(id => options[id] === false);
	const activeIds = resolveActiveCodecs(eco, detected, { noCodecs, noJs: !options.js });
	const runMaven = activeIds.includes("maven");
	const runNpm = activeIds.includes("npm") || activeIds.includes("yarn");

	// --- Collect deps from every active codec into one Map (coordKeys never collide) ---
	const resolved = new Map();
	let mavenCtx = null;
	const collectWarnings = [];
	for (const id of activeIds) {
		if (id === "yarn") continue;   // the npm codec already collects yarn.lock
		const codec = getCodec(id);
		let res;
		try {
			res = await codec.collect(options.src, { ignoreTest: !!options.ignoreTest, deps2Exclude, verbose });
		} catch (err) {
			console.warn(chalk.red(`❌  ${id} collect failed:`), chalk.dim(err.message));
			continue;
		}
		for (const [k, v] of res.deps) resolved.set(k, v);
		if (res.warnings?.length) collectWarnings.push(...res.warnings);
		if (id === "maven") mavenCtx = res._maven;
	}

	if (!readOnly) {
		try { await rimraf(options.target); } catch (_) { /* fresh dir */ }
	}

	if (runMaven && mavenCtx) console.log(chalk.blue(`🔍 Found ${mavenCtx.pomFiles.length} pom.xml files`));
	if (runNpm)   console.log(chalk.blue(`🔍 JS manifests detected — npm/yarn pipeline enabled`));
	console.log();

	// Maven POM rewrite (cleanup feature). Parse + inheritance already happened
	// inside the maven codec's collect(); we reuse its metadata store here.
	if (runMaven && mavenCtx) {
		const { store, propsByPom, pomFiles } = mavenCtx;
		const rewriteOpts = { srcRoot: options.src, targetRoot: options.target, deps2Exclude, verbose, readOnly };
		for (const pom of pomFiles) {
			try {
				if (await core.rewritePoms(pom, store, propsByPom, rewriteOpts)) wrotePom++;
			} catch (err) {
				console.error(chalk.red(`❌  rewrite failed for ${pom}:`), err.message);
			}
		}
	}

	// ---------- Summary: parents missing / excluded ----------
	let privateLibIds = [];
	if (runMaven && mavenCtx) {
	const allPomMetadata = mavenCtx.store;   // reuse the codec's parsed metadata
	console.log(chalk.cyanBright("\n─────────────────────────────────────────────"));
	console.log(chalk.cyanBright("📦 Résumé des POM analysés :"));
	console.log(chalk.cyanBright("─────────────────────────────────────────────\n"));

	const missingParents = Object.keys(allPomMetadata.missingById)
		.filter(id => {
			const parts = id.split(":");
			if (parts.length === 2) return false;
			return !(allPomMetadata.byId[id] || allPomMetadata.byId[`${parts[0]}:${parts[1]}`]);
		});

	if (missingParents.length) {
		console.log(chalk.yellowBright("⚠️ Parents libs Maven manquants ( si ces lib sont privées snyk plantera ) :"));
		console.log(missingParents.map(id => chalk.yellow("  • ") + id).join("\n"));
	} else {
		console.log(chalk.greenBright("✅ Aucun parent Maven manquant."));
	}

	if (options.allLibs) {
		const anyMissingLibs = Object.keys(allPomMetadata.anyMissingById)
			.filter(id => {
				const parts = id.split(":");
				if (parts.length === 3) return false;
				return !(allPomMetadata.byId[id] || allPomMetadata.byId[`${parts[0]}:${parts[1]}`]);
			});
		const limit = pLimit(10);
		console.log(chalk.magentaBright("\n🚫 Libs absentes de Maven Central :"));
		const results = await Promise.all(anyMissingLibs.map(id => {
			const [g, a] = id.split(":");
			return limit(async () => ({ id, found: await checkMavenLibExist(g, a, mavenRepos) }));
		}));
		for (const r of results) if (r && r.found === false) privateLibIds.push(r.id);
	}

	if (deps2Exclude) {
		const excludedLibs = Object.keys(allPomMetadata.excludedById)
			.filter(id => {
				const parts = id.split(":");
				if (parts.length === 2) return false;
				return !(allPomMetadata.byId[id] || allPomMetadata.byId[`${parts[0]}:${parts[1]}`]);
			});
		if (excludedLibs.length) {
			console.log(chalk.magentaBright("\n🚫 Bibliothèques exclues et manquantes :"));
			console.log(excludedLibs.map(id => chalk.magenta("  • ") + id).join("\n"));
		} else {
			console.log(chalk.greenBright("\n✅ Aucune bibliothèque exclue et manquante."));
		}
	} else {
		console.log(chalk.magentaBright("\n🚫 Bibliothèques exclues ( privées ) et manquantes : "));
		console.log(chalk.magenta("  • ") + "Pas d'exclusions ( on considère donc que toutes les deps hors parents sont publiques )");
	}

	console.log(chalk.cyanBright("\n─────────────────────────────────────────────"));
	console.log(chalk.cyanBright(`✅  ${wrotePom} POMs nettoyés ont été obtenus`));
	if (!readOnly) console.log(chalk.whiteBright(`  Ils ont été écrits dans : ${options.target}`));
	console.log(chalk.cyanBright("─────────────────────────────────────────────\n"));
	} // end runMaven

	// ---------- Report flow (CVE / EOL / Obsolete) ----------
	if (options.report) {
		await runReportFlow(resolved, { activeIds, runMaven, runNpm, privateLibIds, mavenRepos, collectWarnings });
	} else if (!readOnly) {
		const target = options.target;
		console.log(chalk.gray(`💡 Pour lancer Snyk depuis ${target} :`));
		console.log(chalk.whiteBright(`   cd ${target} && snyk test --json --all-projects | snyk-to-html -o ../snyk-deps-check.html\n`));
	}
})();

async function runReportFlow(resolved, ecoFlags = {}) {
	const { activeIds = [], runMaven = true, runNpm = false, privateLibIds = [], mavenRepos = [], collectWarnings = [] } = ecoFlags;
	const { expandWithTransitives } = require("./lib/cve-match");
	const { writeReports, computeStats } = require("./lib/cve-report");
	const { getCodec } = require("./lib/codecs");
	const outdated = require("./lib/outdated");
	const offline = !!options.offline;
	if (offline) console.log(chalk.gray("   (--offline: cached data only, no network)"));

	console.log(chalk.bold.cyan("\n📋 Rapport CVE / EOL / Obsolète\n") + chalk.gray("─────────────────────────────"));

	// Deps were already collected per-codec by main(). Just report the counts.
	const byEcoCount = {};
	for (const d of resolved.values()) byEcoCount[d.ecosystem] = (byEcoCount[d.ecosystem] || 0) + 1;
	if (runMaven) console.log(chalk.blue(`📚 ${byEcoCount.maven || 0} dépendances Maven directes (incl. parent POMs)`));
	if (runNpm)   console.log(chalk.blue(`📦 ${byEcoCount.npm || 0} dépendances npm/yarn`));
	for (const [ecoId, n] of Object.entries(byEcoCount)) {
		if (ecoId === "maven" || ecoId === "npm") continue;
		const label = (require("./lib/codecs").getCodec(ecoId)?.label) || ecoId;
		console.log(chalk.blue(`📦 ${n} dépendances ${label}`));
	}

	// Warnings surfaced during collection (e.g. npm no-lockfile fallback).
	const npmWarnings = collectWarnings || [];
	let scanWarnings = [];
	if (npmWarnings.length) {
		console.log(chalk.yellow(`⚠️  ${npmWarnings.length} manifest warning(s) :`));
		for (const w of npmWarnings) {
			console.log(chalk.yellow(`     • ${w.manifestPath} — ${w.message}`));
		}
	}
	const directCount = resolved.size;

	// Scan-completeness signals: BOMs and unresolved-version deps mean fad-checker
	// has gone as far as it can without running Maven/Snyk itself.
	if (runMaven) {
		const { detectScanCompletenessWarnings } = require("./lib/scan-completeness");
		scanWarnings = detectScanCompletenessWarnings(resolved, { ranSnyk: !!options.snyk, ranTransitive: !!options.transitive });
		if (scanWarnings.length) {
			console.log(chalk.yellow(`\n⚠️  ${scanWarnings.length} scan-completeness alert(s) — a real Maven/Snyk run may surface more findings:`));
			for (const w of scanWarnings) {
				console.log(chalk.yellow(`     • [${w.type}] ${w.message}`));
				if (w.items?.length) {
					const shown = w.items.slice(0, 6);
					for (const it of shown) console.log(chalk.gray(`         · ${it}`));
					if (w.items.length > shown.length) console.log(chalk.gray(`         · …and ${w.items.length - shown.length} more`));
				}
			}
		}
	}

	if (options.transitive && runMaven) {
		await expandWithTransitives(resolved, {
			verbose,
			offline,
			maxDepth: parseInt(options.transitiveDepth, 10) || 6,
			includeTestDeps: !options.ignoreTest,
			repos: mavenRepos,
		});
		console.log(chalk.blue(`🌳 ${resolved.size - directCount} dépendances transitives ajoutées (total: ${resolved.size})`));
	}

	// 1. CVE — native scanner contributed by the maven codec (local cvelistV5 index).
	let cveMatches = [];
	let cveDataDate = null;
	if (runMaven) {
		const sc = (getCodec("maven").nativeScanners || []).find(s => s.kind === "cve");
		const indexExists = fs.existsSync(require("./lib/cve-download").CVE_INDEX_PATH);
		if (sc && (!(options.cveOffline || offline) || indexExists)) {
			try {
				const r = await sc.scan(resolved, { cveRefresh: !!options.cveRefresh, cveOffline: !!options.cveOffline, offline, verbose });
				cveMatches = r.matches || [];
				cveDataDate = r.meta?.cveDataDate || null;
			} catch (err) {
				console.warn(chalk.yellow("⚠️  CVE scan skipped:"), err.message);
			}
		}
	}

	// 2. EOL frameworks
	let eolResults = [];
	try { eolResults = await outdated.checkEolDeps(resolved, { verbose, offline }); }
	catch (err) { console.warn(chalk.yellow("⚠️  EOL check skipped:"), err.message); }

	// 3. Obsolete / deprecated
	let obsoleteResults = [];
	try { obsoleteResults = outdated.checkObsoleteDeps(resolved); }
	catch (err) { console.warn(chalk.yellow("⚠️  Obsolete check skipped:"), err.message); }

	// 4. Outdated (latest Maven Central)
	let outdatedResults = [];
	if (options.allLibs) {
		try { outdatedResults = await outdated.checkOutdatedDeps(resolved, { verbose, offline, repos: mavenRepos }); }
		catch (err) { console.warn(chalk.yellow("⚠️  Outdated check skipped:"), err.message); }
	}

	// 4a. npm registry — deprecation (always, authoritative maintainer data) and
	// outdated (gated by --all-libs like Maven Central). Covers npm deps and
	// WebJars (Maven artifacts wrapping npm/bower libs), so it runs even in
	// Maven-only mode. One fetch per package; no-ops when there are no targets.
	try {
		const { checkNpmRegistryDeps } = require("./lib/codecs/npm/registry");
		const npmReg = await checkNpmRegistryDeps(resolved, { verbose, offline, allLibs: options.allLibs });
		obsoleteResults = obsoleteResults.concat(npmReg.deprecated);
		outdatedResults = outdatedResults.concat(npmReg.outdated);
	} catch (err) { console.warn(chalk.yellow("⚠️  npm registry check skipped:"), err.message); }

	// 4b. Per-codec registry for ecosystems beyond maven/npm (composer/pypi/nuget).
	// maven (Maven Central) + npm (registry) are already covered above; this loop
	// drives each remaining active codec's own registry (Packagist abandoned, etc.).
	for (const id of activeIds) {
		if (id === "maven" || id === "npm" || id === "yarn") continue;
		const codec = getCodec(id);
		if (!codec?.checkRegistry) continue;
		try {
			const reg = await codec.checkRegistry(resolved, { verbose, offline, allLibs: options.allLibs });
			obsoleteResults = obsoleteResults.concat(reg.deprecated || []);
			outdatedResults = outdatedResults.concat(reg.outdated || []);
		} catch (err) { console.warn(chalk.yellow(`⚠️  ${id} registry check skipped:`), err.message); }
	}

	// Cross-section dedup: drop entries from outdated that already appear in EOL/Obsolete
	const eolKeys = new Set(eolResults.map(r => `${r.dep.groupId}:${r.dep.artifactId}`));
	const obsKeys = new Set(obsoleteResults.map(r => `${r.dep.groupId}:${r.dep.artifactId}`));
	outdatedResults = outdatedResults.filter(r => {
		const k = `${r.dep.groupId}:${r.dep.artifactId}`;
		return !eolKeys.has(k) && !obsKeys.has(k);
	});

	// 4b. OSV.dev — Maven-native CVE+GHSA feed (huge recall win over raw CVEProject)
	if (options.osv) {
		try {
			const { queryOsvForDeps } = require("./lib/osv");
			const osvMatches = await queryOsvForDeps(resolved, { verbose, offline });
			const before = cveMatches.length;
			cveMatches = mergeBySource(cveMatches, osvMatches);
			console.log(chalk.blue(`🌐 OSV.dev: ${osvMatches.length} vulnerabilities, +${cveMatches.length - before} new after merge`));
		} catch (err) {
			console.warn(chalk.yellow("⚠️  OSV.dev skipped:"), err.message);
		}
	}

	// 4c. NVD enrichment — canonical description + full CVSS for matched CVEs
	if (options.nvd && cveMatches.length) {
		try {
			const { enrichMatches } = require("./lib/nvd");
			await enrichMatches(cveMatches, { verbose, offline });
		} catch (err) {
			console.warn(chalk.yellow("⚠️  NVD enrichment skipped:"), err.message);
		}

		// 4d. CPE refinement — use NVD's CPE configurations to upgrade match
		// confidence and flag likely false positives (CVE matched a product
		// name but the dep version is outside any vulnerable CPE range).
		try {
			const { refineMatchesWithCpe } = require("./lib/cpe");
			refineMatchesWithCpe(cveMatches);
			const upgraded = cveMatches.filter(m => m.cpeConfidence).length;
			const filtered = cveMatches.filter(m => m.cpeFiltered).length;
			if (verbose) console.log(chalk.gray(`   CPE: ${upgraded} matches with CPE confirmation, ${filtered} flagged as likely false positives`));
		} catch (err) {
			console.warn(chalk.yellow("⚠️  CPE refinement skipped:"), err.message);
		}
	}

	// 5. retire.js — native "vendored" scanner contributed by the npm codec. Scans
	//    vendored JS files (jquery copies, bootstrap, pdf.js, …) that live in the
	//    source tree without any lockfile to back them.
	// Not gated by an active npm ecosystem: retire scans the source tree for
	// vendored .js (which can live in a Maven project's resources too). The
	// scanner is owned by the npm codec but runs whenever --retire is on.
	let retireMatches = [];
	if (options.retire) {
		const sc = (getCodec("npm").nativeScanners || []).find(s => s.kind === "vendored");
		if (sc) {
			try {
				const r = await sc.scan(resolved, { src: options.src, verbose, retireRefresh: !!options.retireRefresh, offline });
				retireMatches = r.matches || [];
				console.log(chalk.blue(`🔎 retire.js: ${retireMatches.length} vendored-JS finding(s)`));
			} catch (err) {
				console.warn(chalk.yellow("⚠️  retire.js skipped:"), err.message);
			}
		}
	}

	// 6. Snyk (optional)
	let snykMatches = [];
	if (options.snyk) {
		if (!options.target) {
			console.warn(chalk.yellow("⚠️  --snyk requires --target (snyk runs on cleaned POMs)"));
		} else {
			const snyk = require("./lib/snyk");
			try {
				const raw = await snyk.runSnykTest(options.target, { verbose });
				snykMatches = snyk.parseSnykResults(raw);
				cveMatches = snyk.mergeWithFadResults(cveMatches, snykMatches);
				console.log(chalk.blue(`🐍 Snyk: ${snykMatches.length} findings merged`));
			} catch (err) {
				console.warn(chalk.yellow("⚠️  Snyk run failed:"), err.message);
			}
		}
	}

	// Split prod vs dev based on the dep's isDev flag (set at collection time
	// from Maven scope=test/provided and npm dev/devOptional/optional). Keep the
	// full per-bucket list (including cpeFiltered) so the HTML report can render
	// its "Likely false positives" appendix — only the CLI headline excludes
	// cpeFiltered to avoid alarming on triaged-out matches.
	const prodMatches = cveMatches.filter(m => !m.dep?.isDev);
	const devMatches  = cveMatches.filter(m =>  m.dep?.isDev);
	const prodActive  = prodMatches.filter(m => !m.cpeFiltered);
	const devActive   = devMatches.filter(m => !m.cpeFiltered);
	const cpeFilteredCount = (prodMatches.length - prodActive.length) + (devMatches.length - devActive.length);

	const stats = computeStats(prodActive);
	const devStats = computeStats(devActive);
	console.log(chalk.bold.cyan(`\n  1. CVE Vulnerabilities (production: ${prodActive.length})`));
	console.log(`     critical=${stats.critical}  high=${stats.high}  medium=${stats.medium}  low=${stats.low}  unknown=${stats.unknown}`);
	const depLabel = d => d.ecosystem === "npm" ? `npm:${d.artifactId}` : `${d.groupId}:${d.artifactId}`;
	for (const m of prodActive.slice(0, 20)) {
		const sev = (m.cve.severity || "UNKNOWN").padEnd(8);
		console.log(`       ${chalk.red(sev)} ${m.cve.id}  ${depLabel(m.dep)}:${m.dep.version}`);
	}
	if (prodActive.length > 20) console.log(`       ... and ${prodActive.length - 20} more (see report)`);
	if (cpeFilteredCount) console.log(chalk.gray(`     (${cpeFilteredCount} likely false positives moved to report appendix)`));

	if (devActive.length) {
		console.log(chalk.bold.cyan(`\n  2. CVE in dev dependencies (${devActive.length})`));
		console.log(`     critical=${devStats.critical}  high=${devStats.high}  medium=${devStats.medium}  low=${devStats.low}  unknown=${devStats.unknown}`);
	}
	if (retireMatches.length) {
		console.log(chalk.bold.cyan(`\n  3. Vendored JS (retire.js): ${retireMatches.length}`));
		for (const m of retireMatches.slice(0, 10)) {
			console.log(`       ${chalk.red((m.cve.severity || "?").padEnd(8))} ${m.cve.id}  ${m.dep.artifactId}@${m.dep.version}  ← ${m.dep.vendoredFile}`);
		}
		if (retireMatches.length > 10) console.log(`       ... and ${retireMatches.length - 10} more (see report)`);
	}

	// npm deps have no groupId; show them as "npm:name" rather than ":name".
	const coordOf = d => d.ecosystem === "npm" ? `npm:${d.artifactId}` : `${d.groupId}:${d.artifactId}`;

	console.log(chalk.bold.cyan("\n  2. End-of-Life Frameworks"));
	for (const e of eolResults) console.log(`     ${e.product.padEnd(20)} ${coordOf(e.dep)}:${e.dep.version}  ${e.eol}`);
	if (!eolResults.length) console.log(chalk.gray("     (none)"));

	console.log(chalk.bold.cyan("\n  3. Obsolete / Deprecated Libraries"));
	for (const o of obsoleteResults) console.log(`     ${(o.severity || "info").padEnd(8)} ${coordOf(o.dep)}:${o.dep.version}  → ${o.replacement || "n/a"}`);
	if (!obsoleteResults.length) console.log(chalk.gray("     (none)"));

	console.log(chalk.bold.cyan("\n  4. Outdated Libraries"));
	for (const o of outdatedResults.slice(0, 20)) console.log(`     ${coordOf(o.dep)}  ${o.dep.version} → ${o.latest}`);
	if (outdatedResults.length > 20) console.log(`       ... and ${outdatedResults.length - 20} more`);
	if (!outdatedResults.length && options.allLibs) console.log(chalk.gray("     (none)"));
	if (!options.allLibs) console.log(chalk.gray("     (re-run with -a/--allLibs to query Maven Central)"));

	const reportDir = options.reportOutput || "./fad-checker-report";
	await fs.promises.mkdir(reportDir, { recursive: true });
	const projectInfo = {
		name: path.basename(path.resolve(options.src)),
		src: path.resolve(options.src),
		generatedAt: new Date().toISOString(),
		toolVersion: pkg.version,
		cveDataDate,
	};
	const { htmlPath, docPath } = await writeReports({
		cveMatches: prodMatches,
		devCveMatches: devMatches,
		retireMatches,
		eolResults,
		obsoleteResults,
		outdatedResults,
		resolvedDeps: resolved,
		projectInfo,
		outputDir: reportDir,
		warnings: [
			...npmWarnings,
			...scanWarnings,
			...(privateLibIds.length ? [{
				type: "private-libs",
				count: privateLibIds.length,
				// Enrich each private lib with the relative path(s) of the pom(s)
				// that declare it, so the team knows where to look.
				items: privateLibIds.map(id => {
					const dep = resolved.get(id);
					const paths = (dep?.pomPaths || []).map(p => path.relative(options.src, p));
					return { id, manifestPaths: paths };
				}),
				message: `${privateLibIds.length} Maven coord(s) not found on Maven Central — they are private/internal libraries. Their CVEs (if any) cannot be detected by fad-checker; if you have an internal CVE feed, audit them separately.`,
			}] : []),
		],
	});
	console.log(chalk.bold.green(`\n✅ Report written:\n   ${htmlPath}\n   ${docPath}\n`));
}

/**
 * Merge two match arrays, dedup by (dep, cve.id). When both sides have the
 * same finding, the result keeps the existing record but its `source` is
 * upgraded so the report can show which engine(s) saw it.
 */
function mergeBySource(existing, additions) {
	const byKey = new Map();
	const k = m => `${m.dep.groupId}:${m.dep.artifactId}:${m.dep.version}|${m.cve.id}`;
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
