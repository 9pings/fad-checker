/**
 * lib/osv.js — query OSV.dev for Maven-ecosystem vulnerabilities.
 *
 * OSV.dev (Google + GitHub Security Lab) aggregates CVE + GHSA data and
 * maintains a curated Maven-coordinate mapping. For Maven recall this is
 * vastly better than the raw CVEProject feed (which lacks packageName
 * fields on pre-2024 CVEs).
 *
 * API: https://google.github.io/osv.dev/post-v1-querybatch/
 *   POST /v1/querybatch  with up to 1000 queries
 *   POST /v1/query       for a single dep
 *   GET  /v1/vulns/{id}  to fetch full details
 *
 * Cached responses live in ~/.fad-checker/osv-cache/ for 12h.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");

const OSV_CACHE_DIR = path.join(os.homedir(), ".fad-checker", "osv-cache");
const OSV_CACHE_TTL_MS = 12 * 3600 * 1000;
const OSV_BASE = "https://api.osv.dev";
const BATCH_SIZE = 800;          // OSV limit is 1000; stay under for safety

function cacheKey(g, a, v, ecosystem = "maven") {
	const safeG = (g || "").replace(/[/\\]/g, "_");
	const safeA = (a || "").replace(/[/\\@]/g, "_");
	return `${ecosystem}__${safeG}__${safeA}__${v}.json`;
}

function readCache(name) {
	const p = path.join(OSV_CACHE_DIR, name);
	if (!fs.existsSync(p)) return null;
	try {
		const data = JSON.parse(fs.readFileSync(p, "utf8"));
		if (Date.now() - data._fetchedAt < OSV_CACHE_TTL_MS) return data.body;
	} catch { /* ignore */ }
	return null;
}

function writeCache(name, body) {
	fs.mkdirSync(OSV_CACHE_DIR, { recursive: true });
	fs.writeFileSync(path.join(OSV_CACHE_DIR, name), JSON.stringify({ _fetchedAt: Date.now(), body }));
}

const SEVERITY_ALIASES = { MODERATE: "MEDIUM", IMPORTANT: "HIGH", SEVERE: "HIGH", INFO: "LOW" };

function normalizeSeverity(s) {
	const up = String(s || "").toUpperCase();
	return SEVERITY_ALIASES[up] || up;
}

function severityFromScore(n) {
	if (!Number.isFinite(n)) return "UNKNOWN";
	if (n >= 9) return "CRITICAL";
	if (n >= 7) return "HIGH";
	if (n >= 4) return "MEDIUM";
	if (n > 0) return "LOW";
	return "NONE";
}

// Compute a CVSS v3.0/3.1 base score from its vector string. Returns null for
// non-v3 vectors (v2/v4) or anything unparseable. OSV stores the *vector* in
// `severity[].score` for CVSS_V3 — there is NO bare base number to read, so the
// old "first number in the string" approach extracted the VERSION ("3.1") as the
// score, mislabelling HIGH findings as ~low everywhere downstream (SARIF
// security-severity, priority banding, SBOM/CSAF ratings).
function cvss3BaseScore(vector) {
	const v = String(vector || "");
	if (!/^CVSS:3\.[01]\//.test(v)) return null;
	const p = {};
	for (const kv of v.split("/").slice(1)) {
		const [k, val] = kv.split(":");
		if (k && val) p[k] = val;
	}
	const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[p.AV];
	const AC = { L: 0.77, H: 0.44 }[p.AC];
	const UI = { N: 0.85, R: 0.62 }[p.UI];
	const scopeChanged = p.S === "C";
	const PR = scopeChanged
		? { N: 0.85, L: 0.68, H: 0.5 }[p.PR]
		: { N: 0.85, L: 0.62, H: 0.27 }[p.PR];
	const imp = { H: 0.56, L: 0.22, N: 0 };
	const C = imp[p.C], I = imp[p.I], A = imp[p.A];
	if ([AV, AC, UI, PR, C, I, A].some(x => x == null)) return null;
	const iss = 1 - (1 - C) * (1 - I) * (1 - A);
	const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
	if (impact <= 0) return 0;
	const exploit = 8.22 * AV * AC * PR * UI;
	const base = Math.min(scopeChanged ? 1.08 * (impact + exploit) : impact + exploit, 10);
	return Math.ceil(base * 10) / 10; // CVSS roundup to one decimal
}

/** Best CVSS info from an OSV vuln: { score, vector, version } (version like "3.1"). */
function cvssInfoFromVuln(vuln) {
	for (const s of vuln.severity || []) {
		const str = String(s.score || "");
		const mver = str.match(/^CVSS:(\d\.\d)\//);
		if (mver) {
			const version = mver[1];
			const score = (version === "3.0" || version === "3.1") ? cvss3BaseScore(str) : null;
			return { score, vector: str, version };
		}
		const mnum = str.match(/^\s*(\d+(\.\d+)?)\s*$/); // a bare numeric score ("9.8")
		if (mnum) return { score: parseFloat(mnum[1]), vector: null, version: null };
	}
	return { score: null, vector: null, version: null };
}

/** Map an OSV vuln to { severity, score }. */
function severityFromOsv(vuln) {
	const direct = vuln.database_specific?.severity;
	const { score } = cvssInfoFromVuln(vuln);
	if (direct) return { severity: normalizeSeverity(direct), score };
	if (score != null) return { severity: severityFromScore(score), score };
	return { severity: "UNKNOWN", score: null };
}

function scoreFromVuln(vuln) { return cvssInfoFromVuln(vuln).score; }

/** Extract the first fix version from OSV affected ranges (semver/ecosystem events). */
function fixVersionFromOsv(vuln, depKey) {
	for (const a of vuln.affected || []) {
		const name = a.package?.name?.toLowerCase();
		if (name && name !== depKey.toLowerCase()) continue;
		for (const r of a.ranges || []) {
			for (const ev of r.events || []) {
				if (ev.fixed) return ev.fixed;
			}
		}
	}
	return null;
}

/** Pick the best CVE id from an OSV vuln (prefer CVE-* aliases over GHSA-*). */
function pickPrimaryId(vuln) {
	if (vuln.id?.startsWith("CVE-")) return vuln.id;
	const cveAlias = (vuln.aliases || []).find(a => a.startsWith("CVE-"));
	return cveAlias || vuln.id;
}

// OSV ecosystem name per codec id. OSV.dev natively supports all of these.
const OSV_ECO = { maven: "Maven", npm: "npm", yarn: "npm", nuget: "NuGet", composer: "Packagist", pypi: "PyPI", go: "Go", ruby: "RubyGems" };

/** OSV ecosystem string for a dep, derived from its codec id. */
function osvEcosystemFor(dep) { return OSV_ECO[dep.ecosystem] || "Maven"; }

/** Build the OSV package-name key for a dep — delegated to the dep's codec. */
function osvPkgName(dep) {
	const { getCodec } = require("./codecs");
	const c = getCodec(dep.ecosystem);
	if (c) return c.osvPackageName(dep);
	// Fallback historique si le codec est introuvable.
	return dep.ecosystem === "npm" ? dep.artifactId : `${dep.groupId}:${dep.artifactId}`;
}

/** Convert one OSV vuln to fad-checker match shape. */
function vulnToMatch(dep, vuln) {
	const id = pickPrimaryId(vuln);
	const { severity, score } = severityFromOsv(vuln);
	const cvss = cvssInfoFromVuln(vuln);
	// `details` (long markdown) is the substantive description; `summary` is just the title.
	// We keep them both: summary as headline, details as body.
	const summary = (vuln.summary || "").trim();
	const details = (vuln.details || "").trim();
	let description = "";
	if (summary && details && !details.toLowerCase().startsWith(summary.toLowerCase())) {
		description = `${summary}\n\n${details}`;
	} else if (details) {
		description = details;
	} else {
		description = summary;
	}
	// Keep up to 2000 chars — enough for full advisory text without bloating the report.
	if (description.length > 2000) description = description.slice(0, 2000) + "…";
	// Categorise OSV references: ADVISORY / FIX / REPORT / WEB / PACKAGE / ARTICLE / EVIDENCE
	const refs = (vuln.references || []).map(r => ({ type: String(r.type || "WEB").toUpperCase(), url: r.url }));
	return {
		dep,
		cve: {
			id,
			severity,
			score,
			...(cvss.vector ? { cvssVector: cvss.vector } : {}),
			...(cvss.version ? { cvssVersion: `CVSS:${cvss.version}` } : {}),
			description,
			summary,
			fixVersion: fixVersionFromOsv(vuln, osvPkgName(dep)),
			ghsa: (vuln.aliases || []).find(a => a.startsWith("GHSA-")) || (vuln.id?.startsWith("GHSA-") ? vuln.id : null),
			published: vuln.published || null,
			modified: vuln.modified || null,
			osvRefs: refs,
			aliases: vuln.aliases || [],
		},
		source: "osv",
		confidence: "exact",
	};
}

async function queryBatch(deps, opts = {}) {
	const { verbose, offline, fetcher = globalThis.fetch, onProgress } = opts;
	// Build query list + parallel cached/uncached split
	const queries = [];
	const indexMap = []; // index in `deps` → either { cached: vulns } or { queryIdx: N }

	for (let i = 0; i < deps.length; i++) {
		const d = deps[i];
		const ck = cacheKey(d.groupId, d.artifactId, d.version, d.ecosystem || "maven");
		const hit = readCache(ck);
		if (hit !== null) {
			indexMap[i] = { cached: hit };
		} else {
			indexMap[i] = { queryIdx: queries.length, cacheKey: ck };
			// Ecosystem + package name are both derived from the dep's codec, so
			// adding a new ecosystem (NuGet/Packagist/PyPI) needs no change here.
			const ecosystem = osvEcosystemFor(d);
			const pkgName = osvPkgName(d);
			queries.push({
				package: { name: pkgName, ecosystem },
				version: d.version,
			});
		}
	}

	// Run batch queries for uncached deps (if any). In offline mode we skip
	// the network and rely entirely on cached per-dep ID lists.
	const allResults = new Array(queries.length);
	if (queries.length && !offline) {
		const batches = [];
		for (let i = 0; i < queries.length; i += BATCH_SIZE) {
			batches.push(queries.slice(i, i + BATCH_SIZE));
		}
		let batchIdx = 0;
		for (const batch of batches) {
			batchIdx++;
			if (onProgress) onProgress(batchIdx, batches.length);
			else if (process.stdout.isTTY) process.stdout.write(`\r   OSV batch ${batchIdx}/${batches.length} (${batch.length} deps)…                  `);
			else if (batches.length > 1) console.log(`   OSV batch ${batchIdx}/${batches.length} (${batch.length} deps)…`);
			const res = await fetcher(`${OSV_BASE}/v1/querybatch`, {
				method: "POST",
				headers: { "Content-Type": "application/json", "User-Agent": "fad-checker-osv" },
				body: JSON.stringify({ queries: batch }),
			});
			if (!res.ok) {
				if (verbose) console.warn(`\n   OSV HTTP ${res.status}`);
				for (let j = 0; j < batch.length; j++) allResults[(batchIdx - 1) * BATCH_SIZE + j] = { vulns: [] };
				continue;
			}
			const data = await res.json();
			const results = data.results || [];
			for (let j = 0; j < batch.length; j++) {
				allResults[(batchIdx - 1) * BATCH_SIZE + j] = results[j] || { vulns: [] };
			}
		}
		if (onProgress) { /* finalized by caller */ }
		else if (process.stdout.isTTY) process.stdout.write(`\r   OSV batches complete (${batches.length})                          \n`);

		// Persist per-dep cache (stub list — details cached separately)
		for (let i = 0; i < deps.length; i++) {
			const slot = indexMap[i];
			if (slot.queryIdx != null) {
				const queryGlobalIdx = slot.queryIdx;
				const result = allResults[queryGlobalIdx] || { vulns: [] };
				const ids = (result.vulns || []).map(v => v.id);
				writeCache(slot.cacheKey, ids);
				slot.cached = ids;
			}
		}
	}

	// Collect every unique vuln id we need to enrich — whether it came from
	// the cached per-dep list or from a fresh batch result.
	const allIds = new Set();
	for (const slot of indexMap) for (const id of (slot.cached || [])) allIds.add(id);

	// Split cached vs live so the progress display reflects actual work and
	// detail fetches run in parallel (was silent serial — caused the
	// "stuck after OSV" symptom on large dep trees).
	const detailById = new Map();
	const liveIds = [];
	for (const id of allIds) {
		const detailCacheKey = `vuln_${id}.json`;
		const hit = readCache(detailCacheKey);
		if (hit) { detailById.set(id, hit); continue; }
		if (offline) continue;
		liveIds.push(id);
	}

	if (liveIds.length) {
		if (!onProgress) console.log(`   OSV details: ${liveIds.length} to fetch${allIds.size - liveIds.length ? `, ${allIds.size - liveIds.length} cached` : ""}…`);
		const concurrency = 10;
		let cursor = 0;
		let fetched = 0;
		const startedAt = Date.now();
		const printOsvProgress = (final = false) => {
			if (onProgress) { onProgress(fetched, liveIds.length); return; }
			const elapsed = Math.round((Date.now() - startedAt) / 1000);
			const pct = Math.round((fetched / liveIds.length) * 100);
			const line = `   OSV details: ${fetched}/${liveIds.length} (${pct}%) — ${elapsed}s`;
			if (process.stdout.isTTY) process.stdout.write(`\r${line}${final ? "\n" : "          "}`);
			else if (final) console.log(line);
		};
		const workers = Array.from({ length: concurrency }, async () => {
			while (cursor < liveIds.length) {
				const id = liveIds[cursor++];
				const detailCacheKey = `vuln_${id}.json`;
				try {
					const r = await fetcher(`${OSV_BASE}/v1/vulns/${encodeURIComponent(id)}`, {
						headers: { "User-Agent": "fad-checker-osv" },
					});
					if (r.ok) {
						const body = await r.json();
						detailById.set(id, body);
						writeCache(detailCacheKey, body);
					}
				} catch { /* ignore individual failures */ }
				fetched++;
				if (fetched % 5 === 0 || fetched === liveIds.length) printOsvProgress();
			}
		});
		await Promise.all(workers);
		printOsvProgress(true);
	}

	return runMatches(deps, indexMap, detailById);
}

function runMatches(deps, indexMap, detailById) {
	const matches = [];
	for (let i = 0; i < deps.length; i++) {
		const slot = indexMap[i];
		const ids = slot.cached || [];
		const dep = deps[i];
		for (const id of ids) {
			const vuln = detailById instanceof Map ? detailById.get(id) : null;
			if (!vuln) {
				// Stub-only (id known but no details fetched yet). Skip rather
				// than emit a descriptionless UNKNOWN-severity placeholder:
				// such stubs were FP-prone because the local cache key is
				// (g, a, v) but the underlying advisory may no longer apply
				// to a version upgraded since cache build. M2 in CRITICAL-REVIEW.md.
				continue;
			}
			matches.push(vulnToMatch(dep, vuln));
		}
	}
	return matches;
}

/**
 * Public: query OSV for every dep in `resolvedDeps` Map, return fad-checker-shape matches.
 */
async function queryOsvForDeps(resolvedDeps, opts = {}) {
	const deps = [];
	for (const d of resolvedDeps.values()) {
		if (d.scope === "parent") continue; // parents don't have OSV entries typically
		// Query every distinct concrete version (e.g. two profiles pinning the
		// same g:a), not just the representative highest — otherwise a vuln that
		// only affects a lower-versioned variant would be missed.
		const versions = (d.versions && d.versions.length) ? d.versions : [d.version];
		for (const ver of versions) {
			if (!ver || /\$\{|SNAPSHOT/i.test(ver)) continue;
			// npm version specifiers like "^1.0.0" can't be queried against OSV —
			// need a concrete version. Lockfiles always provide one; package.json-
			// only deps are skipped here.
			if (d.ecosystem === "npm" && /^[\^~>=<*]|^(latest|next|workspace:|git\+|file:|link:)/.test(ver)) continue;
			// Spread the whole depRecord (carries namespace/name/coordKey, which the
			// codec's osvPackageName + the report's dedup rely on) and override only
			// the version for this per-version query. Cherry-picking fields here used
			// to drop name/namespace → OSV queried `undefined` for composer/pypi/nuget.
			deps.push({ ...d, version: ver });
		}
	}
	return queryBatch(deps, opts);
}

module.exports = {
	queryOsvForDeps,
	queryBatch,
	vulnToMatch,
	severityFromOsv,
	fixVersionFromOsv,
	osvEcosystemFor,
	osvPkgName,
	OSV_CACHE_DIR,
};
