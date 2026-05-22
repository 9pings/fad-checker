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
 * Cached responses live in ~/.fad-check/osv-cache/ for 12h.
 */
const fs = require("fs");
const path = require("path");
const os = require("os");

const OSV_CACHE_DIR = path.join(os.homedir(), ".fad-check", "osv-cache");
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

/** Map an OSV severity score string ("9.8", "CVSS:3.1/AV:N/.../I:H/A:H") to a level. */
function severityFromOsv(vuln) {
	// Severity may live in `severity[]` (CVSS vector strings) or
	// `database_specific.severity` (GHSA-style: "CRITICAL", "HIGH", "MODERATE"...).
	const direct = vuln.database_specific?.severity;
	if (direct) return { severity: normalizeSeverity(direct), score: scoreFromVuln(vuln) };
	const sev = vuln.severity?.[0]?.score || "";
	const numeric = parseFloat(sev.match(/(\d+(\.\d+)?)/)?.[1]);
	if (Number.isFinite(numeric)) {
		if (numeric >= 9) return { severity: "CRITICAL", score: numeric };
		if (numeric >= 7) return { severity: "HIGH", score: numeric };
		if (numeric >= 4) return { severity: "MEDIUM", score: numeric };
		if (numeric > 0) return { severity: "LOW", score: numeric };
	}
	return { severity: "UNKNOWN", score: null };
}

function scoreFromVuln(vuln) {
	for (const s of vuln.severity || []) {
		const m = String(s.score || "").match(/(\d+(\.\d+)?)/);
		if (m) return parseFloat(m[1]);
	}
	return null;
}

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

/** Build the OSV package-name key for a dep (Maven uses g:a, npm uses bare name). */
function osvPkgName(dep) {
	return dep.ecosystem === "npm" ? dep.artifactId : `${dep.groupId}:${dep.artifactId}`;
}

/** Convert one OSV vuln to fad-check match shape. */
function vulnToMatch(dep, vuln) {
	const id = pickPrimaryId(vuln);
	const { severity, score } = severityFromOsv(vuln);
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
	const { verbose, offline, fetcher = globalThis.fetch } = opts;
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
			// Ecosystem-aware query: OSV uses "npm" for npm packages (name only,
			// no groupId), "Maven" for Maven (name = "g:a"). The dep record's
			// `ecosystem` field defaults to "maven" — npm collector sets "npm".
			const ecosystem = d.ecosystem === "npm" ? "npm" : "Maven";
			const pkgName = ecosystem === "npm" ? d.artifactId : `${d.groupId}:${d.artifactId}`;
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
			if (verbose) process.stdout.write(`\r   OSV batch ${++batchIdx}/${batches.length} (${batch.length} deps)…`);
			const res = await fetcher(`${OSV_BASE}/v1/querybatch`, {
				method: "POST",
				headers: { "Content-Type": "application/json", "User-Agent": "fad-check-osv" },
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
		if (verbose) process.stdout.write(`\r   OSV batches complete (${batches.length})                \n`);

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

	const detailById = new Map();
	let fetched = 0;
	for (const id of allIds) {
		const detailCacheKey = `vuln_${id}.json`;
		const hit = readCache(detailCacheKey);
		if (hit) { detailById.set(id, hit); continue; }
		if (offline) continue;
		try {
			const r = await fetcher(`${OSV_BASE}/v1/vulns/${encodeURIComponent(id)}`, {
				headers: { "User-Agent": "fad-check-osv" },
			});
			if (r.ok) {
				const body = await r.json();
				detailById.set(id, body);
				writeCache(detailCacheKey, body);
			}
		} catch { /* ignore individual failures */ }
		fetched++;
		if (verbose && fetched % 25 === 0) process.stdout.write(`\r   OSV details fetched: ${fetched}/${allIds.size}`);
	}
	if (verbose) process.stdout.write(`\r   OSV details fetched: ${fetched}/${allIds.size}                \n`);

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
				// Stub only — emit a minimal match with no description so the
				// report still surfaces it.
				matches.push({
					dep,
					cve: { id, severity: "UNKNOWN", score: null, description: "", fixVersion: null },
					source: "osv",
					confidence: "exact",
				});
				continue;
			}
			matches.push(vulnToMatch(dep, vuln));
		}
	}
	return matches;
}

/**
 * Public: query OSV for every dep in `resolvedDeps` Map, return fad-check-shape matches.
 */
async function queryOsvForDeps(resolvedDeps, opts = {}) {
	const deps = [];
	for (const d of resolvedDeps.values()) {
		if (!d.version || /\$\{|SNAPSHOT/i.test(d.version)) continue;
		if (d.scope === "parent") continue; // parents don't have OSV entries typically
		// npm version specifiers like "^1.0.0" can't be queried against OSV — need
		// a concrete version. Lockfiles always provide one; package.json-only deps
		// are skipped here.
		if (d.ecosystem === "npm" && /^[\^~>=<*]|^(latest|next|workspace:|git\+|file:|link:)/.test(d.version)) continue;
		deps.push({
			groupId: d.groupId, artifactId: d.artifactId, version: d.version,
			scope: d.scope, via: d.via, depth: d.depth, pomPaths: d.pomPaths,
			manifestPaths: d.manifestPaths,
			ecosystem: d.ecosystem || "maven",
			ecosystemType: d.ecosystemType,
			isDev: !!d.isDev,
		});
	}
	return queryBatch(deps, opts);
}

module.exports = {
	queryOsvForDeps,
	queryBatch,
	vulnToMatch,
	severityFromOsv,
	fixVersionFromOsv,
	OSV_CACHE_DIR,
};
