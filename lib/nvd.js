/**
 * lib/nvd.js — enrich already-found CVEs with the NIST NVD record.
 *
 * NVD's API doesn't expose a Maven-coord index, so we don't use it for
 * recall. Instead we look up each known CVE ID to get the canonical
 * description, full CVSS metrics (v2 / v3.1 / v4.0), CPE configurations,
 * and reference URLs.
 *
 * API: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-YYYY-NNNN
 * Rate limit: 5 req / 30s unauthenticated, 50 req / 30s with NVD_API_KEY env var.
 *
 * Cache: ~/.fad-check/nvd-cache/<cve-id>.json, 7-day TTL.
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const { getNvdApiKey } = require("./config");

const NVD_CACHE_DIR = path.join(os.homedir(), ".fad-check", "nvd-cache");
const NVD_CACHE_TTL_MS = 7 * 24 * 3600 * 1000;
const NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";

function getRateDelay() {
	// 50 req / 30s with API key, 5 req / 30s without
	return getNvdApiKey() ? 600 : 6000;
}

function cachePath(cveId) {
	return path.join(NVD_CACHE_DIR, `${cveId}.json`);
}

function readCache(cveId) {
	const p = cachePath(cveId);
	if (!fs.existsSync(p)) return null;
	try {
		const data = JSON.parse(fs.readFileSync(p, "utf8"));
		if (Date.now() - data._fetchedAt < NVD_CACHE_TTL_MS) return data.body;
	} catch { /* ignore */ }
	return null;
}

function writeCache(cveId, body) {
	fs.mkdirSync(NVD_CACHE_DIR, { recursive: true });
	fs.writeFileSync(cachePath(cveId), JSON.stringify({ _fetchedAt: Date.now(), body }));
}

function bestMetric(metrics) {
	// NVD 2.0 returns metrics organised by version: cvssMetricV40, V31, V30, V2
	const order = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"];
	for (const k of order) {
		if (Array.isArray(metrics?.[k]) && metrics[k].length) {
			const cv = metrics[k][0].cvssData;
			return {
				version: k.replace("cvssMetric", "CVSS:"),
				score: cv.baseScore,
				severity: (cv.baseSeverity || severityFromScore(cv.baseScore) || "UNKNOWN").toUpperCase(),
				vector: cv.vectorString,
			};
		}
	}
	return null;
}

function severityFromScore(s) {
	if (s == null) return null;
	if (s >= 9) return "CRITICAL";
	if (s >= 7) return "HIGH";
	if (s >= 4) return "MEDIUM";
	if (s > 0) return "LOW";
	return "NONE";
}

function extractFromNvdRecord(record) {
	if (!record) return null;
	const desc = (record.descriptions || []).find(d => d.lang === "en")?.value || "";
	const metric = bestMetric(record.metrics);
	// Keep each reference together with its NVD tags (Patch, Exploit, Vendor Advisory, Third Party Advisory, Mailing List, ...)
	const refs = (record.references || []).map(r => ({
		url: r.url,
		source: r.source || null,
		tags: r.tags || [],
	}));
	const cpes = [];
	for (const c of record.configurations || []) {
		for (const n of c.nodes || []) {
			for (const m of n.cpeMatch || []) cpes.push(m.criteria);
		}
	}
	// Preserve the full configurations tree so cve-match / cpe.js can evaluate
	// AND/OR nodes and version ranges (versionStartIncluding, etc.). We strip
	// `matchCriteriaId` and other UUID-only fields to keep the cache compact.
	const configurations = (record.configurations || []).map(c => ({
		operator: c.operator || "OR",
		negate: c.negate || false,
		nodes: (c.nodes || []).map(slimNode),
	}));
	return {
		id: record.id,
		description: desc,
		severity: metric?.severity || "UNKNOWN",
		score: metric?.score ?? null,
		cvssVector: metric?.vector || null,
		cvssVersion: metric?.version || null,
		published: record.published || null,
		modified: record.lastModified || null,
		references: refs,
		cpes,
		configurations,
	};
}

function slimNode(n) {
	return {
		operator: n.operator || "OR",
		negate: n.negate || false,
		cpeMatch: (n.cpeMatch || []).map(m => ({
			vulnerable: m.vulnerable !== false,
			criteria: m.criteria,
			versionStartIncluding: m.versionStartIncluding,
			versionStartExcluding: m.versionStartExcluding,
			versionEndIncluding: m.versionEndIncluding,
			versionEndExcluding: m.versionEndExcluding,
		})),
		children: Array.isArray(n.children) ? n.children.map(slimNode) : undefined,
	};
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function fetchOne(cveId, opts = {}) {
	const { fetcher = globalThis.fetch, verbose, offline } = opts;
	const cached = readCache(cveId);
	if (cached !== null && cached !== undefined) return cached;
	if (offline) return null;
	const headers = { "User-Agent": "fad-check-nvd-enrich" };
	const key = getNvdApiKey();
	if (key) headers["apiKey"] = key;
	const url = `${NVD_BASE}?cveId=${encodeURIComponent(cveId)}`;
	try {
		const r = await fetcher(url, { headers });
		if (r.status === 404) { writeCache(cveId, null); return null; }
		if (!r.ok) {
			if (verbose) console.warn(`   NVD HTTP ${r.status} for ${cveId}`);
			return null;
		}
		const data = await r.json();
		const record = data.vulnerabilities?.[0]?.cve;
		const extracted = extractFromNvdRecord(record);
		writeCache(cveId, extracted);
		return extracted;
	} catch (err) {
		if (verbose) console.warn(`   NVD fetch failed for ${cveId}: ${err.message}`);
		return null;
	}
}

/**
 * Enrich an array of fad-check matches in place by fetching their NVD records.
 * Adds: cve.description (replaced by NVD's), cve.cvssVector, cve.cvssVersion,
 * cve.references, cve.cpes. Severity/score are only overwritten if currently UNKNOWN/null.
 *
 * Rate limited per the NIST policy (use NVD_API_KEY for faster access).
 */
async function enrichMatches(matches, opts = {}) {
	const { verbose, offline } = opts;
	const uniqueCves = new Set();
	for (const m of matches) if (m.cve?.id?.startsWith("CVE-")) uniqueCves.add(m.cve.id);
	const hasKey = !!getNvdApiKey();
	const delay = getRateDelay();
	if (verbose) console.log(`🔍 NVD: enriching ${uniqueCves.size} unique CVEs${offline ? " (offline — cache only)" : hasKey ? " (with API key, 50/30s)" : " (no API key — throttled to 5/30s; pass --set-nvd-key for 10× faster)"}…`);

	const byId = new Map();
	let i = 0;
	for (const cveId of uniqueCves) {
		// Only sleep between live (non-cached) requests.
		const cached = readCache(cveId);
		if (cached !== null && cached !== undefined) {
			byId.set(cveId, cached);
			continue;
		}
		if (offline) { byId.set(cveId, null); continue; }
		const data = await fetchOne(cveId, opts);
		byId.set(cveId, data);
		i++;
		if (verbose && i % 5 === 0) process.stdout.write(`\r   NVD: ${i} fetched`);
		// Rate limit between requests
		await sleep(delay);
	}
	if (verbose && i) process.stdout.write(`\r   NVD: ${i} fetched                  \n`);

	for (const m of matches) {
		const data = byId.get(m.cve?.id);
		if (!data) continue;
		// Merge: prefer NVD's official text + CVSS but keep what fad-check/OSV already has
		// NVD's description is the official long form — prefer it when available.
		if (data.description) {
			m.cve.description = data.description.length > 2000
				? data.description.slice(0, 2000) + "…"
				: data.description;
		}
		if (m.cve.severity === "UNKNOWN" || !m.cve.severity) m.cve.severity = data.severity;
		if (m.cve.score == null) m.cve.score = data.score;
		m.cve.cvssVector = data.cvssVector || null;
		m.cve.cvssVersion = data.cvssVersion || null;
		m.cve.nvdRefs = data.references || [];   // [{url, tags, source}]
		m.cve.cpes = data.cpes || [];
		m.cve.configurations = data.configurations || [];
		// Tag NVD as a contributing source so the report shows fad+nvd / osv+nvd.
		const sources = new Set((m.source || "").split("+").filter(Boolean));
		sources.add("nvd");
		m.source = [...sources].sort().join("+");
	}
	return matches;
}

module.exports = {
	enrichMatches,
	fetchOne,
	extractFromNvdRecord,
	NVD_CACHE_DIR,
	getNvdApiKey,
};
