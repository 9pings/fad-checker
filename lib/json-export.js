/**
 * lib/json-export.js — emit a single machine-readable findings document.
 *
 * Unlike the CycloneDX SBOM (component-centric) or CSAF VEX (status-centric),
 * this is fad-checker's own flat findings format: every chapter (CVE, EOL,
 * obsolete, outdated, licenses, vendored) in one JSON, easy to diff between
 * audits and post-process. buildFindings is pure; writeFindings writes it.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const { purlFor } = require("./purl");

function coordOf(dep) {
	const ns = dep.namespace || dep.groupId || "";
	const name = dep.name || dep.artifactId;
	if (dep.ecosystem === "maven" && ns) return `${ns}:${name}`;
	if (dep.ecosystem === "composer" && ns) return `${ns}/${name}`;
	return name;
}

function depBrief(dep) {
	return {
		ecosystem: dep.ecosystem,
		coord: coordOf(dep),
		version: dep.version || null,
		scope: dep.scope || null,
		isDev: !!dep.isDev,
		purl: purlFor(dep),
		manifestPaths: dep.manifestPaths || dep.pomPaths || [],
	};
}

function cveFinding(m) {
	const c = m.cve;
	return {
		id: c.id,
		severity: c.severity || "UNKNOWN",
		cvss: c.score ?? null,
		cvssVector: c.cvssVector || null,
		epss: c.epssScore ?? null,
		epssPercentile: c.epssPercentile ?? null,
		kev: !!c.kev,
		kevDueDate: c.kevDueDate || null,
		priority: c.priority ? { band: c.priority.band, score: c.priority.score } : null,
		cwes: c.cwes || [],
		fixVersion: c.fixVersion || null,
		source: m.source || null,
		confidence: m.confidence || null,
		cpeFiltered: !!m.cpeFiltered,
		suppressed: !!m.suppressed,
		suppressedReason: m.suppressedReason || null,
		dep: depBrief(m.dep),
	};
}

const SEV = ["critical", "high", "medium", "low", "none", "unknown"];

/**
 * Build the findings document.
 * payload: { cveMatches, retireMatches, eolResults, obsoleteResults,
 *            outdatedResults, licenseResults, resolvedDeps, projectInfo, toolVersion }
 */
function buildFindings(payload = {}) {
	const {
		cveMatches = [], retireMatches = [], eolResults = [], obsoleteResults = [],
		outdatedResults = [], licenseResults = null, resolvedDeps, projectInfo = {}, toolVersion = "0",
	} = payload;

	const sevCounts = Object.fromEntries(SEV.map(s => [s, 0]));
	let kev = 0;
	for (const m of cveMatches) {
		if (m.cpeFiltered || m.suppressed) continue;
		const s = (m.cve.severity || "unknown").toLowerCase();
		sevCounts[s != null && sevCounts[s] != null ? s : "unknown"]++;
		if (m.cve.kev) kev++;
	}

	return {
		tool: { name: "fad-checker", version: String(toolVersion) },
		generatedAt: projectInfo.generatedAt || null,
		project: { name: projectInfo.name || null, src: projectInfo.src || null },
		summary: {
			dependencies: resolvedDeps?.size ?? null,
			cve: { ...sevCounts, kev, total: cveMatches.filter(m => !m.cpeFiltered && !m.suppressed).length },
			eol: eolResults.length,
			obsolete: obsoleteResults.length,
			outdated: outdatedResults.length,
			licensesFlagged: licenseResults?.flagged?.length || 0,
			vendored: retireMatches.length,
			suppressed: cveMatches.filter(m => m.suppressed).length,
		},
		cve: cveMatches.map(cveFinding),
		vendored: retireMatches.map(cveFinding),
		eol: eolResults.map(e => ({ product: e.product, eol: e.eol, dep: depBrief(e.dep) })),
		obsolete: obsoleteResults.map(o => ({ reason: o.reason || null, replacement: o.replacement || null, source: o.source || null, dep: depBrief(o.dep) })),
		outdated: outdatedResults.map(o => ({ latest: o.latest, releaseDate: o.releaseDate || null, dep: depBrief(o.dep) })),
		licenses: (licenseResults?.assessed || []).map(e => ({ category: e.category, licenses: e.ids.concat(e.raw), source: e.source || null, dep: depBrief(e.dep) })),
	};
}

function writeFindings(payload, outputPath) {
	const doc = buildFindings(payload);
	fs.writeFileSync(outputPath, JSON.stringify(doc, null, 2) + "\n");
	return doc;
}

module.exports = { buildFindings, writeFindings };
