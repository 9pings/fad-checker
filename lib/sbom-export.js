/**
 * lib/sbom-export.js — emit a CycloneDX 1.6 SBOM with vulnerabilities inline
 * (a VDR — Vulnerability Disclosure Report) from the resolved deps + matches.
 *
 * buildCycloneDx is pure (testable); writeCycloneDx writes the JSON to disk.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const { purlFor } = require("./purl");

// NVD "CVSS:3.1" → CycloneDX rating method enum.
function cvssMethod(cvssVersion) {
	const v = String(cvssVersion || "");
	if (v.includes("4.0")) return "CVSSv4";
	if (v.includes("3.1")) return "CVSSv31";
	if (v.includes("3.0") || v === "CVSS:3") return "CVSSv3";
	if (v.includes("2.0") || v === "CVSS:2") return "CVSSv2";
	return "other";
}

function cdxSeverity(sev) {
	const s = (sev || "unknown").toLowerCase();
	return ["critical", "high", "medium", "low", "none", "info"].includes(s) ? s : "unknown";
}

function cweNum(c) {
	const m = String(c).match(/(\d+)/);
	return m ? parseInt(m[1], 10) : null;
}

function licenseEntry(ids) {
	// CycloneDX: {license:{id}} for SPDX ids, {license:{name}} otherwise.
	return (ids || []).map(x => /^[A-Za-z0-9.+-]+$/.test(x) && /[A-Z]/.test(x) ? { license: { id: x } } : { license: { name: x } });
}

/**
 * Build a CycloneDX 1.6 object.
 * opts: { projectInfo, toolVersion, timestamp, licenseResults }
 */
function buildCycloneDx(resolvedDeps, cveMatches, opts = {}) {
	const { projectInfo = {}, toolVersion = "0", timestamp, licenseResults } = opts;

	// coordKey → [spdx ids] for component licenses (optional).
	const licByCoord = new Map();
	for (const e of licenseResults?.assessed || []) {
		const key = e.dep?.coordKey || `${e.dep?.namespace || ""}:${e.dep?.name}`;
		const ids = (e.ids || []).concat(e.raw || []);
		if (ids.length) licByCoord.set(key, ids);
	}

	const components = [];
	for (const dep of resolvedDeps.values()) {
		const purl = purlFor(dep);
		const comp = { type: "library", name: dep.name || dep.artifactId, version: dep.version || undefined };
		if (dep.namespace || dep.groupId) comp.group = dep.namespace || dep.groupId;
		if (purl) { comp["bom-ref"] = purl; comp.purl = purl; }
		const lic = licByCoord.get(dep.coordKey);
		if (lic) comp.licenses = licenseEntry(lic);
		components.push(comp);
	}

	// One vulnerability entry per CVE id, aggregating affected component refs.
	const byCve = new Map();
	for (const m of cveMatches || []) {
		const id = m.cve?.id;
		if (!id) continue;
		const ref = purlFor(m.dep);
		let v = byCve.get(id);
		if (!v) {
			const cve = m.cve;
			v = {
				"bom-ref": `vuln-${id}`,
				id,
				source: { name: (m.source || "").includes("nvd") ? "NVD" : "OSV", url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}` },
				ratings: cve.score != null ? [{
					source: { name: "NVD" },
					score: cve.score,
					severity: cdxSeverity(cve.severity),
					method: cvssMethod(cve.cvssVersion),
					...(cve.cvssVector ? { vector: cve.cvssVector } : {}),
				}] : [],
				...(Array.isArray(cve.cwes) && cve.cwes.length ? { cwes: cve.cwes.map(cweNum).filter(n => n != null) } : {}),
				...(cve.description ? { description: cve.description } : {}),
				affects: [],
				properties: buildVulnProps(cve),
			};
			byCve.set(id, v);
		}
		if (ref && !v.affects.some(a => a.ref === ref)) v.affects.push({ ref });
		if (m.cpeFiltered) v.properties.push({ name: "fad:cpe-filtered", value: "true" });
	}

	const bom = {
		bomFormat: "CycloneDX",
		specVersion: "1.6",
		version: 1,
		metadata: {
			...(timestamp ? { timestamp } : {}),
			tools: { components: [{ type: "application", name: "fad-checker", version: String(toolVersion) }] },
			component: { type: "application", name: projectInfo.name || "project" },
		},
		components,
		vulnerabilities: [...byCve.values()],
	};
	return bom;
}

function buildVulnProps(cve) {
	const props = [];
	if (cve.epssScore != null) props.push({ name: "fad:epss", value: String(cve.epssScore) });
	if (cve.epssPercentile != null) props.push({ name: "fad:epssPercentile", value: String(cve.epssPercentile) });
	if (cve.kev) props.push({ name: "fad:kev", value: "true" });
	if (cve.priority?.band) props.push({ name: "fad:priorityBand", value: cve.priority.band });
	if (cve.priority?.score != null) props.push({ name: "fad:priorityScore", value: String(cve.priority.score) });
	return props;
}

function writeCycloneDx(resolvedDeps, cveMatches, outputPath, opts = {}) {
	const bom = buildCycloneDx(resolvedDeps, cveMatches, opts);
	fs.writeFileSync(outputPath, JSON.stringify(bom, null, 2) + "\n");
	return bom;
}

module.exports = { buildCycloneDx, writeCycloneDx, cvssMethod, cdxSeverity };
