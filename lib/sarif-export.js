/**
 * lib/sarif-export.js — emit a SARIF 2.1.0 log from CVE matches.
 *
 * SARIF is the integration standard for GitHub Code Scanning and GitLab: any
 * tool that emits it shows up in their dashboards with no custom glue. One
 * `reportingDescriptor` (rule) per unique CVE, one `result` per (CVE, dep)
 * match, located at the manifest that declares the dep.
 *
 * buildSarif is pure; writeSarif writes the JSON to disk.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const { purlFor } = require("./purl");

// CVSS/severity → SARIF result level.
function sarifLevel(sev) {
	switch ((sev || "").toUpperCase()) {
		case "CRITICAL":
		case "HIGH": return "error";
		case "MEDIUM": return "warning";
		default: return "note";
	}
}

function relUri(p, srcRoot) {
	if (!p) return null;
	if (srcRoot && path.isAbsolute(p)) {
		const r = path.relative(srcRoot, p);
		if (r && !r.startsWith("..")) return r.split(path.sep).join("/");
	}
	return String(p).split(path.sep).join("/");
}

function depCoord(dep) {
	const ns = dep.namespace || dep.groupId || "";
	const name = dep.name || dep.artifactId;
	if (dep.ecosystem === "maven" && ns) return `${ns}:${name}`;
	if (dep.ecosystem === "composer" && ns) return `${ns}/${name}`;
	return name;
}

/**
 * Build a SARIF 2.1.0 object from matches.
 * opts: { projectInfo, toolVersion }
 */
function buildSarif(matches, opts = {}) {
	const { projectInfo = {}, toolVersion = "0" } = opts;
	const srcRoot = projectInfo.src && projectInfo.src.startsWith("(") ? null : projectInfo.src;

	const rulesById = new Map();
	const results = [];

	for (const m of matches || []) {
		const id = m.cve?.id;
		if (!id) continue;
		const cve = m.cve;

		if (!rulesById.has(id)) {
			const rule = {
				id,
				name: id,
				shortDescription: { text: `${id} affecting ${depCoord(m.dep)}` },
				helpUri: id.startsWith("CVE-") ? `https://nvd.nist.gov/vuln/detail/${id}` : `https://osv.dev/vulnerability/${id}`,
				properties: {},
			};
			// GitHub Code Scanning reads `security-severity` (a CVSS number string).
			if (cve.score != null) rule.properties["security-severity"] = String(cve.score);
			const tags = ["security", "external/cwe", "dependency"];
			if (cve.kev) tags.push("known-exploited", "cisa-kev");
			rule.properties.tags = tags;
			if (Array.isArray(cve.cwes)) rule.properties.cwe = cve.cwes;
			rulesById.set(id, rule);
		}

		const coord = depCoord(m.dep);
		const purl = purlFor(m.dep);
		const bits = [`${coord}@${m.dep.version || "?"}`];
		if (cve.kev) bits.push("CISA-KEV (exploited)");
		if (cve.epssPercentile != null) bits.push(`EPSS ${Math.round(cve.epssPercentile * 100)}%`);
		if (cve.fixVersion) bits.push(`fix ≥ ${cve.fixVersion}`);
		const text = `${id} in ${bits.join(" · ")}${cve.description ? ` — ${cve.description.slice(0, 300)}` : ""}`;

		const locations = (m.dep.manifestPaths || m.dep.pomPaths || [])
			.map(p => relUri(p, srcRoot))
			.filter(Boolean)
			.map(uri => ({ physicalLocation: { artifactLocation: { uri } } }));

		const props = {};
		if (purl) props.purl = purl;
		if (cve.epssScore != null) props.epss = cve.epssScore;
		if (cve.epssPercentile != null) props.epssPercentile = cve.epssPercentile;
		if (cve.kev) props.kev = true;
		if (cve.priority?.band) props.priorityBand = cve.priority.band;
		if (m.dep.provenance && m.dep.provenance !== "manifest") props.provenance = m.dep.provenance;
		if (m.cpeFiltered) props.cpeFiltered = true;
		if (m.source) props.sources = m.source;

		results.push({
			ruleId: id,
			level: sarifLevel(cve.severity),
			message: { text },
			...(locations.length ? { locations } : {}),
			partialFingerprints: { fadKey: `${coord}@${m.dep.version || "?"}|${id}` },
			properties: props,
		});
	}

	return {
		$schema: "https://json.schemastore.org/sarif-2.1.0.json",
		version: "2.1.0",
		runs: [{
			tool: {
				driver: {
					name: "fad-checker",
					version: String(toolVersion),
					informationUri: "https://github.com/n8tz/fad-checker",
					rules: [...rulesById.values()],
				},
			},
			results,
		}],
	};
}

function writeSarif(matches, outputPath, opts = {}) {
	const doc = buildSarif(matches, opts);
	fs.writeFileSync(outputPath, JSON.stringify(doc, null, 2) + "\n");
	return doc;
}

module.exports = { buildSarif, writeSarif, sarifLevel };
