/**
 * lib/csaf-export.js — emit a CSAF 2.0 VEX (csaf_vex) document from the resolved
 * deps + matches. buildCsaf is pure; writeCsaf writes the JSON to disk.
 *
 * Spec: https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const { purlFor } = require("./purl");

function humanName(dep) {
	const ns = dep.namespace || dep.groupId || "";
	const name = dep.name || dep.artifactId;
	const base = dep.ecosystem === "composer" && ns ? `${ns}/${name}` : (ns && dep.ecosystem === "maven" ? `${ns}:${name}` : name);
	return dep.version ? `${base}@${dep.version}` : base;
}

// NVD "CVSS:3.1" → CVSS v3 JSON `version` field, or null when not a v3 score.
function cvssV3Version(cvssVersion) {
	const v = String(cvssVersion || "");
	if (v.includes("3.1")) return "3.1";
	if (v.includes("3.0") || v === "CVSS:3") return "3.0";
	return null;
}

/**
 * Build a CSAF 2.0 csaf_vex object.
 * opts: { projectInfo, toolVersion, timestamp }
 */
function buildCsaf(resolvedDeps, cveMatches, opts = {}) {
	const { projectInfo = {}, toolVersion = "0", timestamp } = opts;
	const now = timestamp || projectInfo.generatedAt || "1970-01-01T00:00:00Z";

	// Stable product ids + coordKey → product_id lookup.
	const full_product_names = [];
	const productIdByCoord = new Map();
	let n = 0;
	for (const dep of resolvedDeps.values()) {
		const pid = `PROD-${n++}`;
		const purl = purlFor(dep);
		productIdByCoord.set(dep.coordKey, pid);
		full_product_names.push({
			product_id: pid,
			name: humanName(dep),
			...(purl ? { product_identification_helper: { purl } } : {}),
		});
	}

	// One vulnerability per CVE, listing every affected product id.
	const byCve = new Map();
	for (const m of cveMatches || []) {
		const id = m.cve?.id;
		if (!id) continue;
		const pid = productIdByCoord.get(m.dep?.coordKey);
		let v = byCve.get(id);
		if (!v) {
			const cve = m.cve;
			const notes = [];
			if (cve.description) notes.push({ category: "description", text: cve.description, title: "Description" });
			const extras = [];
			if (cve.epssPercentile != null) extras.push(`EPSS percentile ${Math.round(cve.epssPercentile * 100)}%`);
			if (cve.kev) extras.push(`CISA KEV (known exploited)${cve.kevDueDate ? `, remediate by ${cve.kevDueDate}` : ""}`);
			if (cve.priority?.band) extras.push(`fad-checker priority: ${cve.priority.band} (${cve.priority.score}/100)`);
			if (extras.length) notes.push({ category: "other", text: extras.join("; "), title: "Prioritization" });

			const v3ver = cvssV3Version(cve.cvssVersion);
			const scores = (v3ver && cve.score != null) ? [{
				cvss_v3: {
					version: v3ver,
					baseScore: cve.score,
					baseSeverity: (cve.severity || "NONE").toUpperCase(),
					...(cve.cvssVector ? { vectorString: cve.cvssVector } : {}),
				},
				products: [],
			}] : [];

			v = {
				cve: id,
				...(notes.length ? { notes } : {}),
				product_status: { known_affected: [] },
				...(scores.length ? { scores } : {}),
				...(cve.kev ? { flags: [{ label: "exploited", product_ids: [] }] } : {}),
			};
			byCve.set(id, v);
		}
		if (pid && !v.product_status.known_affected.includes(pid)) {
			v.product_status.known_affected.push(pid);
			if (v.scores?.[0]) v.scores[0].products.push(pid);
			if (v.flags?.[0]) v.flags[0].product_ids.push(pid);
		}
	}

	return {
		document: {
			category: "csaf_vex",
			csaf_version: "2.0",
			title: `Vulnerability disclosure (VEX) — ${projectInfo.name || "project"}`,
			publisher: {
				category: "vendor",
				name: "fad-checker",
				namespace: "https://github.com/nathb2b/fad-checker",
			},
			tracking: {
				id: `fad-checker-${(projectInfo.name || "project").replace(/[^A-Za-z0-9._-]/g, "-")}-${String(now).slice(0, 10)}`,
				status: "final",
				version: "1",
				generator: { engine: { name: "fad-checker", version: String(toolVersion) } },
				initial_release_date: now,
				current_release_date: now,
				revision_history: [{ number: "1", date: now, summary: "Initial automated VEX from fad-checker scan" }],
			},
		},
		product_tree: { full_product_names },
		vulnerabilities: [...byCve.values()],
	};
}

function writeCsaf(resolvedDeps, cveMatches, outputPath, opts = {}) {
	const doc = buildCsaf(resolvedDeps, cveMatches, opts);
	fs.writeFileSync(outputPath, JSON.stringify(doc, null, 2) + "\n");
	return doc;
}

module.exports = { buildCsaf, writeCsaf };
