/**
 * lib/charts.js — compact, dependency-free SVG charts for the HTML report's
 * "Overview" row (rendered right under the summary totals).
 *
 * Why hand-rolled inline SVG (not <canvas>, not a chart lib, not pure-CSS):
 *   - self-contained: the report ships zero external assets, and an SVG is just
 *     markup — no runtime, no CDN. It even renders in the static .doc (no JS).
 *   - copy-to-Word: each chart rasterises SVG→<canvas>→PNG entirely in the
 *     browser (see the report's chart-copy script) and a PNG pastes into Word
 *     perfectly. A <div> has no native "→ PNG" API; an SVG does.
 *
 * Every visual attribute is INLINE on the SVG elements (fill/font-size/…), never
 * a CSS class — a class would not survive the canvas rasterisation (the document
 * stylesheet is not applied to the serialised SVG).
 *
 * Charts: (1) CWE of DIRECT vulns — donut, sliced by CWE, coloured by that CWE's
 * worst severity, legend carries the human CWE title; (2) vulnerable transitive
 * sub-deps per (root) dependency — readable horizontal bars stacked by severity,
 * with rootless transitives reported as a note rather than a bogus "unknown
 * root" bar; (3) reported CVE/elements — donut; (4) fix-priority bands — donut.
 *
 * Pure: aggregators take match arrays + counts → plain data; renderers turn that
 * into SVG strings. No I/O, no network.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { computePriority } = require("./priority");

const CWE_NAMES = (() => {
	try { const raw = { ...require("../data/cwe-names.json") }; delete raw._comment; return raw; }
	catch { return {}; }
})();
const cweName = id => CWE_NAMES[String(id || "").toUpperCase()] || "";

function esc(s) {
	if (s == null) return "";
	return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// Severity series (stacked bars) — colours mirror the report's severity badges.
const SEV_SERIES = [
	{ key: "critical", label: "Critical", color: "#7c0008" },
	{ key: "high",     label: "High",     color: "#c92a2a" },
	{ key: "medium",   label: "Medium",   color: "#f08c00" },
	{ key: "low",      label: "Low",      color: "#3b82f6" },
	{ key: "unknown",  label: "Unknown",  color: "#9ca3af" },
];
const SEV_COLOR = Object.fromEntries(SEV_SERIES.map(s => [s.key, s.color]));
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
const sevKey = m => {
	const s = (m && m.cve && m.cve.severity || "").toLowerCase();
	return s in SEV_RANK ? s : "unknown";
};
const emptySeg = () => ({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 });
const worstSev = seg => SEV_SERIES.map(s => s.key).find(k => seg[k] > 0) || "unknown";
const coordKeyOf = dep => dep.coordKey || `${dep.ecosystem === "npm" ? "npm:" : (dep.groupId || "") + ":"}${dep.artifactId}`;

// Keep the top-N rows; fold the remainder into a single "+K more" aggregate row
// (a chart must never silently drop categories).
function capRows(rows, topN, { stacked = false } = {}) {
	if (rows.length <= topN) return rows;
	const kept = rows.slice(0, topN);
	const rest = rows.slice(topN);
	if (stacked) {
		const seg = emptySeg();
		let total = 0;
		for (const r of rest) { for (const k of Object.keys(seg)) seg[k] += r.segments[k] || 0; total += r.total; }
		kept.push({ key: "__more__", label: `+${rest.length} more`, segments: seg, total, more: true });
	} else {
		const value = rest.reduce((a, r) => a + r.value, 0);
		kept.push({ key: "__more__", label: `+${rest.length} more`, value, color: "#9ca3af", more: true });
	}
	return kept;
}

// ---------------------------------------------------------------- aggregators

/** Chart 1 — CWE distribution of DIRECT production vulns, with per-severity counts. */
function cweByCriticality(prodMatches, { topN = 7 } = {}) {
	const map = new Map();
	for (const m of prodMatches || []) {
		if (m.dep && m.dep.scope === "transitive") continue;          // direct (declared) only
		const cwes = Array.isArray(m.cve && m.cve.cwes) ? m.cve.cwes : [];
		if (!cwes.length) continue;                                   // a "by CWE" chart only counts categorised findings
		const sev = sevKey(m);
		for (const c of cwes) {
			const id = String(c || "").toUpperCase();
			if (!id) continue;
			if (!map.has(id)) map.set(id, emptySeg());
			map.get(id)[sev]++;
		}
	}
	const rows = [...map.entries()].map(([id, segments]) => ({
		key: id,
		label: id,
		name: cweName(id),
		segments,
		total: SEV_SERIES.reduce((a, s) => a + segments[s.key], 0),
	})).sort((a, b) => b.total - a.total || a.key.localeCompare(b.key));
	return capRows(rows, topN, { stacked: true });
}

// Readable label for a root coordKey: the artifact / package name (the part a
// human recognises), e.g. "org.spring.boot:spring-boot-starter-web" → "spring-boot-starter-web".
function readableDepLabel(coordKey) {
	const s = String(coordKey || "");
	const seg = s.split("/").pop();                                   // npm "@scope/name" path tail
	const tail = seg.includes(":") ? seg.slice(seg.indexOf(":") + 1) : seg;
	return tail || s;
}

/** Chart 2 — sub-dep CVEs grouped by their ROOT (direct) dep, by severity.
 *  Counts CVEs (a sub-dep with 3 CVEs contributes 3), each in its own bucket. */
function vulnSubdepsByDep(prodMatches, { topN = 7 } = {}) {
	const roots = new Map();                                          // rootKey -> segments
	for (const m of prodMatches || []) {
		if (!m.dep || m.dep.scope !== "transitive") continue;
		const root = m.dep.via && m.dep.via[0];
		if (!root) continue;                                          // rootless → unattributedSubdeps()
		if (!roots.has(root)) roots.set(root, emptySeg());
		roots.get(root)[sevKey(m)]++;                                 // one count per CVE, in its own severity
	}
	const rows = [...roots.entries()].map(([root, segments]) => ({
		key: root,
		label: readableDepLabel(root),
		segments,
		total: SEV_SERIES.reduce((a, s) => a + segments[s.key], 0),
	})).filter(r => r.total > 0).sort((a, b) => b.total - a.total || a.key.localeCompare(b.key));
	return capRows(rows, topN, { stacked: true });
}

/** Sub-dep CVEs on transitive deps with no resolved root (e.g. npm). */
function unattributedSubdeps(prodMatches) {
	let n = 0;
	for (const m of prodMatches || []) {
		if (!m.dep || m.dep.scope !== "transitive") continue;
		if (m.dep.via && m.dep.via[0]) continue;
		n++;
	}
	return n;
}

/** Chart 3 — where the risk lives: direct vs transitive production vulns, with
 *  each side's per-severity breakdown carried in the legend (e.g. "2C 1H 1M"). */
function directVsTransitive(prodMatches) {
	const g = { direct: emptySeg(), transitive: emptySeg() };
	for (const m of prodMatches || []) {
		g[(m.dep && m.dep.scope === "transitive") ? "transitive" : "direct"][sevKey(m)]++;
	}
	const tot = seg => SEV_SERIES.reduce((a, s) => a + seg[s.key], 0);
	const summary = seg => SEV_SERIES.filter(s => seg[s.key] > 0).map(s => `${seg[s.key]}${s.label[0]}`).join(" ");
	const out = [];
	if (tot(g.direct))     out.push({ key: "direct",     label: "Direct",     name: summary(g.direct),     value: tot(g.direct),     color: "#4338ca" });
	if (tot(g.transitive)) out.push({ key: "transitive", label: "Transitive", name: summary(g.transitive), value: tot(g.transitive), color: "#d97706" });
	return out;
}

const FIX_BANDS = [
	{ key: "exploited", label: "Exploited", color: "#7c0008" },
	{ key: "critical",  label: "Critical",  color: "#b91c1c" },
	{ key: "high",      label: "High",      color: "#ea580c" },
	{ key: "medium",    label: "Medium",    color: "#ca8a04" },
	{ key: "low",       label: "Low",       color: "#2563eb" },
];
/** Chart 4 — fix-priority distribution (composite KEV/EPSS-weighted bands). */
function fixPriority(prodMatches) {
	const counts = { exploited: 0, critical: 0, high: 0, medium: 0, low: 0 };
	for (const m of prodMatches || []) {
		const p = (m.cve && m.cve.priority) || computePriority(m.cve || {});
		if (counts[p.band] != null) counts[p.band]++;
	}
	return FIX_BANDS.map(b => ({ key: b.key, label: b.label, value: counts[b.key], color: b.color })).filter(r => r.value > 0);
}

// ------------------------------------------------------------------ renderers

const FONT = "font-family='-apple-system,Segoe UI,Roboto,sans-serif'";

const legendStr = s => s.name ? `${s.label} · ${s.name} · ${s.value}` : `${s.label} · ${s.value}`;
const LEGEND_CHARW = 4.15;                          // ~px per char at the 7.5px legend font

// The viewBox width needed to fit the FULL legend text (no ellipsis). The caller
// takes the MAX across all four charts and feeds it to every donut, so they share
// one viewBox width → uniform donut size when each card is the same 25% slot.
function legendBoxWidth(slices, note) {
	const items = (slices || []).filter(s => s.value > 0);
	return Math.ceil(Math.max(0, ...items.map(s => 13 + legendStr(s).length * LEGEND_CHARW), note ? note.length * 4 : 0)) + 8;
}

// A donut + a legend underneath. slices: [{label, name?, value, color}].
// The legend carries the human title (so the principal CWEs read in plain text).
function donutChart({ slices, width = 250, note }) {
	const items = (slices || []).filter(s => s.value > 0);
	const total = items.reduce((a, s) => a + s.value, 0);
	const legendTxt = legendStr;
	const R = 47, cy = R + 4, cx = width / 2;
	const parts = [];
	if (items.length === 1) {
		parts.push(`<circle cx="${cx}" cy="${cy}" r="${R}" fill="${items[0].color}"/>`);
	} else {
		let a0 = -Math.PI / 2;
		for (const s of items) {
			const a1 = a0 + (s.value / total) * 2 * Math.PI;
			const x0 = cx + R * Math.cos(a0), y0 = cy + R * Math.sin(a0);
			const x1 = cx + R * Math.cos(a1), y1 = cy + R * Math.sin(a1);
			const large = (a1 - a0) > Math.PI ? 1 : 0;
			const tip = s.name ? `${s.label} — ${s.name}: ${s.value}` : `${s.label}: ${s.value}`;
			parts.push(`<path d="M${cx.toFixed(1)} ${cy.toFixed(1)} L${x0.toFixed(1)} ${y0.toFixed(1)} A${R} ${R} 0 ${large} 1 ${x1.toFixed(1)} ${y1.toFixed(1)} Z" fill="${s.color}" stroke="#ffffff" stroke-width="1"><title>${esc(tip)}</title></path>`);
			a0 = a1;
		}
	}
	parts.push(`<circle cx="${cx}" cy="${cy}" r="${(R * 0.58).toFixed(1)}" fill="#ffffff"/>`);
	parts.push(`<text x="${cx}" y="${cy + 5}" text-anchor="middle" ${FONT} font-size="17" font-weight="700" fill="#374151">${total}</text>`);
	let ly = R * 2 + 23;                             // +10px breathing room donut → legend
	for (const s of items) {                         // full legend text — no ellipsis
		parts.push(`<rect x="0" y="${ly - 7}" width="8" height="8" rx="1" fill="${s.color}"/>`);
		parts.push(`<text x="11" y="${ly}" ${FONT} font-size="7.5" fill="#4b5563">${esc(legendTxt(s))}</text>`);
		ly += 11;
	}
	if (note) { parts.push(`<text x="0" y="${ly}" ${FONT} font-size="7" font-style="italic" fill="#9ca3af">${esc(note)}</text>`); ly += 11; }
	return { body: parts.join(""), width, height: ly + 2 };
}

function chartCard({ id, title, body, width, height, interactive }) {
	// The title lives INSIDE the svg (so it travels with the copied PNG); the body
	// is shifted down to make room. The copy button is an HTML overlay (top-right).
	const titleH = 18;
	const h = Math.max(1, Math.round(height + titleH));
	const titleSvg = `<text x="0" y="12" ${FONT} font-size="10.5" font-weight="700" fill="#4b5563">${esc(title)}</text>`;
	const svg = `<svg class="chart-svg" xmlns="http://www.w3.org/2000/svg" width="${width}" height="${h}" viewBox="0 0 ${width} ${h}" role="img" aria-label="${esc(title)}"><rect x="0" y="0" width="${width}" height="${h}" fill="#ffffff"/>${titleSvg}<g transform="translate(0,${titleH})">${body}</g></svg>`;
	const copyBtn = interactive ? `<button class="btn-copy chart-copy" type="button" title="Copy this chart as a PNG — paste it into Word">📋</button>` : "";
	return `<figure class="chart-card" id="${esc(id)}">${copyBtn}${svg}</figure>`;
}

function emptyCard(id, title, note) {
	return `<figure class="chart-card" id="${esc(id)}"><figcaption class="chart-head"><span class="chart-title">${esc(title)}</span></figcaption><div class="chart-empty">${esc(note)}</div></figure>`;
}

/**
 * Build the four-chart "Overview" row. Returns "" when there is nothing to plot.
 */
function renderCharts(payload = {}, opts = {}) {
	const prod = payload.prodMatches || [];
	const cwe = cweByCriticality(prod);
	const subs = vulnSubdepsByDep(prod);
	const unattr = unattributedSubdeps(prod);
	const scope = directVsTransitive(prod);
	const prio = fixPriority(prod);

	if (!(cwe.length || subs.length || scope.length || prio.length || unattr)) return "";

	const interactive = opts.interactive !== false;       // copy button only in the interactive HTML

	const cweSlices = cwe.map(r => ({ label: r.key, name: r.name, value: r.total, color: SEV_COLOR[worstSev(r.segments)] }));
	// Donut per direct dep: slice size = its sub-dep CVE count, colour = worst
	// severity among them, legend = readable dep name + count.
	const subSlices = subs.map(r => ({ label: r.label, value: r.total, color: SEV_COLOR[worstSev(r.segments)] }));
	const note2 = unattr ? `+${unattr} transitive CVE(s) with no resolved root` : "";

	// One shared viewBox width across all four donuts (the widest legend) → with
	// equal-width (25%) flex cards they scale identically, so the donuts stay the
	// SAME size regardless of how long any single chart's legend is.
	const W = Math.max(250, legendBoxWidth(cweSlices), legendBoxWidth(subSlices, note2), legendBoxWidth(scope), legendBoxWidth(prio));

	const card1 = cwe.length
		? chartCard({ id: "chart-cwe", title: "CWE — direct vulns (by criticality)", interactive, ...donutChart({ slices: cweSlices, width: W }) })
		: emptyCard("chart-cwe", "CWE — direct vulns (by criticality)", "No categorised direct CVE.");

	const card2 = (subs.length || unattr)
		? chartCard({ id: "chart-subdeps", title: "Sub-dep CVEs per dependency", interactive, ...donutChart({ slices: subSlices, width: W, note: note2 }) })
		: emptyCard("chart-subdeps", "Sub-dep CVEs per dependency", "No vulnerable transitive deps.");

	const card3 = scope.length
		? chartCard({ id: "chart-scope", title: "Direct vs transitive (by severity)", interactive, ...donutChart({ slices: scope, width: W }) })
		: emptyCard("chart-scope", "Direct vs transitive (by severity)", "No production CVE.");

	const card4 = prio.length
		? chartCard({ id: "chart-priority", title: "Fix priority", interactive, ...donutChart({ slices: prio, width: W }) })
		: emptyCard("chart-priority", "Fix priority", "No production CVE.");

	return `<section class="charts-row" aria-label="Overview charts">${card1}${card2}${card3}${card4}</section>`;
}

module.exports = {
	cweByCriticality,
	vulnSubdepsByDep,
	unattributedSubdeps,
	directVsTransitive,
	fixPriority,
	renderCharts,
	SEV_SERIES,
};
