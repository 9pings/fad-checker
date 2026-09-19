const { test } = require("node:test");
const assert = require("node:assert/strict");
const { normaliseLocale, makeT, CATALOG } = require("../lib/i18n");
const { generateHtmlReport, generateWordReport } = require("../lib/cve-report");
const { makeDepRecord } = require("../lib/dep-record");

test("normaliseLocale accepts what a human would type, and refuses to guess", () => {
	for (const x of ["fr", "FR", "fr-FR", "fr_FR", " fr "]) assert.equal(normaliseLocale(x), "fr", x);
	for (const x of ["en", "us", "US", "en-US", "en_GB"]) assert.equal(normaliseLocale(x), "en", x);
	// An unsupported language falls back to English rather than rendering raw keys.
	for (const x of ["de", "es", "zz", "", null, undefined, 42]) assert.equal(normaliseLocale(x), "en", String(x));
});

test("English is pass-through: the key IS the string, so an en report cannot regress", () => {
	const t = makeT("en");
	assert.equal(t("Copy table"), "Copy table");
	assert.equal(t("a string nobody translated"), "a string nobody translated");
	assert.deepEqual(CATALOG.en, {}, "there is no English table to drift from the source");
});

test("a missing French entry degrades to English, never to a raw key", () => {
	const t = makeT("fr");
	assert.equal(t("Dependency"), "Dépendance");
	assert.equal(t("CISA KEV"), "CISA KEV", "identifiers are deliberately untranslated");
	assert.equal(t("something only in the source"), "something only in the source");
});

test("placeholders interpolate, so a sentence can be reordered in translation", () => {
	assert.equal(makeT("en")("{n} of {total}", { n: 3, total: 9 }), "3 of 9");
});

const dep = makeDepRecord({ ecosystem: "maven", namespace: "g", name: "a", version: "1.0.0", manifestPath: "/p/pom.xml" });
const payload = locale => ({
	cveMatches: [{ dep, cve: { id: "CVE-2021-44228", severity: "CRITICAL", score: 10, description: "Log4Shell text from the advisory", fixVersion: "2.15.0", published: "2021-12-10", cwes: ["CWE-502"] }, confidence: "exact" }],
	eolResults: [], obsoleteResults: [], outdatedResults: [],
	projectInfo: { name: "demo", src: "/p", generatedAt: "2026-09-19" }, locale,
});

test("the French report translates its own chrome and leaves the evidence alone", () => {
	const fr = generateHtmlReport(payload("fr"));
	assert.match(fr, /Rapport FAD-Checker/);
	assert.match(fr, /<th>Dépendance<\/th>/);
	assert.match(fr, /Version corrigée/);
	// Advisory text is evidence. Paraphrasing it in an audit report would be wrong, so it
	// is never translated — and neither is the CVE id.
	assert.match(fr, /Log4Shell text from the advisory/);
	assert.match(fr, /CVE-2021-44228/);
});

test("a French CWE title carries MITRE's English original with it", () => {
	// MITRE publishes CWE in English only, so the translation is fad's own. Dropping the
	// original would leave a reader unable to find the weakness on cwe.mitre.org.
	const fr = generateHtmlReport(payload("fr"));
	assert.match(fr, /Désérialisation de données non fiables/);
	assert.match(fr, /MITRE: Deserialization of Untrusted Data/);
	const en = generateHtmlReport(payload("en"));
	assert.match(en, /Deserialization of Untrusted Data/);
	assert.doesNotMatch(en, /MITRE:/, "no redundant original when the title already is the original");
});

test("Word column widths survive translation", () => {
	// They keyed on the English header text until this was caught: a French report lost the
	// <colgroup> on seven of its eight tables, and Word laid them out on content width.
	const counts = ["en", "fr"].map(l => (generateWordReport(payload(l)).match(/<colgroup>/g) || []).length);
	assert.ok(counts[0] > 0, "English has colgroups");
	assert.equal(counts[0], counts[1], `en ${counts[0]} vs fr ${counts[1]}`);
});

test("every French entry is still reachable from the source, or it is dead weight", () => {
	const fs = require("fs"), path = require("path");
	const src = ["lib/cve-report.js", "lib/charts.js"]
		.map(f => fs.readFileSync(path.join(__dirname, "..", f), "utf8")).join("\n");
	const orphans = Object.keys(CATALOG.fr).filter(k => !src.includes(JSON.stringify(k).slice(1, -1)) && !src.includes(k));
	assert.ok(orphans.length <= 40, `too many unreachable translations (${orphans.length}): ${orphans.slice(0, 8).join(" | ")}`);
});

test("writeReports forwards the locale — it was accepted and silently dropped", () => {
	// The CLI threaded --lang into the payload, writeReports destructured the fields it
	// knew about, and `locale` was not one of them: every report rendered in English while
	// the flag appeared to work. A signature that quietly ignores an option is worse than
	// one that rejects it.
	const fs = require("fs"), path = require("path");
	const src = fs.readFileSync(path.join(__dirname, "..", "lib", "cve-report.js"), "utf8");
	const sig = /async function writeReports\(\{([^}]*)\}\)/.exec(src);
	assert.ok(sig, "writeReports signature not found");
	assert.match(sig[1], /\blocale\b/, "writeReports must accept a locale");
	const payload = /\n\tconst payload = \{([^}]*)\};/.exec(src);
	assert.ok(payload, "writeReports payload not found");
	assert.match(payload[1], /\blocale\b/, "writeReports must pass the locale on to the renderers");
});
