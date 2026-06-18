const { test } = require("node:test");
const assert = require("node:assert");

const { diffFindings, summarizeDiff, findingKey, newProductionCveCount } = require("../lib/diff");

function cve(id, coord, version, extra = {}) {
	return { id, severity: extra.severity || "HIGH", suppressed: !!extra.suppressed, cpeFiltered: !!extra.cpeFiltered, dep: { ecosystem: extra.ecosystem || "maven", coord, version } };
}
function doc(cveArr, extra = {}) {
	return { cve: cveArr, eol: extra.eol || [], obsolete: [], outdated: extra.outdated || [], licenses: [] };
}

test("findingKey is stable on id + ecosystem + coord + version", () => {
	const k1 = findingKey(cve("CVE-1", "g:a", "1.0.0"));
	const k2 = findingKey(cve("CVE-1", "g:a", "1.0.0", { severity: "LOW" }));
	assert.strictEqual(k1, k2, "severity does not affect identity");
	assert.notStrictEqual(k1, findingKey(cve("CVE-1", "g:a", "2.0.0")), "version changes identity");
});

test("diffFindings classifies added / removed / unchanged CVEs", () => {
	const base = doc([cve("CVE-1", "g:a", "1.0.0"), cve("CVE-2", "g:b", "2.0.0")]);
	const cur = doc([cve("CVE-1", "g:a", "1.0.0"), cve("CVE-3", "g:c", "3.0.0")]);
	const d = diffFindings(base, cur);
	assert.deepStrictEqual(d.cve.added.map(f => f.id), ["CVE-3"]);
	assert.deepStrictEqual(d.cve.removed.map(f => f.id), ["CVE-2"]);
	assert.deepStrictEqual(d.cve.unchanged.map(f => f.id), ["CVE-1"]);
});

test("a version bump shows the old finding removed and the new one added", () => {
	const base = doc([cve("CVE-9", "g:a", "1.0.0")]);
	const cur = doc([cve("CVE-9", "g:a", "1.0.1")]);
	const d = diffFindings(base, cur);
	assert.strictEqual(d.cve.added.length, 1);
	assert.strictEqual(d.cve.removed.length, 1);
});

test("diffFindings diffs EOL and outdated categories by dep identity", () => {
	const base = { cve: [], eol: [{ product: "java", dep: { ecosystem: "maven", coord: "g:a", version: "8" } }], obsolete: [], outdated: [], licenses: [] };
	const cur = { cve: [], eol: [], obsolete: [], outdated: [{ latest: "2.0", dep: { ecosystem: "npm", coord: "left-pad", version: "1.0" } }], licenses: [] };
	const d = diffFindings(base, cur);
	assert.strictEqual(d.eol.removed.length, 1);
	assert.strictEqual(d.outdated.added.length, 1);
});

test("summarizeDiff counts; new production CVEs exclude suppressed and cpe-filtered", () => {
	const base = doc([]);
	const cur = doc([
		cve("CVE-A", "g:a", "1.0.0", { severity: "CRITICAL" }),
		cve("CVE-B", "g:b", "1.0.0", { suppressed: true }),
		cve("CVE-C", "g:c", "1.0.0", { cpeFiltered: true }),
	]);
	const d = diffFindings(base, cur);
	assert.strictEqual(newProductionCveCount(d), 1, "only CVE-A is a new production finding");
	const s = summarizeDiff(d);
	assert.strictEqual(s.cve.added, 3);
	assert.strictEqual(s.cve.addedProduction, 1);
	assert.strictEqual(s.cve.addedBySeverity.CRITICAL, 1);
});

test("diffFindings tolerates a baseline document missing a category", () => {
	const base = { cve: [cve("CVE-1", "g:a", "1.0.0")] }; // no eol/outdated keys
	const cur = doc([cve("CVE-1", "g:a", "1.0.0")]);
	const d = diffFindings(base, cur);
	assert.strictEqual(d.cve.unchanged.length, 1);
	assert.strictEqual(d.eol.added.length, 0);
});
