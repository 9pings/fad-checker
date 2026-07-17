/**
 * attributeMaskedMatches (lib/version-overlay.js).
 *
 * `versions[]` is tree-wide per coord; a match carries ONE version. An overlay-recovered
 * version (present in `maskedVersions[]`) is a TRANSITIVE of one specific module, but the
 * match inherits the shared record's DIRECT scope + pomPaths. On a scan spanning several
 * independent projects that reports project B's transitive as a direct dep of project A —
 * the pom that pins the FIXED version. The exec summary explicitly ranks "direct
 * production dependencies", so this is what surfaces the fixed coord as the top finding.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { attributeMaskedMatches } = require("../lib/version-overlay");

/** Shared record: declared direct at 1.27.1 in projA; overlay recovered projB's 1.24.0. */
function record() {
	return {
		groupId: "org.apache.commons", artifactId: "commons-compress",
		coordKey: "org.apache.commons:commons-compress",
		ecosystem: "maven", scope: "compile",
		version: "1.27.1", versions: ["1.27.1", "1.24.0"],
		pomPaths: ["projA/pom.xml"],
		maskedVersions: [{ version: "1.24.0", via: ["org.apache.poi:poi-ooxml"], viaPaths: [["org.apache.poi:poi-ooxml"]], module: "projB/pom.xml", depth: 1 }],
	};
}

test("a match on an overlay-recovered version is re-attributed to its resolving module", () => {
	const dep = record();
	const matches = [{ dep: { ...dep, version: "1.24.0" }, cve: { id: "CVE-2024-25710" } }];
	const n = attributeMaskedMatches(matches);

	assert.equal(n, 1);
	const d = matches[0].dep;
	assert.equal(d.scope, "transitive", "1.24.0 is a transitive, not projA's direct declaration");
	assert.deepEqual(d.via, ["org.apache.poi:poi-ooxml"], "carries the real via chain");
	assert.equal(d.depth, 1);
	assert.deepEqual(d.pomPaths, ["projB/pom.xml"], "filed under the module that resolves 1.24.0, not projA");
});

test("a match on the record's own declared version is left untouched", () => {
	const dep = record();
	const matches = [{ dep, cve: { id: "CVE-SOMETHING" } }];
	const n = attributeMaskedMatches(matches);

	assert.equal(n, 0);
	assert.equal(matches[0].dep.scope, "compile", "1.27.1 really is projA's direct declaration");
	assert.deepEqual(matches[0].dep.pomPaths, ["projA/pom.xml"]);
});

test("the shared resolvedDeps record is never mutated", () => {
	const dep = record();
	const shared = { ...dep, version: "1.24.0" };
	attributeMaskedMatches([{ dep: shared, cve: { id: "CVE-2024-25710" } }]);
	assert.equal(shared.scope, "compile", "re-stamping must clone, not mutate (other matches share the record)");
	assert.deepEqual(shared.pomPaths, ["projA/pom.xml"]);
});

test("deps with no maskedVersions and plain transitives are no-ops", () => {
	const plain = { groupId: "g", artifactId: "a", version: "1.0", scope: "compile", pomPaths: ["p/pom.xml"] };
	const trans = { groupId: "g", artifactId: "b", version: "2.0", scope: "transitive", via: ["g:root"] };
	const matches = [{ dep: plain, cve: { id: "C1" } }, { dep: trans, cve: { id: "C2" } }];
	assert.equal(attributeMaskedMatches(matches), 0);
	assert.equal(matches[0].dep.scope, "compile");
	assert.equal(matches[1].dep.scope, "transitive");
});
