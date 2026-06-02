const { test } = require("node:test");
const assert = require("node:assert");
const { generateHtmlReport } = require("../lib/cve-report");
const { makeDepRecord } = require("../lib/dep-record");

test("report renders a Part C inventory chapter for unmanaged binaries", () => {
	const resolved = new Map();
	const d = makeDepRecord({ ecosystem: "binary", name: "libssl.so.1.1", manifestPath: "/p/libssl.so.1.1", provenance: "binary", hashes: { sha1: "a".repeat(40), sha256: "b".repeat(64) }, declaredName: "libssl.so.1.1" });
	d.identity = { ecosystem: null, name: "openssl", version: "3.0", source: "circl:nsrl_modern" }; d.integrity = "known-good";
	resolved.set("binary:/p/libssl.so.1.1", d);
	const html = generateHtmlReport({ cveMatches: [], devCveMatches: [], embeddedMatches: [], retireMatches: [], eolResults: [], obsoleteResults: [], outdatedResults: [], licenseResults: null, resolvedDeps: resolved, projectInfo: { name: "t", src: "/p" }, warnings: [] });
	assert.match(html, /Unmanaged/);
	assert.match(html, /libssl\.so\.1\.1/);
	assert.match(html, /openssl/);
});
