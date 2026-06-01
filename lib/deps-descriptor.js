/**
 * lib/deps-descriptor.js — serialize / deserialize an *anonymized* descriptor of
 * the resolved dependency set, for PASSI-style offline→online→offline audits.
 *
 * Phase 1 (offline): collect deps → serializeDeps → write JSON. No paths, URLs,
 *   hostnames or usernames leave the air-gapped machine — only public package
 *   coordinates (ecosystem / namespace / name / version) + scope.
 * Phase 2 (online): read JSON → deserializeDeps → run the scan flow to warm the
 *   coordinate-keyed caches, then `--export-cache`.
 * Phase 3 (offline): `--import-cache` + a normal `--offline` scan re-collects the
 *   source locally (real paths) and gets cache hits → full detailed report.
 *
 * See docs/superpowers/specs/2026-05-30-anonymized-deps-descriptor-passi-design.md
 *
 * Pure functions: no I/O, no console. The caller does file read/write.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { makeDepRecord, coordKeyFor } = require("./dep-record");

const SCHEMA = "fad-deps/1";

// Fields kept in the descriptor — everything required to query the public vuln
// databases and to group the report. Anything path/URL/host-bearing is dropped:
//   manifestPath(s) / pomPaths, resolved (registry URL), integrity, from
//   (parent chain), depth, lockType.
const ANON_NOTE = "Anonymized: public coordinates only — no paths, URLs, or host info. Review before transfer.";

/**
 * serializeDeps(resolvedMap, opts) -> descriptor object (ready for JSON.stringify).
 *
 * opts:
 *   generator    — tool id/version string for traceability (no env info)
 *   generatedAt  — ISO timestamp (override for deterministic tests)
 *   note         — human-readable banner (defaults to the anonymization notice)
 */
function serializeDeps(resolvedMap, opts = {}) {
	const { generator = "fad-checker", generatedAt = new Date().toISOString(), note = ANON_NOTE } = opts;
	const deps = [];
	const byEcosystem = {};
	for (const d of resolvedMap.values()) {
		if (!d || !d.ecosystem || !d.name) continue;
		const versions = Array.isArray(d.versions) && d.versions.length
			? [...new Set(d.versions)]
			: (d.version ? [d.version] : []);
		deps.push({
			ecosystem: d.ecosystem,
			ecosystemType: d.ecosystemType || d.ecosystem,
			namespace: d.namespace || "",
			name: d.name,
			version: d.version || (versions[0] || null),
			versions,
			scope: d.scope || "prod",
			isDev: !!d.isDev,
		});
		byEcosystem[d.ecosystem] = (byEcosystem[d.ecosystem] || 0) + 1;
	}
	// Stable order so two runs over the same tree produce identical files (easier
	// to diff/review and to detect tampering during transfer).
	deps.sort((a, b) => (a.ecosystem + "\0" + a.namespace + "\0" + a.name).localeCompare(b.ecosystem + "\0" + b.namespace + "\0" + b.name));
	return {
		schema: SCHEMA,
		generator,
		generatedAt,
		note,
		summary: { total: deps.length, byEcosystem },
		deps,
	};
}

/**
 * deserializeDeps(descriptor) -> { resolved, activeIds, runMaven, runNpm }.
 *
 * Rebuilds depRecords with EMPTY manifestPaths (the descriptor carries none) and
 * a RECOMPUTED coordKey (never trusts the input). Throws on schema mismatch.
 */
function deserializeDeps(descriptor) {
	if (!descriptor || typeof descriptor !== "object") throw new Error("invalid descriptor: not an object");
	if (descriptor.schema !== SCHEMA) {
		throw new Error(`unsupported descriptor schema: got "${descriptor.schema}", expected "${SCHEMA}"`);
	}
	const list = Array.isArray(descriptor.deps) ? descriptor.deps : [];
	const resolved = new Map();
	const ecosystems = new Set();
	for (const e of list) {
		if (!e || !e.ecosystem || !e.name) continue;
		const rec = makeDepRecord({
			ecosystem: e.ecosystem,
			ecosystemType: e.ecosystemType || e.ecosystem,
			namespace: e.namespace || "",
			name: e.name,
			version: e.version || null,
			scope: e.scope || "prod",
			isDev: !!e.isDev,
			// manifestPath intentionally omitted → manifestPaths/pomPaths = []
		});
		// Restore the full multi-version set (makeDepRecord only derives it from the
		// single `version`); CVE/OSV matching iterates `versions`.
		if (Array.isArray(e.versions) && e.versions.length) rec.versions = [...new Set(e.versions)];
		resolved.set(coordKeyFor(e.ecosystem, e.namespace || "", e.name), rec);
		ecosystems.add(e.ecosystem);
	}
	const activeIds = [...ecosystems];
	return {
		resolved,
		activeIds,
		runMaven: ecosystems.has("maven"),
		runNpm: ecosystems.has("npm") || ecosystems.has("yarn"),
	};
}

module.exports = { serializeDeps, deserializeDeps, SCHEMA, ANON_NOTE };
