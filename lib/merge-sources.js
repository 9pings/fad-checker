/**
 * lib/merge-sources.js — merge two match arrays into one, deduped per physical finding.
 *
 * Extracted from fad-checker.js so the merge contract is unit-testable: it is the seam
 * where every CVE source (CVEProject index, OSV.dev, OSV local DB, NVD CPE ranges,
 * Packagist advisories) meets every other.
 *
 * The primary key is (coordKey:version | cve.id). The same ADVISORY can arrive under
 * different primary ids though: OSV prefers a CVE alias (CVE-2026-86428) while the
 * Packagist audit record for it may carry no `cve` field at all and only its GHSA
 * remoteId (GHSA-8rr7-cvq3-gmfh) — measured on league/commonmark 2.4.2 in the
 * symfony-demo corpus, where a naive key-only merge emitted the same advisory twice.
 * So the merge is ALIAS-AWARE: a finding carries its aliases and ghsa, and an addition
 * whose id matches an existing finding's alias merges into it instead of duplicating.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
function mergeBySource(existing, additions) {
	// coordKey keeps embedded-binary findings distinct from a same-g:a:v declared dep
	// (see cve-match dedup). Falls back to g:a for any match lacking a coordKey.
	const coordOf = m => m.dep.coordKey || (m.dep.groupId + ":" + m.dep.artifactId);
	const keyOf = (m, id) => `${coordOf(m)}:${m.dep.version}|${id}`;
	const primary = m => keyOf(m, m.cve.id);
	// Every id a finding answers to: its primary id, its aliases, and its GHSA.
	const idsOf = m => [...new Set([m.cve.id, ...(m.cve.aliases || []), m.cve.ghsa].filter(Boolean))];

	const byKey = new Map();        // primary key → merged record
	const aliasIndex = new Map();   // keyOf(m, id) → primary key, for every alias
	const register = m => {
		for (const id of idsOf(m)) if (!aliasIndex.has(keyOf(m, id))) aliasIndex.set(keyOf(m, id), primary(m));
	};

	for (const m of existing || []) {
		const rec = { ...m, source: m.source || "fad" };
		byKey.set(primary(m), rec);
		register(rec);
	}
	for (const m of additions || []) {
		const key = primary(m);
		const targetKey = byKey.has(key) ? key : aliasIndex.get(key);
		if (targetKey) {
			const prev = byKey.get(targetKey);
			// The union is over source TOKENS, not source strings: an existing
			// "osv+packagist" record that absorbs another "packagist" constat must not
			// render as "osv+packagist+packagist".
			const sources = [...new Set([...String(prev.source || "").split("+"),
				...String(m.source || "").split("+")].filter(Boolean))].sort();
			const merged = {
				...prev,
				source: sources.length > 1 ? sources.join("+") : sources[0],
				cve: {
					...prev.cve,
					...m.cve,
					// the EXISTING finding keeps its primary id: OSV's CVE preference must
					// not be overridden by a source that keyed the same advisory by GHSA.
					id: prev.cve.id,
					// an advisory's identity is the UNION of its ids — dropping the
					// previous aliases on merge would unlink the alias index.
					aliases: [...new Set([...(prev.cve.aliases || []), ...(m.cve.aliases || [])])],
					ghsa: prev.cve.ghsa || m.cve.ghsa || null,
					// keep highest non-null score
					score: Math.max(prev.cve.score ?? 0, m.cve.score ?? 0) || prev.cve.score || m.cve.score,
					// prefer non-UNKNOWN severity
					severity: (prev.cve.severity && prev.cve.severity !== "UNKNOWN") ? prev.cve.severity : m.cve.severity,
					// prefer the longer description
					description: ((prev.cve.description || "").length > (m.cve.description || "").length) ? prev.cve.description : m.cve.description,
				},
			};
			byKey.set(targetKey, merged);
			register(merged);
		} else {
			const rec = { ...m, source: m.source || "osv" };
			byKey.set(key, rec);
			register(rec);
		}
	}
	const merged = [...byKey.values()];
	const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0, UNKNOWN: 0 };
	merged.sort((a, b) => {
		const sa = rank[(a.cve.severity || "UNKNOWN").toUpperCase()] || 0;
		const sb = rank[(b.cve.severity || "UNKNOWN").toUpperCase()] || 0;
		if (sb !== sa) return sb - sa;
		return (a.cve.id || "").localeCompare(b.cve.id || "");
	});
	return merged;
}

module.exports = { mergeBySource };
