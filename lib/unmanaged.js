/**
 * lib/unmanaged.js — enrich unmanaged (hash-bearing) records with online identity
 * + an integrity classification.
 *
 *   integrity:
 *     "pristine"    — deps.dev matched: file is byte-identical to a PUBLISHED package
 *                     artifact (so it's unmodified, and ought to be a managed dep).
 *     "known-good"  — CIRCL matched: a known OS/distro/CDN/NSRL file.
 *     "unknown"     — no source recognises the hash (suspicious / vendored unknown).
 *
 * Records carrying a declared coordinate (embedded jars) gain a "modified" status in
 * a later refinement; Plan 2 covers the hash-bearing binary records.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const { lookupHash, loadCache, saveCache } = require("./hash-id");

async function enrichUnmanaged(resolved, opts = {}) {
	const { fetcher, offline = false, cache, onProgress } = opts;
	const targets = [...resolved.values()].filter(d => d.hashes && (d.hashes.sha1 || d.hashes.sha256));
	const summary = { total: targets.length, identified: 0, pristine: 0, knownGood: 0, unknown: 0, malicious: 0 };
	if (!targets.length) return summary;
	const entries = cache || loadCache();
	let done = 0;
	for (const d of targets) {
		const id = await lookupHash(d.hashes, { fetcher, offline, cache: entries });
		d.identity = id || null;
		if (!id) d.integrity = "unknown";
		else if (id.source === "deps.dev") d.integrity = "pristine";
		else d.integrity = "known-good";
		if (id) summary.identified++;
		if (d.integrity === "pristine") summary.pristine++;
		else if (d.integrity === "known-good") summary.knownGood++;
		else summary.unknown++;
		if (id?.knownMalicious) summary.malicious++;
		if (onProgress) onProgress(++done, targets.length);
	}
	if (!cache && !offline) saveCache(entries);
	return summary;
}

module.exports = { enrichUnmanaged };
