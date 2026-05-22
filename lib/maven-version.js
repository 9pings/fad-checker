/**
 * lib/maven-version.js — Maven-flavoured version parsing and comparison.
 *
 * Maven version ordering rules (approximation of Apache Maven's
 * ComparableVersion):
 *   - Versions are split on `.` and `-` into segments.
 *   - Numeric segments compare numerically.
 *   - String segments compare via a qualifier ordering:
 *       alpha < beta < milestone < rc < snapshot < "" (release) < sp
 *   - Trailing zeros are insignificant: 1.0 == 1.0.0 == 1.
 *   - Known release qualifiers (final, release, ga) are treated as "".
 */

// Lower number == lower precedence
const QUALIFIER_ORDER = {
	"alpha": 1, "a": 1,
	"beta": 2, "b": 2,
	"milestone": 3, "m": 3,
	"rc": 4, "cr": 4,
	"snapshot": 5,
	"": 6, "ga": 6, "final": 6, "release": 6,
	"sp": 7,
};

function parseMavenVersion(versionStr) {
	if (versionStr == null) return { original: "", segments: [] };
	const original = String(versionStr).trim();
	if (!original) return { original: "", segments: [] };

	// Split on `.` and `-`, lowercase string segments
	const raw = original.toLowerCase().split(/[.\-]/);
	const segments = raw.map(s => {
		if (/^\d+$/.test(s)) return { kind: "num", value: parseInt(s, 10) };
		// Embedded numbers (e.g. "rc1" → ["rc", 1])
		const m = s.match(/^([a-z]+)(\d+)$/);
		if (m) return { kind: "qual+num", qual: m[1], num: parseInt(m[2], 10) };
		return { kind: "str", value: s };
	});
	return { original, segments };
}

function qualifierRank(q) {
	if (q == null) return QUALIFIER_ORDER[""];
	const r = QUALIFIER_ORDER[q.toLowerCase()];
	return r != null ? r : QUALIFIER_ORDER[""] - 0.5; // unknown qualifier sits just below release
}

function qualOf(seg) {
	if (!seg) return null;
	if (seg.kind === "str") return seg.value;
	if (seg.kind === "qual+num") return seg.qual;
	return null;
}

function cmpSegments(a, b) {
	// a or b may be missing — treat as numeric 0 (trailing zeros are insignificant)
	if (!a) {
		if (b.kind === "num") return b.value === 0 ? 0 : -1;
		// b is a qualifier (str or qual+num) — pre-release < release
		return qualifierRank("") - qualifierRank(qualOf(b));
	}
	if (!b) {
		if (a.kind === "num") return a.value === 0 ? 0 : 1;
		return qualifierRank(qualOf(a)) - qualifierRank("");
	}
	if (a.kind === "num" && b.kind === "num") return a.value - b.value;
	if (a.kind === "num") {
		// number vs qualifier — numbers are "newer" than pre-release qualifiers
		const r = qualifierRank(b.value);
		return r < QUALIFIER_ORDER[""] ? 1 : -1;
	}
	if (b.kind === "num") {
		const r = qualifierRank(a.value);
		return r < QUALIFIER_ORDER[""] ? -1 : 1;
	}
	if (a.kind === "qual+num" && b.kind === "qual+num") {
		const d = qualifierRank(a.qual) - qualifierRank(b.qual);
		return d !== 0 ? d : a.num - b.num;
	}
	if (a.kind === "qual+num") return qualifierRank(a.qual) - qualifierRank(b.value);
	if (b.kind === "qual+num") return qualifierRank(a.value) - qualifierRank(b.qual);
	return qualifierRank(a.value) - qualifierRank(b.value);
}

function compareMavenVersions(aStr, bStr) {
	const a = parseMavenVersion(aStr).segments;
	const b = parseMavenVersion(bStr).segments;
	const n = Math.max(a.length, b.length);
	for (let i = 0; i < n; i++) {
		const c = cmpSegments(a[i], b[i]);
		if (c !== 0) return c < 0 ? -1 : 1;
	}
	return 0;
}

/**
 * Check whether a dependency version falls within a CVE-specified range.
 * spec shape: { version, status, lessThan, lessThanOrEqual, versionType }
 * Returns true if depVersion is affected.
 */
function isVersionAffected(depVersion, spec) {
	if (!spec) return false;
	if (spec.status && spec.status !== "affected") return false;

	const dep = parseMavenVersion(depVersion);
	if (!dep.segments.length) return false;

	// Fail-closed: a spec with no version constraints at all carries no information.
	// Without this guard the function falls through to `return true` for every input,
	// which was the H1 cascade described in CRITICAL-REVIEW.md.
	const hasLower = spec.version && spec.version !== "0" && spec.version !== "*";
	if (!hasLower && !spec.lessThan && !spec.lessThanOrEqual) return false;

	// Lower bound (inclusive)
	if (spec.version && spec.version !== "0" && spec.version !== "*") {
		if (compareMavenVersions(depVersion, spec.version) < 0) return false;
	}
	// Upper bound exclusive
	if (spec.lessThan) {
		if (compareMavenVersions(depVersion, spec.lessThan) >= 0) return false;
	}
	// Upper bound inclusive
	if (spec.lessThanOrEqual) {
		if (compareMavenVersions(depVersion, spec.lessThanOrEqual) > 0) return false;
	}
	// Exact match with no bounds — only affected if equal
	if (!spec.lessThan && !spec.lessThanOrEqual && spec.version && spec.version !== "0" && spec.version !== "*") {
		if (compareMavenVersions(depVersion, spec.version) !== 0) return false;
	}
	return true;
}

/**
 * Parse a Maven version range expression like "[1.0,2.0)", "(,1.5]", "1.2.3".
 * Returns { lower, lowerInclusive, upper, upperInclusive, exact } or null.
 */
function parseRange(rangeStr) {
	if (rangeStr == null) return null;
	const s = String(rangeStr).trim();
	if (!s) return null;
	if (!/^[\[\(]/.test(s)) return { exact: s };
	const open = s[0];
	const close = s[s.length - 1];
	const inner = s.slice(1, -1);
	const [lo, hi] = inner.split(",").map(p => p.trim());
	return {
		lower: lo || null,
		lowerInclusive: open === "[",
		upper: hi || null,
		upperInclusive: close === "]",
	};
}

module.exports = {
	parseMavenVersion,
	compareMavenVersions,
	isVersionAffected,
	parseRange,
};
