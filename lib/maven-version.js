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
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
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
		// number vs qualifier — numbers are "newer" than pre-release qualifiers.
		// qualOf() reads the qualifier from BOTH str and qual+num segments (a bare
		// `.value` is undefined for qual+num and would mis-rank e.g. "1.0.rc1").
		const r = qualifierRank(qualOf(b));
		return r < QUALIFIER_ORDER[""] ? 1 : -1;
	}
	if (b.kind === "num") {
		const r = qualifierRank(qualOf(a));
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
// A bound participates in comparisons only if it looks like a version. CVE 5.x
// records carry placeholders in these fields ("log4j-core*", "*", "unspecified")
// — comparing those as Maven versions is garbage (alpha sorts below numeric), so
// CVE-2021-44228's `lessThan: "log4j-core*"` used to unmatch every real version.
function versionLikeBound(s) {
	return s != null && /^[0-9]/.test(String(s).trim()) && String(s).trim() !== "0";
}

function isVersionAffected(depVersion, spec) {
	if (!spec) return false;
	if (spec.status && spec.status !== "affected") return false;

	const dep = parseMavenVersion(depVersion);
	if (!dep.segments.length) return false;

	const lower = versionLikeBound(spec.version) && spec.version !== "*" ? spec.version : null;
	const upperExcl = versionLikeBound(spec.lessThan) ? spec.lessThan : null;
	const upperIncl = versionLikeBound(spec.lessThanOrEqual) ? spec.lessThanOrEqual : null;

	// Fail-closed: a spec with no usable version constraint carries no information.
	// Without this guard the function falls through to `return true` for every input,
	// which was the H1 cascade described in CRITICAL-REVIEW.md. A wildcard/placeholder
	// upper on its own does not count ({version:"*", lessThan:"*"} must stay inert).
	if (!lower && !upperExcl && !upperIncl) return false;

	// Lower bound (inclusive)
	if (lower && compareMavenVersions(depVersion, lower) < 0) return false;
	// Upper bound exclusive
	if (upperExcl && compareMavenVersions(depVersion, upperExcl) >= 0) return false;
	// Upper bound inclusive
	if (upperIncl && compareMavenVersions(depVersion, upperIncl) > 0) return false;
	// Exact match with no upper of ANY kind (not even a wildcard) — only affected if
	// equal. A wildcard upper ({version:"2.0", lessThan:"log4j-core*"}) instead means
	// "from 2.0 onward, unbounded", so it must NOT collapse to an exact match.
	if (lower && spec.lessThan == null && spec.lessThanOrEqual == null) {
		if (compareMavenVersions(depVersion, lower) !== 0) return false;
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
	versionLikeBound,
	parseRange,
};
