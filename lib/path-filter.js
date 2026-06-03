/**
 * lib/path-filter.js — directory-walk pruning policy shared by every codec walker.
 *
 * Two layers:
 *   - default skips: each walker's own basename set (node_modules, vendor, target,
 *     .git, …). Bypassable with useDefaults=false (CLI --no-default-excludes).
 *   - user globs: --exclude-path / `excludePath` config, matched gitignore-style
 *     against the directory's path RELATIVE to the scan root (`srcRoot`). A bare
 *     `foo/bar` matches that directory and its whole subtree (`foo/bar/**`).
 *
 * makeDirFilter() returns a predicate over a child directory's ABSOLUTE path, so
 * it drops straight into parallel-walk's skipDir and the serial readdir walkers.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const path = require("path");
const { minimatch } = require("minimatch");

/**
 * Compile glob strings into (relPath) → bool matchers. Each glob prunes both the
 * matched directory itself and its whole subtree, so `packages/legacy/**` (or the
 * bare `packages/legacy`) stops the walk at `packages/legacy` — a manifest sitting
 * directly in it is never collected.
 */
function compileGlobs(globs) {
	return (globs || []).filter(Boolean).map(String).map(g => g.trim()).filter(Boolean).map(g => {
		const base = g.replace(/\/+$/, "");
		const patterns = base.endsWith("/**")
			? [base, base.slice(0, -3).replace(/\/+$/, "")] // dir + its subtree
			: [base, base + "/**"];
		return rel => patterns.some(p => p && minimatch(rel, p, { dot: true }));
	});
}

/**
 * Build a skipDir(absChildDir) predicate.
 *   srcRoot       scan root the globs are relative to
 *   defaultSkip   Set of basenames the walker prunes by default (its own SKIP)
 *   excludePath   user glob strings
 *   useDefaults   when false, ignore defaultSkip entirely (--no-default-excludes)
 */
function makeDirFilter({ srcRoot, defaultSkip = null, excludePath = [], useDefaults = true } = {}) {
	const matchers = compileGlobs(excludePath);
	return function skipDir(absChild) {
		const name = path.basename(absChild);
		if (useDefaults && defaultSkip && defaultSkip.has(name)) return true;
		if (matchers.length && srcRoot) {
			const rel = path.relative(srcRoot, absChild).split(path.sep).join("/");
			if (rel && !rel.startsWith("..") && matchers.some(m => m(rel))) return true;
		}
		return false;
	};
}

module.exports = { makeDirFilter, compileGlobs };
