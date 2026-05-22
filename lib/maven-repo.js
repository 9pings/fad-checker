/**
 * lib/maven-repo.js — fan-out HTTP fetcher across the user's configured
 * Maven repositories with Maven Central as a final fallback.
 *
 * Use cases:
 *   - Fetching a transitive POM (lib/transitive.js)
 *   - Checking whether an artifact exists at all (HEAD)
 *   - Reading <maven-metadata.xml> for latest-version discovery
 *     (lib/outdated.js)
 *
 * Repository entry shape (from ~/.fad-check/config.json or CLI):
 *   { name?, url, auth? }   auth = "user:pass" (we wrap as Basic <base64>)
 *
 * URL convention: each repo URL must end at the directory under which Maven
 * artifacts are laid out the standard way:
 *   <repo-url>/<groupId-with-/>/<artifactId>/<version>/<artifactId>-<version>.pom
 *
 * The first 2xx wins. Misses are silently aggregated; the caller decides
 * what to do with "not found anywhere".
 */
const MAVEN_CENTRAL = { name: "central", url: "https://repo1.maven.org/maven2/" };

function normalise(url) {
	if (!url) return url;
	return url.endsWith("/") ? url : url + "/";
}

/**
 * Parse user:pass embedded in a URL (e.g. https://alice:s3cr3t@nexus.acme/...)
 * Returns { url, auth } where auth is "user:pass" stripped of the URL part.
 */
function splitUrlAuth(url) {
	if (!url) return { url, auth: null };
	try {
		const u = new URL(url);
		if (u.username || u.password) {
			const auth = decodeURIComponent(u.username) + ":" + decodeURIComponent(u.password);
			u.username = ""; u.password = "";
			return { url: u.toString(), auth };
		}
	} catch { /* not a URL — return as-is */ }
	return { url, auth: null };
}

/**
 * Build the effective repository list: user-configured + extras (from --repo
 * CLI) + Maven Central as final fallback. Dedupes by URL.
 */
function buildRepoList(userRepos, extraRepos = []) {
	const out = [];
	const seen = new Set();
	const push = r => {
		if (!r?.url) return;
		const { url, auth } = splitUrlAuth(normalise(r.url));
		if (seen.has(url)) return;
		seen.add(url);
		out.push({ name: r.name || url, url, auth: r.auth || auth || null });
	};
	for (const r of userRepos || []) push(r);
	for (const r of extraRepos || []) push(r);
	push(MAVEN_CENTRAL);
	return out;
}

function authHeader(auth) {
	if (!auth) return null;
	return "Basic " + Buffer.from(auth).toString("base64");
}

/**
 * Try fetching `pathSuffix` (relative to each repo URL) from every repo
 * in order. Returns the first 2xx response as { repo, response, body? }.
 *
 * opts:
 *   method     "GET" (default) | "HEAD"
 *   fetcher    custom fetch (for tests)
 *   readBody   read response.text() into body (default false to save mem
 *              on HEAD calls; transitive.js sets true for POMs)
 *   userAgent  default "fad-check-maven-repo"
 *   onMiss     callback(repo, status) for telemetry (verbose mode)
 */
async function tryRepos(repos, pathSuffix, opts = {}) {
	const { method = "GET", fetcher = globalThis.fetch, readBody = false, userAgent = "fad-check-maven-repo", onMiss } = opts;
	for (const repo of repos) {
		const url = repo.url + pathSuffix.replace(/^\//, "");
		const headers = { "User-Agent": userAgent };
		const ah = authHeader(repo.auth);
		if (ah) headers.Authorization = ah;
		let r;
		try {
			r = await fetcher(url, { method, headers });
		} catch (err) {
			if (onMiss) onMiss(repo, `network: ${err.message}`);
			continue;
		}
		if (r.ok) {
			let body = null;
			if (readBody && method !== "HEAD") {
				try { body = await r.text(); } catch { /* ignore body read fail */ }
			}
			return { repo, response: r, body, url };
		}
		if (onMiss) onMiss(repo, `HTTP ${r.status}`);
	}
	return null;
}

/** Convenience: HEAD an artifact (any of the listed repos) to check existence. */
function existsInAny(repos, pathSuffix, opts = {}) {
	return tryRepos(repos, pathSuffix, { ...opts, method: "HEAD" });
}

/** Convenience: GET a POM (text/xml) — sets readBody=true. */
function fetchPomFromRepos(repos, groupId, artifactId, version, opts = {}) {
	const p = `${groupId.replace(/\./g, "/")}/${artifactId}/${version}/${artifactId}-${version}.pom`;
	return tryRepos(repos, p, { ...opts, method: "GET", readBody: true });
}

/** Convenience: GET maven-metadata.xml (for latest-version discovery). */
function fetchMavenMetadata(repos, groupId, artifactId, opts = {}) {
	const p = `${groupId.replace(/\./g, "/")}/${artifactId}/maven-metadata.xml`;
	return tryRepos(repos, p, { ...opts, method: "GET", readBody: true });
}

module.exports = {
	MAVEN_CENTRAL,
	buildRepoList,
	tryRepos,
	existsInAny,
	fetchPomFromRepos,
	fetchMavenMetadata,
	splitUrlAuth,
	authHeader,
};
