/**
 * lib/source-health.js — is this report complete, and if not, which source went dark?
 *
 * An audit tool's worst output is a scan that ran to completion with a quiet hole in it.
 * `lib/maven-repo.js` already reasons this way for mirrors ("dropping Central would
 * silently turn a transient blip into a coverage hole"), but only Maven mirrors were
 * covered and nothing was ever reported. This generalises it to every remote source.
 *
 * The rule, ONLINE only:
 *   - a lookup served from the warm cache issues no request, so a source whose cache
 *     covers everything is silent even if the site is down. That is full coverage.
 *   - a request that gets no usable answer after the retry schedule is a hole. The run
 *     stops before writing anything, naming the domain, the codes, the failing URL and
 *     the flag that disables that source.
 * `--offline` never aborts: that mode's contract is already "warm cache only".
 *
 * A definitive 404/410 is an ANSWER, not an outage — it is precisely how private and
 * internal packages are detected (lib/private-deps.js). Only 403/429/5xx and transport
 * failures count against a host.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */

/** Remote sources, by id. `hosts` are matched as exact host or dot-suffix. */
const SOURCES = {
	cve:      { label: "CVE index (CVEProject)",   flag: "--cve-offline",   hosts: ["github.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "codeload.github.com"] },
	osv:      { label: "OSV.dev",                  flag: "--no-osv",        hosts: ["api.osv.dev", "osv-vulnerabilities.storage.googleapis.com"] },
	nvd:      { label: "NVD (NIST)",               flag: "--no-nvd",        hosts: ["services.nvd.nist.gov", "nvd.nist.gov"] },
	epss:     { label: "EPSS (FIRST.org)",         flag: "--no-epss",       hosts: ["api.first.org", "epss.cyentia.com"] },
	kev:      { label: "CISA KEV",                 flag: "--no-kev",        hosts: ["cisa.gov"] },
	eol:      { label: "endoflife.date",           flag: "--no-eol",        hosts: ["endoflife.date"] },
	maven:    { label: "Maven Central",            flag: "--no-transitive --no-all-libs", hosts: ["repo1.maven.org", "repo.maven.apache.org", "search.maven.org", "storage-download.googleapis.com"] },
	npm:      { label: "npm registry",             flag: "--no-npm",        hosts: ["registry.npmjs.org"] },
	pypi:     { label: "PyPI",                     flag: "--no-pypi",       hosts: ["pypi.org", "files.pythonhosted.org"] },
	nuget:    { label: "NuGet",                    flag: "--no-nuget",      hosts: ["api.nuget.org", "nuget.org"] },
	composer: { label: "Packagist",                flag: "--no-composer",   hosts: ["repo.packagist.org", "packagist.org"] },
	ruby:     { label: "RubyGems",                 flag: "--no-ruby",       hosts: ["rubygems.org"] },
	go:       { label: "Go module proxy",          flag: "--no-go",         hosts: ["proxy.golang.org"] },
	binary:   { label: "Binary identity (deps.dev + CIRCL)", flag: "--no-binaries", hosts: ["api.deps.dev", "deps.dev", "hashlookup.circl.lu"] },
};

const RETRY_ATTEMPTS = 5;
/** 5 + n seconds: 6, 7, 8, 9, 10. ~40s before a host is declared dead, once per host. */
function retryDelaysMs() {
	return Array.from({ length: RETRY_ATTEMPTS }, (_, i) => (5 + i + 1) * 1000);
}

function hostOf(url) {
	try { return new URL(String(url)).hostname.toLowerCase(); } catch { return null; }
}

/** The source a URL belongs to, or null when the host is none of ours (leave it alone). */
function sourceForUrl(url) {
	const host = hostOf(url);
	if (!host) return null;
	for (const [id, s] of Object.entries(SOURCES)) {
		if (s.hosts.some(h => host === h || host.endsWith("." + h))) return { id, ...s };
	}
	return null;
}

/**
 * "answered"    — the host spoke, including a definitive 404/410 or a 4xx we caused.
 * "unavailable" — throttled (429), walled off (403), broken (5xx), or no transport at all.
 */
function classifyResponse(res, err) {
	if (err) return "unavailable";
	if (!res) return "unavailable";
	const status = Number(res.status) || 0;
	if (status === 403 || status === 429 || status >= 500) return "unavailable";
	return "answered";
}

function errCode(res, err) {
	if (err) {
		const m = /\b(E[A-Z]{3,}|ENOTFOUND|ECONNREFUSED|ETIMEDOUT|UND_ERR_[A-Z_]+)\b/.exec(err.message || "");
		return m ? m[1] : (err.message || "network error").slice(0, 60);
	}
	return `HTTP ${res?.status ?? "?"}`;
}

/** Per-run ledger of sources that went dark. */
function createSourceHealth() {
	const down = new Map();
	return {
		isDown: id => down.has(id),
		markOutage(id, { url, code }) {
			let e = down.get(id);
			if (!e) { e = { id, url, codes: [], attempts: 0 }; down.set(id, e); }
			e.attempts += 1;
			if (code && !e.codes.includes(code)) e.codes.push(code);
			return e;
		},
		degraded: () => [...down.values()],
	};
}

/** The block printed instead of a report. Names the domain, codes, URL and flag. */
function formatAbort(entries) {
	const lines = [];
	const many = entries.length > 1;
	lines.push(`${entries.length} source${many ? "s" : ""} injoignable${many ? "s" : ""} — le rapport serait incomplet, aucun fichier n'a été écrit.`);
	lines.push("");
	for (const e of entries) {
		const s = SOURCES[e.id] || { label: e.id, flag: "", hosts: [] };
		lines.push(`  ${s.label} — ${s.hosts[0] || "?"}`);
		lines.push(`    codes    ${e.codes.join(", ") || "aucune réponse"}   (${RETRY_ATTEMPTS} tentatives, 6→10 s)`);
		lines.push(`    url      ${e.url}`);
		lines.push(`    ignorer  ${s.flag}`);
		lines.push("");
	}
	lines.push("  Relancer avec le ou les flags ci-dessus pour auditer sans ces sources,");
	lines.push("  ou avec --offline pour n'utiliser que le cache (zéro réseau).");
	return lines.join("\n");
}

/**
 * Wrap a fetch so every request to a known source is retried on an outage, each retry
 * logged, and a host that never comes back is recorded once. Requests to hosts we do not
 * own pass through untouched. A host already marked down throws immediately rather than
 * burning the schedule again on each of the remaining lookups.
 */
function guardedFetch({ health, fetch: baseFetch = globalThis.fetch, sleep = ms => new Promise(r => setTimeout(r, ms)), onRetry = null } = {}) {
	const delays = retryDelaysMs();
	// One recovery schedule per source, shared by every concurrent caller. The first request
	// to hit an outage owns the loop; the rest await its verdict instead of each sleeping
	// 40s of their own — on a 400-dependency reactor that difference is the whole run.
	const probes = new Map();

	/**
	 * Run the retry schedule for `src`, starting from the failure the caller already saw
	 * (so the first retry notice carries the real code, not a placeholder).
	 * → { alive: true, res } as soon as the host answers, or { alive: false } once exhausted.
	 */
	async function recover(src, url, init, first) {
		let res = first.res, err = first.err;
		for (let attempt = 0; attempt < RETRY_ATTEMPTS; attempt++) {
			if (onRetry) onRetry({ source: src.id, label: src.label, attempt: attempt + 1, of: RETRY_ATTEMPTS, code: errCode(res, err), delayMs: delays[attempt], url: String(url) });
			await sleep(delays[attempt]);
			res = null; err = null;
			try { res = await baseFetch(url, init); }
			catch (e) { err = e; }
			if (classifyResponse(res, err) === "answered") return { alive: true, res };
		}
		health.markOutage(src.id, { url: String(url), code: errCode(res, err) });
		return { alive: false };
	}

	return async function guarded(url, init) {
		const src = sourceForUrl(typeof url === "string" ? url : url?.url);
		if (!src) return baseFetch(url, init);
		if (health.isDown(src.id)) {
			throw new Error(`${src.label} already unreachable this run (${src.flag} to scan without it)`);
		}
		let res = null, err = null;
		try { res = await baseFetch(url, init); }
		catch (e) { err = e; }
		if (classifyResponse(res, err) === "answered") return res;

		let probe = probes.get(src.id);
		const owner = !probe;
		if (owner) {
			probe = recover(src, url, init, { res, err }).finally(() => probes.delete(src.id));
			probes.set(src.id, probe);
		}
		const verdict = await probe;
		if (!verdict.alive) {
			if (err) throw err;
			return res;
		}
		// The owner already holds the answer its own schedule produced.
		if (owner) return verdict.res;
		// A waiter's URL is not the one that was probed, so re-issue it. If THAT still fails,
		// the host is up but this lookup is genuinely holed — record it rather than return a
		// silent gap.
		let r2 = null, e2 = null;
		try { r2 = await baseFetch(url, init); }
		catch (e) { e2 = e; }
		if (classifyResponse(r2, e2) !== "answered") {
			health.markOutage(src.id, { url: String(url), code: errCode(r2, e2) });
			if (e2) throw e2;
		}
		return r2;
	};
}

module.exports = {
	SOURCES, sourceForUrl, classifyResponse, errCode,
	RETRY_ATTEMPTS, retryDelaysMs,
	createSourceHealth, formatAbort, guardedFetch,
};
