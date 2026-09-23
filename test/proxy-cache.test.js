/**
 * test/proxy-cache.test.js — shared persistent proxy-cache: store, client rewrite,
 * server cache/single-flight/TTL/stale behaviour, persistence across restarts,
 * API-key injection, and the --proxy / --upstream-proxy re-exec plumbing.
 */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const { spawn } = require("child_process");

const {
	ttlForUrl, upstreamHeadersFor, createCacheStore, proxiedFetch, startProxyCacheServer,
	parseProxyFlag, DEFAULT_CACHE_DIR, CLIENT_CACHE_DIR,
} = require("../lib/proxy-cache");

const tmpDir = () => fs.mkdtempSync(path.join(os.tmpdir(), "fad-proxy-"));

test("client and server caches live in separate roots (never bundled/swapped together)", () => {
	const server = path.resolve(DEFAULT_CACHE_DIR());
	const client = path.resolve(CLIENT_CACHE_DIR());
	assert.ok(!server.startsWith(client + path.sep), "the shared store must NOT live inside the client cache root");
	assert.notEqual(server, client);
});
const URL_NPM = "https://registry.npmjs.org/express";          // known source (host match)
const URL_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-31210";
const URL_PRIVATE = "https://npm.acme.internal/express";       // unknown host → direct

/** Fake upstream: counts hits, records the headers it received, can fail / return huge bodies. */
function fakeUpstream() {
	const state = { hits: 0, mode: "ok", body: null, lastHeaders: {} };
	const server = http.createServer((req, res) => {
		state.hits++;
		state.lastHeaders = req.headers;
		if (state.mode === "500") { res.writeHead(500, { "content-type": "text/plain" }); res.end("boom"); return; }
		const body = state.body || Buffer.from(JSON.stringify({ url: req.url, n: state.hits }));
		res.writeHead(200, { "content-type": "application/json" });
		res.end(body);
	});
	return {
		state,
		start: () => new Promise(ok => server.listen(0, "127.0.0.1", ok)),
		url: () => `http://127.0.0.1:${server.address().port}`,
		close: () => new Promise(ok => server.close(ok)),
	};
}

/**
 * Harness: a proxy-cache server wired at a fake upstream. `rewrite` maps the target
 * URL's host onto the fake (default: npm registry); everything closes in `close()`.
 */
async function startProxy(opts = {}) {
	const up = fakeUpstream();
	await up.start();
	const { rewrite = t => t.replace(/^https:\/\/registry\.npmjs\.org/, up.url()) } = opts;
	const { server, url } = await startProxyCacheServer({
		port: 0, host: "127.0.0.1",
		store: createCacheStore(opts.dir || tmpDir()),
		fetcher: (t, init) => fetch(rewrite(t), init),
		overrideTtlMs: opts.overrideTtlMs ?? null,
		maxBodyBytes: opts.maxBodyBytes,
		swr: opts.swr,
		token: opts.token,
		keys: opts.keys,
	});
	return {
		up, server, url,
		close: async () => { await new Promise(ok => server.close(ok)); await up.close(); },
	};
}

const get = url => fetch(url).then(async r => ({ status: r.status, tag: r.headers.get("x-fad-proxy"), body: await r.text() }));

// ------------------------------------------------------------------ store ----

test("store: set/get roundtrip, TTL freshness, persistence across instances", () => {
	const dir = tmpDir();
	const s1 = createCacheStore(dir);
	const tmpBody = path.join(dir, "seed");
	fs.writeFileSync(tmpBody, "hello");
	s1.commit(URL_NPM, tmpBody, { fetchedAt: Date.now(), ttlMs: 60_000, contentType: "text/plain", bytes: 5 });
	const e = s1.get(URL_NPM);
	assert.equal(fs.readFileSync(e.bodyPath, "utf8"), "hello");
	assert.equal(e.contentType, "text/plain");
	assert.ok((Date.now() - e.fetchedAt) < e.ttlMs);

	// a second store over the same dir sees the entry (the multi-instance contract)
	const s2 = createCacheStore(dir);
	assert.equal(fs.readFileSync(s2.get(URL_NPM).bodyPath, "utf8"), "hello");

	assert.equal(s2.size(), 1);
	s2.clear();
	assert.equal(s2.size(), 0);
	assert.equal(s2.get(URL_NPM), null);
});

test("ttlForUrl: per-source table + override + default", () => {
	assert.equal(ttlForUrl("https://api.osv.dev/v1/querybatch"), 12 * 3600 * 1000);
	assert.equal(ttlForUrl("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=X"), 7 * 24 * 3600 * 1000);
	assert.equal(ttlForUrl("https://registry.npmjs.org/express"), 24 * 3600 * 1000); // default
	assert.equal(ttlForUrl("https://registry.npmjs.org/express", { overrideTtlMs: 1000 }), 1000);
});

// ----------------------------------------------------------------- client ----

test("proxiedFetch: rewrites known-source URLs, leaves private hosts and Request objects direct", async () => {
	const seen = [];
	const fake = async (input) => { seen.push(typeof input === "string" ? input : (input?.url ?? String(input))); return { ok: true, status: 200, headers: new Map(), text: async () => "" }; };
	const p = proxiedFetch("http://127.0.0.1:9999/", { fetch: fake });
	await p(URL_NPM, { method: "GET" });
	assert.equal(seen[0], "http://127.0.0.1:9999/" + URL_NPM);
	await p(URL_PRIVATE);
	assert.equal(seen[1], URL_PRIVATE);
	await p(new Request("https://registry.npmjs.org/leftpad")); // Request object → untouched
	assert.equal(seen[2], "https://registry.npmjs.org/leftpad");
	await p("not-a-url");
	assert.equal(seen[3], "not-a-url");
});

test("proxiedFetch: rejects an invalid base URL", () => {
	assert.throws(() => proxiedFetch("127.0.0.1:8321"), /invalid proxy-cache URL/);
});

// ----------------------------------------------------------------- server ----

test("server: miss → hit (one upstream call), x-fad-proxy tags, __stats", async () => {
	const p = await startProxy();
	try {
		const target = p.url + "/" + URL_NPM;
		const r1 = await get(target);
		assert.equal(r1.status, 200);
		assert.equal(r1.tag, "miss");
		assert.equal(p.up.state.hits, 1);
		const r2 = await get(target);
		assert.equal(r2.tag, "hit");
		assert.equal(r2.body, r1.body);
		assert.equal(p.up.state.hits, 1); // served from the store, zero extra upstream
		const stats = await get(p.url + "/__stats").then(r => JSON.parse(r.body));
		assert.equal(stats.hits, 1);
		assert.equal(stats.misses, 1);
		assert.equal(stats.upstream, 1);
		assert.equal(stats.entries, 1);
	} finally { await p.close(); }
});

test("server: single-flight — 10 concurrent identical lookups → one upstream call", async () => {
	const p = await startProxy();
	try {
		const target = p.url + "/" + URL_NPM;
		const rs = await Promise.all(Array.from({ length: 10 }, () => get(target)));
		assert.ok(rs.every(r => r.status === 200));
		assert.equal(p.up.state.hits, 1);
	} finally { await p.close(); }
});

test("server: TTL expiry refetches; swr serves stale then refreshes in the background", async () => {
	const p = await startProxy({ overrideTtlMs: 50 });
	try {
		const target = p.url + "/" + URL_NPM;
		await get(target);
		assert.equal(p.up.state.hits, 1);
		await new Promise(r => setTimeout(r, 80)); // expired
		const r2 = await get(target);
		assert.equal(r2.tag, "stale"); // served the old copy immediately
		assert.equal(p.up.state.hits, 2); // …and refreshed upstream (background revalidate)
		const r3 = await get(target);
		assert.equal(r3.tag, "hit"); // the refreshed entry is now served
	} finally { await p.close(); }
});

test("server: --no-swr makes expiry a blocking refetch", async () => {
	const p = await startProxy({ overrideTtlMs: 50, swr: false });
	try {
		const target = p.url + "/" + URL_NPM;
		await get(target);
		await new Promise(r => setTimeout(r, 80));
		const r2 = await get(target);
		assert.equal(r2.tag, "miss"); // blocking: no stale was served
		assert.equal(p.up.state.hits, 2);
	} finally { await p.close(); }
});

test("server: stale-if-error — a dead upstream serves the stale copy instead of 502", async () => {
	const p = await startProxy({ overrideTtlMs: 50, swr: false });
	try {
		const target = p.url + "/" + URL_NPM;
		const first = await get(target);
		await new Promise(r => setTimeout(r, 80)); // expired
		p.up.state.mode = "500";
		const r2 = await get(target);
		assert.equal(r2.status, 200);
		assert.equal(r2.tag, "stale");
		assert.equal(r2.body, first.body);
	} finally { await p.close(); }
});

test("server: a 500 upstream with NO cached copy is mirrored, never cached", async () => {
	const p = await startProxy();
	try {
		p.up.state.mode = "500";
		const r = await get(p.url + "/" + URL_NPM);
		assert.equal(r.status, 500);
		assert.equal(r.tag, "pass");
		const stats = await get(p.url + "/__stats").then(x => JSON.parse(x.body));
		assert.equal(stats.entries, 0);
	} finally { await p.close(); }
});

test("server: non-GET (OSV POST) and unknown hosts pass through uncached", async () => {
	const up = fakeUpstream();
	await up.start();
	const swap = t => t.replace(/^https?:\/\/[^/]+/, up.url());
	const { server, url } = await startProxyCacheServer({ port: 0, host: "127.0.0.1", store: createCacheStore(tmpDir()), fetcher: (t, init) => fetch(swap(t), init) });
	try {
		// POST → pass-through, no cache entry created even for a known host
		let r = await fetch(url + "/https://api.osv.dev/v1/querybatch", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ queries: [] }) });
		assert.equal(r.status, 200);
		assert.equal(r.headers.get("x-fad-proxy"), "pass");
		// GET to an unknown (private) host → proxied, not cached
		r = await get(url + "/" + URL_PRIVATE);
		assert.equal(r.status, 200);
		assert.equal(r.tag, "pass");
		const stats = await get(url + "/__stats").then(x => JSON.parse(x.body));
		assert.equal(stats.entries, 0);
		assert.equal(stats.passes, 2);
	} finally {
		await new Promise(ok => server.close(ok));
		await up.close();
	}
});

test("server: bodies over maxBodyBytes stream through uncached", async () => {
	const p = await startProxy({ maxBodyBytes: 512 });
	try {
		p.up.state.body = Buffer.alloc(1024); // above the cap
		const r = await get(p.url + "/" + URL_NPM);
		assert.equal(r.status, 200);
		assert.equal(r.body.length, 1024); // streamed to the client in full
		assert.equal(r.tag, "miss");
		const stats = await get(p.url + "/__stats").then(x => JSON.parse(x.body));
		assert.equal(stats.entries, 0); // …but never stored
	} finally { await p.close(); }
});

test("server: --token requires Bearer auth on everything but __health", async () => {
	const p = await startProxy({ token: "s3cret" });
	try {
		assert.equal((await get(p.url + "/__health")).status, 200);
		let r = await get(p.url + "/" + URL_NPM);
		assert.equal(r.status, 401);
		r = await fetch(p.url + "/" + URL_NPM, { headers: { authorization: "Bearer s3cret" } });
		assert.equal(r.status, 200);
	} finally { await p.close(); }
});

test("server: persistence — a restarted server serves the store with zero upstream calls", async () => {
	const dir = tmpDir();
	const up = fakeUpstream();
	await up.start();
	const swap = t => t.replace(/^https:\/\/registry\.npmjs\.org/, up.url());
	const s1 = await startProxyCacheServer({ port: 0, host: "127.0.0.1", store: createCacheStore(dir), fetcher: (t, init) => fetch(swap(t), init) });
	const r1 = await get(s1.url + "/" + URL_NPM);
	await new Promise(ok => s1.server.close(ok));
	// "restart": brand-new server + store over the SAME dir
	const s2 = await startProxyCacheServer({ port: 0, host: "127.0.0.1", store: createCacheStore(dir), fetcher: (t, init) => fetch(swap(t), init) });
	try {
		const r2 = await get(s2.url + "/" + URL_NPM);
		assert.equal(r2.tag, "hit");
		assert.equal(r2.body, r1.body);
		assert.equal(up.state.hits, 1); // the base survived the restart
	} finally {
		await new Promise(ok => s2.server.close(ok));
		await up.close();
	}
});

test("server: __clear wipes the shared base", async () => {
	const p = await startProxy();
	try {
		await get(p.url + "/" + URL_NPM);
		const r = await fetch(p.url + "/__clear", { method: "POST" });
		const { cleared } = await r.json();
		assert.equal(cleared, 1);
		const stats = await get(p.url + "/__stats").then(x => JSON.parse(x.body));
		assert.equal(stats.entries, 0);
	} finally { await p.close(); }
});

// ------------------------------------------------------------- api keys ----

test("upstreamHeadersFor: injects the right credential per host, client headers forwarded as baseline", () => {
	const keys = { nvd: "NVD-KEY", wordfence: "WF-KEY", github: "GH-TOK" };
	let h = upstreamHeadersFor("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=X", {}, keys);
	assert.equal(h.apiKey, "NVD-KEY");
	h = upstreamHeadersFor("https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production", {}, keys);
	assert.equal(h.authorization, "Bearer WF-KEY");
	h = upstreamHeadersFor("https://api.github.com/repos/TYPO3/typo3/security-advisories?per_page=100", {}, keys);
	assert.equal(h.authorization, "Bearer GH-TOK");
	// no server key → the client's own credential travels (either spelling)
	h = upstreamHeadersFor(URL_NVD, { apikey: "CLIENT-KEY" }, {});
	assert.equal(h.apiKey, "CLIENT-KEY");
	h = upstreamHeadersFor(URL_NVD, { apiKey: "CLIENT-KEY" }, {});
	assert.equal(h.apiKey, "CLIENT-KEY");
	// a server key overrides the client's — one header, not two spellings
	h = upstreamHeadersFor(URL_NVD, { apikey: "CLIENT-KEY" }, keys);
	assert.equal(h.apiKey, "NVD-KEY");
	assert.equal(Object.keys(h).filter(k => k.toLowerCase() === "apikey").length, 1);
	// keys never leak onto unrelated hosts
	h = upstreamHeadersFor(URL_NPM, { authorization: "Bearer private-registry" }, keys);
	assert.equal(h.authorization, "Bearer private-registry"); // forwarded, not overridden
});

test("server: a keyless instance is served by the server's NVD key (shared quota)", async () => {
	const p = await startProxy({ keys: { nvd: "NVD-KEY" }, rewrite: t => t.replace(/^https:\/\/services\.nvd\.nist\.gov/, p.up.url()) });
	try {
		// the client sends NO apiKey header at all
		const r = await get(p.url + "/" + URL_NVD);
		assert.equal(r.status, 200);
		assert.equal(p.up.state.lastHeaders.apikey, "NVD-KEY"); // the server injected its own
		// second instance, same keyless request → served from the shared entry
		await get(p.url + "/" + URL_NVD);
		assert.equal(p.up.state.hits, 1);
	} finally { await p.close(); }
});

// -------------------------------------------------- --proxy re-exec plumbing ----

test("parseProxyFlag: --proxy and serve-cache --upstream-proxy, never --proxy-cache", () => {
	// exact-token match: --proxy-cache must NOT be read as --proxy
	assert.equal(parseProxyFlag(["node", "fad-checker.js", "-s", ".", "--proxy-cache", "http://127.0.0.1:8321"]), null);
	assert.equal(parseProxyFlag(["node", "fad-checker.js", "-s", ".", "--proxy", "http://corp:3128"]), "http://corp:3128");
	assert.equal(parseProxyFlag(["node", "fad-checker.js", "serve-cache", "--upstream-proxy", "http://corp:3128", "--port", "9000"]), "http://corp:3128");
	assert.equal(parseProxyFlag(["node", "fad-checker.js", "serve-cache", "--proxy", "http://x:1"]), null); // serve-cache uses --upstream-proxy
	// a missing/bad value is ignored, not fatal
	assert.equal(parseProxyFlag(["node", "fad-checker.js", "--proxy"]), null);
	assert.equal(parseProxyFlag(["node", "fad-checker.js", "--proxy", "--verbose"]), null);
});

test("--proxy re-exec: the child runs with the proxy env applied and exit code is preserved", { timeout: 30_000 }, async () => {
	// `fad-checker.js --proxy <url> --version` re-execs itself; the child prints the
	// version and exits 0. A sentinel env var prevents infinite recursion, and the
	// proxy host is exempted from NO_PROXY handling — asserted by __FAD_PROXY_URL.
	const root = path.join(__dirname, "..");
	const res = await new Promise(resolve => {
		const child = spawn(process.execPath, [path.join(root, "fad-checker.js"), "--proxy", "http://127.0.0.1:3128", "--version"], { cwd: root });
		let out = "", err = "";
		child.stdout.on("data", d => out += d);
		child.stderr.on("data", d => err += d);
		child.on("exit", (code, sig) => resolve({ code, sig, out, err }));
	});
	assert.equal(res.code, 0);
	assert.match(res.out, /\d+\.\d+\.\d+/);
	assert.equal(res.err, "");
});
