/**
 * lib/proxy-cache.js — shared, persistent proxy-cache for fad-checker's public data sources.
 *
 * A scan of a real reactor makes hundreds of registry/advisory lookups, and every
 * machine that scans makes them again. This module turns ONE of those machines into
 * a cache point for the others:
 *
 *   fad-checker serve-cache                       # start the server (default 127.0.0.1:8321)
 *   fad-checker -s ./proj --proxy-cache http://127.0.0.1:8321
 *
 * Server: every GET to a known public source (the same host list lib/source-health.js
 * guards — npm/PyPI/Packagist/NuGet/RubyGems/Go proxy/Maven Central, OSV, NVD, EPSS,
 * KEV, endoflife.date, deps.dev, CIRCL) is fetched once, persisted under
 * ~/.fad-checker-proxy-cache/entries/ (one body + one meta file per URL, atomic
 * rename, so a killed server never leaves a half entry) and replayed to every other
 * instance while the per-source TTL holds. POSTs (OSV querybatch) and HEADs
 * (Maven mirror preflight) are proxied uncached; bodies over --max-body-mb (the CVE
 * bulk zip is ~500 MB) are streamed through without being stored.
 *
 * Concurrency: a single-flight map coalesces simultaneous identical lookups into one
 * upstream call — 10 instances scanning the same repo make ONE registry round-trip.
 * An expired entry is served stale while a refresh runs in the background
 * (stale-while-revalidate, `--no-swr` makes expiry blocking instead), and a dead
 * upstream still serves the stale copy (stale-if-error) — the shared base degrades
 * to "as fresh as its last successful fetch" instead of to nothing.
 *
 * Client: `proxiedFetch(proxyBase)` wraps globalThis.fetch in fad-checker.js BEFORE
 * guardedFetch, so a request still carries its real URL into the outage ledger —
 * a dead proxy is classified as a dead *source* (retry schedule, then the exit-2
 * abort naming the flag), never as a quiet coverage hole. Only requests to the
 * known public hosts are routed through the proxy; custom/private registries
 * (and their Authorization headers) always go direct.
 *
 * Persistence is the point: the server may be restarted and entries outlive it. The
 * store deliberately lives in its OWN root (~/.fad-checker-proxy-cache/), NEVER inside
 * the client cache dir ~/.fad-checker/ — the scan's per-pass caches and the shared
 * server base are two different roles and must not be bundled, swapped or merged by
 * --export-cache / --import-cache together.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const http = require("http");
const { sourceForUrl } = require("./source-health");

const DEFAULT_TTL_MS = 24 * 3600 * 1000;
/**
 * Per-source TTLs, aligned with the per-pass client caches (see README "Caching"):
 * OSV 12h, NVD 7d, endoflife.date 7d, EPSS/KEV 24h, everything else (registries,
 * deps.dev, CIRCL) falls back to the 24h default. An explicit --ttl overrides all.
 */
const TTL_BY_SOURCE = {
	osv: 12 * 3600 * 1000,
	nvd: 7 * 24 * 3600 * 1000,
	eol: 7 * 24 * 3600 * 1000,
	epss: 24 * 3600 * 1000,
	kev: 24 * 3600 * 1000,
};

const DEFAULT_MAX_BODY_BYTES = 32 * 1024 * 1024;
const DEFAULT_PORT = 8321;
const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_CACHE_DIR = () => path.join(os.homedir(), ".fad-checker-proxy-cache");
/** The scan's own per-pass cache root — the proxy store must never live inside it. */
const CLIENT_CACHE_DIR = () => path.join(os.homedir(), ".fad-checker");

/**
 * API keys the server may hold so the instances behind it don't have to. A key
 * configured HERE wins over whatever a client sent; a client-sent key is forwarded
 * when the server has none. Cache entries are keyed by the CLIENT url, so a keyed
 * fetch and a keyless one share the same entry — the fleet shares the server's quota.
 *   nvd       → header `apiKey: <key>`      (services.nvd.nist.gov — same as lib/nvd.js)
 *   wordfence → `Authorization: Bearer <k>` (www.wordfence.com — same as the live-snapshot lane)
 *   github    → `Authorization: Bearer <t>` (api.github.com — advisory lanes, pooled rate limit)
 */
function upstreamHeadersFor(target, reqHeaders = {}, keys = {}) {
	const headers = {
		"user-agent": (reqHeaders["user-agent"] && String(reqHeaders["user-agent"])) || "fad-checker-proxy-cache",
		"accept": reqHeaders.accept || "application/json",
	};
	// Forward the client's own credentials for this host (the proxy is in the trust path:
	// every request it makes is one a client asked for). NVD's header is spelled `apiKey`
	// (lib/nvd.js) but Node's http server lowercases every incoming header name, so both
	// spellings are read and re-emitted as one — a server key must overwrite, not sit
	// beside, the client's (same name, different case, ambiguous on the wire).
	const clientApiKey = reqHeaders.apiKey ?? reqHeaders.apikey;
	if (clientApiKey != null) headers.apiKey = clientApiKey;
	for (const h of ["authorization", "x-github-api-version"]) {
		if (reqHeaders[h] != null) headers[h] = reqHeaders[h];
	}
	const host = hostOf(target);
	if (keys.nvd && /(^|\.)nvd\.nist\.gov$/.test(host)) headers.apiKey = keys.nvd;
	if (keys.wordfence && /(^|\.)wordfence\.com$/.test(host)) headers.authorization = "Bearer " + keys.wordfence;
	if (keys.github && /(^|\.)github\.com$/.test(host)) headers.authorization = "Bearer " + keys.github;
	return headers;
}

function hostOf(url) {
	try { return new URL(String(url)).hostname.toLowerCase(); } catch { return null; }
}

/** TTL that applies to one URL (override > per-source > default). */
function ttlForUrl(url, { defaultTtlMs = DEFAULT_TTL_MS, overrideTtlMs = null } = {}) {
	if (overrideTtlMs) return overrideTtlMs;
	const src = sourceForUrl(url);
	return (src && TTL_BY_SOURCE[src.id]) || defaultTtlMs;
}

// ---------------------------------------------------------------- store ----

/**
 * Persistent URL-keyed store. One sha256(url)-hashed pair per entry:
 *   <hash>.json — { url, fetchedAt, ttlMs, contentType, bytes }  (the commit marker)
 *   <hash>.body — the payload, byte-for-byte
 * The body is renamed into place BEFORE the meta file, so a crash mid-commit leaves
 * an orphan body with no meta (invisible, never a truncated entry).
 */
function createCacheStore(dir = DEFAULT_CACHE_DIR()) {
	const entriesDir = path.join(dir, "entries");
	fs.mkdirSync(entriesDir, { recursive: true });
	const hash = url => crypto.createHash("sha256").update(String(url)).digest("hex");
	const metaPath = h => path.join(entriesDir, h + ".json");
	const bodyPath = h => path.join(entriesDir, h + ".body");

	return {
		dir, entriesDir, hash, metaPath, bodyPath,
		get(url) {
			const h = hash(url);
			try {
				const meta = JSON.parse(fs.readFileSync(metaPath(h), "utf8"));
				if (meta.url !== url) return null;
				return { ...meta, bodyPath: bodyPath(h) };
			} catch { return null; }
		},
		/** Promote a fully-written temp body file into an entry (atomic). */
		commit(url, tmpBodyFile, meta) {
			const h = hash(url);
			const tmpMeta = metaPath(h) + ".tmp" + crypto.randomBytes(4).toString("hex");
			fs.writeFileSync(tmpMeta, JSON.stringify({ ...meta, url }));
			fs.renameSync(tmpBodyFile, bodyPath(h));
			fs.renameSync(tmpMeta, metaPath(h));
		},
		clear() {
			let n = 0;
			for (const f of fs.readdirSync(entriesDir)) {
				if (f.endsWith(".json") || f.endsWith(".body")) {
					fs.rmSync(path.join(entriesDir, f), { force: true });
					n++;
				}
			}
			return n;
		},
		size() {
			try { return fs.readdirSync(entriesDir).filter(f => f.endsWith(".json")).length; }
			catch { return 0; }
		},
	};
}

// -------------------------------------------------------------- client ----

/**
 * Wrap a fetch so requests to fad's known public sources are routed through the
 * proxy-cache at `proxyBase` (as `${proxyBase}/${absoluteUrl}` — the server treats
 * everything after its first "/" as the target). Everything else — private
 * registries, custom hosts, Request objects, non-http(s) — goes direct untouched.
 */
function proxiedFetch(proxyBase, opts = {}) {
	const { fetch: base = globalThis.fetch, shouldProxy = url => sourceForUrl(url) != null } = opts;
	const base_ = String(proxyBase || "").replace(/\/+$/, "");
	if (!/^https?:\/\//i.test(base_)) throw new Error(`invalid proxy-cache URL "${proxyBase}" (expected http://host:port)`);
	return async function proxied(input, init) {
		if (typeof input === "string" && /^https?:\/\//i.test(input) && shouldProxy(input)) {
			return base(base_ + "/" + input, init);
		}
		return base(input, init);
	};
}

// -------------------------------------------------------------- server ----

function readRequestBody(req, maxBytes) {
	return new Promise((resolve, reject) => {
		const chunks = [];
		let n = 0;
		req.on("data", c => {
			n += c.length;
			if (n > maxBytes) { reject(new Error("request body too large")); req.destroy(); return; }
			chunks.push(c);
		});
		req.on("end", () => resolve(Buffer.concat(chunks)));
		req.on("error", reject);
	});
}

/**
 * The proxy-cache HTTP server. Endpoints:
 *   GET  /<absolute-url>   — cached when the host is a known source (else proxied)
 *   ANY  /<absolute-url>   — non-GET/HEAD (e.g. OSV POST) proxied uncached
 *   GET  /__health         — liveness (no auth)
 *   GET  /__stats          — counters + entry count
 *   POST|DELETE /__clear  — wipe the store
 */
function createProxyCacheServer(opts = {}) {
	const {
		store = createCacheStore(),
		fetcher = globalThis.fetch,
		defaultTtlMs = DEFAULT_TTL_MS,
		overrideTtlMs = null,
		maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
		swr = true,
		token = null,
		keys = {},           // { nvd, wordfence, github } — see upstreamHeadersFor
		userAgent = "fad-checker-proxy-cache",
	} = opts;

	const stats = { startedAt: Date.now(), requests: 0, hits: 0, misses: 0, coalesced: 0, stale: 0, passes: 0, upstream: 0, errors: 0 };
	const inflight = new Map();

	const authorized = req => !token || req.headers.authorization === "Bearer " + token;
	const ttlFor = url => ttlForUrl(url, { defaultTtlMs, overrideTtlMs });

	function sendJson(res, code, obj, headers = {}) {
		const body = JSON.stringify(obj);
		res.writeHead(code, { "content-type": "application/json", ...headers });
		res.end(body);
	}

	function serveEntry(res, entry, tag) {
		res.writeHead(200, {
			"content-type": entry.contentType || "application/octet-stream",
			"content-length": entry.bytes,
			"x-fad-proxy": tag,
			"x-fad-proxy-fetched-at": new Date(entry.fetchedAt).toISOString(),
		});
		fs.createReadStream(entry.bodyPath).on("error", () => res.destroy()).pipe(res);
	}

	/**
	 * Fetch `target` upstream. When `res` is given the status/body are mirrored to
	 * that client WHILE the payload is teed to a temp file; the temp file is promoted
	 * to a store entry only when the body is complete, a 200, and under the size cap.
	 * Without `res` this is a background (revalidate) fetch that only writes the store.
	 */
	async function runFetch(target, { res = null, reqHeaders = {}, stale = null } = {}) {
		stats.upstream++;
		const up = await fetcher(target, { headers: upstreamHeadersFor(target, reqHeaders, keys), redirect: "follow" });
		const contentType = up.headers.get("content-type") || "application/octet-stream";
		if (up.status !== 200 || !up.body) {
			// An upstream error (403 walled, 429 throttled, 5xx broken) with a stale copy
			// in the store degrades to stale — a shared cache must not go dark because
			// the source blipped. A definitive 404/410 is an ANSWER and is mirrored as-is.
			if (stale && (up.status === 403 || up.status === 429 || up.status >= 500) && (!res || !res.headersSent)) {
				stats.stale++;
				if (res) serveEntry(res, stale, "stale");
				if (up.body) for await (const c of up.body) { /* drain */ }
				return { stored: false, status: up.status, staleServed: true };
			}
			if (res) {
				res.writeHead(up.status, { "content-type": contentType, "x-fad-proxy": "pass" });
				if (up.body) for await (const c of up.body) res.write(c);
				res.end();
			} else if (up.body) {
				for await (const c of up.body) { /* drain */ }
			}
			return { stored: false, status: up.status };
		}
		const tmp = path.join(store.entriesDir, ".tmp-" + crypto.randomBytes(6).toString("hex"));
		const ws = fs.createWriteStream(tmp);
		let bytes = 0, overflow = false;
		try {
			if (res) res.writeHead(200, { "content-type": contentType, "x-fad-proxy": "miss" });
			for await (const chunk of up.body) {
				if (res) res.write(chunk);
				if (!overflow) {
					bytes += chunk.length;
					if (bytes > maxBodyBytes) { overflow = true; ws.end(); fs.rmSync(tmp, { force: true }); }
					else ws.write(chunk);
				}
			}
		} catch (err) {
			if (!overflow) { try { ws.destroy(); } catch { /* already closed */ } fs.rmSync(tmp, { force: true }); }
			throw err;
		}
		if (res) res.end();
		if (overflow) return { stored: false, status: 200, bytes };
		await new Promise((ok, bad) => ws.end(e => (e ? bad(e) : ok())));
		store.commit(target, tmp, { fetchedAt: Date.now(), ttlMs: ttlFor(target), contentType, bytes });
		return { stored: true, status: 200, bytes };
	}

	/** Single-flight wrapper: concurrent identical lookups share one upstream fetch. */
	async function viaInflight(target, runOpts) {
		let p = inflight.get(target);
		if (!p) {
			p = runFetch(target, runOpts).finally(() => inflight.delete(target));
			inflight.set(target, p);
		}
		return p;
	}

	async function passThrough(req, res, target) {
		stats.passes++;
		const body = await readRequestBody(req, maxBodyBytes);
		const headers = upstreamHeadersFor(target, req.headers, keys);
		if (req.headers["content-type"]) headers["content-type"] = req.headers["content-type"];
		const up = await fetcher(target, { method: req.method, headers, body: body.length ? body : undefined });
		res.writeHead(up.status, { "content-type": up.headers.get("content-type") || "application/octet-stream", "x-fad-proxy": "pass" });
		if (up.body) for await (const c of up.body) res.write(c);
		res.end();
	}

	async function handle(req, res) {
		stats.requests++;
		const target = req.url.replace(/^\/+/, "");

		if (!/^https?:\/\//i.test(target)) {
			if (target === "__health") return sendJson(res, 200, { ok: true, uptimeMs: Date.now() - stats.startedAt });
			if (!authorized(req)) return sendJson(res, 401, { error: "unauthorized (start the server with --token <t>, send Authorization: Bearer <t>)" });
			if (target === "__stats" && req.method === "GET") return sendJson(res, 200, { ...stats, entries: store.size() });
			if (target === "__clear" && (req.method === "POST" || req.method === "DELETE")) {
				const cleared = store.size();
				store.clear();
				return sendJson(res, 200, { cleared });
			}
			return sendJson(res, 404, { error: "expected /<absolute-url> or a control endpoint (__health, __stats, __clear)" });
		}
		if (!authorized(req)) return sendJson(res, 401, { error: "unauthorized", "x-fad-proxy": "unauthorized" });

		const method = (req.method || "GET").toUpperCase();
		// Only fad's known public sources are ever cached — anything else (a private
		// registry, an arbitrary URL the server is pointed at) is proxied as-is.
		if (method !== "GET" || sourceForUrl(target) == null) return passThrough(req, res, target);

		const entry = store.get(target);
		const fresh = !!(entry && (Date.now() - entry.fetchedAt) < entry.ttlMs);
		if (fresh) {
			stats.hits++;
			return serveEntry(res, entry, "hit");
		}
		if (swr && entry) {
			// Serve the stale copy now, refresh in the background — instances get
			// the shared base immediately and the next reader sees the fresh one.
			stats.stale++;
			serveEntry(res, entry, "stale");
			viaInflight(target, { reqHeaders: req.headers }).catch(() => {});
			return;
		}
		// Blocking miss (or expired with --no-swr). Coalesce on an already-running fetch.
		if (inflight.has(target)) {
			stats.coalesced++;
			await inflight.get(target);
			const e2 = store.get(target);
			if (e2) { stats.hits++; return serveEntry(res, e2, "hit"); }
		}
		stats.misses++;
		try {
			await viaInflight(target, { res, reqHeaders: req.headers, stale: entry });
		} catch (err) {
			stats.errors++;
			// Stale-if-error: a dead upstream must not become a dead shared cache.
			if (entry && !res.headersSent) { stats.stale++; return serveEntry(res, entry, "stale"); }
			if (!res.headersSent) return sendJson(res, 502, { error: String(err.message || err) }, { "x-fad-proxy": "error" });
			res.destroy();
		}
	}

	const server = http.createServer((req, res) => {
		handle(req, res).catch(err => {
			stats.errors++;
			if (!res.headersSent) sendJson(res, 502, { error: String(err.message || err) }, { "x-fad-proxy": "error" });
			else res.destroy();
		});
	});
	server.fadStats = stats;
	server.fadStore = store;
	return server;
}

/** Convenience: create + listen. Resolves { server, url, port } once the socket is open. */
function startProxyCacheServer(opts = {}) {
	const { port = DEFAULT_PORT, host = DEFAULT_HOST } = opts;
	const server = createProxyCacheServer(opts);
	return new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(port, host, () => resolve({ server, url: `http://${host}:${server.address().port}`, port: server.address().port }));
	});
}

// ------------------------------------------------------ outbound proxy ----

/**
 * Read the corporate-proxy URL from a raw argv: `--proxy <url>` for a scan,
 * `--upstream-proxy <url>` under the serve-cache subcommand. Exact-token match —
 * `--proxy-cache` (a different feature) must never be read as `--proxy`.
 * Returns null when absent or without a usable value.
 */
function parseProxyFlag(argv = process.argv) {
	const names = argv[2] === "serve-cache" ? ["--upstream-proxy"] : ["--proxy"];
	for (const name of names) {
		const i = argv.indexOf(name);
		if (i > -1 && argv[i + 1] && !argv[i + 1].startsWith("-")) return argv[i + 1];
	}
	return null;
}

/** True when the running runtime honors HTTP(S)_PROXY for global fetch. */
function runtimeSupportsEnvProxy() {
	if (typeof Bun !== "undefined") return true;   // bun honors http_proxy natively
	const v = process.versions.node.split(".").map(Number);
	return v[0] > 24 || (v[0] === 24 && v[1] >= 0); // node >= 24 via NODE_USE_ENV_PROXY
}

/**
 * Re-exec the current CLI with the corporate proxy applied to every outbound
 * request: NODE_USE_ENV_PROXY=1 makes Node >= 24's built-in fetch honor
 * HTTP_PROXY/HTTPS_PROXY (bun honors them natively), and both are read at process
 * start — so the only reliable place to apply them is a fresh process. The
 * `loopGuard` env prevents recursion; `noProxy` (the --proxy-cache host, if any)
 * keeps local cache traffic out of the corporate tunnel.
 */
function reexecWithProxy({ proxyUrl, loopGuard = "__FAD_PROXY_REEXEC__", noProxy = null, env = process.env, spawnImpl = null }) {
	const { spawn } = require("child_process");
	const e = { ...env, NODE_USE_ENV_PROXY: "1", HTTP_PROXY: proxyUrl, HTTPS_PROXY: proxyUrl, [loopGuard]: "1" };
	if (noProxy) e.NO_PROXY = [env.NO_PROXY, noProxy].filter(Boolean).join(",");
	// Rebuild the command line for the runtime we're in: under node it is
	// `node <script> args`; under bun (incl. the compiled binary, where argv[1] is
	// the executable itself) the executable replays argv from index 1 — the same
	// self-re-exec contract lib/retire.js uses for the vendored-JS mode.
	const isBun = !!(process.versions && process.versions.bun);
	const args = isBun ? process.argv.slice(1) : [process.argv[1], ...process.argv.slice(2)];
	const child = (spawnImpl || spawn)(process.execPath, args, { stdio: "inherit", env: e });
	child.on("exit", (code, sig) => process.exit(sig ? 1 : (code ?? 0)));
	child.on("error", err => { console.error(`proxy re-exec failed: ${err.message}`); process.exit(1); });
}

module.exports = {
	DEFAULT_TTL_MS, TTL_BY_SOURCE, DEFAULT_MAX_BODY_BYTES, DEFAULT_PORT, DEFAULT_HOST, DEFAULT_CACHE_DIR, CLIENT_CACHE_DIR,
	ttlForUrl, upstreamHeadersFor, createCacheStore, proxiedFetch, createProxyCacheServer, startProxyCacheServer,
	parseProxyFlag, runtimeSupportsEnvProxy, reexecWithProxy,
};
