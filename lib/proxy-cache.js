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
 * Server: POST /v1/resource accepts a provider, data type and subject parameters.
 * Provider files under lib/providers/ build the upstream request. The on-disk key
 * names the requested resource (NVD CVE, OSV package/version, registry package),
 * not its URL or HTTP body. OSV, Packagist and EPSS retain upstream batching while
 * persisting and coalescing each item independently. Immutable body generations
 * and atomic metadata switches preserve a good entry across crashes and outages.
 *
 * Concurrent identical requests share one upstream call. Expired entries can be
 * served while they refresh; failed refreshes retain the last good result. Large
 * responses are spooled for concurrent readers even when they exceed the normal
 * persistent-body limit. CVE release archives have a separate 1 GiB body limit.
 *
 * Client: lib/providers/index.js exposes getResource(provider, type, params).
 * The route uses a local semantic cache, this shared server, or direct transport.
 * A dead proxy is classified against the requested source by source-health;
 * custom/private registry URLs use the direct path.
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
const FAILURE_RETRY_MS = 30 * 1000;
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
 * Persistent resource-keyed store. The metadata is the commit marker and points to an
 * immutable, generation-specific body. A crash before the metadata rename leaves
 * the previous entry intact; a crash afterward leaves the new entry intact.
 * Older <hash>.body entries remain readable for compatibility.
 */
function createCacheStore(dir = DEFAULT_CACHE_DIR()) {
	const entriesDir = path.join(dir, "entries");
	fs.mkdirSync(entriesDir, { recursive: true });
	const hash = url => crypto.createHash("sha256").update(String(url)).digest("hex");
	const metaPath = h => path.join(entriesDir, h + ".json");
	const bodyPath = h => path.join(entriesDir, h + ".body");
	const readers = new Map();
	const retired = new Set();
	const retire = file => {
		if ((readers.get(file) || 0) > 0) { retired.add(file); return; }
		try { fs.rmSync(file, { force: true }); } catch { /* keep an orphan, never harm the active entry */ }
	};

	return {
		dir, entriesDir, hash, metaPath, bodyPath,
		get(url) {
			const h = hash(url);
			try {
				const meta = JSON.parse(fs.readFileSync(metaPath(h), "utf8"));
				if (meta.url !== url) return null;
				if (meta.bodyFile && !new RegExp(`^${h}\\.body-[0-9a-f]+$`).test(meta.bodyFile)) return null;
				const file = meta.bodyFile ? path.join(entriesDir, meta.bodyFile) : bodyPath(h);
				if (fs.statSync(file).size !== meta.bytes) return null;
				return { ...meta, bodyPath: file };
			} catch { return null; }
		},
		/** Keep a body alive while an HTTP response streams it. */
		acquire(entry) {
			const file = entry.bodyPath;
			readers.set(file, (readers.get(file) || 0) + 1);
			let released = false;
			return () => {
				if (released) return;
				released = true;
				const remaining = (readers.get(file) || 1) - 1;
				if (remaining) readers.set(file, remaining);
				else {
					readers.delete(file);
					if (retired.delete(file)) retire(file);
				}
			};
		},
		/** Publish a fully-written body without replacing the previous one first. */
		commit(url, tmpBodyFile, meta) {
			const h = hash(url);
			const previous = this.get(url);
			const bodyFile = h + ".body-" + crypto.randomBytes(8).toString("hex");
			const nextBody = path.join(entriesDir, bodyFile);
			const tmpMeta = metaPath(h) + ".tmp" + crypto.randomBytes(4).toString("hex");
			let published = false;
			try {
				fs.writeFileSync(tmpMeta, JSON.stringify({ ...meta, url, bodyFile }));
				fs.renameSync(tmpBodyFile, nextBody);
				fs.renameSync(tmpMeta, metaPath(h));
				published = true;
			} finally {
				if (!published) {
					fs.rmSync(tmpMeta, { force: true });
					fs.rmSync(nextBody, { force: true });
				}
			}
			if (previous && previous.bodyPath !== nextBody) retire(previous.bodyPath);
		},
		clear() {
			let n = 0;
			for (const f of fs.readdirSync(entriesDir)) {
				if (f.endsWith(".json") || /\.body(?:-[0-9a-f]+)?$/.test(f)) {
					retire(path.join(entriesDir, f));
					n++;
				}
			}
			return n;
		},
		retire,
		size() {
			try { return fs.readdirSync(entriesDir).filter(f => f.endsWith(".json")).length; }
			catch { return 0; }
		},
	};
}

// -------------------------------------------------------------- client ----

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
 *   POST /v1/resource    — typed provider request
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

	const stats = { startedAt: Date.now(), requests: 0, hits: 0, misses: 0, coalesced: 0, stale: 0, upstream: 0, errors: 0 };
	const inflight = new Map();
	const itemInflight = new Map();
	const failureUntil = new Map();

	const authorized = req => !token || req.headers["x-fad-proxy-token"] === token || req.headers.authorization === "Bearer " + token;
	const ttlFor = url => ttlForUrl(url, { defaultTtlMs, overrideTtlMs });

	function sendJson(res, code, obj, headers = {}) {
		const body = JSON.stringify(obj);
		res.writeHead(code, { "content-type": "application/json", ...headers });
		res.end(body);
	}

	function serveEntry(res, entry, tag) {
		const release = store.acquire(entry);
		res.writeHead(200, {
			"content-type": entry.contentType || "application/octet-stream",
			"content-length": entry.bytes,
			"x-fad-proxy": tag,
			"x-fad-proxy-fetched-at": new Date(entry.fetchedAt).toISOString(),
		});
		fs.createReadStream(entry.bodyPath).on("error", () => res.destroy()).on("close", release).pipe(res);
	}

	/**
	 * Fetch `target` upstream. When `res` is given the status/body are mirrored to
	 * that client WHILE the payload is teed to a temp file; the temp file is promoted
	 * to a store entry only when the body is complete, a 200, and under the size cap.
	 * Without `res` this is a background (revalidate) fetch that only writes the store.
	 */
	async function runFetch(target, { res = null, reqHeaders = {}, stale = null, cacheKey = target,
		method = "GET", body = undefined, ttlMs = ttlFor(target), cacheLimitBytes = maxBodyBytes } = {}) {
		stats.upstream++;
		const headers = upstreamHeadersFor(target, reqHeaders, keys);
		if (body != null && reqHeaders["content-type"]) headers["content-type"] = reqHeaders["content-type"];
		const up = await fetcher(target, { method, headers,
			...(body == null ? {} : { body }), redirect: "follow" });
		const contentType = up.headers.get("content-type") || "application/octet-stream";
		if (up.status !== 200 || !up.body) {
			// An upstream error (403 walled, 429 throttled, 5xx broken) with a stale copy
			// in the store degrades to stale — a shared cache must not go dark because
			// the source blipped. A definitive 404/410 is an ANSWER and is mirrored as-is.
			if (stale && (up.status === 403 || up.status === 429 || up.status >= 500) && (!res || !res.headersSent)) {
				stats.stale++;
				if (res) serveEntry(res, stale, "stale");
				if (up.body?.cancel) { try { up.body.cancel().catch(() => {}); } catch { /* stale stays usable */ } }
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
		const writeDone = new Promise((resolve, reject) => {
			ws.once("finish", resolve);
			ws.once("error", reject);
		});
		// The upstream can fail before we await the disk writer. Keep its rejection
		// observed; the later await still propagates it to stale-if-error.
		writeDone.catch(() => {});
		// With an old entry available, keep headers unsent until the replacement is
		// complete. A broken upstream body can then fall back to the old response.
		const deferResponse = !!(res && stale);
		let bytes = 0, overflow = false;
		try {
			if (res && !deferResponse) res.writeHead(200, { "content-type": contentType, "x-fad-proxy": "miss" });
			for await (const chunk of up.body) {
				if (res && !deferResponse) res.write(chunk);
				bytes += chunk.length;
				if (bytes > cacheLimitBytes) overflow = true;
				ws.write(chunk);
			}
		} catch (err) {
			if (ws.closed) fs.rmSync(tmp, { force: true });
			else ws.once("close", () => fs.rmSync(tmp, { force: true }));
			ws.destroy();
			throw err;
		}
		ws.end();
		if (overflow) {
			await writeDone;
			if (deferResponse) { stats.stale++; serveEntry(res, stale, "stale"); }
			else if (res) res.end();
			// Keep a short-lived spool for followers of this same in-flight request.
			// It is never a persistent cache entry; active readers pin it until done.
			const transient = { bodyPath: tmp, contentType, bytes, fetchedAt: Date.now() };
			const timer = setTimeout(() => store.retire(tmp), FAILURE_RETRY_MS);
		timer.unref?.();
			return { stored: false, status: 200, bytes, transient };
		}
		await writeDone;
		store.commit(cacheKey, tmp, { fetchedAt: Date.now(), ttlMs, contentType, bytes });
		if (deferResponse) serveEntry(res, store.get(cacheKey), "miss");
		else if (res) res.end();
		return { stored: true, status: 200, bytes };
	}

	/** Single-flight wrapper: concurrent identical lookups share one upstream fetch. */
	async function viaInflight(cacheKey, target, runOpts) {
		let p = inflight.get(cacheKey);
		if (!p) {
			p = runFetch(target, { ...runOpts, cacheKey }).then(result => {
				if (result.status === 403 || result.status === 429 || result.status >= 500)
					failureUntil.set(cacheKey, Date.now() + FAILURE_RETRY_MS);
				else failureUntil.delete(cacheKey);
				return result;
			}, err => {
				failureUntil.set(cacheKey, Date.now() + FAILURE_RETRY_MS);
				throw err;
			}).finally(() => inflight.delete(cacheKey));
			inflight.set(cacheKey, p);
		}
		return p;
	}

	async function handleCached(res, { target, cacheKey, reqHeaders = {}, method = "GET", body = undefined,
		ttlMs = ttlFor(target), cacheLimitBytes = maxBodyBytes }) {
		const entry = store.get(cacheKey);
		const fresh = !!(entry && (Date.now() - entry.fetchedAt) < entry.ttlMs);
		if (fresh) {
			stats.hits++;
			return serveEntry(res, entry, "hit");
		}
		if ((failureUntil.get(cacheKey) || 0) > Date.now()) {
			if (entry) { stats.stale++; return serveEntry(res, entry, "stale"); }
			return sendJson(res, 502, { error: "upstream unavailable and no cached response" }, { "x-fad-proxy": "error" });
		}
		if (swr && entry) {
			// Serve the stale copy now, refresh in the background — instances get
			// the shared base immediately and the next reader sees the fresh one.
			stats.stale++;
			serveEntry(res, entry, "stale");
			viaInflight(cacheKey, target, { reqHeaders, method, body, ttlMs, cacheLimitBytes }).catch(() => {});
			return;
		}
		// Blocking miss (or expired with --no-swr). Coalesce on an already-running fetch.
		if (inflight.has(cacheKey)) {
			stats.coalesced++;
			let completed;
			try { completed = await inflight.get(cacheKey); }
			catch (err) {
				stats.errors++;
				if (entry) { stats.stale++; return serveEntry(res, entry, "stale"); }
				return sendJson(res, 502, { error: String(err.message || err) }, { "x-fad-proxy": "error" });
			}
			const e2 = store.get(cacheKey);
			if (e2) { stats.hits++; return serveEntry(res, e2, "hit"); }
			if (completed.transient) { stats.coalesced++; return serveEntry(res, completed.transient, "coalesced"); }
			if (completed.status !== 200) {
				return sendJson(res, completed.status, { error: `upstream returned ${completed.status}` }, { "x-fad-proxy": "pass" });
			}
		}
		stats.misses++;
		try {
			await viaInflight(cacheKey, target, { res, reqHeaders, stale: entry, method, body, ttlMs, cacheLimitBytes });
		} catch (err) {
			stats.errors++;
			// Stale-if-error: a dead upstream must not become a dead shared cache.
			if (entry && !res.headersSent) { stats.stale++; return serveEntry(res, entry, "stale"); }
			if (!res.headersSent) return sendJson(res, 502, { error: String(err.message || err) }, { "x-fad-proxy": "error" });
			res.destroy();
		}
	}

	// Batch APIs retain their upstream batching, while cache keys and concurrent
	// reservations belong to each package/version or CVE. Overlapping batches only
	// fetch the items that are not already pending in another request.
	async function handleBatch(res, provider, type, params, reqHeaders) {
		const batch = provider.batch(type, params);
		const items = batch.items;
		const effectiveHeaders = upstreamHeadersFor(provider.build(type, params).url, reqHeaders, keys);
		const { providerKey } = require("./providers");
		const keysForItems = items.map(item => providerKey(provider.id, item.type, item.params, effectiveHeaders));
		const results = new Array(items.length);
		const waits = [];
		const reserved = [];
		for (let i = 0; i < items.length; i++) {
			const key = keysForItems[i];
			const entry = store.get(key);
			const fresh = entry && Date.now() - entry.fetchedAt < entry.ttlMs;
			if (fresh || (entry && swr)) {
				stats[fresh ? "hits" : "stale"]++;
				results[i] = JSON.parse(fs.readFileSync(entry.bodyPath, "utf8"));
				if (fresh) continue;
			}
			if ((failureUntil.get(key) || 0) > Date.now()) {
				if (entry) { results[i] ??= JSON.parse(fs.readFileSync(entry.bodyPath, "utf8")); continue; }
				return sendJson(res, 502, { error: "upstream unavailable and no cached response" }, { "x-fad-proxy": "error" });
			}
			let promise = itemInflight.get(key);
			if (promise) stats.coalesced++;
			else {
				let resolve, reject;
				promise = new Promise((ok, fail) => { resolve = ok; reject = fail; });
				promise.catch(() => {});
				itemInflight.set(key, promise);
				reserved.push({ item: items[i], key, entry, resolve, reject });
				stats.misses++;
			}
			if (results[i] === undefined) waits.push(promise.then(body => { results[i] = body; }, error => {
				if (entry) { stats.stale++; results[i] = JSON.parse(fs.readFileSync(entry.bodyPath, "utf8")); }
				else throw error;
			}));
		}
		if (reserved.length) {
			(async () => {
				try {
					const subset = provider.batch(type, batch.pack(reserved.map(row => row.item)));
					const request = provider.build(type, subset.pack(subset.items));
					const headers = upstreamHeadersFor(request.url, reqHeaders, keys);
					if (request.init?.headers) Object.assign(headers, request.init.headers);
					stats.upstream++;
					const up = await fetcher(request.url, { ...request.init, headers, redirect: "follow" });
					if (!up.ok) throw new Error(`upstream returned ${up.status}`);
					const bodies = subset.split(await up.json());
					if (bodies.length !== reserved.length) throw new Error("incomplete provider batch response");
					for (let j = 0; j < reserved.length; j++) {
						const row = reserved[j], body = bodies[j];
						const bytes = Buffer.from(JSON.stringify(body));
						if (bytes.length <= maxBodyBytes) {
							const tmp = path.join(store.entriesDir, ".tmp-" + crypto.randomBytes(6).toString("hex"));
							fs.writeFileSync(tmp, bytes);
							store.commit(row.key, tmp, { fetchedAt: Date.now(), ttlMs: overrideTtlMs || provider.ttlMs || defaultTtlMs,
								contentType: "application/json", bytes: bytes.length });
						}
						failureUntil.delete(row.key);
						row.resolve(body);
					}
				} catch (error) {
					stats.errors++;
					for (const row of reserved) { failureUntil.set(row.key, Date.now() + FAILURE_RETRY_MS); row.reject(error); }
				} finally {
					for (const row of reserved) itemInflight.delete(row.key);
				}
			})().catch(() => {});
		}
		try { await Promise.all(waits); }
		catch (error) { return sendJson(res, 502, { error: error.message }, { "x-fad-proxy": "error" }); }
		return sendJson(res, 200, batch.merge(results), { "x-fad-proxy": reserved.length ? "miss" : "hit" });
	}

	async function handle(req, res) {
		stats.requests++;
		const target = req.url.replace(/^\/+/, "");
		if (target === "__health") return sendJson(res, 200, { ok: true, uptimeMs: Date.now() - stats.startedAt });
		if (!authorized(req)) return sendJson(res, 401, { error: "unauthorized", "x-fad-proxy": "unauthorized" });
		if (target === "__stats" && req.method === "GET") return sendJson(res, 200, { ...stats, entries: store.size() });
		if (target === "__clear" && (req.method === "POST" || req.method === "DELETE")) {
			const cleared = store.size();
			store.clear();
			return sendJson(res, 200, { cleared });
		}
		if (target === "v1/resource" && req.method === "POST") {
			let payload;
			try { payload = JSON.parse((await readRequestBody(req, 2 * 1024 * 1024)).toString("utf8")); }
			catch { return sendJson(res, 400, { error: "invalid resource request" }); }
			try {
				const { getProvider, providerKey } = require("./providers");
				const provider = getProvider(payload.provider);
				const request = provider.build(payload.type, payload.params);
				const reqHeaders = { ...request.init?.headers, ...payload.headers };
				if (provider.batch?.(payload.type, payload.params))
					return handleBatch(res, provider, payload.type, payload.params, reqHeaders);
				const effectiveHeaders = upstreamHeadersFor(request.url, reqHeaders, keys);
				const cacheKey = providerKey(payload.provider, payload.type, payload.params, effectiveHeaders);
				return handleCached(res, { target: request.url, cacheKey, reqHeaders,
					method: request.init?.method || "GET", body: request.init?.body,
					ttlMs: overrideTtlMs || provider.ttlMs || defaultTtlMs,
					cacheLimitBytes: payload.provider === "github" && payload.type === "cve-archive"
						? 1024 * 1024 * 1024 : maxBodyBytes });
			} catch (error) { return sendJson(res, 400, { error: error.message }); }
		}
		return sendJson(res, 404, { error: "expected /v1/resource or a control endpoint" });
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
	ttlForUrl, upstreamHeadersFor, createCacheStore, createProxyCacheServer, startProxyCacheServer,
	parseProxyFlag, runtimeSupportsEnvProxy, reexecWithProxy,
};
