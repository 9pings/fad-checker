const { test } = require("node:test");
const assert = require("node:assert");

test("npm fetchPackument tries custom registry first, falls back to public, sends auth", async () => {
	const { fetchPackument } = require("../lib/codecs/npm/registry");
	const seen = [];
	const fetcher = async (url, { headers }) => {
		seen.push({ url, auth: headers.Authorization || null });
		if (url.startsWith("https://priv/")) return { ok: false, status: 404 };
		return { ok: true, json: async () => ({ "dist-tags": { latest: "9.9.9" } }) };
	};
	const out = await fetchPackument("left-pad", {
		registries: [{ url: "https://priv/", token: "T" }],
		fetcher,
	});
	assert.strictEqual(out["dist-tags"].latest, "9.9.9");
	assert.strictEqual(seen[0].url, "https://priv/left-pad");
	assert.strictEqual(seen[0].auth, "Bearer T");
	assert.ok(seen[1].url.startsWith("https://registry.npmjs.org/"));
});

test("npm fetchPackument default (no registries) hits npmjs only", async () => {
	const { fetchPackument } = require("../lib/codecs/npm/registry");
	const seen = [];
	const fetcher = async (url) => { seen.push(url); return { ok: true, json: async () => ({}) }; };
	await fetchPackument("react", { fetcher });
	assert.strictEqual(seen.length, 1);
	assert.ok(seen[0].startsWith("https://registry.npmjs.org/"));
});

test("pypi fetchProject hits custom base then public", async () => {
	const { fetchProject } = require("../lib/codecs/pypi/registry");
	const seen = [];
	const fetcher = async (url) => { seen.push(url); return url.includes("priv") ? { ok: false, status: 500 } : { ok: true, json: async () => ({ info: { version: "2.0" } }) }; };
	const out = await fetchProject("flask", { registries: [{ url: "https://priv/pypi/" }], fetcher });
	assert.strictEqual(out.info.version, "2.0");
	assert.ok(seen[0].includes("priv"));
	assert.ok(seen[1].startsWith("https://pypi.org/pypi/flask/json"));
});

test("ruby fetchGem custom-first with Basic auth", async () => {
	const { fetchGem } = require("../lib/codecs/ruby/registry");
	const seen = [];
	const fetcher = async (url, { headers }) => { seen.push({ url, auth: headers.Authorization || null }); return url.includes("priv") ? { ok: false, status: 403 } : { ok: true, json: async () => ({ version: "3.1.0", licenses: ["MIT"] }) }; };
	const out = await fetchGem("rails", { registries: [{ url: "https://priv/", auth: "u:p" }], fetcher });
	assert.strictEqual(out.version, "3.1.0");
	assert.strictEqual(seen[0].auth, "Basic " + Buffer.from("u:p").toString("base64"));
	assert.ok(seen[1].url.startsWith("https://rubygems.org/api/v1/gems/rails.json"));
});

test("go fetchLatest custom-first then public", async () => {
	const { fetchLatest } = require("../lib/codecs/go/registry");
	const seen = [];
	const fetcher = async (url) => { seen.push(url); return url.includes("priv") ? { ok: false, status: 404 } : { ok: true, json: async () => ({ Version: "v1.5.0" }) }; };
	const out = await fetchLatest("github.com/foo/bar", { registries: [{ url: "https://priv/" }], fetcher });
	assert.strictEqual(out.latest, "1.5.0");
	assert.ok(seen[0].includes("priv"));
	assert.ok(seen[1].startsWith("https://proxy.golang.org/"));
});
