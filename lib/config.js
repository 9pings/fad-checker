/**
 * lib/config.js — persistent user config in ~/.fad-check/config.json
 *
 * Stores credentials and per-user preferences that should survive across runs.
 * Currently: NVD API key (so users don't have to re-export the env var).
 */
const fs = require("fs");
const path = require("path");
const os = require("os");

const CONFIG_DIR = path.join(os.homedir(), ".fad-check");
const CONFIG_PATH = path.join(CONFIG_DIR, "config.json");

function load() {
	try { return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8")); }
	catch { return {}; }
}

function save(cfg) {
	fs.mkdirSync(CONFIG_DIR, { recursive: true });
	// 0o600 so an API key isn't world-readable
	fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2), { mode: 0o600 });
	try { fs.chmodSync(CONFIG_PATH, 0o600); } catch { /* ignore on platforms without chmod */ }
}

function set(key, value) {
	const cfg = load();
	if (value == null || value === "") delete cfg[key];
	else cfg[key] = value;
	save(cfg);
	return cfg;
}

function get(key) {
	return load()[key];
}

/** NVD API key resolution: env var first, then ~/.fad-check/config.json. */
function getNvdApiKey() {
	return process.env.NVD_API_KEY || get("nvd_api_key") || null;
}

/**
 * Custom Maven repositories (Nexus, Artifactory, JBoss, …) the user has
 * configured. Returned as an array of { name, url, auth? } where `auth` is
 * pre-encoded "user:pass" (caller wraps as Basic <base64>).
 *
 * Maven Central is intentionally NOT included here — callers append it as
 * the final fallback. That keeps the user's repos in priority order while
 * always ensuring Central works as a safety net.
 */
function getMavenRepos() {
	const list = get("maven_repos") || [];
	return Array.isArray(list) ? list : [];
}

function setMavenRepos(list) {
	return set("maven_repos", Array.isArray(list) && list.length ? list : null);
}

function addMavenRepo(name, url, auth = null) {
	const list = getMavenRepos().filter(r => r.name !== name);
	list.push({ name, url, ...(auth ? { auth } : {}) });
	setMavenRepos(list);
	return list;
}

function removeMavenRepo(name) {
	const before = getMavenRepos();
	const after = before.filter(r => r.name !== name);
	setMavenRepos(after);
	return before.length !== after.length;
}

module.exports = {
	CONFIG_PATH,
	CONFIG_DIR,
	load,
	save,
	set,
	get,
	getNvdApiKey,
	getMavenRepos,
	setMavenRepos,
	addMavenRepo,
	removeMavenRepo,
};
