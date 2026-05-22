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

module.exports = {
	CONFIG_PATH,
	CONFIG_DIR,
	load,
	save,
	set,
	get,
	getNvdApiKey,
};
