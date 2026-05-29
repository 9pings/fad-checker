/**
 * lib/python/parse.js — parse Python manifests / lockfiles.
 *
 *   poetry.lock / uv.lock / pdm.lock — TOML, [[package]] name/version arrays.
 *   Pipfile.lock                     — JSON, { default:{}, develop:{} }, version "==x".
 *   requirements.txt                 — text; only "==" pins are queryable (fallback).
 *
 * All names are PEP 503 normalized (lowercase, runs of -_. → single -) so they
 * match OSV / PyPI / the resolved-deps key.
 */
const fs = require("fs");
const TOML = require("smol-toml");

function pep503(name) { return String(name || "").toLowerCase().replace(/[-_.]+/g, "-"); }

function stripOp(v) { return String(v || "").replace(/^[=~!<>]+/, "").trim(); }
function isPinned(spec) { return /^==\s*\d[\w.\-+!]*$/.test(String(spec || "").trim()); }
function isConcrete(v) { return /^\d+(\.\d+)*([.\-+]\S+)?$/.test(String(v || "")); }

// poetry.lock / uv.lock / pdm.lock all use [[package]] name/version arrays.
function parseTomlPackages(filePath, type) {
	const data = TOML.parse(fs.readFileSync(filePath, "utf8"));
	const pkgs = Array.isArray(data.package) ? data.package : [];
	const deps = [];
	for (const p of pkgs) {
		if (!p.name || !p.version) continue;
		// pdm marks groups; poetry/uv don't reliably → default prod.
		const groups = Array.isArray(p.groups) ? p.groups : null;
		const isDev = groups ? groups.every(g => g === "dev") : false;
		deps.push({ name: pep503(p.name), version: String(p.version), scope: isDev ? "dev" : "prod", isDev });
	}
	return { manifestPath: filePath, manifestType: type, deps };
}
const parsePoetryLock = f => parseTomlPackages(f, "poetry.lock");
const parseUvLock = f => parseTomlPackages(f, "uv.lock");
const parsePdmLock = f => parseTomlPackages(f, "pdm.lock");

function parsePipfileLock(filePath) {
	const json = JSON.parse(fs.readFileSync(filePath, "utf8"));
	const deps = [];
	const push = (obj, scope) => {
		for (const [name, meta] of Object.entries(obj || {})) {
			const v = stripOp(meta.version);
			if (!v) continue;
			deps.push({ name: pep503(name), version: v, scope, isDev: scope === "dev" });
		}
	};
	push(json.default, "prod");
	push(json.develop, "dev");
	return { manifestPath: filePath, manifestType: "Pipfile.lock", deps };
}

function parseRequirementsTxt(filePath) {
	const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
	const deps = [];
	let skipped = 0;
	for (const raw of lines) {
		const line = raw.replace(/#.*$/, "").trim();
		if (!line) continue;
		if (line.startsWith("-")) continue;                 // -e ., -r other.txt, --flags
		const m = line.match(/^([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(.*)$/);
		if (!m) continue;
		const name = pep503(m[1]);
		const spec = m[3].split(";")[0].trim();              // drop env markers
		if (isPinned(spec)) deps.push({ name, version: stripOp(spec), scope: "prod", isDev: false });
		else skipped++;
	}
	return { manifestPath: filePath, manifestType: "requirements.txt", deps, skipped };
}

module.exports = { pep503, isConcrete, parsePoetryLock, parseUvLock, parsePdmLock, parsePipfileLock, parseRequirementsTxt };
