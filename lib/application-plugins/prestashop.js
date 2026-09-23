const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const yaml = require("js-yaml");
const { declaredCollectedAt } = require("../advisory-freshness");
const { fetchGithubAdvisories, writeSnapshotAtomically } = require("../application-providers/live-snapshot");
const { assessGithubAdvisories, prestashopRangeGrammar } = require("../application-providers/github-advisories");
const { join, within, readJson, composerOccurrences, composerComponent, composerCoverageDiagnostic, finishInventory } = require("./wave2-common");

const GITHUB_REPO = "PrestaShop/PrestaShop";
const SOURCE_ID = "github-prestashop-advisories";

function literalVersion(ctx, relative, constant) {
	if (!ctx.index.hasFile(relative)) return null;
	try {
		const source = ctx.readPrefix(relative, 65536);
		return source.match(new RegExp(`\\bdefine\\s*\\(\\s*['\"]${constant}['\"]\\s*,\\s*['\"]([^'\"\\r\\n]+)['\"]`))?.[1] || null;
	} catch { return null; }
}

function moduleAt(ctx, app, dir) {
	const slug = dir.split("/").at(-1);
	const names = dir === "." ? ctx.index.filesIn(".").filter(name => name.endsWith(".php")) : [`${slug}.php`];
	let file, name, observedVersion;
	for (const candidate of names) {
		const relative = join(dir, candidate);
		if (!ctx.index.hasFile(relative)) continue;
		let source;
		try { source = ctx.readPrefix(relative, 65536); } catch { continue; }
		if (!/\bextends\s+\\?[A-Za-z_\\]*Module\b/i.test(source)) continue;
		const declared = source.match(/\$this->name\s*=\s*['"]([^'"\r\n]+)['"]\s*;/)?.[1];
		if (!declared || declared.toLowerCase() !== candidate.slice(0, -4).toLowerCase()) continue;
		file = relative; name = declared;
		observedVersion = source.match(/\$this->version\s*=\s*['"]([^'"\r\n]+)['"]\s*;/)?.[1] || null;
		break;
	}
	if (!file) return null;
	const packageJson = join(dir, "composer.json");
	const coord = ctx.index.hasFile(packageJson) ? readJson(ctx, packageJson)?.name || null : null;
	return { id: `${app.id}:module:${dir}`, applicationId: app.id, kind: "module", path: dir,
		name, coord, version: observedVersion, rawVersion: observedVersion,
		versionStatus: observedVersion ? "observed" : "unknown",
		visibility: ctx.isPrivatePath(dir) ? "private" : "unknown", identityStatus: coord ? "verified" : "unknown",
		activation: "unknown", evidence: [{ path: file, field: "$this->name" },
			...(observedVersion ? [{ path: file, field: "$this->version" }] : [])] };
}

function themeAt(ctx, app, dir) {
	const file = join(dir, "config/theme.yml");
	if (!ctx.index.hasFile(file)) return null;
	let data;
	try { data = yaml.load(ctx.readText(file, 65536), { schema: yaml.JSON_SCHEMA }); }
	catch { return null; }
	if (!data || typeof data !== "object" || typeof data.name !== "string" || !data.name.trim()) return null;
	const observedVersion = typeof data.version === "string" || typeof data.version === "number" ? String(data.version) : null;
	const packageJson = join(dir, "composer.json");
	const coord = ctx.index.hasFile(packageJson) ? readJson(ctx, packageJson)?.name || null : null;
	return { id: `${app.id}:theme:${dir}`, applicationId: app.id, kind: "theme", path: dir,
		name: data.name, coord, version: observedVersion, rawVersion: observedVersion,
		versionStatus: observedVersion ? "observed" : "unknown",
		visibility: ctx.isPrivatePath(dir) ? "private" : "unknown", identityStatus: coord ? "verified" : "unknown",
		activation: "unknown", evidence: [{ path: file, field: "name" },
			...(observedVersion ? [{ path: file, field: "version" }] : [])] };
}

function componentAt(ctx, app) { return moduleAt(ctx, app, ".") || themeAt(ctx, app, "."); }

function isSite(dir, ctx) {
	if (!ctx.index.hasFile(join(dir, "config/config.inc.php"))) return false;
	const manifest = join(dir, "composer.json");
	if (ctx.index.hasFile(manifest) && readJson(ctx, manifest)?.name?.toLowerCase() === "prestashop/prestashop") return true;
	return ctx.index.hasFile(join(dir, "config/settings.inc.php")) && ctx.index.hasFile(join(dir, "classes/Tools.php"));
}

module.exports = {
	id: "prestashop", version: "0.1.0", apiVersion: 1, label: "PrestaShop",
	supportedLayouts: ["composer", "legacy", "component"],
	capabilities: { inventory: "experimental", advisories: "experimental" }, requiredCodecs: [],
	providerIds: [SOURCE_ID],
	discover(ctx) {
		if (ctx.scanContext === "component") {
			const component = componentAt(ctx, { id: "prestashop:." });
			return component ? [{ root: ".", layout: "component", componentKind: component.kind,
				evidence: component.evidence }] : [];
		}
		return ctx.index.directories.filter(dir => isSite(dir, ctx)).map(dir => ({ root: dir,
			layout: ctx.index.hasFile(join(dir, "composer.json")) ? "composer" : "legacy",
			evidence: [{ path: join(dir, "config/config.inc.php") },
				{ path: ctx.index.hasFile(join(dir, "composer.json")) ? join(dir, "composer.json") : join(dir, "classes/Tools.php") }] }));
	},
	collect(app, ctx) {
		if (app.layout === "component") return finishInventory(app, [componentAt(ctx, app)].filter(Boolean),
			[], undefined, { advisories: false });
		const components = [], diagnostics = [composerCoverageDiagnostic(app, ctx)].filter(Boolean);
		const installedFile = join(app.root, "config/settings.inc.php");
		const sourceFile = join(app.root, "install-dev/install_version.php");
		const installed = literalVersion(ctx, installedFile, "_PS_VERSION_");
		const source = literalVersion(ctx, sourceFile, "_PS_INSTALL_VERSION_");
		const version = installed || source;
		if (installed && source && installed !== source) diagnostics.push({ code: "CMS_VERSION_CONFLICT",
			applicationId: app.id, path: installedFile,
			message: `installed PrestaShop version ${installed} differs from source installer version ${source}` });
		components.push({ id: `${app.id}:core`, applicationId: app.id, kind: "core", path: app.root,
			name: "PrestaShop", coord: "prestashop/prestashop", version, rawVersion: version,
			versionStatus: installed ? "observed" : source ? "source-observed" : "unknown",
			visibility: "public", identityStatus: "verified", activation: "unknown",
			evidence: [{ path: installed ? installedFile : source ? sourceFile : join(app.root, "composer.json"),
				field: installed ? "_PS_VERSION_" : source ? "_PS_INSTALL_VERSION_" : "name" }] });
		for (const dir of ctx.index.directories) {
			if (!within(dir, app.root) || dir === app.root) continue;
			const relative = app.root === "." ? dir : dir.slice(app.root.length + 1);
			if (/^modules\/[^/]+$/.test(relative)) {
				const module = moduleAt(ctx, app, dir);
				if (module) components.push(module);
			} else if (/^themes\/[^/]+$/.test(relative)) {
				const theme = themeAt(ctx, app, dir);
				if (theme) components.push(theme);
			}
		}
		for (const entry of composerOccurrences(app, ctx)) {
			if (components.some(c => c.coord?.toLowerCase() === entry.coord)) continue;
			const kind = entry.occurrence.packageType === "prestashop-module" ? "module" :
				entry.occurrence.packageType === "prestashop-theme" ? "theme" : "library";
			components.push(composerComponent(app, entry, kind));
		}
		return finishInventory(app, components, diagnostics, undefined, { advisories: false });
	},
	// The publisher's machine feed is the GitHub advisory list of PrestaShop's own core
	// repository. Its 2020-era records carry no package identity; they are attributed to
	// the core coordinate here, and every range is evaluated with its patched bound.
	async assess(app, components, ctx) {
		if (!ctx.prestashopAdvisoriesPath && !ctx.livePrestashopAdvisoriesUrl) return { findings: [], coverage: [{
			applicationId: app.id, capability: "advisories", sourceId: SOURCE_ID, execution: "not-run",
			result: "indeterminate", expected: (components || []).length, executed: 0, diagnostic: "CMS_PROVIDER_UNCONFIGURED" }] };
		const key = ctx.prestashopAdvisoriesPath
			? `prestashop-advisories:${ctx.prestashopAdvisoriesPath}` : `prestashop-advisories:live:${ctx.livePrestashopAdvisoriesUrl}`;
		let cached = ctx.snapshotCache.get(key);
		if (!cached && ctx.prestashopAdvisoriesPath) {
			const validated = ctx.validatedLocalSources?.get(ctx.prestashopAdvisoriesPath);
			const stat = validated?.stat || fs.statSync(ctx.prestashopAdvisoriesPath);
			if (!stat.isFile() || stat.size > 128 * 1024 * 1024) throw new Error("PrestaShop advisory snapshot must be a JSON file of at most 128 MiB");
			const bytes = validated?.bytes || fs.readFileSync(ctx.prestashopAdvisoriesPath);
			const snapshot = validated?.snapshot || JSON.parse(bytes.toString("utf8"));
			const declared = declaredCollectedAt(snapshot);
			const sourceSnapshot = { sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
				fileModifiedAt: stat.mtime.toISOString(), completeness: "operator-declared",
				...(declared ? { collectedAt: declared.toISOString() } : {}) };
			cached = { snapshot, sourceSnapshot };
		} else if (!cached) {
			const fetched = await fetchGithubAdvisories(GITHUB_REPO, { fetchImpl: ctx.fetchImpl || undefined,
				endpoint: ctx.livePrestashopAdvisoriesUrl.startsWith("http") ? ctx.livePrestashopAdvisoriesUrl : null, now: ctx.now });
			if (ctx.advisoryCacheDir) writeSnapshotAtomically(path.join(ctx.advisoryCacheDir, "github-prestashop-advisories.json"), fetched.snapshot);
			cached = { snapshot: fetched.snapshot, sourceSnapshot: fetched.sourceSnapshot, live: true };
		}
		ctx.snapshotCache.set(key, cached);
		const assessed = assessGithubAdvisories(cached.snapshot, components,
			{ sourceId: SOURCE_ID, fallbackCoord: "prestashop/prestashop", normalizeRange: prestashopRangeGrammar });
		return { findings: assessed.matches, coverage: assessed.coverage.map(check => ({ ...check, sourceSnapshot: cached.sourceSnapshot })),
			diagnostics: assessed.diagnostics };
	},
	remediation() { return null; },
};
