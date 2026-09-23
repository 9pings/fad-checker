const path = require("node:path");

const join = (dir, file) => dir === "." ? file : `${dir}/${file}`;
const posix = value => String(value || "").split(path.sep).join("/");
const within = (child, parent) => parent === "." || child === parent || child.startsWith(parent + "/");

function readJson(ctx, relative, maxBytes = 1024 * 1024) {
	try {
		const value = JSON.parse(ctx.readText(relative, maxBytes));
		return value && typeof value === "object" && !Array.isArray(value) ? value : null;
	} catch { return null; }
}

function composerOccurrences(app, ctx) {
	const lock = join(app.root, "composer.lock");
	const matches = [];
	for (const dep of ctx.resolvedDeps.values()) {
		if (dep.ecosystem !== "composer") continue;
		const coord = `${dep.namespace}/${dep.name}`.toLowerCase();
		for (const occurrence of dep.occurrences || []) {
			const relative = posix(path.relative(ctx.srcRoot, occurrence.manifestPath));
			// A composer.json constraint describes intent, not an installed version.
			// Even an exact root requirement cannot prove the code was installed.
			if (relative !== lock) continue;
			matches.push({ coord, occurrence, relative });
		}
	}
	return matches;
}

function composerComponent(app, entry, kind) {
	const { coord, occurrence, relative } = entry;
	return { id: `${app.id}:${coord}@${occurrence.version}`, applicationId: app.id,
		kind, coord, name: coord, version: occurrence.version, rawVersion: occurrence.version,
		versionStatus: "locked", scope: occurrence.scope,
		managerRelation: occurrence.managerRelation || "unknown", visibility: "unknown",
		activation: "unknown", evidence: [{ path: relative, field: `packages[name=${coord}].version` }] };
}

function composerCoverageDiagnostic(app, ctx) {
	const manifest = ctx.index.hasFile(join(app.root, "composer.json"));
	const lock = ctx.index.hasFile(join(app.root, "composer.lock"));
	if (!manifest && !lock) return null;
	if (!lock) return { code: "CMS_LOCKFILE_MISSING", applicationId: app.id,
		message: "composer.json has no composer.lock; declared package constraints do not prove installed versions" };
	if (ctx.activeCodecIds.includes("composer")) return null;
	return { code: "CMS_CODEC_DISABLED", applicationId: app.id,
		message: "Composer collection is disabled; locked package versions and dependency origins are incomplete" };
}

function finishInventory(app, components, diagnostics = [], sourceId = "application-advisories", options = {}) {
	const unknown = components.filter(component => !component.version);
	return { components, diagnostics: [...diagnostics, ...unknown.map(component => ({ code: "CMS_VERSION_UNKNOWN",
		applicationId: app.id, componentId: component.id,
		message: `version unavailable for ${component.kind} ${component.name || component.coord || component.id}` }))],
		coverage: [
			{ applicationId: app.id, capability: "inventory", execution: unknown.length || diagnostics.length ? "partial" : "completed",
				result: unknown.length || diagnostics.length ? "indeterminate" : "not-applicable",
				expected: components.length, executed: components.length - unknown.length,
				...(unknown.length ? { diagnostic: "CMS_VERSION_UNKNOWN" } : diagnostics.length ? { diagnostic: diagnostics[0].code } : {}) },
			// A plugin with a qualified advisory lane reports that lane from assess() instead
			// (CMS_PROVIDER_UNCONFIGURED when unconfigured); the generic not-qualified entry
			// would then understate a coverage that actually ran.
			...(options.advisories === false ? [] : [{ applicationId: app.id, capability: "advisories", sourceId, execution: "not-run",
				result: "indeterminate", expected: components.length, executed: 0,
				diagnostic: "CMS_ADVISORY_NOT_QUALIFIED" }]),
			{ applicationId: app.id, capability: "lifecycle", sourceId: "application-lifecycle", execution: "not-run",
				result: "indeterminate", expected: 1, executed: 0,
				diagnostic: "CMS_LIFECYCLE_NOT_QUALIFIED" },
		] };
}

module.exports = { join, posix, within, readJson, composerOccurrences, composerComponent,
	composerCoverageDiagnostic, finishInventory };
