/**
 * lib/codecs/gradle/catalog.js — Gradle version catalog (gradle/libs.versions.toml).
 *
 * Parses the TOML [versions]/[libraries] tables into a normalized shape and resolves
 * the Kotlin/Groovy DSL type-safe accessors (`libs.foo.bar` → alias `foo-bar`) plus the
 * `findVersion(ref)`/`findLibrary(alias)` forms used inside convention plugins.
 *
 * A Gradle accessor normalizes `-`, `_` and `.` to the same separator, so `groovy-core`,
 * `groovy.core` and `groovy_core` are the same library. We normalize both the alias keys
 * and the looked-up accessor with `[-_.] → "."` so the reverse lookup is unambiguous.
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
 */
const TOML = require("smol-toml");

function normKey(s) { return String(s || "").replace(/[-_.]/g, "."); }

// A library entry's version may be an inline string, a { ref = "alias" } pointer into
// [versions], or absent (BOM-managed). Return the concrete string or null.
function resolveLibVersion(versionField, versions) {
	if (versionField == null) return null;
	if (typeof versionField === "string") return versionField || null;
	if (typeof versionField === "object") {
		if (typeof versionField.ref === "string") return versions[versionField.ref] || null;
		// { strictly = "x" } / { require = "x" } / { prefer = "x" } rich version constraints.
		return versionField.strictly || versionField.require || versionField.prefer || null;
	}
	return null;
}

/**
 * Parse a libs.versions.toml text → { versions: {alias→str}, libraries: {alias→{group,name,version}},
 * plugins: {alias→{id,version}}, _byAccessor: {normalizedAlias→libraryEntry} }.
 */
function parseVersionCatalog(text) {
	let data = {};
	try { data = TOML.parse(String(text || "")); } catch { data = {}; }
	const versions = {};
	for (const [k, v] of Object.entries(data.versions || {})) {
		versions[k] = typeof v === "string" ? v : resolveLibVersion(v, {});
	}
	const libraries = {};
	for (const [alias, raw] of Object.entries(data.libraries || {})) {
		let group = null, name = null;
		if (typeof raw === "string") {
			// shorthand "group:name:version"
			const parts = raw.split(":");
			group = parts[0] || null; name = parts[1] || null;
			libraries[alias] = { group, name, version: parts[2] || null };
			continue;
		}
		if (raw && typeof raw === "object") {
			if (typeof raw.module === "string") {
				const i = raw.module.indexOf(":");
				group = i >= 0 ? raw.module.slice(0, i) : raw.module;
				name = i >= 0 ? raw.module.slice(i + 1) : null;
			} else {
				group = raw.group || null;
				name = raw.name || null;
			}
			libraries[alias] = { group, name, version: resolveLibVersion(raw.version, versions) };
		}
	}
	const plugins = {};
	for (const [alias, raw] of Object.entries(data.plugins || {})) {
		if (typeof raw === "string") { const [id, version] = raw.split(":"); plugins[alias] = { id: id || null, version: version || null }; continue; }
		if (raw && typeof raw === "object") plugins[alias] = { id: raw.id || null, version: resolveLibVersion(raw.version, versions) };
	}
	const byAccessor = {};
	for (const [alias, entry] of Object.entries(libraries)) byAccessor[normKey(alias)] = entry;
	return { versions, libraries, plugins, _byAccessor: byAccessor };
}

/** Resolve a DSL accessor (the part after `libs.`, e.g. "clamav.client") → library entry or null. */
function resolveLibraryAccessor(catalog, accessor) {
	if (!catalog) return null;
	return catalog._byAccessor[normKey(accessor)] || null;
}

/** Resolve a version alias (libs.findVersion("spring-boot")) → string or null. */
function findCatalogVersion(catalog, ref) {
	if (!catalog || !ref) return null;
	if (catalog.versions[ref] != null) return catalog.versions[ref];
	// tolerate accessor-style refs
	const want = normKey(ref);
	for (const [k, v] of Object.entries(catalog.versions)) if (normKey(k) === want) return v;
	return null;
}

module.exports = { parseVersionCatalog, resolveLibraryAccessor, findCatalogVersion, normKey };
