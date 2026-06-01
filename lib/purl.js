/**
 * lib/purl.js — build Package URL (purl) strings from a depRecord.
 *
 * purl spec: pkg:<type>/<namespace>/<name>@<version>?qualifiers#subpath
 * We only emit type/namespace/name@version — enough for CycloneDX `bom-ref`
 * and CSAF `product_identification_helper.purl`.
 *
 * Pure (no I/O). Shared by lib/sbom-export.js and lib/csaf-export.js.
 */

// purl type per ecosystem. Maven keeps the dotted groupId as a single namespace
// segment (not slash-separated); npm/composer carry a namespace; pypi/nuget don't.
const TYPE = {
	maven: "maven",
	npm: "npm",
	composer: "composer",
	pypi: "pypi",
	nuget: "nuget",
};

// Per the purl spec, each namespace segment and the name are percent-encoded,
// but the dots inside a Maven groupId and the separators are preserved by
// encodeURIComponent (it leaves "." "-" "_" "~" alone), so it is the right tool.
function enc(s) {
	return encodeURIComponent(String(s));
}

// PEP 503 normalisation for PyPI names (purl mandates the canonical form).
function normalizePypi(name) {
	return String(name).toLowerCase().replace(/[-_.]+/g, "-");
}

/**
 * Build a purl for a depRecord. Returns null when the dep lacks a usable
 * ecosystem/name. Version is omitted when absent.
 */
function purlFor(dep) {
	if (!dep || typeof dep !== "object") return null;
	const eco = dep.ecosystem || dep.ecosystemType;
	const type = TYPE[eco];
	if (!type) return null;

	const rawName = dep.name || dep.artifactId;
	if (!rawName) return null;
	let namespace = dep.namespace || dep.groupId || "";
	let name = rawName;

	if (eco === "npm" && !namespace && name.startsWith("@") && name.includes("/")) {
		// Scoped package: "@scope/pkg" → namespace "@scope", name "pkg".
		const slash = name.indexOf("/");
		namespace = name.slice(0, slash);
		name = name.slice(slash + 1);
	} else if (eco === "pypi") {
		name = normalizePypi(name);
		namespace = "";
	} else if (eco === "nuget") {
		namespace = "";
	}

	const nsPart = namespace ? `${enc(namespace)}/` : "";
	const verPart = dep.version ? `@${enc(dep.version)}` : "";
	return `pkg:${type}/${nsPart}${enc(name)}${verPart}`;
}

module.exports = { purlFor };
