/**
 * lib/dep-record.js — contrat de données unifié partagé par tous les codecs.
 *
 * `coordKey` est la clé de la Map résolue ; elle ne collisionne jamais entre
 * écosystèmes grâce au préfixe `ecosystem:`. `groupId`/`artifactId`/`pomPaths`
 * sont conservés comme alias rétro-compat le temps de migrer tous les
 * consommateurs vers `namespace`/`name`/`manifestPaths`.
 */

// Séparateur namespace↔name : ":" pour maven (g:a), "/" pour composer (vendor/pkg)
// et npm scopé (@org/name). "" sinon.
function joinNs(ecosystem, namespace, name) {
	if (!namespace) return name;
	if (ecosystem === "maven") return `${namespace}:${name}`;
	// composer (vendor/pkg) et npm scope (@org/name)
	return `${namespace}/${name}`;
}

// NuGet, Composer et PyPI sont case-insensitive : on normalise la clé en lower
// (l'affichage garde la casse d'origine via dep.name).
function normalizeForKey(ecosystem, s) {
	if (ecosystem === "nuget" || ecosystem === "composer" || ecosystem === "pypi") return String(s).toLowerCase();
	return s;
}

function coordKeyFor(ecosystem, namespace, name) {
	const joined = joinNs(ecosystem, normalizeForKey(ecosystem, namespace || ""), normalizeForKey(ecosystem, name || ""));
	return `${ecosystem}:${joined}`;
}

function makeDepRecord(input) {
	const { ecosystem, namespace = "", name, version = null, manifestPath, scope = "compile", isDev = false, ecosystemType } = input;
	const concrete = version && !/\$\{/.test(version) ? version : null;
	const manifestPaths = manifestPath ? [manifestPath] : [];
	return {
		ecosystem,
		ecosystemType: ecosystemType || ecosystem,
		namespace: namespace || "",
		name,
		version: version || null,
		versions: concrete ? [concrete] : [],
		coordKey: coordKeyFor(ecosystem, namespace, name),
		scope,
		isDev: !!isDev,
		manifestPaths,
		// Alias rétro-compat : CHAMPS DUPLIQUÉS RÉELS (pas des getters — les depRecords
		// sont spreadés dans des chemins chauds : cve-match.js:175, scan-completeness.js,
		// cve-report.js:1036, snyk.js:105 — un getter serait perdu au spread).
		// groupId/artifactId sont des strings jamais réassignées → pas de dérive.
		// pomPaths PARTAGE la référence de manifestPaths → les push restent synchrones.
		groupId: namespace || "",
		artifactId: name,
		pomPaths: manifestPaths,
	};
}

module.exports = { makeDepRecord, coordKeyFor };
