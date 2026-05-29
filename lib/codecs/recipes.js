/**
 * lib/codecs/recipes.js — recettes de fix par écosystème pour le report.
 *
 * Extrait de lib/cve-report.js (ECO_RECIPE + snippet helpers). Clés = id de codec
 * (== ecosystemType). Chaque recette : { label, pinSection, pinIntro(cnt),
 * snippet(items), directSection }. `items` = [{ groupId, artifactId, fixVersion }].
 */
function esc(s) {
	if (s == null) return "";
	return String(s)
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;");
}

function dependencyManagementSnippet(items) {
	const inner = items.map(it => `        <dependency>
            <groupId>${esc(it.groupId)}</groupId>
            <artifactId>${esc(it.artifactId)}</artifactId>
            <version>${esc(it.fixVersion)}</version>
        </dependency>`).join("\n");
	return `<dependencyManagement>
    <dependencies>
${inner}
    </dependencies>
</dependencyManagement>`;
}

function npmOverridesSnippet(items) {
	const lines = items.map(it => `    "${esc(it.artifactId)}": "${esc(it.fixVersion)}"`).join(",\n");
	return `{
  "overrides": {
${lines}
  }
}`;
}

function yarnResolutionsSnippet(items) {
	const lines = items.map(it => `    "${esc(it.artifactId)}": "${esc(it.fixVersion)}"`).join(",\n");
	return `{
  "resolutions": {
${lines}
  }
}`;
}

const maven = {
	label: "Maven",
	pinSection: "A. Pin vulnerable transitives in <dependencyManagement>",
	pinIntro: cnt => `Paste into the root POM to immediately neutralise ${cnt} transitive vulnerabilit${cnt > 1 ? "ies" : "y"}:`,
	snippet: dependencyManagementSnippet,
	directSection: "B. Or update the direct dependencies pulling them in",
};

const npm = {
	label: "npm",
	pinSection: "A. Pin vulnerable transitives via npm overrides",
	pinIntro: cnt => `Add to the root <code>package.json</code> and run <code>npm install</code> to force ${cnt} transitive${cnt > 1 ? "s" : ""} to a fixed version:`,
	snippet: npmOverridesSnippet,
	directSection: "B. Or update the direct dependencies (and run npm install)",
};

const yarn = {
	label: "Yarn",
	pinSection: "A. Pin vulnerable transitives via yarn resolutions",
	pinIntro: cnt => `Add to the root <code>package.json</code> and run <code>yarn install</code> to force ${cnt} transitive${cnt > 1 ? "s" : ""} to a fixed version:`,
	snippet: yarnResolutionsSnippet,
	directSection: "B. Or update the direct dependencies (and run yarn install)",
};

function composerRequireSnippet(items) {
	return items.map(it => `composer require ${it.groupId ? it.groupId + "/" : ""}${it.artifactId}:^${esc(it.fixVersion)}`).join("\n");
}

const composer = {
	label: "Composer",
	pinSection: "A. Update the abandoned / vulnerable packages",
	pinIntro: cnt => `Run for the ${cnt} affected package${cnt > 1 ? "s" : ""}, then commit the updated <code>composer.lock</code>:`,
	snippet: composerRequireSnippet,
	directSection: "B. Or bump them in composer.json and run composer update",
};

module.exports = { maven, npm, yarn, composer, dependencyManagementSnippet, npmOverridesSnippet, yarnResolutionsSnippet, composerRequireSnippet };
