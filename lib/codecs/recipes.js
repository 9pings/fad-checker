/**
 * lib/codecs/recipes.js — recettes de fix par écosystème pour le report.
 *
 * Extrait de lib/cve-report.js (ECO_RECIPE + snippet helpers). Clés = id de codec
 * (== ecosystemType). Chaque recette : { label, pinSection, pinIntro(cnt),
 * snippet(items), directSection }. `items` = [{ groupId, artifactId, fixVersion }].
 *
 * @author: N.BRAUN
 * @email: pp9ping@gmail.com
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

function pipInstallSnippet(items) {
	return items.map(it => `pip install '${esc(it.artifactId)}>=${esc(it.fixVersion)}'`).join("\n");
}

const pypi = {
	label: "PyPI",
	pinSection: "A. Upgrade the affected packages",
	pinIntro: cnt => `Upgrade the ${cnt} affected package${cnt > 1 ? "s" : ""}, then re-lock (poetry lock / pip-compile):`,
	snippet: pipInstallSnippet,
	directSection: "B. Or bump them in pyproject.toml / requirements.txt and re-lock",
};

function dotnetAddSnippet(items) {
	return items.map(it => `dotnet add package ${esc(it.artifactId)} --version ${esc(it.fixVersion)}`).join("\n");
}

const nuget = {
	label: "NuGet",
	pinSection: "A. Update the affected packages",
	pinIntro: cnt => `Run for the ${cnt} affected package${cnt > 1 ? "s" : ""} (or bump <code>Directory.Packages.props</code> under Central Package Management):`,
	snippet: dotnetAddSnippet,
	directSection: "B. Then restore and commit packages.lock.json",
};

function goGetSnippet(items) {
	return items.map(it => `go get ${esc(it.artifactId)}@v${esc(it.fixVersion)}`).join("\n");
}

const go = {
	label: "Go",
	pinSection: "A. Upgrade the affected modules",
	pinIntro: cnt => `Run for the ${cnt} affected module${cnt > 1 ? "s" : ""}, then commit go.mod / go.sum (go mod tidy):`,
	snippet: goGetSnippet,
	directSection: "B. Or bump them in go.mod and run go mod tidy",
};

function bundleUpdateSnippet(items) {
	return items.map(it => `bundle update ${esc(it.artifactId)} --conservative   # to >= ${esc(it.fixVersion)}`).join("\n");
}

const ruby = {
	label: "Ruby",
	pinSection: "A. Update the affected gems",
	pinIntro: cnt => `Run for the ${cnt} affected gem${cnt > 1 ? "s" : ""}, then commit Gemfile.lock:`,
	snippet: bundleUpdateSnippet,
	directSection: "B. Or pin them in the Gemfile and run bundle update",
};

module.exports = { maven, npm, yarn, composer, pypi, nuget, go, ruby, dependencyManagementSnippet, npmOverridesSnippet, yarnResolutionsSnippet, composerRequireSnippet, pipInstallSnippet, dotnetAddSnippet, goGetSnippet, bundleUpdateSnippet };
