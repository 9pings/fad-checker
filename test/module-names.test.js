const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { moduleNameFor, resolveModuleNames } = require("../lib/module-names");

// Injected reader: these are the project's OWN descriptors, never a dependency.
const files = {
	"/p/pom.xml": `<project><parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>2.7.18</version></parent><groupId>com.acme</groupId><artifactId>acme-gateway</artifactId></project>`,
	"/p/api/pom.xml": `<?xml version="1.0"?><project xmlns="http://maven.apache.org/POM/4.0.0">\n  <modelVersion>4.0.0</modelVersion>\n  <artifactId>acme-api</artifactId>\n</project>`,
	"/p/web/package.json": `{"name":"@acme/web","version":"1.0.0"}`,
	"/p/web/package-lock.json": `{"lockfileVersion":3}`,
	"/p/php/composer.json": `{"name":"acme/billing"}`,
	"/p/php/composer.lock": `{"packages":[]}`,
	"/p/svc/go.mod": `module github.com/acme/svc\n\ngo 1.22\n`,
	"/p/py/pyproject.toml": `[project]\nname = "acme-jobs"\nversion = "0.1.0"\n`,
	"/p/py2/pyproject.toml": `[tool.poetry]\nname = "acme-legacy"\n`,
	"/p/rb/Gemfile.lock": `GEM\n  specs:\n`,
	"/p/cs/App.csproj": `<Project Sdk="Microsoft.NET.Sdk"></Project>`,
	"/p/broken/pom.xml": `<project><parent><artifactId>only-a-parent</artifactId></parent></project>`,
	"/p/bad/package.json": `{ not json `,
};
const readFile = p => { if (!(p in files)) throw new Error("ENOENT"); return files[p]; };
const nameOf = p => moduleNameFor(p, { readFile });

test("Maven: the PROJECT artifactId, never the <parent> one", () => {
	// The parent block also carries an artifactId; taking the first match in the file
	// would label every Spring Boot module "spring-boot-starter-parent".
	assert.equal(nameOf("/p/pom.xml"), "acme-gateway");
	assert.equal(nameOf("/p/api/pom.xml"), "acme-api");
	assert.equal(nameOf("/p/broken/pom.xml"), null, "a pom with only a parent artifactId yields no name");
});

test("npm / composer / go / python read their own manifest name", () => {
	assert.equal(nameOf("/p/web/package.json"), "@acme/web");
	assert.equal(nameOf("/p/php/composer.json"), "acme/billing");
	assert.equal(nameOf("/p/svc/go.mod"), "github.com/acme/svc");
	assert.equal(nameOf("/p/py/pyproject.toml"), "acme-jobs");
	assert.equal(nameOf("/p/py2/pyproject.toml"), "acme-legacy");
});

test("a lockfile borrows the name from its sibling manifest", () => {
	assert.equal(nameOf("/p/web/package-lock.json"), "@acme/web");
	assert.equal(nameOf("/p/php/composer.lock"), "acme/billing");
});

test("no name anywhere → null, and the caller falls back to the path", () => {
	assert.equal(nameOf("/p/rb/Gemfile.lock"), null);
	assert.equal(nameOf("/p/cs/App.csproj"), null);
	assert.equal(nameOf("/p/bad/package.json"), null, "malformed JSON must not throw");
	assert.equal(nameOf("/p/missing/pom.xml"), null, "unreadable must not throw");
});

test("resolveModuleNames labels every descriptor, falling back to the path relative to the root", () => {
	const m = resolveModuleNames(
		[{ path: "/p/pom.xml" }, { path: "/p/web/package-lock.json" }, { path: "/p/rb/Gemfile.lock" }],
		{ srcRoot: "/p", readFile });
	assert.equal(m.get("/p/pom.xml"), "acme-gateway");
	assert.equal(m.get("/p/web/package-lock.json"), "@acme/web");
	assert.equal(m.get("/p/rb/Gemfile.lock"), "rb/Gemfile.lock", "no name → relative path");
	assert.equal(m.size, 3);
});

test("resolveModuleNames is robust to junk input", () => {
	assert.equal(resolveModuleNames(null, { srcRoot: "/p", readFile }).size, 0);
	assert.equal(resolveModuleNames([{}, { path: "" }], { srcRoot: "/p", readFile }).size, 0);
});
