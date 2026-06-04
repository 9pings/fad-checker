const { test } = require("node:test");
const assert = require("node:assert/strict");
const { checkObsoleteDeps, checkObsolete, findEolProduct, KNOWN_OBSOLETE } = require("../lib/outdated");

test("known-obsolete.json contains the obvious historical hazards", () => {
	assert.ok(KNOWN_OBSOLETE["log4j:log4j"], "log4j 1.x must be flagged");
	assert.ok(KNOWN_OBSOLETE["commons-logging:commons-logging"]);
	assert.ok(KNOWN_OBSOLETE["org.codehaus.jackson:jackson-databind"] || KNOWN_OBSOLETE["org.codehaus.jackson:jackson-mapper-asl"]);
});

test("checkObsoleteDeps flags log4j 1.x and jackson 1.x", () => {
	const deps = new Map([
		["log4j:log4j", { groupId: "log4j", artifactId: "log4j", version: "1.2.17" }],
		["org.codehaus.jackson:jackson-mapper-asl", { groupId: "org.codehaus.jackson", artifactId: "jackson-mapper-asl", version: "1.9.13" }],
		["com.fasterxml.jackson.core:jackson-databind", { groupId: "com.fasterxml.jackson.core", artifactId: "jackson-databind", version: "2.16.0" }],
	]);
	const out = checkObsoleteDeps(deps);
	const ids = out.map(o => `${o.dep.groupId}:${o.dep.artifactId}`);
	assert.ok(ids.includes("log4j:log4j"));
	assert.ok(ids.includes("org.codehaus.jackson:jackson-mapper-asl"));
	assert.ok(!ids.includes("com.fasterxml.jackson.core:jackson-databind"));
	const log4j = out.find(o => o.dep.artifactId === "log4j");
	assert.equal(log4j.severity, "CRITICAL");
});

test("checkObsoleteDeps deduplicates by g:a", () => {
	const deps = new Map([
		["log4j:log4j", { groupId: "log4j", artifactId: "log4j", version: "1.2.17" }],
	]);
	// Call twice — should still report once
	const out1 = checkObsoleteDeps(deps);
	const out2 = checkObsoleteDeps(deps);
	assert.equal(out1.length, 1);
	assert.equal(out2.length, 1);
});

test("checkObsolete single-dep returns details or null", () => {
	const o = checkObsolete({ groupId: "log4j", artifactId: "log4j", version: "1.2" });
	assert.ok(o);
	assert.equal(o.severity, "CRITICAL");
	assert.equal(checkObsolete({ groupId: "com.fasterxml.jackson.core", artifactId: "jackson-databind" }), null);
});

test("findEolProduct matches Spring Boot by exact coord and by prefix", () => {
	const sb = findEolProduct({ groupId: "org.springframework.boot", artifactId: "spring-boot-starter-parent" });
	assert.equal(sb.product, "spring-boot");

	const sbcustom = findEolProduct({ groupId: "org.springframework.boot", artifactId: "spring-boot-starter-anything" });
	assert.equal(sbcustom.product, "spring-boot", "prefix-only mapping must still match");
});

test("findEolProduct picks longest prefix match", () => {
	const sec = findEolProduct({ groupId: "org.springframework.security", artifactId: "made-up" });
	assert.equal(sec.product, "spring-framework");
	assert.equal(sec.label, "Spring Security");
});

test("findEolProduct maps the npm 'angular' package to AngularJS 1.x", () => {
	// The literal npm package named "angular" IS AngularJS (1.x), EOL since 2022.
	const a = findEolProduct({ ecosystem: "npm", groupId: "", artifactId: "angular" });
	assert.equal(a.product, "angularjs");
	assert.equal(a.label, "AngularJS");
});

test("findEolProduct maps @angular/* scoped packages to modern Angular", () => {
	const core = findEolProduct({ ecosystem: "npm", groupId: "", artifactId: "@angular/core" });
	assert.equal(core.product, "angular");
	const router = findEolProduct({ ecosystem: "npm", groupId: "", artifactId: "@angular/router" });
	assert.equal(router.product, "angular");
});

test("findEolProduct maps react / react-dom / jquery / vue / bootstrap", () => {
	assert.equal(findEolProduct({ ecosystem: "npm", artifactId: "react" }).product, "react");
	assert.equal(findEolProduct({ ecosystem: "npm", artifactId: "react-dom" }).product, "react");
	assert.equal(findEolProduct({ ecosystem: "npm", artifactId: "jquery" }).product, "jquery");
	assert.equal(findEolProduct({ ecosystem: "npm", artifactId: "vue" }).product, "vue");
	assert.equal(findEolProduct({ ecosystem: "npm", artifactId: "bootstrap" }).product, "bootstrap");
});

test("findEolProduct returns null for an unmapped npm package", () => {
	assert.equal(findEolProduct({ ecosystem: "npm", artifactId: "left-pad" }), null);
	// A Maven groupId must never leak into the npm lookup.
	assert.equal(findEolProduct({ ecosystem: "npm", artifactId: "org.springframework" }), null);
});

test("findEolProduct maps WebJars (client-side JS shipped as Maven artifacts)", () => {
	// org.webjars:angularjs:1.8.3 — AngularJS 1.x, EOL since 2021.
	const ajs = findEolProduct({ groupId: "org.webjars", artifactId: "angularjs", version: "1.8.3" });
	assert.ok(ajs, "org.webjars:angularjs must map");
	assert.equal(ajs.product, "angularjs");

	assert.equal(findEolProduct({ groupId: "org.webjars", artifactId: "jquery" }).product, "jquery");
	assert.equal(findEolProduct({ groupId: "org.webjars", artifactId: "bootstrap" }).product, "bootstrap");
	// org.webjars.npm mirrors npm names; scope slash is encoded as "__".
	assert.equal(findEolProduct({ groupId: "org.webjars.npm", artifactId: "vue" }).product, "vue");
	assert.equal(findEolProduct({ groupId: "org.webjars.npm", artifactId: "angular__core" }).product, "angular");
});

test("findEolProduct returns null for an unmapped WebJar artifact", () => {
	assert.equal(findEolProduct({ groupId: "org.webjars", artifactId: "datatables" }), null);
});

test("findEolProduct reports the matched rule + key (origin traceability)", () => {
	const ga = findEolProduct({ groupId: "org.springframework.boot", artifactId: "spring-boot-starter-parent" });
	assert.equal(ga.via, "group-artifact");
	assert.equal(ga.viaKey, "org.springframework.boot:spring-boot-starter-parent");

	const prefix = findEolProduct({ groupId: "org.springframework.security", artifactId: "made-up" });
	assert.equal(prefix.via, "group-prefix");
	assert.equal(prefix.viaKey, "org.springframework.security");

	const npmName = findEolProduct({ ecosystem: "npm", artifactId: "jquery" });
	assert.equal(npmName.via, "npm-name");
	assert.equal(npmName.viaKey, "jquery");

	const npmScope = findEolProduct({ ecosystem: "npm", artifactId: "@angular/core" });
	assert.equal(npmScope.via, "npm-scope");
	assert.equal(npmScope.viaKey, "@angular/");

	const webjar = findEolProduct({ groupId: "org.webjars", artifactId: "angularjs", version: "1.8.3" });
	assert.equal(webjar.via, "webjar");
	assert.equal(webjar.viaKey, "angularjs");

	const composer = findEolProduct({ ecosystem: "composer", namespace: "laravel", name: "framework" });
	assert.equal(composer.via, "composer-name");
	assert.equal(composer.viaKey, "laravel/framework");

	// Returned object must be a COPY — never mutate the shared EOL_MAPPING entry.
	const { EOL_MAPPING } = require("../lib/outdated");
	assert.equal(EOL_MAPPING.by_npm_name.jquery.via, undefined, "must not pollute the shared mapping");
});
