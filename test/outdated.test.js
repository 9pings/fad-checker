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
