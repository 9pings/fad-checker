const { test } = require("node:test");
const assert = require("node:assert/strict");
const { collectImportBoms, backfillVersions, resolveBomManagedVersions, resolveAndBackfill } = require("../lib/maven-bom");

// xml2js-shaped dependencyManagement entry helper.
const dm = (g, a, v, scope) => ({ groupId: [g], artifactId: [a], version: [v], ...(scope ? { scope: [scope] } : {}) });

test("collectImportBoms extracts distinct import BOMs, resolving ${prop} versions", () => {
	const propsByPom = {
		"super-pom/pom.xml": {
			properties: { "spring-boot.version": "3.5.3" },
			dependencyManagement: [
				dm("org.springframework.boot", "spring-boot-dependencies", "${spring-boot.version}", "import"),
				dm("commons-io", "commons-io", "2.20.0"), // not import → ignored
			],
		},
		// a module that inherited the same import entry → must dedupe
		"cnaps-core/pom.xml": {
			properties: { "spring-boot.version": "3.5.3" },
			dependencyManagement: [dm("org.springframework.boot", "spring-boot-dependencies", "${spring-boot.version}", "import")],
		},
	};
	const boms = collectImportBoms(propsByPom);
	assert.equal(boms.length, 1);
	assert.deepEqual(boms[0], { groupId: "org.springframework.boot", artifactId: "spring-boot-dependencies", version: "3.5.3" });
});

test("collectImportBoms skips entries whose version stays unresolved", () => {
	const propsByPom = { "p/pom.xml": { properties: {}, dependencyManagement: [dm("g", "bom", "${missing.version}", "import")] } };
	assert.equal(collectImportBoms(propsByPom).length, 0);
});

test("resolveBomManagedVersions builds a g:a→{version,bom} map via (injected) effectivePom", async () => {
	const fakeEffectivePom = async (g, a, v) => {
		assert.equal(`${g}:${a}:${v}`, "org.springframework.boot:spring-boot-dependencies:3.5.3");
		return { depMgmt: [
			{ groupId: "org.springframework.boot", artifactId: "spring-boot-starter-web", version: "3.5.3" },
			{ groupId: "com.fasterxml.jackson.core", artifactId: "jackson-databind", version: "2.19.0" },
		] };
	};
	const map = await resolveBomManagedVersions(
		[{ groupId: "org.springframework.boot", artifactId: "spring-boot-dependencies", version: "3.5.3" }],
		{ effectivePom: fakeEffectivePom });
	// Value carries the resolved version AND the top-level BOM coordinate that supplied it,
	// so backfill can record provenance ("version managed by <bom>").
	assert.deepEqual(map.get("org.springframework.boot:spring-boot-starter-web"),
		{ version: "3.5.3", bom: "org.springframework.boot:spring-boot-dependencies:3.5.3" });
	assert.deepEqual(map.get("com.fasterxml.jackson.core:jackson-databind"),
		{ version: "2.19.0", bom: "org.springframework.boot:spring-boot-dependencies:3.5.3" });
});

test("resolveBomManagedVersions records the FIRST (top-level) BOM that manages a coord", async () => {
	// Two platform BOMs both manage commons-io; first declared wins (Maven order) and is the
	// coord surfaced as provenance — not the nested/second one.
	const boms = [
		{ groupId: "com.acme", artifactId: "platform-a", version: "1.0.0" },
		{ groupId: "com.acme", artifactId: "platform-b", version: "2.0.0" },
	];
	const fakeEffectivePom = async (g, a) => a === "platform-a"
		? { depMgmt: [{ groupId: "commons-io", artifactId: "commons-io", version: "2.20.0" }] }
		: { depMgmt: [{ groupId: "commons-io", artifactId: "commons-io", version: "2.11.0" }] };
	const map = await resolveBomManagedVersions(boms, { effectivePom: fakeEffectivePom });
	assert.deepEqual(map.get("commons-io:commons-io"), { version: "2.20.0", bom: "com.acme:platform-a:1.0.0" });
});

test("backfillVersions fills ONLY versionless/unresolved Maven deps, leaving concrete ones", () => {
	const map = new Map([
		["org.springframework.boot:spring-boot-starter-web", { version: "3.5.3", bom: "org.springframework.boot:spring-boot-dependencies:3.5.3" }],
		["com.acme:lib", { version: "9.9.9", bom: "com.acme:bom:1.0.0" }],
	]);
	const deps = new Map([
		["a", { ecosystem: "maven", groupId: "org.springframework.boot", artifactId: "spring-boot-starter-web", version: null, versions: [] }],
		["b", { ecosystem: "maven", groupId: "com.acme", artifactId: "lib", version: "1.0.0", versions: ["1.0.0"] }], // concrete → untouched
		["c", { ecosystem: "maven", groupId: "x", artifactId: "y", version: "${unresolved}", versions: [] }], // not in map → stays
	]);
	const filled = backfillVersions(deps, map);
	assert.equal(filled, 1);
	assert.equal(deps.get("a").version, "3.5.3");
	assert.deepEqual(deps.get("a").versions, ["3.5.3"]);
	assert.equal(deps.get("b").version, "1.0.0");
	assert.equal(deps.get("c").version, "${unresolved}");
});

test("backfillVersions stamps versionSource on backfilled deps only", () => {
	const map = new Map([
		["org.springframework.batch:spring-batch-integration", { version: "6.0.3", bom: "org.springframework.boot:spring-boot-dependencies:4.0.6" }],
		["com.acme:lib", { version: "9.9.9", bom: "com.acme:bom:1.0.0" }],
	]);
	const deps = new Map([
		["a", { ecosystem: "maven", groupId: "org.springframework.batch", artifactId: "spring-batch-integration", version: null, versions: [] }],
		["b", { ecosystem: "maven", groupId: "com.acme", artifactId: "lib", version: "1.0.0", versions: ["1.0.0"] }], // concrete → not stamped
		["c", { ecosystem: "maven", groupId: "x", artifactId: "y", version: "${unresolved}", versions: [] }], // unmanaged → not stamped
	]);
	backfillVersions(deps, map);
	assert.deepEqual(deps.get("a").versionSource, { via: "bom", bom: "org.springframework.boot:spring-boot-dependencies:4.0.6" });
	assert.equal(deps.get("b").versionSource, undefined);
	assert.equal(deps.get("c").versionSource, undefined);
});

test("resolveAndBackfill end-to-end (injected effectivePom): spring-boot starters get versions", async () => {
	const propsByPom = { "p/pom.xml": { properties: { "spring-boot.version": "3.5.3" },
		dependencyManagement: [dm("org.springframework.boot", "spring-boot-dependencies", "${spring-boot.version}", "import")] } };
	const resolved = new Map([
		["org.springframework.boot:spring-boot-starter-web", { ecosystem: "maven", groupId: "org.springframework.boot", artifactId: "spring-boot-starter-web", version: null, versions: [] }],
	]);
	const fakeEffectivePom = async () => ({ depMgmt: [{ groupId: "org.springframework.boot", artifactId: "spring-boot-starter-web", version: "3.5.3" }] });
	const r = await resolveAndBackfill(propsByPom, resolved, { effectivePom: fakeEffectivePom });
	assert.equal(r.filled, 1);
	assert.equal(resolved.get("org.springframework.boot:spring-boot-starter-web").version, "3.5.3");
	assert.deepEqual(resolved.get("org.springframework.boot:spring-boot-starter-web").versionSource,
		{ via: "bom", bom: "org.springframework.boot:spring-boot-dependencies:3.5.3" });
});
