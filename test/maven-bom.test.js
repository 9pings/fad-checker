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

test("resolveBomManagedVersions builds a g:a→version map via (injected) effectivePom", async () => {
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
	assert.equal(map.get("org.springframework.boot:spring-boot-starter-web"), "3.5.3");
	assert.equal(map.get("com.fasterxml.jackson.core:jackson-databind"), "2.19.0");
});

test("backfillVersions fills ONLY versionless/unresolved Maven deps, leaving concrete ones", () => {
	const map = new Map([
		["org.springframework.boot:spring-boot-starter-web", "3.5.3"],
		["com.acme:lib", "9.9.9"],
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
});
