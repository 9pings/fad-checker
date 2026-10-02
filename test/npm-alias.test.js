/**
 * npm aliases (`"lodash-legacy": "npm:lodash@4.17.20"`) must be recorded under the
 * REAL package name. Recorded under the alias, OSV/the CVE matchers are queried for a
 * package that does not exist on the registry (false negative: every CVE of the real
 * package is missed) and the exported purl names a phantom package.
 *
 * Every lockfile format spells an alias differently:
 *   package-lock v2/v3  "node_modules/string-width-cjs": { "name": "string-width", … }
 *   package-lock v1     "string-width-cjs": { "version": "npm:string-width@4.2.3" }
 *   yarn v1             "lodash-legacy@npm:lodash@4.17.20": version "4.17.20"
 *   yarn Berry          "lodash-legacy@npm:lodash@4.17.20": resolution "lodash@npm:4.17.20"
 *   pnpm v9             lodash-legacy: { version: lodash@4.17.20 }   → key lodash@4.17.20
 *   pnpm v6             lodash-legacy: { version: /lodash@4.17.20 }  → key /lodash@4.17.20
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { parsePackageLock, parseYarnLockV1, parsePnpmLock, parsePackageJson } = require("../lib/codecs/npm/parse");
const { collectNpmDeps } = require("../lib/codecs/npm/collect");

function project(files) {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fad-npm-alias-"));
	for (const [name, body] of Object.entries(files)) {
		fs.writeFileSync(path.join(dir, name), typeof body === "string" ? body : JSON.stringify(body, null, 2));
	}
	return dir;
}

const PKG = { name: "aliastest", version: "1.0.0", dependencies: { "@isaacs/cliui": "^8.0.2", "lodash-legacy": "npm:lodash@4.17.20", lodash: "4.17.21" } };

test("package-lock v3: entry.name wins over the node_modules folder name (audit repro)", () => {
	const dir = project({
		"package.json": PKG,
		"package-lock.json": {
			name: "aliastest", version: "1.0.0", lockfileVersion: 3, requires: true,
			packages: {
				"": { name: "aliastest", version: "1.0.0", dependencies: PKG.dependencies },
				"node_modules/@isaacs/cliui": { version: "8.0.2", dependencies: { "string-width-cjs": "npm:string-width@^4.2.0" } },
				"node_modules/string-width-cjs": { name: "string-width", version: "4.2.3", resolved: "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz" },
				"node_modules/lodash-legacy": { name: "lodash", version: "4.17.20", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz" },
				"node_modules/lodash": { version: "4.17.21" },
			},
		},
	});
	const deps = parsePackageLock(path.join(dir, "package-lock.json")).deps;
	const sw = deps.find(d => d.version === "4.2.3");
	assert.equal(sw.name, "string-width");
	assert.equal(sw.alias, "string-width-cjs");
	assert.equal(sw.scope, "transitive");
	const legacy = deps.find(d => d.version === "4.17.20");
	assert.equal(legacy.name, "lodash");
	assert.equal(legacy.alias, "lodash-legacy");
	assert.equal(legacy.scope, "prod", "the alias is what package.json declares → still a direct prod dep");

	const map = collectNpmDeps(dir);
	assert.equal(map.has("npm:string-width-cjs"), false, "no phantom alias coordinate");
	assert.equal(map.has("npm:lodash-legacy"), false, "no phantom alias coordinate");
	assert.deepEqual(map.get("npm:string-width").versions, ["4.2.3"]);
	assert.equal(map.get("npm:string-width").name, "string-width");
	// The real name AND the alias of it at a different version are both scanned.
	assert.deepEqual([...map.get("npm:lodash").versions].sort(), ["4.17.20", "4.17.21"]);
	assert.deepEqual(map.get("npm:lodash").aliases, ["lodash-legacy"]);
	fs.rmSync(dir, { recursive: true, force: true });
});

test("package-lock v1: alias version 'npm:string-width@4.2.3' → real name + concrete version", () => {
	const dir = project({
		"package.json": { name: "t", dependencies: { "string-width-cjs": "npm:string-width@^4.2.0", "sc": "npm:@scope/real@1.0.0" } },
		"package-lock.json": {
			name: "t", version: "1.0.0", lockfileVersion: 1,
			dependencies: {
				"string-width-cjs": { version: "npm:string-width@4.2.3", resolved: "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz" },
				"sc": { version: "npm:@scope/real@1.0.0" },
			},
		},
	});
	const deps = parsePackageLock(path.join(dir, "package-lock.json")).deps;
	const sw = deps.find(d => d.alias === "string-width-cjs");
	assert.equal(sw.name, "string-width");
	assert.equal(sw.version, "4.2.3");
	const sc = deps.find(d => d.alias === "sc");
	assert.equal(sc.name, "@scope/real");
	assert.equal(sc.version, "1.0.0");
	const map = collectNpmDeps(dir);
	assert.deepEqual(map.get("npm:string-width").versions, ["4.2.3"]);
	assert.equal(map.get("npm:string-width").scope, "prod", "the alias is declared in package.json dependencies");
	assert.deepEqual(map.get("npm:@scope/real").versions, ["1.0.0"]);
	assert.equal(map.has("npm:string-width-cjs"), false);
	fs.rmSync(dir, { recursive: true, force: true });
});

test("yarn v1: 'lodash-legacy@npm:lodash@4.17.20' recorded as lodash, merged with the real lodash", () => {
	const dir = project({
		"package.json": { name: "t", dependencies: { "lodash-legacy": "npm:lodash@4.17.20", lodash: "^4.17.21", "lo2": "npm:lodash@4.17.20" } },
		"yarn.lock": `# yarn lockfile v1


"lo2@npm:lodash@4.17.20", "lodash-legacy@npm:lodash@4.17.20":
  version "4.17.20"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
`,
	});
	const deps = parseYarnLockV1(path.join(dir, "yarn.lock")).deps;
	assert.deepEqual(deps.map(d => d.name).sort(), ["lodash", "lodash"], "no alias name leaks out as a package");
	const legacy = deps.find(d => d.version === "4.17.20");
	assert.equal(legacy.scope, "prod");
	assert.ok(["lo2", "lodash-legacy"].includes(legacy.alias));
	const map = collectNpmDeps(dir);
	assert.deepEqual([...map.get("npm:lodash").versions].sort(), ["4.17.20", "4.17.21"]);
	assert.equal(map.has("npm:lodash-legacy"), false);
	assert.equal(map.has("npm:lodash-legacy@npm:lodash"), false);
	assert.equal(map.has("npm:lo2"), false);
	fs.rmSync(dir, { recursive: true, force: true });
});

test("yarn v1: an alias declared in a dependency block resolves to the real package (transitive)", () => {
	const dir = project({
		"package.json": { name: "t", dependencies: { "@isaacs/cliui": "^8.0.2" } },
		"yarn.lock": `# yarn lockfile v1


"@isaacs/cliui@^8.0.2":
  version "8.0.2"
  dependencies:
    string-width-cjs "npm:string-width@^4.2.0"

"string-width-cjs@npm:string-width@^4.2.0":
  version "4.2.3"
  resolved "https://registry.yarnpkg.com/string-width/-/string-width-4.2.3.tgz"
`,
	});
	const sw = parseYarnLockV1(path.join(dir, "yarn.lock")).deps.find(d => d.version === "4.2.3");
	assert.equal(sw.name, "string-width");
	assert.equal(sw.alias, "string-width-cjs");
	assert.equal(sw.scope, "transitive");
	assert.deepEqual(sw.via, ["npm:@isaacs/cliui"]);
	fs.rmSync(dir, { recursive: true, force: true });
});

test("yarn Berry: alias descriptor resolved through `resolution` to the real package", () => {
	const dir = project({
		"package.json": { name: "t", dependencies: { "lodash-legacy": "npm:lodash@4.17.20", lodash: "^4.17.21" } },
		"yarn.lock": `__metadata:
  version: 8
  cacheKey: 10

"lodash-legacy@npm:lodash@4.17.20":
  version: 4.17.20
  resolution: "lodash@npm:4.17.20"
  checksum: 10c0/a
  languageName: node
  linkType: hard

"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: 10c0/b
  languageName: node
  linkType: hard

"t@workspace:.":
  version: 0.0.0-use.local
  resolution: "t@workspace:."
  dependencies:
    lodash: "npm:^4.17.21"
    lodash-legacy: "npm:lodash@4.17.20"
  languageName: unknown
  linkType: soft
`,
	});
	const deps = parseYarnLockV1(path.join(dir, "yarn.lock")).deps;
	assert.deepEqual(deps.map(d => d.name).sort(), ["lodash", "lodash"]);
	const legacy = deps.find(d => d.version === "4.17.20");
	assert.equal(legacy.alias, "lodash-legacy");
	assert.equal(legacy.scope, "prod");
	const map = collectNpmDeps(dir);
	assert.deepEqual([...map.get("npm:lodash").versions].sort(), ["4.17.20", "4.17.21"]);
	assert.equal(map.has("npm:lodash-legacy"), false);
	fs.rmSync(dir, { recursive: true, force: true });
});

test("pnpm v9: importer alias (version: lodash@4.17.20) classified as a direct prod dep of the real package", () => {
	const dir = project({
		"package.json": { name: "t", dependencies: { "lodash-legacy": "npm:lodash@4.17.20" }, devDependencies: { "sw": "npm:string-width@4.2.3" } },
		"pnpm-lock.yaml": `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      lodash-legacy:
        specifier: npm:lodash@4.17.20
        version: lodash@4.17.20
    devDependencies:
      sw:
        specifier: npm:string-width@4.2.3
        version: string-width@4.2.3

packages:

  lodash@4.17.20:
    resolution: {integrity: sha512-a}
  string-width@4.2.3:
    resolution: {integrity: sha512-b}

snapshots:

  lodash@4.17.20: {}
  string-width@4.2.3: {}
`,
	});
	const m = Object.fromEntries(parsePnpmLock(path.join(dir, "pnpm-lock.yaml")).deps.map(d => [d.name, d]));
	assert.equal(m.lodash.version, "4.17.20");
	assert.equal(m.lodash.scope, "prod");
	assert.equal(m.lodash.alias, "lodash-legacy");
	assert.equal(m["string-width"].scope, "dev");
	assert.equal(m["string-width"].isDev, true);
	assert.ok(!("lodash-legacy" in m) && !("sw" in m));
	fs.rmSync(dir, { recursive: true, force: true });
});

test("pnpm v6: importer alias (version: /lodash@4.17.20) + alias inside a package's dependencies", () => {
	const dir = project({
		"package.json": { name: "t", dependencies: { "lodash-legacy": "npm:lodash@4.17.20", cliui: "8.0.2" } },
		"pnpm-lock.yaml": `lockfileVersion: '6.0'

dependencies:
  cliui:
    specifier: 8.0.2
    version: 8.0.2
  lodash-legacy:
    specifier: npm:lodash@4.17.20
    version: /lodash@4.17.20

packages:

  /cliui@8.0.2:
    resolution: {integrity: sha512-a}
    dependencies:
      string-width-cjs: /string-width@4.2.3
    dev: false

  /lodash@4.17.20:
    resolution: {integrity: sha512-b}
    dev: false

  /string-width@4.2.3:
    resolution: {integrity: sha512-c}
    dev: false
`,
	});
	const m = Object.fromEntries(parsePnpmLock(path.join(dir, "pnpm-lock.yaml")).deps.map(d => [d.name, d]));
	assert.equal(m.lodash.scope, "prod");
	assert.equal(m.lodash.alias, "lodash-legacy");
	assert.equal(m["string-width"].scope, "transitive");
	assert.deepEqual(m["string-width"].via, ["npm:cliui"]);
	assert.equal(m["string-width"].alias, "string-width-cjs");
	fs.rmSync(dir, { recursive: true, force: true });
});

test("package.json without a lockfile: a pinned alias is scanned under the real name", () => {
	const res = (() => {
		const dir = project({ "package.json": { name: "t", dependencies: { "lodash-legacy": "npm:lodash@4.17.20", "x": "npm:other@^1.0.0" } } });
		const pj = parsePackageJson(path.join(dir, "package.json"));
		const map = collectNpmDeps(dir);
		fs.rmSync(dir, { recursive: true, force: true });
		return { pj, map };
	})();
	const legacy = res.pj.deps.find(d => d.alias === "lodash-legacy");
	assert.equal(legacy.name, "lodash");
	assert.equal(legacy.version, "4.17.20");
	assert.deepEqual(res.map.get("npm:lodash").versions, ["4.17.20"]);
	assert.equal(res.map.has("npm:lodash-legacy"), false);
	assert.equal(res.map.has("npm:other"), false, "an alias to a RANGE stays a range — skipped like any other");
});
