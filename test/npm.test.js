const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const {
	parsePackageJson,
	parsePackageLock,
	parseYarnLockV1,
	findJsManifests,
} = require("../lib/codecs/npm/parse");
const { collectNpmDeps } = require("../lib/codecs/npm/collect");

const FIX = path.join(__dirname, "fixtures", "monorepo-mixed");

test("parsePackageJson extracts dependencies + dev + peer scopes", () => {
	const res = parsePackageJson(path.join(FIX, "packages", "web-app", "package.json"));
	assert.equal(res.packageName, "@acme/web-app");
	assert.equal(res.packageVersion, "1.0.0");
	const byName = Object.fromEntries(res.deps.map(d => [d.name, d]));
	assert.equal(byName.axios.scope, "prod");
	assert.equal(byName.jest.scope, "dev");
	assert.equal(byName.react.scope, "peer");
});

test("parsePackageLock v3 enumerates direct + transitive deps with correct scopes", () => {
	const res = parsePackageLock(path.join(FIX, "packages", "web-app", "package-lock.json"));
	assert.equal(res.lockfileVersion, 3);
	const byName = Object.fromEntries(res.deps.map(d => [d.name, d]));
	// direct prod
	assert.equal(byName.axios.scope, "prod");
	assert.equal(byName.axios.version, "0.21.0");
	// transitive (depth via nested node_modules) — flat in v3, but here axios's "follow-redirects" lives at the top, depth 0
	assert.equal(byName["follow-redirects"].version, "1.13.0");
	// dev
	assert.equal(byName.jest.scope, "dev");
	assert.equal(byName.eslint.scope, "dev");
	// peer
	assert.equal(byName.react.scope, "peer");
});

test("parseYarnLockV1 picks up versions and dedupes by (name, version)", () => {
	const res = parseYarnLockV1(path.join(FIX, "packages", "cli", "yarn.lock"));
	assert.equal(res.lockfileVersion, 1);
	const byName = Object.fromEntries(res.deps.map(d => [d.name, d]));
	assert.equal(byName.chalk.version, "4.1.2");
	assert.equal(byName["ansi-styles"].version, "4.3.0");
	assert.equal(byName["@acme/private-utils"].version, "1.0.0");
	assert.equal(byName.mocha.version, "9.0.0");
});

test("findJsManifests discovers both packages, skips node_modules and Maven dirs", () => {
	const groups = findJsManifests(FIX);
	const dirs = groups.map(g => path.relative(FIX, g.dir)).sort();
	assert.ok(dirs.includes(path.join("packages", "web-app")));
	assert.ok(dirs.includes(path.join("packages", "cli")));
	// No Maven dir should appear
	assert.ok(!dirs.some(d => d.startsWith("services" + path.sep)));
});

test("collectNpmDeps merges both packages and namespaces keys with 'npm:'", () => {
	const map = collectNpmDeps(FIX, { verbose: false });
	assert.ok(map.has("npm:axios"));
	assert.ok(map.has("npm:lodash"));
	assert.ok(map.has("npm:chalk"));
	assert.ok(map.has("npm:@acme/private-utils"));
	const axios = map.get("npm:axios");
	assert.equal(axios.ecosystem, "npm");
	assert.equal(axios.artifactId, "axios");
	assert.equal(axios.groupId, "");
	assert.equal(axios.version, "0.21.0");
	assert.equal(axios.scope, "prod");
});

test("collectNpmDeps --ignore-test skips devDependencies (jest, eslint, mocha)", () => {
	const map = collectNpmDeps(FIX, { ignoreTest: true, verbose: false });
	assert.equal(map.has("npm:jest"), false);
	assert.equal(map.has("npm:eslint"), false);
	assert.equal(map.has("npm:mocha"), false);
	// prod deps still present
	assert.ok(map.has("npm:axios"));
	assert.ok(map.has("npm:chalk"));
});

test("collectNpmDeps deps2Exclude regex strips @acme/private-utils", () => {
	const map = collectNpmDeps(FIX, { deps2Exclude: /^@acme\//, verbose: false });
	assert.equal(map.has("npm:@acme/private-utils"), false);
	// public deps still present
	assert.ok(map.has("npm:axios"));
	assert.ok(map.has("npm:chalk"));
});

test("collectNpmDeps prefers lockfile (resolved) version over package.json range", () => {
	const map = collectNpmDeps(FIX, { verbose: false });
	// In web-app, package.json pins "0.21.0" and lockfile says "0.21.0" — verify
	// concrete resolved version is the one kept.
	const axios = map.get("npm:axios");
	assert.equal(/^\d/.test(axios.version), true);
});

test("collectNpmDeps skips package.json when a lockfile is present in the same dir", () => {
	// web-app has both package.json and package-lock.json. Only the lockfile
	// should source dep entries; the package.json (which carries ranges like
	// "^1.0.0" we can't query OSV with) must be ignored as a source.
	const map = collectNpmDeps(FIX, { verbose: false });
	const axios = map.get("npm:axios");
	assert.ok(axios.lockType?.startsWith("package-lock-v"), `axios should come from lockfile, got lockType=${axios.lockType}`);
	// And the only manifestPaths recorded for axios should be the lockfile
	for (const p of axios.manifestPaths) {
		assert.ok(p.endsWith("package-lock.json") || p.endsWith("yarn.lock"),
			`expected only lockfile manifestPaths for axios, got ${p}`);
	}
});

test("collectNpmDeps no-lockfile fallback: warns + scans pinned, skips ranges", () => {
	const map = collectNpmDeps(FIX, { verbose: false });
	assert.ok(Array.isArray(map.warnings), "warnings array should be present");
	const w = map.warnings.find(x => x.type === "no-lockfile" && x.manifestPath.includes("no-lock"));
	assert.ok(w, "expected a no-lockfile warning for packages/no-lock/package.json");
	assert.match(w.message, /best-effort/, "warning should mention best-effort/partial results");
	// Range-only deps must NOT leak into the Map (can't query OSV with "^1.0.0").
	assert.equal(map.has("npm:left-pad"), false, "left-pad ^1.0.0 must not be collected (unresolved range)");
	// Pinned exact versions ARE now collected best-effort (changed contract).
	assert.ok(map.has("npm:semver"), "semver 7.5.0 (pinned) should be collected from no-lock package.json");
	assert.equal(map.get("npm:semver").version, "7.5.0");
});

test("parsePackageLock tags flattened-transitive entries as scope='transitive'", () => {
	// follow-redirects is pulled in by axios but is not in the root's direct
	// dependency lists — even though npm v3 places it at depth 0 in node_modules,
	// it must be reported as transitive.
	const res = parsePackageLock(path.join(FIX, "packages", "web-app", "package-lock.json"));
	const byName = Object.fromEntries(res.deps.map(d => [d.name, d]));
	assert.equal(byName["follow-redirects"].scope, "transitive");
	assert.equal(byName.qs.scope, "transitive");
	// direct deps stay direct
	assert.equal(byName.axios.scope, "prod");
	assert.equal(byName.express.scope, "prod");
});

test("collectNpmDeps sets ecosystemType=npm for package-lock and yarn for yarn.lock", () => {
	const map = collectNpmDeps(FIX, { verbose: false });
	assert.equal(map.get("npm:axios").ecosystemType, "npm");      // from package-lock.json
	assert.equal(map.get("npm:chalk").ecosystemType, "yarn");     // from yarn.lock
});

test("collectNpmDeps captures peerDependencies (react@17 in web-app)", () => {
	const map = collectNpmDeps(FIX, { verbose: false });
	const react = map.get("npm:react");
	assert.ok(react, "react peer dep should be present");
	assert.equal(react.scope, "peer");
});
