const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
	buildRepoList,
	splitUrlAuth,
	authHeader,
	tryRepos,
	fetchPomFromRepos,
	fetchMavenMetadata,
	MAVEN_CENTRAL,
} = require("../lib/maven-repo");

test("splitUrlAuth pulls user:pass out of a URL", () => {
	const { url, auth } = splitUrlAuth("https://alice:s3cr3t@nexus.acme.com/repository/maven-public/");
	assert.equal(auth, "alice:s3cr3t");
	assert.ok(!/alice:s3cr3t/.test(url));
	assert.ok(url.startsWith("https://nexus.acme.com/"));
});

test("splitUrlAuth no-op when URL has no auth", () => {
	const { url, auth } = splitUrlAuth("https://repo1.maven.org/maven2/");
	assert.equal(auth, null);
	assert.equal(url, "https://repo1.maven.org/maven2/");
});

test("authHeader returns Basic <base64>", () => {
	assert.equal(authHeader("alice:s3cr3t"), "Basic " + Buffer.from("alice:s3cr3t").toString("base64"));
	assert.equal(authHeader(null), null);
});

test("buildRepoList puts user repos first, Central last, dedupes by URL, normalises trailing slash", () => {
	const list = buildRepoList(
		[
			{ name: "nexus", url: "https://nexus.acme.com/repository/maven-public" },          // no trailing /
			{ name: "jboss", url: "https://repository.jboss.org/nexus/content/groups/public/" },
		],
		[
			{ url: "https://nexus.acme.com/repository/maven-public/" },                          // dup, with trailing /
			{ url: "https://maven.atlassian.com/" },
		],
	);
	assert.equal(list[0].name, "nexus");
	assert.equal(list[0].url, "https://nexus.acme.com/repository/maven-public/");
	assert.equal(list[1].name, "jboss");
	// The dup of "nexus" is dropped
	assert.equal(list.filter(r => r.name === "nexus").length, 1);
	// atlassian is in the middle (extra repo, before Central)
	assert.ok(list.some(r => r.url === "https://maven.atlassian.com/"));
	// Maven Central is last
	assert.equal(list[list.length - 1].url, MAVEN_CENTRAL.url);
});

test("buildRepoList strips and stores embedded user:pass auth", () => {
	const list = buildRepoList([
		{ name: "private", url: "https://bob:hunter2@nexus.acme.com/repository/private/" },
	]);
	assert.equal(list[0].url, "https://nexus.acme.com/repository/private/");
	assert.equal(list[0].auth, "bob:hunter2");
});

test("tryRepos returns the first 2xx, skipping 404s", async () => {
	const calls = [];
	const fetcher = async (url) => {
		calls.push(url);
		if (url.startsWith("https://nexus.acme/")) return { ok: false, status: 404 };
		if (url.startsWith("https://repo1.maven.org/")) return { ok: true, status: 200, text: async () => "<project/>" };
		return { ok: false, status: 500 };
	};
	const repos = buildRepoList([{ name: "nexus", url: "https://nexus.acme/" }]);
	const hit = await tryRepos(repos, "log4j/log4j/1.2.17/log4j-1.2.17.pom", { fetcher, readBody: true });
	assert.ok(hit, "should hit Central after Nexus 404");
	assert.equal(hit.repo.url, MAVEN_CENTRAL.url);
	assert.equal(hit.body, "<project/>");
	assert.equal(calls.length, 2);
});

test("tryRepos returns null when no repo answers 2xx", async () => {
	const fetcher = async () => ({ ok: false, status: 404 });
	const repos = buildRepoList([{ name: "a", url: "https://a.example/" }, { name: "b", url: "https://b.example/" }]);
	const hit = await tryRepos(repos, "g/a/1/a-1.pom", { fetcher });
	assert.equal(hit, null);
});

test("tryRepos sends Basic auth header for repos with creds", async () => {
	let seenAuth = null;
	const fetcher = async (url, init) => {
		seenAuth = init?.headers?.Authorization || null;
		return { ok: true, status: 200, text: async () => "ok" };
	};
	const repos = buildRepoList([{ name: "p", url: "https://x:y@nexus.acme/" }]);
	await tryRepos(repos, "g/a/1/a-1.pom", { fetcher });
	assert.equal(seenAuth, "Basic " + Buffer.from("x:y").toString("base64"));
});

test("fetchPomFromRepos constructs the standard Maven path", async () => {
	const seen = [];
	const fetcher = async (url) => { seen.push(url); return { ok: false, status: 404 }; };
	const repos = buildRepoList([{ name: "a", url: "https://a.example/" }]);
	await fetchPomFromRepos(repos, "org.apache.logging.log4j", "log4j-core", "2.17.0", { fetcher });
	assert.ok(seen[0].endsWith("org/apache/logging/log4j/log4j-core/2.17.0/log4j-core-2.17.0.pom"),
		`unexpected URL: ${seen[0]}`);
});

test("fetchMavenMetadata hits the maven-metadata.xml path", async () => {
	const seen = [];
	const fetcher = async (url) => { seen.push(url); return { ok: false, status: 404 }; };
	const repos = buildRepoList([{ name: "a", url: "https://a.example/" }]);
	await fetchMavenMetadata(repos, "org.apache.logging.log4j", "log4j-core", { fetcher });
	assert.ok(seen[0].endsWith("org/apache/logging/log4j/log4j-core/maven-metadata.xml"),
		`unexpected URL: ${seen[0]}`);
});
