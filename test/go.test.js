const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { parseGoMod, parseGoSum } = require("../lib/codecs/go/parse");
const { escapeModule } = require("../lib/codecs/go/registry");
const { purlFor } = require("../lib/purl");
const go = require("../lib/codecs/go.codec");

test("parseGoMod reads require blocks, strips v, flags indirect as transitive", () => {
	const { module, deps } = parseGoMod(`module github.com/acme/app
go 1.21
require (
	github.com/gin-gonic/gin v1.9.1
	github.com/bytedance/sonic v1.9.1 // indirect
)
require github.com/stretchr/testify v1.8.4
`);
	assert.equal(module, "github.com/acme/app");
	const gin = deps.find(d => d.name === "github.com/gin-gonic/gin");
	assert.equal(gin.version, "1.9.1");       // v stripped
	assert.equal(gin.scope, "compile");
	const sonic = deps.find(d => d.name === "github.com/bytedance/sonic");
	assert.equal(sonic.scope, "transitive");  // // indirect
	assert.ok(deps.find(d => d.name === "github.com/stretchr/testify"));
});

test("parseGoSum dedups module → version", () => {
	const { deps } = parseGoSum(`github.com/gin-gonic/gin v1.9.1 h1:abc=
github.com/gin-gonic/gin v1.9.1/go.mod h1:def=
`);
	assert.equal(deps.length, 1);
	assert.equal(deps[0].version, "1.9.1");
});

test("escapeModule case-encodes uppercase per the proxy protocol", () => {
	assert.equal(escapeModule("github.com/BurntSushi/toml"), "github.com/!burnt!sushi/toml");
});

test("go purl splits the module path into namespace + name", () => {
	const dep = { ecosystem: "go", namespace: "", name: "github.com/gin-gonic/gin", version: "1.9.1" };
	assert.equal(purlFor(dep), "pkg:golang/github.com/gin-gonic/gin@1.9.1");
});

test("go codec collects from the fixture (go.mod authoritative)", async () => {
	const { deps } = await go.collect(path.join(__dirname, "fixtures", "go-app"));
	assert.ok(deps.has("go:github.com/gin-gonic/gin"));
	assert.equal(deps.get("go:github.com/gin-gonic/gin").version, "1.9.1");
	assert.equal(deps.get("go:github.com/bytedance/sonic").scope, "transitive");
	assert.equal(go.osvPackageName(deps.get("go:github.com/gin-gonic/gin")), "github.com/gin-gonic/gin");
});

test("go codec detects the fixture dir", () => {
	assert.equal(go.detect(path.join(__dirname, "fixtures", "go-app")), true);
});
