const crypto = require("node:crypto");

function requestKey(provider, operation, params, scope = "") {
	return JSON.stringify([provider, operation, params, scope]);
}
function credentialScope(headers = {}) {
	const h = new Headers(headers);
	const secret = [h.get("authorization") || "", h.get("apikey") || ""].join("\0");
	return secret.replace(/\0/g, "") ? crypto.createHash("sha256").update(secret).digest("hex") : "";
}
function cveId(value) {
	return /^CVE-\d{4}-\d{4,}$/i.test(String(value || "")) ? String(value).toUpperCase() : null;
}
function encodePath(value) { return String(value).split("/").map(encodeURIComponent).join("/"); }

module.exports = { requestKey, credentialScope, cveId, encodePath };
