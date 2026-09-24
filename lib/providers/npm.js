const { requestKey } = require("./common");
module.exports = {
	id: "npm", ttlMs: 24 * 3600 * 1000,
	key(type, params, scope) { return requestKey("npm", type, { name: String(params?.name || "").toLowerCase() }, scope); },
	build(operation, params) {
		if (operation !== "package" || !params?.name || typeof params.name !== "string") throw new Error("invalid npm request");
		const name = params.name.startsWith("@") ? params.name.replace("/", "%2F") : encodeURIComponent(params.name);
		return { url: `https://registry.npmjs.org/${name}` };
	},
};
