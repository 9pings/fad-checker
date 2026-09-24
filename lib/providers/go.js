module.exports = {
	id: "go", ttlMs: 24 * 3600 * 1000,
	build(operation, params) {
		if (operation !== "module-latest" || !params?.module || /\.\./.test(params.module) || typeof params.module !== "string") throw new Error("invalid Go module request");
		return { url: `https://proxy.golang.org/${params.module}/@latest` };
	},
};
