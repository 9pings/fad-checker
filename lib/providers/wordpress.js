module.exports = {
	id: "wordpress", ttlMs: 24 * 3600 * 1000,
	build(type, params) {
		if (type !== "checksums" || !params?.version || typeof params.version !== "string") throw new Error("invalid WordPress checksums request");
		return { url: `https://api.wordpress.org/core/checksums/1.0/?version=${encodeURIComponent(params.version)}&locale=${encodeURIComponent(params.locale || "en_US")}` };
	},
};
