module.exports = {
	id: "wordfence", ttlMs: 24 * 3600 * 1000,
	build(type) {
		if (type !== "production-feed") throw new Error("invalid Wordfence request");
		return { url: "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production" };
	},
};
