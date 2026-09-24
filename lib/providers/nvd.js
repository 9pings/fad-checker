const { cveId, requestKey } = require("./common");
module.exports = {
	id: "nvd", ttlMs: 7 * 24 * 3600 * 1000,
	key(type, params, scope) { return requestKey("nvd", type, { id: cveId(params?.id) }, scope); },
	build(operation, params) {
		if (operation !== "cve" || !cveId(params?.id)) throw new Error("invalid NVD CVE request");
		return { url: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId(params.id))}` };
	},
};
