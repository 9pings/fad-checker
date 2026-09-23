/**
 * Coverage is a record of checks performed, independent of their findings.
 * A missing source or unknown version can never become a reassuring no-match.
 */
const EXECUTIONS = new Set(["completed", "partial", "not-run", "failed", "not-applicable"]);
const RESULTS = new Set(["affected", "no-match", "indeterminate", "not-applicable"]);

function createCoverage() {
	const records = [];
	const keys = new Set();
	return {
		records,
		record(input) {
			if (!input || !input.applicationId || !input.capability) throw new Error("coverage requires applicationId and capability");
			const { execution, result } = input;
			if (!EXECUTIONS.has(execution)) throw new Error(`invalid coverage execution: ${execution}`);
			if (!RESULTS.has(result)) throw new Error(`invalid coverage result: ${result}`);
			if (result === "no-match" && execution !== "completed") throw new Error("no-match requires a completed check");
			if (execution === "not-applicable" && result !== "not-applicable") throw new Error("not-applicable execution requires not-applicable result");
			if ((execution === "failed" || execution === "not-run") && result === "affected") throw new Error("an unexecuted check cannot establish affected");
			const expected = input.expected ?? 0;
			const executed = input.executed ?? 0;
			if (![expected, executed].every(n => Number.isSafeInteger(n) && n >= 0)) throw new Error("coverage counts must be nonnegative integers");
			if (execution === "completed" && executed < expected) throw new Error("completed check has fewer executions than expected");
			const key = [input.applicationId, input.occurrenceId || "", input.capability, input.sourceId || ""].join("\0");
			if (keys.has(key)) throw new Error("duplicate coverage check");
			keys.add(key);
			const entry = { ...input, expected, executed };
			records.push(entry);
			return entry;
		},
	};
}

function summarizeCoverage(records = []) {
	const out = { checks: records.length, completed: 0, partial: 0, failed: 0, notRun: 0, expected: 0, executed: 0 };
	for (const r of records) {
		if (r.execution === "completed") out.completed++;
		else if (r.execution === "partial") out.partial++;
		else if (r.execution === "failed") out.failed++;
		else if (r.execution === "not-run") out.notRun++;
		out.expected += r.expected || 0;
		out.executed += r.executed || 0;
	}
	return out;
}

function requiredCoverageComplete(records = [], capabilities = []) {
	if (!capabilities.length) return true;
	const applications = new Set(records.map(r => r.applicationId));
	if (!applications.size) return false;
	for (const applicationId of applications) {
		for (const capability of capabilities) {
			const checks = records.filter(r => r.applicationId === applicationId && r.capability === capability);
			if (!checks.length || checks.some(r => r.execution !== "completed" && r.execution !== "not-applicable")) return false;
		}
	}
	return true;
}

module.exports = { createCoverage, summarizeCoverage, requiredCoverageComplete, EXECUTIONS, RESULTS };
