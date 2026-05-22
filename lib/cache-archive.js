/**
 * lib/cache-archive.js — export / import the entire ~/.fad-check/ directory.
 *
 * Use case:
 *   - Move the warmed-up CVE/OSV/NVD/POM caches between machines
 *   - Snapshot the index before a scheduled refresh
 *   - Share a known-good cache with a teammate
 *
 * Format:
 *   .tar.gz   — preferred when tar is available (Linux, macOS, Windows 10+)
 *   .zip      — fallback for Windows-only envs without tar
 *
 * The format is selected from the file extension. Tar uses native `tar`
 * binary (zero new deps).
 */
const fs = require("fs");
const path = require("path");
const os = require("os");
const { execFile } = require("child_process");
const { promisify } = require("util");
const execFileP = promisify(execFile);

const FAD_CACHE_DIR = path.join(os.homedir(), ".fad-check");

/**
 * Files inside ~/.fad-check/ that hold secrets and should NOT be shipped by default.
 * Override by passing `includeConfig: true`.
 */
const SENSITIVE_FILES = ["config.json"];

async function exportCache(destFile, opts = {}) {
	const { verbose, includeConfig } = opts;
	if (!fs.existsSync(FAD_CACHE_DIR)) throw new Error(`no ~/.fad-check/ directory to export`);
	const abs = path.resolve(destFile);
	fs.mkdirSync(path.dirname(abs), { recursive: true });

	const excludes = includeConfig ? [] : SENSITIVE_FILES.map(f => `${path.basename(FAD_CACHE_DIR)}/${f}`);
	if (excludes.length && verbose) console.log(`   excluding (use --include-config to keep): ${excludes.join(", ")}`);

	const ext = abs.toLowerCase();
	if (ext.endsWith(".tar.gz") || ext.endsWith(".tgz")) {
		const args = ["-czf", abs];
		for (const e of excludes) args.push(`--exclude=${e}`);
		args.push("-C", path.dirname(FAD_CACHE_DIR), path.basename(FAD_CACHE_DIR));
		if (verbose) console.log(`📦 tar ${args.join(" ")}`);
		await execFileP("tar", args, { maxBuffer: 1024 * 1024 * 32 });
	} else if (ext.endsWith(".zip")) {
		if (process.platform === "win32") {
			if (verbose) console.log(`📦 Compress-Archive -Path ${FAD_CACHE_DIR}\\* -DestinationPath ${abs}`);
			// Powershell Compress-Archive doesn't have a clean exclude flag — manual copy
			await execFileP("powershell", ["-NoProfile", "-Command",
				`$src='${FAD_CACHE_DIR}'; $dst='${abs}'; ${includeConfig ? `Compress-Archive -Path "$src\\*" -DestinationPath $dst -Force` : `$tmp=Join-Path $env:TEMP "fad-check-stage-$(Get-Random)"; Copy-Item $src $tmp -Recurse; ${SENSITIVE_FILES.map(f => `Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $tmp '${f}')`).join("; ")}; Compress-Archive -Path "$tmp\\*" -DestinationPath $dst -Force; Remove-Item $tmp -Recurse -Force`}`]);
		} else {
			const args = ["-r", "-q", abs, path.basename(FAD_CACHE_DIR)];
			for (const e of excludes) { args.push("-x"); args.push(e); }
			if (verbose) console.log(`📦 zip ${args.join(" ")}`);
			await execFileP("zip", args, { cwd: path.dirname(FAD_CACHE_DIR), maxBuffer: 1024 * 1024 * 32 });
		}
	} else {
		throw new Error(`unknown archive extension on ${destFile} (expected .tar.gz, .tgz, or .zip)`);
	}

	const size = fs.statSync(abs).size;
	return { path: abs, size, excluded: excludes };
}

async function importCache(srcFile, opts = {}) {
	const { verbose, force } = opts;
	const abs = path.resolve(srcFile);
	if (!fs.existsSync(abs)) throw new Error(`archive not found: ${abs}`);

	if (fs.existsSync(FAD_CACHE_DIR) && !force) {
		// Move existing aside as .fad-check.bak-<timestamp>
		const backup = `${FAD_CACHE_DIR}.bak-${Date.now()}`;
		fs.renameSync(FAD_CACHE_DIR, backup);
		if (verbose) console.log(`💾 existing ~/.fad-check/ moved to ${backup}`);
	} else if (force && fs.existsSync(FAD_CACHE_DIR)) {
		fs.rmSync(FAD_CACHE_DIR, { recursive: true, force: true });
		if (verbose) console.log(`🗑  --force: existing ~/.fad-check/ removed`);
	}

	const parent = path.dirname(FAD_CACHE_DIR);
	fs.mkdirSync(parent, { recursive: true });
	const ext = abs.toLowerCase();
	if (ext.endsWith(".tar.gz") || ext.endsWith(".tgz")) {
		if (verbose) console.log(`📦 tar -xzf ${abs} -C ${parent}`);
		await execFileP("tar", ["-xzf", abs, "-C", parent], { maxBuffer: 1024 * 1024 * 32 });
	} else if (ext.endsWith(".zip")) {
		if (process.platform === "win32") {
			if (verbose) console.log(`📦 Expand-Archive -Path ${abs} -DestinationPath ${parent}`);
			await execFileP("powershell", ["-NoProfile", "-Command",
				`Expand-Archive -Path '${abs}' -DestinationPath '${parent}' -Force`]);
		} else {
			if (verbose) console.log(`📦 unzip ${abs} -d ${parent}`);
			await execFileP("unzip", ["-o", "-q", abs, "-d", parent], { maxBuffer: 1024 * 1024 * 32 });
		}
	} else {
		throw new Error(`unknown archive extension on ${srcFile}`);
	}

	if (!fs.existsSync(FAD_CACHE_DIR)) {
		throw new Error(`import completed but ~/.fad-check/ was not created — was the archive built with fad-check --export-cache?`);
	}
	return { dir: FAD_CACHE_DIR };
}

module.exports = { exportCache, importCache, FAD_CACHE_DIR };
