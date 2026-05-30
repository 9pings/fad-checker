---
title: "Auditing a polyglot codebase you can't build — without leaking it"
published: false
description: "A free, MIT CLI that scans Maven/npm/pnpm/Composer/PyPI/NuGet deps for CVEs, EOL and outdated versions in one pass, no build required — plus an air-gapped mode where the codebase never leaves the enclave."
tags: security, devsecops, opensource, showdev
canonical_url: https://github.com/n8tz/fad-checker
---

> TL;DR — `npm i -g fad-checker` then `fad -s ./your-project`. It scans Maven, npm/yarn/pnpm, Composer, PyPI and NuGet dependencies (plus vendored JS) for CVEs, end-of-life and outdated/deprecated versions, with **no build step**, and writes a self-contained HTML + Word report. There's also an **air-gapped audit mode** where your source never touches the online machine. Repo: [n8tz/fad-checker](https://github.com/n8tz/fad-checker).

## The problem

Security audits — including French **ANSSI/PASSI** engagements — keep landing me in the same corner:

1. The codebase is **polyglot**. A single repo has a Maven backend, an npm/pnpm frontend, a couple of PHP tools and a Python script. Five ecosystems, five different scanners, five reports.
2. I often **can't build it**. No matching JDK, no private Nexus creds, no `npm install` that completes on my laptop. Half the SCA tooling assumes a successful build.
3. The code is **confidential**. On a sensitive engagement it cannot be uploaded to a SaaS, and sometimes the audited machine is **air-gapped** while the vuln databases live online.

Most tools solve one or two of these. I wanted one pass, no build, and a way to keep the code inside the perimeter.

## What's already out there (honestly)

The OSS SCA space is strong, and I'm not trying to replace it:

- **Trivy**, **Grype + Syft**, **OSV-Scanner** — excellent container/SBOM supply-chain scanners. They *do* read lockfiles without a build (so does this tool); their sweet spot is CI, containers and SBOM pipelines.
- **Snyk** — great DB, but its Open Source scan generally needs you to **build the project** for accuracy.
- **OWASP Dependency-Check** — the Java veteran, but its CPE matching is noisy and it needs Maven Central / built artifacts to behave.

What I kept missing from the free tools: a single **no-setup, multi-ecosystem audit of a checkout** that also flags **end-of-life and outdated** components (most scanners skip EOL), produces a **report you can hand to a client**, and has a story for **confidential / air-gapped** work.

So I wrote [`fad-checker`](https://github.com/n8tz/fad-checker).

## How it works

It reads manifests and lockfiles **directly** — `pom.xml`, `package-lock.json`, `yarn.lock` (v1 + Berry), `pnpm-lock.yaml`, `composer.lock`, `poetry.lock`/`Pipfile.lock`/`uv.lock`/`pdm.lock`/`pyproject.toml`/`requirements.txt`, `packages.lock.json`/`*.csproj`/`*.fsproj`/`*.vbproj`. No `mvn`, no `npm install`, no Docker. When there's no lockfile, it does **best-effort** on pinned versions and tells you what it skipped.

Then for each resolved dependency it:

- matches against **CVEProject (cvelistV5) + OSV.dev + NIST NVD + retire.js** (vendored JS), merged and deduped, with each finding tagged by source;
- **cross-checks the NVD CPE version ranges** to drop matches whose version is outside the vulnerable range — keeping OSV-style recall while trimming false positives;
- flags **EOL** frameworks (via endoflife.date), **deprecated** packages (registry `deprecated`/`abandoned`/`yanked` fields + a curated list) and **outdated** versions (latest from each registry);
- writes a **self-contained HTML report + a Word-compatible `.doc`**, organized by ecosystem and by the manifest that declares each dep, with per-tool fix recipes.

```bash
npm i -g fad-checker
fad -s ./your-project            # read-only, full report
fad -s . --offline               # cached data only, no network
fad -s . --ecosystem maven,npm   # restrict to specific ecosystems
```

The CLI shows a global `[n/N]` progress checklist while it warms each database:

```
▸ Vulnerability database update
  [1/8] ✓ Transitive resolution (Maven Central) — +237 (total 1709)
  [2/8] ✓ CVE index (CVEProject)      — 9 match(es) · 2026-05-29
  [3/8] ✓ EOL frameworks              — 3 EOL
  ...
  [7/8] ✓ NVD enrichment              — 9 CVE · 1 false-positive filtered
  [8/8] ✓ retire.js (vendored JS)     — 17 finding(s)
```

## The part I'm proudest of: air-gapped audits

The vuln lookups need the network. The confidential codebase must not. So the scan is split into three phases, and **only public coordinates ever leave the secure machine**:

```bash
# Phase 1 — OFFLINE (audited machine): export an anonymized descriptor
fad -s ./proj -e "^(client|internal)\." --export-anonymized deps.json
#   deps.json = public coordinates only — no paths, URLs, hostnames or code

# Phase 2 — ONLINE (any machine, no source): warm the caches from those coordinates
fad --import-anonymized deps.json
fad --export-cache fad-cache.tar.gz

# Phase 3 — OFFLINE again: full report with real paths, from the warmed cache
fad --import-cache fad-cache.tar.gz
fad -s ./proj --offline
```

It works because fad-checker's caches are keyed by **coordinate / vuln id**, never by path — so warming them online and replaying offline yields cache hits. The descriptor is plain, reviewable JSON:

```json
{
  "schema": "fad-deps/1",
  "summary": { "total": 1472, "byEcosystem": { "maven": 141, "npm": 1331 } },
  "deps": [
    { "ecosystem": "npm", "name": "lodash", "version": "4.17.21", "scope": "prod" }
  ]
}
```

OSV-Scanner has an offline mode too, but it still needs the **source on the scanning machine**. Here the online box only ever sees `lodash@4.17.21`, never your repo.

## Where it fits — and where it doesn't

**Reach for fad-checker when:** you need a one-shot audit of a polyglot checkout you may not be able to build, a presentable HTML/Word deliverable, or a confidential / air-gapped engagement.

**Reach for Trivy or Grype + Syft when:** you want continuous CI supply-chain security, container/OS-package scanning, SBOM (CycloneDX/SPDX), license compliance, or EPSS/KEV-based gating — none of which fad-checker does. It's deliberately a different tool.

It also won't pretend: for **Maven `pom.xml`**, transitive versions aren't in the file, so — like every other tool — it reaches Maven Central (or you point it at your Nexus), and anything it genuinely can't resolve is reported up front rather than silently dropped.

## Try it / break it

It's MIT, Node ≥ 20 (or a single self-contained binary), ~250 tests. I'd love feedback — especially on the Maven transitive resolution and the anonymized-descriptor workflow.

👉 **[github.com/n8tz/fad-checker](https://github.com/n8tz/fad-checker)**
