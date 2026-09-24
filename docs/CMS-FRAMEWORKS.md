# CMS & frameworks — the instance view

Most scanners read a WordPress or Drupal site the way they read any other directory: as a
bunch of lockfiles. fad-checker inventories the **instance** — the CMS or framework as a
product with a version, its plugins, themes, bundles, extensions and framework components —
attributes every dependency CVE to the component that actually ships it, and reports each
instance in its own sub-chapter. This guide is the reference for that view; every flag it
mentions also lives in [`USAGE.md`](USAGE.md).

## What gets detected, and how

Detection is a **conjunction of positive physical markers** — a bare `require` constraint
never creates an application, so a plain PHP library that happens to depend on
`symfony/framework-bundle` scans as exactly that: a library. Every recognized layout found
in the tree is activated by the default `--app-plugins auto`; `--app-plugins none` opts
out, `all` forces every plugin. Several instances of the same product in one tree are each
inventoried and reported separately, with shared occurrences detailed in every exposed
instance.

| Product | Requires | Core version evidence | Components inventoried |
| --- | --- | --- | --- |
| **WordPress** | `wp-load.php` + `wp-includes/version.php` + `wp-admin/` | `$wp_version` | core, plugins (`Plugin Name`, `Update URI`), themes (`style.css`) |
| **Drupal 8–11** | `composer.json` `require.drupal/core` + `core/lib/Drupal.php` + `core.services.yml` | lock pin, observed `Drupal.php`, conflict reported | core, modules (`.info.yml`, incl. `modules/contrib`), themes, profiles |
| **Drupal 7** | `includes/bootstrap.inc` with the literal 7.x `VERSION` define + `modules/system/system.module` | `VERSION` | core, legacy `.info` extensions |
| **Symfony** | kernel/front-controller marker *and* `symfony/framework-bundle` in that tree's lock | `composer.lock` pin | framework, framework-components, bundles, libraries; Symfony Flex recipes (`symfony.lock`) |
| **Laravel** | `artisan` + `bootstrap/app.php` + the framework requirement | `composer.lock` pin | framework, bundles, libraries |
| **PrestaShop** | `config/config.inc.php` + `config/settings.inc.php` | `define('_PS_VERSION_', …)` | core, modules, themes |
| **TYPO3** | composer layout with the core requirement | observed core marker | core, extensions |
| **SPIP** | `spip.php` + `ecrire/inc_version.php` (the version constant must be readable) | `$spip_version_branche` | core, dist plugins (`paquet.xml`), user plugins (`paquet.xml` or legacy `plugin.xml`) |
| **Joomla / Magento (Adobe Commerce)** | their own marker sets | product-internal | core, extensions/modules, themes |

Versions are read from **bounded prefixes** of the marker files — no file is ever executed.

## Direct vs indirect, private vs public

A CVE on a core, framework, official component, bundle, plugin or theme is **direct**; a
CVE on one of its *libraries* is **indirect** under the component that introduces it — never
direct by mere lock presence. Attribution comes from proven component ownership
(`lib/application-inventory.js`), not path guessing, and a finding shared by several
instances keeps its own origins in each.

**Private/custom components** (a plugin with a third-party `Update URI`, a module under
`modules/custom/`, anything you declare with `--private-component`) are inventoried
separately, their dependency CVEs stay in their own report group, and they are **never sent
to any publisher feed**. A component with a public catalogue identity can be declared with
`--public-component <relative-path>=<slug>`.

## Advisory lanes, per product

| Product | Advisory lane | Notes |
| --- | --- | --- |
| **WordPress** | **Wordfence v3 production feed** (`--wordfence-feed <file>` snapshot, or live with `WORDFENCE_API_KEY` / `--wordfence-api-key`) | matches only explicitly declared public plugin/theme identities; a live request without a key stops with exit `2` |
| **WordPress** (integrity) | **core checksums** (`--wp-checksums-live` / `--wp-checksums <file>`, `--wp-checksums-locale`) | modified / missing / extra core files are **diagnostics**, never CVE findings; `wp-content/` is user land |
| **Drupal** | **packages.drupal.org** per-package security advisories (`--drupal-advisories[-live]`) | queried for exactly the inventoried **public** `drupal/*` identities; `--max-advisory-age` bounds snapshot age |
| **PrestaShop** | the publisher's **GitHub security-advisories** feed (`--prestashop-advisories[-live]`) | whole-repository feed, range grammar normalized in the lane |
| **TYPO3** | the publisher's **GitHub security-advisories** feed (`--typo3-advisories[-live]`) | same mechanism |
| **SPIP** | **NVD product CVEs** for the core (`cpe:2.3:a:spip:spip`, `--spip-advisories[-live]`) | SPIP has no publisher API and no package ecosystem (not on Packagist, no GHSA — hosted on git.spip.net); NVD's versioned CPE is the one machine-readable source. SPIP *plugins* have no advisory source at all — their rows stay `not-run / CMS_ADVISORY_NOT_QUALIFIED`. The optional NVD API key only lifts the rate limit |
| **Symfony / Laravel** | **the dependency lanes** (OSV.dev, Packagist security-advisories, NVD) | neither framework publishes a machine-readable advisory feed; the inventoried components *are* Composer dependencies, so the coverage row reads `advisories (dependency-lanes): completed (n/n)` — a clean framework scan is stated as a result, not as an unexplained gap |
| **Joomla / Magento** | **per component** | no machine-readable publisher feed exists; a component locked as a Composer package is covered by the dependency lanes (`advisories (dependency-lanes): completed`), a source-only extension without a dep record stays honestly `not-run / CMS_ADVISORY_NOT_QUALIFIED` |

A publisher constat the standard Composer lane already found **merges** into that finding
with the union of its sources instead of duplicating it.

## Coverage that never overstates

Every capability row names the component it is about; identical gaps group into one
actionable block per cause. A lane that did not run is `not-run` with its diagnostic
(`CMS_PROVIDER_UNCONFIGURED`, `CMS_IDENTITY_UNVERIFIED`, …), never a clean verdict. The
instance synthesis (`CMS & Frameworks` chapter) aggregates per capability **and** provider:
a lane is `completed` only when every one of its checks ran. The one exception to
not-qualified noise is deliberate: a framework without a publisher feed reports its
advisories as covered by the dependency lanes (see the table above), because they are.

## The report

- **« CMS & Frameworks » chapter** — first CVE section whenever an instance was
  inventoried: an instance synthesis (observed version, direct/indirect counts, worst
  priority, aggregated coverage), then per-instance CVE groups split Direct / Indirect /
  Private, with cross-references for shared occurrences. A **zero-finding instance keeps
  its chapter** — the synthesis and coverage always render, so "detected and clean" is a
  stated result; only the CVE tables wait for findings.
- **Application inventory & coverage chapter** — every inventoried component with its
  version and evidence path, and the per-source coverage table.
- **Overview chart** — `Most vulnerable instances` ranks exposed instances by
  critical/high application findings; a shared occurrence counts in each.

## The air-gapped workflow

The publisher lanes are the only data an anonymized dependency descriptor cannot carry by
itself — so it carries what they need:

1. **Phase 1 (offline)** — `--export-anonymized` writes the public coordinates *and* the
   application identities: type, core version, and the inventoried **public** component
   identities (private components never leave the enclave; a module inventoried from its
   `.info.yml` without a lock entry is included, because the Drupal feed is keyed by
   package identity).
2. **Phase 2 (online)** — `--import-anonymized` warms **every** advisory snapshot the
   descriptor justifies, in one run: the Drupal feed (union of lock coordinates and
   inventoried identities — exactly the set the live source would query), the
   PrestaShop/TYPO3 repository feeds, one WordPress checksums reference per declared core
   version, and the Wordfence catalogue **when the warming machine holds an API key** (the
   key itself never travels). Each snapshot is validated with its provider's schema before
   being written. `--export-cache` then bundles everything.
3. **Phase 3 (offline)** — `--import-cache` + the plain `--offline` scan. Cached snapshots
   are consumed **automatically, with no advisory flag** — in every mode, so the air-gapped
   scan and its online reference (same command, same options) produce identical reports.
   An explicit flag always wins; a corrupt or stale snapshot fails the scan instead of
   silently under-reporting; `--max-advisory-age` applies to auto-consumed files exactly as
   to operator-supplied ones. Provenance follows the data: an auto-consumed snapshot
   reports `completeness: "tool-fetched"` with its stamp's `collectedAt` and source URL.

## Where the code lives

`lib/application-plugins/` (one plugin per product, `runner.js` for selection, validation
and the offline fallback), `lib/application-providers/` (publisher clients and evaluators,
`live-snapshot.js` for fetch/stamp/cache), `lib/application-inventory.js` (attribution),
`lib/cms-snapshot-warm.js` (phase-2 warming), `lib/deps-descriptor.js` (the `applications`
section of `fad-deps/1`).
