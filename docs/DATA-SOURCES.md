# Data sources & acknowledgments

`fad-checker` is glue around several outstanding public datasets. Each is used per its license terms.

| Source | What we use | License | API / endpoint |
| --- | --- | --- | --- |
| [CVEProject `cvelistV5`](https://github.com/CVEProject/cvelistV5) | Daily bulk CVE bundle, filtered to Maven-relevant entries | CC0-1.0 | GitHub release asset (zip) |
| [OSV.dev](https://osv.dev/) (Google + GitHub Security Lab) | Per-dep vulnerability lookup (Maven, npm, Packagist, PyPI, NuGet, …); full DB import via `--osv-db` | CC-BY 4.0 | `POST api.osv.dev/v1/querybatch`, `GET api.osv.dev/v1/vulns/{id}`, `Maven/all.zip` |
| [NIST NVD](https://nvd.nist.gov/) | Canonical CVE description + CVSS vectors + CPE configurations + CWE | US-gov public domain | `GET services.nvd.nist.gov/rest/json/cves/2.0?cveId=…` — free [API key](https://nvd.nist.gov/developers/request-an-api-key) bumps the rate limit 10× |
| [FIRST.org EPSS](https://www.first.org/epss/) | Exploit-prediction score + percentile per CVE | CC-BY 4.0 | `GET api.first.org/data/v1/epss?cve=…` (batched) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known-exploited-vulnerability catalogue membership | US-gov public domain | `GET cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| [endoflife.date](https://endoflife.date/) | Framework / runtime EOL cycle data | MIT | `GET endoflife.date/api/{product}.json` |
| [Maven Central](https://search.maven.org/) | Latest-version lookups + transitive POM fetches | Free public service | Solr `search.maven.org/solrsearch/select?q=…` + `repo1.maven.org/maven2/<coord>` |
| [npm registry](https://registry.npmjs.org/) | Per-version `deprecated` + `dist-tags.latest` | Free public service | `GET registry.npmjs.org/<pkg>` |
| [Packagist](https://packagist.org/) | Latest stable + `abandoned` flag | Free public service | `GET packagist.org/packages/<vendor>/<pkg>.json` |
| [PyPI](https://pypi.org/) | Latest + `yanked` + "Inactive" classifier | Free public service | `GET pypi.org/pypi/<pkg>/json` |
| [NuGet](https://www.nuget.org/) | Latest stable + per-version `deprecation` | Free public service | `GET api.nuget.org/v3/registration5-gz-semver2/<id>/index.json` |
| [Go module proxy](https://proxy.golang.org/) | Latest module version (outdated) | Free public service | `GET proxy.golang.org/<module>/@latest` |
| [RubyGems](https://rubygems.org/) | Latest stable + licenses | Free public service | `GET rubygems.org/api/v1/gems/<gem>.json` |
| [deps.dev](https://deps.dev/) | Native-binary identity by checksum (→ package coordinate) | Free public API (CC-BY) | `GET api.deps.dev/v3/query?hash.type=SHA1&hash.value=<base64>` |
| [CIRCL hashlookup](https://hashlookup.circl.lu/) | Known-good file identity (NSRL/distro/CDN) + KnownMalicious | Free public service | `GET hashlookup.circl.lu/lookup/sha256/<hash>` |
| [retire.js](https://retirejs.github.io/retire.js/) | Vendored-JS signature DB + scanner | Apache-2.0 | npm package `retire`, executed locally |
| [Snyk](https://snyk.io/) (optional) | Additional CVE source via `snyk test --all-projects --json` | Per Snyk EULA; needs a Snyk account | Local CLI `snyk` |
| [MITRE CWE](https://cwe.mitre.org/) | Weakness category links in the report | Free public reference | Linked by URL only, no API call |

Persistent caches (`~/.fad-checker/`) mean each source is hit at most once per its TTL (full
table → [`USAGE.md`](USAGE.md)). **No telemetry, no third-party analytics** — every request
above is made directly to the named endpoint with a `User-Agent: fad-checker-*` header, and
`--offline` makes none at all.
