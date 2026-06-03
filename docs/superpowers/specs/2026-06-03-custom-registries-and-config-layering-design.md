# Custom registries (all ecosystems) + layered config — design

Date: 2026-06-03
Status: approved (pending spec review)

## Goal

Two related capabilities:

1. **Custom/private registries for every "easy" ecosystem**, not just Maven.
   Today only Maven supports private repos (`--add-repo`, `--repo`, `config.json`
   `maven_repos`, `lib/maven-repo.js`). Extend the same model to **npm, PyPI,
   Ruby, Go** (base-URL swap + auth). NuGet and Composer are explicitly **out of
   scope** for now (private feeds need V3 service-index / Satis `packages.json`
   discovery — a follow-up).

2. **Layered configuration** so options (including registries) don't have to be
   retyped each run: a project-local `./.fad-env.json` (JSON), an explicit
   `--config <file.json>` (JSON), and a `FAD_CHECKER_ENV` environment variable
   carrying a **string of CLI flags** (exactly what you'd type after
   `fad-checker`, e.g. `--fail-on high --ecosystem maven,npm --repo npm=https://npm.acme/`).

**No backward compatibility is kept.** The legacy `maven_repos` config key and
the 2-arg `--add-repo <name> <url>` Maven shortcut are removed/replaced.

## 1. Unified registry store

`~/.fad-checker/config.json` gains a per-ecosystem `registries` map (the
`maven_repos` key is gone — Maven is just one ecosystem now):

```json
{
  "registries": {
    "maven": [{ "name": "nexus", "url": "https://nexus.acme/maven-public/", "auth": "user:pass" }],
    "npm":   [{ "name": "verdaccio", "url": "https://npm.acme/", "token": "abc" }],
    "pypi":  [{ "name": "devpi", "url": "https://pypi.acme/", "auth": "user:pass" }],
    "ruby":  [{ "name": "gemfury", "url": "https://gem.acme/" }],
    "go":    [{ "name": "athens", "url": "https://goproxy.acme/" }]
  }
}
```

Entry shape: `{ name, url, auth?, token? }`.
- `auth: "user:pass"` → `Authorization: Basic <base64>`.
- `token: "…"` → `Authorization: Bearer <token>` (npm/Ruby/Go private feeds).
- Inline `https://user:pass@host/…` is accepted and split out (existing
  `splitUrlAuth`).

**Fallback semantics (same as Maven Central today):** custom registries are
tried **first, in declared order; the public registry is appended last**
(`registry.npmjs.org` / `pypi.org` / `rubygems.org` / `proxy.golang.org`). First
2xx wins.

**Merge semantics:** registries are a **list, unioned across every config
layer** (global config + config file + env + CLI `--repo`), deduped by URL.
They are never overridden by a higher layer — only added to.

### New module: `lib/registries.js`

Generalizes `lib/maven-repo.js`'s list-building (the Maven HTTP fan-out helpers
stay in `maven-repo.js`; only the *list assembly* generalizes):

- `getRegistries(ecosystem, mergedConfig)` → `[{name,url,auth,token}]` from the
  merged config layers for that ecosystem (no public fallback appended — callers
  append it, matching Maven's "Central last").
- `buildRegistryList(ecosystem, layers, extras)` → dedup-by-URL union + auth
  split. The Maven path keeps using `lib/maven-repo.js#buildRepoList` (which now
  reads `registries.maven`); the new helper serves npm/pypi/ruby/go.
- `authHeaderFor(entry)` → `Basic`/`Bearer`/null. Pure.

## 2. CLI surface

```bash
# Persisted (writes ~/.fad-checker/config.json → registries.<eco>)
fad-checker --add-repo <eco> <name> <url> [--auth user:pass] [--token TOK]
fad-checker --add-repo npm verdaccio https://npm.acme/ --token abc
fad-checker --list-repos                 # grouped by ecosystem
fad-checker --remove-repo <eco> <name>

# One-off (not persisted), repeatable, ALWAYS eco-scoped (no backward compat)
fad-checker -s ./proj --repo npm=https://npm.acme/ --repo maven=https://nexus.acme/maven-public/
```

- `--add-repo` is parsed **before `program.parse()`** (like today) so it can
  read the 3 positional args and exit. Now requires exactly `<eco> <name> <url>`;
  `<eco>` must be one of the supported ids (`maven|npm|pypi|ruby|go`) or it errors
  with the allowed list.
- `--repo <eco=url...>` is a commander variadic; each value must match
  `^<eco>=<url>$`. A bare URL (no `eco=`) is a hard error (no Maven default).
- `--list-repos` prints each ecosystem's entries in priority order, masking auth.

## 3. Layered config (`./.fad-env.json`, `--config`, `FAD_CHECKER_ENV`)

Two different formats, on purpose:
- **File layer** (`--config <file.json>` / `./.fad-env.json`): a **JSON object**
  whose keys mirror commander camelCase option names (e.g. `failOn`, `ecosystem`,
  `exclude`, `noNuget`, `reportSbom`, plus `registries`).
- **Env layer** (`FAD_CHECKER_ENV`): a **string of CLI flags**, exactly as typed
  on the command line (e.g. `--fail-on high --ecosystem maven,npm --repo npm=https://npm.acme/`).

### New module: `lib/options-env.js`

- `loadConfigFile(path)` → parsed JSON object or `null` (with a clear error on
  malformed JSON — do not silently swallow).
- `parseEnvFlags(str, program)` → an options object derived from a CLI-flag
  string. Tokenizes quote-aware (a tiny shell-style splitter; supports
  single/double quotes and `\` escapes), then runs a **throwaway clone of the
  commander `program`** over those tokens with `{ from: 'user' }`, and returns
  only the options whose `getOptionValueSource(name)` is **not** `'default'`
  (i.e. the ones the env string actually set). Registries from `--repo` in the
  env string are captured for the union.
- `loadLayers({ cwd, configPath, envStr, program })` → `{ fileLayer, envLayer }`:
  - file layer = `--config <path>` if given, else `./.fad-env.json` if present,
    else `{}`.
  - env layer = `parseEnvFlags(FAD_CHECKER_ENV, program)` if set, else `{}`.
- `applyLayers(program, layers, configStore)` → effective options.
  Uses commander's `program.getOptionValueSource(name)` on the **real** parse: a
  layer value fills an option **only when the CLI source is `'default'` or
  undefined** (the user did not pass it), trying file layer first, then env
  layer, then the global `configStore`. Registries are merged separately (union,
  see §1) across all layers + CLI `--repo`.

### Precedence (highest → lowest)

1. **CLI flags** (explicitly passed)
2. **Config file** — `--config <file>` (if given) **else** `./.fad-env.json`
3. **`FAD_CHECKER_ENV`** env var (string of CLI flags)
4. **`~/.fad-checker/config.json`** (global persisted store: NVD key + registries)
5. Built-in commander defaults

Registries: unioned across layers 2–4 + CLI `--repo`, never overridden.

### Wiring in `fad-checker.js`

After `program.parse()`, before building repo lists / running:
`const layers = loadLayers({ cwd, configPath: program.opts().config, envStr: process.env.FAD_CHECKER_ENV, program });`
`const options = applyLayers(program, layers, config.load());`
Then registry lists are built per ecosystem from the merged `registries` and
threaded into each codec's `checkRegistry`.

## 4. Per-codec plumbing

`lib/codecs/{npm,pypi,ruby,go}/registry.js` — each `check…RegistryDeps(deps,
opts)` gains `opts.registries` (array; **public base appended last** by the
caller). The internal `fetch…` helper iterates the list, applying per-registry
auth, returning the first success. With no custom registries the behaviour is
byte-identical to today (single public base).

Orchestrator (`fad-checker.js`, the per-codec registry pass ~line 720 and the
maven/npm passes ~648/711) builds each ecosystem's list once and passes it via
the existing `opts` object the codec `checkRegistry` already receives.

**PyPI/Ruby caveat (documented):** a custom base must speak the **same JSON API**
as the public one (`{base}/pypi/{name}/json`, `{base}/api/v1/gems/{name}.json`).
A pure PEP 503 / simple-index private mirror yields no latest/yanked/license
metadata — we note this in the docs rather than parsing simple-index HTML.

## 5. Docs & assets

- **README.md**
  - Rename "Custom Maven repositories" → **"Custom repositories & registries"**;
    document all four new ecosystems + `--add-repo <eco> …` + `--repo eco=url` +
    the auth/token + fallback + PyPI/Ruby caveat.
  - New section **"Config file & environment (`.fad-env.json` / `--config` /
    `FAD_CHECKER_ENV`)"** with the precedence table.
  - Add a **TL;DR summary** at the head of "How it scans without any build tool"
    (3-4 sentences + a one-line-per-ecosystem table), keeping the detailed
    bullets below.
- **docs/index.html** (gh-page): mirror the registries + config-file additions
  and the "how it scans" summary; refresh the screenshots.
- **docs/USAGE.md**: full flag docs for `--add-repo`/`--repo`/`--list-repos`/
  `--remove-repo`/`--config`, the `.fad-env.json` schema, `FAD_CHECKER_ENV`.
- **CLAUDE.md**: convention notes (generalized registries, config layering,
  precedence, no-backward-compat).
- **CHANGELOG.md**: new entry.
- **Assets**: regenerate `docs/assets/cli.png` (run against `test/fixtures`,
  offline, warm cache) and `report.png` (Playwright screenshot of the generated
  HTML report); refresh `docs/demo.tape`. Attempt with available tooling; if a
  renderer (VHS / terminal-to-image / headless browser) is unavailable, report
  honestly and fall back to refreshing the tape + instructions only.

## 6. Tests (node:test)

- `lib/options-env.js`: file+env+CLI precedence; `--config` overrides
  auto-discovery; malformed JSON errors; `parseEnvFlags` quote/escape
  tokenizing + only-set-options capture; registry union across layers.
- `lib/registries.js`: per-ecosystem list assembly, dedup-by-URL, auth/token →
  header, inline `user:pass@` split, public-base-last ordering.
- Per-codec registry fan-out: custom registry tried first, public fallback on
  miss, auth header sent, single-public-base behaviour unchanged when no custom
  registry.
- CLI parsing: `--add-repo <eco> <name> <url>` (incl. bad-eco error), `--repo
  eco=url` (incl. bare-URL error), `--list-repos` grouping, `--remove-repo`.
- All existing tests stay green (375 → grows).

## Out of scope

- NuGet & Composer private feeds (service-index / Satis discovery) — follow-up.
- Parsing PyPI simple-index HTML or npm "search" endpoints.
- Per-registry scopes (npm `@scope:registry` routing) — single ordered list with
  fallback is enough for the audit use case.
```
