# lightwell_osv_validate.py

Validates Lightwell OSV advisory records on two axes:

1. **Schema / structure** (offline) — the *agreed* Lightwell shape: schema 1.9.0,
   a single `Red Hat Lightwell:Maven` affected entry carrying a **versionless**
   `pkg:maven/...` purl and a full `database_specific.lightwell` lineage block
   (`backport_base_version` / `remediated_version` / `repository_url`), RFC3339
   timestamps, well-formed `upstream[]` ids, valid severity/reference/credit types,
   `fixed` range event matching `remediated_version`, and `filename == id`.
2. **CVE ↔ package correctness** (online, cached) — for **every** CVE in
   `upstream[]`, confirms the reported Maven artifact is actually one the CVE
   affects, using CVE.org (CNA + REJECTED state), OSV.dev / GHSA structured Maven
   names, and NVD text.

## Why this instead of `osv_quality_check.py`

That script has two blind spots this one fixes (both caused real misses in the
#8–#11 review):

- Its CVE↔package check **only ran on non-`Red Hat Lightwell:*` entries**, so on
  our actual feed it computed **zero** verdicts and never checked attribution.
  This one checks the `Red Hat Lightwell:Maven` entry directly.
- It resolves **each CVE to its own artifact** (via that CVE's own GHSA alias /
  CVE.org packageName), so a correct sibling CVE can't mask a mis-filed one — the
  exact netty-codec-dns-vs-resolver-dns case. It also flags **REJECTED** CVEs and,
  as a secondary net, any `upstream` GHSA whose affected package differs from the
  record's.

Its schema model also matches the committed `examples/osv/*` (the old script
errored on those); here the agreed examples pass clean.

## Usage

```bash
# a directory of advisories
python3 tools/lightwell_osv_validate.py --input-dir path/to/advisories

# schema only, no network (fast)
python3 tools/lightwell_osv_validate.py --input-dir advisories --offline

# pull a PR's changed advisories straight from GitHub (needs the `gh` CLI, authed)
python3 tools/lightwell_osv_validate.py --pr 11 --repo project-lightwell/lightwell-osv

# machine-readable output for CI / further processing
python3 tools/lightwell_osv_validate.py --input-dir advisories --json-report report.json
```

Run it under `python3 -I` if the advisories were downloaded into an untrusted
directory (isolates the interpreter from a planted `json.py` etc.).

Options: `--glob` (default `*.json`), `--cache-dir` (default
`<input>/.lightwell_osv_cache`), `--offline`, `--json-report`, `--pr` / `--repo`.

## Reading the output

Per-file status:

| Status | Meaning |
|---|---|
| `OK` | clean |
| `OK_WITH_WARNINGS` | schema warnings only (e.g. empty severity, or a bundled GHSA that points at a sibling artifact but CVE.org still backs the reported package — e.g. mime4j dom vs core) |
| `NEEDS_REVIEW` | a CVE has only product-family data public (no artifact-level coordinate yet) — confirm manually against OSIDB |
| `MISATTRIBUTED` | **action required** — a CVE is REJECTED, or ground truth says it affects a *different* artifact |
| `ERROR` | load failure or a schema ERROR |

Per-CVE verdicts shown for non-clean files: `CONFIRMED`, `CONFIRMED_TEXTUAL`,
`MISATTRIBUTED`, `REJECTED`, `NEEDS_REVIEW`, `LOOKUP_FAILED`.

**Exit code:** `0` if all files are OK / warnings / needs-review; `1` if any file
is `ERROR` or `MISATTRIBUTED` (suitable as a CI gate).

## Networking & caching

Queries `cveawg.mitre.org`, `api.osv.dev`, `services.nvd.nist.gov`. Every response
(including 404s) is cached under the cache dir, so re-runs over a batch sharing
CVEs are fast and offline-ish. Delete the cache dir to force a refresh.

## Known limitation

`NEEDS_REVIEW` CVEs are typically brand-new (e.g. 2026) advisories whose CNA only
names the product family, not the Maven artifact. The tool can't auto-confirm the
module for those — treat them as "verify against OSIDB", not as pass or fail.
