# tools

| Tool | What it checks | Runs in CI |
|---|---|---|
| [`lightwell_osv_validate.py`](lightwell_osv_validate_README.md) | Schema, structure and Lightwell lineage (offline), plus CVE ↔ package attribution against CVE.org and osv.dev/GHSA (online) | Yes |
| [`lightwell_osv_ranges_check.py`](lightwell_osv_ranges_check_README.md) | Full-repo scan for same-CVE range overlaps across base-version branches | Yes |
| `check_ranges.py` (below) | Diff gate between two git refs | No, manual or PR review |

All three need only Python 3.9+ and the standard library.

## Continuous validation on `main`

`.github/workflows/validate-advisories.yml` runs the first two tools on `main` after
every push that touches `advisories/` (including slan-cuan's automated publish
commits), nightly at 03:17 UTC, and on demand (Actions → Validate advisories → Run
workflow). It never blocks publication.

| Job | Command | Scope |
|---|---|---|
| a. offline validation | `lightwell_osv_validate.py --offline` | All advisories |
| b. online validation | `lightwell_osv_validate.py` | Push: added or changed advisories. Nightly or manual: all |
| c. ranges check | `lightwell_osv_ranges_check.py --input-dir advisories` | All advisories |

- **A failure** (an `ERROR` finding, a `MISATTRIBUTED`/`REJECTED` CVE, or an actionable
  range overlap) opens one issue labeled `osv-validation-failure`, or comments on the
  open one. Assignees default to `syncrou,JAVGan,p-rog`; override them with the repo
  variable `VALIDATION_ISSUE_ASSIGNEES`.
- **A fully passing run** comments on the open issue and closes it.
- **Warnings** (for example `LIGHTWELL:NO_SEVERITY`) and `NEEDS_REVIEW` results,
  including network lookup failures, never open an issue.
- Each job writes its output to the run's step summary and uploads a JSON report as an
  artifact.

Run the same checks locally from the repository root:

```sh
python3 tools/lightwell_osv_validate.py --input-dir advisories --offline
python3 tools/lightwell_osv_validate.py --input-dir advisories   # online, takes a few minutes
python3 tools/lightwell_osv_ranges_check.py --input-dir advisories
```

## check_ranges.py — advisory range checker

Validates changes to `advisories/` between two git refs. It catches range mistakes
that look correct in a diff but change what OSV consumers see. Requires Python 3.9+
and git, with no other dependencies. `packaging` is used for PyPI versions if installed.

```sh
git fetch origin pull/<N>/head:pr-<N>          # or check out the branch
python3 tools/check_ranges.py --base origin/main --head pr-<N>
```

Exit status: `0` clean, `1` errors found, `2` git/usage failure. That makes it usable
as a CI gate.

### What it checks

OSV ranges are `[introduced, fixed)`: `introduced` is inclusive and `fixed` is
exclusive (OSV spec, *Evaluation*). A remediated build is affected by an advisory if
it is listed in `versions` or falls inside any of its ranges.

1. **Field diff.** Every changed advisory is compared with its version on the base
   ref. Changes outside `modified` and range `introduced` are errors. Pass
   `--allow <path>` (for example `--allow references`) when a PR is meant to touch
   other fields.
2. **Range rule.** Each multi-branch advisory's `introduced` is compared with the value
   expected by `--rule`:

   | Rule | Expected `introduced` |
   |---|---|
   | `scoped` (default) | The advisory's own `backport_base_version`. It stays at `"0"` if scoping would exclude a remediated build that does not carry all of the advisory's CVEs, or if no other build is excluded. |
   | `own-base` | The lowest branch per CVE gets `"0"`, others their `backport_base_version`. Reports `CONFLICT` when the CVEs of one advisory disagree. |
   | `tiling` | The lowest branch gets `"0"`, others the previous branch's `fixed`. |

   A range that starts exactly at a sibling advisory's `fixed` version is always an
   error, because that fixed build stays affected. It also warns when
   `backport_base_version` is not an upstream version that sorts below `fixed`.
3. **Simulated OSV query.** Every known remediated build (the `fixed` version of some
   advisory) is evaluated against every advisory on both refs:
   - **Error:** a build stops being affected by a CVE it does not carry (false negative).
   - **Error:** a fixed build becomes newly affected by a CVE it fixes (new false positive).
   - **Info:** false positives that already exist on the base ref, per package.
   - **Warning:** a later rebuild of a lower branch falls inside a higher branch's range.

Use `-v` to list every finding and `--all` to apply the rule check to unchanged
advisories too.

### Limits

- **Only known builds are evaluated.** The simulation covers remediated builds that
  appear as some advisory's `fixed` version. Builds with no advisory are invisible to it.
- **"Carries a CVE" comes from the data.** It means some advisory with that `fixed`
  build lists the CVE in `upstream`/`aliases`. Whether an upstream base is actually
  vulnerable is not checked.
- **Version ordering follows the ecosystem.** Maven versions follow Maven
  `ComparableVersion` ordering, and PyPI versions use `packaging` when available.
