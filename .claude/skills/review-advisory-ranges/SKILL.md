---
name: review-advisory-ranges
description: Use when reviewing a PR or branch that adds or modifies files under advisories/ in lightwell-osv, especially changes to affected ranges, introduced/fixed events, or advisories for a CVE remediated on more than one base-version branch.
---

# Reviewing OSV advisory range changes

## Overview

Every changed advisory is compared against **its own previous version on the base ref** and against **the previous-branch advisory** (same package + CVE, next lower `fixed`). Then an OSV-style query is simulated over every known remediated build. That simulation is the ground truth: a range edit that looks right can still leave fixed builds reported as affected.

OSV range semantics, which most range bugs come from:
- `introduced` is **inclusive** and `fixed` is **exclusive**: `[introduced, fixed)`.
- Starting a range *at* another branch's fixed version keeps that fixed build affected.
- A range is per advisory, not per CVE. An advisory listing several CVEs can need different starts for each one (CONFLICT), and a single range can't express that.

## Steps

1. Fetch the PR without checking it out:
   `git fetch origin pull/<N>/head:pr-<N>` and `gh pr view <N>`
2. Run the checker from the repo root:
   `python3 -I .claude/skills/review-advisory-ranges/check_ranges.py --base origin/main --head pr-<N>`
   Add `-v` to see every finding, `--all` to tile-check unchanged advisories too, and `--allow <path>` when the PR is meant to touch other fields (for example `references`).
3. Read the report in this order:

| Section | Signal | Meaning |
|---|---|---|
| 1 diff | `ERROR <file>: <path>` | A field outside the allowed set changed. Compare it with the PR description's claimed scope. |
| 2 tiling | `MISMATCH` | `introduced` doesn't match the previous branch's latest `fixed`. |
| 2 tiling | `CONFLICT` | The advisory's CVEs need different starts. The advisory needs splitting or a different range design. |
| 2 tiling | `start AT a sibling's fixed` | The inclusive-`introduced` bug. The fixed build is still affected. |
| 3 simulate | `base=X head=Y (resolved, new)` | The PR's real effect on false positives. If `resolved=0` and the PR claims to fix overlaps, the fix doesn't work. |
| 3 simulate | `no longer affected` | A possible false negative. Check that another advisory still covers it. |
| 3 simulate | `later rebuild ... falls in` | A rebuild of a lower branch that is fixed but falls in a higher branch's range. |

4. Check the PR's claims against section 3, not against the diff.
5. Write the review: start with the verdict, give the counts from section 3, list each CONFLICT advisory, and propose the range shape that fixes it.

## Common mistakes

- Reviewing only the diff. An edit that looks correct can change nothing; section 3 shows the effect.
- Grouping by advisory instead of by (package, CVE). Multi-CVE advisories hide conflicts.
- Trusting string order for versions. The script uses Maven ComparableVersion rules (`1.10.0` > `1.9.4`, `2.13.4.rhlw-00027` < `2.13.4.1-rhlw-00013`) and `packaging` for PyPI.
- Taking the script's "expected" value as correct. Section 2 checks consistency with the tiling rule; whether the rule is valid is decided in section 3.
