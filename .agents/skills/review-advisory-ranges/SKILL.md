---
name: review-advisory-ranges
description: Use when reviewing a PR or branch that adds or modifies files under advisories/ in lightwell-osv, especially changes to affected ranges, introduced/fixed events, versions lists, or advisories for a CVE remediated on more than one base-version branch.
---

# Reviewing OSV advisory range changes

The checker is a plain script; see `tools/README.md` for what it checks and its limits.

## Steps

1. Fetch the PR without checking it out: `git fetch origin pull/<N>/head:pr-<N>`. Read the description (`gh pr view <N>`) and note which range rule it claims to implement.
2. Run the checker from the repo root: `python3 tools/check_ranges.py --base origin/main --head pr-<N>`. Pass `--rule` if the PR implements a rule other than `scoped`. Pass `--allow <path>` for fields the PR is meant to change.
3. Check the PR's claims against section 3 (the simulated OSV query), not against the diff. Report `resolved` and `new` false positives and any false negatives.
4. Confirm surprising results independently before reporting them. Query `https://api.osv.dev/v1/query` for already-ingested records, or re-derive the result with a second implementation.
5. Write the review: start with the verdict, give the counts from section 3, list each error, and separate pre-existing issues from ones the PR introduces.

## Common mistakes

- Reviewing only the diff. An edit that looks correct can change nothing; section 3 shows the effect.
- Forgetting that `introduced` is inclusive. A range starting at a sibling's `fixed` still covers that build.
- Ignoring `affected[].versions`. An entry there is affected regardless of ranges.
- Grouping by advisory instead of by (package, CVE). One range per advisory cannot be right for every CVE in a multi-CVE advisory.
- Treating a drop in false positives as success without checking false negatives. A hidden CVE is worse than a repeated one.
- Taking the rule check (section 2) as proof of correctness. It checks consistency with a rule; section 3 decides whether the rule works.
