# `lightwell_osv_ranges_check.py` — Usage Guide

**Last updated:** 2026-10-27
**Script location:** `tools/lightwell_osv_ranges_check.py` in this repository

---

## What it does

Detects **same-CVE range overlaps** across Lightwell OSV advisories for a package.

When the same CVE is remediated on more than one base-version branch, each advisory
uses `introduced: 0`. A higher branch's range `[0, 6.2.2.rhlw-00004)` then spans the
lower branch's remediated build `6.0.3.rhlw-00001`, so an OSV.dev query for that build
returns the higher advisory — a false positive, even though the build carries the fix.

### The rule that matters: `introduced` is INCLUSIVE

Per the OSV spec ([ossf/osv-schema `docs/schema.md`][spec], `IncludedInRanges`):

```
if evt.introduced is present && v >= evt.introduced
   vulnerable = true
else if evt.fixed is present && v >= evt.fixed
   vulnerable = false
```

A range is `[introduced, fixed)`. A version sitting **exactly on** `introduced` **is**
reported affected. This is why "tiling" each branch to start at the previous branch's
`fixed` version does **not** work — the previous branch's remediated build lands exactly
on the new `introduced` and is still flagged. The script's self-test contains an explicit
regression guard for this.

[spec]: https://github.com/ossf/osv-schema/blob/main/docs/schema.md

### The fix it proposes

**Rule 1 — scope to the advisory's own base.** Set `introduced` to the advisory's own
`backport_base_version`. The base sorts *below* every lower branch's remediated build
(`6.0.3.rhlw-00001` < `6.2.2`), so the range covers only its own line. It is
self-contained, so adding a branch later never requires editing existing advisories.

```
Before:  [0, 5.0.3.rhlw-00001)  [0, 6.0.3.rhlw-00001)  [0, 6.2.2.rhlw-00004)
After:   [0, 5.0.3.rhlw-00001)  [6.0.3, 6.0.3.rhlw-00001)  [6.2.2, 6.2.2.rhlw-00004)
```

**Rule 2 — only where it hides nothing (safety condition).** Raise `introduced` only if
**every remediated build that drops out of the range already fixes *all* of that
advisory's CVEs**. If any excluded build is missing even one, it still needs the
advisory, and raising would create a **false negative** — so the advisory keeps
`introduced: 0`.

The check is **per build**, never against the union of lower advisories. The union can
cover a CVE when no single build does (snakeyaml CVE-2022-1471: fixed on 1.29.0, absent
from 1.30.0, fixed again on 1.33.0).

**Rule 3 — the lowest branch keeps `introduced: 0`** (it excludes nothing).

**Why not tile on the previous branch's `fixed`?** Because `introduced` is inclusive,
that build lands exactly on the boundary and stays in range. The self-test has a
regression guard for this.

### Output classification

- **ACTIONABLE** — the advisory can be scoped safely. Exit code 1; fix these.
- **Retained by safety rule** — must keep `introduced: 0`; scoping would hide a CVE.
  Reported for information, exit code 0.

Only **same-CVE** overlaps are considered. A build flagged for a *different* CVE is a
true positive and left alone.

## Modes

### 1. Single package — live OSV.dev API

```bash
python3 tools/lightwell_osv_ranges_check.py \
    --package "com.fasterxml.woodstox:woodstox-core"
```

Fetches all advisories for the package from the live OSV.dev API. Verbose output:
shows all intervals, each overlap, the proposed fix, and verification status.

Default ecosystem: `Red Hat Lightwell:Maven`. Override with `--ecosystem`:

```bash
python3 tools/lightwell_osv_ranges_check.py \
    --package tokenizers --ecosystem "Red Hat Lightwell:PyPI"
```

### 2. Single advisory file

```bash
python3 tools/lightwell_osv_ranges_check.py \
    --advisory advisories/RHLW-2026-403d1e66c95ef9bb.json
```

Reads the package from the file, then loads all sibling advisories in the same
directory to compare all branches. Useful for a quick per-file check after editing.

### 3. Full repo scan — local clone

```bash
python3 tools/lightwell_osv_ranges_check.py \
    --input-dir advisories
```

Scans every unique `(ecosystem, package)` pair found in the directory. Compact
per-package output; full stats at the top. **This is the CI mode** — exit code 1
if any same-CVE overlap is found, 0 if clean.

### 4. Single package — local clone

```bash
python3 tools/lightwell_osv_ranges_check.py \
    --package "com.fasterxml.woodstox:woodstox-core" \
    --input-dir advisories
```

Verbose single-package output, sourced from the local clone instead of the API.

### 5. Live API cross-check

```bash
python3 tools/lightwell_osv_ranges_check.py \
    --package "com.fasterxml.woodstox:woodstox-core" --live-confirm
```

After structural analysis, also queries `api.osv.dev/v1/query` at each remediated
build and shows what the API actually returns — confirms whether the live feed
matches the structural prediction.

### 6. Machine-readable output

```bash
python3 tools/lightwell_osv_ranges_check.py \
    --package "com.fasterxml.woodstox:woodstox-core" \
    --json-report report.json
```

Writes a JSON report alongside the normal output. Combines with any mode.

### 7. Self-test

```bash
python3 tools/lightwell_osv_ranges_check.py --self-test
```

Runs the built-in test suite: Maven `ComparableVersion` ordering (incl. rhlw
builds), overlap detection on the real woodstox case, proposal verification,
the spec-conformance checks (`introduced` inclusive / `fixed` exclusive), a
regression guard proving that tiling on the previous `fixed` does **not** fix the
bug, the multi-CVE self-containment check, and the different-CVE non-report guard. Useful after any script edits.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Nothing actionable (clean, or only safety-retained overlaps) |
| `1` | Actionable same-CVE overlaps detected — advisories can be scoped safely |
| `2` | Usage error or I/O failure |

---

## CI integration

Add to any PR workflow that touches `advisories/`:

```bash
python3 tools/lightwell_osv_ranges_check.py \
    --input-dir advisories
# exit 1 + ACTIONABLE listed → scope those advisories to their own base
# exit 0 + 'Retained by safety rule' → expected, do not "fix" them
# exit 0, nothing listed → clean
```

