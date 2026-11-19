#!/usr/bin/env python3
"""Detect overlapping affected-version ranges across Lightwell OSV advisories for a
package, and propose non-overlapping ranges so OSV.dev queries don't report an
already-remediated build as still affected (the multi-branch backport problem).

Background
----------
Lightwell publishes one advisory per remediated base-version branch. Each advisory's
range is `introduced: 0 .. fixed: <base>.rhlw-NNNNN`. When the SAME CVE is remediated
on more than one base branch, those `[0, fixed)` ranges OVERLAP: a higher branch's
range (e.g. `[0, 6.2.2.rhlw-00004)`) contains a lower branch's remediated build
(`6.0.3.rhlw-00001`), so an OSV.dev query for that build returns the higher advisory
— a false positive, even though the build already carries the fix.

What this script does
---------------------
1. Collects every advisory for one package (live OSV.dev API, or a local clone).
2. For each CVE, groups all advisories that mention it and checks whether any
   remediated build in a lower branch falls inside a higher branch's range
   (same-CVE overlap = misleading false positive).
3. If overlaps exist, proposes corrected, non-overlapping ranges using a tiling
   strategy: the lowest branch keeps `introduced: 0` (unchanged); each higher branch
   gets `introduced` set to the previous branch's `fixed` version, so the ranges
   tile cleanly — e.g.
     [0,                   5.0.3.rhlw-00001)   lowest branch — unchanged
     [5.0.3.rhlw-00001,   6.0.3.rhlw-00001)
     [6.0.3.rhlw-00001,   6.2.2.rhlw-00004)
4. Re-simulates the proposed ranges and verifies no remediated build is flagged.

Usage
-----
    # scan a specific package (live OSV.dev API)
    python3 lightwell_osv_ranges_check.py \
        --package "com.fasterxml.woodstox:woodstox-core"

    # scan a different ecosystem
    python3 lightwell_osv_ranges_check.py \
        --package tokenizers --ecosystem "Red Hat Lightwell:PyPI"

    # scan a single advisory file
    python3 lightwell_osv_ranges_check.py \
        --advisory advisories/RHLW-2026-403d1e66c95ef9bb.json

    # scan the entire local repo (all packages, all advisories)
    python3 lightwell_osv_ranges_check.py \
        --input-dir path/to/advisories

    # scan a specific package from a local clone
    python3 lightwell_osv_ranges_check.py \
        --package "com.fasterxml.woodstox:woodstox-core" \
        --input-dir path/to/advisories

    # cross-check structural result against live OSV.dev responses
    python3 lightwell_osv_ranges_check.py \
        --package "com.fasterxml.woodstox:woodstox-core" --live-confirm

    # machine-readable output
    python3 lightwell_osv_ranges_check.py --package ... --json-report out.json

    # verify the version comparator / detection logic
    python3 lightwell_osv_ranges_check.py --self-test

Exit code: 0 if no overlaps, 1 if any are found (CI-friendly), 2 on usage error.
Stdlib only (PyPI ordering uses `packaging` if importable, else a PEP 440 fallback).
"""

import argparse
import functools
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

OSV_API = "https://api.osv.dev/v1"
USER_AGENT = "lightwell-osv-ranges-check/1.0 (+https://github.com/project-lightwell/lightwell-osv)"
REQUEST_TIMEOUT = 25
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
GHSA_RE = re.compile(r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$", re.I)


# --------------------------------------------------------------------------- #
# Maven ComparableVersion (faithful port of
# org.apache.maven.artifact.versioning.ComparableVersion)
# --------------------------------------------------------------------------- #
_QUALIFIERS = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"]
_RELEASE_INDEX = str(_QUALIFIERS.index(""))          # "5"
_ALIASES = {"ga": "", "final": "", "release": "", "cr": "rc"}


def _comparable_qualifier(q):
    q = _ALIASES.get(q, q)
    if q in _QUALIFIERS:
        return str(_QUALIFIERS.index(q))
    return f"{len(_QUALIFIERS)}-{q}"                  # "7-<q>"  -> sorts after release


class _IntItem:
    __slots__ = ("v",)

    def __init__(self, v):
        self.v = int(v)

    def is_null(self):
        return self.v == 0

    def cmp(self, other):
        if other is None:
            return 0 if self.v == 0 else 1
        if isinstance(other, _IntItem):
            return (self.v > other.v) - (self.v < other.v)
        return 1                                      # int > string, int > list


class _StringItem:
    __slots__ = ("v",)

    def __init__(self, v, followed_by_digit=False):
        if followed_by_digit and len(v) == 1:
            v = {"a": "alpha", "b": "beta", "m": "milestone"}.get(v, v)
        self.v = _ALIASES.get(v, v)

    def is_null(self):
        return _comparable_qualifier(self.v) == _RELEASE_INDEX

    def cmp(self, other):
        if other is None:
            a = _comparable_qualifier(self.v)
            return (a > _RELEASE_INDEX) - (a < _RELEASE_INDEX)
        if isinstance(other, _IntItem):
            return -1
        if isinstance(other, _StringItem):
            a, b = _comparable_qualifier(self.v), _comparable_qualifier(other.v)
            return (a > b) - (a < b)
        return -1                                     # string < list


class _ListItem:
    __slots__ = ("items",)

    def __init__(self):
        self.items = []

    def add(self, it):
        self.items.append(it)

    def is_null(self):
        return len(self.items) == 0

    def normalize(self):
        i = len(self.items)
        while i > 0 and self.items[i - 1].is_null():
            i -= 1
        del self.items[i:]

    def cmp(self, other):
        if other is None:
            return 0 if not self.items else self.items[0].cmp(None)
        if isinstance(other, _IntItem):
            return -1
        if isinstance(other, _StringItem):
            return 1
        a, b = self.items, other.items
        for i in range(max(len(a), len(b))):
            l = a[i] if i < len(a) else None
            r = b[i] if i < len(b) else None
            if l is None:
                c = 0 if r is None else -1 * r.cmp(None)
            else:
                c = l.cmp(r)
            if c != 0:
                return c
        return 0


def _parse_maven(version):
    version = version.lower()
    root = _ListItem()
    stack = [root]
    cur = root
    is_digit = False
    start = 0

    def parse_item(isdig, buf):
        if isdig:
            return _IntItem(buf.lstrip("0") or "0")
        return _StringItem(buf)

    n = len(version)
    for i in range(n):
        c = version[i]
        if c == ".":
            cur.add(_IntItem(0) if i == start else parse_item(is_digit, version[start:i]))
            start = i + 1
        elif c == "-":
            cur.add(_IntItem(0) if i == start else parse_item(is_digit, version[start:i]))
            start = i + 1
            new = _ListItem()
            cur.add(new)
            cur = new
            stack.append(new)
        elif c.isdigit():
            if not is_digit and i > start:
                cur.add(_StringItem(version[start:i], followed_by_digit=True))
                start = i
                new = _ListItem()
                cur.add(new)
                cur = new
                stack.append(new)
            is_digit = True
        else:
            if is_digit and i > start:
                cur.add(parse_item(True, version[start:i]))
                start = i
                new = _ListItem()
                cur.add(new)
                cur = new
                stack.append(new)
            is_digit = False
    if n > start:
        cur.add(parse_item(is_digit, version[start:]))
    for lst in reversed(stack):
        lst.normalize()
    return root


def maven_cmp(a, b):
    return _parse_maven(a).cmp(_parse_maven(b))


# --------------------------------------------------------------------------- #
# PyPI (PEP 440) comparator — prefer `packaging`, fall back to a safe subset
# --------------------------------------------------------------------------- #
try:
    from packaging.version import Version as _PepVersion  # type: ignore

    def pypi_cmp(a, b):
        va, vb = _PepVersion(a), _PepVersion(b)
        return (va > vb) - (va < vb)

    _PYPI_BACKEND = "packaging"
except Exception:  # pragma: no cover - environment dependent
    def _pep440_key(v):
        # Minimal, good enough for release + local forms (X.Y.Z, X.Y.Z+rhlw.N).
        v = v.strip().lower()
        local = ""
        if "+" in v:
            v, local = v.split("+", 1)
        rel = tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", v) if x != "")
        # local version sorts AFTER the same release (PEP 440); compare segments
        loc = tuple((1, int(s)) if s.isdigit() else (0, s)
                    for s in re.split(r"[.\-_]", local) if s != "")
        return (rel, loc)

    def pypi_cmp(a, b):
        ka, kb = _pep440_key(a), _pep440_key(b)
        return (ka > kb) - (ka < kb)

    _PYPI_BACKEND = "fallback (no 'packaging' module)"


def version_cmp(ecosystem, a, b):
    base = ecosystem.split(":", 1)[0]
    suffix = ecosystem.split(":", 1)[1] if ":" in ecosystem else ""
    fam = suffix or base
    if fam == "PyPI":
        return pypi_cmp(a, b)
    return maven_cmp(a, b)                            # Maven + sensible default


def in_range(ecosystem, version, introduced, fixed):
    """OSV ECOSYSTEM semantics for one introduced/fixed window.

    Transcribed from ossf/osv-schema docs/schema.md (IncludedInRanges):

        if evt.introduced is present && v >= evt.introduced
           vulnerable = true
        else if evt.fixed is present && v >= evt.fixed
           vulnerable = false

    `introduced` is INCLUSIVE. Do NOT add an "exclusive introduced" variant:
    a version sitting exactly on `introduced` IS reported affected by osv.dev,
    which is precisely the boundary case this checker exists to catch.
    """
    ge_intro = introduced in ("0", None) or version_cmp(ecosystem, version, introduced) >= 0
    lt_fixed = fixed is None or version_cmp(ecosystem, version, fixed) < 0
    return ge_intro and lt_fixed


# --------------------------------------------------------------------------- #
# advisory collection
# --------------------------------------------------------------------------- #
def _http_post(url, body):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/json",
                 "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as r:
        return json.loads(r.read().decode())


def fetch_from_api(name, ecosystem):
    out, token = [], None
    while True:
        body = {"package": {"name": name, "ecosystem": ecosystem}}
        if token:
            body["page_token"] = token
        data = _http_post(f"{OSV_API}/query", body)
        out.extend(data.get("vulns", []))
        token = data.get("next_page_token")
        if not token:
            break
    return out


def load_from_dir(input_dir, name, ecosystem):
    out = []
    for p in sorted(Path(input_dir).glob("*.json")):
        try:
            rec = json.loads(p.read_text("utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for a in rec.get("affected", []):
            pkg = a.get("package", {})
            if pkg.get("name") == name and pkg.get("ecosystem") == ecosystem:
                out.append(rec)
                break
    return out


# --------------------------------------------------------------------------- #
# interval extraction + overlap detection
# --------------------------------------------------------------------------- #
class Interval:
    def __init__(self, record_id, ecosystem, name, introduced, fixed, base, remediated, cves):
        self.record_id = record_id
        self.ecosystem = ecosystem
        self.name = name
        self.introduced = introduced
        self.fixed = fixed
        self.base = base
        self.remediated = remediated
        self.cves = cves                             # set of CVE/GHSA ids

    def __repr__(self):
        return (f"{self.record_id}[{self.introduced}..{self.fixed}) base={self.base}")


def extract_intervals(records, name, ecosystem):
    intervals = []
    for rec in records:
        cves = {u for u in rec.get("upstream", []) if CVE_RE.match(u) or GHSA_RE.match(u)}
        for a in rec.get("affected", []):
            pkg = a.get("package", {})
            if pkg.get("name") != name or pkg.get("ecosystem") != ecosystem:
                continue
            lw = a.get("database_specific", {}).get("lightwell", {})
            base = lw.get("backport_base_version")
            remediated = lw.get("remediated_version")
            for rng in a.get("ranges", []):
                if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                    continue
                introduced, fixed = None, None
                for e in rng.get("events", []):
                    if "introduced" in e:
                        introduced = e["introduced"]
                    if "fixed" in e:
                        fixed = e["fixed"]
                if fixed is None:
                    continue
                intervals.append(Interval(rec.get("id", "?"), ecosystem, name,
                                          introduced or "0", fixed, base,
                                          remediated or fixed, cves))
    return intervals


def detect_overlaps(intervals):
    """Return a list of misleading overlaps: cases where two advisories share a CVE
    and a lower branch's remediated build falls inside a higher branch's range.
    Only same-CVE overlaps are reported — different-CVE ranges on the same package
    are intentional and not a problem."""
    misleading = []
    for a in intervals:
        build = a.remediated or a.fixed
        for b in intervals:
            if a is b or a.record_id == b.record_id:
                continue
            shared = sorted(a.cves & b.cves)
            if not shared:
                continue                              # different CVE — not our problem
            # Use strict-intro comparison: a build that exactly equals another
            # advisory's introduced boundary is the fixed build of a lower branch —
            # it should not be flagged as affected by the next window.
            if in_range(b.ecosystem, build, b.introduced, b.fixed):
                misleading.append({
                    "build": build,
                    "victim_record": a.record_id,
                    "victim_base": a.base,
                    "flagged_by": b.record_id,
                    "flagger_range": f"[{b.introduced}, {b.fixed})",
                    "flagger_base": b.base,
                    "shared_cves": shared,
                })
    return misleading


def propose_fix(intervals, misleading):
    """Propose `introduced` = the advisory's own backport_base_version, but only
    where that hides nothing. See docs/range-model.md in lightwell-osv.

    Rule 1 — scope to own base. `introduced: <own base>` works because the base sorts
    BELOW every lower branch's remediated build (6.0.3.rhlw-00001 < 6.2.2), and it is
    self-contained (no coupling to neighbouring advisories).

    Rule 2 — only when it hides nothing. Raise only if EVERY remediated build that
    drops out of the range already fixes ALL of this advisory's CVEs. If any excluded
    build is missing even one, that build still needs this advisory and raising would
    create a FALSE NEGATIVE, so the advisory keeps `introduced: 0`.

    The check is PER BUILD, not against the union of lower advisories: the union can
    cover a CVE when no single build does (snakeyaml CVE-2022-1471 — fixed on 1.29.0,
    absent from 1.30.0, fixed again on 1.33.0).

    Rule 3 — the lowest branch keeps `introduced: 0`; it excludes nothing.

    Note: tiling on the previous branch's `fixed` does NOT work, because `introduced`
    is inclusive — that build lands exactly on the boundary and stays in range.
    """
    proposals, proposed, blocked = [], [], []
    for iv in intervals:
        new_intro = iv.introduced
        if iv.base:
            trial = Interval(iv.record_id, iv.ecosystem, iv.name, iv.base, iv.fixed,
                             iv.base, iv.remediated, iv.cves)
            excluded = [o for o in intervals
                        if o.record_id != iv.record_id and (o.remediated or o.fixed)
                        and in_range(iv.ecosystem, o.remediated or o.fixed,
                                     iv.introduced, iv.fixed)
                        and not in_range(iv.ecosystem, o.remediated or o.fixed,
                                         trial.introduced, trial.fixed)]
            unsafe = [o for o in excluded if not (iv.cves <= o.cves)]
            if excluded and not unsafe:
                new_intro = iv.base
            elif unsafe:
                blocked.append({
                    "record": iv.record_id,
                    "reason": "keeping introduced:0 — raising would hide a CVE",
                    "builds": [{"build": o.remediated or o.fixed,
                                "missing": sorted(iv.cves - o.cves)} for o in unsafe],
                })
        proposed.append(Interval(iv.record_id, iv.ecosystem, iv.name, new_intro,
                                 iv.fixed, iv.base, iv.remediated, iv.cves))
        if new_intro != iv.introduced:
            proposals.append({
                "record": iv.record_id, "base": iv.base,
                "old_range": f"[{iv.introduced}, {iv.fixed})",
                "new_range": f"[{new_intro}, {iv.fixed})",
            })
    residual = detect_overlaps(proposed)
    for p in proposals:
        p["blocked"] = []
    if blocked and proposals:
        proposals[0].setdefault("_blocked_note", len(blocked))
    propose_fix.last_blocked = blocked
    return proposals, proposed, residual


def find_false_negatives(before, after):
    """(build, CVE) pairs reported by `before` ranges but not by `after` ranges,
    where the build genuinely does NOT fix that CVE. Must always be empty."""
    def reported(ivs):
        out = set()
        for a in ivs:
            build = a.remediated or a.fixed
            for b in ivs:
                if a.record_id == b.record_id or not build:
                    continue
                if in_range(b.ecosystem, build, b.introduced, b.fixed):
                    for c in b.cves - a.cves:
                        out.add((a.name, build, c))
        return out
    return reported(before) - reported(after)


def live_confirm(name, ecosystem, intervals):
    """Query OSV.dev at each remediated build; report advisories that still flag it."""
    results = []
    for iv in intervals:
        build = iv.remediated or iv.fixed
        try:
            data = _http_post(f"{OSV_API}/query",
                              {"package": {"name": name, "ecosystem": ecosystem}, "version": build})
        except urllib.error.URLError as e:
            results.append({"build": build, "error": str(e)})
            continue
        ids = [v["id"] for v in data.get("vulns", [])]
        results.append({"build": build, "returned": ids})
    return results


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #
def report(name, ecosystem, intervals, misleading, proposals, residual, confirm):
    print(f"\n{'=' * 74}")
    print(f"Lightwell OSV range check — {name}  ({ecosystem})")
    print(f"{'=' * 74}")
    print(f"advisories/ranges found: {len(intervals)}")
    for iv in sorted(intervals, key=lambda x: _sort_key(x.ecosystem, x.fixed)):
        print(f"  {iv.record_id}  [{iv.introduced}, {iv.fixed})  base={iv.base}  "
              f"CVEs={sorted(c for c in iv.cves if c.startswith('CVE')) or '-'}")

    if confirm is not None:
        print("\nLive OSV.dev confirmation (query at each remediated build):")
        for r in confirm:
            if "error" in r:
                print(f"  {r['build']}: ERROR {r['error']}")
            else:
                others = r["returned"]
                flag = "  <-- flagged (same-CVE overlap)" if others else "  (empty = clean)"
                print(f"  {r['build']}: {others or 'EMPTY'}{flag}")

    if not misleading:
        print("\n✅ No same-CVE range overlaps detected — queries will not mislead for this package.")
        return

    print(f"\n🔴 Same-CVE overlaps (false positives — shared CVE already fixed in the build): "
          f"{len(misleading)}")
    for m in misleading:
        print(f"  build {m['build']} (fixed by {m['victim_record']}) is reported AFFECTED by "
              f"{m['flagged_by']} {m['flagger_range']} for {m['shared_cves']}")

    print("\nProposed ranges (introduced := advisory's own backport_base_version, "
          "only where it hides no CVE), sorted ascending:")
    if not proposals:
        print("  (no changes needed — lowest branch already starts at 0 and higher branches "
              "already start at the previous fixed version)")
    for p in sorted(proposals, key=lambda x: _sort_key(ecosystem, x["new_range"])):
        print(f"  {p['record']}  base={p['base']}:  {p['old_range']}  ->  {p['new_range']}")
    if residual:
        print(f"\n⚠️  Proposal still leaves {len(residual)} misleading overlap(s) — "
              "manual review needed (non-standard version layout).")
    else:
        print("\n✅ Verification: proposal removes the same-CVE false positives.")
    blocked = getattr(propose_fix, "last_blocked", [])
    if blocked:
        print(f"\nKept at introduced:0 — raising would hide a CVE ({len(blocked)}):")
        for b in blocked[:10]:
            ex = b["builds"][0]
            print(f"  {b['record']}: {ex['build']} still missing {ex['missing'][:4]}")
        if len(blocked) > 10:
            print(f"  ... and {len(blocked)-10} more")


def _sort_key(ecosystem, version_or_range):
    # extract a version for sorting from either a bare version or a "[i, f)" string
    m = re.search(r"\[.*?,\s*([^)]+)\)", version_or_range)
    v = m.group(1).strip() if m else version_or_range
    return functools.cmp_to_key(lambda a, b: version_cmp(ecosystem, a, b))(v)


# --------------------------------------------------------------------------- #
# self-test
# --------------------------------------------------------------------------- #
def self_test():
    ok = True

    def check(cond, msg):
        nonlocal ok
        print(f"  {'PASS' if cond else 'FAIL'}  {msg}")
        ok = ok and cond

    print("Maven comparator — canonical orderings:")
    check(maven_cmp("1", "1.0") == 0, "1 == 1.0")
    check(maven_cmp("1.0", "1.0.0") == 0, "1.0 == 1.0.0")
    check(maven_cmp("1.0", "1.1") < 0, "1.0 < 1.1")
    check(maven_cmp("1.0-alpha-1", "1.0") < 0, "1.0-alpha-1 < 1.0")
    check(maven_cmp("1.0-rc1", "1.0") < 0, "1.0-rc1 < 1.0")
    check(maven_cmp("1.0-sp", "1.0") > 0, "1.0-sp > 1.0")
    check(maven_cmp("1.0.1", "1.0") > 0, "1.0.1 > 1.0")
    check(maven_cmp("1.0-ga", "1.0") == 0, "1.0-ga == 1.0")

    print("Maven comparator — Lightwell rhlw builds (must match OSV.dev ordering):")
    check(maven_cmp("5.0.3.rhlw-00001", "6.0.3") < 0, "5.0.3.rhlw-00001 < 6.0.3")
    check(maven_cmp("6.0.3", "6.0.3.rhlw-00001") < 0, "6.0.3 < 6.0.3.rhlw-00001")
    check(maven_cmp("6.0.3.rhlw-00001", "6.2.2") < 0, "6.0.3.rhlw-00001 < 6.2.2")
    check(maven_cmp("6.2.2", "6.2.2.rhlw-00004") < 0, "6.2.2 < 6.2.2.rhlw-00004")

    print("Spec conformance — introduced is INCLUSIVE (ossf/osv-schema IncludedInRanges):")
    eco = "Red Hat Lightwell:Maven"
    check(in_range(eco, "6.0.3.rhlw-00001", "6.0.3.rhlw-00001", "6.2.2.rhlw-00004") is True,
          "version sitting exactly on 'introduced' IS in range (inclusive)")
    check(in_range(eco, "6.2.2.rhlw-00004", "6.2.2", "6.2.2.rhlw-00004") is False,
          "version sitting exactly on 'fixed' is NOT in range (exclusive)")

    print("Overlap detection — the real woodstox case (introduced:0 model):")
    name = "com.fasterxml.woodstox:woodstox-core"
    cve = {"CVE-2022-40152"}
    ivs = [
        Interval("A-5.0.3", eco, name, "0", "5.0.3.rhlw-00001", "5.0.3", "5.0.3.rhlw-00001", cve),
        Interval("B-6.0.3", eco, name, "0", "6.0.3.rhlw-00001", "6.0.3", "6.0.3.rhlw-00001", cve),
        Interval("C-6.2.2", eco, name, "0", "6.2.2.rhlw-00004", "6.2.2", "6.2.2.rhlw-00004", cve),
    ]
    mis = detect_overlaps(ivs)
    check(any(m["build"] == "6.0.3.rhlw-00001" and m["flagged_by"] == "C-6.2.2" for m in mis),
          "6.0.3.rhlw-00001 flagged by the 6.2.2 advisory (the reported production bug)")

    print("Tiling on previous 'fixed' does NOT fix it (the regression we shipped once):")
    tiled = [
        Interval("A-5.0.3", eco, name, "0", "5.0.3.rhlw-00001", "5.0.3", "5.0.3.rhlw-00001", cve),
        Interval("B-6.0.3", eco, name, "5.0.3.rhlw-00001", "6.0.3.rhlw-00001", "6.0.3",
                 "6.0.3.rhlw-00001", cve),
        Interval("C-6.2.2", eco, name, "6.0.3.rhlw-00001", "6.2.2.rhlw-00004", "6.2.2",
                 "6.2.2.rhlw-00004", cve),
    ]
    check(len(detect_overlaps(tiled)) > 0,
          "tiled ranges still report fixed builds as affected (guards the old mistake)")

    print("Proposal — introduced := own base, only where it hides nothing:")
    props, prop_ivs, residual = propose_fix(ivs, mis)
    check(len(residual) == 0, "no same-CVE overlap remains after proposal")
    check(len(find_false_negatives(ivs, prop_ivs)) == 0, "proposal introduces no false negative")
    a_iv = next(iv for iv in prop_ivs if iv.record_id == "A-5.0.3")
    c_iv = next(iv for iv in prop_ivs if iv.record_id == "C-6.2.2")
    check(a_iv.introduced == "0", "lowest branch untouched (keeps introduced=0)")
    check(c_iv.introduced == "6.2.2", "6.2.2 advisory starts at its own base 6.2.2")

    print("Safety rule — real snakeyaml CVE-2022-1471 case (fixed, absent, fixed again):")
    sy = [
        Interval("c782a5bb", eco, "org.yaml:snakeyaml", "0", "1.29.0.rhlw-00021",
                 "1.29.0", "1.29.0.rhlw-00021", {"CVE-2022-1471", "CVE-2022-41854"}),
        Interval("c7695b3b", eco, "org.yaml:snakeyaml", "0", "1.30.0.rhlw-00013",
                 "1.30.0", "1.30.0.rhlw-00013", {"CVE-2022-41854"}),
        Interval("db6cfa79", eco, "org.yaml:snakeyaml", "0", "1.33.0.rhlw-00001",
                 "1.33.0", "1.33.0.rhlw-00001", {"CVE-2022-1471"}),
    ]
    sp, sy_ivs, _ = propose_fix(sy, detect_overlaps(sy))
    db = next(i for i in sy_ivs if i.record_id == "db6cfa79")
    c7 = next(i for i in sy_ivs if i.record_id == "c7695b3b")
    check(db.introduced == "0",
          "db6cfa79 keeps introduced=0 (1.30.0.rhlw-00013 still needs CVE-2022-1471)")
    check(c7.introduced == "1.30.0",
          "c7695b3b raised to 1.30.0 (its only excluded build fixes all its CVEs)")
    check(len(find_false_negatives(sy, sy_ivs)) == 0, "snakeyaml case: zero false negatives")

    print("Multi-CVE advisory — safety rule keeps it at 0 rather than hiding a CVE:")
    mc = [
        Interval("L-1.2.11", eco, "t:mc", "0", "1.2.11.rhlw-00001", "1.2.11",
                 "1.2.11.rhlw-00001", {"CVE-A"}),
        Interval("M-1.2.12", eco, "t:mc", "0", "1.2.12.rhlw-00001", "1.2.12",
                 "1.2.12.rhlw-00001", {"CVE-A", "CVE-B"}),
        Interval("N-1.5.0", eco, "t:mc", "0", "1.5.0.rhlw-00001", "1.5.0",
                 "1.5.0.rhlw-00001", {"CVE-B"}),
    ]
    _, mc_ivs, _ = propose_fix(mc, detect_overlaps(mc))
    m_iv = next(i for i in mc_ivs if i.record_id == "M-1.2.12")
    n_iv = next(i for i in mc_ivs if i.record_id == "N-1.5.0")
    check(m_iv.introduced == "0",
          "M keeps 0 (L-1.2.11 is missing CVE-B, so M still applies to it)")
    check(n_iv.introduced == "0",
          "N keeps 0 (L-1.2.11 is missing CVE-B, so N still applies to it)")
    check(len(find_false_negatives(mc, mc_ivs)) == 0,
          "multi-CVE case: zero false negatives (correctness over tidiness)")

    print("Different-CVE ranges on same package — NOT reported (not our problem):")
    ivs2 = [
        Interval("X-6.0.3", eco, name, "0", "6.0.3.rhlw-00001", "6.0.3", "6.0.3.rhlw-00001",
                 {"CVE-1111-1"}),
        Interval("Y-6.2.2", eco, name, "0", "6.2.2.rhlw-00004", "6.2.2", "6.2.2.rhlw-00004",
                 {"CVE-2222-2"}),
    ]
    check(len(detect_overlaps(ivs2)) == 0,
          "distinct-CVE overlap not reported (different CVEs, intentional)")

    print(f"\n{'ALL PASS' if ok else 'SOME FAILED'}  (PyPI backend: {_PYPI_BACKEND})")
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
def _check_one_package(name, ecosystem, records, live_confirm_flag):
    """Run detection + proposal for a single (name, ecosystem) pair. Returns the
    result dict used for JSON reporting and the exit-code contribution."""
    intervals = extract_intervals(records, name, ecosystem)
    if not intervals:
        return None, 0
    misleading = detect_overlaps(intervals)
    proposals, _, residual = propose_fix(intervals, misleading) if misleading else ([], [], [])
    confirm = live_confirm(name, ecosystem, intervals) if live_confirm_flag else None
    report(name, ecosystem, intervals, misleading, proposals, residual, confirm)
    result = {
        "package": name, "ecosystem": ecosystem,
        "intervals": [{"record": i.record_id, "introduced": i.introduced, "fixed": i.fixed,
                        "base": i.base, "remediated": i.remediated,
                        "cves": sorted(i.cves)} for i in intervals],
        "misleading": misleading,
        "proposals": proposals, "residual_after_proposal": residual,
        "live_confirm": confirm,
    }
    return result, (1 if misleading else 0)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--package",
                     help="check a specific package, e.g. 'com.fasterxml.woodstox:woodstox-core'")
    grp.add_argument("--advisory", metavar="FILE",
                     help="check a single advisory JSON file (and all same-package advisories "
                          "in the same directory)")
    ap.add_argument("--ecosystem", default="Red Hat Lightwell:Maven",
                    help="ecosystem for --package (ignored when --advisory or full-repo scan)")
    ap.add_argument("--input-dir",
                    help="directory of advisory *.json; if --package is omitted, scans every "
                         "package in the directory (full-repo mode)")
    ap.add_argument("--live-confirm", action="store_true",
                    help="cross-check by querying OSV.dev at each remediated build")
    ap.add_argument("--json-report", help="write machine-readable JSON here")
    ap.add_argument("--self-test", action="store_true", help="run comparator/detection self-tests")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    # ------------------------------------------------------------------ #
    # resolve input source and determine which packages to check
    # ------------------------------------------------------------------ #
    if args.advisory:
        # Single-file mode: resolve the package from the file itself, then load
        # its sibling directory so we can compare all branches.
        advisory_path = Path(args.advisory)
        if not advisory_path.exists():
            print(f"error: {args.advisory} not found", file=sys.stderr)
            return 2
        try:
            seed = json.loads(advisory_path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            print(f"error reading {args.advisory}: {e}", file=sys.stderr)
            return 2
        # Extract the package(s) from this advisory.
        pairs = set()
        for a in seed.get("affected", []):
            pkg = a.get("package", {})
            if pkg.get("ecosystem") and pkg.get("name"):
                pairs.add((pkg["ecosystem"], pkg["name"]))
        if not pairs:
            print("error: advisory has no affected[].package entries", file=sys.stderr)
            return 2
        # Load the whole sibling directory (or just the single file if no dir).
        input_dir = advisory_path.parent
        records = [json.loads(p.read_text())
                   for p in sorted(input_dir.glob("*.json"))
                   if p.suffix == ".json"]
        src = f"advisory {advisory_path.name} + siblings in {input_dir}"

    elif args.input_dir:
        input_dir = Path(args.input_dir)
        if not input_dir.is_dir():
            print(f"error: {input_dir} is not a directory", file=sys.stderr)
            return 2
        try:
            records = [json.loads(p.read_text()) for p in sorted(input_dir.glob("*.json"))]
        except (json.JSONDecodeError, OSError) as e:
            print(f"error reading from {input_dir}: {e}", file=sys.stderr)
            return 2
        if args.package:
            pairs = {(args.ecosystem, args.package)}
        else:
            # Full-repo mode: every unique (ecosystem, package) in the directory.
            pairs = set()
            for rec in records:
                for a in rec.get("affected", []):
                    pkg = a.get("package", {})
                    if pkg.get("ecosystem") and pkg.get("name"):
                        pairs.add((pkg["ecosystem"], pkg["name"]))
        src = f"local clone {input_dir}"

    elif args.package:
        # Live API, single package.
        try:
            records = fetch_from_api(args.package, args.ecosystem)
        except urllib.error.URLError as e:
            print(f"error: could not reach OSV.dev: {e}", file=sys.stderr)
            return 2
        pairs = {(args.ecosystem, args.package)}
        src = "OSV.dev API"

    else:
        ap.error("one of --package, --advisory, or --input-dir is required (or --self-test)")

    print(f"source: {src}")

    # ------------------------------------------------------------------ #
    # run the check for every (ecosystem, name) pair
    # ------------------------------------------------------------------ #
    all_results = []
    exit_code = 0

    if len(pairs) > 1:
        # Multi-package mode: compact per-package output.
        clean, actionable, retained = 0, [], []
        for eco, name in sorted(pairs):
            ivs = extract_intervals(records, name, eco)
            if len(ivs) < 2:
                clean += 1
                continue
            mis = detect_overlaps(ivs)
            if not mis:
                clean += 1
                continue
            props, prop_ivs, residual = propose_fix(ivs, mis)
            fns = find_false_negatives(ivs, prop_ivs)
            if props:
                exit_code = 1
                actionable.append((eco, name, ivs, mis, props, residual, fns))
            else:
                retained.append((eco, name, ivs, mis))

        print(f"\n{'=' * 74}")
        print(f"Full-repo scan — {len(records)} advisories, {len(pairs)} packages")
        print(f"{'=' * 74}")
        print(f"  Clean (no same-CVE overlap):              {clean}")
        print(f"  ACTIONABLE (can be scoped safely):        {len(actionable)}")
        print(f"  Retained by safety rule (must stay at 0): {len(retained)}")
        print()

        for eco, name, ivs, mis, props, residual, fns in actionable:
            print(f"🔴  {name}  ({eco})")
            for iv in sorted(ivs, key=lambda x: _sort_key(x.ecosystem, x.fixed)):
                cves = sorted(c for c in iv.cves if c.startswith("CVE"))
                print(f"    {iv.record_id}  [{iv.introduced}, {iv.fixed})  CVEs={cves}")
            for m in mis:
                print(f"    ↳ build {m['build']} flagged by {m['flagged_by']} "
                      f"for {m['shared_cves']}")
            for pr in sorted(props, key=lambda x: _sort_key(eco, x["new_range"])):
                print(f"    fix  {pr['record']}:  {pr['old_range']}  ->  {pr['new_range']}")
            if fns:
                print(f"    ❌ proposal would introduce {len(fns)} false negative(s) — DO NOT APPLY")
            else:
                print(f"    ✅ verified: no false negative introduced")
            print()

        if retained:
            print("ℹ️  Retained at introduced:0 by the safety rule — scoping these would hide")
            print("   a CVE from a build that still needs the advisory (expected, not a defect):")
            for eco, name, ivs, mis in retained:
                print(f"   {name}  ({len(mis)} repeat-hit(s))")
            print()

        if not actionable and not retained:
            print("✅ No same-CVE overlaps across the entire repository.")
        elif not actionable:
            print("✅ Nothing actionable — all remaining overlaps are safety-retained.")

        for eco, name, ivs, mis, props, residual, _fns in actionable:
            all_results.append({
                "package": name, "ecosystem": eco, "kind": "fixable",
                "intervals": [{"record": i.record_id, "introduced": i.introduced,
                                "fixed": i.fixed, "base": i.base,
                                "remediated": i.remediated, "cves": sorted(i.cves)}
                               for i in ivs],
                "misleading": mis, "proposals": props,
                "residual_after_proposal": residual,
            })
    else:
        # Single-package mode: full verbose output.
        eco, name = next(iter(pairs))
        result, pkg_exit = _check_one_package(name, eco, records, args.live_confirm)
        if result:
            all_results.append(result)
        exit_code = pkg_exit

    if args.json_report:
        payload = all_results if len(all_results) != 1 else all_results[0]
        Path(args.json_report).write_text(
            json.dumps({"source": src, "results": payload}, indent=2), "utf-8")
        print(f"\nJSON report written to {args.json_report}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
