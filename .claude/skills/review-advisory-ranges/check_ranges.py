#!/usr/bin/env python3
"""Compare OSV advisories between two git refs and validate multi-branch range tiling.

For every (ecosystem, package, CVE) that is remediated on more than one branch, the
advisories must tile the version line: the lowest branch starts at "0" and every
other branch starts at the latest `fixed` version of the previous (lower) branch.

Checks:
  1. diff      - per changed file, every JSON change outside the allowed paths
                 (default: `modified` and range `introduced`) is reported.
  2. tiling    - each range's `introduced` vs the expected value derived from the
                 previous advisory in the same (package, CVE) group; advisories
                 whose CVEs demand different starts are reported as CONFLICT.
  3. simulate  - evaluates every known remediated version of a package against
                 every advisory, on both refs, and reports fixed builds that are
                 still reported affected (false positives), versions that stopped
                 being affected (possible false negatives), and later rebuilds of
                 a lower branch that fall inside a tiled range.

Usage:
  check_ranges.py --base origin/main --head pr-17 [--repo .] [--allow PATH ...]
Exit status: 0 clean, 1 errors found, 2 usage/git failure.
"""

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from functools import cmp_to_key

ADVISORY_DIR = "advisories/"
DEFAULT_ALLOWED = ["modified", "affected[].ranges[].events[].introduced"]

# ---------------------------------------------------------------- versions

_QUALIFIERS = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"]
_ALIASES = {"ga": "", "final": "", "release": "", "cr": "rc", "a": "alpha", "b": "beta", "m": "milestone"}


def _qual_key(s):
    """Sort key for a Maven string item: known qualifiers first, unknown ones lexically after."""
    s = _ALIASES.get(s, s)
    if s in _QUALIFIERS:
        return (_QUALIFIERS.index(s), "")
    return (len(_QUALIFIERS), s)


def _maven_parse(v):
    """Parse a version into nested lists following Maven ComparableVersion rules."""
    v = v.lower()
    root = []
    cur = root
    buf = ""

    def flush(buf):
        if buf == "":
            cur.append(0)
        elif buf.isdigit():
            cur.append(int(buf))
        else:
            # a single-letter qualifier directly followed by a digit (a1, b2, m3) is an alias
            cur.append(buf)

    def trim(lst):
        while lst and (lst[-1] == 0 or lst[-1] == "" or (isinstance(lst[-1], str) and _ALIASES.get(lst[-1]) == "")
                       or (isinstance(lst[-1], list) and not lst[-1])):
            lst.pop()

    i = 0
    while i < len(v):
        c = v[i]
        if c == ".":
            flush(buf)
            buf = ""
        elif c == "-":
            flush(buf)
            buf = ""
            trim(cur)
            new = []
            cur.append(new)
            cur = new
        elif buf and (c.isdigit() != buf[-1].isdigit()):
            # digit/letter transition is equivalent to a hyphen
            flush(buf)
            buf = c
            trim(cur)
            new = []
            cur.append(new)
            cur = new
        else:
            buf += c
        i += 1
    if buf or not cur:
        flush(buf)
    # trim every list bottom-up
    def deep_trim(lst):
        for x in lst:
            if isinstance(x, list):
                deep_trim(x)
        trim(lst)
    deep_trim(root)
    return root


def _cmp_item(a, b):
    """Compare two Maven items (int, str, list, or None for padding)."""
    if a is None and b is None:
        return 0
    if a is None:
        return -_cmp_item(b, None)
    if isinstance(a, int):
        if b is None:
            return 0 if a == 0 else 1
        if isinstance(b, int):
            return (a > b) - (a < b)
        return 1  # int > string, int > list
    if isinstance(a, str):
        if b is None:
            ka, kb = _qual_key(a), _qual_key("")
            return (ka > kb) - (ka < kb)
        if isinstance(b, int):
            return -1
        if isinstance(b, str):
            ka, kb = _qual_key(a), _qual_key(b)
            return (ka > kb) - (ka < kb)
        return -1  # string < list
    # a is list
    if b is None:
        return _cmp_item(a[0], None) if a else 0
    if isinstance(b, int):
        return -1
    if isinstance(b, str):
        return 1
    for i in range(max(len(a), len(b))):
        r = _cmp_item(a[i] if i < len(a) else None, b[i] if i < len(b) else None)
        if r:
            return r
    return 0


def maven_cmp(x, y):
    return _cmp_item(_maven_parse(x), _maven_parse(y))


def pypi_cmp(x, y):
    try:
        from packaging.version import Version
        a, b = Version(x), Version(y)
        return (a > b) - (a < b)
    except Exception:
        return maven_cmp(x, y)  # reasonable fallback for odd strings


def comparator(ecosystem):
    base = ecosystem.split(":")[-1].lower()
    return pypi_cmp if base == "pypi" else maven_cmp


def in_range(cmp, version, events):
    """True if version falls inside an OSV ECOSYSTEM range given its events."""
    affected = False
    for ev in sorted(events, key=cmp_to_key(lambda a, b: _event_order(cmp, a, b))):
        (kind, val), = ev.items()
        if kind == "introduced":
            if val == "0" or cmp(version, val) >= 0:
                affected = True
        elif kind == "fixed":
            if cmp(version, val) >= 0:
                affected = False
        elif kind == "last_affected":
            if cmp(version, val) > 0:
                affected = False
        elif kind == "limit":
            if cmp(version, val) >= 0:
                affected = False
    return affected


def _event_order(cmp, a, b):
    va, vb = next(iter(a.values())), next(iter(b.values()))
    if va == "0":
        return -1
    if vb == "0":
        return 1
    return cmp(va, vb)


# ---------------------------------------------------------------- loading

def git(repo, *args, input=None):
    return subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True, input=input).stdout


def load_ref(repo, ref):
    names = git(repo, "ls-tree", "-r", "--name-only", ref, "--", ADVISORY_DIR).decode().split()
    names = [n for n in names if n.endswith(".json")]
    if not names:
        return {}
    out = git(repo, "cat-file", "--batch", input="".join(f"{ref}:{n}\n" for n in names).encode())
    result, pos = {}, 0
    for n in names:
        nl = out.index(b"\n", pos)
        size = int(out[pos:nl].split()[2])
        raw = out[nl + 1:nl + 1 + size]
        pos = nl + 1 + size + 1
        result[n] = (raw, json.loads(raw))
    return result


# ---------------------------------------------------------------- checks

def json_diff(a, b, path=""):
    """Yield (path, old, new) for every leaf difference; list indices rendered as []."""
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            p = f"{path}.{k}" if path else k
            if k not in a or k not in b:
                yield p, a.get(k, "<absent>"), b.get(k, "<absent>")
            else:
                yield from json_diff(a[k], b[k], p)
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            yield from json_diff(x, y, f"{path}[{i}]")
    elif a != b:
        yield path, a, b


def generic_path(p):
    return re.sub(r"\[\d+\]", "[]", p)


def cve_keys(adv):
    ups = adv.get("upstream", []) + adv.get("aliases", [])
    cves = sorted({u for u in ups if u.startswith("CVE-")})
    return cves or sorted(set(ups)) or [adv["id"]]


def ranges(adv):
    """Yield (affected_idx, range_idx, ecosystem, name, events, fixed) for ECOSYSTEM/SEMVER ranges."""
    for ai, aff in enumerate(adv.get("affected", [])):
        pkg = aff.get("package", {})
        for ri, rng in enumerate(aff.get("ranges", [])):
            if rng.get("type") == "GIT":
                continue
            fixed = [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
            yield ai, ri, pkg.get("ecosystem"), pkg.get("name"), rng.get("events", []), (fixed[0] if fixed else None)


def introduced_of(events):
    vals = [e["introduced"] for e in events if "introduced" in e]
    return vals[0] if vals else None


def expected_tiling(advs):
    """Return {(file, ai, ri): {"actual", "expected": {cve: value}, "eco", "name", "fixed", "id"}}."""
    groups = defaultdict(list)  # (eco, name, cve) -> [(fixed, key)]
    info = {}
    for f, (_, adv) in advs.items():
        for ai, ri, eco, name, events, fixed in ranges(adv):
            key = (f, ai, ri)
            info[key] = {"id": adv["id"], "eco": eco, "name": name, "fixed": fixed,
                         "actual": introduced_of(events), "expected": {}, "events": events,
                         "cves": cve_keys(adv)}
            if fixed is None:
                continue
            for cve in cve_keys(adv):
                groups[(eco, name, cve)].append((fixed, key))
    for (eco, name, cve), members in groups.items():
        cmp = comparator(eco)
        members.sort(key=cmp_to_key(lambda a, b: cmp(a[0], b[0])))
        prev = "0"
        for i, (fixed, key) in enumerate(members):
            # the previous fix is the highest fixed strictly below this one
            lower = [m[0] for m in members[:i] if cmp(m[0], fixed) < 0]
            prev = lower[-1] if lower else "0"
            info[key]["expected"][cve] = prev
            info[key].setdefault("group_sizes", {})[cve] = len(members)
    return info


def simulate(advs):
    """Return {(eco, name, version, cve): bool affected} over all known fixed versions, plus known-fixed set."""
    versions = defaultdict(set)
    fixed_by = set()
    for _, (_, adv) in advs.items():
        for _, _, eco, name, _, fixed in ranges(adv):
            if fixed:
                versions[(eco, name)].add(fixed)
                for cve in cve_keys(adv):
                    fixed_by.add((eco, name, fixed, cve))
    affected = {}
    for _, (_, adv) in advs.items():
        for _, _, eco, name, events, _ in ranges(adv):
            cmp = comparator(eco)
            for v in versions[(eco, name)]:
                hit = in_range(cmp, v, events)
                for cve in cve_keys(adv):
                    k = (eco, name, v, cve)
                    affected[k] = affected.get(k, False) or hit
    return affected, fixed_by, versions


def base_of(v):
    """Upstream base of a remediated version, e.g. 6.0.3.rhlw-00001 -> 6.0.3."""
    m = re.match(r"^(.*?)[.\-+]rhlw[.\-]?\d+$", v)
    return m.group(1) if m else None


# ---------------------------------------------------------------- report

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="origin/main")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--allow", action="append", help="extra allowed generic JSON path (e.g. 'references')")
    ap.add_argument("--all", action="store_true", help="check tiling for all advisories, not only changed ones")
    ap.add_argument("-v", "--verbose", action="store_true", help="list every finding instead of a sample")
    args = ap.parse_args()
    allowed = set(DEFAULT_ALLOWED + (args.allow or []))

    try:
        base, head = load_ref(args.repo, args.base), load_ref(args.repo, args.head)
    except subprocess.CalledProcessError as e:
        print(f"git failed: {e.stderr.decode().strip()}", file=sys.stderr)
        return 2

    errors = warnings = 0
    added = sorted(set(head) - set(base))
    removed = sorted(set(base) - set(head))
    changed = sorted(f for f in set(base) & set(head) if base[f][0] != head[f][0])

    print(f"# Advisory range review: {args.base} -> {args.head}")
    print(f"files: {len(head)} total, {len(changed)} changed, {len(added)} added, {len(removed)} removed\n")

    # 1. diff
    print("## 1. Field diff vs base (allowed: " + ", ".join(sorted(allowed)) + ")")
    whitespace_only = 0
    for f in changed:
        b, h = base[f][1], head[f][1]
        diffs = list(json_diff(b, h))
        if not diffs:
            whitespace_only += 1
            continue
        bad = [d for d in diffs if generic_path(d[0]) not in allowed]
        for p, o, n in bad:
            print(f"  ERROR {f}: {p}: {o!r} -> {n!r}")
            errors += 1
        content = [d for d in diffs if d[0] != "modified"]
        if not content:
            print(f"  WARN  {f}: only `modified` bumped, no semantic change (re-serialized file)")
            warnings += 1
        if content and b.get("modified") == h.get("modified"):
            print(f"  WARN  {f}: content changed but `modified` not bumped")
            warnings += 1
        if h.get("modified", "") < h.get("published", ""):
            print(f"  ERROR {f}: modified < published")
            errors += 1
    fmt = sum(1 for f in changed if base[f][0].endswith(b"\n") != head[f][0].endswith(b"\n"))
    if whitespace_only:
        print(f"  INFO  {whitespace_only} file(s) changed in formatting only")
    if fmt:
        print(f"  INFO  {fmt} file(s) gained/lost a trailing newline")
    for f in added:
        print(f"  INFO  added {f}")
    for f in removed:
        print(f"  WARN  removed {f}")
        warnings += 1
    print()

    # 2. tiling
    print("## 2. `introduced` vs latest fixed of the previous advisory (same package + CVE)")
    info = expected_tiling(head)
    base_info = expected_tiling(base)
    sibling_fixes = defaultdict(set)  # (eco, name, cve) -> fixed versions
    for r in info.values():
        for cve in r["cves"]:
            if r["fixed"]:
                sibling_fixes[(r["eco"], r["name"], cve)].add(r["fixed"])
    ok, inclusive = [], []
    for key, r in sorted(info.items(), key=lambda kv: (kv[1]["eco"], kv[1]["name"], kv[1]["fixed"] or "")):
        f = key[0]
        multi = any(s > 1 for s in r.get("group_sizes", {}).values())
        if not (args.all or f in changed or f in added or multi):
            continue
        exp = set(r["expected"].values())
        old = base_info.get(key, {}).get("actual")
        tag = f"{r['id']} {r['name']} [{r['actual']}, {r['fixed']})"
        if old is not None and old != r["actual"]:
            tag += f" (was introduced={old})"
        if len(exp) > 1:
            by_val = defaultdict(list)
            for cve, v in r["expected"].items():
                by_val[v].append(cve)
            detail = "; ".join(f"{v} <- {','.join(sorted(c))}" for v, c in sorted(by_val.items()))
            print(f"  CONFLICT {tag}\n           one range cannot satisfy every CVE: {detail}")
            errors += 1
        elif exp and r["actual"] != next(iter(exp)):
            print(f"  MISMATCH {tag}  expected introduced={next(iter(exp))}")
            errors += 1
        elif f in changed and old != r["actual"]:
            ok.append(tag)
        # OSV `introduced` is inclusive: starting at a sibling's fix keeps that fixed build affected
        if r["actual"] and r["actual"] != "0" and any(
                r["actual"] in sibling_fixes[(r["eco"], r["name"], c)] for c in r["cves"]):
            inclusive.append(tag)
    print(f"  OK       {len(ok)} changed range(s) follow the previous-branch rule")
    if inclusive:
        print(f"  ERROR    {len(inclusive)} range(s) start AT a sibling advisory's fixed version; `introduced` is"
              f" inclusive,\n           so that fixed build is still reported affected")
        errors += len(inclusive)
        for t in inclusive if args.verbose else inclusive[:5]:
            print(f"           - {t}")
        if not args.verbose and len(inclusive) > 5:
            print(f"           ... {len(inclusive) - 5} more (-v)")
    print()

    # 3. simulate
    print("## 3. Simulated OSV query over known remediated versions (ground truth)")
    a_base, fixed_base, _ = simulate(base)
    a_head, fixed_head, versions = simulate(head)
    fp_base = {k for k in fixed_base if a_base.get(k)}
    fp_head = {k for k in fixed_head if a_head.get(k)}
    print(f"  fixed builds reported affected by the CVE they fix: base={len(fp_base)} head={len(fp_head)}"
          f"  (resolved={len(fp_base - fp_head)}, new={len(fp_head - fp_base)})")
    per_pkg = defaultdict(lambda: [0, 0])
    for _, name, _, _ in fp_base:
        per_pkg[name][0] += 1
    for _, name, _, _ in fp_head:
        per_pkg[name][1] += 1
    for name, (b, h) in sorted(per_pkg.items()):
        print(f"    {name:60} {b:3} -> {h:3}")
    if fp_head:
        errors += 1
    for _, name, v, cve in sorted(fp_head - fp_base):
        print(f"  ERROR newly affected fixed build: {name} {v} {cve}")
        errors += 1
    if args.verbose:
        for _, name, v, cve in sorted(fp_head):
            print(f"    still affected: {name} {v} {cve}")
    gone = sorted(k for k, hit in a_base.items() if hit and not a_head.get(k) and k not in fixed_head)
    for _, name, v, cve in gone:
        print(f"  WARN  no longer affected (verify not a false negative): {name} {v} {cve}")
        warnings += 1
    # later rebuilds of a lower branch landing inside a tiled range
    for key, r in info.items():
        start = r["actual"]
        if not start or start == "0" or not r["fixed"]:
            continue
        cmp, sb = comparator(r["eco"]), base_of(start)
        for v in versions[(r["eco"], r["name"])]:
            if v != start and sb and base_of(v) == sb and in_range(cmp, v, r["events"]):
                print(f"  WARN  {r['id']}: {v} is a later rebuild of the {sb} branch but falls in "
                      f"[{start}, {r['fixed']})")
                warnings += 1
    print()

    print(f"Result: {errors} error(s), {warnings} warning(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
