#!/usr/bin/env python3
"""Validate Lightwell OSV advisory records — schema + CVE<->package consistency.

Purpose
-------
Catch the two classes of problem found in the #8-#11 PR review that the older
osv_quality_check.py misses:

  1. SCHEMA / STRUCTURE (offline) — does the record follow the *agreed* Lightwell
     shape (at least one `Red Hat Lightwell:<ecosystem>` entry — Maven or PyPI —
     carrying a versionless purl and the database_specific.lightwell lineage block,
     schema 1.9.0, unique RHLW id)?

  2. CVE <-> PACKAGE CORRECTNESS (online, cached) — for EVERY CVE the record
     claims to fix, is the reported Maven artifact actually one of the artifacts
     the CVE affects?  Unlike the old script this works on `Red Hat Lightwell:*`
     entries (the old one silently skipped them), resolves each CVE to its own
     artifact (so a sibling CVE's GHSA can't mask a mis-filed one), and flags:
        * REJECTED CVEs,
        * CVEs that belong to a *different* artifact (e.g. a netty-resolver-dns
          CVE filed under netty-codec-dns, or a spring-core CVE under spring-web),
        * GHSAs bundled into a record whose affected package differs.

Ground truth: CVE.org (CNA, incl. REJECTED state + packageName), OSV.dev / GHSA
(structured Maven names), NVD (description fallback).  Stdlib only.

Usage
-----
    # a directory of *.json advisories
    python3 lightwell_osv_validate.py --input-dir path/to/advisories

    # schema only, no network
    python3 lightwell_osv_validate.py --input-dir advisories --offline

    # pull a PR's changed advisories straight from GitHub (needs `gh`)
    python3 lightwell_osv_validate.py --pr 11 --repo project-lightwell/lightwell-osv

    # machine-readable output
    python3 lightwell_osv_validate.py --input-dir advisories --json-report out.json

Exit code: 0 if everything is OK/needs-review-only, 1 if any file has a schema
ERROR or a MISATTRIBUTED / REJECTED CVE verdict.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

USER_AGENT = "lightwell-osv-validate/1.0 (+https://github.com/project-lightwell/lightwell-osv)"
REQUEST_TIMEOUT = 25
REQUEST_DELAY = 0.2
MAX_RETRIES = 2
CACHE_SUBDIR = ".lightwell_osv_cache"

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
GHSA_RE = re.compile(r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$")
RHLW_ID_RE = re.compile(r"^(x_)?RHLW-[A-Za-z0-9:_.-]+$")
ID_CHARSET_RE = re.compile(r"^[a-zA-Z0-9:_.-]+$")
RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
# A Maven-coordinate-looking string: group<sep>artifact, group contains a dot.
# (OSV gives reliable group:artifact already; this is only to sift CVE.org's
#  packageName field, which also lists container/product names.)
COORD_RE = re.compile(r"^([a-z0-9_.-]*\.[a-z0-9_.-]+)[/:]([A-Za-z0-9_.-]+)$")
# GHSA id as it appears inside OSV's 404 "...the following aliases were: GHSA-..."
# message; tolerant on segment length (real ids are usually 4-4-4 but not guaranteed).
OSV_ALIAS_GHSA_RE = re.compile(r"GHSA-[0-9a-z]{4,}-[0-9a-z]{4,}-[0-9a-z]{4,}", re.I)

VALID_RANGE_TYPES = {"SEMVER", "ECOSYSTEM", "GIT"}
VALID_REFERENCE_TYPES = {
    "ADVISORY", "ARTICLE", "DETECTION", "DISCUSSION", "REPORT", "FIX",
    "INTRODUCED", "PACKAGE", "EVIDENCE", "WEB",
}
VALID_SEVERITY_TYPES = {"CVSS_V2", "CVSS_V3", "CVSS_V4", "Ubuntu"}
VALID_CREDIT_TYPES = {
    "FINDER", "REPORTER", "ANALYST", "COORDINATOR", "REMEDIATION_DEVELOPER",
    "REMEDIATION_REVIEWER", "REMEDIATION_VERIFIER", "TOOL", "SPONSOR", "OTHER",
}

# Recognized Red Hat Lightwell ecosystems and the purl type each entry must carry.
LIGHTWELL_ECOSYSTEMS = {"Maven": "pkg:maven/", "PyPI": "pkg:pypi/"}


# --------------------------------------------------------------------------- #
# data holders
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    level: str   # ERROR | WARNING | INFO
    code: str
    message: str


@dataclass
class CveVerdict:
    cve_id: str
    package_name: str
    verdict: str   # CONFIRMED | CONFIRMED_TEXTUAL | MISATTRIBUTED | REJECTED | NEEDS_REVIEW | LOOKUP_FAILED
    evidence: str
    sources: list = field(default_factory=list)


@dataclass
class FileResult:
    path: Path
    record_id: str = ""
    schema: list = field(default_factory=list)
    verdicts: list = field(default_factory=list)
    load_error: str = ""

    @property
    def status(self):
        if self.load_error or any(f.level == "ERROR" for f in self.schema):
            return "ERROR"
        if any(v.verdict in ("MISATTRIBUTED", "REJECTED") for v in self.verdicts):
            return "MISATTRIBUTED"
        if any(v.verdict in ("NEEDS_REVIEW", "LOOKUP_FAILED") for v in self.verdicts):
            return "NEEDS_REVIEW"
        if any(f.level == "WARNING" for f in self.schema):
            return "OK_WITH_WARNINGS"
        return "OK"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def norm_coord(name):
    """Normalise a coordinate for comparison: lower-case, '/'->':'."""
    return name.strip().lower().replace("/", ":")


def artifact_of(coord):
    return norm_coord(coord).split(":")[-1]


class HttpCache:
    def __init__(self, cache_dir: Path):
        self.dir = cache_dir
        self.dir.mkdir(parents=True, exist_ok=True)

    def _p(self, url):
        return self.dir / (re.sub(r"[^A-Za-z0-9]+", "_", url)[-180:] + ".json")

    def get(self, url):
        p = self._p(url)
        if p.exists():
            try:
                return json.loads(p.read_text("utf-8"))
            except Exception:
                return None
        return None

    def set(self, url, val):
        try:
            self._p(url).write_text(json.dumps(val), "utf-8")
        except OSError:
            pass


def fetch_json(url, cache: HttpCache, quiet=False):
    c = cache.get(url)
    # Return cached values, except legacy "not found" entries written before 404
    # bodies were captured — re-fetch those so the GHSA-alias logic can run.
    if c is not None and not (isinstance(c, dict) and c.get("__nf__") and "__body__" not in c):
        return c
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    for attempt in range(MAX_RETRIES + 1):
        try:
            time.sleep(REQUEST_DELAY)
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as r:
                data = json.loads(r.read().decode("utf-8"))
                cache.set(url, data)
                return data
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # Keep the 404 body: OSV names the GHSA alias(es) there for CVEs it
                # only indexes under a GHSA id (resolved in osv_truth()).
                try:
                    body = json.loads(e.read().decode("utf-8"))
                except Exception:
                    body = None
                val = {"__nf__": True, "__body__": body}
                cache.set(url, val)
                return val
            if attempt == MAX_RETRIES and not quiet:
                print(f"  ! HTTP {e.code} {url}", file=sys.stderr)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            if attempt == MAX_RETRIES and not quiet:
                print(f"  ! network error {url}: {e}", file=sys.stderr)
    return None


# --------------------------------------------------------------------------- #
# phase 1: schema (offline)
# --------------------------------------------------------------------------- #
def check_schema(record, path, F):
    for req in ("id", "modified"):
        if req not in record:
            F.append(Finding("ERROR", "SCHEMA:MISSING_FIELD", f"missing required top-level field {req!r}"))

    sv = record.get("schema_version")
    if sv is None:
        F.append(Finding("WARNING", "SCHEMA:NO_VERSION", "no schema_version (OSV assumes 1.0.0)"))
    elif sv != "1.9.0":
        F.append(Finding("INFO", "SCHEMA:VERSION", f"schema_version is {sv!r}; feed convention is 1.9.0"))

    rid = record.get("id", "")
    if rid:
        if not ID_CHARSET_RE.match(rid):
            F.append(Finding("ERROR", "SCHEMA:ID_CHARSET", f"id {rid!r} has chars outside [a-zA-Z0-9:_.-]"))
        if not RHLW_ID_RE.match(rid):
            F.append(Finding("WARNING", "SCHEMA:ID_PREFIX", f"id {rid!r} is not an RHLW-* id"))
        if path is not None and rid and path.name != f"{rid}.json":
            F.append(Finding("WARNING", "SCHEMA:FILENAME", f"filename {path.name!r} != {rid}.json"))

    for df in ("modified", "published"):
        v = record.get(df)
        if v and not RFC3339_RE.match(v):
            F.append(Finding("ERROR", "SCHEMA:BAD_TIMESTAMP", f"{df} {v!r} is not RFC3339 UTC ('...Z')"))
    if "published" not in record:
        F.append(Finding("WARNING", "SCHEMA:NO_PUBLISHED", "no 'published' date"))

    for t in ("summary", "details"):
        if not record.get(t):
            F.append(Finding("WARNING", f"SCHEMA:NO_{t.upper()}", f"no {t!r}"))

    if "aliases" in record:
        F.append(Finding("WARNING", "LIGHTWELL:ALIASES_USED",
                         "'aliases' present; downstream advisories should use 'upstream'"))

    upstream = record.get("upstream", [])
    cves = [u for u in upstream if CVE_RE.match(u)]
    if not upstream:
        F.append(Finding("WARNING", "LIGHTWELL:NO_UPSTREAM", "no upstream[] CVE/GHSA ids"))
    bad = [u for u in upstream if not (CVE_RE.match(u) or GHSA_RE.match(u))]
    if bad:
        F.append(Finding("ERROR", "SCHEMA:BAD_UPSTREAM_ID", f"malformed upstream id(s): {bad}"))

    sev = record.get("severity", [])
    if not sev:
        F.append(Finding("WARNING", "LIGHTWELL:NO_SEVERITY",
                         "severity[] is empty/absent — inconsistent with the rest of the feed; "
                         "add a CVSS vector if one is published"))
    for i, s in enumerate(sev):
        if s.get("type") not in VALID_SEVERITY_TYPES:
            F.append(Finding("ERROR", "SCHEMA:BAD_SEVERITY_TYPE", f"severity[{i}].type {s.get('type')!r} invalid"))
        if not s.get("score"):
            F.append(Finding("ERROR", "SCHEMA:SEVERITY_NO_SCORE", f"severity[{i}] has no score"))

    for i, ref in enumerate(record.get("references", [])):
        if ref.get("type") not in VALID_REFERENCE_TYPES:
            F.append(Finding("ERROR", "SCHEMA:BAD_REF_TYPE", f"references[{i}].type {ref.get('type')!r} invalid"))
        if not ref.get("url"):
            F.append(Finding("ERROR", "SCHEMA:REF_NO_URL", f"references[{i}] has no url"))

    for i, c in enumerate(record.get("credits", [])):
        if not c.get("name"):
            F.append(Finding("ERROR", "SCHEMA:CREDIT_NO_NAME", f"credits[{i}] has no name"))
        if c.get("type") and c["type"] not in VALID_CREDIT_TYPES:
            F.append(Finding("ERROR", "SCHEMA:BAD_CREDIT_TYPE", f"credits[{i}].type {c['type']!r} invalid"))

    for cwe in record.get("database_specific", {}).get("lightwell", {}).get("cwe_ids", []):
        if not re.match(r"^CWE-\d+$", cwe):
            F.append(Finding("ERROR", "SCHEMA:BAD_CWE_ID", f"malformed cwe id {cwe!r}"))

    check_affected(record, F)
    return cves


def check_affected(record, F):
    affected = record.get("affected")
    if not affected:
        F.append(Finding("ERROR", "SCHEMA:NO_AFFECTED", "affected[] missing or empty"))
        return

    lightwell_entries = 0
    for i, entry in enumerate(affected):
        pkg = entry.get("package", {})
        eco = pkg.get("ecosystem", "")
        name = pkg.get("name", "")
        pre = f"affected[{i}]"
        if not eco:
            F.append(Finding("ERROR", "SCHEMA:NO_ECOSYSTEM", f"{pre}.package.ecosystem missing"))
        if not name:
            F.append(Finding("ERROR", "SCHEMA:NO_PACKAGE_NAME", f"{pre}.package.name missing"))

        base = eco.split(":", 1)[0]
        suffix = eco.split(":", 1)[1] if ":" in eco else ""

        if base == "Red Hat Lightwell":
            if not suffix:
                F.append(Finding("ERROR", "LIGHTWELL:BARE_ECOSYSTEM",
                                 f"{pre}.ecosystem is bare 'Red Hat Lightwell' with no ':<ecosystem>' suffix"))
            else:
                lightwell_entries += 1
                expected_purl = LIGHTWELL_ECOSYSTEMS.get(suffix)
                if expected_purl is None:
                    F.append(Finding("WARNING", "LIGHTWELL:UNKNOWN_ECOSYSTEM",
                                     f"{pre}.ecosystem 'Red Hat Lightwell:{suffix}' is not a recognized "
                                     f"Lightwell ecosystem (expected one of {sorted(LIGHTWELL_ECOSYSTEMS)})"))
                purl = pkg.get("purl")
                if not purl:
                    F.append(Finding("ERROR", "LIGHTWELL:NO_PURL",
                                     f"{pre} (Lightwell:{suffix}) has no package.purl"))
                else:
                    if expected_purl and not purl.startswith(expected_purl):
                        F.append(Finding("ERROR", "SCHEMA:BAD_PURL_TYPE",
                                         f"{pre}.purl {purl!r} not {expected_purl}"))
                    if "@" in purl:
                        F.append(Finding("WARNING", "LIGHTWELL:VERSIONED_PURL",
                                         f"{pre}.purl {purl!r} is versioned; convention is versionless"))
                # Maven names are group:artifact; PyPI (and others) use a single project name.
                if suffix == "Maven" and name and ":" not in name:
                    F.append(Finding("WARNING", "LIGHTWELL:NAME_NOT_COORD",
                                     f"{pre}.name {name!r} is not group:artifact form"))
                lw = entry.get("database_specific", {}).get("lightwell", {})
                if not lw:
                    F.append(Finding("ERROR", "LIGHTWELL:NO_LINEAGE",
                                     f"{pre} has no database_specific.lightwell lineage block"))
                else:
                    for k in ("backport_base_version", "remediated_version", "repository_url"):
                        if k not in lw:
                            F.append(Finding("WARNING", "LIGHTWELL:MISSING_LINEAGE_FIELD",
                                             f"{pre}.database_specific.lightwell missing {k!r}"))
                    _check_fixed_matches(entry, lw, pre, F)

        ranges = entry.get("ranges", [])
        if not ranges and not entry.get("versions"):
            F.append(Finding("ERROR", "SCHEMA:NO_RANGES_OR_VERSIONS", f"{pre} has neither ranges[] nor versions[]"))
        for j, rng in enumerate(ranges):
            if rng.get("type") not in VALID_RANGE_TYPES:
                F.append(Finding("ERROR", "SCHEMA:BAD_RANGE_TYPE", f"{pre}.ranges[{j}].type {rng.get('type')!r} invalid"))
            events = rng.get("events", [])
            if not events:
                F.append(Finding("ERROR", "SCHEMA:NO_EVENTS", f"{pre}.ranges[{j}].events empty"))
            else:
                if not events[0].get("introduced"):
                    F.append(Finding("ERROR", "SCHEMA:FIRST_EVENT_NOT_INTRODUCED",
                                     f"{pre}.ranges[{j}].events[0] must be 'introduced'"))
                if not any("fixed" in e or "last_affected" in e for e in events):
                    F.append(Finding("WARNING", "SCHEMA:NO_FIXED_EVENT",
                                     f"{pre}.ranges[{j}] has no 'fixed'/'last_affected' event"))

    if lightwell_entries == 0:
        F.append(Finding("ERROR", "LIGHTWELL:NO_LIGHTWELL_ENTRY",
                         "no 'Red Hat Lightwell:<ecosystem>' affected[] entry (the agreed feed shape)"))


def _check_fixed_matches(entry, lw, pre, F):
    remediated = lw.get("remediated_version")
    if not remediated:
        return
    fixed_vals = [e["fixed"] for rng in entry.get("ranges", []) for e in rng.get("events", []) if "fixed" in e]
    if fixed_vals and remediated not in fixed_vals:
        F.append(Finding("WARNING", "LIGHTWELL:FIXED_VS_REMEDIATED",
                         f"{pre}: ranges fixed={fixed_vals} != remediated_version {remediated!r}"))


# --------------------------------------------------------------------------- #
# phase 2: CVE <-> package (online)
# --------------------------------------------------------------------------- #
def cveorg_truth(cve, cache):
    """Return (state, maven_coords:set, texts:list) from CVE.org CNA/ADP."""
    d = fetch_json(f"https://cveawg.mitre.org/api/cve/{quote(cve)}", cache)
    coords, texts = set(), []
    state = None
    if not d or d.get("__nf__"):
        return state, coords, texts
    state = d.get("cveMetadata", {}).get("state")
    cna = d.get("containers", {}).get("cna", {})

    def harvest(container):
        for aff in container.get("affected", []):
            for key in ("packageName", "product"):
                v = aff.get(key)
                if v and v not in ("n/a", "N/A") and COORD_RE.match(norm_coord(v)):
                    coords.add(norm_coord(v))
        for desc in container.get("descriptions", []):
            if desc.get("lang", "en").startswith("en"):
                texts.append(desc.get("value", ""))

    harvest(cna)
    for adp in d.get("containers", {}).get("adp", []):
        harvest(adp)
    return state, coords, texts


def osv_truth(vuln_id, cache):
    """Return (maven_coords:set, aliases:list, texts:list) from OSV.dev.

    OSV indexes some advisories (notably Spring / VMware CVEs) only under their
    GHSA id, so GET /v1/vulns/<CVE> 404s. In that case OSV still names the GHSA
    alias(es) in the 404 body ("...the following aliases were: GHSA-..."); we
    surface those as `aliases` so the caller can resolve the real coordinate.
    """
    d = fetch_json(f"https://api.osv.dev/v1/vulns/{quote(vuln_id)}", cache)
    coords, texts = set(), []
    if not d:
        return coords, [], texts
    if d.get("__nf__"):
        body = d.get("__body__") or {}
        msg = body.get("message", "") if isinstance(body, dict) else ""
        aliases = list(dict.fromkeys(OSV_ALIAS_GHSA_RE.findall(msg)))
        return coords, aliases, texts
    for a in d.get("affected", []):
        p = a.get("package", {})
        if p.get("ecosystem") in ("Maven", "PyPI") and p.get("name"):
            coords.add(norm_coord(p["name"]))
    for t in ("summary", "details"):
        if d.get(t):
            texts.append(d[t])
    aliases = (d.get("aliases", []) or []) + (d.get("related", []) or [])
    return coords, aliases, texts


def verify_cve(cve, reported_pkg, cache):
    reported = norm_coord(reported_pkg)
    art = artifact_of(reported_pkg)
    sources = []

    state, cve_coords, cve_texts = cveorg_truth(cve, cache)
    sources.append("cve.org")
    if state == "REJECTED":
        return CveVerdict(cve, reported_pkg, "REJECTED",
                          "CVE is in the REJECTED state at CVE.org — should not be in the feed", sources)

    osv_coords, aliases, osv_texts = osv_truth(cve, cache)
    sources.append("osv.dev")
    # Resolve this CVE's own GHSA aliases (incl. the alias OSV names when it only
    # indexes the CVE under a GHSA) for precise attribution — not sibling CVEs' GHSAs.
    for al in aliases:
        if al.startswith("GHSA-"):
            g_coords, _, g_texts = osv_truth(al, cache)
            osv_coords |= g_coords
            osv_texts += g_texts
            sources.append(al)

    truth = cve_coords | osv_coords
    texts = " \n ".join(cve_texts + osv_texts).lower()

    if reported in truth:
        return CveVerdict(cve, reported_pkg, "CONFIRMED",
                          f"reported package {reported_pkg!r} is listed as affected by ground truth", sources)
    for t in truth:
        if artifact_of(t) == art:
            return CveVerdict(cve, reported_pkg, "CONFIRMED",
                              f"artifact {art!r} matches affected coordinate {t!r}", sources)
    if truth:
        return CveVerdict(cve, reported_pkg, "MISATTRIBUTED",
                          f"ground truth says this CVE affects {sorted(truth)}, NOT {reported_pkg!r}", sources)
    if art and art in texts:
        return CveVerdict(cve, reported_pkg, "CONFIRMED_TEXTUAL",
                          f"no structured package coord, but description text names {art!r}", sources)
    if not texts and not truth:
        return CveVerdict(cve, reported_pkg, "LOOKUP_FAILED",
                          "no ground-truth data retrieved (network issue or no public record) — verify manually", sources)
    return CveVerdict(cve, reported_pkg, "NEEDS_REVIEW",
                      "only product-family data public, no artifact-level coordinate to confirm/refute — verify manually", sources)


def check_cve_package(record, cache, F):
    upstream = record.get("upstream", []) or record.get("aliases", [])
    cves = [u for u in upstream if CVE_RE.match(u)]
    ghsas = [u for u in upstream if GHSA_RE.match(u)]

    # package coordinate(s) this record is about
    # (Lightwell:Maven / Lightwell:PyPI OR plain Maven / PyPI)
    pkgs = []
    for a in record.get("affected", []):
        p = a.get("package", {})
        eco = p.get("ecosystem", "")
        base = eco.split(":", 1)[0]
        suffix = eco.split(":", 1)[1] if ":" in eco else ""
        is_pkg = base in ("Maven", "PyPI") or (base == "Red Hat Lightwell" and suffix in LIGHTWELL_ECOSYSTEMS)
        if is_pkg and p.get("name"):
            pkgs.append(p["name"])
    pkgs = list(dict.fromkeys(pkgs))

    verdicts = []
    for cve in cves:
        for pkg in pkgs:
            verdicts.append(verify_cve(cve, pkg, cache))

    # secondary net: each upstream GHSA should map to (one of) the reported package(s)
    reported_norm = {norm_coord(p) for p in pkgs}
    reported_arts = {artifact_of(p) for p in pkgs}
    for g in ghsas:
        g_coords, _, _ = osv_truth(g, cache)
        if g_coords and not (g_coords & reported_norm) and not ({artifact_of(c) for c in g_coords} & reported_arts):
            F.append(Finding("WARNING", "LIGHTWELL:GHSA_OTHER_PACKAGE",
                             f"upstream GHSA {g} affects {sorted(g_coords)}, not the reported package(s) {pkgs} "
                             "— likely a CVE bundled under the wrong artifact"))
    return verdicts


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #
def process_file(path: Path, cache, offline):
    r = FileResult(path=path)
    try:
        record = json.loads(path.read_text("utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        r.load_error = str(e)
        return r
    r.record_id = record.get("id", "")
    F = []
    check_schema(record, path, F)
    r.schema = F
    if not offline:
        r.verdicts = check_cve_package(record, cache, r.schema)
    return r


def download_pr(pr, repo, dest: Path):
    """Use gh to fetch a PR's changed advisories/*.json into dest."""
    files = subprocess.check_output(
        ["gh", "pr", "view", str(pr), "--repo", repo, "--json", "files",
         "-q", ".files[].path"], text=True).splitlines()
    branch = subprocess.check_output(
        ["gh", "pr", "view", str(pr), "--repo", repo, "--json", "headRefName",
         "-q", ".headRefName"], text=True).strip()
    n = 0
    for f in files:
        if not f.strip() or not f.endswith(".json"):
            continue
        content = subprocess.check_output(
            ["gh", "api", f"repos/{repo}/contents/{f}?ref={branch}", "-q", ".content"], text=True)
        import base64
        (dest / os.path.basename(f)).write_bytes(base64.b64decode(content))
        n += 1
    return n


def print_summary(results):
    by = {}
    for r in results:
        by.setdefault(r.status, []).append(r)
    print(f"\n{'=' * 72}\nLightwell OSV Validation — {len(results)} file(s)\n{'=' * 72}")
    for s in ("OK", "OK_WITH_WARNINGS", "NEEDS_REVIEW", "MISATTRIBUTED", "ERROR"):
        if by.get(s):
            print(f"  {s:<18} {len(by[s])}")
    print()
    order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    for r in results:
        if r.status == "OK":
            continue
        print(f"--- {r.path.name}  [{r.status}]  id={r.record_id!r}")
        if r.load_error:
            print(f"    LOAD ERROR: {r.load_error}")
        for f in sorted(r.schema, key=lambda f: order[f.level]):
            print(f"    [{f.level}] {f.code}: {f.message}")
        for v in r.verdicts:
            if v.verdict not in ("CONFIRMED", "CONFIRMED_TEXTUAL"):
                print(f"    [{v.verdict}] {v.cve_id} vs {v.package_name}: {v.evidence}")
        print()


def write_json(results, out):
    payload = [{
        "file": r.path.name, "id": r.record_id, "status": r.status,
        "load_error": r.load_error or None,
        "schema_findings": [vars(f) for f in r.schema],
        "cve_verdicts": [vars(v) for v in r.verdicts],
    } for r in results]
    Path(out).write_text(json.dumps(payload, indent=2), "utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input-dir", help="directory of *.json OSV advisories")
    ap.add_argument("--pr", type=int, help="GitHub PR number to fetch changed advisories from (needs gh)")
    ap.add_argument("--repo", default="project-lightwell/lightwell-osv", help="owner/repo for --pr")
    ap.add_argument("--glob", default="*.json")
    ap.add_argument("--offline", action="store_true", help="schema checks only; no network")
    ap.add_argument("--json-report", help="write machine-readable JSON here")
    ap.add_argument("--cache-dir", help=f"HTTP cache dir (default: <input>/{CACHE_SUBDIR})")
    args = ap.parse_args(argv)

    tmp = None
    if args.pr:
        tmp = Path(tempfile.mkdtemp(prefix=f"lw-pr{args.pr}-"))
        try:
            n = download_pr(args.pr, args.repo, tmp)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"error: could not fetch PR #{args.pr} via gh: {e}", file=sys.stderr)
            return 2
        print(f"Fetched {n} advisory file(s) from {args.repo} PR #{args.pr} into {tmp}")
        input_dir = tmp
    elif args.input_dir:
        input_dir = Path(args.input_dir)
    else:
        ap.error("one of --input-dir or --pr is required")

    if not input_dir.is_dir():
        print(f"error: {input_dir} is not a directory", file=sys.stderr)
        return 2
    files = sorted(input_dir.glob(args.glob))
    if not files:
        print(f"error: no files matching {args.glob!r} in {input_dir}", file=sys.stderr)
        return 2

    cache = HttpCache(Path(args.cache_dir) if args.cache_dir else input_dir / CACHE_SUBDIR)
    mode = "offline, schema-only" if args.offline else "schema + CVE/package"
    print(f"Validating {len(files)} file(s) in {input_dir} ({mode})...")
    results = []
    for i, p in enumerate(files, 1):
        print(f"  [{i}/{len(files)}] {p.name}", file=sys.stderr, end="\r")
        results.append(process_file(p, cache, args.offline))
    print(file=sys.stderr)

    print_summary(results)
    if args.json_report:
        write_json(results, args.json_report)
        print(f"JSON report written to {args.json_report}")

    return 1 if any(r.status in ("ERROR", "MISATTRIBUTED") for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
