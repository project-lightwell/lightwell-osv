# Consuming Red Hat Lightwell Security Data on OSV.dev

**A practical guide to Lightwell OSV advisories: structure, queries, and end-to-end usage**

Version 1.2 · 2026-10-27

---

## 1. Overview

**Red Hat Lightwell** is an automated vulnerability-remediation service. It takes a known-vulnerable
open source library from its upstream source (for example `com.fasterxml.woodstox:woodstox-core` `6.0.3`
from Maven Central), backports the official upstream security fix, and republishes the result as a new,
drop-in compatible build with an `.rhlw-NNNNN` version suffix (for example `6.0.3.rhlw-00001`).

For every remediated release, Lightwell publishes a machine-readable **security advisory in
[OSV format](https://ossf.github.io/osv-schema/)**. These advisories are the subject of this guide.
They live in the public repository:

> **https://github.com/project-lightwell/lightwell-osv** — one OSV record per file under
> [`advisories/<ADVISORY-ID>.json`](https://github.com/project-lightwell/lightwell-osv/tree/main/advisories)

This guide shows you how to:

- Read and interpret a Lightwell OSV record
- Query the data (directly from the repository and via the OSV.dev API)
- Determine whether a given Lightwell build fixes a specific CVE
- Integrate the data into your SCA scanning workflow (osv-scanner, Trivy, Grype, ACS)
- Understand and resolve the "upstream false positive" that affects **all** downstream rebuilds

### Who this is for

Security engineers, platform teams, and SCA tooling integrators who consume Lightwell
remediated packages and need authoritative "is this fixed?" data.

### The one thing to know first

Lightwell advisories are published under **dedicated, scoped OSV ecosystems** — `Red Hat Lightwell:Maven`
for Maven/Java, `Red Hat Lightwell:PyPI` for Python, and more as coverage grows — **not** the plain
`Maven` / `PyPI` ecosystems. This is the same approach every downstream rebuild vendor uses on OSV.dev
(Chainguard, Echo, Root, Red Hat, …).

> **Maven is only the running example in this guide.** Lightwell remediates packages across several
> ecosystems; `Red Hat Lightwell:Maven` is used throughout for concreteness, but every query pattern
> applies unchanged to the others — just substitute the ecosystem name, the package coordinate, and the
> PURL type (e.g. `Red Hat Lightwell:PyPI` with `pkg:pypi/<name>`).

It has one important consequence you must design for:

> A standard `pkg:maven/...` query will **not** return Lightwell records. You must query the
> `Red Hat Lightwell:Maven` ecosystem explicitly. Section 4 and Section 6 explain exactly how, and how
> to resolve the upstream false positives this creates.

---

## 2. Where to get the data

Lightwell OSV records are available through two channels.

### 2.1 Directly from the Git repository

Every advisory is a plain JSON file you can fetch, clone, or vendor into your own tooling:

```bash
# Clone the whole advisory database
git clone https://github.com/project-lightwell/lightwell-osv.git

# Or fetch a single advisory by ID
curl -s https://raw.githubusercontent.com/project-lightwell/lightwell-osv/main/advisories/RHLW-2026-403d1e66c95ef9bb.json
```

Repository layout:

```
lightwell-osv/
├── README.md
└── advisories/
    ├── RHLW-2026-403d1e66c95ef9bb.json   # woodstox-core 6.0.3.rhlw-00001
    ├── RHLW-2026-25544e781d50b856.json   # spring-expression 5.3.18.rhlw-00010
    ├── RHLW-2026-1da18ff8e343fdf8.json   # org.json:json 20220320.0.0.rhlw-00003
    └── ...
```

This is the authoritative source and works with any OSV-compatible tool that can be pointed at a local
directory of records, or with your own ingestion pipeline.

### 2.2 Via the OSV.dev API

The Lightwell feed is **registered as an OSV.dev data source**, so the advisories are queryable through
the standard OSV.dev API and website using the scoped `Red Hat Lightwell:*` ecosystems (e.g.
`Red Hat Lightwell:Maven`). Browse them at
<https://osv.dev/list?ecosystem=Red+Hat+Lightwell>, or query the API as shown in §4.

---

## 3. Anatomy of a Lightwell OSV record

Below is a complete, **real** advisory taken verbatim from the repository —
[`RHLW-2026-403d1e66c95ef9bb.json`](https://github.com/project-lightwell/lightwell-osv/blob/main/advisories/RHLW-2026-403d1e66c95ef9bb.json),
the `woodstox-core 6.0.3.rhlw-00001` release that backports the fix for **CVE-2022-40152** — annotated
field by field.

```json
{
  "schema_version": "1.9.0",
  "id": "RHLW-2026-403d1e66c95ef9bb",
  "published": "2026-10-08T19:45:11Z",
  "modified": "2026-10-27T21:27:53Z",
  "severity": [
    { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" }
  ],
  "references": [
    { "url": "https://github.com/CVEProject/cvelistV5/tree/main/cves/2022/40xxx/CVE-2022-40152.json", "type": "ADVISORY" },
    { "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-40152", "type": "ADVISORY" },
    { "url": "https://github.com/x-stream/xstream/issues/304", "type": "REPORT" },
    { "url": "https://github.com/advisories/GHSA-3f7h-mf4q-vrm4", "type": "ADVISORY" }
  ],
  "summary": "Lightwell Security Advisory: woodstox-core 6.0.3.rhlw-00001",
  "details": "Red Hat Lightwell has released com.fasterxml.woodstox:woodstox-core 6.0.3.rhlw-00001 with a backported security fix.\n\nCVE-2022-40152: Stack Buffer Overflow in Woodstox\n\nThis patched artifact is a drop-in replacement for com.fasterxml.woodstox:woodstox-core 6.0.3 from Maven Central.",
  "upstream": [
    "CVE-2022-40152",
    "GHSA-3f7h-mf4q-vrm4"
  ],
  "affected": [
    {
      "package": {
        "ecosystem": "Red Hat Lightwell:Maven",
        "name": "com.fasterxml.woodstox:woodstox-core",
        "purl": "pkg:maven/com.fasterxml.woodstox/woodstox-core"
      },
      "versions": ["6.0.3"],
      "ranges": [
        {
          "type": "ECOSYSTEM",
          "events": [
            { "introduced": "6.0.3" },
            { "fixed": "6.0.3.rhlw-00001" }
          ]
        }
      ],
      "database_specific": {
        "lightwell": {
          "backport_base_version": "6.0.3",
          "remediated_version": "6.0.3.rhlw-00001",
          "repository_url": "https://packages.redhat.com/lightwell/java/remediated/"
        }
      }
    }
  ],
  "credits": [
    { "name": "Red Hat Lightwell", "type": "REMEDIATION_DEVELOPER" }
  ]
}
```

### Field reference

| Field | Meaning for a consumer |
|---|---|
| `id` | The Lightwell advisory ID. Format: `RHLW-YYYY-{16 hex digits}`. One advisory = one `.rhlw-NNNNN` release. The ID is stable and also the filename. |
| `published` / `modified` | When the advisory was first issued and last changed (RFC 3339 timestamps). |
| `severity` | CVSS vector(s) for the bundled vulnerabilities. |
| `references` | Links to the upstream advisory, vendor page, fix, and report — typed `ADVISORY` (NVD, GHSA, CVE List), `WEB`, `REPORT`, `FIX`. |
| `summary` / `details` | Human-readable description of the release and each CVE it fixes. |
| `upstream` | **The CVEs (and their GHSA IDs) that this release fixes.** This is the link from the Lightwell advisory to the upstream vulnerabilities. A multi-CVE release lists them all here. |
| `affected[].package.ecosystem` | Always `Red Hat Lightwell:Maven` (scoped ecosystem — see §4). |
| `affected[].package.name` | The Maven coordinate `groupId:artifactId`. |
| `affected[].package.purl` | A **versionless** PURL for package identification (`pkg:maven/group/name`). Version data lives in `ranges`/`versions`. |
| `affected[].ranges[].events.introduced` | Start of the affected range, **inclusive**. Normally the advisory's `backport_base_version`, which scopes the advisory to its own base-version line so that a build remediated on a *different* line is not reported. `"0"` is used where lower builds on the same package still need this advisory. |
| `affected[].ranges[].events.fixed` | **The Lightwell build that contains the fix** (e.g. `6.0.3.rhlw-00001`), **exclusive**. Together with `introduced` it bounds one base-version line: versions from `introduced` up to (but not including) this build are affected; this build and above are fixed. |
| `affected[].versions` | Explicit enumeration of affected upstream base version(s) as a matching safety net. The repository file lists the base version(s); when served via the OSV.dev API this list is expanded by OSV.dev's version enrichment, so expect more entries there. |
| `affected[].database_specific.lightwell` | Lineage: `backport_base_version` (the upstream version patched), `remediated_version` (the fixed Lightwell build), and `repository_url` (where to download it). |
| `credits` | Attribution — `Red Hat Lightwell` as the `REMEDIATION_DEVELOPER`. |

### A release that fixes multiple CVEs

A single `.rhlw-NNNNN` release can bundle several fixes. They all appear in one record's `upstream`
array. A real example is
[`RHLW-2026-25544e781d50b856.json`](https://github.com/project-lightwell/lightwell-osv/blob/main/advisories/RHLW-2026-25544e781d50b856.json)
— `org.springframework:spring-expression 5.3.18.rhlw-00010`, which backports **seven** CVEs in one
release:

```json
{
  "schema_version": "1.9.0",
  "id": "RHLW-2026-25544e781d50b856",
  "summary": "Lightwell Security Advisory: spring-expression 5.3.18.rhlw-00010",
  "upstream": [
    "CVE-2023-20860", "CVE-2025-41249", "CVE-2024-38816", "CVE-2024-22243",
    "CVE-2024-38808", "CVE-2023-20863", "CVE-2023-20861",
    "GHSA-7phw-cxx7-q9vq", "GHSA-jmp9-x22r-554x", "GHSA-cx7f-g6mp-7hqm",
    "GHSA-ccgv-vj62-xf9h", "GHSA-9cmq-m9j5-mvww", "GHSA-wxqc-pxw9-g2p8", "GHSA-564r-hj7v-mcr5"
  ],
  "affected": [{
    "package": {
      "ecosystem": "Red Hat Lightwell:Maven",
      "name": "org.springframework:spring-expression",
      "purl": "pkg:maven/org.springframework/spring-expression"
    },
    "versions": ["5.3.18"],
    "ranges": [{ "type": "ECOSYSTEM",
      "events": [{ "introduced": "0" }, { "fixed": "5.3.18.rhlw-00010" }] }],
    "database_specific": { "lightwell": {
      "backport_base_version": "5.3.18",
      "remediated_version": "5.3.18.rhlw-00010",
      "repository_url": "https://packages.redhat.com/lightwell/java/remediated/"
    }}
  }]
}
```

(The CVSS `severity`, `references`, `details`, and `credits` are present in the full record but trimmed
here for brevity — open the linked file for the complete advisory.)

---

## 4. Querying Lightwell data

### 4.1 Why standard PURL queries don't work

Lightwell builds do not exist on Maven Central — `6.0.3.rhlw-00001` is a Red Hat artifact, not an
upstream one. Publishing it under `ecosystem: "Maven"` would misrepresent where the version is
available and generate false positives for everyone querying upstream Maven versions. So, like every
downstream rebuild vendor, Lightwell uses a **scoped ecosystem**: `Red Hat Lightwell:Maven`.

Consequence: a plain Maven query returns only **upstream** records, which still flag the Lightwell
build as vulnerable (because the upstream fix is at a higher version, e.g. `6.4.0` for CVE-2022-40152):

```bash
# Standard query — DOES NOT return the Lightwell advisory
curl -s -X POST https://api.osv.dev/v1/query \
  -d '{"package": {"purl": "pkg:maven/com.fasterxml.woodstox/woodstox-core"},
       "version": "6.0.3.rhlw-00001"}'
# -> returns upstream GHSA-3f7h-mf4q-vrm4 reporting the version as "affected" (a false positive)
```

### 4.2 Querying the Lightwell ecosystem explicitly (OSV.dev API)

To find Lightwell advisories, query the scoped ecosystem by name:

```bash
curl -s -X POST https://api.osv.dev/v1/query \
  -d '{
    "package": {
      "name": "com.fasterxml.woodstox:woodstox-core",
      "ecosystem": "Red Hat Lightwell:Maven"
    },
    "version": "6.0.3"
  }'
```

- Query the **un-remediated base version** (here `6.0.3`) → the advisory **is returned**
  → that version is still affected; upgrade to the `fixed` build.
- Query the fixed build or higher (`6.0.3.rhlw-00001`) → **empty response** → not affected. In the
  OSV model, absence of a match against a vendor ecosystem is the authoritative "fixed" signal.

> Each advisory describes **one base-version line**. Query this ecosystem with Lightwell content —
> a `.rhlw-` build or the base version it was built from. Plain upstream releases are described by
> the upstream `Maven` / `PyPI` ecosystems, not here, so an empty response for an arbitrary
> upstream version means "not Lightwell content", not "not vulnerable".

To pull one advisory by ID directly:

```bash
curl -s https://api.osv.dev/v1/vulns/RHLW-2026-403d1e66c95ef9bb
```

### 4.3 Querying directly from the repository

You can also answer the same questions directly against the raw records — handy for air-gapped
environments, vendoring, or working from a local clone.

> **Note on `jq`:** inside a `{...}` object constructor, any value that uses a pipe (`|`) must be
> wrapped in parentheses, and testing an array for a value is done with `any(...)`. The queries below
> follow both rules and are verified against the published records.

Fetch one advisory and print its fixed version and the CVEs it covers:

```bash
curl -s https://raw.githubusercontent.com/project-lightwell/lightwell-osv/main/advisories/RHLW-2026-403d1e66c95ef9bb.json \
  | jq '{id,
         fixed: (.affected[0].ranges[0].events[] | select(.fixed) | .fixed),
         cves:  [.upstream[] | select(startswith("CVE"))]}'
```

```json
{
  "id": "RHLW-2026-403d1e66c95ef9bb",
  "fixed": "6.0.3.rhlw-00001",
  "cves": ["CVE-2022-40152"]
}
```

Over a full local clone, "does Lightwell fix CVE-X anywhere?" becomes a one-liner:

```bash
# Which advisory (if any) remediates CVE-2022-40152?
jq -r 'select(any(.upstream[]?; . == "CVE-2022-40152"))
       | "\(.id)  ->  \(.affected[0].package.name) fixed in \(.affected[0].ranges[0].events[] | select(.fixed).fixed)"' \
   advisories/*.json
# -> RHLW-2026-36d9ed0bb47c794f  ->  com.fasterxml.woodstox:woodstox-core fixed in 6.2.2.rhlw-00004
# -> RHLW-2026-403d1e66c95ef9bb  ->  com.fasterxml.woodstox:woodstox-core fixed in 6.0.3.rhlw-00001
# -> RHLW-2026-dd8ed0b211be109b  ->  com.fasterxml.woodstox:woodstox-core fixed in 5.0.3.rhlw-00001
```

> A single CVE can be remediated across **more than one base-version branch** (here woodstox `5.0.3`,
> `6.0.3`, and `6.2.2` each get their own remediated build and advisory). Pick the advisory whose
> `backport_base_version` matches the upstream version you depend on.

---

## 5. Typical use cases

### Use case A — "Does Lightwell fix CVE-X, and in which build?"

You have a CVE and want to know whether a remediated build exists, and in which version.

#### Primary — OSV.dev API (two steps)

The OSV.dev query API is indexed by **package**, not by CVE, so a CVE-first lookup takes two calls:
first resolve the affected package from the CVE, then ask the Lightwell ecosystem about that package.

```bash
# Step 1 — the CVE record aliases to a GHSA that carries the Maven coordinate
GHSA=$(curl -s https://api.osv.dev/v1/vulns/CVE-2022-40152 | jq -r '.aliases[] | select(startswith("GHSA"))')
curl -s https://api.osv.dev/v1/vulns/$GHSA \
  | jq -r '[.affected[].package | select(.ecosystem=="Maven") | .name] | unique[]'
# -> com.fasterxml.woodstox:woodstox-core
```

```bash
# Step 2 — ask the Lightwell ecosystem for every advisory on that package, filtered to the CVE
curl -s -X POST https://api.osv.dev/v1/query \
  -d '{"package": {"name": "com.fasterxml.woodstox:woodstox-core",
                   "ecosystem": "Red Hat Lightwell:Maven"}}' \
  | jq '.vulns[] | select(any(.upstream[]?; . == "CVE-2022-40152"))
                 | {id,
                    fixed: (.affected[0].ranges[0].events[] | select(.fixed).fixed),
                    download: .affected[0].database_specific.lightwell.repository_url}'
```

Omitting `version` in step 2 returns **all** advisories for the package, so you see every base-version
branch that remediates the CVE.

> **Why two steps:** OSV.dev has no "find advisories that list CVE-X in `upstream`" endpoint, and a CVE
> record does not back-reference the downstream advisories that remediate it. The package pivot above is
> the OSV-native way around this — see §8 for the full explanation.

#### Alternative — local clone (no API required)

Scan the records directly with the same `upstream` filter:

```bash
jq -r 'select(any(.upstream[]?; . == "CVE-2022-40152"))
       | "Advisory: \(.id)",
         "Package:  \(.affected[0].package.name)",
         "Fixed in: \(.affected[0].ranges[0].events[] | select(.fixed).fixed)",
         "Download: \(.affected[0].database_specific.lightwell.repository_url)"' \
   advisories/*.json
```

```
Advisory: RHLW-2026-36d9ed0bb47c794f
Package:  com.fasterxml.woodstox:woodstox-core
Fixed in: 6.2.2.rhlw-00004
Download: https://packages.redhat.com/lightwell/java/remediated/
Advisory: RHLW-2026-403d1e66c95ef9bb
Package:  com.fasterxml.woodstox:woodstox-core
Fixed in: 6.0.3.rhlw-00001
Download: https://packages.redhat.com/lightwell/java/remediated/
Advisory: RHLW-2026-dd8ed0b211be109b
Package:  com.fasterxml.woodstox:woodstox-core
Fixed in: 5.0.3.rhlw-00001
Download: https://packages.redhat.com/lightwell/java/remediated/
```

Either way, three advisories match because Lightwell remediated this CVE on the `5.0.3`, `6.0.3`, and
`6.2.2` base branches. Pick the one whose `backport_base_version` matches the upstream version you
depend on, then pin that fixed build in your `pom.xml` and resolve it from the Lightwell repository (§7.1).

### Use case B — "I'm running package Y at version V. Is it safe?"

Given a Lightwell build you already depend on, confirm it is not affected:

```bash
curl -s -X POST https://api.osv.dev/v1/query \
  -d '{"package": {"name": "com.fasterxml.woodstox:woodstox-core",
                   "ecosystem": "Red Hat Lightwell:Maven"},
       "version": "6.0.3.rhlw-00001"}'
# Empty response  ->  6.0.3.rhlw-00001 is at or above the fix  ->  NOT AFFECTED
```

If instead you were still on the un-remediated base version `6.0.3`, the advisory would be returned,
telling you to upgrade to `6.0.3.rhlw-00001`.

### Use case C — "Scan my project / SBOM and get a clean, accurate result"

This is the most common workflow and the one most affected by the upstream false-positive issue.
Because scanners construct a bare `pkg:maven/...` PURL from your build metadata, they query the
**upstream** Maven ecosystem and report the backported CVE as still open.

Getting a clean, accurate result from OSV data requires the scanner (or your own tooling) to **detect
that the package is Lightwell content** — most reliably from the `.rhlw-` version suffix — and then
query the `Red Hat Lightwell:Maven` ecosystem for the real status. That detection-and-re-query flow is
described in detail in §6.2.

---

## 6. Resolving the upstream false positive

This section is the heart of consuming Lightwell data correctly. Read it before wiring Lightwell into
any scanner.

### 6.1 Why the false positive happens

When an SCA scanner inspects your project, it builds a PURL from your build metadata. For a Maven
package, for example, it reads `pom.xml` / `META-INF/maven/**/pom.properties` and constructs a PURL
like `pkg:maven/com.fasterxml.woodstox/woodstox-core@6.0.3.rhlw-00001`. It does **not** know the
artifact came from Lightwell, so it matches against the **upstream** vulnerability database (GHSA,
NVD). The upstream record says CVE-2022-40152 is fixed in `6.4.0` — and `6.0.3.rhlw-00001 < 6.4.0` —
so the scanner reports the CVE as **affected**, even though the fix is backported into your build.

This is not a Lightwell quirk; it is the inherent tradeoff of scoped ecosystems and affects every
downstream rebuild (Chainguard, AlmaLinux, Red Hat, Echo, Root).

### 6.2 The resolution — Lightwell-aware detection and an ecosystem query

A scanner (or your own OSV tooling) resolves the false positive by recognizing that the package is
Lightwell content and issuing a **second, ecosystem-scoped query** to OSV.dev:

1. **Detect Lightwell content.** The most reliable signal is the **`.rhlw-NNNNN` version suffix**
   (e.g. `6.0.3.rhlw-00001`) → classify the package as Lightwell-remediated.
2. **Re-query the Lightwell ecosystem** for the same package and installed version:
   `{"name": "com.fasterxml.woodstox:woodstox-core", "ecosystem": "Red Hat Lightwell:Maven", "version": "6.0.3.rhlw-00001"}`.
3. **An empty response at your installed version = authoritatively not affected** → the upstream
   finding is a false positive and can be resolved against the Lightwell record.

This is exactly the "absence of match against the vendor ecosystem means fixed" pattern that scanners
like Trivy, Grype, and ACS already use for RPM/APK OS packages (RHEL, AlmaLinux, Chainguard) — the
same mechanism, applied to the `Red Hat Lightwell:Maven` ecosystem. It relies on the consuming tool
implementing the detect-and-re-query step against the Lightwell ecosystems on OSV.dev (§2.2).

### 6.3 Tool support today

| Tool | Consumes OSV.dev | Detect-and-re-query (§6.2) | How to get a correct result today |
|---|---|---|---|
| Your own OSV tooling | Yes (repo clone or API) | You implement it | Follow §6.2 / Use case A directly |
| osv-scanner | Yes (primary) | Not yet | Query the `Red Hat Lightwell:Maven` ecosystem directly (Use case A/B) |
| ACS (Red Hat Advanced Cluster Security) | Yes (data feed) | Not yet | Automatic once ACS adds Lightwell detection (the feed is already on OSV.dev) |
| Trivy / Grype | Aggregated DB (GHSA/NVD) | Not for Maven | Cross-check findings against the Lightwell ecosystem (Use case B) |

> **Bottom line:** the OSV records are the authoritative source for "which Lightwell build fixes what."
> Turning that into an automatically clean *scan* depends on the consuming tool detecting Lightwell
> content and querying the `Red Hat Lightwell:Maven` ecosystem (§6.2). Until a given scanner does this
> for you, use the ecosystem query in Use case A/B to verify status directly.

---

## 7. End-to-end example

A complete flow, from adding a Lightwell dependency to verifying its status in OSV data.

### 7.1 Add and resolve the remediated dependency

```xml
<!-- pom.xml -->
<dependency>
  <groupId>com.fasterxml.woodstox</groupId>
  <artifactId>woodstox-core</artifactId>
  <version>6.0.3.rhlw-00001</version>
</dependency>
```

```xml
<!-- settings.xml: point Maven at the Lightwell remediated repository -->
<repository>
  <id>lightwell-remediated</id>
  <url>https://packages.redhat.com/lightwell/java/remediated/</url>
</repository>
```

### 7.2 Confirm the remediation in Lightwell data

```bash
# Which CVEs does this build fix?
curl -s https://raw.githubusercontent.com/project-lightwell/lightwell-osv/main/advisories/RHLW-2026-403d1e66c95ef9bb.json \
  | jq '{fixed: (.affected[0].ranges[0].events[] | select(.fixed) | .fixed),
         cves:  [.upstream[] | select(startswith("CVE"))]}'
# { "fixed": "6.0.3.rhlw-00001", "cves": ["CVE-2022-40152"] }
```

### 7.3 Scan — observe the upstream false positive

```bash
trivy fs ./my-project
# Reports CVE-2022-40152 as affecting woodstox-core 6.0.3.rhlw-00001 (upstream GHSA — false positive)
```

The scanner queried the upstream `Maven` ecosystem (§6.1), so it cannot see that the fix is backported.

### 7.4 Verify the real status against the Lightwell ecosystem

Detect the `.rhlw-` suffix and re-query the Lightwell ecosystem for the installed version (§6.2):

```bash
curl -s -X POST https://api.osv.dev/v1/query \
  -d '{"package": {"name": "com.fasterxml.woodstox:woodstox-core",
                   "ecosystem": "Red Hat Lightwell:Maven"},
       "version": "6.0.3.rhlw-00001"}'
# Empty response  ->  the installed build is at/above the fix  ->  the upstream finding is a false positive
```

An empty response confirms `6.0.3.rhlw-00001` is not affected by CVE-2022-40152 — the Lightwell record
(§7.2) attributes the fix to exactly this build. Tooling that implements the detect-and-re-query step
(§6.2) performs this cross-check automatically; until your scanner does, this query is the
authoritative verification.

---

## 8. Frequently asked questions

**Why can't I find Lightwell records with a normal `pkg:maven/...` OSV query?**
Because they live in the scoped `Red Hat Lightwell:Maven` ecosystem, by design (§4.1). Query that
ecosystem by name (§4.2) to find them.

**Do the OSV records alone make my scan clean?**
Not automatically with today's off-the-shelf scanners. OSV records are the authoritative source for
which build fixes what, and the ecosystem query (Use case A/B) gives you the correct status directly.
A *scan* becomes automatically clean only when the consuming tool detects Lightwell content and
re-queries the scoped ecosystem (§6.2).

**Can I look up a Lightwell build directly from a CVE on OSV.dev?**
Not in one call. The OSV.dev query API is indexed by package, not by CVE, and a CVE record does not
back-reference the downstream advisories that remediate it (this is inherent to the `upstream` linking
model). Use the two-step package pivot in Use case A, or the local-clone scan.

**What does an empty OSV response for my version mean?**
For the `Red Hat Lightwell:Maven` ecosystem, empty = **not affected** (your version is at or above the
`fixed` build). This is the standard OSV semantics for vendor ecosystems.

**How is the advisory ID generated?**
`RHLW-YYYY-{16 hex digits}`, derived deterministically from the package coordinates. It is stable,
collision-resistant, and used both as the record `id` and the filename. `RHLW` is a registered OSV
prefix ([ossf/osv-schema PR #571](https://github.com/ossf/osv-schema/pull/571)).

**A release fixed several CVEs — are there multiple records?**
No. One release = one advisory = one record. All bundled CVEs are listed in the `upstream` array — see
the 7-CVE `spring-expression` example in §3.

**Where do I download the actual fixed artifact?**
From the `repository_url` in `database_specific.lightwell`:
`https://packages.redhat.com/lightwell/java/remediated/`, combined with the Maven coordinates and the
`remediated_version`.

---

## 9. Reference

| Resource | Link |
|---|---|
| Lightwell OSV advisory repository | https://github.com/project-lightwell/lightwell-osv |
| Advisories directory | https://github.com/project-lightwell/lightwell-osv/tree/main/advisories |
| Lightwell documentation | https://www.redhat.com/en/lightwell |
| OSV Schema specification | https://ossf.github.io/osv-schema/ |
| OSV.dev API documentation | https://google.github.io/osv.dev/api/ |
| OSV-Scanner | https://google.github.io/osv-scanner/ |
| PURL specification | https://github.com/package-url/purl-spec |

---

*Red Hat Lightwell — OSV security advisories. This guide describes how to consume Lightwell
remediation data; the advisory records themselves in
[`advisories/`](https://github.com/project-lightwell/lightwell-osv/tree/main/advisories) are the
authoritative source.*
