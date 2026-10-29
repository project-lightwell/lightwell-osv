# Consuming Red Hat Lightwell Security Data on OSV.dev

## 1. Overview

**Red Hat Lightwell** is an automated vulnerability-remediation service. It takes a known-vulnerable
open source library from its upstream source (for example `com.fasterxml.woodstox:woodstox-core` `6.0.3`
from Maven Central), backports the official upstream security fix, and republishes the result as a new,
drop-in compatible build with an `.rhlw-NNNNN` version suffix (for example `6.0.3.rhlw-00001`).

For every remediated release, Lightwell publishes a machine-readable **security advisory in
[OSV format](https://ossf.github.io/osv-schema/)** — one record per release under
[`advisories/<ADVISORY-ID>.json`](https://github.com/project-lightwell/lightwell-osv/tree/main/advisories)
in **https://github.com/project-lightwell/lightwell-osv**. These advisories are the subject of this guide.

This guide shows you how to read a Lightwell record, query the data (from the repository and via the
OSV.dev API), determine whether a given build fixes a specific CVE, and resolve the "upstream false
positive" that affects **all** downstream rebuilds.

**Who this is for:** security engineers, platform teams, and SCA tooling integrators who consume
Lightwell remediated packages and need authoritative "is this fixed?" data.

### The one thing to know first

> Records use scoped ecosystems (`Red Hat Lightwell:Maven`, `Red Hat Lightwell:PyPI`, …), not plain
> `Maven`/`PyPI`, so a standard `pkg:maven/...` query will **not** find them — you must query the
> scoped ecosystem explicitly (§4). Examples below use Maven throughout; substitute the ecosystem name,
> package coordinate, and PURL type for other ecosystems.

---

## 2. Where to get the data

### 2.1 Directly from the Git repository

Every advisory is a plain JSON file you can fetch, clone, or vendor into your own tooling:

```bash
# Clone the whole advisory database
git clone https://github.com/project-lightwell/lightwell-osv.git

# Or fetch a single advisory by ID
curl -s https://raw.githubusercontent.com/project-lightwell/lightwell-osv/main/advisories/RHLW-2026-403d1e66c95ef9bb.json
```

Records live under `advisories/<ADVISORY-ID>.json` (one file per remediated release). This is the
authoritative source and works with any OSV-compatible tool that can read a local directory of records.

### 2.2 Via the OSV.dev API

The Lightwell feed is **registered as an OSV.dev data source**, so the advisories are queryable through
the standard OSV.dev API and website using the scoped `Red Hat Lightwell:*` ecosystems. Browse them at
<https://osv.dev/list?ecosystem=Red+Hat+Lightwell>, or query the API as shown in §4.

---

## 3. Anatomy of a Lightwell OSV record

Below is a complete, **real** advisory taken verbatim from the repository —
[`RHLW-2026-403d1e66c95ef9bb.json`](https://github.com/project-lightwell/lightwell-osv/blob/main/advisories/RHLW-2026-403d1e66c95ef9bb.json),
the `woodstox-core 6.0.3.rhlw-00001` release that backports the fix for **CVE-2022-40152**.

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
    { "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-40152", "type": "ADVISORY" },
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
| `references` | Links to the upstream advisory, vendor page, fix, and report — typed `ADVISORY`, `WEB`, `REPORT`, `FIX`. |
| `summary` / `details` | Human-readable description of the release and each CVE it fixes. |
| `upstream` | **The CVEs (and their GHSA IDs) that this release fixes** — the link from the Lightwell advisory to the upstream vulnerabilities. A multi-CVE release lists them all here. |
| `affected[].package.ecosystem` | A scoped `Red Hat Lightwell:*` ecosystem (e.g. `Red Hat Lightwell:Maven`, `Red Hat Lightwell:PyPI`) — see §4. |
| `affected[].package.name` | The package coordinate (for Maven, `groupId:artifactId`). |
| `affected[].package.purl` | A **versionless** PURL for package identification. Version data lives in `ranges`/`versions`. |
| `affected[].ranges[].events.introduced` | Start of the affected range, **inclusive**. Either `"0"` or the advisory's `backport_base_version`. The base version scopes the advisory to its own base-version line; `"0"` is used for the lowest branch, where builds below the base still need this advisory. |
| `affected[].ranges[].events.fixed` | **The Lightwell build that contains the fix** (e.g. `6.0.3.rhlw-00001`), **exclusive**. With `introduced` it bounds one base-version line: versions from `introduced` up to (not including) this build are affected; this build and above are fixed. |
| `affected[].versions` | Explicit enumeration of affected upstream base version(s) as a matching safety net. The repository file lists the base version(s); the OSV.dev API expands this via version enrichment, so expect more entries there. |
| `affected[].database_specific.lightwell` | Lineage: `backport_base_version` (upstream version patched), `remediated_version` (fixed Lightwell build), `repository_url` (download location). |
| `credits` | Attribution — `Red Hat Lightwell` as the `REMEDIATION_DEVELOPER`. |

A single release can bundle several fixes — they all appear in that record's `upstream` array. See
[`RHLW-2026-25544e781d50b856.json`](https://github.com/project-lightwell/lightwell-osv/blob/main/advisories/RHLW-2026-25544e781d50b856.json)
(`spring-expression 5.3.18.rhlw-00010`) for a release that backports seven CVEs in one record.

---

## 4. Querying Lightwell data

### 4.1 Why standard PURL queries don't work

Lightwell builds do not exist on Maven Central — `6.0.3.rhlw-00001` is a Red Hat artifact, not an
upstream one. Publishing it under `ecosystem: "Maven"` would misrepresent where the version is
available and generate false positives for everyone querying upstream Maven versions. So, like every
downstream rebuild vendor, Lightwell uses a **scoped ecosystem**: `Red Hat Lightwell:Maven`.

Consequence: a plain Maven query returns only **upstream** records, which still flag the Lightwell
build as vulnerable (the upstream fix is at a higher version, e.g. `6.4.0` for CVE-2022-40152):

```bash
# Standard query — DOES NOT return the Lightwell advisory
curl -s -X POST https://api.osv.dev/v1/query \
  -d '{"package": {"purl": "pkg:maven/com.fasterxml.woodstox/woodstox-core"},
       "version": "6.0.3.rhlw-00001"}'
# -> returns upstream GHSA-3f7h-mf4q-vrm4 reporting the version as "affected" (a false positive)
```

### 4.2 OSV.dev API

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

- Query the **un-remediated base version** (here `6.0.3`) → the advisory **is returned** → that version
  is still affected; upgrade to the `fixed` build.
- Query a fixed build and above → **no advisory for that line** → that line is remediated.

> **Interpreting the response.** An empty response means not affected. A *returned* advisory does not
> automatically mean your build is vulnerable: Lightwell remediates a CVE on several base-version
> branches, and the lowest branch uses `introduced: "0"`, so a query for an intermediate build can match
> a **higher** branch's advisory. Compare the returned advisory's `backport_base_version` to your build's
> base-version line — if your own line's advisory lists the CVE as `fixed` at or below your build, a
> match from a different branch is a cross-branch false positive (§6).

To pull one advisory by ID directly:

```bash
curl -s https://api.osv.dev/v1/vulns/RHLW-2026-403d1e66c95ef9bb
```

### 4.3 Directly from the repository

You can answer the same questions against the raw records — handy for air-gapped environments,
vendoring, or a local clone. Over a full clone, "does Lightwell fix CVE-X anywhere?" is a one-liner:

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

The OSV.dev query API is indexed by **package**, not by CVE, so a CVE-first lookup takes two calls:
first resolve the affected package from the CVE, then ask the Lightwell ecosystem about that package.

```bash
# Step 1 — the CVE record aliases to a GHSA that carries the Maven coordinate
GHSA=$(curl -s https://api.osv.dev/v1/vulns/CVE-2022-40152 | jq -r '.aliases[] | select(startswith("GHSA"))' | head -1)
curl -s https://api.osv.dev/v1/vulns/$GHSA \
  | jq -r '[.affected[].package | select(.ecosystem=="Maven") | .name] | unique[]'
# -> com.fasterxml.woodstox:woodstox-core

# Step 2 — ask the Lightwell ecosystem for every advisory on that package, filtered to the CVE
curl -s -X POST https://api.osv.dev/v1/query \
  -d '{"package": {"name": "com.fasterxml.woodstox:woodstox-core",
                   "ecosystem": "Red Hat Lightwell:Maven"}}' \
  | jq '.vulns[] | select(any(.upstream[]?; . == "CVE-2022-40152"))
                 | {id,
                    fixed: (.affected[0].ranges[0].events[] | select(.fixed).fixed),
                    base: .affected[0].database_specific.lightwell.backport_base_version,
                    download: .affected[0].database_specific.lightwell.repository_url}'
```

Omitting `version` in step 2 returns **all** advisories for the package, so you see every base-version
branch that remediates the CVE. Pick the one whose `backport_base_version` matches the upstream version
you depend on, then pin that fixed build in your `pom.xml` and resolve it from the Lightwell repository (§7).

> **Why two steps:** OSV.dev has no "find advisories that list CVE-X in `upstream`" endpoint, and a CVE
> record does not back-reference the downstream advisories that remediate it. The package pivot above is
> the OSV-native way around this. (Against a local clone, the `advisories/*.json` scan in §4.3 answers
> the same question in one pass.)

### Use case B — "I'm running package Y at version V. Is it safe?"

Given a Lightwell build you depend on, query your installed version in the scoped ecosystem:

```bash
curl -s -X POST https://api.osv.dev/v1/query \
  -d '{"package": {"name": "com.fasterxml.woodstox:woodstox-core",
                   "ecosystem": "Red Hat Lightwell:Maven"},
       "version": "6.0.3.rhlw-00001"}'
```

- **No advisory returned** → your build is at or above the fix for its line → not affected.
- **An advisory returned** → check its `backport_base_version` (§4.2). If it is your own base-version
  line and `fixed` is above your build, upgrade. If it is a *higher* branch (its `introduced` is `"0"`)
  while your own line's advisory already fixes the CVE at or below your build, it is a cross-branch
  false positive — resolve it against your line's record (§6).

---

## 6. Resolving the upstream false positive

### 6.1 Why it happens

When an SCA scanner inspects your project it builds a PURL from your build metadata — for Maven, reading
`pom.xml` / `META-INF/maven/**/pom.properties` to construct e.g.
`pkg:maven/com.fasterxml.woodstox/woodstox-core@6.0.3.rhlw-00001`. It does **not** know the artifact
came from Lightwell, so it matches the **upstream** database (GHSA, NVD). The upstream record says
CVE-2022-40152 is fixed in `6.4.0` — and `6.0.3.rhlw-00001 < 6.4.0` — so the scanner reports the CVE as
affected even though the fix is backported into your build. This is the inherent tradeoff of scoped
ecosystems and affects every downstream rebuild (§4.1).

### 6.2 The fix: detect Lightwell content and re-query the ecosystem

A scanner (or your own OSV tooling) resolves the false positive by:

1. **Detecting Lightwell content** — most reliably from the `.rhlw-NNNNN` version suffix.
2. **Re-querying the scoped ecosystem** for the same package and installed version (§4.2).
3. **Interpreting the result** per §4.2 / Use case B — no match for your line means the upstream finding
   is a false positive for your build.

This is the same "match against the vendor ecosystem" pattern scanners like Trivy, Grype, and ACS
already use for RPM/APK OS packages (RHEL, AlmaLinux, Chainguard), applied to `Red Hat Lightwell:*`.

### 6.3 Tool support (as of 2026-10)

| Tool | Consumes OSV.dev | Detect-and-re-query | How to get a correct result today |
|---|---|---|---|
| Your own OSV tooling | Yes (repo clone or API) | You implement it | Follow §6.2 / Use case A directly |
| osv-scanner | Yes (primary) | Not yet | Query the scoped ecosystem directly (Use case A/B) |
| ACS (Red Hat Advanced Cluster Security) | Yes (data feed) | Not yet | Automatic once ACS adds Lightwell detection (feed is already on OSV.dev) |
| Trivy / Grype | Aggregated DB (GHSA/NVD) | Not for Maven | Cross-check findings against the scoped ecosystem (Use case B) |

---

## 7. Adding a Lightwell dependency

Pin the remediated build and point the build tool at the Lightwell repository. For Maven, declare the
repository in a `settings.xml` profile (a bare `<repository>` is not valid at the top level) or in your
`pom.xml`; the repository requires authentication, so add a matching `<server>` credentials block.

```xml
<!-- pom.xml -->
<dependency>
  <groupId>com.fasterxml.woodstox</groupId>
  <artifactId>woodstox-core</artifactId>
  <version>6.0.3.rhlw-00001</version>
</dependency>
```

```xml
<!-- settings.xml -->
<profiles>
  <profile>
    <id>lightwell</id>
    <repositories>
      <repository>
        <id>lightwell-remediated</id>
        <url>https://packages.redhat.com/lightwell/java/remediated/</url>
      </repository>
    </repositories>
  </profile>
</profiles>
<activeProfiles>
  <activeProfile>lightwell</activeProfile>
</activeProfiles>
<servers>
  <server>
    <id>lightwell-remediated</id>
    <username>${env.LIGHTWELL_USER}</username>
    <password>${env.LIGHTWELL_TOKEN}</password>
  </server>
</servers>
```

Confirm which CVEs the build fixes with the §4.3 query or Use case A; verify its status against the
scoped ecosystem with Use case B.

---

## 8. Frequently asked questions

**How is the advisory ID generated?**
`RHLW-YYYY-{16 hex digits}`, derived deterministically from the package coordinates and base version
(so each base-version branch gets its own stable ID — e.g. woodstox-core has three). It is stable,
collision-resistant, and used both as the record `id` and the filename. `RHLW` is a registered OSV
prefix ([ossf/osv-schema PR #571](https://github.com/ossf/osv-schema/pull/571)).

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
