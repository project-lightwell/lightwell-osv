# Red Hat Lightwell — OSV security advisories

This repository is the public **home database** for [Red Hat Lightwell](https://www.redhat.com)
security advisories in the [OSV](https://ossf.github.io/osv-schema/) format. It is the
source that [osv.dev](https://osv.dev) ingests for Lightwell records.

Red Hat Lightwell is an automated vulnerability-remediation service that produces
patched, verified builds of open source libraries. Each advisory here describes a
vulnerability remediated by Lightwell and the patched release that fixes it.

## Layout

```
advisories/<ADVISORY-ID>.json
```

- One OSV record per file, named after its advisory id.
- Advisory ids use the registered **`RHLW-`** prefix (`RHLW-YYYY-NNNNN`), reserved in
  [ossf/osv-schema](https://github.com/ossf/osv-schema) (PR #571).
- Records use the **`Red Hat Lightwell`** OSV ecosystem (e.g. `Red Hat Lightwell:Maven`),
  defined in osv-schema, alongside a plain-ecosystem entry (`Maven`, `PyPI`, …) with a
  versionless PURL for broad scanner matching.
- Upstream CVEs are referenced via the OSV `upstream` field.

## Consuming this data

Point OSV-compatible tooling at the records under `advisories/`, or query them via
[osv.dev](https://osv.dev) once ingestion is enabled. Match on the affected package
`ecosystem` + `name` and use the `fixed` version to identify the remediated release.

## Status

This feed is being populated by the Lightwell pipeline. Advisories will appear under
`advisories/` as remediations are released.

## Notes

The authoritative schema is the public [OSV Schema](https://ossf.github.io/osv-schema/);
this repository follows it and may add optional fields per the specification.
