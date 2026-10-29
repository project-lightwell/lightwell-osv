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
- Advisory ids use the **`RHLW-`** prefix reserved in
  [ossf/osv-schema](https://github.com/ossf/osv-schema), in an opaque, semantically neutral
  form `RHLW-YYYY-<16 hex digits>` (e.g. `RHLW-2026-a1b2c3d4e5f6a7b8`).
- Records use the **`Red Hat Lightwell`** OSV ecosystem only (e.g. `Red Hat Lightwell:Maven`,
  `Red Hat Lightwell:PyPI`), defined in osv-schema. Lightwell-remediated versions do not
  exist in the upstream registries (Maven Central, PyPI), so records are scoped to the
  Red Hat Lightwell ecosystem and do not carry plain `Maven`/`PyPI` entries.
- Upstream CVEs are referenced via the OSV `upstream` field.
- [`tools/check_ranges.py`](tools/README.md) validates advisory changes between two git
  refs (range rules plus a simulated OSV query for false positives and negatives).

## Consuming this data

See the [Lightwell OSV data usage guide](docs/) for record structure, example
queries, and how to resolve upstream false positives.

Point OSV-compatible tooling at the records under `advisories/`, or query them via
[osv.dev](https://osv.dev), where this feed is ingested. Match on the affected package
`ecosystem` + `name` and use the `fixed` version to identify the remediated release.

## Status

This feed is actively maintained and is ingested by [osv.dev](https://osv.dev), where
the records are queryable under the `Red Hat Lightwell:*` ecosystems. New advisories are
added under `advisories/` by the Lightwell pipeline as remediations are released.

## Notes

The authoritative schema is the public [OSV Schema](https://ossf.github.io/osv-schema/);
this repository follows it and may add optional fields per the specification.

## License

The vulnerability advisory data in this repository (the OSV-format JSON under
`advisories/`) is licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — see [LICENSE](LICENSE).

This license covers the advisory data only. The Red Hat Lightwell software,
packages, and remediated build artifacts are a separate, commercially licensed
offering and are not covered by this license.
