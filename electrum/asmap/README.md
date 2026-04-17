# ASMap

This directory ships a binary ASMap (`asmap.dat`) used by Electrum's
`Network` to diversify peer selection by Autonomous System Number
rather than by IP prefix. See `electrum/asmap/__init__.py` for the
decoder and `electrum/interface.py:bucket_based_on_ipaddress` for the
consumer.

## Format

Identical to Bitcoin Core's `-asmap=` format. See:

- <https://asmap.org/>
- <https://github.com/bitcoin/bitcoin/tree/master/contrib/asmap>

Using the same file format means auditors can byte-compare the
`asmap.dat` shipped by Electrum against the published artifact at
asmap.org for the same generation date.

## Files

| File        | Purpose |
|-------------|---------|
| `asmap.dat` | Compact binary prefix-tree file. Loaded at runtime. |
| `asmap.json`| Metadata: generation date, source URL, sha256. Advisory. |
| `README.md` | This file. |

If `asmap.dat` is absent (e.g. a stripped dev checkout), Electrum
falls back to the legacy `/16`/`/48` IP-prefix bucketing with an
`INFO`-level log line. There is no hard dependency on the file.

## Regenerating for a release

1. Download a recent MRT routing-table dump (e.g. from RIPE RIS or
   RouteViews).
2. Run Bitcoin Core's `contrib/asmap/asmap.py` builder against the
   dump to produce a new `asmap.dat`.
3. Sanity-check: size should be a few MiB, sha256 recorded, spot-check
   a handful of well-known IPs (`8.8.8.8` → `AS15169`,
   `1.1.1.1` → `AS13335`, etc.) with `ASMap.lookup_asn`.
4. Update `asmap.json` with the new sha256, size, `generated_at`,
   `source_url`, `source_commit`.
5. Commit both files as part of the release-prep branch.

Regenerate roughly once per minor release. Staleness only means a
recently-renumbered prefix falls through to the `/16`/`/48` fallback —
it is not a security or correctness concern.
