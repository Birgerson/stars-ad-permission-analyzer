# ADR 0026 — `ShareScanResult.share_dacls` carries `ShareDaclScan`

**Status:** Accepted  
**Date:** 2026-05-25

## Context

ADR 0024 introduced `ShareDaclScan { dacl, unsupported_count }` as the
return type of `get_share_dacl`, so that the CLI/GUI per-path flow can pass
the per-share audit diagnostic through to the engine.

`scan_shares` (the aggregate function over all shares of a server) also
received this information, but the field `ShareScanResult.share_dacls`
remained `Vec<(String, ShareDacl)>`. The `unsupported_count` thus flowed
only into the completion log (as `unsupported_share_aces_total`) and was
then discarded per share.

Consequence for consumers that use the full `scan_shares` result instead of
the per-path path: they could see the aggregate, but not decide **which**
share counts as `incomplete` because of unevaluated ACE types.

Review 2026-05-25, finding 2 (Medium).

## Decision

**`ShareScanResult.share_dacls` is now `Vec<(String, ShareDaclScan)>`.**
Per share, the complete `ShareDaclScan` (DACL + unsupported count) goes into
the result — no data is lost at the aggregation boundary anymore.

The call site in `scan_shares` no longer pushes `(share.name, scan.dacl)`
but `(share.name, scan)`. The aggregating `unsupported_share_aces_total`
log remains as an operational quick overview.

## Rationale

- **Single source of truth**: per share there is now exactly one place
  where all relevant audit data lives — the caller's view is uniform,
  whether they use `get_share_dacl` (one share) or `scan_shares` (all
  shares).
- **Prevent data loss**: audit diagnostics that the parser collects must
  not get lost at the aggregation boundary.
- **Small breakage**: per grep, the field was consumed only in the
  `share_scanner` crate's own tests. There are no external consumers.

## Consequences

- 1 new test in `share_scanner::scanner::tests`:
  `share_dacls_field_preserves_per_share_unsupported_count` — constructs a
  `ShareScanResult` with `unsupported_count: 7` and checks that the value
  stays accessible through storage in `share_dacls`.
- Two existing tests rewritten so they construct the new `ShareDaclScan`
  tuple or match `&scan.dacl` instead of `dacl`:
  - `permissions_equals_flattened_acl_entries_from_share_dacls`
  - `null_dacl_distinguishable_from_empty_acl_in_share_dacls`
- No API breaks outside the crate (no external consumer).
- No schema or persistence impact — `share_dacls` lives only in-memory in
  `ShareScanResult`.
