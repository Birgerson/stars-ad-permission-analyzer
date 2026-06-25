# ADR 0017 — Share scan preserves the NULL-DACL semantics

**Status:** Accepted  
**Date:** 2026-05-24

## Context

Since ADR 0010, `get_share_dacl` correctly distinguishes between
`ShareDacl::NullDacl` (no access restriction — full access for everyone)
and `ShareDacl::Acl(vec![])` (an existing empty DACL — no access). The
distinction is essential for audits:

- A NULL DACL is often a misconfiguration (full access for everyone over
  SMB) — it must be visible in reporting.
- An empty DACL, by contrast, is a deliberate "no access".

The combined entry point `scan_shares`, however, called
`get_share_permissions`, which flattens `ShareDacl::NullDacl` into an
empty `Vec<SharePermission>` — after which the flat
`ShareScanResult.permissions` field could no longer distinguish whether a
share has no restriction or effectively allows no access.

See review finding 7.

## Decision

1. **`ShareScanResult` additionally carries a structured field**

   ```rust
   pub struct ShareScanResult {
       pub shares: Vec<Share>,
       pub permissions: Vec<SharePermission>,
       pub errors: Vec<ShareScanError>,
       pub share_dacls: Vec<(String, ShareDacl)>,
   }
   ```

   `share_dacls` contains, for every successfully read share, its
   `ShareDacl` status. For audits, `share_dacls` is the authoritative
   source; `permissions` remains as a flat-aggregated convenience for
   callers that do not need per-share resolution.

2. **`scan_shares` calls `get_share_dacl` directly** instead of
   `get_share_permissions`. For each share:

   - `Ok(dacl)` → `(name, dacl)` goes into `share_dacls`; for
     `Acl(perms)`, `perms` is additionally flat-aggregated into
     `permissions`.
   - `Err(e)` → into `errors` as before.

   `null_dacl_shares` is counted in the completion log — operators thus
   see directly how many shares are unrestricted.

3. **`ShareDacl` derives `Clone`** so the value can be both stored in
   `share_dacls` and used for flat aggregation.

4. **`get_share_permissions` stays unchanged** as a convenient path for
   callers that do not care about the NULL/empty distinction. Since
   ADR 0010 its docstring already points to `get_share_dacl` for the
   strict case.

## Rationale

- **Minimally invasive:** existing callers of `ShareScanResult`
  (internal: tests; external: none in production) see the new field as an
  addition — no breakage.
- **Audit correctness takes precedence** (AGENTS.md base rule 1) — a
  share with full access for everyone must not be persisted/exported in
  the same form as "no access".
- **Consistency with the FSO path:** on the NTFS side,
  `FileSystemObject.null_dacl` already carries the distinction; the share
  side now follows.

## Consequences

- 3 new tests in `share_scanner::scanner::tests`:
  - `scan_shares_records_dacl_status_for_every_successful_share`
  - `permissions_equals_flattened_acl_entries_from_share_dacls`
  - `null_dacl_distinguishable_from_empty_acl_in_share_dacls`
    (synthetic construction test that proves the structural distinction
    and sends both cases through `effective_share_mask`:
    `NullDacl → None`, `Acl([]) → Some(0)`).
- No schema change — `share_dacls` lives only in the in-memory result.
  If per-share persistence is wanted later, it can build on this.
- ADR 0010 remains valid; ADR 0017 extends the NULL/empty distinction to
  the combined scan path.
