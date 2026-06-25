# ADR 0038 — Share-DACL trustees in the scan output

**Status:** Accepted
**Date:** 2026-06-04

## Context

Review 2026-06-04 round 3 finding 3 (Medium): the scan path called
`build_path_trustees(&fso, None, None)` — the **NTFS-only** argument left
the share DACL outside the collected `path_trustees` and thus outside the
path-centric trustee table.

The HTML table, however, is labeled **"who can access this path at all"**
and even has a dedicated `TrusteeCategory::Share` column. For SMB analyses
this created a systematic discrepancy:

- **Risk view**: correctly accounts for Share ∩ NTFS; the effective finding
  can be "only Read" even though NTFS grants Modify.
- **Trustee view** (same report): shows only the NTFS Allow entries —
  Share-Deny, Share-Allow for broad groups, or a read-only share mask stay
  invisible.

This violates the memory rule "no silent skips" (Stars reports must explain
what they show and what they omit) as well as the audit promise "read-only
analysis explains completely".

## Decision

**Read the share DACL once per share** and attach it as an overlay to every
path under that share:

1. **New type `ShareTrusteeOverlay`** in the GUI worker:

   ```rust
   pub struct ShareTrusteeOverlay {
       pub trustees: Vec<PathTrustee>,  // all TrusteeCategory::Share
   }
   ```

2. **New function `read_share_overlay(server, share)`** reads the share
   DACL via `get_share_dacl` once and produces the `ShareTrusteeOverlay`.
   Read errors are rendered as a visible pseudo-row ("Share DACL not
   readable: …") — no silent skips.

3. **New helper `build_path_trustees_with_share(fso, overlay)`** takes an
   already-read overlay reference and thus avoids the re-read per path. The
   existing `build_path_trustees` signature stays (for the Analyze
   single-path use case).

4. **Scan path** (`handle_scan_path`) reads the share DACL **once** before
   the path loop and passes the overlay reference to every
   `build_path_trustees_with_share` call:

   ```rust
   let share_overlay = match (effective_smb_target(root, smb_server),
                              share_name.or_else(parse_unc)) {
       (Some(s), Some(n)) => Some(read_share_overlay(&s, &n)),
       _ => None,
   };
   for fso in walk.objects {
       let raw_trustees = build_path_trustees_with_share(&fso, share_overlay.as_ref());
       …
   }
   ```

The share DACL is a property of the share, not of the subpath — a single
read per scan is both semantically correct and performance-friendly.

## Consequences

**Positive:**

- The path-centric trustee table now keeps the promise "who can access this
  path at all" consistently with the risk and explanation table.
- Share-DACL read errors appear as a visible marker, not as an invisible
  gap.
- Performance: one read per share, not per path — a clear win on large
  trees.
- API additive: `build_path_trustees` stays; the new
  `build_path_trustees_with_share` and `read_share_overlay` are additions.

**Negative:**

- The trustee list per path is potentially longer (NTFS ACEs + share ACEs).
  That is intended — the separation via `TrusteeCategory::{Ntfs, Share}`
  makes the source recognizable.

**Test requirements:**

- There is currently no automated test for the scan path with an existing
  share DACL, because the GUI worker needs an SMB live probe. A manual
  smoke test via the GUI is part of the v1.5.0 release check.

## Closes

Review 2026-06-04 round 3, finding 3 (the scan/HTML trustee view omitted
share-DACL trustees).

## References

- ADR 0026 — persistent scan history (`PathTrustees` as a model).
- ADR 0031 — `effective_smb_target` for the server choice in the scan path.
- ADR 0036 — unified principal-resolution pipeline (parallel).
- ADR 0037 — validated wrappers consistently (parallel).
