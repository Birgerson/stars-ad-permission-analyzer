# ADR 0023 — Evaluate the share DACL in stored order (symmetry with the NTFS engine)

**Status:** Accepted  
**Date:** 2026-05-25

## Context

ADR 0012 switched the NTFS engine to Windows `AccessCheck` semantics:
evaluate the DACL in stored ACE order, first decision per right bit wins.
The share side remained on the old bucket model:

```rust
let mut allow: u32 = 0;
let mut deny: u32 = 0;
for perm in perms {
    if user_sids.contains(&perm.sid.0) {
        let expanded = expand_generic_rights(perm.mask.0);
        match perm.kind {
            AceKind::Allow => allow |= expanded,
            AceKind::Deny  => deny  |= expanded,
        }
    }
}
Some(AccessMask(allow & !deny))
```

For a non-canonical share DACL this yields a different result than
Windows. Reviewer example (follow-up review 2026-05-25, finding 1):
Allow-Everyone-Read followed by Deny-Everyone-Read.

- NTFS engine (stored order): first Allow wins → Read granted
- Share path (bucket): Deny is OR-combined with allow → Read revoked

Because the final result is `NTFS ∩ Share`, an asymmetrically wrong share
mask poisons every effective-rights computation over UNC paths, even when
the NTFS side computes correctly.

## Decision

1. **`effective_share_mask` walks the share DACL in stored ACE order.**
   The algorithm is exactly symmetric to
   `permission_engine::engine::evaluate_dacl_ordered`:

   ```text
   granted, denied = 0, 0
   for perm in dacl:
       if perm.sid not in token: skip
       mask = expand_generic_rights(perm.mask)
       undecided = ¬(granted ∨ denied)
       bits = mask ∧ undecided
       match perm.kind:
           Allow → granted |= bits
           Deny  → denied  |= bits
   return granted
   ```

   For a canonical DACL (Deny before Allow) the result is identical to the
   previous bucket model; for a non-canonical DACL it matches exactly what
   Windows `AccessCheck` produces at runtime.

2. **Non-canonical share DACLs are logged via `tracing::warn!`.** The
   structured diagnostic in `EffectivePermission.diagnostics` is
   NTFS-specific (cf. ADR 0021); an extension to the share side (either via
   an additional variant `NonCanonicalShareDaclOrder` or via a diagnostic
   field in `ShareMaskStatus::Applied`) remains open for a later iteration.
   The log path is sufficient until a concrete audit use case structurally
   demands share diagnostics.

3. **New detector `first_non_canonical_position(&[SharePermission])`**
   analogous to the NTFS counterpart in `engine.rs`. Share DACLs
   technically never carry an INHERITED flag (no share-to-share
   inheritance), so the phase space practically reduces to 0 (Deny) and
   1 (Allow). The 4-phase model is structurally retained as symmetry to the
   NTFS variant.

## Rationale

- **Correctness takes precedence** (AGENTS.md base rule 1) and applies
  symmetrically to NTFS and share. AccessCheck fidelity fixed only halfway
  is worse than none, because it suggests a false sense of security.
- **Single-source-of-truth symmetry:** the same algorithm runs on both
  DACL types, which makes future adjustments easier to keep consistent.
- **Deliberate trade-off on the diagnostic:** a `warn!` log already catches
  the audit case today; structural persistence would be more invasive
  (schema/export/persistence migration) and comes when a concrete use case
  demands it — the same pattern as ADR 0012 → ADR 0021.

## Consequences

- 5 new tests in `share_scanner::scanner::tests`:
  - `non_canonical_allow_before_deny_first_wins`
    (reviewer example, direct proof of the new semantics)
  - `canonical_deny_before_allow_first_wins`
    (standard case, identical result before/after the fix)
  - `partial_overlap_first_decision_per_bit`
    (disjoint Deny/Allow bits: per bit the first match wins)
  - `detects_non_canonical_share_dacl_position`
  - `canonical_share_dacl_passes_detector`
- 2 existing tests switched to canonical order:
  - `deny_overrides_allow`
  - `generic_read_deny_blocks_file_read_bits`

  Both implicitly assumed the bucket behavior (`[Allow, Deny]` → Deny
  wins). With stored-order semantics, "Deny wins only when it comes first"
  holds, which matches the Windows canonical order. Statement and intent
  stay identical; only the ACE order of the fixtures was adjusted.
- No API change, no schema migration.
- Callers (CLI/GUI via `resolve_(scan_)share_status`) are unaffected — the
  function interface stays unchanged.
- This change alone does **not** fix finding 2 from the same review
  (unsupported share ACE types without a diagnostic) — that is a separate
  follow-up.
