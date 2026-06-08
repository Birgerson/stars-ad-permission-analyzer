# ADR 0012 — DACL evaluation with Windows AccessCheck semantics

**Status:** Accepted
**Date:** 2026-05-24

## Context

The original implementation in `DefaultPermissionEngine` collected every DACL entry into four buckets (explicit/inherited × allow/deny) and combined them into aggregate masks. The approach was simple but diverged from the Windows `AccessCheck` semantics in three ways:

1. **ACE order was ignored.** With non-canonical DACLs a later Deny ACE cannot override an earlier Allow ACE — Windows evaluates ACEs in stored order. The bucket algorithm could therefore produce diverging effective rights in rare but real cases (review finding 2).
2. **`INHERIT_ONLY_ACE` (0x08) was not evaluated.** ACEs with this flag apply only to children and must not contribute any bits to the current object. They exist in the DACL but are inert for the current object (finding 1).
3. **Generic rights (GENERIC_READ/WRITE/EXECUTE/ALL, bits 28–31) were not expanded on the NTFS path.** A `GENERIC_ALL` Allow could therefore pass through as "Special" and drop to 0 in the `NTFS ∩ Share` AND. The share path already expanded; the NTFS path did not — the inconsistency was a correctness bug (finding 3).

## Decision

1. **Evaluation walks ACEs in stored order.** `evaluate_dacl_ordered` runs through the DACL once from front to back. Per right bit, the first matching decision wins; already-decided bits are "immune" to later ACEs:

   ```text
   granted, denied = 0, 0
   for ace in dacl:
       if ace not applicable (INHERIT_ONLY) or SID not in token: skip
       mask = expand_generic_rights(ace.mask)
       undecided = ¬(granted ∨ denied)
       bits = mask ∧ undecided
       match ace.kind:
           Allow → granted |= bits
           Deny  → denied  |= bits
   return granted
   ```

   For canonically ordered DACLs the result is identical to the previous four-phase model; for non-canonical DACLs it matches exactly what `AccessCheck` produces at runtime.

2. **`INHERIT_ONLY_ACE` is filtered out before evaluation.** The `fs_scanner` parser now splits `ACE_HEADER::AceFlags` cleanly into `inheritance_flags` (OI | CI — *which* children inherit) and `propagation_flags` (NP | IO — *how* propagation works). The `INHERITED` bit (0x10) stays in the separate `inherited: bool`. The engine consistently filters ACEs with the IO bit out for the current object.

3. **Generic rights are expanded centrally.** `permission_engine::mask::expand_generic_rights()` maps `GENERIC_READ/WRITE/EXECUTE/ALL` to the matching `FILE_GENERIC_*` bits or `MASK_FULL_CONTROL`. NTFS engine, explanation output, and `share_scanner` all call the same function — the share path gave up its local copy.

4. **Non-canonical DACLs are detected and logged.** `first_non_canonical_position` marks the first ACE that violates Windows canonical order (explicit-Deny → explicit-Allow → inherited-Deny → inherited-Allow). Evaluation still follows stored order; a `tracing::warn!` warning makes the finding visible to audits without changing the data model or the DB schema.

## Rationale

- **Correctness before speed** (AGENTS.md, base rule 1). The earlier bucket approach was faster but incorrect at a critical point — fixing it is not optional.
- **Unified mask normalization** keeps the NTFS and share paths consistent. A duplicated implementation would be a source of future drift.
- The diagnostic path via `tracing::warn!` is deliberately low-impact: `EffectivePermission`, the DB schema, and the GUI/CLI/export formats stay unchanged. A later structured diagnostic (e.g. a `non_canonical_dacl: bool` field) is possible once a concrete audit use case demands it.

## Consequences

- New regression tests in `permission_engine::engine::tests` for INHERIT_ONLY, GENERIC_* bits, Allow-before-Deny ordering, and the non-canonical detector.
- New tests in `fs_scanner::acl::tests` for `split_ace_flags`.
- `share_scanner` now depends on `permission_engine` — the shared `expand_generic_rights` function lives in the permission module because mask expansion is permission semantics, not file-system semantics.
- `contributing_sids` filters INHERIT_ONLY ACEs out and expands generic bits before the AND with the result; previously `GENERIC_ALL` ACEs could wrongly appear as "contributed nothing".
