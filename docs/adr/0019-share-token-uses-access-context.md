# ADR 0019 — Share token uses the same AccessContext as the NTFS token

**Status:** Accepted  
**Date:** 2026-05-24

## Context

ADR 0013 introduced the `AccessContext`: for UNC paths the engine
implicitly adds `NETWORK` (S-1-5-2) to the access token, and for local
paths `INTERACTIVE` + `LOCAL`. This bit flowed correctly into the NTFS
evaluation path.

The share mask, however, is **not** computed by the NTFS evaluator but
beforehand by two dedicated helpers:

- `crates/cli/src/main.rs`: `resolve_scan_share_status`
- `crates/gui/src/worker.rs`: `resolve_share_status`

Both built the token via `build_token_sids_with_local`, which internally
delegates to `build_token_sids_with_context(_, _, _, Unspecified)`.
**Consequence:** while the NTFS path had `NETWORK` in the token on a UNC
scan, the same SID was missing in the share path — share ACEs on
`NETWORK` (e.g. a `Deny NETWORK Read`) were ignored. Because the final
result is `NTFS ∩ Share`, the weaker share token poisoned every effective
SMB computation.

The follow-up review (2026-05-24) correctly identified this as
high-priority finding 1.

## Decision

1. **`resolve_scan_share_status` (CLI) and `resolve_share_status` (GUI)
   take a new mandatory parameter `access_context: AccessContext`.**

2. **Both now build the token via
   `build_token_sids_with_context(..., access_context)`** instead of
   `build_token_sids_with_local`. Thus `RemoteSmb` automatically puts
   `NETWORK` in the token (and `LocalInteractive` puts `INTERACTIVE` +
   `LOCAL`).

3. **Both callers (CLI scan + analyze, GUI scan + analyze) compute
   `AccessContext::for_path(path)` and pass exactly the same value both to
   `resolve_*share_status` and to `PermissionEvaluationInput.access_context`.**
   This rules out NTFS and share paths evaluating with different token
   contexts.

4. **`build_token_sids_with_context` is re-exported from
   `permission_engine`.** `build_token_sids_with_local` stays for
   backward compatibility but is no longer the right choice for CLI/GUI.

## Rationale

- **Correctness before speed** (AGENTS.md, base rule 1). A mask computed
  wrong in two steps is a direct audit harm.
- **Symmetry NTFS ↔ Share** — if the engine is context-sensitive, the
  share path must be too, otherwise the weaker token poisons the
  `NTFS ∩ Share` result.
- **Derive `AccessContext` once per call and pass it through** is less
  error-prone than calling `for_path(path)` twice — the latter would be
  correct, but passing it through makes the symmetry obvious.

## Consequences

- 3 new tests in `share_scanner::scanner::tests`:
  - `deny_network_share_ace_does_nothing_without_network_in_token`
    (regression baseline for the old behavior — serves as an explicit
    "this is how it was broken before" marker)
  - `deny_network_share_ace_blocks_read_when_network_in_token`
    (the new intended behavior)
  - `allow_network_share_ace_grants_when_network_in_token`
    (mirror image for allow-NETWORK-only ACEs)
- No schema change, no DB migration needed.
- ADR 0013 remains valid — this ADR adds the missing application in the
  share path.
- After this ADR the existing `build_token_sids_with_local` is still
  formally public, but no longer in use on production paths. A later
  deprecation is conceivable.
