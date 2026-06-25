# ADR 0043 — Effective access context with an explicit SMB context

**Status:** Accepted
**Date:** 2026-06-05

## Context

`AccessContext::for_path(&path)` derives the logon context from the **path
form**:

- UNC path (`\\server\share\…`) → `RemoteSmb` (adds `NETWORK` to the token)
- Local path (`C:\…`) → `LocalInteractive` (adds `INTERACTIVE` + `LOCAL`)

For the typical auditing calls this is correct. But it breaks in a real
auditing scenario that is deliberately allowed in CLI and GUI:

```text
adpa.exe analyze --path "D:\Shares\Data" --user "DOMAIN\alice" \
    --smb-server fs01 --share-name Data
```

The auditor sits **locally on the file server** and wants to know the
effective **SMB** permission of the share. Stars reads the share DACL
correctly from the explicit SMB target — but the token context was still
derived from the local path and stayed `LocalInteractive`. Consequence:

- `NETWORK` (S-1-5-2) was **missing** from the token.
- Share-DACL ACEs on `NETWORK` (e.g. a `Deny NETWORK Read` on the share)
  therefore had no effect.
- ACEs on `INTERACTIVE` and `LOCAL`, by contrast, wrongly took effect even
  though the audit was supposed to model a remote view.

Round-7 review finding 1 (High) classified the bug: an audit tool that
aggregates share rules against well-known logon SIDs incorrectly delivers,
in the most common real case (file server, locally logged in), a
too-permissive effective-rights result. That is silently wrong and thus the
most dangerous bug class for a read-only auditing tool.

## Decision

New helper method `AccessContext::for_path_with_smb`:

```rust
pub fn for_path_with_smb(
    path: &str,
    smb_server: Option<&str>,
    share_name: Option<&str>,
) -> Self {
    let has_explicit_smb =
        smb_server.map(|s| !s.is_empty()).unwrap_or(false)
        || share_name.map(|s| !s.is_empty()).unwrap_or(false);
    if has_explicit_smb {
        return Self::RemoteSmb;
    }
    Self::for_path(path)
}
```

Rules:

- Both SMB-hint fields are `Option<&str>` (exactly as they come from
  `clap`/Slint) and are checked for "not empty". An empty GUI text input
  does not force it.
- As soon as **at least one** of the two SMB hints is set, the context is
  `RemoteSmb` — even if the path looks local.
- Otherwise the function falls back to the existing `for_path` heuristic, so
  UNC still leads to `RemoteSmb` and local paths to `LocalInteractive`.

Six call sites in CLI and GUI use the helper:

- `crates/cli/src/main.rs::analyze` — share status and engine input
- `crates/cli/src/main.rs::scan` — per scan result
- `crates/gui/src/worker.rs::handle_analyze` — share status (1) and engine
  input (2)
- `crates/gui/src/worker.rs::handle_scan` — share status (1) and
  scan-result aggregation (2)

`AccessContext::for_path` stays — it is the correct case for pure path
derivation without an SMB hint, and tests/code that use it directly do not
need to change.

## Consequences

### Positive

- **Silent misevaluation eliminated**: the most common real audit case
  (file server, locally logged in) now correctly models a remote SMB view.
- **Consistency between CLI and GUI**: both use the same helper, no one
  relies on duplicated conditional logic.
- **The engine stays unchanged**: the `RemoteSmb` effect has been correct
  since ADR 0013/0019; ADR 0043 ensures that CLI/GUI actually request it.

### Negative / trade-offs

- Anyone who previously deliberately used `LocalInteractive` via a local
  path *despite* passing an SMB hint now gets different results. That is not
  a realistic use case — an SMB hint implies a remote view by definition —
  but note it as a breaking-change note.
- `AccessContext::for_path` and `for_path_with_smb` coexist. Avoids
  duplicate logic, because `for_path_with_smb` internally calls `for_path`.

### Tests

In `crates/core/src/model.rs::tests`:

- `access_context_for_path_with_smb_forces_remote_when_smb_server_given`
- `access_context_for_path_with_smb_forces_remote_when_share_name_given`
- `access_context_for_path_with_smb_keeps_unc_as_remote`
- `access_context_for_path_with_smb_keeps_local_when_no_smb_hint`
- `access_context_for_path_with_smb_ignores_empty_smb_hints`

In `crates/permission_engine/src/engine.rs::tests` as an end-to-end
safeguard:

- `remote_smb_context_grants_network_ace_even_on_local_path` — Allow
  NETWORK takes effect with a local path form + explicit RemoteSmb.
- `local_interactive_context_ignores_network_ace` — mirror image: without
  RemoteSmb, NETWORK must not take effect.

Live verification against the lab in
[`docs/lab/verification.md`](../lab/verification.md), Part G: scenario E4b
yields `Result = Modify` before the fix, `Result = Special (0x00000000)`
after the fix — the Deny-NETWORK on the share permission now takes effect.

## Relationship to other ADRs

- **ADR 0013** defines the `AccessContext` enum in the first place.
- **ADR 0019** establishes that the engine adds `NETWORK` only under
  `RemoteSmb` — that is the condition which ADR 0043 now finally enforces
  consistently from the CLI/GUI side.
