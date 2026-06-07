# ADR 0047 — `SmbAuditContext`: typed wrapper as the single source for server/share derivation

**Status:** Accepted
**Date:** 2026-06-06

## Context

Stars has to derive at several places — from a path plus optional explicit flags — **which SMB server** and **which share** apply to a share-DACL query. This derivation was previously carried by two separate helpers:

```rust
// crates/validation/src/path.rs
pub fn parse_unc_components(path: &str) -> Option<(String, String)>;
pub fn effective_smb_target(path: &str, explicit_smb_server: Option<&str>) -> Option<String>;
```

Different call sites combined these functions by hand to build the final `(server, share)` strings from path + server flag + share flag:

```rust
// CLI: resolve_scan_share_status
let path_components = parse_unc_components(path);
let server = match effective_smb_target(path, smb_server) {
    Some(s) => s,
    None => return NotApplicable,
};
let share = match share_name {
    Some(s) => s.to_owned(),
    None => match path_components {
        Some((_, s)) => s,
        None => return NotApplicable,
    },
};
```

Review round 10 finding 1 revealed that the new trustee-overlay creation (`build_path_trustees`, `read_share_overlay`) **did not** duplicate the same derivation:

```rust
// CLI: run_analyze (before)
let trustees = exporter::build_path_trustees(
    &fso,
    smb_server.as_deref(),       // <-- only the explicit flag,
    share_name.as_deref(),       // <-- NO UNC fallback
);

// CLI: run_scan (before)
#[cfg(windows)]
let scan_share_overlay = match (smb_server.as_deref(), share_name.as_deref()) {
    (Some(server), Some(name)) if !server.is_empty() && !name.is_empty() => {
        Some(exporter::read_share_overlay(server, name))
    }
    _ => None,                    // <-- bare UNC without flags: nothing
};
```

Consequence: a call like

```
adpa scan --path \\fs01\data --user alice --output report.json
```

produced the *correct* `share_status` mask (`resolve_scan_share_status` used the UNC fallback), but the `path_trustees` list contained **only the NTFS layer**. That was a silent data asymmetry within the same report — the auditor saw two different "truths" about the same path.

Three independent sites with three independent implementations of the same derivation is **a bug class by itself**: each site can drift independently and reviewers have to verify each one separately.

## Decision

We introduce a **typed wrapper** `SmbAuditContext` that becomes the single source of truth for the server/share derivation:

```rust
// crates/validation/src/path.rs
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbAuditContext {
    pub server: String,
    pub share: String,
}

impl SmbAuditContext {
    pub fn resolve(
        path: &str,
        explicit_smb_server: Option<&str>,
        explicit_share_name: Option<&str>,
    ) -> Option<Self>;
}
```

### Design decisions

1. **Per field: explicit > UNC component.** When `--smb-server fs02` is supplied, the explicit server wins even on a UNC path `\\fs01\…`. Motivated by audit scenarios where the share DACL lives on a different server from the NTFS path (e.g. DR replication).
2. **Either both fields or nothing (`Option<Self>`).** If only the server can be determined (for example `--smb-server fs01` with the local path `C:\data` without `--share-name`), `resolve` returns `None`. Rationale: a DACL lookup needs **both**. Half information led to silently failing calls with an empty share name.
3. **Empty string flags count as "not set".** `Some("")` and `Some("   ")` are treated like `None`. Rationale: CLI frontends and GUI bindings often pass `Some("")` instead of `None` when a field was left blank. This was a source of wrong trustee lookups in the GUI before v1.5.14.

### Where the wrapper is used

With Round 10, `SmbAuditContext::resolve` becomes the central site for the three paths that previously drifted apart or carried duplicated code:

| Call site | Before | After |
|---|---|---|
| `cli::main::run_analyze` (trustee overlay) | only explicit flags, no UNC fallback | `SmbAuditContext::resolve(...)` |
| `cli::main::run_scan` (trustee overlay) | only explicit flags, no UNC fallback | `SmbAuditContext::resolve(...)` |
| `cli::main::resolve_scan_share_status` | manual combination `effective_smb_target` + `parse_unc_components` | `SmbAuditContext::resolve(...)` |
| `gui::worker::sweep_one_root` (trustee overlay) | manual combination | `SmbAuditContext::resolve(...)` |
| `gui::worker::compute_share_mask_for_analyze` | manual combination | `SmbAuditContext::resolve(...)` |

This **guarantees** that CLI analyze, CLI scan, and GUI scan see the same SMB context. Mask computation and trustee overlay are no longer derivation-asymmetric.

### Where the wrapper deliberately is NOT used

`effective_smb_target` stays for callers that only need the server (e.g. `compute_local_group_memberships_for_analyze` for local groups — share name irrelevant). That is semantically a different question and should stay typed separately.

`parse_unc_components` stays for callers that explicitly need only the raw components of the UNC path (for example inside validation error messages).

### Tests

Six tests in the `validation::path::tests` module cover the invariants:

| Test | What it guarantees |
|---|---|
| `smb_audit_context_from_unc_alone` | Bare UNC without flags → both fields from the path. **Direct Round-10 finding-1 behaviour.** |
| `smb_audit_context_explicit_flags_override_unc` | Explicit flags win per field. |
| `smb_audit_context_local_path_yields_none` | Local path without flags → `None`. Guards against the `C:`-as-server bug. |
| `smb_audit_context_server_without_share_yields_none` | Half context (server explicit, no share) → `None`. Guards against `get_share_dacl` calls with an empty share. |
| `smb_audit_context_mixed_explicit_server_unc_share` | Mixed form: server explicit, share from UNC. |
| `smb_audit_context_empty_explicit_flags_are_treated_as_none` | `Some("")` counts as not set — defensive against GUI frontends. |

## Consequences

### Positive

- **Bug class eliminated.** Three sites that derived server/share independently are replaced by a shared source. Any future correction in the derivation now takes effect everywhere automatically.
- **Type system instead of convention.** `SmbAuditContext` as a struct with `server: String, share: String` is as clear as possible. Whoever holds one knows that **both** fields are valid.
- **Data symmetry between mask and trustees.** The same report no longer shows two different server/share truths in the mask computation and the trustee list.
- **Test coverage broadened.** Six new unit tests in the `validation` crate guard the invariants platform independently.

### Negative / trade-offs

- `Option<SmbAuditContext>` has to be unpacked by the caller. Previously a half context (only server) would have triggered a DACL call with an empty share name and failed internally. Now the derivation fails earlier and more cleanly — but callers that previously implicitly relied on the half context now have to handle the `None` case explicitly. In the current workspace that is limited to four call sites and correctly implemented everywhere.
- One additional type definition in the public API of `validation`. Costs a bit more documentation attention but is semantically valuable.

### Relationship to other ADRs

- **ADR 0043** (AccessContext with SMB hints): `AccessContext::for_path_with_smb` receives the SMB hints from the caller. Whoever uses `SmbAuditContext::resolve` passes `(server, share)` straight on — no double lookup needed.
- **ADR 0044** (`exporter::trustees` as a shared module): the module accepts `Option<&str>, Option<&str>` for the SMB hints. Callers in CLI and GUI now fill these fields from `SmbAuditContext`.
