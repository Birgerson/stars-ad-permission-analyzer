# ADR 0010 — NTFS ∩ share combination in the scan command

## Status
Accepted

## Context

Step 14 wires the share permission layer into the `adpa scan` subcommand.
The permission engine already supports `share_mask: Option<AccessMask>` in
`PermissionEvaluationInput` and computes `effective = ntfs & share` correctly.
What was missing was the CLI plumbing to obtain the share mask and pass it through.

## Decision

### New share_scanner API

**`ShareDacl` enum**

```rust
pub enum ShareDacl {
    NullDacl,              // NULL DACL — no restriction; full access for everyone
    Acl(Vec<SharePermission>),   // DACL present with ACEs
}
```

Distinguishes NULL DACL (no restrictions) from an empty DACL (deny all), which
`get_share_permissions` previously conflated.

**`get_share_dacl(server, share_name) -> Result<ShareDacl, CoreError>`**

Returns the full DACL status of a share. `get_share_permissions` now delegates
to this function and returns an empty list for `NullDacl`.

**`effective_share_mask(dacl, user_sids) -> Option<AccessMask>`**

Computes the user's effective share permission:
- `None` if `dacl` is `NullDacl` (no restriction from share side)
- `Some(allow & !deny)` for `Acl` variant

### CLI extension

Two new optional arguments added to `adpa scan`:

```
--smb-server <HOST>    SMB server for share permission lookup
--share-name <NAME>    Share name for NTFS ∩ Share combination
```

**Auto-detection for UNC paths**: when `--path` is a UNC path
(`\\server\share\...`), both `smb-server` and `share-name` are inferred
automatically. Explicit `--smb-server` / `--share-name` override the
auto-detected values.

**Scan header** now prints the resolved share mask when present:
```
  Share mask: Read & Execute (0x001200A9)
```

**Flow for a scan with share combination**:
1. Resolve identity (LDAP or SID-only)
2. Detect/parse server+share from UNC or explicit args
3. Call `get_share_dacl(server, share)` → `ShareDacl`
4. Call `effective_share_mask(dacl, user_sids)` → `Option<AccessMask>`
5. Walk tree (same as before)
6. For every path: pass the share mask to `DefaultPermissionEngine.evaluate()`

The share mask is the same for all paths under the scan root — this is correct
because all paths reachable via a given share share the same share-level ACL.

### NULL DACL handling

When the share has a NULL DACL, `effective_share_mask` returns `None`.
The permission engine treats `share_mask: None` as "no restriction from share
side" and returns `effective = ntfs`. This is the correct Windows behaviour:
a NULL DACL grants full access to everyone.

### Known limitation

Share permissions use generic rights (`GENERIC_READ`, `GENERIC_WRITE`,
`GENERIC_ALL`) which must be mapped to specific access bits before combining
with NTFS masks. The current engine performs the bitwise AND directly — this
is correct for standard Share ACLs that use specific rights (common on Windows
Server), but may produce unexpected results for shares that use generic rights
exclusively. This will be addressed when generic-rights expansion is added to
the core engine.

## Alternatives considered

- **Per-path share lookup**: determine the share for each individual path during
  the walk. Rejected — all paths in the scan root are under the same share; a
  single lookup before the walk is both simpler and correct.
- **Separate `adpa shares` subcommand**: deferred to a future step when a
  full share-listing report is needed. The per-scan share integration (Step 14)
  is independent of a standalone listing command.

## Consequences

- `adpa scan --path \\server\share\data --user S-1-5-...` now automatically
  applies the share permission for that user, producing the true effective
  permission rather than just the NTFS permission.
- Explicit override via `--smb-server` + `--share-name` covers local paths
  accessed over shares whose local path differs from the UNC path.
- `ShareDacl` and `effective_share_mask` are part of the public `share_scanner`
  crate API for use by the future GUI and other callers.
