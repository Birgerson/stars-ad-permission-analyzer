# ADR 0009 — SMB Share Scanner

## Status
Accepted

## Context

Step 13 adds the ability to enumerate SMB shares on a server and read the share-level security
descriptors. The `share_scanner` crate, which previously only had a stub, now implements the
full Windows Net API integration.

## Decision

### Windows APIs

| API | Info level | Purpose |
|---|---|---|
| `NetShareEnum` | 1 (`SHARE_INFO_1`) | List all shares — name and type |
| `NetShareGetInfo` | 502 (`SHARE_INFO_502`) | Per-share security descriptor |
| `NetApiBufferFree` | — | Free buffers allocated by the Net API |

Both functions are in `windows_sys::Win32::Storage::FileSystem` in windows-sys 0.59 (despite the
logical category; this mirrors their header-file grouping in the Windows SDK).
`NetApiBufferFree` is in `windows_sys::Win32::NetworkManagement::NetManagement`.

### Public API (`share_scanner` crate)

```rust
pub fn scan_shares(server: &str) -> ShareScanResult
pub fn enumerate_shares(server: &str) -> Result<Vec<Share>, CoreError>
pub fn get_share_permissions(server: &str, share_name: &str) -> Result<Vec<SharePermission>, CoreError>

pub struct ShareScanResult {
    pub shares: Vec<Share>,
    pub permissions: Vec<SharePermission>,
    pub errors: Vec<ShareScanError>,
}

pub struct ShareScanError {
    pub share_name: String,
    pub error: CoreError,
}
```

`scan_shares` is the high-level entry point: it calls `enumerate_shares` first, then
`get_share_permissions` for each share. Errors reading individual shares are collected; the
scan continues (same fault-tolerance pattern as the file-system walker).

### Admin share detection

A share is marked `is_admin_share = true` if:
- its type has `STYPE_SPECIAL` (bit 31) set, **or**
- its name ends with `$` (e.g. `ADMIN$`, `C$`).

The second condition covers shares that Windows reports with `STYPE_DISKTREE` but that still
have the conventional admin-share naming.

### Security descriptor parsing

`NetShareGetInfo` at level 502 returns a `PSECURITY_DESCRIPTOR` in
`SHARE_INFO_502.shi502_security_descriptor`. The DACL is extracted with
`GetSecurityDescriptorDacl`, then iterated with `GetAclInformation` + `GetAce` —
the same pattern used in `fs_scanner::acl`.

### Tracing

- `info!` at start and end of `enumerate_shares` and `scan_shares`
- `debug!` per discovered share and per share with read permissions
- `warn!` on any failure (Net API error, missing security descriptor, SID conversion error)

## Alternatives considered

- **`windows` crate (higher-level)**: more ergonomic but adds a large dependency. The existing
  project uses `windows-sys`; consistency favoured staying with it.
- **`NetShareEnum` at level 502 for both list and permissions**: would save one round-trip per
  share, but separating enumeration from permission-reading keeps the API clearer and lets
  callers enumerate without paying for DACL parsing.
- **`GetNamedSecurityInfoW` on UNC path**: an alternative way to read the share DACL via the
  file-system path. Rejected because `NetShareGetInfo` level 502 returns the share-specific
  security descriptor directly, while `GetNamedSecurityInfoW` on `\\server\share` may return
  the NTFS DACL of the underlying directory, not the share permission DACL.

## Consequences

- `adpa scan` can now be extended (Step 14) to pass the share permission mask to the
  permission engine, enabling the NTFS ∩ Share combination for any path reachable via a share.
- Administrative shares (`C$`, `ADMIN$`) are identified and can be filtered in the CLI or GUI.
- Share permissions are stored in the existing `SharePermission` model and can be persisted to
  SQLite alongside NTFS results once the wiring is added in Step 14.
