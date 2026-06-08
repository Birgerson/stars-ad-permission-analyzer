// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! SMB share enumeration and permission reading via Windows Net API.
//!
//! - `enumerate_shares` lists all shares on a server.
//! - `get_share_permissions` reads permissions for a single share.
//! - `scan_shares` is the combined entry point.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use adpa_core::{
    error::CoreError,
    model::{AccessMask, AceKind, NormalizedPath, Share, SharePermission, Sid},
};
use permission_engine::mask::expand_generic_rights;
use tracing::{debug, info, warn};
use win_safe::netapi::NetApiBuffer;
use windows_sys::Win32::Foundation::{GetLastError, FALSE};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetAce, GetAclInformation, GetSecurityDescriptorDacl, ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE,
    ACE_HEADER, ACL, ACL_SIZE_INFORMATION, INHERITED_ACE,
};
use windows_sys::Win32::Storage::FileSystem::{NetShareEnum, NetShareGetInfo, SHARE_INFO_502};

// Windows constant not re-exported by windows-sys 0.59
// Tells NetShareEnum to allocate as much buffer as needed.
const MAX_PREFERRED_LENGTH: u32 = 0xFFFF_FFFF;

// Net API success status
const NERR_SUCCESS: u32 = 0;

// Share type flag: hidden / administrative share
const STYPE_SPECIAL: u32 = 0x8000_0000;

// ACE type raw values (WinNT.h) — not exported as constants in windows-sys 0.59
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

// ───────────────────────────────────────────────────────────────────────────
// Public data types
// ───────────────────────────────────────────────────────────────────────────

/// DACL status of a share.
/// DACL status of a share.
///
///
/// `NullDacl` and `Acl(vec![])` have opposite real-world meaning: NULL
/// means "no access restriction" (full access for everyone), while a
/// present-but-empty DACL means "no access". Both cases must remain
/// distinguishable for audits.
#[derive(Debug, Clone)]
pub enum ShareDacl {
    /// NULL DACL — no access restrictions; equivalent to full control for everyone.
    NullDacl,
    /// DACL present with the listed ACEs.
    Acl(Vec<SharePermission>),
}

///
///
/// Result of a share DACL read including audit diagnostic for share
/// ACE types the parser did not interpret (object, callback,
/// conditional or vendor-specific). When `unsupported_count > 0` the
/// share mask is potentially incomplete — callers should propagate the
/// value into `PermissionEvaluationInput.unsupported_share_ace_count`
/// so the engine pushes a `PermissionDiagnostic::UnsupportedShareAces`
/// into `EffectivePermission.diagnostics` and risk findings for this
/// permission get flagged `incomplete` (follow-up finding 2 from the
/// 2026-05-25 review).
#[derive(Debug, Clone)]
pub struct ShareDaclScan {
    pub dacl: ShareDacl,
    pub unsupported_count: usize,
}

/// Result of an SMB share scan.
pub struct ShareScanResult {
    pub shares: Vec<Share>,
    /// in denen `NullDacl` vs. `Acl(vec![])` unterscheidbar bleiben
    /// Flattened aggregate ACE list across all shares — a convenience
    /// for callers that don't need per-share resolution. For audits
    /// where `NullDacl` vs. `Acl(vec![])` must stay distinguishable,
    /// `share_dacls` is the authoritative source.
    pub permissions: Vec<SharePermission>,
    pub errors: Vec<ShareScanError>,
    /// verworfen.
    ///
    /// Per-share DACL status in enumeration order including audit
    /// diagnostics. Preserves two things: first, the `NullDacl` vs.
    /// present-but-empty `Acl(vec![])` distinction (Finding 7); second,
    /// the per-share `unsupported_count`, so consumers can decide per
    /// share which share should be flagged `incomplete` for unevaluated
    /// ACE types (follow-up finding 2 from the 2026-05-25 review).
    /// Previously the count was only logged in aggregate and discarded
    /// on push to this field.
    pub share_dacls: Vec<(String, ShareDaclScan)>,
}

/// Error reading a single share.
pub struct ShareScanError {
    pub share_name: String,
    pub error: CoreError,
}

// ───────────────────────────────────────────────────────────────────────────
// Public API
// ───────────────────────────────────────────────────────────────────────────

/// Combined scan: shares and permissions for one server.
///
/// Errors reading individual shares are recorded; the scan continues.
pub fn scan_shares(server: &str) -> ShareScanResult {
    info!(server, "Starting SMB share scan");

    let mut result = ShareScanResult {
        shares: Vec::new(),
        permissions: Vec::new(),
        errors: Vec::new(),
        share_dacls: Vec::new(),
    };

    let shares = match enumerate_shares(server) {
        Err(e) => {
            warn!(server, error = %e, "Cannot enumerate shares — scan aborted");
            result.errors.push(ShareScanError {
                share_name: String::new(),
                error: e,
            });
            return result;
        }
        Ok(s) => s,
    };

    // Call `get_share_dacl` per share so the `NullDacl` case flows
    // through structured (Finding 7). The flat `permissions` field
    // stays as a convenience — it carries ACE lists from `Acl(_)`;
    // NULL DACLs (correctly) contribute nothing.
    let mut null_dacl_count: usize = 0;
    let mut unsupported_share_aces_total: usize = 0;
    for share in &shares {
        match get_share_dacl(server, &share.name) {
            Err(e) => {
                warn!(server, share = %share.name, error = %e, "Cannot read share permissions");
                result.errors.push(ShareScanError {
                    share_name: share.name.clone(),
                    error: e,
                });
            }
            Ok(scan) => {
                if let ShareDacl::Acl(perms) = &scan.dacl {
                    result.permissions.extend(perms.iter().cloned());
                } else {
                    null_dacl_count += 1;
                }
                unsupported_share_aces_total += scan.unsupported_count;
                // Previously: only scan.dacl was pushed, unsupported_count
                // was lost. Now: the whole scan, so consumers can decide
                // per share (follow-up finding 2).
                result.share_dacls.push((share.name.clone(), scan));
            }
        }
    }

    result.shares = shares;
    info!(
        server,
        shares = result.shares.len(),
        permissions = result.permissions.len(),
        null_dacl_shares = null_dacl_count,
        unsupported_share_aces = unsupported_share_aces_total,
        errors = result.errors.len(),
        "SMB share scan complete"
    );
    result
}

/// Lists all shares on a server (Level 502 — name, type, local path).
///
/// `server` is the NetBIOS or DNS name; an empty string means localhost. In
/// that case `localhost` is used for the UNC representation to avoid a UNC
/// path with an empty server component.
///
/// Level 502 requires administrative rights on the target server — the same
/// rights are already required to read share DACLs.
pub fn enumerate_shares(server: &str) -> Result<Vec<Share>, CoreError> {
    let wide_server = to_wide_null(server);
    // RAII guard for the NetApi buffer: every path — success, error,
    // `?` from a helper — frees the buffer in Drop.
    let mut buf: NetApiBuffer<SHARE_INFO_502> = NetApiBuffer::null();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;
    let mut resume_handle: u32 = 0;

    info!(server, "Enumerating SMB shares (level 502)");

    // SAFETY: wide_server is a valid null-terminated UTF-16 string for the duration of the call.
    // The OS allocates the buffer via NetApiBufferAllocate; NetApiBuffer<T> calls
    // NetApiBufferFree on drop.
    let status = unsafe {
        NetShareEnum(
            wide_server.as_ptr(),
            502,
            buf.out_ptr().cast(),
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
            &mut resume_handle,
        )
    };

    if status != NERR_SUCCESS {
        warn!(server, status, "NetShareEnum(502) failed");
        return Err(CoreError::ShareEnumeration(format!(
            "NetShareEnum({server}) failed: status {status}"
        )));
    }

    if buf.is_null() || entries_read == 0 {
        return Ok(Vec::new());
    }

    // SAFETY: buf.as_ptr() points to an array of entries_read SHARE_INFO_502
    // structs allocated by NetShareEnum. Valid for the lifetime of `buf`.
    let entries = unsafe {
        std::slice::from_raw_parts(buf.as_ptr() as *const SHARE_INFO_502, entries_read as usize)
    };

    // \\\share entsteht.
    // For empty server names produce UNC paths with "localhost" to avoid \\\share.
    let server_for_unc = if server.is_empty() {
        "localhost"
    } else {
        server
    };

    let mut shares = Vec::with_capacity(entries_read as usize);
    for entry in entries {
        // SAFETY: shi502_netname is a valid null-terminated UTF-16 string inside the buffer.
        let name = unsafe { wide_ptr_to_string(entry.shi502_netname) };
        if name.is_empty() {
            continue;
        }
        // SAFETY: shi502_path may be null/empty for special shares (e.g. IPC$); handle both.
        let local_path_str = unsafe { wide_ptr_to_string(entry.shi502_path) };
        let local_path = if local_path_str.is_empty() {
            None
        } else {
            Some(NormalizedPath(local_path_str))
        };
        let unc_path = format!("\\\\{server_for_unc}\\{name}");
        let is_admin = entry.shi502_type & STYPE_SPECIAL != 0 || name.ends_with('$');

        debug!(server, share = %name, is_admin, local_path = ?local_path, "Found share");
        shares.push(Share {
            name,
            unc_path,
            local_path,
            is_admin_share: is_admin,
        });
    }

    info!(server, count = shares.len(), "Share enumeration complete");
    Ok(shares)
    // `buf` is dropped here, calling NetApiBufferFree.
}

/// Reads permissions for a single share (Level 502).
///
/// For NULL DACL (no access restriction) an empty list is returned.
/// Use `get_share_dacl` when NULL vs empty DACL must be distinguished.
pub fn get_share_permissions(
    server: &str,
    share_name: &str,
) -> Result<Vec<SharePermission>, CoreError> {
    match get_share_dacl(server, share_name)?.dacl {
        ShareDacl::NullDacl => Ok(Vec::new()),
        ShareDacl::Acl(perms) => Ok(perms),
    }
}

/// Reads the DACL status of a share, distinguishing NULL DACL from empty DACL.
///
/// - `ShareDacl::NullDacl` → no restrictions (full control for everyone)
/// - `ShareDacl::Acl(perms)` → DACL present, `perms` contains all ACEs
///
///
/// Additionally returns `unsupported_count` (follow-up finding 2): the
/// number of share ACEs the parser did not interpret. Callers propagate
/// the value to the engine so a `PermissionDiagnostic::UnsupportedShareAces`
/// ends up in the result.
pub fn get_share_dacl(server: &str, share_name: &str) -> Result<ShareDaclScan, CoreError> {
    let wide_server = to_wide_null(server);
    let wide_share = to_wide_null(share_name);
    // RAII guard: this used to be where `parse_share_dacl(...)?` could leak
    // the buffer (review round 10 finding 3). The guard frees the buffer in
    // Drop, no matter whether the `?` path is taken or not.
    let mut buf: NetApiBuffer<SHARE_INFO_502> = NetApiBuffer::null();

    debug!(server, share = share_name, "Reading share DACL");

    // SAFETY: wide_server and wide_share are valid null-terminated UTF-16 strings.
    // NetApiBuffer<SHARE_INFO_502> owns the allocated buffer after this call.
    let status = unsafe {
        NetShareGetInfo(
            wide_server.as_ptr(),
            wide_share.as_ptr(),
            502,
            buf.out_ptr().cast(),
        )
    };

    if status != NERR_SUCCESS {
        warn!(
            server,
            share = share_name,
            status,
            "NetShareGetInfo(502) failed"
        );
        return Err(CoreError::ShareEnumeration(format!(
            "NetShareGetInfo({server}, {share_name}) failed: status {status}"
        )));
    }

    if buf.is_null() {
        return Ok(ShareDaclScan {
            dacl: ShareDacl::NullDacl,
            unsupported_count: 0,
        });
    }

    // SAFETY: buf.as_ptr() is a valid SHARE_INFO_502 struct for the lifetime
    // of `buf`.
    let info = unsafe { &*buf.as_ptr() };

    let (dacl, unsupported_count) = if info.shi502_security_descriptor.is_null() {
        // No security descriptor → treat as NULL DACL (full access)
        warn!(
            server,
            share = share_name,
            "Share has no security descriptor — treating as NULL DACL"
        );
        (ShareDacl::NullDacl, 0usize)
    } else {
        // SAFETY: shi502_security_descriptor is valid for the lifetime of `buf`.
        // If parse_share_dacl returns Err, the `?` propagates out and `buf`
        // is dropped on the way out — NetApiBufferFree runs.
        match unsafe { parse_share_dacl(share_name, info.shi502_security_descriptor) }? {
            None => (ShareDacl::NullDacl, 0usize),
            Some((perms, unsupported)) => {
                debug!(
                    server,
                    share = share_name,
                    aces = perms.len(),
                    unsupported,
                    "Share DACL read"
                );
                (ShareDacl::Acl(perms), unsupported)
            }
        }
    };

    Ok(ShareDaclScan {
        dacl,
        unsupported_count,
    })
    // `buf` is dropped here, calling NetApiBufferFree.
}

/// Computes the effective share permission for a user.
///
/// Evaluates the share DACL in **stored ACE order** — first decision per
/// bit wins (matching Windows `AccessCheck` and symmetric to the NTFS
/// engine, see ADR 0012). Generic rights are expanded before evaluation.
/// A non-canonical DACL is surfaced via `tracing::warn!`; evaluation
/// still follows stored order, matching real Windows behavior (follow-up
/// review 2026-05-25, finding 1).
///
/// Returns `None` when the DACL is NULL (no restriction from the share
/// side). `user_sids` must contain the user's own SID and all group SIDs.
pub fn effective_share_mask(
    dacl: &ShareDacl,
    user_sids: &std::collections::HashSet<String>,
) -> Option<AccessMask> {
    let perms = match dacl {
        ShareDacl::NullDacl => return None,
        ShareDacl::Acl(p) => p,
    };

    if let Some(at) = first_non_canonical_position(perms) {
        warn!(
            at,
            "Non-canonical share DACL ordering detected — evaluation follows \
             stored ACE order (matches Windows AccessCheck), but tools like \
             SMB-share-MMC normally enforce canonical order"
        );
    }

    // ACEs. Symmetrisch zu permission_engine::engine::evaluate_dacl_ordered.
    // Stored-order walk: per bit the first matching decision wins; bits
    // already decided are "immune" to later ACEs. Symmetric to
    // permission_engine::engine::evaluate_dacl_ordered.
    let mut granted: u32 = 0;
    let mut denied: u32 = 0;
    for perm in perms {
        if !user_sids.contains(&perm.sid.0) {
            continue;
        }
        let mask = expand_generic_rights(perm.mask.0);
        let undecided = !(granted | denied);
        let bits = mask & undecided;
        if bits == 0 {
            continue;
        }
        match perm.kind {
            AceKind::Allow => granted |= bits,
            AceKind::Deny => denied |= bits,
        }
    }
    Some(AccessMask(granted))
}

/// Canonical share DACL order mirroring the NTFS convention: 0 =
/// explicit deny, 1 = explicit allow, 2 = inherited deny, 3 = inherited
/// allow. Returns the index of the first ACE that violates phase
/// monotonicity.
///
/// Note: share DACLs technically never carry an INHERITED flag (no
/// share-to-share inheritance), so in practice only phases 0/1 matter.
/// The 4-phase model is kept for structural consistency with the NTFS
/// detector in `permission_engine::engine`.
fn first_non_canonical_position(perms: &[SharePermission]) -> Option<usize> {
    let mut max_phase = 0u8;
    for (i, p) in perms.iter().enumerate() {
        // SharePermission carries no `inherited` info — assume false
        // (the case for real SMB shares). Phase space reduces to
        // 0 (Deny) and 1 (Allow).
        let phase: u8 = match p.kind {
            AceKind::Deny => 0,
            AceKind::Allow => 1,
        };
        if phase < max_phase {
            return Some(i);
        }
        max_phase = phase;
    }
    None
}

// ───────────────────────────────────────────────────────────────────────────
// Internals
// ───────────────────────────────────────────────────────────────────────────

fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Converts a null-terminated UTF-16 pointer to a String.
///
/// # Safety
/// `ptr` must be a valid null-terminated UTF-16 pointer.
unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: ptr is a valid UTF-16 null-terminated string.
    let len = (0usize..).take_while(|&i| *ptr.add(i) != 0).count();
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

/// Converts a SID pointer to the canonical S-R-I-... string.
///
/// # Safety
/// `sid` must be a valid PSID pointer valid for the duration of this call.
unsafe fn sid_to_string(sid: *const core::ffi::c_void) -> Result<String, CoreError> {
    let mut str_ptr: *mut u16 = std::ptr::null_mut();
    // SAFETY: sid is a valid PSID. The OS allocates str_ptr; we must free it with LocalFree.
    if ConvertSidToStringSidW(sid as *mut _, &mut str_ptr) == FALSE {
        return Err(CoreError::InvalidSecurityDescriptor(
            "ConvertSidToStringSidW failed in share ACE".into(),
        ));
    }
    // SAFETY: str_ptr is a valid null-terminated UTF-16 string allocated by LocalAlloc.
    let len = (0usize..).take_while(|&i| *str_ptr.add(i) != 0).count();
    let s = String::from_utf16_lossy(std::slice::from_raw_parts(str_ptr, len));
    // SAFETY: str_ptr was allocated by LocalAlloc inside ConvertSidToStringSidW.
    windows_sys::Win32::Foundation::LocalFree(str_ptr as *mut core::ffi::c_void);
    Ok(s)
}

/// Parses the DACL from a share security descriptor into SharePermission entries.
///
/// # Safety
/// `sd` must be a valid security descriptor pointer.
/// Returns `None` when the DACL is NULL (no access restriction).
///
/// # Safety
/// `sd` must be a valid security descriptor pointer.
/// Share-DACL-Auswertung isoliert testbar.
///
/// Pure classification of a security descriptor's DACL state, independent
/// of Win32 pointers. Lets the bug-prone part of share DACL evaluation be
/// unit-tested in isolation.
///
/// Semantik (`GetSecurityDescriptorDacl` per MSDN):
///
/// Semantics (`GetSecurityDescriptorDacl` per MSDN):
///   `present` is `lpbDaclPresent`, `ptr_is_null` whether `pDacl == NULL`.
///   `ace_count` is only meaningful when `pDacl != NULL`.
///
/// | `present` | `ptr_is_null` | `ace_count` | Classification       |
/// |-----------|---------------|-------------|----------------------|
/// | false     | egal          | egal        | `Null` (unrestricted)|
/// | true      | true          | egal        | `Null` (unrestricted)|
/// | true      | false         | 0           | `Empty` (deny-all)   |
/// | true      | false         | > 0         | `Normal`             |
///
///
/// Follow-up finding 1 (review 2026-05-25): previously `parse_share_dacl`
/// treated `present=TRUE, pDacl=NULL` as `Empty` (deny-all), turning an
/// unrestricted NULL DACL into an apparent "no SMB access" — a direct
/// source of false-negative audit reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaclClassification {
    /// NULL DACL — no DACL-level access restriction.
    Null,
    /// Vorhandene DACL ohne ACEs — deny all.
    /// Present DACL with zero ACEs — deny all.
    Empty,
    /// Normal DACL with at least one ACE.
    /// Normal DACL with at least one ACE.
    Normal,
}

fn classify_dacl(present: bool, ptr_is_null: bool, ace_count: u32) -> DaclClassification {
    if !present || ptr_is_null {
        return DaclClassification::Null;
    }
    if ace_count == 0 {
        return DaclClassification::Empty;
    }
    DaclClassification::Normal
}

unsafe fn parse_share_dacl(
    share_name: &str,
    sd: *mut core::ffi::c_void,
) -> Result<Option<(Vec<SharePermission>, usize)>, CoreError> {
    let mut dacl_ptr: *mut ACL = std::ptr::null_mut();
    let mut dacl_present: windows_sys::Win32::Foundation::BOOL = 0;
    let mut defaulted: windows_sys::Win32::Foundation::BOOL = 0;

    // SAFETY: sd is a valid security descriptor, dacl_ptr/dacl_present/defaulted are valid
    // output pointers. dacl_ptr points into sd and remains valid until sd is freed.
    if GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl_ptr, &mut defaulted) == FALSE {
        let err = GetLastError();
        return Err(CoreError::ShareEnumeration(format!(
            "GetSecurityDescriptorDacl failed for '{}': error {err}",
            share_name
        )));
    }

    // Read AceCount only when pDacl is non-null — otherwise
    // `GetAclInformation(NULL, ...)` is UB, and the classification is
    // `Null` anyway (see `classify_dacl`).
    let ace_count: u32 = if dacl_ptr.is_null() {
        0
    } else {
        let mut acl_info = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        use windows_sys::Win32::Security::AclSizeInformation;
        // SAFETY: dacl_ptr is a valid non-null ACL pointer; acl_info is a valid stack variable.
        if GetAclInformation(
            dacl_ptr,
            std::ptr::addr_of_mut!(acl_info).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        ) == FALSE
        {
            let err = GetLastError();
            return Err(CoreError::ShareEnumeration(format!(
                "GetAclInformation failed for '{}': error {err}",
                share_name
            )));
        }
        acl_info.AceCount
    };

    match classify_dacl(dacl_present != 0, dacl_ptr.is_null(), ace_count) {
        DaclClassification::Null => return Ok(None),
        DaclClassification::Empty => return Ok(Some((Vec::new(), 0))),
        DaclClassification::Normal => {}
    }

    let mut permissions = Vec::with_capacity(ace_count as usize);
    let mut unsupported_count: usize = 0;

    for i in 0..ace_count {
        let mut ace_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: dacl_ptr is valid; i is within bounds (0..AceCount).
        if GetAce(dacl_ptr, i, &mut ace_ptr) == FALSE || ace_ptr.is_null() {
            continue;
        }

        // SAFETY: ace_ptr points to a valid ACE structure returned by GetAce.
        let header = &*(ace_ptr as *const ACE_HEADER);
        let (kind, mask, sid_ptr): (AceKind, u32, *const core::ffi::c_void) = match header.AceType {
            ACCESS_ALLOWED_ACE_TYPE => {
                // SAFETY: AceType is ACCESS_ALLOWED_ACE_TYPE, layout is ACCESS_ALLOWED_ACE.
                let ace = &*(ace_ptr as *const ACCESS_ALLOWED_ACE);
                let sid = std::ptr::addr_of!(ace.SidStart).cast();
                (AceKind::Allow, ace.Mask, sid)
            }
            ACCESS_DENIED_ACE_TYPE => {
                // SAFETY: AceType is ACCESS_DENIED_ACE_TYPE, layout is ACCESS_DENIED_ACE.
                let ace = &*(ace_ptr as *const ACCESS_DENIED_ACE);
                let sid = std::ptr::addr_of!(ace.SidStart).cast();
                (AceKind::Deny, ace.Mask, sid)
            }
            other => {
                // Follow-up finding 2: count + warn (instead of debug-only)
                // so the incomplete evaluation surfaces downstream.
                unsupported_count += 1;
                warn!(
                    share = share_name,
                    ace_type = other,
                    "Unsupported share ACE type — recorded as diagnostic, not evaluated"
                );
                continue;
            }
        };

        let sid_str = match sid_to_string(sid_ptr) {
            Ok(s) => s,
            Err(e) => {
                warn!(share = share_name, error = %e, "Cannot convert SID in share ACE");
                continue;
            }
        };

        let _ = INHERITED_ACE; // suppress unused import warning
        permissions.push(SharePermission {
            share_name: share_name.to_owned(),
            sid: Sid(sid_str),
            mask: AccessMask(mask),
            kind,
        });
    }

    Ok(Some((permissions, unsupported_count)))
}

// ───────────────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerate_shares_localhost_succeeds_or_access_denied() {
        // On a developer machine with no shares this is expected to succeed with 0 results
        // or fail with ShareEnumeration (access denied in restricted test environments).
        let result = enumerate_shares("");
        match result {
            Ok(shares) => {
                // Every share must have a non-empty name and UNC path
                for share in &shares {
                    assert!(!share.name.is_empty(), "share name must be non-empty");
                    assert!(
                        share.unc_path.starts_with("\\\\"),
                        "UNC path must start with \\\\"
                    );
                    // F8 regression: an empty server name must never produce \\\share.
                    assert!(
                        !share.unc_path.starts_with("\\\\\\"),
                        "UNC must not have an empty server segment: {}",
                        share.unc_path
                    );
                    let unc_without_prefix = &share.unc_path[2..];
                    let server_segment = unc_without_prefix.split('\\').next().unwrap_or("");
                    assert!(
                        !server_segment.is_empty(),
                        "server segment in UNC must not be empty: {}",
                        share.unc_path
                    );
                }
            }
            Err(CoreError::ShareEnumeration(_)) => {
                // Acceptable — restricted environment / no admin rights for level 502
            }
            Err(e) => panic!("Unexpected error: {e}"),
        }
    }

    #[test]
    fn enumerate_shares_local_path_populated_for_admin_share() {
        // If enumeration succeeds and C$ exists, local_path must be set
        // (level 502 provides shi502_path).
        if let Ok(shares) = enumerate_shares("") {
            if let Some(c_admin) = shares.iter().find(|s| s.name.eq_ignore_ascii_case("C$")) {
                assert!(
                    c_admin.local_path.is_some(),
                    "C$ share must report a local target path; got None"
                );
            }
        }
    }

    #[test]
    fn scan_shares_localhost_does_not_panic() {
        // Smoke test: must not panic regardless of environment
        let _result = scan_shares("");
    }

    #[test]
    fn scan_result_shares_and_permissions_consistent() {
        let result = scan_shares("");
        // Every permission must reference a share that was found (or an error was recorded)
        let share_names: std::collections::HashSet<_> =
            result.shares.iter().map(|s| s.name.as_str()).collect();
        let error_names: std::collections::HashSet<_> = result
            .errors
            .iter()
            .map(|e| e.share_name.as_str())
            .collect();
        for perm in &result.permissions {
            assert!(
                share_names.contains(perm.share_name.as_str())
                    || error_names.contains(perm.share_name.as_str()),
                "Permission for unknown share '{}' — must come from enumerated or errored shares",
                perm.share_name
            );
        }
    }

    // --- Finding 7: NULL DACL semantics in the combined scan ---

    /// Every successfully read share must appear in `share_dacls` as
    /// `(name, ShareDacl)` — NULL DACL or not. Audit consumers can then
    /// decide per share whether access protection exists.
    #[test]
    fn scan_shares_records_dacl_status_for_every_successful_share() {
        let result = scan_shares("");
        let dacl_names: std::collections::HashSet<_> = result
            .share_dacls
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        let error_names: std::collections::HashSet<_> = result
            .errors
            .iter()
            .map(|e| e.share_name.as_str())
            .collect();
        for share in &result.shares {
            assert!(
                dacl_names.contains(share.name.as_str())
                    || error_names.contains(share.name.as_str()),
                "Share '{}' has neither a DACL status nor a recorded error",
                share.name
            );
        }
    }

    /// `permissions` must contain nothing that does not stem from an
    /// `Acl(_)` entry of `share_dacls`. NULL-DACL shares must not
    /// inflate the flat list.
    #[test]
    fn permissions_equals_flattened_acl_entries_from_share_dacls() {
        let result = scan_shares("");
        let mut expected: Vec<&SharePermission> = Vec::new();
        for (_, scan) in &result.share_dacls {
            if let ShareDacl::Acl(perms) = &scan.dacl {
                expected.extend(perms.iter());
            }
        }
        assert_eq!(
            result.permissions.len(),
            expected.len(),
            "flat permissions must match the sum of Acl(_) entries in share_dacls"
        );
    }

    /// Pure data test: constructs a `ShareScanResult` with both
    /// Pure data test: construct a `ShareScanResult` with both edge
    /// cases and check they remain structurally distinguishable. Before,
    /// `permissions = vec![]` collapsed both into the same shape —
    /// `share_dacls` resolves precisely that.
    #[test]
    fn null_dacl_distinguishable_from_empty_acl_in_share_dacls() {
        let result = ShareScanResult {
            shares: vec![
                Share {
                    name: "unrestricted".to_owned(),
                    unc_path: r"\\srv\unrestricted".to_owned(),
                    local_path: None,
                    is_admin_share: false,
                },
                Share {
                    name: "deny-all".to_owned(),
                    unc_path: r"\\srv\deny-all".to_owned(),
                    local_path: None,
                    is_admin_share: false,
                },
            ],
            permissions: vec![],
            errors: vec![],
            share_dacls: vec![
                (
                    "unrestricted".to_owned(),
                    ShareDaclScan {
                        dacl: ShareDacl::NullDacl,
                        unsupported_count: 0,
                    },
                ),
                (
                    "deny-all".to_owned(),
                    ShareDaclScan {
                        dacl: ShareDacl::Acl(vec![]),
                        unsupported_count: 0,
                    },
                ),
            ],
        };

        let unrestricted = result
            .share_dacls
            .iter()
            .find(|(n, _)| n == "unrestricted")
            .map(|(_, scan)| &scan.dacl)
            .unwrap();
        let deny_all = result
            .share_dacls
            .iter()
            .find(|(n, _)| n == "deny-all")
            .map(|(_, scan)| &scan.dacl)
            .unwrap();

        assert!(
            matches!(unrestricted, ShareDacl::NullDacl),
            "unrestricted share must carry NullDacl status"
        );
        assert!(
            matches!(deny_all, ShareDacl::Acl(p) if p.is_empty()),
            "deny-all share must carry Acl(vec![]) status"
        );
        // Sicherheits-Roundtrip durch effective_share_mask:
        // Safety roundtrip via effective_share_mask:
        //   NullDacl → None  (no restriction — NTFS stays authoritative)
        //   Acl([])  → Some(0) (no access)
        let token = sids(&["S-1-1-0"]);
        assert!(
            effective_share_mask(unrestricted, &token).is_none(),
            "NullDacl must yield None from effective_share_mask"
        );
        assert_eq!(
            effective_share_mask(deny_all, &token).map(|m| m.0),
            Some(0),
            "Acl(vec![]) must yield Some(0) — no access"
        );
    }

    // --- effective_share_mask ---

    fn make_perm(share: &str, sid: &str, mask: u32, kind: AceKind) -> SharePermission {
        SharePermission {
            share_name: share.to_owned(),
            sid: Sid(sid.to_owned()),
            mask: AccessMask(mask),
            kind,
        }
    }

    fn sids(list: &[&str]) -> std::collections::HashSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn null_dacl_returns_none() {
        let mask = effective_share_mask(&ShareDacl::NullDacl, &sids(&["S-1-1-0"]));
        assert!(
            mask.is_none(),
            "NULL DACL must return None (no restriction)"
        );
    }

    #[test]
    fn empty_acl_returns_zero() {
        let mask = effective_share_mask(&ShareDacl::Acl(vec![]), &sids(&["S-1-1-0"]));
        assert_eq!(
            mask.map(|m| m.0),
            Some(0),
            "Empty ACL must yield zero (deny all)"
        );
    }

    #[test]
    fn allow_ace_grants_mask() {
        let perms = vec![make_perm("share", "S-1-1-0", 0x1F01FF, AceKind::Allow)];
        let mask = effective_share_mask(&ShareDacl::Acl(perms), &sids(&["S-1-1-0"]));
        assert_eq!(mask.map(|m| m.0), Some(0x1F01FF));
    }

    #[test]
    fn deny_overrides_allow() {
        // Canonical order (deny before allow). Before follow-up finding 1
        // (stored-order switch) the test used [Allow, Deny] and relied
        // on the old bucket semantics. With stored order, the first
        // decision per bit wins — the original "Deny blocks the
        // overlapping bits" assertion holds only when deny comes first
        // (= Windows-canonical order).
        let perms = vec![
            make_perm("share", "S-1-1-0", 0x0001FF, AceKind::Deny),
            make_perm("share", "S-1-1-0", 0x1F01FF, AceKind::Allow),
        ];
        let mask = effective_share_mask(&ShareDacl::Acl(perms), &sids(&["S-1-1-0"]));
        assert_eq!(mask.map(|m| m.0), Some(0x1F01FF & !0x0001FFu32));
    }

    #[test]
    fn non_matching_sid_ignored() {
        let perms = vec![make_perm("share", "S-1-5-32-544", 0x1F01FF, AceKind::Allow)];
        let mask = effective_share_mask(&ShareDacl::Acl(perms), &sids(&["S-1-1-0"]));
        assert_eq!(
            mask.map(|m| m.0),
            Some(0),
            "Non-matching SID must not contribute"
        );
    }

    #[test]
    fn group_membership_grants_rights() {
        let perms = vec![make_perm("share", "S-1-5-32-545", 0x1200A9, AceKind::Allow)];
        // user is a member of group S-1-5-32-545
        let mask = effective_share_mask(
            &ShareDacl::Acl(perms),
            &sids(&["S-1-5-21-1-1-1-1001", "S-1-5-32-545"]),
        );
        assert_eq!(mask.map(|m| m.0), Some(0x1200A9));
    }

    // --- expand_generic_rights ---

    #[test]
    fn generic_read_expands_to_file_generic_read() {
        // GENERIC_READ (0x8000_0000) must map to FILE_GENERIC_READ (0x0012_0089)
        let expanded = expand_generic_rights(0x8000_0000);
        assert_eq!(
            expanded, 0x0012_0089,
            "GENERIC_READ must expand to FILE_GENERIC_READ"
        );
    }

    #[test]
    fn generic_write_expands_to_file_generic_write() {
        // GENERIC_WRITE (0x4000_0000) must map to FILE_GENERIC_WRITE (0x0012_0116)
        let expanded = expand_generic_rights(0x4000_0000);
        assert_eq!(
            expanded, 0x0012_0116,
            "GENERIC_WRITE must expand to FILE_GENERIC_WRITE"
        );
    }

    #[test]
    fn generic_all_expands_to_file_all_access() {
        // GENERIC_ALL (0x1000_0000) must map to FILE_ALL_ACCESS (0x001F_01FF)
        let expanded = expand_generic_rights(0x1000_0000);
        assert_eq!(
            expanded, 0x001F_01FF,
            "GENERIC_ALL must expand to FILE_ALL_ACCESS"
        );
    }

    #[test]
    fn non_generic_mask_unchanged() {
        let mask = 0x0012_0089u32; // FILE_GENERIC_READ already
        assert_eq!(expand_generic_rights(mask), mask);
    }

    #[test]
    fn generic_all_ace_grants_full_access() {
        // Share ACE with GENERIC_ALL should yield FILE_ALL_ACCESS effective mask
        let perms = vec![make_perm("share", "S-1-1-0", 0x1000_0000, AceKind::Allow)];
        let mask = effective_share_mask(&ShareDacl::Acl(perms), &sids(&["S-1-1-0"]));
        assert_eq!(
            mask.map(|m| m.0),
            Some(0x001F_01FF),
            "GENERIC_ALL ACE must yield FILE_ALL_ACCESS"
        );
    }

    #[test]
    fn generic_read_deny_blocks_file_read_bits() {
        // GENERIC_READ deny must block the file-read bits, not just the
        // generic bit itself. Switched to canonical order (deny first); see deny_overrides_allow
        // for the reasoning.
        let perms = vec![
            make_perm("share", "S-1-1-0", 0x8000_0000, AceKind::Deny), // GENERIC_READ deny
            make_perm("share", "S-1-1-0", 0x001F_01FF, AceKind::Allow),
        ];
        let mask = effective_share_mask(&ShareDacl::Acl(perms), &sids(&["S-1-1-0"]));
        let effective = mask.map(|m| m.0).unwrap_or(0);
        assert_eq!(
            effective & 0x0012_0089,
            0,
            "GENERIC_READ deny must clear FILE_GENERIC_READ bits"
        );
    }

    /// S-1-5-2 = NETWORK (well-known SID Windows includes in the token on
    /// SMB logon). Before the follow-up finding 1 fix, share ACEs targeting
    /// NETWORK were ignored in CLI/GUI because the share token was always
    /// built with `Unspecified`.
    const SID_NETWORK: &str = "S-1-5-2";
    const SID_EVERYONE: &str = "S-1-1-0";
    const SID_USER: &str = "S-1-5-21-9-9-9-1001";

    #[test]
    fn deny_network_share_ace_does_nothing_without_network_in_token() {
        // Regression baseline: old token-build path (Unspecified) → token has
        // no NETWORK → Deny-NETWORK matches no SID → no effect.
        let perms = vec![
            make_perm("share", SID_NETWORK, 0x0012_0089, AceKind::Deny),
            make_perm("share", SID_EVERYONE, 0x0012_0089, AceKind::Allow),
        ];
        let token = sids(&[SID_USER, SID_EVERYONE]); // no NETWORK
        let effective = effective_share_mask(&ShareDacl::Acl(perms), &token)
            .map(|m| m.0)
            .unwrap();
        assert_eq!(
            effective, 0x0012_0089,
            "Without NETWORK in the token the Deny-NETWORK ACE is silently \
             ignored — this is the bug fixed by follow-up finding 1"
        );
    }

    #[test]
    fn deny_network_share_ace_blocks_read_when_network_in_token() {
        // Correct behaviour: NETWORK is in the SMB token after follow-up
        // finding 1 → Deny-NETWORK Read overrides Allow-Everyone Read →
        // effective 0.
        let perms = vec![
            make_perm("share", SID_NETWORK, 0x0012_0089, AceKind::Deny),
            make_perm("share", SID_EVERYONE, 0x0012_0089, AceKind::Allow),
        ];
        let token = sids(&[SID_USER, SID_EVERYONE, SID_NETWORK]);
        let effective = effective_share_mask(&ShareDacl::Acl(perms), &token)
            .map(|m| m.0)
            .unwrap();
        assert_eq!(
            effective, 0,
            "Deny-NETWORK must clear the Allow-Everyone Read bits when NETWORK \
             is part of the SMB token"
        );
    }

    #[test]
    fn allow_network_share_ace_grants_when_network_in_token() {
        // Mirror case: an Allow-NETWORK-only ACE must apply over SMB.
        let perms = vec![make_perm("share", SID_NETWORK, 0x0012_0089, AceKind::Allow)];
        let token_with_network = sids(&[SID_USER, SID_NETWORK]);
        let token_without_network = sids(&[SID_USER]);
        assert_eq!(
            effective_share_mask(&ShareDacl::Acl(perms.clone()), &token_with_network).map(|m| m.0),
            Some(0x0012_0089),
            "Allow-NETWORK must grant Read over SMB"
        );
        assert_eq!(
            effective_share_mask(&ShareDacl::Acl(perms), &token_without_network).map(|m| m.0),
            Some(0),
            "Same ACE must not grant anything for a token without NETWORK"
        );
    }

    // --- Follow-up finding 1 (review 2026-05-25): stored-order share eval ---
    //

    /// Direct reviewer example. Before: bucket → 0. Now: stored order
    /// → Read. NTFS and share paths now share the same semantics.
    #[test]
    fn non_canonical_allow_before_deny_first_wins() {
        let perms = vec![
            make_perm("share", SID_EVERYONE, 0x0012_0089, AceKind::Allow),
            make_perm("share", SID_EVERYONE, 0x0012_0089, AceKind::Deny),
        ];
        let token = sids(&[SID_USER, SID_EVERYONE]);
        let mask = effective_share_mask(&ShareDacl::Acl(perms), &token)
            .map(|m| m.0)
            .unwrap();
        assert_eq!(
            mask, 0x0012_0089,
            "Allow first must win (stored-order AccessCheck); \
             the old bucket model would have wrongly returned 0 here"
        );
    }

    /// Canonical case — deny before allow. Deny wins because it is the
    /// first decision per bit. The bucket model happened to give the
    /// same result; now the result is semantically correct.
    #[test]
    fn canonical_deny_before_allow_first_wins() {
        let perms = vec![
            make_perm("share", SID_EVERYONE, 0x0012_0089, AceKind::Deny),
            make_perm("share", SID_EVERYONE, 0x0012_0089, AceKind::Allow),
        ];
        let token = sids(&[SID_USER, SID_EVERYONE]);
        let mask = effective_share_mask(&ShareDacl::Acl(perms), &token)
            .map(|m| m.0)
            .unwrap();
        assert_eq!(mask, 0, "Deny first must block all bits");
    }

    /// Disjunkte Bits: Deny SYNCHRONIZE (0x100000), dann Allow Read
    /// = 0x0002_0089 (Read MINUS SYNCHRONIZE).
    /// Disjoint bits: Deny SYNCHRONIZE then Allow Read. Stored order
    /// allows the read bits except SYNCHRONIZE which is already denied.
    #[test]
    fn partial_overlap_first_decision_per_bit() {
        let perms = vec![
            make_perm("share", SID_EVERYONE, 0x0010_0000, AceKind::Deny), // SYNCHRONIZE deny
            make_perm("share", SID_EVERYONE, 0x0012_0089, AceKind::Allow), // Read (inkl. SYNCHRONIZE)
        ];
        let token = sids(&[SID_USER, SID_EVERYONE]);
        let mask = effective_share_mask(&ShareDacl::Acl(perms), &token)
            .map(|m| m.0)
            .unwrap();
        assert_eq!(
            mask, 0x0002_0089,
            "Read bits are allowed, but SYNCHRONIZE stays denied — \
             the first decision per bit wins"
        );
    }

    #[test]
    fn detects_non_canonical_share_dacl_position() {
        let perms = vec![
            make_perm("share", SID_EVERYONE, 0x0012_0089, AceKind::Allow),
            make_perm("share", SID_EVERYONE, 0x0012_0089, AceKind::Deny),
        ];
        assert_eq!(super::first_non_canonical_position(&perms), Some(1));
    }

    #[test]
    fn canonical_share_dacl_passes_detector() {
        let perms = vec![
            make_perm("share", SID_EVERYONE, 0x0012_0089, AceKind::Deny),
            make_perm("share", SID_EVERYONE, 0x0012_0089, AceKind::Allow),
        ];
        assert_eq!(super::first_non_canonical_position(&perms), None);
    }

    /// Pure data test: ShareDaclScan can carry both fields. Live creation
    /// via `get_share_dacl` against a real share DACL is not unit-testable;
    /// this test covers the data shape. Plumbing logic (engine pushes
    /// diagnostic, risk engine flags incomplete) is covered in the
    /// respective crates.
    #[test]
    fn share_dacl_scan_carries_dacl_and_unsupported_count() {
        let scan_clean = ShareDaclScan {
            dacl: ShareDacl::Acl(vec![make_perm(
                "s",
                SID_EVERYONE,
                0x0012_0089,
                AceKind::Allow,
            )]),
            unsupported_count: 0,
        };
        assert_eq!(scan_clean.unsupported_count, 0);
        assert!(matches!(scan_clean.dacl, ShareDacl::Acl(ref p) if p.len() == 1));

        let scan_partial = ShareDaclScan {
            dacl: ShareDacl::Acl(vec![]),
            unsupported_count: 3,
        };
        assert_eq!(scan_partial.unsupported_count, 3);
    }

    // --- Follow-up finding 1 (review 2026-05-25): NULL DACL classification ---

    /// Per MSDN: `GetSecurityDescriptorDacl` returns `bDaclPresent = FALSE`,
    /// Per MSDN: `GetSecurityDescriptorDacl` returns `bDaclPresent = FALSE`
    /// when the SD has no DACL entry at all. That is a NULL DACL —
    /// unrestricted. `ptr` and `ace_count` are irrelevant in this case.
    #[test]
    fn classify_dacl_not_present_is_null() {
        assert_eq!(
            super::classify_dacl(false, false, 5),
            super::DaclClassification::Null
        );
        assert_eq!(
            super::classify_dacl(false, true, 0),
            super::DaclClassification::Null
        );
    }

    /// **The core fix for follow-up finding 1:** `bDaclPresent = TRUE` with
    /// `pDacl == NULL` is an explicit NULL DACL and means unrestricted
    /// access. Previously `parse_share_dacl` mapped this to `Empty`
    /// (deny-all) — a direct false-negative source for share audits.
    #[test]
    fn classify_dacl_present_but_pointer_null_is_null() {
        assert_eq!(
            super::classify_dacl(true, true, 0),
            super::DaclClassification::Null,
            "present=TRUE, pDacl=NULL MUST classify as Null (unrestricted), \
             not Empty (deny-all) — this was the follow-up-finding-1 bug"
        );
        // ace_count cannot be filled by GetAclInformation in this case; a
        // garbage value must not change the result.
        assert_eq!(
            super::classify_dacl(true, true, 999),
            super::DaclClassification::Null,
            "ptr_is_null must short-circuit before ace_count is consulted"
        );
    }

    #[test]
    fn classify_dacl_present_non_null_zero_aces_is_empty() {
        assert_eq!(
            super::classify_dacl(true, false, 0),
            super::DaclClassification::Empty,
            "Genuine empty ACL stays deny-all"
        );
    }

    #[test]
    fn classify_dacl_present_non_null_with_aces_is_normal() {
        assert_eq!(
            super::classify_dacl(true, false, 1),
            super::DaclClassification::Normal
        );
        assert_eq!(
            super::classify_dacl(true, false, 1_000_000),
            super::DaclClassification::Normal
        );
    }

    /// Structural regression: previously `share_dacls: Vec<(String,
    /// ShareDacl)>` and the unsupported_count was lost on push. Now it
    /// is `Vec<(String, ShareDaclScan)>` — the per-share count is
    /// accessible to audit consumers.
    #[test]
    fn share_dacls_field_preserves_per_share_unsupported_count() {
        let result = ShareScanResult {
            shares: vec![Share {
                name: "S".to_owned(),
                unc_path: r"\\srv\S".to_owned(),
                local_path: None,
                is_admin_share: false,
            }],
            permissions: vec![],
            errors: vec![],
            share_dacls: vec![(
                "S".to_owned(),
                ShareDaclScan {
                    dacl: ShareDacl::Acl(vec![]),
                    unsupported_count: 7,
                },
            )],
        };

        let scan = &result.share_dacls[0].1;
        assert_eq!(
            scan.unsupported_count, 7,
            "per-share unsupported_count must survive into share_dacls"
        );
    }
}
