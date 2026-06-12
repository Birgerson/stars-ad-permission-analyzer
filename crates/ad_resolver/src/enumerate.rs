// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Inventory of visible identities for the UX search helper.
//!
//!
//! Returns a flat list of `IdentitySnapshot` entries with name, type,
//! domain and an optional description. **Not** used for permission
//! evaluation by the GUI — that only depends on SIDs and tokens. The
//! function exists purely for the autocomplete helper in the name field
//! ("you type, I suggest").
//!
//!   audit-relevant.
//!
//! **Data sources:**
//! * `NetUserEnum`         → domain users (on a DC) / local users elsewhere
//! * `NetGroupEnum`        → global (domain) groups
//! * `NetLocalGroupEnum`   → local groups (BUILTIN\… on the DC)
//! * Hard-coded well-known table for `Everyone`, `Authenticated Users`,
//!   `SYSTEM` etc. — those SIDs are not enumerable but matter for audit.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use adpa_core::error::CoreError;
use adpa_core::model::IdentityKind;
use tracing::{debug, warn};
use win_safe::netapi::NetApiBuffer;
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, NO_ERROR};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetGroupEnum, NetLocalGroupEnum, NetUserEnum, NetWkstaGetInfo, FILTER_NORMAL_ACCOUNT,
    GROUP_INFO_1, LOCALGROUP_INFO_1, MAX_PREFERRED_LENGTH, USER_INFO_10, WKSTA_INFO_100,
};

/// A single identity as it appears in the search suggestions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentitySnapshot {
    /// Logon name without domain prefix, e.g. `Administrator`.
    pub name: String,
    /// Authority/domain, e.g. `TESTDOMAIN`, `BUILTIN`, `NT AUTHORITY`, empty
    /// for non-domain well-knowns like `Everyone`.
    pub domain: String,
    pub kind: IdentityKind,
    /// Description from the NetAPI structs (`usri10_comment`,
    /// `grpi1_comment`, `lgrpi1_comment`) or a short hand-written gloss
    /// for well-knowns. Empty when none.
    pub description: String,
}

impl IdentitySnapshot {
    /// Classifies the entry as "does the search string match me?".
    /// Case-insensitive search over name + domain so e.g. `bui` matches
    /// `BUILTIN\Administrators`.
    pub fn matches(&self, query: &str) -> bool {
        let q = query.to_lowercase();
        self.name.to_lowercase().contains(&q) || self.domain.to_lowercase().contains(&q)
    }

    /// Display form `DOMAIN\Name`, no backslash when no domain.
    pub fn qualified_name(&self) -> String {
        if self.domain.is_empty() {
            self.name.clone()
        } else {
            format!("{}\\{}", self.domain, self.name)
        }
    }
}

/// Collects all identities relevant for the search suggestions. Errors in
/// individual sources are logged as warnings and **do not** abort — the
/// other sources still contribute.
pub fn enumerate_all() -> Vec<IdentitySnapshot> {
    let netbios_domain = local_netbios_domain().unwrap_or_default();
    let mut out: Vec<IdentitySnapshot> = Vec::new();

    out.extend(well_known_table());

    match list_users(None, &netbios_domain) {
        Ok(mut v) => out.append(&mut v),
        Err(e) => warn!(error = %e, "enumerate_all: NetUserEnum failed"),
    }
    match list_global_groups(None, &netbios_domain) {
        Ok(mut v) => out.append(&mut v),
        Err(e) => warn!(error = %e, "enumerate_all: NetGroupEnum failed"),
    }
    match list_local_groups(None) {
        Ok(mut v) => out.append(&mut v),
        Err(e) => warn!(error = %e, "enumerate_all: NetLocalGroupEnum failed"),
    }

    // Stable, predictable ordering: first by domain, then by name
    // (locale-independent via case-insensitive comparison).
    out.sort_by(|a, b| {
        a.domain
            .to_lowercase()
            .cmp(&b.domain.to_lowercase())
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    out.dedup_by(|a, b| a.name == b.name && a.domain == b.domain);

    debug!(count = out.len(), "enumerate_all: snapshot built");
    out
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

fn list_users(server: Option<&str>, domain: &str) -> Result<Vec<IdentitySnapshot>, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());

    let mut out: Vec<IdentitySnapshot> = Vec::new();
    let mut resume_handle: u32 = 0;

    loop {
        // RAII-Guard pro Iteration — neue Variable, neue Lifetime, neuer Free.
        // RAII guard per iteration — new variable, new lifetime, new Free.
        let mut buf: NetApiBuffer<USER_INFO_10> = NetApiBuffer::null();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;

        // null-terminierte UTF-16-Sequenz. NetApiBuffer<USER_INFO_10> owns
        // the allocated buffer after this call.
        // SAFETY: server_ptr is either null or points to a valid null-
        // terminated UTF-16 sequence. NetApiBuffer<USER_INFO_10> owns the
        // allocated buffer after this call.
        let status = unsafe {
            NetUserEnum(
                server_ptr,
                10,                    // Level 10 = USER_INFO_10
                FILTER_NORMAL_ACCOUNT, // "normal" users only, no trust or service accounts
                buf.out_ptr().cast(),
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            )
        };

        if !buf.is_null() && entries_read > 0 {
            // SAFETY: buf.as_ptr() references `entries_read` consecutive
            // USER_INFO_10 structs allocated by NetAPI.
            let entries =
                unsafe { std::slice::from_raw_parts(buf.as_ptr(), entries_read as usize) };
            for entry in entries {
                // SAFETY: all fields are null-terminated UTF-16 strings in
                // the NetApi buffer.
                let name = unsafe { wide_ptr_to_string(entry.usri10_name) };
                if name.is_empty() {
                    continue;
                }
                let comment = unsafe { wide_ptr_to_string(entry.usri10_comment) };
                let full = unsafe { wide_ptr_to_string(entry.usri10_full_name) };
                let description = if !comment.is_empty() { comment } else { full };
                out.push(IdentitySnapshot {
                    name,
                    domain: domain.to_string(),
                    kind: IdentityKind::User,
                    description,
                });
            }
        }
        // `buf` is dropped at the end of the iteration and calls
        // NetApiBufferFree — regardless of subsequent break or new loop.

        if status == NO_ERROR {
            break;
        }
        if status != ERROR_MORE_DATA {
            return Err(CoreError::LdapQuery(format!(
                "NetUserEnum failed with status {status}"
            )));
        }
        // On MORE_DATA: next page using the updated resume_handle.
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

fn list_global_groups(
    server: Option<&str>,
    domain: &str,
) -> Result<Vec<IdentitySnapshot>, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());

    let mut out: Vec<IdentitySnapshot> = Vec::new();
    let mut resume_handle: usize = 0;

    loop {
        // RAII-Guard pro Iteration.
        // RAII guard per iteration.
        let mut buf: NetApiBuffer<GROUP_INFO_1> = NetApiBuffer::null();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;

        // NetApiBuffer<GROUP_INFO_1> owns the allocated buffer.
        // SAFETY: as above. resume_handle is updated in-place by NetAPI.
        // NetApiBuffer<GROUP_INFO_1> owns the allocated buffer.
        let status = unsafe {
            NetGroupEnum(
                server_ptr,
                1, // Level 1 = GROUP_INFO_1
                buf.out_ptr().cast(),
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            )
        };

        if !buf.is_null() && entries_read > 0 {
            // SAFETY: GROUP_INFO_1 array from NetApi buffer.
            let entries =
                unsafe { std::slice::from_raw_parts(buf.as_ptr(), entries_read as usize) };
            for entry in entries {
                // SAFETY: null-terminierte UTF-16-Strings.
                // SAFETY: null-terminated UTF-16 strings.
                let name = unsafe { wide_ptr_to_string(entry.grpi1_name) };
                if name.is_empty() {
                    continue;
                }
                let description = unsafe { wide_ptr_to_string(entry.grpi1_comment) };
                out.push(IdentitySnapshot {
                    name,
                    domain: domain.to_string(),
                    kind: IdentityKind::Group,
                    description,
                });
            }
        }
        // `buf` is dropped at the end of the iteration and calls NetApiBufferFree.

        if status == NO_ERROR {
            break;
        }
        if status != ERROR_MORE_DATA {
            return Err(CoreError::LdapQuery(format!(
                "NetGroupEnum failed with status {status}"
            )));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

fn list_local_groups(server: Option<&str>) -> Result<Vec<IdentitySnapshot>, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());

    let mut out: Vec<IdentitySnapshot> = Vec::new();
    let mut resume_handle: usize = 0;

    loop {
        // RAII-Guard pro Iteration.
        // RAII guard per iteration.
        let mut buf: NetApiBuffer<LOCALGROUP_INFO_1> = NetApiBuffer::null();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;

        let status = unsafe {
            NetLocalGroupEnum(
                server_ptr,
                1, // Level 1 = LOCALGROUP_INFO_1
                buf.out_ptr().cast(),
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            )
        };

        if !buf.is_null() && entries_read > 0 {
            // SAFETY: LOCALGROUP_INFO_1-Array.
            let entries =
                unsafe { std::slice::from_raw_parts(buf.as_ptr(), entries_read as usize) };
            for entry in entries {
                // SAFETY: null-terminierte UTF-16-Strings.
                let name = unsafe { wide_ptr_to_string(entry.lgrpi1_name) };
                if name.is_empty() {
                    continue;
                }
                let description = unsafe { wide_ptr_to_string(entry.lgrpi1_comment) };
                out.push(IdentitySnapshot {
                    name,
                    // Local groups carry the BUILTIN authority on a DC; on
                    // a member server it would be the NetBIOS machine name.
                    // We display "BUILTIN" for UX; the actual SID lookup
                    // via `LookupAccountNameW` does not rely on this field
                    // and routes through the local LSA correctly.
                    domain: "BUILTIN".to_string(),
                    kind: IdentityKind::Group,
                    description,
                });
            }
        }
        // `buf` is dropped at iteration end and calls NetApiBufferFree.

        if status == NO_ERROR {
            break;
        }
        if status != ERROR_MORE_DATA {
            return Err(CoreError::LdapQuery(format!(
                "NetLocalGroupEnum failed with status {status}"
            )));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

/// A hard-coded list of audit-relevant well-known SIDs that NetUserEnum /
/// NetGroupEnum do not return. The authority strings use Microsoft's
/// non-localized names so `LookupAccountNameW` resolves them on any
/// system (including German installs where the LSA "display name" is
/// localized).
fn well_known_table() -> Vec<IdentitySnapshot> {
    let g = IdentityKind::WellKnown;
    vec![
        IdentitySnapshot {
            name: "Everyone".into(),
            domain: String::new(),
            kind: g.clone(),
            description: "Everyone, including anonymous access in certain configurations".into(),
        },
        IdentitySnapshot {
            name: "Authenticated Users".into(),
            domain: "NT AUTHORITY".into(),
            kind: g.clone(),
            description: "Every authenticated user (excludes anonymous logon)".into(),
        },
        IdentitySnapshot {
            name: "ANONYMOUS LOGON".into(),
            domain: "NT AUTHORITY".into(),
            kind: g.clone(),
            description: "Unauthenticated access".into(),
        },
        IdentitySnapshot {
            name: "SYSTEM".into(),
            domain: "NT AUTHORITY".into(),
            kind: g.clone(),
            description: "Local System — services run under this identity".into(),
        },
        IdentitySnapshot {
            name: "LOCAL SERVICE".into(),
            domain: "NT AUTHORITY".into(),
            kind: g.clone(),
            description: "Local service account, no network authentication".into(),
        },
        IdentitySnapshot {
            name: "NETWORK SERVICE".into(),
            domain: "NT AUTHORITY".into(),
            kind: g.clone(),
            description: "Service account with computer identity on the network".into(),
        },
        IdentitySnapshot {
            name: "NETWORK".into(),
            domain: "NT AUTHORITY".into(),
            kind: g.clone(),
            description: "Implicit for any access via SMB/network".into(),
        },
        IdentitySnapshot {
            name: "INTERACTIVE".into(),
            domain: "NT AUTHORITY".into(),
            kind: g.clone(),
            description: "Users logged on locally".into(),
        },
        IdentitySnapshot {
            name: "CREATOR OWNER".into(),
            domain: String::new(),
            kind: g,
            description: "Placeholder for the creator of an object".into(),
        },
    ]
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

/// Reads the NetBIOS domain name via `NetWkstaGetInfo` (level 100). On a
/// workgroup host this returns the computer name instead of a domain —
/// either way is usable for our UX.
fn local_netbios_domain() -> Option<String> {
    // RAII guard for WKSTA_INFO_100.
    let mut buf: NetApiBuffer<WKSTA_INFO_100> = NetApiBuffer::null();
    // NetApiBuffer<WKSTA_INFO_100> owns the allocated buffer.
    // SAFETY: null server = local host, level 100 is valid,
    // NetApiBuffer<WKSTA_INFO_100> owns the allocated buffer.
    let status = unsafe { NetWkstaGetInfo(std::ptr::null(), 100, buf.out_ptr().cast()) };
    if status != NO_ERROR || buf.is_null() {
        return None;
    }
    // SAFETY: buf.as_ptr() refers to a WKSTA_INFO_100 struct.
    let info = unsafe { &*buf.as_ptr() };
    // SAFETY: wki100_langroup is a null-terminated UTF-16 string.
    let name = unsafe { wide_ptr_to_string(info.wki100_langroup) };
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
    // `buf` is dropped here and calls NetApiBufferFree.
}

fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// # Safety
/// `p` must be a valid pointer to a null-terminated UTF-16 sequence or
/// null.
unsafe fn wide_ptr_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let len = (0usize..).take_while(|&i| *p.add(i) != 0).count();
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The well-known table must include the standard audit identities.
    /// Pure code check — no Windows API.
    #[test]
    fn well_known_table_includes_critical_entries() {
        let table = well_known_table();
        let names: Vec<&str> = table.iter().map(|i| i.name.as_str()).collect();
        for required in [
            "Everyone",
            "Authenticated Users",
            "SYSTEM",
            "NETWORK",
            "ANONYMOUS LOGON",
            "CREATOR OWNER",
        ] {
            assert!(
                names.contains(&required),
                "Well-Known-Tabelle fehlt: {required}"
            );
        }
    }

    /// Substring matching is case-insensitive and searches name + domain.
    #[test]
    fn matches_is_case_insensitive_and_covers_domain() {
        let s = IdentitySnapshot {
            name: "Administrator".into(),
            domain: "TESTDOMAIN".into(),
            kind: IdentityKind::User,
            description: String::new(),
        };
        assert!(s.matches("ADM"));
        assert!(s.matches("adm"));
        assert!(s.matches("TESTDOM"));
        assert!(s.matches("testdom"));
        assert!(!s.matches("krbtgt"));
    }

    /// On a real Windows host enumeration returns at least the well-known
    /// entries + local groups. `#[ignore]` because CI runners have
    /// different local account layouts.
    #[test]
    #[ignore = "runs live against LSA/NetAPI — run locally with `cargo test -- --ignored`"]
    fn enumerate_returns_at_least_well_known_and_local_groups() {
        let all = enumerate_all();
        assert!(all.iter().any(|i| i.name == "Everyone"));
        assert!(all.iter().any(|i| i.domain == "BUILTIN"));
    }
}
