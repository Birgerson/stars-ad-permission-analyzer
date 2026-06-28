// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Identity and group resolution via the local Windows LSA/SAM APIs.
//!
//! On a domain controller (and usually on domain-joined members with a
//! current cache) Windows can supply the full identity and group
//! membership of an account via the SAM/LSA interfaces — no LDAP bind
//! required. This is exactly the path Windows itself walks during a
//! logon.
//!
//! This module provides the building blocks and a convenience call
//! [`resolve_identity_via_sam`] that turns a SID into a complete
//! `(Identity, Vec<GroupMembership>)` pair:
//!   * `LookupAccountSidW` → name, domain, kind,
//!   * `NetUserGetGroups` → global (domain) groups,
//!   * `NetUserGetLocalGroups` (via `local_groups`) → local groups on
//!     the target system,
//!   * `LookupAccountNameW` → SID per group name.
//!
//! With this resolution the `permission_engine` sees the same set of
//! token SIDs Windows would build for the real access — and
//! `BUILTIN\Administrators` shows up for the Administrator account
//! even without an LDAP connection.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use adpa_core::error::CoreError;
use adpa_core::model::{
    GroupMembership, Identity, IdentityKind, MembershipPath, MembershipPathSource, Sid,
};
use tracing::{debug, warn};
use win_safe::netapi::NetApiBuffer;
use windows_sys::Win32::Foundation::{LocalFree, ERROR_ACCESS_DENIED, FALSE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetUserGetGroups, NetUserGetInfo, GROUP_USERS_INFO_0, MAX_PREFERRED_LENGTH, UF_ACCOUNTDISABLE,
    USER_INFO_1,
};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{
    LookupAccountNameW, LookupAccountSidW, SidTypeAlias, SidTypeComputer, SidTypeDeletedAccount,
    SidTypeGroup, SidTypeInvalid, SidTypeUnknown, SidTypeUser, SidTypeWellKnownGroup,
};

// resolve_local_group_sids stays in the public API for external callers
// (e.g. the GUI worker). The SAM resolver now uses the richer
// resolve_local_group_chains variant; the pure-SID fallback is no longer
// needed here.

/// NERR_UserNotFound status code from lmerr.h.
const NERR_USER_NOT_FOUND: u32 = 2221;

/// Resolution result of `LookupAccountSidW`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountInfo {
    /// Account name without domain prefix, e.g. `Administrator`.
    pub name: String,
    /// Authority/domain name, e.g. `EXAMPLE` or `BUILTIN`. May be empty
    /// when the SID type has no domain (rare `SidTypeWellKnownGroup`
    /// cases).
    pub domain: String,
    /// Classifies the SID-Use field from the LSA response.
    pub kind: IdentityKind,
}

/// Looks up a SID string via the local LSA and returns name, domain and
/// account kind. Uses `ConvertStringSidToSidW` for string-to-bytes
/// conversion and `LookupAccountSidW` for the lookup.
pub fn lookup_account_for_sid(sid_str: &str) -> Result<AccountInfo, CoreError> {
    let sid_w = to_wide_null(sid_str);
    let mut sid_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY: sid_w is a valid null-terminated wide string; sid_ptr is set
    // by Windows via LocalAlloc on success and must be released with
    // LocalFree below.
    let ok = unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut sid_ptr) };
    if ok == FALSE || sid_ptr.is_null() {
        return Err(CoreError::SidResolution(format!(
            "ConvertStringSidToSidW failed for '{sid_str}'"
        )));
    }

    let result = lookup_account_for_sid_ptr(sid_ptr);

    // SAFETY: sid_ptr was allocated by ConvertStringSidToSidW; LocalFree
    // is the documented release call.
    unsafe { LocalFree(sid_ptr) };
    result
}

fn lookup_account_for_sid_ptr(sid_ptr: *mut std::ffi::c_void) -> Result<AccountInfo, CoreError> {
    let mut name_size: u32 = 0;
    let mut domain_size: u32 = 0;
    let mut sid_use: i32 = 0;

    // Two-call pattern: query required sizes first (the call returns
    // ERROR_INSUFFICIENT_BUFFER and writes the sizes).
    // SAFETY: sid_ptr is a valid SID buffer; output pointers may be null
    // on the sizing call.
    unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid_ptr,
            std::ptr::null_mut(),
            &mut name_size,
            std::ptr::null_mut(),
            &mut domain_size,
            &mut sid_use,
        );
    }

    if name_size == 0 {
        return Err(CoreError::SidResolution(
            "LookupAccountSidW: SID has no name on this system".to_owned(),
        ));
    }

    let mut name_buf = vec![0u16; name_size as usize];
    let mut domain_buf = vec![0u16; domain_size as usize];

    // SAFETY: buffers are sized per the sizing call.
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid_ptr,
            name_buf.as_mut_ptr(),
            &mut name_size,
            domain_buf.as_mut_ptr(),
            &mut domain_size,
            &mut sid_use,
        )
    };
    if ok == FALSE {
        return Err(CoreError::SidResolution(
            "LookupAccountSidW failed on the second call".to_owned(),
        ));
    }

    Ok(AccountInfo {
        name: wide_buf_to_string(&name_buf),
        domain: wide_buf_to_string(&domain_buf),
        kind: sid_use_to_kind(sid_use),
    })
}

/// Returns the global (domain) groups `username` is a direct member of.
/// `NetUserGetGroups` is the domain counterpart to
/// `NetUserGetLocalGroups` and does not include nested memberships
/// (those are handled separately during LSA token construction).
pub fn user_global_group_names(
    server: Option<&str>,
    username: &str,
) -> Result<Vec<String>, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let username_w = to_wide_null(username);

    // RAII guard for the NetApi buffer: every path — success, status error,
    // slice read — frees the buffer in Drop. Before review round 10 the free
    // calls were sprinkled across three manual sites.
    let mut buf: NetApiBuffer<GROUP_USERS_INFO_0> = NetApiBuffer::null();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;

    // SAFETY: server_ptr is either null or points to a valid null-terminated
    // wide string; username_w is null-terminated. NetApiBuffer<GROUP_USERS_INFO_0>
    // owns the allocated buffer after this call.
    let status = unsafe {
        NetUserGetGroups(
            server_ptr,
            username_w.as_ptr(),
            0, // level 0 = GROUP_USERS_INFO_0
            buf.out_ptr().cast(),
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
        )
    };

    if status != NO_ERROR {
        return match status {
            ERROR_ACCESS_DENIED => Err(CoreError::AccessDenied(format!(
                "NetUserGetGroups: access denied for '{username}' on {server:?}"
            ))),
            NERR_USER_NOT_FOUND => {
                debug!(username, ?server, "NetUserGetGroups: user not found");
                Ok(Vec::new())
            }
            _ => Err(CoreError::LdapQuery(format!(
                "NetUserGetGroups('{username}') failed with status {status}"
            ))),
        };
    }

    let mut groups = Vec::with_capacity(entries_read as usize);
    if !buf.is_null() && entries_read > 0 {
        // SAFETY: buf.as_ptr() points to `entries_read` consecutive
        // GROUP_USERS_INFO_0 records allocated by NetApi.
        let entries = unsafe { std::slice::from_raw_parts(buf.as_ptr(), entries_read as usize) };
        for entry in entries {
            // SAFETY: grui0_name is a valid null-terminated wide string
            // inside the NetApi-allocated buffer.
            let name = unsafe { wide_ptr_to_string(entry.grui0_name) };
            if !name.is_empty() {
                groups.push(name);
            }
        }
    }

    Ok(groups)
    // `buf` is dropped here, calling NetApiBufferFree.
}

/// Looks up an account or group name on the given system and returns
/// its SID as the canonical S-R-I-... string.
pub fn lookup_sid_for_account(system: Option<&str>, name: &str) -> Result<Sid, CoreError> {
    let system_w = system.map(to_wide_null);
    let system_ptr = system_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let name_w = to_wide_null(name);

    let mut sid_size: u32 = 0;
    let mut domain_size: u32 = 0;
    let mut sid_use: i32 = 0;
    // SAFETY: name_w is null-terminated; output pointers may be null on
    // the sizing call.
    unsafe {
        LookupAccountNameW(
            system_ptr,
            name_w.as_ptr(),
            std::ptr::null_mut(),
            &mut sid_size,
            std::ptr::null_mut(),
            &mut domain_size,
            &mut sid_use,
        );
    }
    if sid_size == 0 {
        return Err(CoreError::SidResolution(format!(
            "LookupAccountNameW: '{name}' has no SID on this system"
        )));
    }

    let mut sid_buf = vec![0u8; sid_size as usize];
    let mut domain_buf = vec![0u16; domain_size as usize];
    // SAFETY: buffers are sized per the sizing call.
    let ok = unsafe {
        LookupAccountNameW(
            system_ptr,
            name_w.as_ptr(),
            sid_buf.as_mut_ptr() as *mut _,
            &mut sid_size,
            domain_buf.as_mut_ptr(),
            &mut domain_size,
            &mut sid_use,
        )
    };
    if ok == FALSE {
        return Err(CoreError::SidResolution(format!(
            "LookupAccountNameW failed for '{name}'"
        )));
    }

    let mut sid_str: *mut u16 = std::ptr::null_mut();
    // SAFETY: sid_buf contains a valid SID written by LookupAccountNameW.
    let ok = unsafe { ConvertSidToStringSidW(sid_buf.as_ptr() as *mut _, &mut sid_str) };
    if ok == FALSE || sid_str.is_null() {
        return Err(CoreError::SidResolution(format!(
            "ConvertSidToStringSidW failed for '{name}'"
        )));
    }
    // SAFETY: sid_str was allocated by Windows via LocalAlloc.
    let s = unsafe { wide_ptr_to_string(sid_str) };
    // SAFETY: sid_str must be released with LocalFree per the API contract.
    unsafe { LocalFree(sid_str as *mut _) };
    Ok(Sid(s))
}

/// Reads the `disabled` status of a user via `NetUserGetInfo` level 1 and
/// checks the `UF_ACCOUNTDISABLE` flag.
///
/// `Ok(Some(true))`  → account is disabled.
/// `Ok(Some(false))` → account is active.
/// `Ok(None)`        → status could not be reliably determined (user not
///                      found, access denied, or another NetAPI error).
///                      Callers should then set the
///                      `PermissionDiagnostic::IdentityDisabledStatusUnknown`
///                      marker.
/// `Err`             → unexpected library error.
///
/// Closes review 2026-06-04 round 2 finding 5 — the SAM path previously
/// hard-coded `disabled = false`, silently showing disabled accounts as
/// active.
pub fn user_account_disabled(
    server: Option<&str>,
    username: &str,
) -> Result<Option<bool>, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let username_w = to_wide_null(username);

    // RAII guard: frees the USER_INFO_1 buffer in every path.
    let mut buf: NetApiBuffer<USER_INFO_1> = NetApiBuffer::null();
    // SAFETY: server_ptr is null or a valid null-terminated wide string;
    // username_w is null-terminated. NetApiBuffer<USER_INFO_1> owns the
    // allocated buffer after this call.
    let status = unsafe {
        NetUserGetInfo(
            server_ptr,
            username_w.as_ptr(),
            1, // level 1 → USER_INFO_1
            buf.out_ptr().cast(),
        )
    };

    if status != NO_ERROR {
        return match status {
            ERROR_ACCESS_DENIED => {
                debug!(
                    username,
                    ?server,
                    "NetUserGetInfo: access denied — disabled status unknown"
                );
                Ok(None)
            }
            NERR_USER_NOT_FOUND => {
                debug!(
                    username,
                    ?server,
                    "NetUserGetInfo: user not found — disabled status unknown"
                );
                Ok(None)
            }
            _ => {
                warn!(
                    username,
                    ?server,
                    status,
                    "NetUserGetInfo failed — disabled status unknown"
                );
                Ok(None)
            }
        };
    }

    if buf.is_null() {
        return Ok(None);
    }

    // SAFETY: buf.as_ptr() points to a USER_INFO_1 record allocated by NetApi.
    let info = unsafe { &*buf.as_ptr() };
    let disabled = (info.usri1_flags & UF_ACCOUNTDISABLE) != 0;

    Ok(Some(disabled))
    // `buf` is dropped here, calling NetApiBufferFree.
}

///
///
/// `user_global_group_names` + `resolve_local_group_sids`, returning the
/// result in the domain types `Identity` and `GroupMembership`.
///
/// On a domain controller this produces exactly the token-SID list Windows
/// itself would assemble when building an access token for the user —
/// including `BUILTIN\Administrators` when the user is (directly or via a
/// domain group) in that local group.
pub fn resolve_identity_via_sam(sid_str: &str) -> Result<SamResolution, CoreError> {
    let account = lookup_account_for_sid(sid_str)?;
    let account_kind = account.kind.clone();

    // Closes review 2026-06-04 round 2 finding 5: for user accounts we
    // try to read the `disabled` flag via `NetUserGetInfo` level 1. If
    // that fails (e.g. access denied for a non-privileged caller) we
    // explicitly flag the status as unknown rather than defaulting to
    // false.
    let (disabled, disabled_known) = if matches!(account_kind, IdentityKind::User) {
        match user_account_disabled(None, &account.name) {
            Ok(Some(flag)) => (flag, true),
            Ok(None) => (false, false),
            Err(e) => {
                warn!(
                    sid = sid_str,
                    error = %e,
                    "SAM: NetUserGetInfo failed — disabled status unknown"
                );
                (false, false)
            }
        }
    } else {
        // Groups, computers, and well-known SIDs have no `disabled`
        // flag — by definition they are active.
        (false, true)
    };

    let identity = Identity {
        sid: Sid(sid_str.to_owned()),
        name: Some(account.name.clone()),
        domain: if account.domain.is_empty() {
            None
        } else {
            Some(account.domain.clone())
        },
        kind: account.kind,
        disabled,
        user_principal_name: None,
        sid_history_count: 0,
    };

    // Global groups only meaningful for user accounts.
    let mut memberships: Vec<GroupMembership> = Vec::new();
    if matches!(account_kind, IdentityKind::User) {
        match user_global_group_names(None, &account.name) {
            Ok(names) => {
                for group_name in names {
                    match lookup_sid_for_account(None, &group_name) {
                        Ok(group_sid) => {
                            let member_sid_val = Sid(sid_str.to_owned());
                            memberships.push(GroupMembership {
                                member_sid: member_sid_val.clone(),
                                group_sid: group_sid.clone(),
                                direct: true,
                                // NetUserGetGroups returns the name directly;
                                // we pass it through verbatim.
                                group_name: Some(group_name.clone()),
                                // SAM/NetAPI returns a flat list —
                                // direkte Kante; verschachtelte Beziehungen
                                // Kante.
                                // SAM/NetAPI returns a flat list — only the
                                // user → group direct edge is visible;
                                // nested relationships are not exposed
                                // through this API. The path stays two SIDs
                                // long and is considered complete for the
                                // direct edge.
                                path: Some(MembershipPath {
                                    nodes: vec![member_sid_val, group_sid],
                                    names: vec![
                                        Some(account.name.clone()),
                                        Some(group_name.clone()),
                                    ],
                                    source: MembershipPathSource::DomainGroup,
                                    complete: true,
                                }),
                            });
                        }
                        Err(e) => warn!(
                            group_name,
                            error = %e,
                            "SAM: could not resolve domain group name to SID"
                        ),
                    }
                }
            }
            Err(e) => warn!(
                error = %e,
                "SAM: NetUserGetGroups failed; falling back to local groups only"
            ),
        }

        // konkret beschriften.
        // Reconstruct local group chains via NetLocalGroupGetMembers. The
        // already-resolved domain groups are passed as token SIDs so the
        // function can label the mediator step (e.g. "Domain Admins →
        // BUILTIN\Administrators") concretely.
        let mut known_token_sids: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        known_token_sids.insert(sid_str.to_owned(), account.name.clone());
        for m in &memberships {
            if let Some(name) = m.group_name.as_deref() {
                known_token_sids.insert(m.group_sid.0.clone(), name.to_owned());
            }
        }
        match crate::local_groups::resolve_local_group_chains(
            None,
            &Sid(sid_str.to_owned()),
            Some(&account.name),
            &known_token_sids,
            &account.name,
        ) {
            Ok(chains) => {
                for (group_sid, group_name, path) in chains {
                    memberships.push(GroupMembership {
                        member_sid: Sid(sid_str.to_owned()),
                        group_sid,
                        // direct == path.nodes.len() == 2 → echte direkte
                        // direct == path.nodes.len() == 2 → real direct
                        // membership on the local group; otherwise
                        // (mediated via domain group) transitive.
                        direct: path.nodes.len() == 2 && path.complete,
                        group_name,
                        path: Some(path),
                    });
                }
            }
            Err(e) => warn!(
                error = %e,
                "SAM: resolve_local_group_chains failed; local group SIDs missing from token"
            ),
        }
    }

    Ok(SamResolution {
        identity,
        memberships,
        disabled_known,
    })
}

///
/// Result of [`resolve_identity_via_sam`]. The `disabled_known` flag
/// lets callers distinguish a real value of `Identity.disabled` from a
/// conservative default, so they can set the
/// `IdentityDisabledStatusUnknown` diagnostic when needed.
#[derive(Debug, Clone)]
pub struct SamResolution {
    pub identity: Identity,
    pub memberships: Vec<GroupMembership>,
    pub disabled_known: bool,
}

///
///
/// Builds a SID → name lookup table for the group SIDs in `memberships`
/// plus any extra SIDs supplied (e.g. ACE trustees from the target's
/// DACL). Memberships that already carry a `group_name` (set by the
/// LDAP or SAM resolver) keep their name verbatim. All remaining SIDs
/// are resolved once via `lookup_account_for_sid` and the result is
/// stored as `DOMAIN\Name` (or just `Name` when the authority is
/// empty). SIDs that cannot be resolved are absent from the map — the
/// name in the explanation text.
pub fn build_sid_name_map<I>(
    memberships: &[GroupMembership],
    extra_sids: I,
) -> std::collections::BTreeMap<String, String>
where
    I: IntoIterator<Item = String>,
{
    let mut resolver = SidNameResolver::new(memberships);
    resolver.resolve(extra_sids);
    resolver.into_map()
}

/// Incremental SID → name resolver: the streaming counterpart to
/// [`build_sid_name_map`] (engine review 2026-06-13 finding 1).
///
/// `build_sid_name_map` resolves a whole batch of trustee SIDs at once,
/// which forces a scanner to collect every SID up front and therefore
/// buffer the whole object set. A streaming scan instead feeds each
/// object's trustee SIDs to [`SidNameResolver::resolve`] as the object is
/// processed; the resolver keeps the growing `map` and a `tried` set, so
/// each distinct SID is still resolved via LSA **exactly once** across the
/// whole scan, without an up-front collection pass. The per-object output
/// (trustee table, explanation) only references that object's own SIDs,
/// all of which are resolved before the object is rendered — so the
/// streaming result is identical to the batched one.
pub struct SidNameResolver {
    map: std::collections::BTreeMap<String, String>,
    tried: std::collections::HashSet<String>,
}

impl SidNameResolver {
    /// Seeds the resolver from group memberships: those with a pre-set
    /// `group_name` go into the map verbatim (and count as resolved), the
    /// rest are queued for LSA resolution on the first [`resolve`] call.
    ///
    /// [`resolve`]: SidNameResolver::resolve
    pub fn new(memberships: &[GroupMembership]) -> Self {
        let mut map = std::collections::BTreeMap::new();
        let mut tried = std::collections::HashSet::new();
        let mut pending: Vec<String> = Vec::new();
        for m in memberships {
            if let Some(name) = m.group_name.as_deref().filter(|s| !s.is_empty()) {
                map.insert(m.group_sid.0.clone(), name.to_owned());
                tried.insert(m.group_sid.0.clone());
            } else {
                pending.push(m.group_sid.0.clone());
            }
        }
        let mut resolver = Self { map, tried };
        resolver.resolve(pending);
        resolver
    }

    /// Resolves any of `sids` not yet seen via `lookup_account_for_sid`,
    /// caching the result. Already-tried SIDs are skipped, so this is safe
    /// to call once per scanned object with that object's trustee SIDs.
    pub fn resolve<I>(&mut self, sids: I)
    where
        I: IntoIterator<Item = String>,
    {
        for sid in sids {
            if !self.tried.insert(sid.clone()) {
                continue;
            }
            if let Ok(info) = lookup_account_for_sid(&sid) {
                let display = if info.domain.is_empty() {
                    info.name
                } else {
                    format!("{}\\{}", info.domain, info.name)
                };
                if !display.is_empty() {
                    self.map.insert(sid, display);
                }
            }
        }
    }

    /// The SID → name map resolved so far.
    pub fn map(&self) -> &std::collections::BTreeMap<String, String> {
        &self.map
    }

    /// Consumes the resolver, returning the accumulated map.
    pub fn into_map(self) -> std::collections::BTreeMap<String, String> {
        self.map
    }
}

/// Classifies the `SID_NAME_USE` field of the LSA response.
fn sid_use_to_kind(use_code: i32) -> IdentityKind {
    match use_code {
        x if x == SidTypeUser => IdentityKind::User,
        x if x == SidTypeGroup => IdentityKind::Group,
        x if x == SidTypeAlias => IdentityKind::Group,
        x if x == SidTypeWellKnownGroup => IdentityKind::WellKnown,
        x if x == SidTypeComputer => IdentityKind::Computer,
        x if x == SidTypeDeletedAccount => IdentityKind::Orphaned,
        x if x == SidTypeInvalid => IdentityKind::Unknown,
        x if x == SidTypeUnknown => IdentityKind::Unknown,
        _ => IdentityKind::Unknown,
    }
}

/// Converts a Rust string to a null-terminated UTF-16 sequence.
fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// # Safety
/// `p` must be a valid pointer to a null-terminated UTF-16 sequence, or
/// null.
unsafe fn wide_ptr_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let len = (0usize..).take_while(|&i| *p.add(i) != 0).count();
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

/// Strips trailing nulls from a fixed buffer and returns the decoded
/// string.
fn wide_buf_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Well-known: `S-1-5-32-544` (on en-US `BUILTIN\Administrators`,
    /// Well-known: `S-1-5-32-544` (on en-US `BUILTIN\Administrators`,
    /// on de-DE `VORDEFINIERT\Administratoren`). Both the name and the
    /// domain are localized on German installs — so the test asserts
    /// locale-independently: lookup succeeds, both strings are
    /// non-empty, kind is Group/WellKnown, and the `domain\name → SID`
    /// roundtrip recovers the original SID.
    #[test]
    fn lookup_well_known_builtin_administrators() {
        let info = lookup_account_for_sid("S-1-5-32-544")
            .expect("LookupAccountSidW must succeed for S-1-5-32-544");
        assert!(!info.name.is_empty(), "name must not be empty");
        assert!(!info.domain.is_empty(), "domain must not be empty");
        assert!(
            matches!(info.kind, IdentityKind::Group | IdentityKind::WellKnown),
            "S-1-5-32-544 must classify as Group or WellKnown, got: {:?}",
            info.kind
        );
        let qualified = format!("{}\\{}", info.domain, info.name);
        let sid_again = lookup_sid_for_account(None, &qualified)
            .expect("name → SID lookup must succeed for the recovered qualified name");
        assert_eq!(sid_again.0, "S-1-5-32-544");
    }

    /// Well-known: `S-1-5-18` (en-US `NT AUTHORITY\SYSTEM`, de-DE
    #[test]
    fn lookup_well_known_system() {
        let info = lookup_account_for_sid("S-1-5-18")
            .expect("LookupAccountSidW must succeed for S-1-5-18");
        assert!(!info.name.is_empty());
        assert!(!info.domain.is_empty());
        assert!(
            matches!(
                info.kind,
                IdentityKind::User | IdentityKind::Group | IdentityKind::WellKnown
            ),
            "S-1-5-18 must classify as User/Group/WellKnown, got: {:?}",
            info.kind
        );
        let qualified = format!("{}\\{}", info.domain, info.name);
        let sid_again =
            lookup_sid_for_account(None, &qualified).expect("name → SID lookup must succeed");
        assert_eq!(sid_again.0, "S-1-5-18");
    }

    /// Invalid SID syntax must yield a `SidResolution` error, not a
    /// panic.
    #[test]
    fn invalid_sid_returns_resolution_error() {
        let err = lookup_account_for_sid("not-a-sid").expect_err("non-SID input must not succeed");
        match err {
            CoreError::SidResolution(_) => {}
            other => panic!("expected SidResolution, got {other:?}"),
        }
    }

    /// Syntactically correct SID that has no account on this system.
    #[test]
    fn unmapped_but_valid_sid_returns_resolution_error() {
        // Fictional SID in a domain unknown to this system.
        let result = lookup_account_for_sid("S-1-5-21-9999999999-9999999999-9999999999-1234");
        assert!(
            matches!(result, Err(CoreError::SidResolution(_))),
            "unmapped SID should yield SidResolution error, got: {result:?}"
        );
    }

    /// DC test: does SAM resolution of the built-in `Administrator`
    /// account yield a user identity with at least one group
    /// membership? `#[ignore]` because GitHub Windows runners (no DC,
    /// built-in Administrator usually disabled) do not run this
    /// reliably.
    #[test]
    #[ignore = "DC- or workstation-specific; run locally with `cargo test -- --ignored`"]
    fn resolve_local_administrator_yields_memberships() {
        let admin_sid = lookup_sid_for_account(None, "Administrator")
            .expect("local Administrator must resolve to a SID");
        let res = resolve_identity_via_sam(&admin_sid.0)
            .expect("SAM resolution of local Administrator must succeed");
        assert!(matches!(res.identity.kind, IdentityKind::User));
        assert!(
            res.memberships
                .iter()
                .any(|m| m.group_sid.0 == "S-1-5-32-544"),
            "Administrator must be in BUILTIN\\Administrators via SAM resolution"
        );
        assert!(
            res.disabled_known,
            "On a DC, NetUserGetInfo should be answerable for the built-in Administrator"
        );
    }

    // --- SidNameResolver (engine review 2026-06-13 finding 1) ---

    fn membership(sid: &str, name: Option<&str>) -> GroupMembership {
        GroupMembership {
            member_sid: Sid("S-1-5-21-1-1-1-500".into()),
            group_sid: Sid(sid.into()),
            direct: true,
            group_name: name.map(|s| s.to_owned()),
            path: None,
        }
    }

    #[test]
    fn resolver_seeds_membership_names_verbatim() {
        let r = SidNameResolver::new(&[
            membership("S-1-5-21-9-9-9-1001", Some("CORP\\Sales")),
            membership("S-1-5-21-9-9-9-1002", None),
        ]);
        // The named membership is in the map verbatim; the unnamed one is
        // only present if LSA resolved it (a synthetic SID won't), so we
        // only assert the named one deterministically.
        assert_eq!(
            r.map().get("S-1-5-21-9-9-9-1001").map(String::as_str),
            Some("CORP\\Sales")
        );
    }

    #[test]
    fn resolver_resolves_each_sid_once() {
        let mut r = SidNameResolver::new(&[]);
        // An already-seeded SID is not retried; a synthetic SID resolves to
        // nothing (LSA miss) but is marked tried, so a second resolve is a
        // no-op and the map stays stable.
        r.resolve(["S-1-5-21-9-9-9-7777".to_owned()]);
        let after_first = r.map().len();
        r.resolve(["S-1-5-21-9-9-9-7777".to_owned()]);
        assert_eq!(
            r.map().len(),
            after_first,
            "resolving the same SID twice must not change the map"
        );
    }

    #[test]
    fn build_sid_name_map_matches_resolver() {
        // The batch helper must equal new() + resolve() + into_map().
        let memberships = [membership("S-1-5-21-9-9-9-1001", Some("CORP\\Sales"))];
        let extra = ["S-1-5-21-9-9-9-2002".to_owned()];
        let batch = build_sid_name_map(&memberships, extra.iter().cloned());
        let mut resolver = SidNameResolver::new(&memberships);
        resolver.resolve(extra.iter().cloned());
        assert_eq!(batch, resolver.into_map());
    }
}
