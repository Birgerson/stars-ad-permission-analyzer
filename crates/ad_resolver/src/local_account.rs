// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Local accounts of the analysis target server (ADR 0070).
//!
//! A local account exists only in the SAM of one machine, so its name, SID,
//! state and groups must be read **on that machine** — not on the machine
//! Stars runs on. Until ADR 0070 every lookup without LDAP ran locally: a
//! local account of a remote file server could not be analysed at all, and a
//! name that exists on both machines (`Administrator`) silently resolved to
//! the *analysing* machine's account — a different SID evaluated against
//! the server's ACLs.
//!
//! Everything read here is validated: the server's account domain SID must
//! be a machine/domain SID, the account's SID must belong to it and be a
//! user, `NetUserGetInfo` must report the same SID, every group must be a
//! group of the same domain. A domain controller has no local accounts (its
//! account domain is the domain); its accounts are left to the domain path.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use adpa_core::error::CoreError;
use adpa_core::model::{
    GroupMembership, Identity, IdentityKind, MembershipPath, MembershipPathSource, Sid,
};
use tracing::debug;
use win_safe::netapi::NetApiBuffer;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, FALSE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetServerGetInfo, NetUserGetGroups, NetUserGetInfo, NetUserModalsGet, NetWkstaGetInfo,
    GROUP_USERS_INFO_0, MAX_PREFERRED_LENGTH, SERVER_INFO_101, SV_TYPE_DOMAIN_BAKCTRL,
    SV_TYPE_DOMAIN_CTRL, UF_ACCOUNTDISABLE, USER_INFO_4, USER_MODALS_INFO_2, WKSTA_INFO_100,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::{
    LookupAccountNameW, LookupAccountSidW, SidTypeGroup, SidTypeUser,
};

/// `Local account` — Windows adds it to the token of every local account.
pub const SID_LOCAL_ACCOUNT: &str = "S-1-5-113";

/// The SAM account domain of a machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAccountDomain {
    /// NetBIOS name of the account domain (the computer name on a member).
    pub name: String,
    /// `S-1-5-21-a-b-c`.
    pub sid: Sid,
    /// A domain controller's account domain is the domain itself.
    pub is_domain_controller: bool,
}

/// Outcome of resolving an identity input on the target server.
#[derive(Debug, Clone)]
pub enum ServerAccountLookup {
    /// A local account of the server, completely resolved.
    LocalAccount(LocalAccountResolution),
    /// The server resolved the input, but it is not one of its local
    /// accounts (a domain account, a group, a well-known SID, or the server
    /// is a domain controller). The SID is the server's answer — callers
    /// use it instead of resolving the name on the analysing machine.
    NotALocalAccount { sid: Sid },
}

/// A local account of the target server with its complete group set.
#[derive(Debug, Clone)]
pub struct LocalAccountResolution {
    pub identity: Identity,
    /// SAM global groups of the server (primary group included) and the
    /// `Local account` SID. Local groups (aliases) are added later from the
    /// server's local-group table (ADR 0068).
    pub memberships: Vec<GroupMembership>,
    pub disabled_known: bool,
    /// Reader-facing reasons why the group set may be incomplete.
    pub gaps: Vec<String>,
}

/// ADR 0079: the NetBIOS computer name of `server` (`None` = this machine)
/// — `NetWkstaGetInfo` level 100 (`wki100_computername`), so a server given
/// by IP address or DNS name maps to its computer object. Not
/// `NetServerGetInfo`: called remotely it echoes the name the caller passed
/// (an IP address stays an IP address; lab 2026-10-17). Read-only; the
/// answer is validated with [`crate::selective_auth::is_valid_netbios_computer_name`].
pub fn server_netbios_name(server: Option<&str>) -> Result<String, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let mut wks: NetApiBuffer<WKSTA_INFO_100> = NetApiBuffer::null();
    // SAFETY: server_ptr is null or a valid null-terminated wide string;
    // NetApi allocates the buffer, the guard frees it on drop.
    let status = unsafe { NetWkstaGetInfo(server_ptr, 100, wks.out_ptr().cast()) };
    if status != NO_ERROR {
        return Err(net_error("NetWkstaGetInfo", server, status));
    }
    if wks.is_null() {
        return Err(CoreError::SidResolution(format!(
            "NetWkstaGetInfo on {server:?} returned no data"
        )));
    }
    // SAFETY: the buffer holds one WKSTA_INFO_100; wki100_computername is a
    // null-terminated wide string (or null).
    let name = unsafe { wide_ptr_to_string((*wks.as_ptr()).wki100_computername) };
    let name = name.trim().to_owned();
    if !crate::selective_auth::is_valid_netbios_computer_name(&name) {
        return Err(CoreError::SidResolution(format!(
            "NetWkstaGetInfo on {server:?} returned an invalid computer name {name:?}"
        )));
    }
    Ok(name)
}

/// Reads the SAM account domain of `server` (`None` = this machine):
/// `NetUserModalsGet` level 2 (name + SID) and `NetServerGetInfo` level 101
/// (domain controller or not). Both answers are validated.
pub fn read_server_account_domain(server: Option<&str>) -> Result<ServerAccountDomain, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());

    let mut modals: NetApiBuffer<USER_MODALS_INFO_2> = NetApiBuffer::null();
    // SAFETY: server_ptr is null or a valid null-terminated wide string;
    // NetApi allocates the buffer, the guard frees it on drop.
    let status = unsafe { NetUserModalsGet(server_ptr, 2, modals.out_ptr().cast()) };
    if status != NO_ERROR {
        return Err(net_error("NetUserModalsGet", server, status));
    }
    if modals.is_null() {
        return Err(CoreError::SidResolution(format!(
            "NetUserModalsGet on {server:?} returned no data"
        )));
    }
    // SAFETY: the buffer holds one USER_MODALS_INFO_2 allocated by NetApi.
    let info = unsafe { &*modals.as_ptr() };
    // SAFETY: usrmod2_domain_name is a null-terminated wide string (or null).
    let name = unsafe { wide_ptr_to_string(info.usrmod2_domain_name) };
    if info.usrmod2_domain_id.is_null() {
        return Err(CoreError::SidResolution(format!(
            "NetUserModalsGet on {server:?} returned no account domain SID"
        )));
    }
    // SAFETY: usrmod2_domain_id is a valid PSID inside the NetApi buffer.
    let sid =
        unsafe { win_safe::sid::sid_to_string_lossy(info.usrmod2_domain_id) }.map_err(|code| {
            CoreError::SidResolution(format!("account domain SID unreadable (error {code})"))
        })?;
    let sid = validate_account_domain(&name, &sid)?;

    let mut srv: NetApiBuffer<SERVER_INFO_101> = NetApiBuffer::null();
    // SAFETY: as above; SERVER_INFO_101 is the documented level-101 layout.
    let status = unsafe { NetServerGetInfo(server_ptr, 101, srv.out_ptr().cast()) };
    if status != NO_ERROR {
        return Err(net_error("NetServerGetInfo", server, status));
    }
    if srv.is_null() {
        return Err(CoreError::SidResolution(format!(
            "NetServerGetInfo on {server:?} returned no data"
        )));
    }
    // SAFETY: the buffer holds one SERVER_INFO_101 allocated by NetApi.
    let sv_type = unsafe { (*srv.as_ptr()).sv101_type };
    let is_domain_controller = sv_type & (SV_TYPE_DOMAIN_CTRL | SV_TYPE_DOMAIN_BAKCTRL) != 0;
    debug!(?server, %name, sid = %sid.0, is_domain_controller, "Server account domain read");
    Ok(ServerAccountDomain {
        name,
        sid,
        is_domain_controller,
    })
}

/// Validates a SAM account domain answer: a non-empty name and a SID of the
/// form `S-1-5-21-a-b-c` (machine and domain SIDs have exactly that shape).
fn validate_account_domain(name: &str, sid: &str) -> Result<Sid, CoreError> {
    if name.trim().is_empty() {
        return Err(CoreError::SidResolution(
            "the server's account domain has no name".to_owned(),
        ));
    }
    validation::sid::validate_sid(sid).map_err(|e| {
        CoreError::SidResolution(format!("the server's account domain SID is invalid: {e}"))
    })?;
    let parts: Vec<&str> = sid.split('-').collect();
    if parts.len() != 7 || parts[..4] != ["S", "1", "5", "21"] {
        return Err(CoreError::SidResolution(format!(
            "the server's account domain SID {sid} is not a machine/domain SID (S-1-5-21-a-b-c)"
        )));
    }
    Ok(Sid(sid.to_owned()))
}

/// The RID of `sid` when it belongs to `domain` (`domain-RID`), else `None`.
pub fn rid_in_domain(sid: &Sid, domain: &Sid) -> Option<u32> {
    let rest = sid.0.strip_prefix(domain.0.as_str())?.strip_prefix('-')?;
    if rest.contains('-') {
        return None;
    }
    rest.parse::<u32>().ok()
}

/// Resolves `input` (a name or a SID, already validated by the caller) on
/// `server` and, when it is a local user account of that server, reads its
/// complete group set there.
pub fn resolve_account_on_server(
    server: Option<&str>,
    input: &str,
) -> Result<ServerAccountLookup, CoreError> {
    let domain = read_server_account_domain(server)?;
    let trimmed = input.trim();
    let (sid, name, sid_use) = if validation::sid::looks_like_sid(trimmed) {
        let sid = Sid::try_new(trimmed)
            .map_err(|e| CoreError::SidResolution(format!("invalid SID: {e}")))?;
        let (name, _account_domain, sid_use) = lookup_sid_on(server, &sid)?;
        (sid, name, sid_use)
    } else {
        lookup_name_on(server, trimmed)?
    };
    let rid = rid_in_domain(&sid, &domain.sid);
    if domain.is_domain_controller || sid_use != SidTypeUser || rid.is_none() {
        debug!(
            ?server,
            sid = %sid.0,
            sid_use,
            dc = domain.is_domain_controller,
            "Not a local account of the target server"
        );
        return Ok(ServerAccountLookup::NotALocalAccount { sid });
    }

    let mut gaps: Vec<String> = Vec::new();
    // NetUserGetInfo level 4: state, the account's own SID (cross-checked)
    // and the primary group RID.
    let (disabled, disabled_known, primary_rid) = match user_info_4(server, &name)? {
        Some(info) => {
            if info.sid != sid {
                return Err(CoreError::SidResolution(format!(
                    "the server reports SID {} for account '{name}', the name lookup {}",
                    info.sid.0, sid.0
                )));
            }
            (info.disabled, true, Some(info.primary_group_rid))
        }
        None => {
            gaps.push(format!(
                "the account '{name}' could not be read on the target server (state and \
                 primary group unknown)"
            ));
            (false, false, None)
        }
    };

    let identity = Identity {
        sid: sid.clone(),
        name: Some(name.clone()),
        domain: Some(domain.name.clone()),
        kind: IdentityKind::User,
        disabled,
        user_principal_name: None,
        // A SAM account of a machine carries no sIDHistory — 0 is exact.
        sid_history_count: 0,
        sid_history: Vec::new(),
    };

    // SAM global groups of the machine (on a member server: "None", the
    // primary group of every local account). They cannot nest.
    let mut memberships: Vec<GroupMembership> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = Default::default();
    match user_global_groups(server, &name) {
        Ok(groups) => {
            for group_name in groups {
                let qualified = format!("{}\\{group_name}", domain.name);
                match lookup_name_on(server, &qualified) {
                    Ok((gsid, _, gu))
                        if gu == SidTypeGroup && rid_in_domain(&gsid, &domain.sid).is_some() =>
                    {
                        let is_primary = primary_rid.is_some()
                            && rid_in_domain(&gsid, &domain.sid) == primary_rid;
                        if seen.insert(gsid.0.clone()) {
                            memberships.push(membership(
                                &identity,
                                &gsid,
                                &qualified,
                                if is_primary {
                                    MembershipPathSource::PrimaryGroup
                                } else {
                                    MembershipPathSource::DomainGroup
                                },
                            ));
                        }
                    }
                    Ok((gsid, _, gu)) => gaps.push(format!(
                        "the group '{qualified}' of the account resolves to {} (SID type {gu}), \
                         not to a group of the server",
                        gsid.0
                    )),
                    Err(e) => gaps.push(format!(
                        "the group '{qualified}' of the account could not be resolved ({e})"
                    )),
                }
            }
        }
        Err(e) => gaps.push(format!(
            "the groups of the account could not be read on the target server ({e})"
        )),
    }
    // The primary group is in every token; NetUserGetGroups lists it on a
    // member server — if it did not, add it from the RID (validated).
    if let Some(rid) = primary_rid {
        let psid = Sid(format!("{}-{rid}", domain.sid.0));
        if !seen.contains(&psid.0) {
            match lookup_sid_on(server, &psid) {
                Ok((gname, gdomain, gu)) if gu == SidTypeGroup => {
                    seen.insert(psid.0.clone());
                    memberships.push(membership(
                        &identity,
                        &psid,
                        &format!("{gdomain}\\{gname}"),
                        MembershipPathSource::PrimaryGroup,
                    ));
                }
                Ok((_, _, gu)) => gaps.push(format!(
                    "the primary group RID {rid} of the account is not a group (SID type {gu})"
                )),
                Err(e) => gaps.push(format!(
                    "the primary group RID {rid} of the account could not be resolved ({e})"
                )),
            }
        }
    }
    // Windows adds `Local account` to every local account's token
    // (lab-confirmed for interactive, network and batch logons, ADR 0070).
    memberships.push(membership(
        &identity,
        &Sid(SID_LOCAL_ACCOUNT.to_owned()),
        "NT AUTHORITY\\Local account",
        MembershipPathSource::AccountType,
    ));

    Ok(ServerAccountLookup::LocalAccount(LocalAccountResolution {
        identity,
        memberships,
        disabled_known,
        gaps,
    }))
}

/// Turns a resolved local account into the principal resolution the
/// engine consumes: status `LocalAccount` (complete group set), the account
/// state as read on the server, gaps as `GroupResolutionIncomplete`.
pub fn local_account_principal(r: LocalAccountResolution) -> crate::principal::PrincipalResolution {
    use crate::principal::{DisabledStatus, GroupResolutionStatus, IdentityScopeStatus};
    use adpa_core::model::PermissionDiagnostic;
    let disabled_status = if r.disabled_known {
        DisabledStatus::Known(r.identity.disabled)
    } else {
        DisabledStatus::Unknown
    };
    let mut diagnostics = Vec::new();
    match disabled_status {
        DisabledStatus::Unknown => {
            diagnostics.push(PermissionDiagnostic::IdentityDisabledStatusUnknown)
        }
        DisabledStatus::Known(true) => diagnostics.push(PermissionDiagnostic::IdentityDisabled),
        DisabledStatus::Known(false) => {}
    }
    crate::principal::PrincipalResolution {
        sid: r.identity.sid.clone(),
        identity: r.identity,
        memberships: r.memberships,
        scope_status: IdentityScopeStatus::InsideConfiguredLdapBase,
        group_resolution_status: GroupResolutionStatus::LocalAccount,
        disabled_status,
        diagnostics,
        resolved_via_fsp: false,
        resolved_via_global_catalog: false,
        group_resolution_gaps: r.gaps,
        excluded_groups: Vec::new(),
        trusted_domain: Default::default(),
    }
}

fn membership(
    identity: &Identity,
    group: &Sid,
    group_name: &str,
    source: MembershipPathSource,
) -> GroupMembership {
    GroupMembership {
        member_sid: identity.sid.clone(),
        group_sid: group.clone(),
        direct: true,
        group_name: Some(group_name.to_owned()),
        path: Some(MembershipPath {
            nodes: vec![identity.sid.clone(), group.clone()],
            names: vec![identity.name.clone(), Some(group_name.to_owned())],
            source,
            complete: true,
            also_via: Vec::new(),
        }),
        group_sid_history_count: 0,
        group_sid_history: Vec::new(),
    }
}

struct UserInfo4 {
    sid: Sid,
    disabled: bool,
    primary_group_rid: u32,
}

/// `NetUserGetInfo` level 4 on `server`. `Ok(None)` when the account cannot
/// be read (access denied, not found); other failures are errors.
fn user_info_4(server: Option<&str>, name: &str) -> Result<Option<UserInfo4>, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let name_w = to_wide_null(name);
    let mut buf: NetApiBuffer<USER_INFO_4> = NetApiBuffer::null();
    // SAFETY: pointers are null or valid null-terminated wide strings; the
    // guard frees the NetApi buffer on drop.
    let status = unsafe { NetUserGetInfo(server_ptr, name_w.as_ptr(), 4, buf.out_ptr().cast()) };
    match status {
        NO_ERROR => {}
        ERROR_ACCESS_DENIED | NERR_USER_NOT_FOUND => {
            debug!(?server, name, status, "NetUserGetInfo level 4 unavailable");
            return Ok(None);
        }
        _ => return Err(net_error("NetUserGetInfo", server, status)),
    }
    if buf.is_null() {
        return Ok(None);
    }
    // SAFETY: the buffer holds one USER_INFO_4 allocated by NetApi.
    let info = unsafe { &*buf.as_ptr() };
    if info.usri4_user_sid.is_null() {
        return Err(CoreError::SidResolution(format!(
            "NetUserGetInfo returned no SID for '{name}'"
        )));
    }
    // SAFETY: usri4_user_sid is a valid PSID inside the NetApi buffer.
    let sid = unsafe { win_safe::sid::sid_to_string_lossy(info.usri4_user_sid) }
        .map_err(|code| CoreError::SidResolution(format!("account SID unreadable ({code})")))?;
    validation::sid::validate_sid(&sid)
        .map_err(|e| CoreError::SidResolution(format!("account SID invalid: {e}")))?;
    Ok(Some(UserInfo4 {
        sid: Sid(sid),
        disabled: info.usri4_flags & UF_ACCOUNTDISABLE != 0,
        primary_group_rid: info.usri4_primary_group_id,
    }))
}

/// `NetUserGetGroups` level 0 on `server`: the SAM global groups of `name`.
fn user_global_groups(server: Option<&str>, name: &str) -> Result<Vec<String>, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let name_w = to_wide_null(name);
    let mut buf: NetApiBuffer<GROUP_USERS_INFO_0> = NetApiBuffer::null();
    let mut read: u32 = 0;
    let mut total: u32 = 0;
    // SAFETY: as above.
    let status = unsafe {
        NetUserGetGroups(
            server_ptr,
            name_w.as_ptr(),
            0,
            buf.out_ptr().cast(),
            MAX_PREFERRED_LENGTH,
            &mut read,
            &mut total,
        )
    };
    if status != NO_ERROR {
        return Err(net_error("NetUserGetGroups", server, status));
    }
    if read != total {
        return Err(CoreError::SidResolution(format!(
            "NetUserGetGroups returned {read} of {total} groups for '{name}'"
        )));
    }
    let mut groups = Vec::with_capacity(read as usize);
    if !buf.is_null() && read > 0 {
        // SAFETY: NetApi returns exactly `read` consecutive structs.
        let entries = unsafe { std::slice::from_raw_parts(buf.as_ptr(), read as usize) };
        for e in entries {
            // SAFETY: grui0_name is a null-terminated wide string in the buffer.
            let g = unsafe { wide_ptr_to_string(e.grui0_name) };
            if g.is_empty() {
                return Err(CoreError::SidResolution(format!(
                    "NetUserGetGroups returned a group without a name for '{name}'"
                )));
            }
            groups.push(g);
        }
    }
    groups.sort_by_key(|g| g.to_lowercase());
    Ok(groups)
}

/// `LookupAccountNameW` on `server`: SID (validated), SID use, and the
/// account name without its domain.
fn lookup_name_on(server: Option<&str>, name: &str) -> Result<(Sid, String, i32), CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let name_w = to_wide_null(name);
    let mut sid_size: u32 = 0;
    let mut domain_size: u32 = 0;
    let mut sid_use: i32 = 0;
    // SAFETY: sizing call — output pointers may be null.
    unsafe {
        LookupAccountNameW(
            server_ptr,
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
            "'{name}' is not known on {}",
            server.unwrap_or("this machine")
        )));
    }
    let mut sid_buf = vec![0u8; sid_size as usize];
    let mut domain_buf = vec![0u16; domain_size as usize];
    // SAFETY: buffers sized by the sizing call.
    let ok = unsafe {
        LookupAccountNameW(
            server_ptr,
            name_w.as_ptr(),
            sid_buf.as_mut_ptr().cast(),
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
    // SAFETY: sid_buf holds a valid SID written by LookupAccountNameW.
    let sid = unsafe { win_safe::sid::sid_to_string_lossy(sid_buf.as_ptr().cast()) }
        .map_err(|code| CoreError::SidResolution(format!("SID of '{name}' unreadable ({code})")))?;
    validation::sid::validate_sid(&sid)
        .map_err(|e| CoreError::SidResolution(format!("SID of '{name}' invalid: {e}")))?;
    let bare = name.rsplit_once('\\').map_or(name, |(_, n)| n).to_owned();
    Ok((Sid(sid), bare, sid_use))
}

/// `LookupAccountSidW` on `server`: name, domain, SID use.
pub(crate) fn lookup_sid_on(
    server: Option<&str>,
    sid: &Sid,
) -> Result<(String, String, i32), CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let sid_w = to_wide_null(&sid.0);
    let mut psid: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY: sid_w is null-terminated; Windows allocates psid via LocalAlloc.
    let ok = unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut psid) };
    if ok == FALSE || psid.is_null() {
        return Err(CoreError::SidResolution(format!("invalid SID '{}'", sid.0)));
    }
    // SAFETY: psid was allocated by ConvertStringSidToSidW; the guard frees it.
    let _guard = unsafe { win_safe::localalloc::LocalFreeGuard::new(psid) };
    let mut name_size: u32 = 0;
    let mut domain_size: u32 = 0;
    let mut sid_use: i32 = 0;
    // SAFETY: sizing call.
    unsafe {
        LookupAccountSidW(
            server_ptr,
            psid,
            std::ptr::null_mut(),
            &mut name_size,
            std::ptr::null_mut(),
            &mut domain_size,
            &mut sid_use,
        );
    }
    if name_size == 0 {
        return Err(CoreError::SidResolution(format!(
            "{} is not known on {}",
            sid.0,
            server.unwrap_or("this machine")
        )));
    }
    let mut name_buf = vec![0u16; name_size as usize];
    let mut domain_buf = vec![0u16; domain_size as usize];
    // SAFETY: buffers sized by the sizing call.
    let ok = unsafe {
        LookupAccountSidW(
            server_ptr,
            psid,
            name_buf.as_mut_ptr(),
            &mut name_size,
            domain_buf.as_mut_ptr(),
            &mut domain_size,
            &mut sid_use,
        )
    };
    if ok == FALSE {
        return Err(CoreError::SidResolution(format!(
            "LookupAccountSidW failed for {}",
            sid.0
        )));
    }
    let name = wide_buf_to_string(&name_buf);
    if name.is_empty() {
        return Err(CoreError::SidResolution(format!(
            "{} has an empty name",
            sid.0
        )));
    }
    Ok((name, wide_buf_to_string(&domain_buf), sid_use))
}

/// NERR_UserNotFound (lmerr.h).
const NERR_USER_NOT_FOUND: u32 = 2221;

fn net_error(api: &str, server: Option<&str>, status: u32) -> CoreError {
    match status {
        ERROR_ACCESS_DENIED => {
            CoreError::AccessDenied(format!("{api}: access denied on {server:?}"))
        }
        _ => CoreError::SidResolution(format!("{api} on {server:?} failed with status {status}")),
    }
}

fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// # Safety
/// `p` must be null or a valid null-terminated UTF-16 string.
unsafe fn wide_ptr_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let len = (0usize..).take_while(|&i| *p.add(i) != 0).count();
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

fn wide_buf_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rid_in_domain_requires_exactly_one_more_subauthority() {
        let d = Sid("S-1-5-21-10-20-30".into());
        assert_eq!(
            rid_in_domain(&Sid("S-1-5-21-10-20-30-1000".into()), &d),
            Some(1000)
        );
        assert_eq!(rid_in_domain(&Sid("S-1-5-21-10-20-30".into()), &d), None);
        assert_eq!(
            rid_in_domain(&Sid("S-1-5-21-10-20-300-1000".into()), &d),
            None
        );
        assert_eq!(
            rid_in_domain(&Sid("S-1-5-21-10-20-30-1-2".into()), &d),
            None
        );
        assert_eq!(rid_in_domain(&Sid("S-1-5-32-544".into()), &d), None);
    }

    #[test]
    fn account_domain_answer_is_validated() {
        assert!(validate_account_domain("MS-01", "S-1-5-21-1-2-3").is_ok());
        assert!(validate_account_domain("", "S-1-5-21-1-2-3").is_err());
        assert!(validate_account_domain("X", "S-1-5-32").is_err());
        assert!(validate_account_domain("X", "S-1-5-21-1-2").is_err());
        assert!(validate_account_domain("X", "S-1-5-21-1-2-3-4").is_err());
        assert!(validate_account_domain("X", "not a sid").is_err());
    }

    /// Live, this machine: its built-in Administrator (RID 500 of the
    /// machine domain) always exists — enabled or not. On a domain
    /// controller there are no local accounts.
    #[test]
    fn builtin_administrator_of_this_machine_resolves_as_local_account() {
        let domain = read_server_account_domain(None).expect("account domain");
        let admin = format!("{}-500", domain.sid.0);
        match resolve_account_on_server(None, &admin).expect("lookup") {
            ServerAccountLookup::LocalAccount(r) => {
                assert!(!domain.is_domain_controller);
                assert_eq!(r.identity.sid.0, admin);
                assert!(r
                    .memberships
                    .iter()
                    .any(|m| m.group_sid.0 == SID_LOCAL_ACCOUNT));
                if r.disabled_known {
                    assert!(
                        r.memberships.iter().any(|m| m
                            .path
                            .as_ref()
                            .is_some_and(|p| p.source == MembershipPathSource::PrimaryGroup)),
                        "primary group present: {:?}",
                        r.memberships
                    );
                }
            }
            ServerAccountLookup::NotALocalAccount { .. } => {
                assert!(domain.is_domain_controller, "a non-DC has local accounts")
            }
        }
    }

    fn resolution(disabled: bool, known: bool) -> LocalAccountResolution {
        let identity = Identity {
            sid: Sid("S-1-5-21-1-2-3-1000".into()),
            name: Some("msuser1".into()),
            domain: Some("MS-01".into()),
            kind: IdentityKind::User,
            disabled,
            user_principal_name: None,
            sid_history_count: 0,
            sid_history: Vec::new(),
        };
        LocalAccountResolution {
            memberships: vec![membership(
                &identity,
                &Sid(SID_LOCAL_ACCOUNT.into()),
                "NT AUTHORITY\\Local account",
                MembershipPathSource::AccountType,
            )],
            identity,
            disabled_known: known,
            gaps: vec!["g".into()],
        }
    }

    /// A local account's group set is complete — it must not be flagged as
    /// the incomplete SAM fallback; its state and gaps travel along.
    #[test]
    fn local_account_principal_is_complete_and_carries_state_and_gaps() {
        use crate::principal::GroupResolutionStatus;
        use adpa_core::model::PermissionDiagnostic;
        let p = local_account_principal(resolution(true, true));
        assert!(matches!(
            p.group_resolution_status,
            GroupResolutionStatus::LocalAccount
        ));
        let flags = p.engine_flags();
        assert!(!flags.group_resolution_via_sam_fallback);
        assert_eq!(flags.group_resolution_gaps, vec!["g".to_string()]);
        assert!(p
            .diagnostics
            .contains(&PermissionDiagnostic::IdentityDisabled));
        let unknown = local_account_principal(resolution(false, false));
        assert!(unknown
            .diagnostics
            .contains(&PermissionDiagnostic::IdentityDisabledStatusUnknown));
    }

    #[test]
    fn a_builtin_group_is_not_a_local_account() {
        match resolve_account_on_server(None, "S-1-5-32-544").expect("lookup") {
            ServerAccountLookup::NotALocalAccount { sid } => assert_eq!(sid.0, "S-1-5-32-544"),
            ServerAccountLookup::LocalAccount(_) => panic!("a group is not an account"),
        }
    }
}
