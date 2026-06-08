// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Local group memberships of a user on a target server.
//! Local group memberships for a user on a target server.
//!
//!
//! On a Windows access token, alongside the AD group SIDs, are the SIDs of the
//! target server's local groups in which the user is a direct or transitive
//! member (e.g. `BUILTIN\Administrators`, which often contains a domain group).
//! Without these SIDs, NTFS/share ACEs that grant access via local groups are
//! missed and effective rights are computed too low.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use adpa_core::{
    error::CoreError,
    model::{GroupMembership, Identity, MembershipPath, MembershipPathSource, Sid},
};
use tracing::{debug, warn};
use win_safe::netapi::NetApiBuffer;
use windows_sys::Win32::Foundation::{LocalFree, ERROR_ACCESS_DENIED, FALSE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetLocalGroupGetMembers, NetUserGetLocalGroups, LG_INCLUDE_INDIRECT, LOCALGROUP_MEMBERS_INFO_2,
    LOCALGROUP_USERS_INFO_0, MAX_PREFERRED_LENGTH,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::LookupAccountNameW;

/// User-Not-Found-Statuscode aus lmerr.h / NERR_UserNotFound from lmerr.h.
const NERR_USER_NOT_FOUND: u32 = 2221;

/// Bestandteile (mindestens ein `.`)? In Trust-/Multi-Domain-Szenarien
/// als UPN-Suffix valide.
/// Heuristic: does the domain string look like a DNS suffix (contains a
/// dot)? In trust / multi-domain scenarios LSA usually returns the NetBIOS
/// name (`TRUSTED`); `name@TRUSTED` is NOT a valid account reference for
/// `NetUserGetLocalGroups` — only DNS-style suffixes (`corp.local`) work
/// as UPN suffixes.
fn looks_like_dns_domain(domain: &str) -> bool {
    domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

///
/// blind `name@domain`, was bei NetBIOS-Domains (`alice@TRUSTED` statt
///
/// Order:
///    konstruiert.
/// 4. `name` (rein) — lokale Konten ohne Domain.
///
/// Returns a **candidate list** of account names for
/// `NetUserGetLocalGroups`, in preference order. The caller iterates
/// until one form is recognized by the target server.
///
/// Closes review 2026-06-04 round 5 finding 1.
pub fn format_account_candidates_for_local_groups(identity: &Identity) -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();
    if let Some(upn) = identity
        .user_principal_name
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        candidates.push(upn.to_string());
    }
    let name = match identity.name.as_deref().filter(|s| !s.is_empty()) {
        Some(n) => n,
        None => return candidates,
    };
    if let Some(domain) = identity.domain.as_deref().filter(|s| !s.is_empty()) {
        let domain_backslash_name = format!("{domain}\\{name}");
        if !candidates.contains(&domain_backslash_name) {
            candidates.push(domain_backslash_name);
        }
        // Only as UPN construction when the domain looks DNS-style.
        if looks_like_dns_domain(domain) {
            let upn_form = format!("{name}@{domain}");
            if !candidates.contains(&upn_form) {
                candidates.push(upn_form);
            }
        }
    }
    if !candidates.contains(&name.to_string()) {
        candidates.push(name.to_string());
    }
    candidates
}

pub fn format_account_for_local_groups(identity: &Identity) -> Option<String> {
    format_account_candidates_for_local_groups(identity)
        .into_iter()
        .next()
}

/// (review round 5 finding 1).
/// `NetUserGetLocalGroups` outcome — separates **"user not found"**
/// from **"user found but has no group memberships"**.
#[derive(Debug, Clone)]
pub enum LocalGroupLookupOutcome {
    /// Account was found; the returned vector is the actual group set.
    WithGroups(Vec<Sid>),
    /// Account was not known on the target server.
    UserNotFoundOnServer,
}

///
///
/// Returns the SIDs of all local groups on `server` in which `account` is a
/// direct or transitive member (`LG_INCLUDE_INDIRECT`).
///
/// `account`: typically `DOMAIN\username` or `username@domain`.
pub fn resolve_local_group_sids(
    server: Option<&str>,
    account: &str,
) -> Result<Vec<Sid>, CoreError> {
    match resolve_local_group_sids_strict(server, account)? {
        LocalGroupLookupOutcome::WithGroups(v) => Ok(v),
        LocalGroupLookupOutcome::UserNotFoundOnServer => Ok(Vec::new()),
    }
}

/// Unterscheidung, um Kandidatenlisten durchzuprobieren ohne stille
/// Skips.
/// Strict variant — distinguishes "not found" from "found, no groups".
pub fn resolve_local_group_sids_strict(
    server: Option<&str>,
    account: &str,
) -> Result<LocalGroupLookupOutcome, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let account_w = to_wide_null(account);

    // RAII guard: frees the LOCALGROUP_USERS_INFO_0 buffer in every path.
    let mut buf: NetApiBuffer<LOCALGROUP_USERS_INFO_0> = NetApiBuffer::null();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;

    // SAFETY: server_ptr is either null or points to a valid null-terminated wide
    // string; account_w is a valid null-terminated wide string. NetApiBuffer
    // owns the allocated buffer after this call.
    let status = unsafe {
        NetUserGetLocalGroups(
            server_ptr,
            account_w.as_ptr(),
            0, // level 0 = LOCALGROUP_USERS_INFO_0
            LG_INCLUDE_INDIRECT,
            buf.out_ptr().cast(),
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
        )
    };

    if status != NO_ERROR {
        return match status {
            ERROR_ACCESS_DENIED => Err(CoreError::AccessDenied(format!(
                "NetUserGetLocalGroups: access denied for '{account}' on {server:?}"
            ))),
            NERR_USER_NOT_FOUND => {
                debug!(
                    account,
                    ?server,
                    "NetUserGetLocalGroups: user not found on server"
                );
                Ok(LocalGroupLookupOutcome::UserNotFoundOnServer)
            }
            _ => Err(CoreError::LdapQuery(format!(
                "NetUserGetLocalGroups('{account}') failed with status {status}"
            ))),
        };
    }

    let mut sids = Vec::with_capacity(entries_read as usize);
    if !buf.is_null() && entries_read > 0 {
        // SAFETY: buf.as_ptr() points to `entries_read` consecutive
        // LOCALGROUP_USERS_INFO_0 entries allocated by NetApi.
        let entries = unsafe { std::slice::from_raw_parts(buf.as_ptr(), entries_read as usize) };
        for entry in entries {
            // SAFETY: lgrui0_name is a valid null-terminated wide string inside the buffer.
            let name = unsafe { wide_ptr_to_string(entry.lgrui0_name) };
            if name.is_empty() {
                continue;
            }
            match lookup_account_sid(server, &name) {
                Some(sid_str) => {
                    debug!(local_group = %name, sid = %sid_str, "Local group resolved");
                    sids.push(Sid(sid_str));
                }
                None => warn!(local_group = %name, "Could not resolve local group SID"),
            }
        }
    }

    Ok(LocalGroupLookupOutcome::WithGroups(sids))
    // `buf` is dropped here, calling NetApiBufferFree.
}

/// ([`format_account_candidates_for_local_groups`]) durch.
///
/// - `Err(...)` bei anderen technischen Fehlern (Access Denied, NetAPI-
///
///
/// Tries to resolve local groups for `identity` on `server`, iterating
/// over candidate account name forms.
pub fn resolve_local_group_sids_for_identity(
    server: Option<&str>,
    identity: &Identity,
) -> Result<Vec<Sid>, CoreError> {
    let candidates = format_account_candidates_for_local_groups(identity);
    if candidates.is_empty() {
        return Err(CoreError::Validation(format!(
            "Local groups: no usable account name form derivable from identity {}",
            identity.sid.0
        )));
    }
    let mut tried: Vec<String> = Vec::with_capacity(candidates.len());
    for candidate in &candidates {
        tried.push(candidate.clone());
        match resolve_local_group_sids_strict(server, candidate)? {
            LocalGroupLookupOutcome::WithGroups(sids) => {
                debug!(
                    ?server,
                    account = %candidate,
                    count = sids.len(),
                    "Local groups resolved via candidate"
                );
                return Ok(sids);
            }
            LocalGroupLookupOutcome::UserNotFoundOnServer => {
                debug!(
                    ?server,
                    account = %candidate,
                    "Candidate not known on server, trying next"
                );
            }
        }
    }
    Err(CoreError::Validation(format!(
        "NetUserGetLocalGroups: account for identity {} not known on {server:?} \
         (tried forms: {:?}). Local server group memberships are not available; \
         the result is marked incomplete.",
        identity.sid.0, tried
    )))
}

/// Entry in the `NetUserGetLocalGroups` response with both name and SID. The
/// plain `resolve_local_group_sids` variant discards the name; for chain
/// reconstruction we need both because `NetLocalGroupGetMembers` requires
/// the name.
#[derive(Debug, Clone)]
pub struct LocalGroupInfo {
    pub name: String,
    pub sid: Sid,
}

/// `NetLocalGroupGetMembers` Level 2.
/// A member of a local group from `NetLocalGroupGetMembers` level 2.
#[derive(Debug, Clone)]
pub struct LocalGroupMember {
    /// Member SID (None only when conversion failed — should be vanishingly
    /// rare).
    pub sid: Option<Sid>,
    /// `DOMAIN\Name`-Darstellung wie von Windows geliefert; bei lokalen
    /// `DOMAIN\name` form as returned by Windows; for local accounts without
    /// a domain it may just be `Name`.
    pub display_name: Option<String>,
}

/// name. Required for chain reconstruction.
pub fn resolve_local_groups(
    server: Option<&str>,
    account: &str,
) -> Result<Vec<LocalGroupInfo>, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let account_w = to_wide_null(account);

    // RAII-Guard analog zu resolve_local_group_sids.
    // RAII guard analogous to resolve_local_group_sids.
    let mut buf: NetApiBuffer<LOCALGROUP_USERS_INFO_0> = NetApiBuffer::null();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;

    // SAFETY: same as resolve_local_group_sids — pointers are valid or null,
    // NetApi populates the buffer and the guard frees it on drop.
    let status = unsafe {
        NetUserGetLocalGroups(
            server_ptr,
            account_w.as_ptr(),
            0,
            LG_INCLUDE_INDIRECT,
            buf.out_ptr().cast(),
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
        )
    };

    if status != NO_ERROR {
        return match status {
            ERROR_ACCESS_DENIED => Err(CoreError::AccessDenied(format!(
                "NetUserGetLocalGroups: access denied for '{account}' on {server:?}"
            ))),
            NERR_USER_NOT_FOUND => {
                debug!(account, ?server, "user not found");
                Ok(Vec::new())
            }
            _ => Err(CoreError::LdapQuery(format!(
                "NetUserGetLocalGroups('{account}') failed with status {status}"
            ))),
        };
    }

    let mut result = Vec::with_capacity(entries_read as usize);
    if !buf.is_null() && entries_read > 0 {
        // SAFETY: see above
        let entries = unsafe { std::slice::from_raw_parts(buf.as_ptr(), entries_read as usize) };
        for entry in entries {
            // SAFETY: lgrui0_name is a valid null-terminated wide string inside the buffer.
            let name = unsafe { wide_ptr_to_string(entry.lgrui0_name) };
            if name.is_empty() {
                continue;
            }
            if let Some(sid_str) = lookup_account_sid(server, &name) {
                result.push(LocalGroupInfo {
                    name,
                    sid: Sid(sid_str),
                });
            }
        }
    }

    Ok(result)
    // `buf` is dropped here, calling NetApiBufferFree.
}

/// Lists the direct members of a local group via `NetLocalGroupGetMembers`
/// level 2. Returns SID + display name per member.
pub fn get_local_group_members(
    server: Option<&str>,
    group_name: &str,
) -> Result<Vec<LocalGroupMember>, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let group_w = to_wide_null(group_name);

    // RAII guard for the NetLocalGroupGetMembers buffer.
    let mut buf: NetApiBuffer<LOCALGROUP_MEMBERS_INFO_2> = NetApiBuffer::null();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;
    let mut resume: usize = 0;

    // SAFETY: server_ptr is null or a valid PCWSTR; group_w is a valid
    // null-terminated UTF-16 sequence; NetApi populates the buffer and the
    // guard frees it on drop.
    let status = unsafe {
        NetLocalGroupGetMembers(
            server_ptr,
            group_w.as_ptr(),
            2,
            buf.out_ptr().cast(),
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
            &mut resume,
        )
    };

    if status != NO_ERROR {
        return match status {
            ERROR_ACCESS_DENIED => Err(CoreError::AccessDenied(format!(
                "NetLocalGroupGetMembers: access denied for '{group_name}' on {server:?}"
            ))),
            _ => Err(CoreError::LdapQuery(format!(
                "NetLocalGroupGetMembers('{group_name}') failed with status {status}"
            ))),
        };
    }

    let mut members = Vec::with_capacity(entries_read as usize);
    if !buf.is_null() && entries_read > 0 {
        // SAFETY: NetApi returns exactly entries_read consecutive structs.
        // SAFETY: NetApi returns exactly entries_read consecutive structs.
        let entries = unsafe { std::slice::from_raw_parts(buf.as_ptr(), entries_read as usize) };
        for e in entries {
            // SID via ConvertSidToStringSidW.
            let sid = if e.lgrmi2_sid.is_null() {
                None
            } else {
                let mut sid_str_ptr: *mut u16 = std::ptr::null_mut();
                // SAFETY: lgrmi2_sid is a valid PSID from the NetApi buffer.
                let ok = unsafe { ConvertSidToStringSidW(e.lgrmi2_sid, &mut sid_str_ptr) };
                if ok == FALSE || sid_str_ptr.is_null() {
                    None
                } else {
                    // SAFETY: sid_str_ptr is a null-terminated UTF-16 sequence allocated
                    // via LocalAlloc; freed below with LocalFree.
                    let s = unsafe { wide_ptr_to_string(sid_str_ptr) };
                    unsafe { LocalFree(sid_str_ptr.cast()) };
                    if s.is_empty() {
                        None
                    } else {
                        Some(Sid(s))
                    }
                }
            };
            // SAFETY: lgrmi2_domainandname is a null-terminated UTF-16
            // sequence inside the NetApi buffer (or null).
            let name = unsafe { wide_ptr_to_string(e.lgrmi2_domainandname) };
            let display_name = if name.is_empty() { None } else { Some(name) };
            members.push(LocalGroupMember { sid, display_name });
        }
    }

    Ok(members)
    // `buf` is dropped here, calling NetApiBufferFree.
}

///
/// 1. Mitglieder von `L` via [`get_local_group_members`] holen.
///    `complete = true`, Quelle `LocalGroup`.
///    `[user → vermittler → L]`, `complete = true`.
/// 4. Otherwise chain `[user, L]`, `complete = false` with source `LocalGroup`
///
///
/// Reconstructs concrete membership chains for every local group in which
/// `user_sid` is a direct or transitive member.
///
/// Per local group `L`:
/// 1. Fetch members of `L` via [`get_local_group_members`].
/// 2. If the user's own `user_sid` is listed → chain `[user → L]`,
///    `complete = true`, source `LocalGroup`.
/// 3. If a known token SID (own SID or a domain group supplied by the
///    caller) is listed → chain `[user → mediator → L]`,
///    `complete = true`.
/// 4. Otherwise chain `[user, L]`, `complete = false` with source
///    `LocalGroup` (nested via another local group — a later iteration
///    can resolve those).
///
/// `known_member_sids_to_names` carries the domain groups the caller has
/// already resolved via `NetUserGetGroups`, as `SID string → display name`.
/// Used to label the mediator step in case 3 with a human-readable name.
pub fn resolve_local_group_chains(
    server: Option<&str>,
    user_sid: &Sid,
    user_name: Option<&str>,
    known_member_sids_to_names: &std::collections::HashMap<String, String>,
    account: &str,
) -> Result<Vec<(Sid, Option<String>, MembershipPath)>, CoreError> {
    let local_groups = resolve_local_groups(server, account)?;
    let mut out: Vec<(Sid, Option<String>, MembershipPath)> = Vec::new();
    for lg in local_groups {
        let lg_display =
            lookup_account_for_sid_display(&lg.sid.0).unwrap_or_else(|| lg.name.clone());
        let members = match get_local_group_members(server, &lg.name) {
            Ok(m) => m,
            Err(e) => {
                // sichtbare Annotation statt stillem Wegwerfen.
                // If we cannot read the members, the membership stays
                // confirmed (NetUserGetLocalGroups gave it to us) but
                // without a concrete path — a visible annotation rather
                // than a silent drop.
                debug!(local_group = %lg.name, error = %e, "members unreadable");
                out.push((
                    lg.sid.clone(),
                    Some(lg_display.clone()),
                    MembershipPath {
                        nodes: vec![user_sid.clone(), lg.sid.clone()],
                        names: vec![user_name.map(str::to_owned), Some(lg_display.clone())],
                        source: MembershipPathSource::LocalGroup,
                        complete: false,
                    },
                ));
                continue;
            }
        };

        //   1. user_sid direct → chain with 2 nodes
        //      chain with 3 nodes (user → mediator → L)
        // Candidate member SIDs in order of preference:
        //   1. user_sid directly → 2-node chain
        //   2. a known token SID (own or a domain group) → 3-node chain
        //      (user → mediator → L)
        let mut chain_via_self = false;
        let mut mediator: Option<(Sid, Option<String>)> = None;
        for m in &members {
            let Some(ref msid) = m.sid else { continue };
            if msid.0 == user_sid.0 {
                chain_via_self = true;
                break;
            }
            if mediator.is_none() {
                if let Some(name) = known_member_sids_to_names.get(&msid.0) {
                    mediator = Some((msid.clone(), Some(name.clone())));
                }
            }
        }

        let path = if chain_via_self {
            MembershipPath {
                nodes: vec![user_sid.clone(), lg.sid.clone()],
                names: vec![user_name.map(str::to_owned), Some(lg_display.clone())],
                source: MembershipPathSource::LocalGroup,
                complete: true,
            }
        } else if let Some((med_sid, med_name)) = mediator {
            MembershipPath {
                nodes: vec![user_sid.clone(), med_sid.clone(), lg.sid.clone()],
                names: vec![
                    user_name.map(str::to_owned),
                    med_name,
                    Some(lg_display.clone()),
                ],
                source: MembershipPathSource::LocalGroup,
                complete: true,
            }
        } else {
            // ehrlich als incomplete kennzeichnen.
            // Likely nested via another local group — honestly flag as
            // incomplete.
            MembershipPath {
                nodes: vec![user_sid.clone(), lg.sid.clone()],
                names: vec![user_name.map(str::to_owned), Some(lg_display.clone())],
                source: MembershipPathSource::LocalGroup,
                complete: false,
            }
        };

        out.push((lg.sid, Some(lg_display), path));
    }
    Ok(out)
}

/// Kandidaten-Loop analog zu [`resolve_local_group_sids_for_identity`].
/// Returns `Vec<GroupMembership>` with `MembershipPathSource::LocalGroup`,
/// `Member of BUILTIN\\Administrators [source: LocalGroup]` ausweisen
///
///
/// Identity-aware variant of [`resolve_local_group_chains`] using the
/// same candidate-list loop as [`resolve_local_group_sids_for_identity`].
/// Returns `Vec<GroupMembership>` with
/// `MembershipPathSource::LocalGroup` so the explanation path renders
/// each local server group as a `Member of …` step.
pub fn resolve_local_group_chains_for_identity(
    server: Option<&str>,
    identity: &Identity,
    known_member_sids_to_names: &std::collections::HashMap<String, String>,
) -> Result<Vec<GroupMembership>, CoreError> {
    let candidates = format_account_candidates_for_local_groups(identity);
    if candidates.is_empty() {
        return Err(CoreError::Validation(format!(
            "Local group chains: no usable account name form derivable from identity {}",
            identity.sid.0
        )));
    }
    let user_name = identity.name.as_deref();
    let mut tried: Vec<String> = Vec::with_capacity(candidates.len());
    let mut last_err: Option<CoreError> = None;
    for candidate in &candidates {
        tried.push(candidate.clone());
        // Probe via the strict variant first to separate
        // UserNotFoundOnServer from "found, no groups".
        match resolve_local_group_sids_strict(server, candidate) {
            Ok(LocalGroupLookupOutcome::UserNotFoundOnServer) => continue,
            Ok(LocalGroupLookupOutcome::WithGroups(_)) => {
                // Account-Bezug laeuft.
                // Account known — reconstruct chains with the same name.
                match resolve_local_group_chains(
                    server,
                    &identity.sid,
                    user_name,
                    known_member_sids_to_names,
                    candidate,
                ) {
                    Ok(chains) => {
                        let memberships: Vec<GroupMembership> = chains
                            .into_iter()
                            .map(|(group_sid, group_name, path)| GroupMembership {
                                member_sid: identity.sid.clone(),
                                group_sid,
                                // direct = 2-node complete path; mediator
                                // chain (3 nodes) is transitive.
                                direct: path.nodes.len() == 2 && path.complete,
                                group_name,
                                path: Some(path),
                            })
                            .collect();
                        return Ok(memberships);
                    }
                    Err(e) => {
                        last_err = Some(e);
                        // Kandidaten technisch gescheitert (z. B.
                        // chains call failed for this candidate (e.g.
                        // NetLocalGroupGetMembers error); try next.
                        continue;
                    }
                }
            }
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        }
    }
    // No candidate matched — propagate technical error if any.
    if let Some(e) = last_err {
        return Err(e);
    }
    Err(CoreError::Validation(format!(
        "Local group chains: no account form for identity {} known on {server:?} \
         (tried: {:?}). Local server group memberships are not available; the result \
         is marked incomplete.",
        identity.sid.0, tried
    )))
}

/// Returns the `DOMAIN\name` form of a SID via LookupAccountSidW — small
/// variant just for the local group's display label.
fn lookup_account_for_sid_display(sid_str: &str) -> Option<String> {
    use crate::sam::lookup_account_for_sid;
    let info = lookup_account_for_sid(sid_str).ok()?;
    if info.domain.is_empty() {
        Some(info.name)
    } else {
        Some(format!("{}\\{}", info.domain, info.name))
    }
}

/// Converts a Rust string into a null-terminated UTF-16 sequence.
fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// # Safety
/// `p` must be a valid pointer to a null-terminated UTF-16 sequence, or null.
unsafe fn wide_ptr_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let len = (0usize..).take_while(|&i| *p.add(i) != 0).count();
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

/// als kanonischen S-R-I-...-String zurueck.
/// Looks up an account name on the given system and returns its SID as the
/// canonical S-R-I-... string.
fn lookup_account_sid(system: Option<&str>, name: &str) -> Option<String> {
    let system_w = system.map(to_wide_null);
    let system_ptr = system_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let name_w = to_wide_null(name);

    // Two-step pattern: query sizes first, then call again with allocated buffers.
    // Two-call pattern: query required sizes first, then call with the allocated buffers.
    let mut sid_size: u32 = 0;
    let mut domain_size: u32 = 0;
    let mut sid_use: i32 = 0;
    // SAFETY: name_w is a valid null-terminated wide string. Output pointers may be null
    // on the sizing call; Windows returns the required sizes via sid_size/domain_size.
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
        return None;
    }

    let mut sid_buf = vec![0u8; sid_size as usize];
    let mut domain_buf = vec![0u16; domain_size as usize];
    // SAFETY: buffers are sized per the previous sizing call.
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
        return None;
    }

    let mut sid_str: *mut u16 = std::ptr::null_mut();
    // SAFETY: sid_buf contains a valid SID written by LookupAccountNameW.
    let ok = unsafe { ConvertSidToStringSidW(sid_buf.as_ptr() as *mut _, &mut sid_str) };
    if ok == FALSE {
        return None;
    }
    // SAFETY: sid_str was allocated by Windows via LocalAlloc; we free it below.
    let s = unsafe { wide_ptr_to_string(sid_str) };
    unsafe { LocalFree(sid_str as *mut _) };
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `S-1-5-32-544`).
    ///
    ///
    /// Local sanity check: the built-in `Administrator` is a member of the
    /// local `Administrators` group (`BUILTIN\Administrators`, SID
    /// `S-1-5-32-544`).
    ///
    /// `#[ignore]` because GitHub Actions runners use a different admin
    /// account layout (built-in `Administrator` is often disabled or does
    /// not exist; the CI user is `runneradmin`). On a normal local Windows
    /// box the test passes — run explicitly via `cargo test -- --ignored`.
    #[test]
    #[ignore = "depends on local Administrator being enabled — fails on GitHub windows-latest"]
    fn administrator_is_in_local_administrators() {
        let sids = resolve_local_group_sids(None, "Administrator")
            .expect("NetUserGetLocalGroups for local Administrator must succeed");
        assert!(
            sids.iter().any(|s| s.0 == "S-1-5-32-544"),
            "Administrator must be in BUILTIN\\Administrators (S-1-5-32-544); got: {:?}",
            sids.iter().map(|s| s.0.as_str()).collect::<Vec<_>>()
        );
    }

    /// Unknown user returns an empty list without an error.
    #[test]
    fn unknown_user_returns_empty() {
        let sids = resolve_local_group_sids(None, "definitely_not_a_real_user_zz_9f3a8b")
            .expect("call must succeed even for unknown users");
        assert!(sids.is_empty());
    }

    use adpa_core::model::IdentityKind;

    fn identity_with(name: Option<&str>, domain: Option<&str>, upn: Option<&str>) -> Identity {
        Identity {
            sid: Sid("S-1-5-21-1-2-3-1000".into()),
            name: name.map(String::from),
            domain: domain.map(String::from),
            kind: IdentityKind::User,
            disabled: false,
            user_principal_name: upn.map(String::from),
        }
    }

    #[test]
    fn format_prefers_upn_when_present() {
        let id = identity_with(
            Some("max.mustermann"),
            Some("testdomain.local"),
            Some("max@corp.example"),
        );
        assert_eq!(
            format_account_for_local_groups(&id).as_deref(),
            Some("max@corp.example")
        );
    }

    /// auftauchen.
    /// Round 5 finding 1: without UPN, prefer `DOMAIN\name`; DNS suffixes
    /// still get a UPN-style fallback in the candidate list.
    #[test]
    fn format_falls_back_to_domain_backslash_name_for_dns_domain() {
        let id = identity_with(Some("max.mustermann"), Some("testdomain.local"), None);
        let candidates = format_account_candidates_for_local_groups(&id);
        assert_eq!(candidates[0], "testdomain.local\\max.mustermann");
        assert!(
            candidates.contains(&"max.mustermann@testdomain.local".to_string()),
            "DNS-style domain must also produce the UPN-form fallback; got {candidates:?}"
        );
        assert_eq!(
            format_account_for_local_groups(&id).as_deref(),
            Some("testdomain.local\\max.mustermann")
        );
    }

    /// Review 2026-06-04 round 5 finding 1: when given a NetBIOS domain name
    /// produktiv zu stillen NERR_USER_NOT_FOUND.
    /// Round 5 finding 1: NetBIOS domain must NOT produce a `name@domain`
    /// candidate — that exact form was the production bug.
    #[test]
    fn format_netbios_domain_only_emits_domain_backslash_form() {
        let id = identity_with(Some("alice"), Some("TRUSTED"), None);
        let candidates = format_account_candidates_for_local_groups(&id);
        assert!(
            candidates.contains(&"TRUSTED\\alice".to_string()),
            "NetBIOS domain must produce DOMAIN\\name candidate; got {candidates:?}"
        );
        assert!(
            !candidates.contains(&"alice@TRUSTED".to_string()),
            "NetBIOS domain must NOT produce the misleading UPN-style form 'alice@TRUSTED' — that was the round 5 finding 1 bug; got {candidates:?}"
        );
    }

    #[test]
    fn format_returns_plain_name_without_domain() {
        let id = identity_with(Some("Administrator"), None, None);
        let candidates = format_account_candidates_for_local_groups(&id);
        assert_eq!(candidates, vec!["Administrator".to_string()]);
        assert_eq!(
            format_account_for_local_groups(&id).as_deref(),
            Some("Administrator")
        );
    }

    #[test]
    fn format_returns_empty_without_name() {
        let id = identity_with(None, Some("testdomain.local"), None);
        assert!(format_account_candidates_for_local_groups(&id).is_empty());
        assert_eq!(format_account_for_local_groups(&id), None);
    }

    #[test]
    fn format_ignores_empty_upn() {
        let id = identity_with(Some("Administrator"), Some("testdomain.local"), Some(""));
        // Empty UPN is skipped; DOMAIN\name comes first.
        assert_eq!(
            format_account_for_local_groups(&id).as_deref(),
            Some("testdomain.local\\Administrator")
        );
    }

    /// Heuristic: NetBIOS names have no dot; DNS suffixes do.
    #[test]
    fn looks_like_dns_domain_distinguishes_netbios_and_dns() {
        assert!(looks_like_dns_domain("corp.local"));
        assert!(looks_like_dns_domain("ad.example.com"));
        assert!(!looks_like_dns_domain("TRUSTED"));
        assert!(!looks_like_dns_domain("CORP"));
        assert!(!looks_like_dns_domain(".trailing"));
        assert!(!looks_like_dns_domain("leading."));
        assert!(!looks_like_dns_domain(""));
    }

    /// UPN takes absolute priority.
    #[test]
    fn format_upn_wins_over_domain_form() {
        let id = identity_with(
            Some("alice"),
            Some("TRUSTED"),
            Some("alice@trusted.example"),
        );
        let candidates = format_account_candidates_for_local_groups(&id);
        assert_eq!(candidates[0], "alice@trusted.example");
    }
}
