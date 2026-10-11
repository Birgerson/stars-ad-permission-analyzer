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
    model::{
        GroupMembership, Identity, LocalGroupDescriptor, LocalGroupEntry, MembershipHop,
        MembershipPath, MembershipPathSource, Sid,
    },
};
use tracing::{debug, warn};
use win_safe::netapi::NetApiBuffer;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_MORE_DATA, FALSE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetLocalGroupEnum, NetLocalGroupGetMembers, NetUserGetLocalGroups, LG_INCLUDE_INDIRECT,
    LOCALGROUP_INFO_0, LOCALGROUP_MEMBERS_INFO_2, LOCALGROUP_USERS_INFO_0, MAX_PREFERRED_LENGTH,
};
use windows_sys::Win32::Security::LookupAccountNameW;

/// NERR_UserNotFound status code from lmerr.h.
const NERR_USER_NOT_FOUND: u32 = 2221;

/// `NetUserGetLocalGroups` outcome — separates **"user not found"**
/// from **"user found but has no group memberships"**.
#[derive(Debug, Clone)]
pub enum LocalGroupLookupOutcome {
    /// Account was found; the returned vector is the actual group set.
    WithGroups(Vec<Sid>),
    /// Account was not known on the target server.
    UserNotFoundOnServer,
}

// NOTE (ADR 0068): `NetUserGetLocalGroups` is NOT a complete source of an
// account's local groups. On a domain member it omits groups entered through
// a nested domain group, a domain local group, `Everyone` or `Authenticated
// Users`, and from a machine outside the domain it fails for every domain
// account (status 1355). The analysis path therefore reads the server's
// local groups by SID ([`read_local_group_table`]) and expands them like a
// logon does (`permission_engine::engine::expand_local_groups`). The
// name-based functions below remain only for the SAM fallback, whose results
// are always marked not determinable.

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
    /// `DOMAIN\name` form as returned by Windows; for local accounts without
    /// a domain it may just be `Name`.
    pub display_name: Option<String>,
}

/// name. Required for chain reconstruction. The second list names every
/// local group whose SID could not be looked up — it is missing from the
/// token and must surface as a gap (ADR 0066), never be dropped silently.
pub fn resolve_local_groups(
    server: Option<&str>,
    account: &str,
) -> Result<(Vec<LocalGroupInfo>, Vec<String>), CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let account_w = to_wide_null(account);

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
                Ok((Vec::new(), Vec::new()))
            }
            _ => Err(CoreError::LdapQuery(format!(
                "NetUserGetLocalGroups('{account}') failed with status {status}"
            ))),
        };
    }

    let mut result = Vec::with_capacity(entries_read as usize);
    let mut unresolved: Vec<String> = Vec::new();
    if !buf.is_null() && entries_read > 0 {
        // SAFETY: see above
        let entries = unsafe { std::slice::from_raw_parts(buf.as_ptr(), entries_read as usize) };
        for entry in entries {
            // SAFETY: lgrui0_name is a valid null-terminated wide string inside the buffer.
            let name = unsafe { wide_ptr_to_string(entry.lgrui0_name) };
            if name.is_empty() {
                unresolved.push("(a local group with an empty name)".to_owned());
                continue;
            }
            match lookup_account_sid(server, &name) {
                Some(sid_str) => result.push(LocalGroupInfo {
                    name,
                    sid: Sid(sid_str),
                }),
                None => {
                    warn!(local_group = %name, "Could not resolve local group SID");
                    unresolved.push(name);
                }
            }
        }
    }

    Ok((result, unresolved))
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
                // SAFETY: lgrmi2_sid is a valid PSID inside the NetApi
                // buffer; the shared helper owns the OS string via
                // LocalFreeGuard (win_safe review 2026-07-25, W-1/W-2).
                match unsafe { win_safe::sid::sid_to_string_lossy(e.lgrmi2_sid) } {
                    Ok(s) if !s.is_empty() => Some(Sid(s)),
                    _ => None,
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

/// `SID_NAME_USE::SidTypeAlias` — a local group (alias), builtin or not.
const SID_TYPE_ALIAS: i32 = 4;

/// Every local group of `server` (`None` = this machine) with its direct
/// members as SIDs, plus the reader-facing gaps (ADR 0068).
#[derive(Debug, Clone, Default)]
pub struct LocalGroupTable {
    pub groups: Vec<LocalGroupDescriptor>,
    /// Groups whose SID or members could not be read completely. Callers
    /// must mark the local-group evaluation as not complete when non-empty.
    pub gaps: Vec<String>,
}

/// Reads all local groups of `server` and their members by SID (ADR 0068):
/// `NetLocalGroupEnum` → `LookupAccountNameW` on the server (the SID must
/// be an alias) → `NetLocalGroupGetMembers`. No account names of the
/// analysed identity are involved, so this works from a machine outside the
/// domain as well — `NetUserGetLocalGroups` fails there for every domain
/// account (status 1355), and on a domain member it omits groups entered
/// through nested domain groups, domain local groups and well-known SIDs.
///
/// Every value is validated; a group that cannot be read completely is a
/// gap, never a silently shorter table. Enumeration failure is an error.
pub fn read_local_group_table(server: Option<&str>) -> Result<LocalGroupTable, CoreError> {
    let names = enumerate_local_group_names(server)?;
    let mut table = LocalGroupTable::default();
    let mut account_domains: std::collections::BTreeSet<String> = Default::default();
    for name in names {
        let sid = match lookup_account_sid_with_use(server, &name) {
            Some((sid, SID_TYPE_ALIAS)) => match validation::sid::validate_sid(&sid) {
                Ok(_) => Sid(sid),
                Err(e) => {
                    table.gaps.push(format!(
                        "the local group '{name}' returned an invalid SID ({e})"
                    ));
                    continue;
                }
            },
            Some((sid, other)) => {
                table.gaps.push(format!(
                    "the name of the local group '{name}' resolves to {sid}, which is not a \
                     local group (SID type {other})"
                ));
                continue;
            }
            None => {
                table.gaps.push(format!(
                    "the SID of the local group '{name}' could not be read"
                ));
                continue;
            }
        };
        if !sid.0.starts_with("S-1-5-32-") {
            if let Some((domain, _rid)) = sid.0.rsplit_once('-') {
                account_domains.insert(domain.to_owned());
            }
        }
        let members = match get_local_group_members(server, &name) {
            Ok(m) => m,
            Err(e) => {
                table.gaps.push(format!(
                    "the members of the local group '{name}' could not be read ({e})"
                ));
                continue;
            }
        };
        let mut member_sids = Vec::with_capacity(members.len());
        let mut unreadable = 0usize;
        for m in &members {
            match &m.sid {
                Some(s) if validation::sid::validate_sid(&s.0).is_ok() => {
                    member_sids.push(s.clone())
                }
                _ => unreadable += 1,
            }
        }
        if unreadable > 0 {
            table.gaps.push(format!(
                "{unreadable} member(s) of the local group '{name}' have no readable SID"
            ));
        }
        member_sids.sort_by(|a, b| a.0.cmp(&b.0));
        member_sids.dedup();
        table.groups.push(LocalGroupDescriptor {
            sid,
            name,
            members: member_sids,
        });
    }
    // All non-builtin local groups belong to the server's own account
    // domain. More than one domain means a name resolved to something else
    // (e.g. a domain group of the same name) — a gap, not a guess.
    if account_domains.len() > 1 {
        table.gaps.push(format!(
            "the local groups resolve to {} different account domains ({}) — a group name \
             may have resolved to a non-local group",
            account_domains.len(),
            account_domains.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    table.groups.sort_by(|a, b| a.sid.0.cmp(&b.sid.0));
    debug!(
        ?server,
        groups = table.groups.len(),
        gaps = table.gaps.len(),
        "Local group table read"
    );
    Ok(table)
}

/// Upper bound for `NetLocalGroupEnum` pages — a server has a few dozen
/// local groups; a server that keeps answering "more data" is an error.
const MAX_LOCAL_GROUP_PAGES: usize = 10_000;

/// All local group names of `server` via `NetLocalGroupEnum` level 0,
/// following the resume handle until the server reports the end.
fn enumerate_local_group_names(server: Option<&str>) -> Result<Vec<String>, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let mut resume: usize = 0;
    let mut names: Vec<String> = Vec::new();
    for _ in 0..MAX_LOCAL_GROUP_PAGES {
        let mut buf: NetApiBuffer<LOCALGROUP_INFO_0> = NetApiBuffer::null();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;
        // SAFETY: server_ptr is null or a valid null-terminated wide string;
        // NetApi allocates the buffer, the guard frees it on drop.
        let status = unsafe {
            NetLocalGroupEnum(
                server_ptr,
                0,
                buf.out_ptr().cast(),
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume,
            )
        };
        if status != NO_ERROR && status != ERROR_MORE_DATA {
            return Err(match status {
                ERROR_ACCESS_DENIED => CoreError::AccessDenied(format!(
                    "NetLocalGroupEnum: access denied on {server:?}"
                )),
                _ => CoreError::LdapQuery(format!(
                    "NetLocalGroupEnum on {server:?} failed with status {status}"
                )),
            });
        }
        if !buf.is_null() && entries_read > 0 {
            // SAFETY: NetApi returns exactly `entries_read` consecutive structs.
            let entries =
                unsafe { std::slice::from_raw_parts(buf.as_ptr(), entries_read as usize) };
            for e in entries {
                // SAFETY: lgrpi0_name is a null-terminated wide string in the buffer.
                let name = unsafe { wide_ptr_to_string(e.lgrpi0_name) };
                if name.is_empty() {
                    return Err(CoreError::LdapQuery(format!(
                        "NetLocalGroupEnum on {server:?} returned a local group without a name"
                    )));
                }
                names.push(name);
            }
        }
        if status == NO_ERROR {
            names.sort();
            names.dedup();
            return Ok(names);
        }
    }
    Err(CoreError::LdapQuery(format!(
        "NetLocalGroupEnum on {server:?} did not finish after {MAX_LOCAL_GROUP_PAGES} pages"
    )))
}

/// Builds the explanation memberships for the local groups an account is in
/// (ADR 0068): `account → local group` when the account itself is a member,
/// otherwise `account → token SID → local group` through the first entry of
/// `via`; the other entries go into `also_via`. `names` labels the SIDs;
/// a SID without a label there is looked up through LSA on this machine.
pub fn local_group_memberships(
    identity: &Identity,
    entries: &[LocalGroupEntry],
    names: &std::collections::HashMap<String, String>,
) -> Vec<GroupMembership> {
    // Names the caller knows win; anything else (well-known SIDs such as
    // `Everyone`) is looked up once through LSA on this machine.
    let label = |sid: &Sid| {
        names
            .get(&sid.0)
            .cloned()
            .or_else(|| lookup_account_for_sid_display(&sid.0))
    };
    entries
        .iter()
        .map(|e| {
            let via_self = e.via.first().is_some_and(|s| *s == identity.sid);
            let mut rest: Vec<MembershipHop> = e
                .via
                .iter()
                .filter(|s| **s != identity.sid)
                .map(|s| MembershipHop {
                    sid: s.clone(),
                    name: label(s),
                })
                .collect();
            let user_label = identity.name.clone();
            let path = if via_self || rest.is_empty() {
                MembershipPath {
                    nodes: vec![identity.sid.clone(), e.group.clone()],
                    names: vec![user_label, Some(e.name.clone())],
                    source: MembershipPathSource::LocalGroup,
                    complete: true,
                    also_via: rest,
                }
            } else {
                let first = rest.remove(0);
                MembershipPath {
                    nodes: vec![identity.sid.clone(), first.sid.clone(), e.group.clone()],
                    names: vec![user_label, first.name, Some(e.name.clone())],
                    source: MembershipPathSource::LocalGroup,
                    complete: true,
                    also_via: rest,
                }
            };
            GroupMembership {
                member_sid: identity.sid.clone(),
                group_sid: e.group.clone(),
                direct: path.nodes.len() == 2,
                group_name: Some(e.name.clone()),
                path: Some(path),
                // Local server groups have no sIDHistory — 0 is exact (ADR 0059).
                group_sid_history_count: 0,
                group_sid_history: Vec::new(),
            }
        })
        .collect()
}

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
) -> Result<LocalGroupChains, CoreError> {
    let (local_groups, unresolved) = resolve_local_groups(server, account)?;
    let gaps: Vec<String> = if unresolved.is_empty() {
        Vec::new()
    } else {
        vec![format!(
            "{} local group(s) of the target server could not be resolved to a SID and are not \
             in the evaluated token: {}",
            unresolved.len(),
            unresolved.join(", ")
        )]
    };
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
                        also_via: Vec::new(),
                    },
                ));
                continue;
            }
        };

        out.push((
            lg.sid.clone(),
            Some(lg_display.clone()),
            local_group_path(
                user_sid,
                user_name,
                &lg.sid,
                &lg_display,
                &members,
                known_member_sids_to_names,
            ),
        ));
    }
    sort_local_group_chains(&mut out);
    Ok(LocalGroupChains { chains: out, gaps })
}

/// Local-group chains of one account plus the gaps found (ADR 0066).
#[derive(Debug, Clone)]
pub struct LocalGroupChains {
    pub chains: Vec<(Sid, Option<String>, MembershipPath)>,
    /// Reader-facing reasons why local groups are missing from `chains`.
    pub gaps: Vec<String>,
}

/// Orders local-group chains by display name (case-insensitive), then SID,
/// so the explanation path does not depend on the order in which
/// `NetUserGetLocalGroups` happened to list the groups (ADR 0063).
fn sort_local_group_chains(chains: &mut [(Sid, Option<String>, MembershipPath)]) {
    chains.sort_by(|(a_sid, a_name, _), (b_sid, b_name, _)| {
        let an = a_name.as_deref().unwrap_or("").to_lowercase();
        let bn = b_name.as_deref().unwrap_or("").to_lowercase();
        an.cmp(&bn).then_with(|| a_sid.0.cmp(&b_sid.0))
    });
}

/// Builds the membership path into one local group from its direct members.
///
/// Every member that is the user or one of the user's known token groups is
/// a real entry into the group. Preference for the shown chain: the user
/// itself (2-node chain) — otherwise the known group with the
/// alphabetically first name, then SID (3-node chain `user → group →
/// local group`). All further entries go into `also_via`, sorted the same
/// way, so neither the member order the API returned nor the order of the
/// lookup map can change the output (ADR 0063). No entry at all — the user
/// is probably nested via another local group — yields an honestly
/// incomplete 2-node path.
fn local_group_path(
    user_sid: &Sid,
    user_name: Option<&str>,
    group_sid: &Sid,
    group_display: &str,
    members: &[LocalGroupMember],
    known_member_sids_to_names: &std::collections::HashMap<String, String>,
) -> MembershipPath {
    let via_self = members
        .iter()
        .any(|m| m.sid.as_ref().is_some_and(|s| s.0 == user_sid.0));
    let mut mediators: Vec<MembershipHop> = members
        .iter()
        .filter_map(|m| m.sid.as_ref())
        .filter(|s| s.0 != user_sid.0)
        .filter_map(|s| {
            known_member_sids_to_names
                .get(&s.0)
                .map(|name| MembershipHop {
                    sid: s.clone(),
                    name: Some(name.clone()),
                })
        })
        .collect();
    mediators.sort_by(|a, b| {
        let an = a.name.as_deref().unwrap_or("").to_lowercase();
        let bn = b.name.as_deref().unwrap_or("").to_lowercase();
        an.cmp(&bn).then_with(|| a.sid.0.cmp(&b.sid.0))
    });
    mediators.dedup_by(|a, b| a.sid == b.sid);

    let user_label = user_name.map(str::to_owned);
    if via_self {
        return MembershipPath {
            nodes: vec![user_sid.clone(), group_sid.clone()],
            names: vec![user_label, Some(group_display.to_owned())],
            source: MembershipPathSource::LocalGroup,
            complete: true,
            also_via: mediators,
        };
    }
    let mut rest = mediators.into_iter();
    match rest.next() {
        Some(first) => MembershipPath {
            nodes: vec![user_sid.clone(), first.sid.clone(), group_sid.clone()],
            names: vec![user_label, first.name, Some(group_display.to_owned())],
            source: MembershipPathSource::LocalGroup,
            complete: true,
            also_via: rest.collect(),
        },
        // Likely nested via another local group — honestly flag as
        // incomplete.
        None => MembershipPath {
            nodes: vec![user_sid.clone(), group_sid.clone()],
            names: vec![user_label, Some(group_display.to_owned())],
            source: MembershipPathSource::LocalGroup,
            complete: false,
            also_via: Vec::new(),
        },
    }
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

/// Looks up an account name on the given system and returns its SID as the
/// canonical S-R-I-... string.
fn lookup_account_sid(system: Option<&str>, name: &str) -> Option<String> {
    lookup_account_sid_with_use(system, name).map(|(sid, _)| sid)
}

/// Like [`lookup_account_sid`], plus the `SID_NAME_USE` of the account so a
/// caller can check what kind of object the name resolved to (ADR 0068).
fn lookup_account_sid_with_use(system: Option<&str>, name: &str) -> Option<(String, i32)> {
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

    // SAFETY: sid_buf contains a valid SID written by LookupAccountNameW;
    // the shared helper owns the OS string via LocalFreeGuard and also
    // covers the null double-check this site previously missed
    // (win_safe review 2026-07-25, W-1/W-2).
    unsafe { win_safe::sid::sid_to_string_lossy(sid_buf.as_ptr().cast()) }
        .ok()
        .map(|sid| (sid, sid_use))
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
        let outcome = resolve_local_group_sids_strict(None, "Administrator")
            .expect("NetUserGetLocalGroups for local Administrator must succeed");
        let sids = match outcome {
            LocalGroupLookupOutcome::WithGroups(v) => v,
            LocalGroupLookupOutcome::UserNotFoundOnServer => {
                panic!("local Administrator must be known on this machine")
            }
        };
        assert!(
            sids.iter().any(|s| s.0 == "S-1-5-32-544"),
            "Administrator must be in BUILTIN\\Administrators (S-1-5-32-544); got: {:?}",
            sids.iter().map(|s| s.0.as_str()).collect::<Vec<_>>()
        );
    }

    /// An unknown account must surface as `UserNotFoundOnServer` — **not** as
    /// an empty group list. The removed lossy wrapper conflated the two
    /// (ad_resolver review 2026-07-25, AD-1); this pins the distinction.
    #[test]
    fn unknown_user_is_reported_as_not_found_not_as_empty() {
        let outcome = resolve_local_group_sids_strict(None, "definitely_not_a_real_user_zz_9f3a8b")
            .expect("call must succeed even for unknown users");
        assert!(
            matches!(outcome, LocalGroupLookupOutcome::UserNotFoundOnServer),
            "unknown account must be distinguishable from 'no groups'; got: {outcome:?}"
        );
    }

    // --- ADR 0068: local groups read by SID ---

    const DOMAIN_ADMINS: &str = "S-1-5-21-1-2-3-512";

    /// Reads this machine's local groups. Every Windows machine has
    /// BUILTIN\Administrators and BUILTIN\Users; every SID read must be
    /// valid and every group an alias.
    #[test]
    fn local_group_table_of_this_machine_is_complete_and_valid() {
        let table = read_local_group_table(None).expect("NetLocalGroupEnum on this machine");
        let sids: Vec<&str> = table.groups.iter().map(|g| g.sid.0.as_str()).collect();
        assert!(sids.contains(&"S-1-5-32-544"), "{sids:?}");
        assert!(sids.contains(&"S-1-5-32-545"), "{sids:?}");
        for g in &table.groups {
            assert!(
                validation::sid::validate_sid(&g.sid.0).is_ok(),
                "{}",
                g.sid.0
            );
            for m in &g.members {
                assert!(validation::sid::validate_sid(&m.0).is_ok(), "{}", m.0);
            }
        }
        // Sorted by SID — deterministic regardless of enumeration order.
        let mut sorted = sids.clone();
        sorted.sort();
        assert_eq!(sids, sorted);
    }

    fn entry(group: &str, name: &str, via: &[&str]) -> LocalGroupEntry {
        LocalGroupEntry {
            group: Sid(group.into()),
            name: name.into(),
            via: via.iter().map(|s| Sid((*s).into())).collect(),
        }
    }

    fn account() -> Identity {
        Identity {
            sid: Sid(USER_SID.into()),
            name: Some("alice".into()),
            domain: None,
            kind: adpa_core::model::IdentityKind::User,
            disabled: false,
            user_principal_name: None,
            sid_history_count: 0,
            sid_history: Vec::new(),
        }
    }

    #[test]
    fn local_group_membership_via_the_account_itself_is_direct() {
        let ms = local_group_memberships(
            &account(),
            &[entry(
                LOCAL_ADMINS,
                "Administrators",
                &[USER_SID, DOMAIN_ADMINS],
            )],
            &known(),
        );
        assert_eq!(ms.len(), 1);
        let path = ms[0].path.as_ref().unwrap();
        assert!(ms[0].direct && path.complete);
        assert_eq!(
            path.nodes,
            vec![Sid(USER_SID.into()), Sid(LOCAL_ADMINS.into())]
        );
        assert_eq!(path.also_via.len(), 1);
        assert_eq!(path.also_via[0].sid, Sid(DOMAIN_ADMINS.into()));
    }

    #[test]
    fn local_group_membership_via_a_token_sid_names_the_mediator() {
        let ms = local_group_memberships(
            &account(),
            &[entry(LOCAL_ADMINS, "Administrators", &[DOMAIN_ADMINS])],
            &known(),
        );
        let path = ms[0].path.as_ref().unwrap();
        assert!(!ms[0].direct && path.complete);
        assert_eq!(
            path.nodes,
            vec![
                Sid(USER_SID.into()),
                Sid(DOMAIN_ADMINS.into()),
                Sid(LOCAL_ADMINS.into())
            ]
        );
        assert_eq!(path.names[1].as_deref(), Some("Domain Admins"));
        assert!(path.also_via.is_empty());
    }

    // --- local_group_path: deterministic mediator choice (ADR 0063) ---

    const USER_SID: &str = "S-1-5-21-1-2-3-1000";
    const LOCAL_ADMINS: &str = "S-1-5-32-544";

    fn member(sid: &str) -> LocalGroupMember {
        LocalGroupMember {
            sid: Some(Sid(sid.to_owned())),
            display_name: None,
        }
    }

    fn known() -> std::collections::HashMap<String, String> {
        let mut m = std::collections::HashMap::new();
        m.insert(USER_SID.to_owned(), "alice".to_owned());
        m.insert("S-1-5-21-1-2-3-512".to_owned(), "Domain Admins".to_owned());
        m.insert(
            "S-1-5-21-1-2-3-519".to_owned(),
            "Enterprise Admins".to_owned(),
        );
        m.insert("S-1-5-21-1-2-3-1500".to_owned(), "Admins-Tier0".to_owned());
        m
    }

    fn path_for(members: &[LocalGroupMember]) -> MembershipPath {
        local_group_path(
            &Sid(USER_SID.to_owned()),
            Some("alice"),
            &Sid(LOCAL_ADMINS.to_owned()),
            "BUILTIN\\Administrators",
            members,
            &known(),
        )
    }

    #[test]
    fn local_group_mediator_choice_ignores_member_order() {
        let orders = [
            [
                "S-1-5-21-1-2-3-519",
                "S-1-5-21-1-2-3-512",
                "S-1-5-21-1-2-3-1500",
            ],
            [
                "S-1-5-21-1-2-3-1500",
                "S-1-5-21-1-2-3-519",
                "S-1-5-21-1-2-3-512",
            ],
            [
                "S-1-5-21-1-2-3-512",
                "S-1-5-21-1-2-3-1500",
                "S-1-5-21-1-2-3-519",
            ],
        ];
        let paths: Vec<MembershipPath> = orders
            .iter()
            .map(|o| path_for(&o.iter().map(|s| member(s)).collect::<Vec<_>>()))
            .collect();
        assert!(paths.windows(2).all(|w| w[0] == w[1]));
        let p = &paths[0];
        assert!(p.complete);
        // Alphabetically first name wins the shown chain …
        assert_eq!(p.nodes[1], Sid("S-1-5-21-1-2-3-1500".to_owned()));
        // … and the other two are disclosed as further routes.
        let also: Vec<&str> = p.also_via.iter().map(|h| h.sid.0.as_str()).collect();
        assert_eq!(also, ["S-1-5-21-1-2-3-512", "S-1-5-21-1-2-3-519"]);
    }

    #[test]
    fn direct_local_membership_still_lists_mediating_groups() {
        let p = path_for(&[
            member("S-1-5-21-1-2-3-512"),
            member(USER_SID),
            member("S-1-5-21-9-9-9-777"), // unknown to the token: no route
        ]);
        assert_eq!(p.nodes.len(), 2, "direct chain");
        assert!(p.complete);
        let also: Vec<&str> = p.also_via.iter().map(|h| h.sid.0.as_str()).collect();
        assert_eq!(also, ["S-1-5-21-1-2-3-512"]);
    }

    #[test]
    fn local_group_chains_are_sorted_by_name_then_sid() {
        let path = |sid: &str| MembershipPath {
            nodes: vec![Sid(USER_SID.to_owned()), Sid(sid.to_owned())],
            names: vec![None, None],
            source: MembershipPathSource::LocalGroup,
            complete: true,
            also_via: Vec::new(),
        };
        let mut chains = vec![
            (
                Sid("S-1-5-32-545".to_owned()),
                Some(r"BUILTIN\Users".to_owned()),
                path("S-1-5-32-545"),
            ),
            (
                Sid("S-1-5-32-544".to_owned()),
                Some(r"BUILTIN\Administrators".to_owned()),
                path("S-1-5-32-544"),
            ),
            (
                Sid("S-1-5-32-555".to_owned()),
                Some(r"builtin\Remote Desktop Users".to_owned()),
                path("S-1-5-32-555"),
            ),
        ];
        sort_local_group_chains(&mut chains);
        let order: Vec<&str> = chains.iter().map(|(s, _, _)| s.0.as_str()).collect();
        assert_eq!(order, ["S-1-5-32-544", "S-1-5-32-555", "S-1-5-32-545"]);
    }

    #[test]
    fn local_group_without_known_member_is_incomplete() {
        let p = path_for(&[member("S-1-5-21-9-9-9-777")]);
        assert!(!p.complete);
        assert!(p.also_via.is_empty());
    }
}
