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
    model::{GroupMembership, Identity, MembershipHop, MembershipPath, MembershipPathSource, Sid},
};
use tracing::{debug, warn};
use win_safe::netapi::NetApiBuffer;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, FALSE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetLocalGroupGetMembers, NetUserGetLocalGroups, LG_INCLUDE_INDIRECT, LOCALGROUP_MEMBERS_INFO_2,
    LOCALGROUP_USERS_INFO_0, MAX_PREFERRED_LENGTH,
};
use windows_sys::Win32::Security::LookupAccountNameW;

/// NERR_UserNotFound status code from lmerr.h.
const NERR_USER_NOT_FOUND: u32 = 2221;

/// Heuristic: does the domain string look like a DNS suffix (contains a
/// dot)? In trust / multi-domain scenarios LSA usually returns the NetBIOS
/// name (`TRUSTED`); `name@TRUSTED` is NOT a valid account reference for
/// `NetUserGetLocalGroups` — only DNS-style suffixes (`corp.local`) work
/// as UPN suffixes.
fn looks_like_dns_domain(domain: &str) -> bool {
    domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

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

// NOTE: a lossy `resolve_local_group_sids` wrapper existed here until the
// ad_resolver review 2026-07-25 (AD-1). It returned `Vec<Sid>` and mapped
// `UserNotFoundOnServer` to an empty vector — silently conflating "the
// account is unknown on this server" with "the account has no local
// groups". That is exactly the silent-omission class this project rejects,
// and it had no production caller (a stale comment claimed the GUI used
// it; the GUI uses `resolve_local_group_chains_for_identity`).
//
// Use instead:
//   * `resolve_local_group_sids_strict` — same lookup, but the
//     not-found case stays visible via `LocalGroupLookupOutcome`.
//   * `resolve_local_group_chains_for_identity` — the richer variant that
//     also yields group names and membership paths for the explanation,
//     and derives the account name form from the `Identity` itself.

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

/// Tries to resolve local groups for `identity` on `server`, iterating
/// over candidate account name forms
/// ([`format_account_candidates_for_local_groups`]). Returns `Err(...)`
/// on technical failures (Access Denied, NetAPI errors).
pub fn resolve_local_group_sids_for_identity(
    server: Option<&str>,
    identity: &Identity,
) -> Result<Vec<Sid>, CoreError> {
    let candidates = format_account_candidates_for_local_groups(identity);
    if candidates.is_empty() {
        return Err(CoreError::Validation(format!(
            "{} has no account name, so its local group memberships on the target server cannot be looked up",
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

/// Local-group memberships of an identity plus the gaps found (ADR 0066).
#[derive(Debug, Clone)]
pub struct LocalGroupMemberships {
    pub memberships: Vec<GroupMembership>,
    /// Reader-facing reasons why local groups are missing; callers must mark
    /// the local-group evaluation as not complete when this is non-empty.
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

/// Identity-aware variant of [`resolve_local_group_chains`] using the
/// same candidate-list loop as [`resolve_local_group_sids_for_identity`].
/// Returns `Vec<GroupMembership>` with
/// `MembershipPathSource::LocalGroup` so the explanation path renders
/// each local server group as a `Member of …` step.
pub fn resolve_local_group_chains_for_identity(
    server: Option<&str>,
    identity: &Identity,
    known_member_sids_to_names: &std::collections::HashMap<String, String>,
) -> Result<LocalGroupMemberships, CoreError> {
    let candidates = format_account_candidates_for_local_groups(identity);
    if candidates.is_empty() {
        return Err(CoreError::Validation(format!(
            "{} has no account name, so its local group memberships on the target server cannot be looked up",
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
                    Ok(LocalGroupChains { chains, gaps }) => {
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
                                // Local server groups have no sIDHistory —
                                // 0 is exact, not unknown (ADR 0059).
                                group_sid_history_count: 0,
                                group_sid_history: Vec::new(),
                            })
                            .collect();
                        return Ok(LocalGroupMemberships { memberships, gaps });
                    }
                    Err(e) => {
                        last_err = Some(e);
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

    // SAFETY: sid_buf contains a valid SID written by LookupAccountNameW;
    // the shared helper owns the OS string via LocalFreeGuard and also
    // covers the null double-check this site previously missed
    // (win_safe review 2026-07-25, W-1/W-2).
    unsafe { win_safe::sid::sid_to_string_lossy(sid_buf.as_ptr().cast()) }.ok()
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

    use adpa_core::model::IdentityKind;

    fn identity_with(name: Option<&str>, domain: Option<&str>, upn: Option<&str>) -> Identity {
        Identity {
            sid: Sid("S-1-5-21-1-2-3-1000".into()),
            name: name.map(String::from),
            domain: domain.map(String::from),
            kind: IdentityKind::User,
            disabled: false,
            user_principal_name: upn.map(String::from),
            sid_history_count: 0,
            sid_history: Vec::new(),
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
