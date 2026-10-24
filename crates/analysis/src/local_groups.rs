// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! The account's local groups on the analysis target server (ADR 0068).
//!
//! Until ADR 0082 step 5 the CLI and the GUI each had their own copy of
//! these functions; they are the same code here once.

use ad_resolver::PrincipalResolution;
use adpa_core::model::{
    AccessContext, GroupMembership, Identity, LocalGroupEvalStatus, RemoteUacFiltering, Sid,
};
use validation::path::effective_smb_target;

/// The local groups of the analysis target server the account is in
/// (ADR 0068), split into token memberships and groups reachable only
/// through a logon-dependent SID.
#[derive(Debug, Clone)]
pub struct LocalGroupResolution {
    pub sids: Vec<Sid>,
    pub memberships: Vec<GroupMembership>,
    pub logon_dependent: Vec<Sid>,
    /// Display names of the logon-dependent groups, for reader-facing notes.
    pub logon_dependent_names: Vec<String>,
    /// Token groups User Account Control may filter for this access
    /// (ADR 0070/0071) — deny-only for the engine.
    pub uac_filtered: Vec<Sid>,
    /// ADR 0076: remote UAC decided from the target's policies.
    pub remote_uac: RemoteUacFiltering,
    /// L17: EveryoneIncludesAnonymous read from the target.
    pub anonymous_everyone: Option<bool>,
    pub status: LocalGroupEvalStatus,
}

/// Resolves the account's local groups on the analysis target server. For
/// UNC paths the server is derived from the path; for local paths the local
/// machine is used. The server's local groups are read by SID and expanded
/// against the account's token like a logon does (ADR 0068) — no account
/// name lookup, so a machine outside the domain gets the same answer. A
/// failure does not abort the analysis; it marks the result incomplete.
pub fn collect_local_group_sids_for_path(
    path: &str,
    explicit_smb_server: Option<&str>,
    identity: &Identity,
    domain_memberships: &[GroupMembership],
    access_context: AccessContext,
    local_account: bool,
) -> LocalGroupResolution {
    let server_owned = effective_smb_target(path, explicit_smb_server);
    collect_local_groups_on(
        server_owned.as_deref(),
        identity,
        domain_memberships,
        access_context,
        local_account,
    )
}

/// The token groups User Account Control may filter for this access
/// (ADR 0070/0071): over all groups of the token — domain groups with their
/// SID history, and the local groups.
pub fn uac_filtered_token_groups(
    domain_memberships: &[GroupMembership],
    local_group_sids: &[Sid],
    local_account: bool,
    access_context: AccessContext,
) -> Vec<Sid> {
    let token_groups: Vec<Sid> = domain_memberships
        .iter()
        .flat_map(|m| {
            std::iter::once(m.group_sid.clone()).chain(m.group_sid_history.iter().cloned())
        })
        .chain(local_group_sids.iter().cloned())
        .collect();
    permission_engine::engine::uac_filtered_groups(&token_groups, local_account, access_context)
}

/// [`collect_local_group_sids_for_path`] for a known server (`None` = this
/// machine) — also used by the membership view of a local account.
pub fn collect_local_groups_on(
    server: Option<&str>,
    identity: &Identity,
    domain_memberships: &[GroupMembership],
    access_context: AccessContext,
    local_account: bool,
) -> LocalGroupResolution {
    // L17: EveryoneIncludesAnonymous of the target decides Everyone for an
    // anonymous logon; an unreadable value keeps it bounded.
    #[cfg(windows)]
    let anonymous_everyone = if identity.sid.0 == permission_engine::engine::SID_ANONYMOUS_LOGON {
        permission_engine::engine::anonymous_everyone(
            &ad_resolver::read_everyone_includes_anonymous(server),
        )
    } else {
        None
    };
    #[cfg(not(windows))]
    let anonymous_everyone: Option<bool> = None;

    let table = match ad_resolver::read_local_group_table(server) {
        Ok(t) => t,
        Err(e) => {
            let msg = e.to_string();
            tracing::warn!(
                ?server,
                sid = %identity.sid.0,
                error = %msg,
                "Local group table unreadable; result will be marked incomplete"
            );
            return LocalGroupResolution {
                sids: Vec::new(),
                memberships: Vec::new(),
                logon_dependent: Vec::new(),
                logon_dependent_names: Vec::new(),
                uac_filtered: uac_filtered_token_groups(
                    domain_memberships,
                    &[],
                    local_account,
                    access_context,
                ),
                remote_uac: RemoteUacFiltering::Unknown,
                anonymous_everyone,
                status: LocalGroupEvalStatus::NotAvailable(msg),
            };
        }
    };
    let expansion = permission_engine::engine::expand_local_groups_with(
        &identity.sid.0,
        &identity.sid_history,
        domain_memberships,
        &table.groups,
        access_context,
        anonymous_everyone,
    );
    // Labels for the mediator step of each chain (account, domain groups);
    // well-known SIDs are looked up by the builder.
    let mut names: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    if let Some(ref n) = identity.name {
        names.insert(identity.sid.0.clone(), n.clone());
    }
    for gm in domain_memberships {
        if let Some(ref n) = gm.group_name {
            names.insert(gm.group_sid.0.clone(), n.clone());
        }
    }
    let memberships = ad_resolver::local_group_memberships(identity, &expansion.certain, &names);
    let all_sids: Vec<Sid> = memberships.iter().map(|m| m.group_sid.clone()).collect();
    // ADR 0070/0071: groups User Account Control may filter for this access;
    // they stay in the token lists and the explanation, the engine treats
    // them as deny-only.
    let uac_filtered =
        uac_filtered_token_groups(domain_memberships, &all_sids, local_account, access_context);
    // ADR 0076: over SMB the target's policies decide remote UAC for a
    // local account — filtered groups become certainly deny-only, or are
    // enabled; unreadable policies keep them bounded.
    // On a local path only the built-in Administrator with
    // FilterAdministratorToken = 0 is decided (full token, measured).
    #[cfg(windows)]
    let remote_uac = if local_account && !uac_filtered.is_empty() {
        let builtin_administrator = identity.sid.0.ends_with("-500");
        match access_context {
            AccessContext::RemoteSmb => {
                let policy = ad_resolver::read_target_uac_policy(server);
                permission_engine::engine::remote_uac_filtering(
                    builtin_administrator,
                    &policy.enable_lua,
                    &policy.local_account_token_filter_policy,
                    &policy.filter_administrator_token,
                )
            }
            AccessContext::LocalInteractive if builtin_administrator => {
                let policy = ad_resolver::read_target_uac_policy(server);
                permission_engine::engine::local_uac_filtering(
                    true,
                    &policy.enable_lua,
                    &policy.filter_administrator_token,
                )
            }
            _ => RemoteUacFiltering::Unknown,
        }
    } else {
        RemoteUacFiltering::Unknown
    };
    #[cfg(not(windows))]
    let remote_uac = RemoteUacFiltering::Unknown;
    let uac_filtered = if matches!(remote_uac, RemoteUacFiltering::NotFiltered { .. }) {
        Vec::new()
    } else {
        uac_filtered
    };
    let sids = all_sids;
    let logon_dependent = expansion
        .logon_dependent
        .iter()
        .map(|e| e.group.clone())
        .collect();
    let logon_dependent_names = expansion
        .logon_dependent
        .iter()
        .map(|e| e.name.clone())
        .collect();
    tracing::debug!(
        ?server,
        sid = %identity.sid.0,
        groups = table.groups.len(),
        member_of = memberships.len(),
        logon_dependent = expansion.logon_dependent.len(),
        "Local groups expanded for target server"
    );
    // ADR 0066: groups that could not be read keep the evaluation
    // incomplete; the resolved ones stay in the token.
    let status = if table.gaps.is_empty() {
        LocalGroupEvalStatus::Applied
    } else {
        LocalGroupEvalStatus::NotAvailable(table.gaps.join("; "))
    };
    LocalGroupResolution {
        sids,
        memberships,
        logon_dependent,
        logon_dependent_names,
        uac_filtered,
        remote_uac,
        anonymous_everyone,
        status,
    }
}

/// ADR 0070: the membership view of a local account of this machine lists
/// its local groups too — read by SID and expanded like a logon (no specific
/// logon). Groups reachable only through a logon-dependent SID and an
/// incomplete local-group table are named as gaps, never dropped.
pub fn add_local_groups_for_membership_view(res: &mut PrincipalResolution) {
    let lg = collect_local_groups_on(
        None,
        &res.identity,
        &res.memberships,
        AccessContext::Unspecified,
        false,
    );
    res.memberships.extend(lg.memberships);
    if let LocalGroupEvalStatus::NotAvailable(msg) = lg.status {
        res.group_resolution_gaps.push(format!(
            "the local groups could not be read completely ({msg})"
        ));
    }
    if !lg.logon_dependent_names.is_empty() {
        res.group_resolution_gaps.push(format!(
            "membership in {} depends on how the account logs on (the group is entered \
             only through a logon-dependent SID such as INTERACTIVE)",
            lg.logon_dependent_names.join(", ")
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::uac_filtered_token_groups;
    use adpa_core::model::{AccessContext, GroupMembership, Sid};

    fn membership(sid: &str, history: &[&str]) -> GroupMembership {
        GroupMembership {
            member_sid: Sid("S-1-5-21-1-2-3-1000".to_owned()),
            group_sid: Sid(sid.to_owned()),
            direct: true,
            group_name: None,
            path: None,
            group_sid_history_count: history.len(),
            group_sid_history: history.iter().map(|h| Sid((*h).to_owned())).collect(),
        }
    }

    /// The UAC candidates are taken over the whole token: a domain group,
    /// a SID in a group's history and a local group all count; groups UAC
    /// never filters do not.
    #[test]
    fn uac_candidates_cover_domain_groups_history_and_local_groups() {
        let domain_admins = "S-1-5-21-1-2-3-512";
        let old_domain_admins = "S-1-5-21-9-9-9-512";
        let users = "S-1-5-21-1-2-3-513";
        let administrators = "S-1-5-32-544";
        let memberships = vec![
            membership(domain_admins, &[]),
            membership(users, &[old_domain_admins]),
        ];
        let filtered = uac_filtered_token_groups(
            &memberships,
            &[Sid(administrators.to_owned())],
            false,
            AccessContext::LocalInteractive,
        );
        let got: Vec<&str> = filtered.iter().map(|s| s.0.as_str()).collect();
        assert!(got.contains(&domain_admins), "{got:?}");
        assert!(got.contains(&old_domain_admins), "{got:?}");
        assert!(got.contains(&administrators), "{got:?}");
        assert!(!got.contains(&users), "{got:?}");
    }
}
