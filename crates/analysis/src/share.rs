// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! The share mask of an SMB path for the account's token.
//!
//! The orchestration itself has lived in
//! `share_scanner::resolve_share_mask_status_explained` since G1; the CLI
//! and the GUI still had one adapter each. They share this one now.

use adpa_core::model::{
    AccessContext, GroupMembership, Identity, RemoteUacFiltering, ShareMaskStatus, Sid,
};

/// The share result for one path: the status (with the mask when applied),
/// the number of share ACEs that could not be evaluated, and the per-ACE
/// decisions for the explanation path (review CR-7).
pub struct ShareResolution {
    pub status: ShareMaskStatus,
    pub unevaluated: usize,
    pub decisions: Vec<share_scanner::ShareAceDecision>,
}

/// Computes the share mask and its evaluation status. `NotApplicable` when
/// no SMB context exists, `Applied(mask)` after a successful DACL read,
/// `ReadFailed(reason)` when the share DACL could not be read.
///
/// The RESOLVED identity goes in — its SID and its historical SIDs
/// (sIDHistory, ADR 0056) both enter the share token, so it matches the
/// NTFS token.
#[allow(clippy::too_many_arguments)]
pub fn resolve_share_status(
    path: &str,
    smb_server: Option<&str>,
    share_name: Option<&str>,
    identity: &Identity,
    memberships: &[GroupMembership],
    local_group_sids: &[Sid],
    logon_dependent_group_sids: &[Sid],
    uac_filtered_group_sids: &[Sid],
    access_context: AccessContext,
    remote_uac: &RemoteUacFiltering,
    anonymous_everyone: Option<bool>,
) -> ShareResolution {
    let r = share_scanner::resolve_share_mask_status_explained(
        path,
        smb_server,
        share_name,
        &identity.sid.0,
        &identity.sid_history,
        memberships,
        local_group_sids,
        logon_dependent_group_sids,
        uac_filtered_group_sids,
        access_context,
        matches!(remote_uac, RemoteUacFiltering::Filtered { .. }),
        anonymous_everyone,
    );
    ShareResolution {
        status: r.status,
        unevaluated: r.unevaluated,
        decisions: r.decisions,
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_share_status;
    use adpa_core::model::{
        AccessContext, Identity, IdentityKind, RemoteUacFiltering, ShareMaskStatus, Sid,
    };

    /// A local path without an SMB override has no share: no share lookup,
    /// `NotApplicable` (review finding 1 — before the fix the path was split
    /// as UNC and `NetShareGetInfo("C:", "Windows")` was called). The UNC
    /// parsing itself is tested in `validation::path`.
    #[test]
    fn share_status_does_not_treat_local_path_as_unc() {
        let identity = Identity {
            sid: Sid("S-1-5-21-1-2-3-1000".to_owned()),
            name: Some("test".into()),
            domain: None,
            kind: IdentityKind::User,
            disabled: false,
            user_principal_name: None,
            sid_history_count: 0,
            sid_history: Vec::new(),
        };
        let r = resolve_share_status(
            r"C:\Windows\SYSVOL",
            None,
            None,
            &identity,
            &[],
            &[],
            &[],
            &[],
            AccessContext::LocalInteractive,
            &RemoteUacFiltering::Unknown,
            None,
        );
        assert!(matches!(r.status, ShareMaskStatus::NotApplicable));
        assert_eq!(r.unevaluated, 0);
        assert!(r.decisions.is_empty());
    }
}
