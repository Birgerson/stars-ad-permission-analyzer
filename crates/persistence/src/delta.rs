// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Delta comparison between two scan runs.

use adpa_core::{
    error::CoreError,
    model::{
        AccessMask, EffectivePermission, LocalGroupEvalStatus, NormalizedPath,
        PermissionDiagnostic, ShareEvalStatus,
    },
};
use rusqlite::Connection;
use uuid::Uuid;

use crate::scan_store::load_permissions_for_run;

/// vergleicht `compare_scans` nur `effective_mask` — d.h. audit-
///
/// Audit-relevant fields of a permission, bundled for comparison.
/// Code review 2026-06-07 finding 3: before this patch, `compare_scans`
/// only diffed `effective_mask` — meaning audit-relevant changes with
/// the same final mask (NTFS/share composition, share_status flipping
/// to ReadFailed, new diagnostics) silently disappeared from the delta
/// report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionSignature {
    pub effective_mask: u32,
    pub ntfs_mask: u32,
    pub share_mask: Option<u32>,
    pub share_status: ShareStatusTag,
    pub local_group_status: LocalGroupStatusTag,
    pub unsupported_ace_count: usize,
    pub diagnostics: Vec<PermissionDiagnostic>,
}

/// Comparable status tag for `ShareEvalStatus` — the string in
/// `ReadFailed` is included on purpose because the reason can shift
/// between scans, not just the variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareStatusTag {
    NotApplicable,
    Applied,
    Unrestricted,
    ReadFailed(String),
}

impl From<&ShareEvalStatus> for ShareStatusTag {
    fn from(s: &ShareEvalStatus) -> Self {
        match s {
            ShareEvalStatus::NotApplicable => ShareStatusTag::NotApplicable,
            ShareEvalStatus::Applied => ShareStatusTag::Applied,
            ShareEvalStatus::Unrestricted => ShareStatusTag::Unrestricted,
            ShareEvalStatus::ReadFailed(msg) => ShareStatusTag::ReadFailed(msg.clone()),
        }
    }
}

/// Counterpart to `ShareStatusTag` for the local-group status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalGroupStatusTag {
    NotQueried,
    Applied,
    NotAvailable(String),
}

impl From<&LocalGroupEvalStatus> for LocalGroupStatusTag {
    fn from(s: &LocalGroupEvalStatus) -> Self {
        match s {
            LocalGroupEvalStatus::NotQueried => LocalGroupStatusTag::NotQueried,
            LocalGroupEvalStatus::Applied => LocalGroupStatusTag::Applied,
            LocalGroupEvalStatus::NotAvailable(msg) => {
                LocalGroupStatusTag::NotAvailable(msg.clone())
            }
        }
    }
}

impl PermissionSignature {
    pub fn from(p: &EffectivePermission) -> Self {
        Self {
            effective_mask: p.effective_mask.0,
            ntfs_mask: p.ntfs_mask.0,
            share_mask: p.share_mask.map(|m| m.0),
            share_status: (&p.share_status).into(),
            local_group_status: (&p.local_group_status).into(),
            unsupported_ace_count: p.unsupported_ace_count,
            diagnostics: p.diagnostics.clone(),
        }
    }
}

/// Concrete reason for a change between two permissions. Multiple
/// reasons can co-occur — e.g. an NTFS mask shift that does not flip
/// the effective mask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaReason {
    EffectiveMaskChanged,
    NtfsMaskChanged,
    ShareMaskChanged,
    ShareStatusChanged,
    LocalGroupStatusChanged,
    UnsupportedAceCountChanged,
    DiagnosticsChanged,
}

impl DeltaReason {
    pub fn label(&self) -> &'static str {
        match self {
            DeltaReason::EffectiveMaskChanged => "effective mask",
            DeltaReason::NtfsMaskChanged => "NTFS mask",
            DeltaReason::ShareMaskChanged => "share mask",
            DeltaReason::ShareStatusChanged => "share status",
            DeltaReason::LocalGroupStatusChanged => "local-group status",
            DeltaReason::UnsupportedAceCountChanged => "unsupported-ACE count",
            DeltaReason::DiagnosticsChanged => "diagnostics",
        }
    }
}

/// Compares two signatures and yields every reason for a detected
/// change. Empty vec = identical.
fn signature_diff(old: &PermissionSignature, new: &PermissionSignature) -> Vec<DeltaReason> {
    let mut reasons = Vec::new();
    if old.effective_mask != new.effective_mask {
        reasons.push(DeltaReason::EffectiveMaskChanged);
    }
    if old.ntfs_mask != new.ntfs_mask {
        reasons.push(DeltaReason::NtfsMaskChanged);
    }
    if old.share_mask != new.share_mask {
        reasons.push(DeltaReason::ShareMaskChanged);
    }
    if old.share_status != new.share_status {
        reasons.push(DeltaReason::ShareStatusChanged);
    }
    if old.local_group_status != new.local_group_status {
        reasons.push(DeltaReason::LocalGroupStatusChanged);
    }
    if old.unsupported_ace_count != new.unsupported_ace_count {
        reasons.push(DeltaReason::UnsupportedAceCountChanged);
    }
    if old.diagnostics != new.diagnostics {
        reasons.push(DeltaReason::DiagnosticsChanged);
    }
    reasons
}

/// Type of change between two scans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaKind {
    /// Path is new — was not present in the old scan.
    Added,
    /// Path removed — no longer present in the new scan.
    Removed,
    /// Permission changed. `old_mask`/`new_mask` are kept for backwards
    /// compatibility; `reasons` lists every detected change cause as of
    /// the 2026-06-07 patch.
    Changed {
        old_mask: AccessMask,
        new_mask: AccessMask,
        reasons: Vec<DeltaReason>,
    },
}

/// A single change row in the delta report.
#[derive(Debug, Clone)]
pub struct DeltaEntry {
    pub path: NormalizedPath,
    pub kind: DeltaKind,
    pub old_perm: Option<EffectivePermission>,
    pub new_perm: Option<EffectivePermission>,
}

/// Compares two scan runs and returns all changes.
pub fn compare_scans(
    conn: &Connection,
    old_run_id: &Uuid,
    new_run_id: &Uuid,
) -> Result<Vec<DeltaEntry>, CoreError> {
    let old_perms = load_permissions_for_run(conn, old_run_id)?;
    let new_perms = load_permissions_for_run(conn, new_run_id)?;

    Ok(diff_permission_lists(old_perms, new_perms))
}

/// Pure diff logic on two permission lists — for tests without a DB.
pub fn diff_permission_lists(
    old: Vec<EffectivePermission>,
    new: Vec<EffectivePermission>,
) -> Vec<DeltaEntry> {
    let old_map: std::collections::HashMap<String, EffectivePermission> =
        old.into_iter().map(|p| (p.path.0.clone(), p)).collect();
    let new_map: std::collections::HashMap<String, EffectivePermission> =
        new.into_iter().map(|p| (p.path.0.clone(), p)).collect();

    let mut entries: Vec<DeltaEntry> = Vec::new();

    // Added + Changed via Signatur-Diff (Finding 3).
    // Added + Changed via signature diff (finding 3).
    for (path, new_p) in &new_map {
        match old_map.get(path) {
            None => entries.push(DeltaEntry {
                path: NormalizedPath(path.clone()),
                kind: DeltaKind::Added,
                old_perm: None,
                new_perm: Some(new_p.clone()),
            }),
            Some(old_p) => {
                let old_sig = PermissionSignature::from(old_p);
                let new_sig = PermissionSignature::from(new_p);
                let reasons = signature_diff(&old_sig, &new_sig);
                if !reasons.is_empty() {
                    entries.push(DeltaEntry {
                        path: NormalizedPath(path.clone()),
                        kind: DeltaKind::Changed {
                            old_mask: old_p.effective_mask,
                            new_mask: new_p.effective_mask,
                            reasons,
                        },
                        old_perm: Some(old_p.clone()),
                        new_perm: Some(new_p.clone()),
                    });
                }
            }
        }
    }

    // Removed
    for (path, old_p) in &old_map {
        if !new_map.contains_key(path) {
            entries.push(DeltaEntry {
                path: NormalizedPath(path.clone()),
                kind: DeltaKind::Removed,
                old_perm: Some(old_p.clone()),
                new_perm: None,
            });
        }
    }

    entries.sort_by(|a, b| a.path.0.cmp(&b.path.0));
    entries
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use adpa_core::model::{
        AccessMask, Identity, IdentityKind, PermissionDiagnostic, PermissionPath, Sid,
    };
    use permission_engine::mask::{MASK_MODIFY, MASK_READ};

    fn mk_perm(path: &str, mask: u32) -> EffectivePermission {
        EffectivePermission {
            identity: Identity {
                sid: Sid("S-1-5-21-test".into()),
                name: None,
                domain: None,
                kind: IdentityKind::User,
                disabled: false,
                user_principal_name: None,
                sid_history_count: 0,
            },
            path: NormalizedPath(path.to_string()),
            ntfs_mask: AccessMask(mask),
            share_mask: None,
            effective_mask: AccessMask(mask),
            path_explanation: PermissionPath { steps: vec![] },
            share_status: adpa_core::model::ShareEvalStatus::NotApplicable,
            local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
            contributing_sids: vec![],
            unsupported_ace_count: 0,
            matched_aces: vec![],
            diagnostics: vec![],
        }
    }

    #[test]
    fn added_path_detected() {
        let old = vec![mk_perm(r"C:\data", MASK_READ)];
        let new = vec![
            mk_perm(r"C:\data", MASK_READ),
            mk_perm(r"C:\data\new", MASK_READ),
        ];
        let delta = diff_permission_lists(old, new);
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].kind, DeltaKind::Added);
    }

    #[test]
    fn removed_path_detected() {
        let old = vec![
            mk_perm(r"C:\data", MASK_READ),
            mk_perm(r"C:\data\old", MASK_READ),
        ];
        let new = vec![mk_perm(r"C:\data", MASK_READ)];
        let delta = diff_permission_lists(old, new);
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].kind, DeltaKind::Removed);
    }

    #[test]
    fn changed_permission_detected() {
        let old = vec![mk_perm(r"C:\data", MASK_READ)];
        let new = vec![mk_perm(r"C:\data", MASK_MODIFY)];
        let delta = diff_permission_lists(old, new);
        assert_eq!(delta.len(), 1);
        assert!(matches!(delta[0].kind, DeltaKind::Changed { .. }));
        if let DeltaKind::Changed {
            old_mask,
            new_mask,
            reasons,
        } = &delta[0].kind
        {
            assert_eq!(old_mask.0, MASK_READ);
            assert_eq!(new_mask.0, MASK_MODIFY);
            // beide Trigger gleichzeitig an.
            // mk_perm sets ntfs_mask = effective_mask, so both
            // triggers fire at the same time.
            assert!(reasons.contains(&DeltaReason::EffectiveMaskChanged));
            assert!(reasons.contains(&DeltaReason::NtfsMaskChanged));
        }
    }

    #[test]
    fn unchanged_path_not_in_delta() {
        let old = vec![mk_perm(r"C:\data", MASK_READ)];
        let new = vec![mk_perm(r"C:\data", MASK_READ)];
        assert!(diff_permission_lists(old, new).is_empty());
    }

    /// NTFS=Read, Share=Full, Effective=Read. Effektiver Zugriff
    /// Code review 2026-06-07 finding 3: identical `effective_mask` but
    /// different NTFS or share mask must be reported as Changed. Example:
    /// old NTFS=Modify, Share=Read, Effective=Read; new NTFS=Read,
    /// Share=Full, Effective=Read. Same effective access, completely
    /// different cause and responsibility.
    #[test]
    fn ntfs_share_swap_with_same_effective_is_detected() {
        let mut old = mk_perm(r"C:\data", MASK_READ);
        old.ntfs_mask = AccessMask(MASK_MODIFY);
        old.share_mask = Some(AccessMask(MASK_READ));
        old.effective_mask = AccessMask(MASK_READ);

        let mut new = mk_perm(r"C:\data", MASK_READ);
        new.ntfs_mask = AccessMask(MASK_READ);
        new.share_mask = Some(AccessMask(0x001F_01FF)); // Full
        new.effective_mask = AccessMask(MASK_READ);

        let delta = diff_permission_lists(vec![old], vec![new]);
        assert_eq!(
            delta.len(),
            1,
            "NTFS/share swap with same effective mask must be detected — closes Finding 3"
        );
        let DeltaKind::Changed { reasons, .. } = &delta[0].kind else {
            panic!("expected Changed");
        };
        assert!(reasons.contains(&DeltaReason::NtfsMaskChanged));
        assert!(reasons.contains(&DeltaReason::ShareMaskChanged));
        assert!(
            !reasons.contains(&DeltaReason::EffectiveMaskChanged),
            "effective mask did not change in this scenario"
        );
    }

    /// Code review 2026-06-07 finding 3: `share_status` flips from
    /// Code review 2026-06-07 finding 3: `share_status` flips from
    /// `Applied` to `ReadFailed`. The engine then keeps
    /// `Effective = NTFS` and sets a diagnostic/incompleteness. If the
    /// mask happens to stay equal, the old delta reported nothing.
    #[test]
    fn share_status_change_with_same_mask_is_detected() {
        let mut old = mk_perm(r"C:\share\folder", MASK_READ);
        old.share_status = ShareEvalStatus::Applied;
        let mut new = mk_perm(r"C:\share\folder", MASK_READ);
        new.share_status = ShareEvalStatus::ReadFailed("Access denied (5)".to_string());

        let delta = diff_permission_lists(vec![old], vec![new]);
        assert_eq!(
            delta.len(),
            1,
            "share status change must be detected even with identical mask — closes Finding 3"
        );
        let DeltaKind::Changed { reasons, .. } = &delta[0].kind else {
            panic!("expected Changed");
        };
        assert!(reasons.contains(&DeltaReason::ShareStatusChanged));
    }

    /// Code Review 2026-06-07 Finding 3: neue `PermissionDiagnostic`
    /// Code review 2026-06-07 finding 3: a new `PermissionDiagnostic`
    /// (e.g. `NonCanonicalDaclOrder`) must be reported as Changed even
    /// when the final mask stays equal — such markers are audit events
    /// that must not silently vanish.
    #[test]
    fn new_diagnostic_with_same_mask_is_detected() {
        let old = mk_perm(r"C:\share\folder", MASK_READ);
        let mut new = mk_perm(r"C:\share\folder", MASK_READ);
        new.diagnostics = vec![PermissionDiagnostic::NonCanonicalDaclOrder { at_index: 2 }];

        let delta = diff_permission_lists(vec![old], vec![new]);
        assert_eq!(
            delta.len(),
            1,
            "new diagnostic must be detected — closes Finding 3"
        );
        let DeltaKind::Changed { reasons, .. } = &delta[0].kind else {
            panic!("expected Changed");
        };
        assert!(reasons.contains(&DeltaReason::DiagnosticsChanged));
    }

    /// Code review 2026-06-07 finding 3: `local_group_status` flips
    /// from `Applied` to `NotAvailable` — relevant for audit because it
    /// concerns a completeness claim.
    #[test]
    fn local_group_status_change_with_same_mask_is_detected() {
        let mut old = mk_perm(r"C:\share\folder", MASK_READ);
        old.local_group_status = LocalGroupEvalStatus::Applied;
        let mut new = mk_perm(r"C:\share\folder", MASK_READ);
        new.local_group_status = LocalGroupEvalStatus::NotAvailable("RPC error".to_string());

        let delta = diff_permission_lists(vec![old], vec![new]);
        assert_eq!(delta.len(), 1);
        let DeltaKind::Changed { reasons, .. } = &delta[0].kind else {
            panic!("expected Changed");
        };
        assert!(reasons.contains(&DeltaReason::LocalGroupStatusChanged));
    }

    /// Code Review 2026-06-07 Finding 3: `unsupported_ace_count`
    /// Code review 2026-06-07 finding 3: `unsupported_ace_count`
    /// flips — signals new/disappeared exotic ACEs.
    #[test]
    fn unsupported_ace_count_change_is_detected() {
        let old = mk_perm(r"C:\share\folder", MASK_READ);
        let mut new = mk_perm(r"C:\share\folder", MASK_READ);
        new.unsupported_ace_count = 1;

        let delta = diff_permission_lists(vec![old], vec![new]);
        assert_eq!(delta.len(), 1);
        let DeltaKind::Changed { reasons, .. } = &delta[0].kind else {
            panic!("expected Changed");
        };
        assert!(reasons.contains(&DeltaReason::UnsupportedAceCountChanged));
    }
}
