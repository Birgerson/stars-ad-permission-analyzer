// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Delta comparison between two scan runs.

use adpa_core::{
    error::CoreError,
    model::{
        AccessMask, EffectivePermission, LocalGroupEvalStatus, NormalizedPath,
        PermissionDiagnostic, RunScope, ShareEvalStatus, SCAN_CANCELLED_MESSAGE,
    },
};
use rusqlite::Connection;
use uuid::Uuid;

use crate::scan_store::load_permissions_for_run;

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
    /// Review CR-9: whether the effective right is determinable (ADR 0065).
    /// Derived from the statuses and markers above, compared on its own so
    /// a flip between "exact" and "not determinable" is named as such.
    pub effective_determinable: bool,
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
            effective_determinable: p.effective_determinable(),
        }
    }
}

/// Concrete reason for a change between two permissions. Multiple
/// reasons can co-occur — e.g. an NTFS mask shift that does not flip
/// the effective mask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaReason {
    EffectiveMaskChanged,
    /// The effective right turned exact or not determinable (review CR-9).
    DeterminabilityChanged,
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
            DeltaReason::DeterminabilityChanged => "determinability",
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
    if old.effective_determinable != new.effective_determinable {
        reasons.push(DeltaReason::DeterminabilityChanged);
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
    /// Review CR-19: the path is in one run only, and the other run did not
    /// cover it — it was cancelled, or could not read or enumerate the path
    /// or one of its parents. Neither added nor removed can be claimed.
    /// `in_old`: the path is in the old run (it would have read "Removed").
    NotObserved { in_old: bool, reason: String },
}

/// Review CR-19: the result of a comparison — the entries and the notes a
/// reader needs to judge them.
#[derive(Debug, Clone, Default)]
pub struct DeltaReport {
    pub entries: Vec<DeltaEntry>,
    pub notes: Vec<String>,
}

/// Review CR-19: what one stored run covered, as far as it was recorded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunCoverage {
    /// `None` for a run stored before schema v9.
    pub scope: Option<RunScope>,
    /// The depth limit (`None` = unlimited when `scope` is known).
    pub max_depth: Option<u32>,
    pub cancelled: bool,
    /// The paths the run could not read or did not enumerate.
    pub error_paths: Vec<String>,
}

impl RunCoverage {
    /// Why this run cannot say whether `path` exists — `None` when it
    /// covered the path. Pure.
    fn unobserved_reason(&self, path: &str) -> Option<String> {
        if self.cancelled {
            return Some("the run was cancelled before it finished".to_owned());
        }
        self.error_paths
            .iter()
            .find(|e| path_is_at_or_below(path, e))
            .map(|e| format!("the run could not read or enumerate {e}"))
    }
}

/// `path` is `parent` or lies below it (ASCII case ignored, at a component
/// boundary). Pure.
fn path_is_at_or_below(path: &str, parent: &str) -> bool {
    let parent = parent.trim_end_matches('\\');
    match path.get(..parent.len()) {
        Some(head) if head.eq_ignore_ascii_case(parent) => {
            path.len() == parent.len() || path[parent.len()..].starts_with('\\')
        }
        _ => false,
    }
}

/// Review CR-19: refuses runs that did not look at the same tree — a scan
/// and a single-path analysis, or two depth limits. Runs stored before v9
/// have no recorded scope; they are compared, with a note. Pure.
pub fn check_comparable(old: &RunCoverage, new: &RunCoverage) -> Result<Vec<String>, CoreError> {
    let describe = |c: &RunCoverage| match (c.scope, c.max_depth) {
        (Some(RunScope::Analyze), _) => "a single-path analysis".to_owned(),
        (Some(RunScope::Scan), None) => "a scan without a depth limit".to_owned(),
        (Some(RunScope::Scan), Some(d)) => format!("a scan to depth {d}"),
        (None, _) => "a run of unknown scope".to_owned(),
    };
    match (old.scope, new.scope) {
        (Some(a), Some(b)) if a != b || old.max_depth != new.max_depth => {
            Err(CoreError::Validation(format!(
                "scan runs are not comparable: the old run is {}, the new run {} — paths one \
                 of them never looked at would read as added or removed",
                describe(old),
                describe(new)
            )))
        }
        (Some(_), Some(_)) => Ok(Vec::new()),
        _ => Ok(vec![
            "One of the runs was stored before Stars recorded what a run covers (scope and \
             depth limit). Additions and removals assume both runs covered the same tree."
                .to_owned(),
        ]),
    }
}

/// Review CR-19: an addition or removal the other run could not have seen
/// becomes `NotObserved`. Pure.
pub fn apply_coverage(
    entries: Vec<DeltaEntry>,
    old: &RunCoverage,
    new: &RunCoverage,
) -> Vec<DeltaEntry> {
    entries
        .into_iter()
        .map(|mut e| {
            let unobserved = match e.kind {
                DeltaKind::Removed => new
                    .unobserved_reason(&e.path.0)
                    .map(|r| (true, format!("not in the new run, but {r}"))),
                DeltaKind::Added => old
                    .unobserved_reason(&e.path.0)
                    .map(|r| (false, format!("not in the old run, but {r}"))),
                _ => None,
            };
            if let Some((in_old, reason)) = unobserved {
                e.kind = DeltaKind::NotObserved { in_old, reason };
            }
            e
        })
        .collect()
}

/// A single change row in the delta report.
#[derive(Debug, Clone)]
pub struct DeltaEntry {
    pub path: NormalizedPath,
    pub kind: DeltaKind,
    pub old_perm: Option<EffectivePermission>,
    pub new_perm: Option<EffectivePermission>,
}

/// Fetches the stored target of a scan run. A nonexistent run id is a
/// `Validation` error — before this guard, comparing against an unknown id
/// silently read as "everything was removed"
/// (persistence review 2026-07-26, PS-4).
fn run_target(conn: &Connection, run_id: &Uuid) -> Result<String, CoreError> {
    conn.query_row(
        "SELECT target FROM scan_runs WHERE id = ?1",
        [run_id.to_string()],
        |row| row.get(0),
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => {
            CoreError::Validation(format!("unknown scan run id '{run_id}'"))
        }
        other => CoreError::Database(format!("reading scan run '{run_id}': {other}")),
    })
}

/// Review CR-19: what a stored run covered — scope and depth limit (schema
/// v9), cancellation and the paths it left out (its stored errors).
fn run_coverage(conn: &Connection, run_id: &Uuid) -> Result<RunCoverage, CoreError> {
    let (scope, max_depth): (Option<String>, Option<i64>) = conn
        .query_row(
            "SELECT scope, max_depth FROM scan_runs WHERE id = ?1",
            [run_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|e| CoreError::Database(format!("reading scan run '{run_id}': {e}")))?;
    // Validated like any stored value: an unknown scope or an impossible
    // depth is a damaged record, not a guess.
    let scope = match scope.as_deref() {
        None => None,
        Some(s) => Some(RunScope::parse(s).ok_or_else(|| {
            CoreError::Database(format!("scan run '{run_id}' has the unknown scope '{s}'"))
        })?),
    };
    let max_depth = match max_depth {
        None => None,
        Some(d) => Some(u32::try_from(d).map_err(|_| {
            CoreError::Database(format!("scan run '{run_id}' has the depth limit {d}"))
        })?),
    };
    let errors = crate::scan_store::ScanStore::new(conn).list_errors_for(run_id)?;
    Ok(RunCoverage {
        scope,
        max_depth,
        cancelled: errors
            .iter()
            .any(|e| e.path.is_none() && e.message == SCAN_CANCELLED_MESSAGE),
        error_paths: errors
            .into_iter()
            .filter_map(|e| e.path.map(|p| p.0))
            .collect(),
    })
}

/// Compares two scan runs and returns all changes.
///
/// Persistence review 2026-07-26, PS-4: refuses semantically incomparable
/// runs. Two runs with different targets produce a plausible-looking but
/// meaningless report ("everything changed"), so the mismatch is a
/// `Validation` error naming both targets instead of a silent nonsense
/// delta.
///
/// Review CR-19: also refuses a scan against a single-path analysis and two
/// depth limits, and reports a path that only one run has as `NotObserved`
/// when the other run did not cover it (cancelled, or a parent it could not
/// read or enumerate).
pub fn compare_scans(
    conn: &Connection,
    old_run_id: &Uuid,
    new_run_id: &Uuid,
) -> Result<DeltaReport, CoreError> {
    let old_target = run_target(conn, old_run_id)?;
    let new_target = run_target(conn, new_run_id)?;
    if old_target != new_target {
        return Err(CoreError::Validation(format!(
            "scan runs are not comparable: the old run scanned '{old_target}', \
             the new run scanned '{new_target}'"
        )));
    }
    let old_coverage = run_coverage(conn, old_run_id)?;
    let new_coverage = run_coverage(conn, new_run_id)?;
    let notes = check_comparable(&old_coverage, &new_coverage)?;

    let old_perms = load_permissions_for_run(conn, old_run_id)?;
    let new_perms = load_permissions_for_run(conn, new_run_id)?;

    let entries = apply_coverage(
        diff_permission_lists(old_perms, new_perms),
        &old_coverage,
        &new_coverage,
    );
    Ok(DeltaReport { entries, notes })
}

/// Pure diff logic on two permission lists — for tests without a DB.
///
/// Keyed by **(identity SID, path)**, not by path alone: with path-only
/// keys, two rows for different identities on the same path would silently
/// collapse to whichever the map kept last (persistence review 2026-07-26,
/// PS-4). Runs are single-identity today, so the key change is free — and
/// correct the day multi-identity runs land.
pub fn diff_permission_lists(
    old: Vec<EffectivePermission>,
    new: Vec<EffectivePermission>,
) -> Vec<DeltaEntry> {
    type Key = (String, String);
    let key_of = |p: &EffectivePermission| (p.identity.sid.0.clone(), p.path.0.clone());
    let old_map: std::collections::HashMap<Key, EffectivePermission> =
        old.into_iter().map(|p| (key_of(&p), p)).collect();
    let new_map: std::collections::HashMap<Key, EffectivePermission> =
        new.into_iter().map(|p| (key_of(&p), p)).collect();

    let mut entries: Vec<DeltaEntry> = Vec::new();

    // Added + Changed via signature diff (finding 3).
    for (key, new_p) in &new_map {
        match old_map.get(key) {
            None => entries.push(DeltaEntry {
                path: NormalizedPath(key.1.clone()),
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
                        path: NormalizedPath(key.1.clone()),
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
    for (key, old_p) in &old_map {
        if !new_map.contains_key(key) {
            entries.push(DeltaEntry {
                path: NormalizedPath(key.1.clone()),
                kind: DeltaKind::Removed,
                old_perm: Some(old_p.clone()),
                new_perm: None,
            });
        }
    }

    // Deterministic order: path first, then the identity SID for the rare
    // case of two identities on the same path.
    entries.sort_by(|a, b| {
        a.path
            .0
            .cmp(&b.path.0)
            .then_with(|| entry_sid(a).cmp(entry_sid(b)))
    });
    entries
}

/// SID of the permission a delta entry is about (from whichever side is
/// present) — only used for deterministic ordering.
fn entry_sid(e: &DeltaEntry) -> &str {
    e.new_perm
        .as_ref()
        .or(e.old_perm.as_ref())
        .map(|p| p.identity.sid.0.as_str())
        .unwrap_or("")
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
                sid_history: Vec::new(),
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
            trace: Default::default(),
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

    // --- PS-4 (persistence review 2026-07-26): comparability guards ---

    fn mk_perm_sid(sid: &str, path: &str, mask: u32) -> EffectivePermission {
        let mut p = mk_perm(path, mask);
        p.identity.sid = Sid(sid.into());
        p
    }

    /// PS-4: two identities on the same path must be diffed independently —
    /// with the old path-only key, one of the two rows silently vanished
    /// (HashMap last-wins).
    #[test]
    fn two_identities_on_same_path_are_diffed_independently() {
        let old = vec![
            mk_perm_sid("S-1-5-21-1", r"C:\data", MASK_READ),
            mk_perm_sid("S-1-5-21-2", r"C:\data", MASK_READ),
        ];
        let new = vec![
            mk_perm_sid("S-1-5-21-1", r"C:\data", MASK_MODIFY), // changed
            mk_perm_sid("S-1-5-21-2", r"C:\data", MASK_READ),   // unchanged
        ];
        let delta = diff_permission_lists(old, new);
        assert_eq!(
            delta.len(),
            1,
            "exactly the changed identity must be reported, the unchanged one not"
        );
        assert!(matches!(delta[0].kind, DeltaKind::Changed { .. }));
        assert_eq!(
            delta[0].new_perm.as_ref().unwrap().identity.sid.0,
            "S-1-5-21-1"
        );
    }

    /// PS-4: the same path held by different identities in old vs. new run
    /// is Removed + Added — not a fake "Changed" between two different
    /// principals.
    #[test]
    fn identity_swap_on_same_path_is_removed_plus_added() {
        let old = vec![mk_perm_sid("S-1-5-21-1", r"C:\data", MASK_READ)];
        let new = vec![mk_perm_sid("S-1-5-21-2", r"C:\data", MASK_READ)];
        let delta = diff_permission_lists(old, new);
        assert_eq!(delta.len(), 2);
        assert!(delta.iter().any(|e| e.kind == DeltaKind::Removed));
        assert!(delta.iter().any(|e| e.kind == DeltaKind::Added));
    }

    /// PS-4: comparing runs with different targets is refused with a
    /// Validation error naming both targets.
    #[test]
    fn compare_scans_refuses_different_targets() {
        use crate::scan_store::ScanStore;
        use adpa_core::model::ScanRun;
        use chrono::Utc;
        use uuid::Uuid;

        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::migrations::run_migrations(&conn).unwrap();
        let store = ScanStore::new(&conn);
        let run_a = ScanRun {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            target: r"C:\alpha".into(),
            errors: vec![],
            scope: Some(RunScope::Scan),
            max_depth: None,
        };
        let run_b = ScanRun {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            target: r"C:\beta".into(),
            errors: vec![],
            scope: Some(RunScope::Scan),
            max_depth: None,
        };
        store.insert_scan_run(&run_a).unwrap();
        store.insert_scan_run(&run_b).unwrap();

        let result = compare_scans(&conn, &run_a.id, &run_b.id);
        let err = result.expect_err("different targets must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains(r"C:\alpha") && msg.contains(r"C:\beta"),
            "error must name both targets; got: {msg}"
        );
    }

    fn cov(scope: Option<RunScope>, depth: Option<u32>) -> RunCoverage {
        RunCoverage {
            scope,
            max_depth: depth,
            ..Default::default()
        }
    }

    /// Review CR-19: a scan and an analysis, or two depth limits, are not
    /// comparable; runs stored before v9 are compared with a note.
    #[test]
    fn runs_of_another_scope_or_depth_are_refused() {
        let scan = cov(Some(RunScope::Scan), None);
        let shallow = cov(Some(RunScope::Scan), Some(2));
        let analysis = cov(Some(RunScope::Analyze), None);
        assert!(check_comparable(&scan, &scan).unwrap().is_empty());
        let err = check_comparable(&scan, &shallow).unwrap_err().to_string();
        assert!(
            err.contains("a scan without a depth limit") && err.contains("a scan to depth 2"),
            "{err}"
        );
        let err = check_comparable(&analysis, &scan).unwrap_err().to_string();
        assert!(err.contains("a single-path analysis"), "{err}");
        let legacy = cov(None, None);
        let notes = check_comparable(&legacy, &scan).unwrap();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("before Stars recorded"), "{notes:?}");
    }

    /// Review CR-19: a full run followed by an interrupted run, or by one
    /// that could not read a folder, does not report the unobserved paths
    /// as removed — nor, the other way, as added.
    #[test]
    fn paths_the_other_run_did_not_cover_are_not_observed() {
        let full = vec![
            mk_perm(r"C:\data\a", MASK_READ),
            mk_perm(r"C:\data\locked\x", MASK_READ),
            mk_perm(r"C:\data\lockedtwin\y", MASK_READ),
        ];
        let partial = vec![mk_perm(r"C:\data\a", MASK_READ)];
        let scan = cov(Some(RunScope::Scan), None);

        // The new run could not read C:\data\locked.
        let blocked = RunCoverage {
            error_paths: vec![r"C:\data\Locked".into()],
            ..scan.clone()
        };
        let entries = apply_coverage(
            diff_permission_lists(full.clone(), partial.clone()),
            &scan,
            &blocked,
        );
        let kind_of = |p: &str| {
            entries
                .iter()
                .find(|e| e.path.0 == p)
                .map(|e| e.kind.clone())
        };
        assert!(
            matches!(kind_of(r"C:\data\locked\x"), Some(DeltaKind::NotObserved { in_old: true, reason }) if reason.contains(r"C:\data\Locked"))
        );
        assert_eq!(
            kind_of(r"C:\data\lockedtwin\y"),
            Some(DeltaKind::Removed),
            "a sibling with a longer name is not below the error path"
        );

        // The new run was cancelled: nothing it lacks was removed.
        let cancelled = RunCoverage {
            cancelled: true,
            ..scan.clone()
        };
        let entries = apply_coverage(
            diff_permission_lists(full.clone(), partial.clone()),
            &scan,
            &cancelled,
        );
        assert!(
            entries
                .iter()
                .all(|e| matches!(e.kind, DeltaKind::NotObserved { in_old: true, .. })),
            "{entries:#?}"
        );

        // The other way: the old run was cancelled, the new one complete.
        let entries = apply_coverage(diff_permission_lists(partial, full), &cancelled, &scan);
        assert!(
            entries
                .iter()
                .all(|e| matches!(e.kind, DeltaKind::NotObserved { in_old: false, .. })),
            "{entries:#?}"
        );
        assert!(path_is_at_or_below(r"C:\data\locked", r"C:\data\locked\"));
    }

    /// Review CR-19 through the database: the stored cancel marker and the
    /// stored error paths decide, and a v9 run records its scope.
    #[test]
    fn compare_scans_reads_scope_cancellation_and_errors_from_the_database() {
        use crate::scan_store::ScanStore;
        use adpa_core::model::{ScanError, ScanRun};
        use chrono::Utc;
        use uuid::Uuid;
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::migrations::run_migrations(&conn).unwrap();
        let store = ScanStore::new(&conn);
        let run = |depth: Option<u32>| ScanRun {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            target: r"C:\data".into(),
            errors: vec![],
            scope: Some(RunScope::Scan),
            max_depth: depth,
        };
        let (old, new, other_depth) = (run(None), run(None), run(Some(1)));
        store
            .persist_scan_atomic(
                &old,
                &[
                    mk_perm(r"C:\data\a", MASK_READ),
                    mk_perm(r"C:\data\b", MASK_READ),
                ],
                &[],
            )
            .unwrap();
        store
            .persist_scan_atomic(
                &new,
                &[mk_perm(r"C:\data\a", MASK_READ)],
                &[ScanError {
                    path: None,
                    message: SCAN_CANCELLED_MESSAGE.to_owned(),
                }],
            )
            .unwrap();
        store.persist_scan_atomic(&other_depth, &[], &[]).unwrap();
        let report = compare_scans(&conn, &old.id, &new.id).unwrap();
        assert!(report.notes.is_empty());
        assert!(
            matches!(
                &report.entries[..],
                [DeltaEntry {
                    kind: DeltaKind::NotObserved { in_old: true, .. },
                    ..
                }]
            ),
            "{:#?}",
            report.entries
        );
        let err = compare_scans(&conn, &old.id, &other_depth.id).unwrap_err();
        assert!(err.to_string().contains("a scan to depth 1"), "{err}");
    }

    /// PS-4: an unknown run id is a Validation error — before the guard it
    /// silently read as an empty permission list ("everything removed").
    #[test]
    fn compare_scans_refuses_unknown_run_id() {
        use uuid::Uuid;
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::migrations::run_migrations(&conn).unwrap();
        let result = compare_scans(&conn, &Uuid::new_v4(), &Uuid::new_v4());
        let err = result.expect_err("unknown run id must be refused");
        assert!(
            format!("{err}").contains("unknown scan run id"),
            "error must say the run id is unknown; got: {err}"
        );
    }

    /// Review CR-9: a flip between "not determinable" and "exact" is named
    /// as its own reason; an informational marker is not such a flip.
    #[test]
    fn determinability_flip_is_a_named_reason() {
        let mut old = mk_perm(r"C:\shareolder", MASK_READ);
        old.diagnostics = vec![PermissionDiagnostic::GroupResolutionIncomplete {
            reason: "gap".into(),
        }];
        let new = mk_perm(r"C:\shareolder", MASK_READ);
        assert!(!old.effective_determinable() && new.effective_determinable());
        let delta = diff_permission_lists(vec![old], vec![new]);
        let DeltaKind::Changed { reasons, .. } = &delta[0].kind else {
            panic!("expected Changed, got {:?}", delta[0].kind);
        };
        assert_eq!(
            reasons,
            &vec![
                DeltaReason::DeterminabilityChanged,
                DeltaReason::DiagnosticsChanged
            ]
        );

        let old = mk_perm(r"C:\shareolder", MASK_READ);
        let mut new = mk_perm(r"C:\shareolder", MASK_READ);
        new.diagnostics = vec![PermissionDiagnostic::NonCanonicalDaclOrder { at_index: 2 }];
        let delta = diff_permission_lists(vec![old], vec![new]);
        let DeltaKind::Changed { reasons, .. } = &delta[0].kind else {
            panic!("expected Changed, got {:?}", delta[0].kind);
        };
        assert_eq!(reasons, &vec![DeltaReason::DiagnosticsChanged]);
    }
}
