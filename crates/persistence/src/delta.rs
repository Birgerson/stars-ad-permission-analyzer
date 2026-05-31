//! Delta-Vergleich zwischen zwei Scan-Läufen.
//! Delta comparison between two scan runs.

use adpa_core::{
    error::CoreError,
    model::{AccessMask, EffectivePermission, NormalizedPath},
};
use rusqlite::Connection;
use uuid::Uuid;

use crate::scan_store::load_permissions_for_run;

/// Art der Änderung zwischen zwei Scans.
/// Type of change between two scans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaKind {
    /// Pfad neu — war im alten Scan nicht vorhanden.
    /// Path is new — was not present in the old scan.
    Added,
    /// Pfad entfernt — ist im neuen Scan nicht mehr vorhanden.
    /// Path removed — no longer present in the new scan.
    Removed,
    /// Berechtigung hat sich geändert.
    /// Permission changed.
    Changed {
        old_mask: AccessMask,
        new_mask: AccessMask,
    },
}

/// Eine einzelne Änderungszeile im Delta-Bericht.
/// A single change row in the delta report.
#[derive(Debug, Clone)]
pub struct DeltaEntry {
    pub path: NormalizedPath,
    pub kind: DeltaKind,
    pub old_perm: Option<EffectivePermission>,
    pub new_perm: Option<EffectivePermission>,
}

/// Vergleicht zwei Scan-Läufe und gibt alle Änderungen zurück.
/// Compares two scan runs and returns all changes.
pub fn compare_scans(
    conn: &Connection,
    old_run_id: &Uuid,
    new_run_id: &Uuid,
) -> Result<Vec<DeltaEntry>, CoreError> {
    let old_perms = load_permissions_for_run(conn, old_run_id)?;
    let new_perms = load_permissions_for_run(conn, new_run_id)?;

    let old_map: std::collections::HashMap<String, EffectivePermission> = old_perms
        .into_iter()
        .map(|p| (p.path.0.clone(), p))
        .collect();

    let new_map: std::collections::HashMap<String, EffectivePermission> = new_perms
        .into_iter()
        .map(|p| (p.path.0.clone(), p))
        .collect();

    let mut entries: Vec<DeltaEntry> = Vec::new();

    // Added and Changed
    for (path, new_p) in &new_map {
        match old_map.get(path) {
            None => entries.push(DeltaEntry {
                path: NormalizedPath(path.clone()),
                kind: DeltaKind::Added,
                old_perm: None,
                new_perm: Some(new_p.clone()),
            }),
            Some(old_p) if old_p.effective_mask.0 != new_p.effective_mask.0 => {
                entries.push(DeltaEntry {
                    path: NormalizedPath(path.clone()),
                    kind: DeltaKind::Changed {
                        old_mask: old_p.effective_mask,
                        new_mask: new_p.effective_mask,
                    },
                    old_perm: Some(old_p.clone()),
                    new_perm: Some(new_p.clone()),
                });
            }
            _ => {}
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
    Ok(entries)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use adpa_core::model::{AccessMask, Identity, IdentityKind, PermissionPath, Sid};
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

    fn compare_vecs(
        old: Vec<EffectivePermission>,
        new: Vec<EffectivePermission>,
    ) -> Vec<DeltaEntry> {
        let old_map: std::collections::HashMap<String, EffectivePermission> =
            old.into_iter().map(|p| (p.path.0.clone(), p)).collect();
        let new_map: std::collections::HashMap<String, EffectivePermission> =
            new.into_iter().map(|p| (p.path.0.clone(), p)).collect();

        let mut entries = Vec::new();
        for (path, new_p) in &new_map {
            match old_map.get(path) {
                None => entries.push(DeltaEntry {
                    path: NormalizedPath(path.clone()),
                    kind: DeltaKind::Added,
                    old_perm: None,
                    new_perm: Some(new_p.clone()),
                }),
                Some(old_p) if old_p.effective_mask.0 != new_p.effective_mask.0 => {
                    entries.push(DeltaEntry {
                        path: NormalizedPath(path.clone()),
                        kind: DeltaKind::Changed {
                            old_mask: old_p.effective_mask,
                            new_mask: new_p.effective_mask,
                        },
                        old_perm: Some(old_p.clone()),
                        new_perm: Some(new_p.clone()),
                    });
                }
                _ => {}
            }
        }
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

    #[test]
    fn added_path_detected() {
        let old = vec![mk_perm(r"C:\data", MASK_READ)];
        let new = vec![
            mk_perm(r"C:\data", MASK_READ),
            mk_perm(r"C:\data\new", MASK_READ),
        ];
        let delta = compare_vecs(old, new);
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
        let delta = compare_vecs(old, new);
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].kind, DeltaKind::Removed);
    }

    #[test]
    fn changed_permission_detected() {
        let old = vec![mk_perm(r"C:\data", MASK_READ)];
        let new = vec![mk_perm(r"C:\data", MASK_MODIFY)];
        let delta = compare_vecs(old, new);
        assert_eq!(delta.len(), 1);
        assert!(matches!(delta[0].kind, DeltaKind::Changed { .. }));
        if let DeltaKind::Changed { old_mask, new_mask } = delta[0].kind {
            assert_eq!(old_mask.0, MASK_READ);
            assert_eq!(new_mask.0, MASK_MODIFY);
        }
    }

    #[test]
    fn unchanged_path_not_in_delta() {
        let old = vec![mk_perm(r"C:\data", MASK_READ)];
        let new = vec![mk_perm(r"C:\data", MASK_READ)];
        assert!(compare_vecs(old, new).is_empty());
    }
}
