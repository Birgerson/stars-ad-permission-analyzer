//! Speicherung und Abfrage von Scan-Läufen, Berechtigungen und Scan-Fehlern.
//! Storage and retrieval of scan runs, permissions, and scan errors.

use adpa_core::{
    error::CoreError,
    model::{
        AccessMask, AceEntry, ContributingAce, EffectivePermission, Identity, IdentityKind,
        NormalizedPath, PermissionPath, ScanError, ScanRun, ShareEvalStatus, Sid,
    },
};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use uuid::Uuid;

pub struct ScanStore<'a> {
    conn: &'a Connection,
}

impl<'a> ScanStore<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Speichert einen neuen Scan-Lauf.
    /// Stores a new scan run.
    pub fn insert_scan_run(&self, run: &ScanRun) -> Result<(), CoreError> {
        self.conn
            .execute(
                "INSERT INTO scan_runs (id, started_at, finished_at, target)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    run.id.to_string(),
                    run.started_at.to_rfc3339(),
                    run.finished_at.as_ref().map(|dt| dt.to_rfc3339()),
                    run.target,
                ],
            )
            .map_err(|e| CoreError::Database(format!("insert_scan_run failed: {e}")))?;
        Ok(())
    }

    /// Setzt den Endzeitstempel eines Scan-Laufs.
    /// Sets the finish timestamp of a scan run.
    pub fn finish_scan_run(&self, id: &Uuid, finished_at: DateTime<Utc>) -> Result<(), CoreError> {
        self.conn
            .execute(
                "UPDATE scan_runs SET finished_at = ?1 WHERE id = ?2",
                params![finished_at.to_rfc3339(), id.to_string()],
            )
            .map_err(|e| CoreError::Database(format!("finish_scan_run failed: {e}")))?;
        Ok(())
    }

    /// Speichert eine effektive Berechtigung und upserted die zugehörige Identität.
    /// Stores an effective permission and upserts the associated identity.
    pub fn insert_permission(
        &self,
        scan_run_id: &Uuid,
        perm: &EffectivePermission,
    ) -> Result<(), CoreError> {
        // Identität mitpersistieren / also persist the identity
        self.conn
            .execute(
                "INSERT INTO identities (sid, name, domain, kind, disabled)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(sid) DO UPDATE SET
                     name     = excluded.name,
                     domain   = excluded.domain,
                     kind     = excluded.kind,
                     disabled = excluded.disabled",
                params![
                    perm.identity.sid.0,
                    perm.identity.name,
                    perm.identity.domain,
                    kind_to_str(&perm.identity.kind),
                    perm.identity.disabled as i32,
                ],
            )
            .map_err(|e| {
                CoreError::Database(format!("identity upsert in insert_permission: {e}"))
            })?;

        let explanation =
            serde_json::to_string(&perm.path_explanation.steps).unwrap_or_else(|_| "[]".into());
        let contributing =
            serde_json::to_string(&perm.contributing_sids).unwrap_or_else(|_| "[]".into());
        let matched_aces =
            serde_json::to_string(&perm.matched_aces).unwrap_or_else(|_| "[]".into());
        let diagnostics = serde_json::to_string(&perm.diagnostics).unwrap_or_else(|_| "[]".into());

        // ShareEvalStatus in Status-Text + optionalen Fehlertext zerlegen.
        // Decompose ShareEvalStatus into a status string + optional error text.
        let (share_status, share_error): (&str, Option<&str>) = match &perm.share_status {
            ShareEvalStatus::NotApplicable => ("NotApplicable", None),
            ShareEvalStatus::Applied => ("Applied", None),
            ShareEvalStatus::Unrestricted => ("Unrestricted", None),
            ShareEvalStatus::ReadFailed(msg) => ("ReadFailed", Some(msg.as_str())),
        };

        // Analog für LocalGroupEvalStatus.
        // Same for LocalGroupEvalStatus.
        let (local_group_status, local_group_error): (&str, Option<&str>) =
            match &perm.local_group_status {
                adpa_core::model::LocalGroupEvalStatus::NotQueried => ("NotQueried", None),
                adpa_core::model::LocalGroupEvalStatus::Applied => ("Applied", None),
                adpa_core::model::LocalGroupEvalStatus::NotAvailable(msg) => {
                    ("NotAvailable", Some(msg.as_str()))
                }
            };

        self.conn
            .execute(
                "INSERT INTO effective_permissions
                     (scan_run_id, sid, path, ntfs_mask, share_mask, effective_mask,
                      explanation, share_status, share_error, contributing_sids,
                      unsupported_ace_count, matched_aces,
                      local_group_status, local_group_error, diagnostics)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    scan_run_id.to_string(),
                    perm.identity.sid.0,
                    perm.path.0,
                    perm.ntfs_mask.0 as i64,
                    perm.share_mask.map(|m| m.0 as i64),
                    perm.effective_mask.0 as i64,
                    explanation,
                    share_status,
                    share_error,
                    contributing,
                    perm.unsupported_ace_count as i64,
                    matched_aces,
                    local_group_status,
                    local_group_error,
                    diagnostics,
                ],
            )
            .map_err(|e| CoreError::Database(format!("insert_permission failed: {e}")))?;
        Ok(())
    }

    /// Speichert einen Scan-Fehler.
    /// Stores a scan error.
    pub fn insert_error(&self, scan_run_id: &Uuid, error: &ScanError) -> Result<(), CoreError> {
        self.conn
            .execute(
                "INSERT INTO scan_errors (scan_run_id, path, message)
                 VALUES (?1, ?2, ?3)",
                params![
                    scan_run_id.to_string(),
                    error.path.as_ref().map(|p| p.0.as_str()),
                    error.message,
                ],
            )
            .map_err(|e| CoreError::Database(format!("insert_error failed: {e}")))?;
        Ok(())
    }

    /// Liest alle gespeicherten Scan-Fehler für einen Lauf in der ursprünglichen
    /// Einfüge-Reihenfolge (per rowid).
    /// Returns all stored scan errors for a run in insertion order (by rowid).
    pub fn list_errors_for(&self, scan_run_id: &Uuid) -> Result<Vec<ScanError>, CoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT path, message
                 FROM scan_errors
                 WHERE scan_run_id = ?1
                 ORDER BY rowid",
            )
            .map_err(|e| CoreError::Database(format!("prepare list_errors_for: {e}")))?;
        let rows = stmt
            .query_map(params![scan_run_id.to_string()], |row| {
                let path: Option<String> = row.get(0)?;
                let message: String = row.get(1)?;
                Ok(ScanError {
                    path: path.map(NormalizedPath),
                    message,
                })
            })
            .map_err(|e| CoreError::Database(format!("query list_errors_for: {e}")))?;
        let mut errors = Vec::new();
        for r in rows {
            errors.push(r.map_err(|e| CoreError::Database(format!("row list_errors_for: {e}")))?);
        }
        Ok(errors)
    }

    /// Gibt alle gespeicherten Scan-Läufe zurück (neueste zuerst).
    /// Returns all stored scan runs (newest first).
    pub fn list_scan_runs(&self) -> Result<Vec<ScanRun>, CoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, started_at, finished_at, target
                 FROM scan_runs
                 ORDER BY started_at DESC",
            )
            .map_err(|e| CoreError::Database(format!("prepare list_scan_runs: {e}")))?;

        let rows = stmt
            .query_map([], |row| {
                let id_str: String = row.get(0)?;
                let started_str: String = row.get(1)?;
                let finished_str: Option<String> = row.get(2)?;
                let target: String = row.get(3)?;
                Ok((id_str, started_str, finished_str, target))
            })
            .map_err(|e| CoreError::Database(format!("query list_scan_runs: {e}")))?;

        let mut result = Vec::new();
        for row in rows {
            let (id_str, started_str, finished_str, target) =
                row.map_err(|e| CoreError::Database(e.to_string()))?;
            let id = Uuid::parse_str(&id_str)
                .map_err(|e| CoreError::Database(format!("Invalid UUID in scan_runs: {e}")))?;
            let started_at = DateTime::parse_from_rfc3339(&started_str)
                .map_err(|e| CoreError::Database(format!("Invalid timestamp: {e}")))?
                .with_timezone(&Utc);
            let finished_at = finished_str
                .map(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .map(|dt| dt.with_timezone(&Utc))
                        .map_err(|e| CoreError::Database(format!("Invalid timestamp: {e}")))
                })
                .transpose()?;
            result.push(ScanRun {
                id,
                started_at,
                finished_at,
                target,
                errors: vec![],
            });
        }
        Ok(result)
    }

    /// Gibt alle gespeicherten Berechtigungen für einen Scan-Lauf zurück.
    /// Returns all stored permissions for a scan run.
    pub fn get_permissions(
        &self,
        scan_run_id: &Uuid,
    ) -> Result<Vec<EffectivePermission>, CoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT ep.sid, ep.path, ep.ntfs_mask, ep.share_mask,
                         ep.effective_mask, ep.explanation,
                         ep.share_status, ep.share_error, ep.contributing_sids,
                         ep.unsupported_ace_count, ep.matched_aces,
                         ep.local_group_status, ep.local_group_error,
                         ep.diagnostics,
                         i.name, i.domain, i.kind, i.disabled
                 FROM effective_permissions ep
                 LEFT JOIN identities i ON i.sid = ep.sid
                 WHERE ep.scan_run_id = ?1",
            )
            .map_err(|e| CoreError::Database(format!("prepare get_permissions: {e}")))?;

        let rows = stmt
            .query_map(params![scan_run_id.to_string()], |row| {
                let sid: String = row.get(0)?;
                let path: String = row.get(1)?;
                let ntfs: i64 = row.get(2)?;
                let share: Option<i64> = row.get(3)?;
                let eff: i64 = row.get(4)?;
                let expl: String = row.get(5)?;
                let share_status_str: String = row.get(6)?;
                let share_error: Option<String> = row.get(7)?;
                let contributing_json: String = row.get(8)?;
                let unsupported_ace_count: i64 = row.get(9)?;
                let matched_aces_json: String = row.get(10)?;
                let local_group_status_str: String = row.get(11)?;
                let local_group_error: Option<String> = row.get(12)?;
                let diagnostics_json: Option<String> = row.get(13)?;
                let name: Option<String> = row.get(14)?;
                let domain: Option<String> = row.get(15)?;
                let kind_str: Option<String> = row.get(16)?;
                let disabled: Option<i32> = row.get(17)?;

                let steps: Vec<String> = serde_json::from_str(&expl).unwrap_or_default();
                let contributing_sids: Vec<ContributingAce> =
                    serde_json::from_str(&contributing_json).unwrap_or_default();
                let matched_aces: Vec<AceEntry> =
                    serde_json::from_str(&matched_aces_json).unwrap_or_default();
                // diagnostics ist neu (Folge-Befund 3); ältere Zeilen ohne
                // Spaltenwert geben NULL → leere Liste.
                // diagnostics is new (follow-up finding 3); older rows
                // without a column value return NULL → empty list.
                let diagnostics: Vec<adpa_core::model::PermissionDiagnostic> = diagnostics_json
                    .as_deref()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or_default();
                let share_status = match share_status_str.as_str() {
                    "Applied" => ShareEvalStatus::Applied,
                    "Unrestricted" => ShareEvalStatus::Unrestricted,
                    "ReadFailed" => ShareEvalStatus::ReadFailed(share_error.unwrap_or_default()),
                    // Unbekannte/ältere Werte konservativ als NotApplicable behandeln.
                    // Treat unknown/legacy values conservatively as NotApplicable.
                    _ => ShareEvalStatus::NotApplicable,
                };
                let local_group_status = match local_group_status_str.as_str() {
                    "Applied" => adpa_core::model::LocalGroupEvalStatus::Applied,
                    "NotAvailable" => adpa_core::model::LocalGroupEvalStatus::NotAvailable(
                        local_group_error.unwrap_or_default(),
                    ),
                    _ => adpa_core::model::LocalGroupEvalStatus::NotQueried,
                };
                let kind = kind_str
                    .as_deref()
                    .map(kind_from_str)
                    .unwrap_or(IdentityKind::Unknown);

                Ok(EffectivePermission {
                    identity: Identity {
                        sid: Sid(sid),
                        name,
                        domain,
                        kind,
                        disabled: disabled.unwrap_or(0) != 0,
                        // UPN wird derzeit nicht persistiert; er ist nur für
                        // Live-AD-/NetAPI-Aufrufe relevant, nicht für historische Reports.
                        // UPN is not persisted today; it's only relevant for live AD/NetAPI
                        // calls, not for historical reports.
                        user_principal_name: None,
                    },
                    path: NormalizedPath(path),
                    ntfs_mask: AccessMask(ntfs as u32),
                    share_mask: share.map(|s| AccessMask(s as u32)),
                    effective_mask: AccessMask(eff as u32),
                    path_explanation: PermissionPath { steps },
                    share_status,
                    local_group_status,
                    contributing_sids,
                    unsupported_ace_count: unsupported_ace_count.max(0) as usize,
                    matched_aces,
                    diagnostics,
                })
            })
            .map_err(|e| CoreError::Database(format!("query get_permissions: {e}")))?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| CoreError::Database(e.to_string()))?);
        }
        Ok(result)
    }
}

/// Lädt alle Berechtigungen für einen Scan-Lauf (freie Funktion für delta-Modul).
/// Loads all permissions for a scan run (free function for the delta module).
pub fn load_permissions_for_run(
    conn: &Connection,
    scan_run_id: &Uuid,
) -> Result<Vec<EffectivePermission>, CoreError> {
    ScanStore::new(conn).get_permissions(scan_run_id)
}

fn kind_to_str(kind: &IdentityKind) -> &'static str {
    match kind {
        IdentityKind::User => "User",
        IdentityKind::Group => "Group",
        IdentityKind::Computer => "Computer",
        IdentityKind::WellKnown => "WellKnown",
        IdentityKind::Orphaned => "Orphaned",
        IdentityKind::Unknown => "Unknown",
    }
}

fn kind_from_str(s: &str) -> IdentityKind {
    match s {
        "User" => IdentityKind::User,
        "Group" => IdentityKind::Group,
        "Computer" => IdentityKind::Computer,
        "WellKnown" => IdentityKind::WellKnown,
        "Orphaned" => IdentityKind::Orphaned,
        _ => IdentityKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use adpa_core::model::{
        AccessMask, AceEntry, AceKind, ContributingAce, EffectivePermission, Identity,
        IdentityKind, NormalizedPath, PermissionPath, ScanError, ScanRun, ShareEvalStatus, Sid,
    };
    use chrono::Utc;
    use rusqlite::Connection;
    use uuid::Uuid;

    use super::ScanStore;
    use crate::migrations::run_migrations;

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        conn
    }

    fn make_run(target: &str) -> ScanRun {
        ScanRun {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            finished_at: None,
            target: target.to_owned(),
            errors: vec![],
        }
    }

    fn make_perm(
        sid: &str,
        path: &str,
        ntfs: u32,
        share: Option<u32>,
        eff: u32,
    ) -> EffectivePermission {
        EffectivePermission {
            identity: Identity {
                sid: Sid(sid.to_owned()),
                name: Some("TestUser".to_owned()),
                domain: Some("TESTDOMAIN".to_owned()),
                kind: IdentityKind::User,
                disabled: false,
                user_principal_name: None,
            },
            path: NormalizedPath(path.to_owned()),
            ntfs_mask: AccessMask(ntfs),
            share_mask: share.map(AccessMask),
            effective_mask: AccessMask(eff),
            path_explanation: PermissionPath {
                steps: vec!["Step A".to_owned(), "Step B".to_owned()],
            },
            share_status: adpa_core::model::ShareEvalStatus::NotApplicable,
            local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
            contributing_sids: vec![],
            unsupported_ace_count: 0,
            matched_aces: vec![],
            diagnostics: vec![],
        }
    }

    #[test]
    fn insert_and_list_scan_run() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run = make_run("C:\\Share");
        store.insert_scan_run(&run).unwrap();
        let runs = store.list_scan_runs().unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].id, run.id);
        assert_eq!(runs[0].target, "C:\\Share");
        assert!(runs[0].finished_at.is_none());
    }

    #[test]
    fn finish_scan_run_sets_timestamp() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run = make_run("\\\\server\\share");
        store.insert_scan_run(&run).unwrap();
        let finished = Utc::now();
        store.finish_scan_run(&run.id, finished).unwrap();
        let runs = store.list_scan_runs().unwrap();
        assert!(runs[0].finished_at.is_some());
    }

    #[test]
    fn insert_and_retrieve_permission() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run = make_run("C:\\TestShare");
        store.insert_scan_run(&run).unwrap();

        let perm = make_perm(
            "S-1-5-21-1-2-3-1000",
            "C:\\TestShare\\Folder",
            0x0012_0089,
            None,
            0x0012_0089,
        );
        store.insert_permission(&run.id, &perm).unwrap();

        let perms = store.get_permissions(&run.id).unwrap();
        assert_eq!(perms.len(), 1);
        let p = &perms[0];
        assert_eq!(p.identity.sid.0, "S-1-5-21-1-2-3-1000");
        assert_eq!(p.identity.name.as_deref(), Some("TestUser"));
        assert_eq!(p.path.0, "C:\\TestShare\\Folder");
        assert_eq!(p.ntfs_mask.0, 0x0012_0089);
        assert!(p.share_mask.is_none());
        assert_eq!(p.path_explanation.steps, ["Step A", "Step B"]);
    }

    #[test]
    fn share_mask_none_stored_and_retrieved_as_none() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run = make_run("target");
        store.insert_scan_run(&run).unwrap();
        let perm = make_perm("S-1-5-21-1-1-1-1", "C:\\P", 0x001F_01FF, None, 0x001F_01FF);
        store.insert_permission(&run.id, &perm).unwrap();
        let perms = store.get_permissions(&run.id).unwrap();
        assert!(perms[0].share_mask.is_none());
    }

    #[test]
    fn share_mask_some_stored_and_retrieved() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run = make_run("target");
        store.insert_scan_run(&run).unwrap();
        let perm = make_perm(
            "S-1-5-21-1-1-1-2",
            "C:\\P",
            0x001F_01FF,
            Some(0x0012_0089),
            0x0012_0089,
        );
        store.insert_permission(&run.id, &perm).unwrap();
        let perms = store.get_permissions(&run.id).unwrap();
        assert_eq!(perms[0].share_mask.unwrap().0, 0x0012_0089);
    }

    #[test]
    fn share_status_and_contributing_sids_round_trip() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run = make_run("\\\\server\\share");
        store.insert_scan_run(&run).unwrap();

        let mut perm = make_perm(
            "S-1-5-21-9-9-9-1000",
            "\\\\server\\share\\Folder",
            0x0012_0089,
            Some(0x0012_0089),
            0x0012_0089,
        );
        perm.share_status = ShareEvalStatus::ReadFailed("Access denied (5)".to_owned());
        perm.contributing_sids = vec![
            ContributingAce {
                sid: Sid("S-1-5-21-9-9-9-2000".to_owned()),
                mask: AccessMask(0x0012_0089),
            },
            ContributingAce {
                sid: Sid("S-1-5-32-544".to_owned()),
                mask: AccessMask(0x001F_01FF),
            },
        ];
        store.insert_permission(&run.id, &perm).unwrap();

        let perms = store.get_permissions(&run.id).unwrap();
        assert_eq!(perms.len(), 1);
        let p = &perms[0];
        assert_eq!(
            p.share_status,
            ShareEvalStatus::ReadFailed("Access denied (5)".to_owned()),
            "ReadFailed status with error text must survive a reload"
        );
        assert_eq!(p.contributing_sids.len(), 2);
        assert_eq!(p.contributing_sids[0].sid.0, "S-1-5-21-9-9-9-2000");
        assert_eq!(p.contributing_sids[0].mask.0, 0x0012_0089);
        assert_eq!(p.contributing_sids[1].sid.0, "S-1-5-32-544");
        assert_eq!(p.contributing_sids[1].mask.0, 0x001F_01FF);
    }

    #[test]
    fn matched_aces_round_trip() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run = make_run("C:\\Share");
        store.insert_scan_run(&run).unwrap();
        let mut perm = make_perm("S-1-5-21-4-4-4-1", "C:\\Share\\F", 0x0012_0089, None, 0x1);
        perm.matched_aces = vec![
            AceEntry {
                kind: AceKind::Allow,
                sid: Sid("S-1-5-21-4-4-4-1".to_owned()),
                mask: AccessMask(0x0012_0089),
                inherited: false,
                inheritance_flags: 0,
                propagation_flags: 0,
            },
            AceEntry {
                kind: AceKind::Deny,
                sid: Sid("S-1-5-32-545".to_owned()),
                mask: AccessMask(0x0001_0000),
                inherited: true,
                inheritance_flags: 0x10,
                propagation_flags: 0,
            },
        ];
        store.insert_permission(&run.id, &perm).unwrap();
        let perms = store.get_permissions(&run.id).unwrap();
        assert_eq!(perms[0].matched_aces.len(), 2);
        assert_eq!(perms[0].matched_aces[0].kind, AceKind::Allow);
        assert!(!perms[0].matched_aces[0].inherited);
        assert_eq!(perms[0].matched_aces[1].kind, AceKind::Deny);
        assert!(perms[0].matched_aces[1].inherited);
        assert_eq!(perms[0].matched_aces[1].sid.0, "S-1-5-32-545");
    }

    #[test]
    fn diagnostics_round_trip() {
        use adpa_core::model::PermissionDiagnostic;
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run = make_run("C:\\Share");
        store.insert_scan_run(&run).unwrap();
        let mut perm = make_perm("S-1-5-21-6-6-6-1", "C:\\Share\\NonCan", 0x1, None, 0x1);
        perm.diagnostics = vec![PermissionDiagnostic::NonCanonicalDaclOrder { at_index: 3 }];
        store.insert_permission(&run.id, &perm).unwrap();
        let perms = store.get_permissions(&run.id).unwrap();
        assert_eq!(perms[0].diagnostics.len(), 1);
        assert_eq!(
            perms[0].diagnostics[0],
            PermissionDiagnostic::NonCanonicalDaclOrder { at_index: 3 }
        );
    }

    #[test]
    fn unsupported_ace_count_round_trips() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run = make_run("C:\\Share");
        store.insert_scan_run(&run).unwrap();
        let mut perm = make_perm("S-1-5-21-7-7-7-1", "C:\\Share\\F", 0x1, None, 0x1);
        perm.unsupported_ace_count = 3;
        store.insert_permission(&run.id, &perm).unwrap();
        let perms = store.get_permissions(&run.id).unwrap();
        assert_eq!(
            perms[0].unsupported_ace_count, 3,
            "unsupported ACE count must survive a reload"
        );
    }

    #[test]
    fn local_group_status_round_trips() {
        use adpa_core::model::LocalGroupEvalStatus;
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run = make_run("target");
        store.insert_scan_run(&run).unwrap();

        // Drei Varianten: NotQueried (Default), Applied, NotAvailable(msg).
        // Three variants: NotQueried (default), Applied, NotAvailable(msg).
        let mut p1 = make_perm("S-1-5-21-9-9-9-1", "C:\\A", 0x1, None, 0x1);
        p1.local_group_status = LocalGroupEvalStatus::NotQueried;
        store.insert_permission(&run.id, &p1).unwrap();

        let mut p2 = make_perm("S-1-5-21-9-9-9-2", "C:\\B", 0x1, None, 0x1);
        p2.local_group_status = LocalGroupEvalStatus::Applied;
        store.insert_permission(&run.id, &p2).unwrap();

        let mut p3 = make_perm("S-1-5-21-9-9-9-3", "C:\\C", 0x1, None, 0x1);
        p3.local_group_status = LocalGroupEvalStatus::NotAvailable("RPC error 5".to_owned());
        store.insert_permission(&run.id, &p3).unwrap();

        let perms = store.get_permissions(&run.id).unwrap();
        let by_path: std::collections::HashMap<_, _> =
            perms.iter().map(|p| (p.path.0.as_str(), p)).collect();
        assert_eq!(
            by_path["C:\\A"].local_group_status,
            LocalGroupEvalStatus::NotQueried
        );
        assert_eq!(
            by_path["C:\\B"].local_group_status,
            LocalGroupEvalStatus::Applied
        );
        assert_eq!(
            by_path["C:\\C"].local_group_status,
            LocalGroupEvalStatus::NotAvailable("RPC error 5".to_owned())
        );
    }

    #[test]
    fn share_status_unrestricted_round_trips() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run = make_run("target");
        store.insert_scan_run(&run).unwrap();
        let mut perm = make_perm(
            "S-1-5-21-4-4-4-1",
            "C:\\NullShare",
            0x1F01FF,
            None,
            0x1F01FF,
        );
        perm.share_status = ShareEvalStatus::Unrestricted;
        store.insert_permission(&run.id, &perm).unwrap();
        let perms = store.get_permissions(&run.id).unwrap();
        assert_eq!(perms[0].share_status, ShareEvalStatus::Unrestricted);
        assert!(
            perms[0].share_mask.is_none(),
            "Unrestricted must not materialise a fake share mask"
        );
    }

    #[test]
    fn share_status_applied_round_trips() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run = make_run("target");
        store.insert_scan_run(&run).unwrap();
        let mut perm = make_perm("S-1-5-21-3-3-3-1", "C:\\P", 0x0012_0089, Some(0x1), 0x1);
        perm.share_status = ShareEvalStatus::Applied;
        store.insert_permission(&run.id, &perm).unwrap();
        let perms = store.get_permissions(&run.id).unwrap();
        assert_eq!(perms[0].share_status, ShareEvalStatus::Applied);
        assert!(perms[0].contributing_sids.is_empty());
    }

    #[test]
    fn insert_and_count_scan_error() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run = make_run("target");
        store.insert_scan_run(&run).unwrap();
        let err = ScanError {
            path: Some(NormalizedPath("C:\\Denied".to_owned())),
            message: "Access denied".to_owned(),
        };
        store.insert_error(&run.id, &err).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM scan_errors", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn list_errors_for_returns_inserted_errors_in_order() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run = make_run("target");
        store.insert_scan_run(&run).unwrap();
        let with_path = ScanError {
            path: Some(NormalizedPath("C:\\Denied".to_owned())),
            message: "Access denied".to_owned(),
        };
        let without_path = ScanError {
            path: None,
            message: "Cancelled by user".to_owned(),
        };
        store.insert_error(&run.id, &with_path).unwrap();
        store.insert_error(&run.id, &without_path).unwrap();

        let errors = store.list_errors_for(&run.id).unwrap();
        assert_eq!(errors.len(), 2);
        assert_eq!(
            errors[0].path.as_ref().map(|p| p.0.as_str()),
            Some("C:\\Denied")
        );
        assert_eq!(errors[0].message, "Access denied");
        assert!(errors[1].path.is_none());
        assert_eq!(errors[1].message, "Cancelled by user");
    }

    #[test]
    fn list_errors_for_other_run_is_empty() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run_a = make_run("target-a");
        let run_b = make_run("target-b");
        store.insert_scan_run(&run_a).unwrap();
        store.insert_scan_run(&run_b).unwrap();
        store
            .insert_error(
                &run_a.id,
                &ScanError {
                    path: None,
                    message: "only for A".to_owned(),
                },
            )
            .unwrap();
        let errors = store.list_errors_for(&run_b.id).unwrap();
        assert!(errors.is_empty());
    }

    #[test]
    fn list_runs_returns_newest_first() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        for i in 0..3 {
            let mut run = make_run(&format!("target{i}"));
            // Ensure slightly different timestamps
            run.started_at = Utc::now() + chrono::Duration::seconds(i);
            store.insert_scan_run(&run).unwrap();
        }
        let runs = store.list_scan_runs().unwrap();
        assert_eq!(runs.len(), 3);
        // newest first: target2 should come before target0
        assert!(runs[0].started_at >= runs[1].started_at);
        assert!(runs[1].started_at >= runs[2].started_at);
    }

    #[test]
    fn get_permissions_empty_for_different_run() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run1 = make_run("target1");
        let run2 = make_run("target2");
        store.insert_scan_run(&run1).unwrap();
        store.insert_scan_run(&run2).unwrap();
        let perm = make_perm("S-1-5-21-1-1-1-1", "C:\\P", 0x001F_01FF, None, 0x001F_01FF);
        store.insert_permission(&run1.id, &perm).unwrap();
        // run2 has no permissions
        let perms = store.get_permissions(&run2.id).unwrap();
        assert!(perms.is_empty());
    }
}
