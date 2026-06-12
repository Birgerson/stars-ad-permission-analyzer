// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

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

    ///
    /// Deletes a scan run completely along with all dependent records
    /// (permissions and scan errors). Runs in a transaction: either
    /// everything is gone or nothing. SQLite foreign keys are not enabled
    /// via `PRAGMA foreign_keys = ON` in this codebase, so we explicitly
    /// delete the dependent rows.
    ///
    /// Returns the number of removed scan-run rows (0 if the ID does not
    /// exist; 1 on success).
    pub fn delete_scan_run(&self, id: &Uuid) -> Result<usize, CoreError> {
        let id_str = id.to_string();
        // Manual transaction over the borrowed connection — the mutable
        // borrow required by `Connection::transaction()` would conflict with
        // our `&Connection`. BEGIN/COMMIT are semantically equivalent here.
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| CoreError::Database(format!("delete_scan_run BEGIN failed: {e}")))?;

        let run_step = (|| -> Result<usize, CoreError> {
            self.conn
                .execute(
                    "DELETE FROM effective_permissions WHERE scan_run_id = ?1",
                    params![id_str],
                )
                .map_err(|e| {
                    CoreError::Database(format!("delete effective_permissions failed: {e}"))
                })?;
            self.conn
                .execute(
                    "DELETE FROM scan_errors WHERE scan_run_id = ?1",
                    params![id_str],
                )
                .map_err(|e| CoreError::Database(format!("delete scan_errors failed: {e}")))?;
            let removed = self
                .conn
                .execute("DELETE FROM scan_runs WHERE id = ?1", params![id_str])
                .map_err(|e| CoreError::Database(format!("delete scan_runs failed: {e}")))?;
            Ok(removed)
        })();

        match run_step {
            Ok(removed) => {
                self.conn.execute_batch("COMMIT").map_err(|e| {
                    CoreError::Database(format!("delete_scan_run COMMIT failed: {e}"))
                })?;
                Ok(removed)
            }
            Err(e) => {
                // Explicit rollback; swallow the secondary error here — the
                // original cause matters more.
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Stores an effective permission and upserts the associated identity.
    pub fn insert_permission(
        &self,
        scan_run_id: &Uuid,
        perm: &EffectivePermission,
    ) -> Result<(), CoreError> {
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

        // Same for LocalGroupEvalStatus.
        let (local_group_status, local_group_error): (&str, Option<&str>) =
            match &perm.local_group_status {
                adpa_core::model::LocalGroupEvalStatus::NotQueried => ("NotQueried", None),
                adpa_core::model::LocalGroupEvalStatus::Applied => ("Applied", None),
                adpa_core::model::LocalGroupEvalStatus::NotAvailable(msg) => {
                    ("NotAvailable", Some(msg.as_str()))
                }
            };

        // Code Review 2026-06-07 Finding 1: Identity-Snapshot pro
        // Code review 2026-06-07 finding 1: identity snapshot per
        // permission row. Previously the identity (name/domain/kind/
        // disabled) lived only in the global `identities` table and was
        // resolved on read via JOIN — meaning a later upsert could
        // retroactively change how earlier runs looked. The snapshot
        // columns make the permission row immutable against later
        self.conn
            .execute(
                "INSERT INTO effective_permissions
                     (scan_run_id, sid, path, ntfs_mask, share_mask, effective_mask,
                      explanation, share_status, share_error, contributing_sids,
                      unsupported_ace_count, matched_aces,
                      local_group_status, local_group_error, diagnostics,
                      identity_name, identity_domain, identity_kind, identity_disabled)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                         ?16, ?17, ?18, ?19)",
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
                    perm.identity.name,
                    perm.identity.domain,
                    kind_to_str(&perm.identity.kind),
                    perm.identity.disabled as i32,
                ],
            )
            .map_err(|e| CoreError::Database(format!("insert_permission failed: {e}")))?;
        Ok(())
    }

    /// Persists a complete scan run — the run row, all effective
    /// permissions, and all scan errors — in a **single transaction**.
    ///
    /// Engine review 2026-06-12 finding 1: the previous caller-side loop
    /// inserted each permission in its own implicit transaction (one
    /// SQLite commit + fsync per path — the dominant cost of a large
    /// scan) and only `warn!`-logged a failed row, so a partial scan
    /// could be stored while the `scan_runs` row still looked complete.
    ///
    /// This method is all-or-nothing: a `BEGIN IMMEDIATE` wraps the whole
    /// run, any failure triggers a `ROLLBACK` and returns the error, and
    /// success commits once. The history is therefore never silently
    /// partial.
    pub fn persist_scan_atomic(
        &self,
        run: &ScanRun,
        permissions: &[EffectivePermission],
        errors: &[ScanError],
    ) -> Result<(), CoreError> {
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| CoreError::Database(format!("persist_scan_atomic BEGIN failed: {e}")))?;

        let body = (|| -> Result<(), CoreError> {
            self.insert_scan_run(run)?;
            for perm in permissions {
                self.insert_permission(&run.id, perm)?;
            }
            for error in errors {
                self.insert_error(&run.id, error)?;
            }
            Ok(())
        })();

        match body {
            Ok(()) => {
                self.conn.execute_batch("COMMIT").map_err(|e| {
                    CoreError::Database(format!("persist_scan_atomic COMMIT failed: {e}"))
                })?;
                Ok(())
            }
            Err(e) => {
                // Explicit rollback; the original cause matters more than a
                // secondary rollback error.
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

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

    /// Returns all stored permissions for a scan run.
    pub fn get_permissions(
        &self,
        scan_run_id: &Uuid,
    ) -> Result<Vec<EffectivePermission>, CoreError> {
        // Code review 2026-06-07 finding 1: read identity exclusively
        // from the per-permission snapshot — no more JOIN against the
        // global `identities` table. This makes history truly
        // immutable: a later scan that upserts the same SID with
        // different identity values can no longer change how earlier
        // runs look when reloaded. Backfill cases (old v1..v6 rows
        // without an identities entry at backfill time) appear as
        // name=NULL/domain=NULL/kind='Unknown'; that is the honest
        // "we no longer know" answer instead of showing a potentially
        // mutated value.
        let mut stmt = self
            .conn
            .prepare(
                "SELECT ep.sid, ep.path, ep.ntfs_mask, ep.share_mask,
                         ep.effective_mask, ep.explanation,
                         ep.share_status, ep.share_error, ep.contributing_sids,
                         ep.unsupported_ace_count, ep.matched_aces,
                         ep.local_group_status, ep.local_group_error,
                         ep.diagnostics,
                         ep.identity_name, ep.identity_domain,
                         ep.identity_kind, ep.identity_disabled
                 FROM effective_permissions ep
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
                // Identity snapshot (v7): single source. No fallback.
                // identity_kind is NOT NULL DEFAULT 'Unknown', so String not
                // Option<String>; identity_disabled is NOT NULL DEFAULT 0.
                let name: Option<String> = row.get(14)?;
                let domain: Option<String> = row.get(15)?;
                let kind_str: String = row.get(16)?;
                let disabled: i32 = row.get(17)?;

                let steps: Vec<String> = serde_json::from_str(&expl).unwrap_or_default();
                let contributing_sids: Vec<ContributingAce> =
                    serde_json::from_str(&contributing_json).unwrap_or_default();
                let matched_aces: Vec<AceEntry> =
                    serde_json::from_str(&matched_aces_json).unwrap_or_default();
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
                let kind = kind_from_str(&kind_str);

                Ok(EffectivePermission {
                    identity: Identity {
                        sid: Sid(sid),
                        name,
                        domain,
                        kind,
                        disabled: disabled != 0,
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
        IdentityKind::ForeignSecurityPrincipal => "ForeignSecurityPrincipal",
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
        "ForeignSecurityPrincipal" => IdentityKind::ForeignSecurityPrincipal,
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
    fn persist_scan_atomic_writes_run_permissions_and_errors() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run = make_run(r"C:\atomic");
        let perms = vec![
            make_perm("S-1-5-21-1-2-3-1000", r"C:\atomic\a", 1, None, 1),
            make_perm("S-1-5-21-1-2-3-1001", r"C:\atomic\b", 1, None, 1),
        ];
        let errors = vec![ScanError {
            path: Some(NormalizedPath(r"C:\atomic\denied".to_owned())),
            message: "access denied".to_owned(),
        }];
        store.persist_scan_atomic(&run, &perms, &errors).unwrap();

        assert_eq!(store.list_scan_runs().unwrap().len(), 1);
        assert_eq!(store.get_permissions(&run.id).unwrap().len(), 2);
        assert_eq!(store.list_errors_for(&run.id).unwrap().len(), 1);
    }

    #[test]
    fn persist_scan_atomic_rolls_back_on_failure() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run = make_run(r"C:\atomic");

        // First batch commits cleanly.
        let first = vec![make_perm("S-1-5-21-1-2-3-1000", r"C:\atomic\a", 1, None, 1)];
        store.persist_scan_atomic(&run, &first, &[]).unwrap();
        assert_eq!(store.get_permissions(&run.id).unwrap().len(), 1);

        // Second batch reuses the same run id → the scan_runs INSERT
        // fails on the primary key. The whole batch (including the new
        // permissions) must roll back, leaving the first batch intact.
        let second = vec![
            make_perm("S-1-5-21-1-2-3-2000", r"C:\atomic\x", 1, None, 1),
            make_perm("S-1-5-21-1-2-3-2001", r"C:\atomic\y", 1, None, 1),
        ];
        let result = store.persist_scan_atomic(&run, &second, &[]);
        assert!(result.is_err(), "duplicate run id must fail the batch");

        // Nothing from the failed batch leaked in.
        assert_eq!(
            store.get_permissions(&run.id).unwrap().len(),
            1,
            "rollback must leave only the first batch's single permission"
        );
    }

    #[test]
    fn delete_scan_run_removes_run_and_dependents() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run = make_run(r"C:\to-delete");
        store.insert_scan_run(&run).unwrap();
        let perm = make_perm("S-1-5-21-1-2-3-1000", r"C:\to-delete\x", 1, None, 1);
        store.insert_permission(&run.id, &perm).unwrap();
        store
            .insert_error(
                &run.id,
                &ScanError {
                    path: Some(NormalizedPath(r"C:\to-delete\bad".to_owned())),
                    message: "test error".to_owned(),
                },
            )
            .unwrap();

        // Sanity: everything is present.
        assert_eq!(store.list_scan_runs().unwrap().len(), 1);
        assert_eq!(store.get_permissions(&run.id).unwrap().len(), 1);
        assert_eq!(store.list_errors_for(&run.id).unwrap().len(), 1);

        let removed = store.delete_scan_run(&run.id).unwrap();
        assert_eq!(removed, 1, "exactly one scan_run row must be removed");

        // Run gone, dependent data gone too.
        assert!(store.list_scan_runs().unwrap().is_empty());
        assert!(store.get_permissions(&run.id).unwrap().is_empty());
        assert!(store.list_errors_for(&run.id).unwrap().is_empty());
    }

    #[test]
    fn delete_scan_run_unknown_id_returns_zero() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let removed = store.delete_scan_run(&Uuid::new_v4()).unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn delete_scan_run_leaves_other_runs_untouched() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let keep = make_run(r"C:\keep");
        let drop = make_run(r"C:\drop");
        store.insert_scan_run(&keep).unwrap();
        store.insert_scan_run(&drop).unwrap();
        store
            .insert_permission(
                &keep.id,
                &make_perm("S-1-5-21-1-2-3-1000", r"C:\keep\x", 1, None, 1),
            )
            .unwrap();
        store
            .insert_permission(
                &drop.id,
                &make_perm("S-1-5-21-1-2-3-2000", r"C:\drop\x", 1, None, 1),
            )
            .unwrap();

        store.delete_scan_run(&drop.id).unwrap();

        let runs = store.list_scan_runs().unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].id, keep.id);
        assert_eq!(store.get_permissions(&keep.id).unwrap().len(), 1);
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

    /// geschuetzt.
    /// Code review 2026-06-07 finding 1: historical scan data must be
    /// immune against later identity upserts. Before v7,
    /// `insert_permission` upserted `identities` and `get_permissions`
    /// joined against the current `identities` row — meaning run A
    /// showed, on reload, the identity state from the LATER run B, not
    /// its own state at scan time. With the v7 snapshot columns, run A
    /// must stay unchanged after run B persisted the same SID with a
    /// different name/disabled status. Without this test, audit
    /// integrity is not protected.
    #[test]
    fn run_a_immutable_against_later_identity_upsert_in_run_b() {
        let conn = setup();
        let store = ScanStore::new(&conn);
        let run_a = make_run("target-a");
        let run_b = make_run("target-b");
        store.insert_scan_run(&run_a).unwrap();
        store.insert_scan_run(&run_b).unwrap();

        // Run A: SID S-1-5-21-…-1000, Name "alice.old", aktiv (disabled=false).
        // Run A: SID S-1-5-21-…-1000, name "alice.old", active (disabled=false).
        let mut perm_a = make_perm("S-1-5-21-7-7-7-1000", r"C:\X", 0x1, None, 0x1);
        perm_a.identity.name = Some("alice.old".to_owned());
        perm_a.identity.domain = Some("OLD-DOMAIN".to_owned());
        perm_a.identity.kind = IdentityKind::User;
        perm_a.identity.disabled = false;
        store.insert_permission(&run_a.id, &perm_a).unwrap();

        // Run B (spaeter): gleiche SID, jetzt deaktiviert, anderer Name,
        // Run B (later): same SID, now disabled, different name, different
        // domain. Historic pattern: identities upsert overwrites the
        // global row, JOIN on read of run A returns the new values ->
        // audit corruption.
        let mut perm_b = make_perm("S-1-5-21-7-7-7-1000", r"C:\Y", 0x1, None, 0x1);
        perm_b.identity.name = Some("alice.new".to_owned());
        perm_b.identity.domain = Some("NEW-DOMAIN".to_owned());
        perm_b.identity.kind = IdentityKind::User;
        perm_b.identity.disabled = true;
        store.insert_permission(&run_b.id, &perm_b).unwrap();

        // Run A must return its own values.
        let perms_a = store.get_permissions(&run_a.id).unwrap();
        assert_eq!(perms_a.len(), 1);
        assert_eq!(
            perms_a[0].identity.name.as_deref(),
            Some("alice.old"),
            "Run A name must NOT be overwritten by Run B identity upsert — closes Finding 1"
        );
        assert_eq!(
            perms_a[0].identity.domain.as_deref(),
            Some("OLD-DOMAIN"),
            "Run A domain must NOT be overwritten by Run B"
        );
        assert!(
            !perms_a[0].identity.disabled,
            "Run A disabled flag must stay false — was active at scan time"
        );

        // Run B sees its own values by construction.
        let perms_b = store.get_permissions(&run_b.id).unwrap();
        assert_eq!(perms_b[0].identity.name.as_deref(), Some("alice.new"));
        assert_eq!(perms_b[0].identity.domain.as_deref(), Some("NEW-DOMAIN"));
        assert!(perms_b[0].identity.disabled);
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
