// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Versionierte Schema-Migrationen via PRAGMA user_version.
//! Versioned schema migrations using PRAGMA user_version.

use adpa_core::error::CoreError;
use rusqlite::Connection;

/// Jede Migration ist ein (Zielversion, SQL)-Paar.
/// Each migration is a (target_version, SQL) pair.
const MIGRATIONS: &[(u32, &str)] = &[
    (1, include_str!("schema.sql")),
    (2, include_str!("schema_v2.sql")),
    (3, include_str!("schema_v3.sql")),
    (4, include_str!("schema_v4.sql")),
    (5, include_str!("schema_v5.sql")),
    (6, include_str!("schema_v6.sql")),
    (7, include_str!("schema_v7.sql")),
];

/// Wendet alle ausstehenden Migrationen in aufsteigender Reihenfolge an.
/// Applies all pending migrations in ascending order.
pub fn run_migrations(conn: &Connection) -> Result<(), CoreError> {
    let current: u32 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|e| CoreError::Database(format!("Cannot read schema version: {e}")))?;

    for (version, sql) in MIGRATIONS {
        if *version <= current {
            continue;
        }
        conn.execute_batch(&format!(
            "BEGIN; {sql} PRAGMA user_version = {version}; COMMIT;"
        ))
        .map_err(|e| CoreError::Database(format!("Migration v{version} failed: {e}")))?;
        tracing::info!("Applied database migration v{version}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::run_migrations;

    fn in_memory() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn fresh_database_gets_latest_version() {
        let conn = in_memory();
        run_migrations(&conn).unwrap();
        let v: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(v, 7);
    }

    #[test]
    fn migration_adds_diagnostic_columns() {
        let conn = in_memory();
        run_migrations(&conn).unwrap();
        // Die neuen Spalten aus v2–v7 müssen abfragbar sein.
        // The new columns from v2–v7 must be queryable.
        conn.query_row(
            "SELECT share_status, share_error, contributing_sids, unsupported_ace_count,
                    matched_aces, local_group_status, local_group_error, diagnostics,
                    identity_name, identity_domain, identity_kind, identity_disabled
             FROM effective_permissions LIMIT 1",
            [],
            |_| Ok(()),
        )
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(()),
            other => Err(other),
        })
        .expect("v2–v7 columns must exist on effective_permissions");
    }

    #[test]
    fn tables_exist_after_migration() {
        let conn = in_memory();
        run_migrations(&conn).unwrap();

        for table in &[
            "scan_runs",
            "scan_errors",
            "identities",
            "group_memberships",
            "effective_permissions",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap_or_else(|_| panic!("Table '{table}' does not exist"));
            assert_eq!(count, 0, "fresh table '{table}' should be empty");
        }
    }

    #[test]
    fn migration_is_idempotent() {
        let conn = in_memory();
        run_migrations(&conn).unwrap();
        // Running again must not fail (version guard skips already-applied migrations)
        run_migrations(&conn).unwrap();
        let v: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(v, 7);
    }

    /// Schrittweise Migration: v1-Daten überleben das Upgrade auf v7
    /// und alle neuen Spalten erhalten ihre Default-Werte. Ohne diesen
    /// Test wäre nicht garantiert, dass ein in-place-Upgrade einer alten
    /// Datenbank ohne Datenverlust läuft.
    ///
    /// Step-wise migration: v1 data survives the upgrade to v7 and all new
    /// columns receive their default values. Without this test, an in-place
    /// upgrade of an old database is not guaranteed to survive without data
    /// loss.
    #[test]
    fn v1_data_survives_full_migration_to_v7() {
        let conn = in_memory();

        // Schritt 1: nur v1-Schema anwenden und PRAGMA user_version=1 setzen,
        // sodass die nachfolgende run_migrations-Schleife exakt die v2..v6-
        // Wege durchläuft, die ein produktives Upgrade auch nimmt.
        // Step 1: apply v1 schema only and set PRAGMA user_version=1 so that
        // the subsequent run_migrations loop walks exactly the v2..v6 path a
        // production upgrade would take.
        conn.execute_batch(&format!(
            "BEGIN; {} PRAGMA user_version = 1; COMMIT;",
            include_str!("schema.sql")
        ))
        .unwrap();

        // Schritt 2: v1-typische Datensätze einfügen — nur Spalten, die in
        // v1 existieren.
        // Step 2: insert v1-typical rows — only columns that exist in v1.
        conn.execute(
            "INSERT INTO scan_runs (id, started_at, finished_at, target) \
             VALUES ('run-legacy', '2025-01-01T00:00:00Z', NULL, 'C:\\Legacy')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO identities (sid, name, domain, kind, disabled) \
             VALUES ('S-1-5-21-1-2-3-1000', 'legacy.user', 'OLDCORP', 'User', 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO effective_permissions \
                (scan_run_id, sid, path, ntfs_mask, share_mask, effective_mask, explanation) \
             VALUES ('run-legacy', 'S-1-5-21-1-2-3-1000', 'C:\\Legacy', 131241, NULL, 131241, '[]')",
            [],
        )
        .unwrap();

        // Schritt 3: vollständige Migration anwenden.
        // Step 3: apply full migration.
        run_migrations(&conn).unwrap();

        let v: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(v, 7, "migration must end at v7");

        // Schritt 4: v1-Werte überleben unverändert.
        // Step 4: v1 values survive unchanged.
        let v1_row: (String, String, i64, i64) = conn
            .query_row(
                "SELECT sid, path, ntfs_mask, effective_mask \
                 FROM effective_permissions WHERE scan_run_id = 'run-legacy'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("legacy row must survive migration");
        assert_eq!(v1_row.0, "S-1-5-21-1-2-3-1000");
        assert_eq!(v1_row.1, "C:\\Legacy");
        assert_eq!(v1_row.2, 131241);
        assert_eq!(v1_row.3, 131241);

        // Schritt 5: v2..v6-Defaults greifen für die Altzeile.
        // Step 5: v2..v6 defaults apply to the legacy row.
        let defaults: (
            String,
            Option<String>,
            String,
            i64,
            String,
            String,
            Option<String>,
            String,
        ) = conn
            .query_row(
                "SELECT share_status, share_error, contributing_sids, unsupported_ace_count,
                        matched_aces, local_group_status, local_group_error, diagnostics
                 FROM effective_permissions WHERE scan_run_id = 'run-legacy'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .expect("v2..v6 columns must read back defaults");
        assert_eq!(defaults.0, "NotApplicable");
        assert_eq!(defaults.1, None);
        assert_eq!(defaults.2, "[]");
        assert_eq!(defaults.3, 0);
        assert_eq!(defaults.4, "[]");
        assert_eq!(defaults.5, "NotQueried");
        assert_eq!(defaults.6, None);
        assert_eq!(defaults.7, "[]");

        // Schritt 6 (Code Review 2026-06-07, Finding 1): v7-Backfill aus
        // identities-Tabelle. Die Legacy-Identitaet (legacy.user,
        // OLDCORP, User, disabled=false) muss in den neuen Snapshot-
        // Spalten landen, damit die historische Permission ohne JOIN
        // gegen identities lesbar bleibt.
        // Step 6 (code review 2026-06-07, finding 1): v7 backfill from
        // the identities table. The legacy identity (legacy.user,
        // OLDCORP, User, disabled=false) must land in the new snapshot
        // columns so the historical permission stays readable without
        // joining against identities.
        let snapshot: (Option<String>, Option<String>, String, i64) = conn
            .query_row(
                "SELECT identity_name, identity_domain, identity_kind, identity_disabled
                 FROM effective_permissions WHERE scan_run_id = 'run-legacy'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("v7 snapshot columns must read back");
        assert_eq!(
            snapshot.0.as_deref(),
            Some("legacy.user"),
            "name must be backfilled from identities cache"
        );
        assert_eq!(
            snapshot.1.as_deref(),
            Some("OLDCORP"),
            "domain must be backfilled from identities cache"
        );
        assert_eq!(snapshot.2, "User", "kind must be backfilled");
        assert_eq!(snapshot.3, 0, "disabled flag must be backfilled");
    }
}
