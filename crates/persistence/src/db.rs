// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Main database entry point — opens the SQLite connection and runs migrations.

use adpa_core::{error::CoreError, model::ScanRun};
use rusqlite::Connection;
use uuid::Uuid;

use crate::{delta::DeltaReport, migrations::run_migrations, scan_store::ScanStore};

pub struct Database {
    conn: Connection,
}

impl Database {
    /// Opens or creates a SQLite database at the given path and applies
    /// all pending migrations.
    pub fn open(path: &str) -> Result<Self, CoreError> {
        let conn = Connection::open(path)
            .map_err(|e| CoreError::Database(format!("Cannot open database '{path}': {e}")))?;
        let db = Self { conn };
        db.initialize()?;
        Ok(db)
    }

    /// Review CR-30: opens an existing database for **reading only** —
    /// SQLite's read-only mode, no migration, nothing written. For the
    /// history commands, which promise exactly that: inspecting an older
    /// audit database must not change it. Their queries use only the
    /// columns of schema v1, so a database of any Stars version opens; a
    /// file without a Stars schema, or of a newer Stars, is refused.
    pub fn open_read_only(path: &str) -> Result<Self, CoreError> {
        use rusqlite::OpenFlags;
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| {
            CoreError::Database(format!("Cannot open database '{path}' read-only: {e}"))
        })?;
        let version: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|e| CoreError::Database(format!("Cannot read schema version: {e}")))?;
        let latest = crate::migrations::latest_schema_version();
        if version == 0 {
            return Err(CoreError::Database(format!(
                "'{path}' is not a Stars database (it has no schema version)"
            )));
        }
        if version > latest {
            return Err(CoreError::Database(format!(
                "'{path}' was written by a newer Stars (schema v{version}; this version knows \
                 up to v{latest})"
            )));
        }
        Ok(Self { conn })
    }

    /// Creates an in-memory database — for tests only.
    pub fn open_in_memory() -> Result<Self, CoreError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| CoreError::Database(format!("Cannot open in-memory database: {e}")))?;
        let db = Self { conn };
        db.initialize()?;
        Ok(db)
    }

    fn initialize(&self) -> Result<(), CoreError> {
        run_migrations(&self.conn)
    }

    /// Returns a ScanStore backed by this database's connection.
    pub fn scan_store(&self) -> ScanStore<'_> {
        ScanStore::new(&self.conn)
    }

    /// Lists all stored scan runs (newest first).
    pub fn list_scan_runs(&self) -> Result<Vec<ScanRun>, CoreError> {
        self.scan_store().list_scan_runs()
    }

    /// Deletes a scan run including all dependent data (permissions and
    /// scan errors). Returns the number of removed scan-run rows (0 if
    /// the ID did not exist, 1 on success).
    pub fn delete_scan_run(&self, id: &Uuid) -> Result<usize, CoreError> {
        self.scan_store().delete_scan_run(id)
    }

    /// Compares two scan runs and returns all changes.
    pub fn compare_scans(&self, old_id: &Uuid, new_id: &Uuid) -> Result<DeltaReport, CoreError> {
        crate::delta::compare_scans(&self.conn, old_id, new_id)
    }
}

#[cfg(test)]
mod tests {
    use super::Database;

    #[test]
    fn open_in_memory_succeeds() {
        Database::open_in_memory().unwrap();
    }

    #[test]
    fn scan_store_accessible() {
        let db = Database::open_in_memory().unwrap();
        let runs = db.scan_store().list_scan_runs().unwrap();
        assert!(runs.is_empty());
    }

    /// Review CR-30: an older database is read without being migrated —
    /// its schema version and its bytes stay as they were; a newer or a
    /// foreign file is refused.
    #[test]
    fn a_read_only_open_never_migrates() {
        let dir = std::env::temp_dir().join(format!("adpa-cr30-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("old.db");
        let _ = std::fs::remove_file(&path);
        let p = path.to_str().unwrap();
        {
            let db = Database::open(p).unwrap();
            db.scan_store()
                .insert_scan_run(&adpa_core::model::ScanRun {
                    id: uuid::Uuid::new_v4(),
                    started_at: chrono::Utc::now(),
                    finished_at: None,
                    target: r"C:\data".into(),
                    errors: vec![],
                    scope: None,
                    max_depth: None,
                })
                .unwrap();
        }
        // Pretend the file was written by an older Stars (schema v8).
        rusqlite::Connection::open(p)
            .unwrap()
            .execute_batch("PRAGMA user_version = 8;")
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        {
            let db = Database::open_read_only(p).unwrap();
            assert_eq!(db.list_scan_runs().unwrap().len(), 1);
            let version: u32 = db
                .conn
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
            assert_eq!(version, 8, "no migration");
            assert!(
                db.conn.execute_batch("PRAGMA user_version = 9;").is_err(),
                "the connection cannot write"
            );
        }
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "the file is unchanged"
        );

        rusqlite::Connection::open(p)
            .unwrap()
            .execute_batch("PRAGMA user_version = 999;")
            .unwrap();
        let err = Database::open_read_only(p).err().unwrap().to_string();
        assert!(err.contains("newer Stars"), "{err}");
        let foreign = dir.join("foreign.db");
        let _ = std::fs::remove_file(&foreign);
        rusqlite::Connection::open(&foreign)
            .unwrap()
            .execute_batch("CREATE TABLE t (x INTEGER);")
            .unwrap();
        let err = Database::open_read_only(foreign.to_str().unwrap())
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("not a Stars database"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
