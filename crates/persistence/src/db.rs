// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Main database entry point — opens the SQLite connection and runs migrations.

use adpa_core::{error::CoreError, model::ScanRun};
use rusqlite::Connection;
use uuid::Uuid;

use crate::{
    delta::DeltaEntry, identity_cache::IdentityCache, migrations::run_migrations,
    scan_store::ScanStore,
};

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

    /// Returns an IdentityCache backed by this database's connection.
    pub fn identity_cache(&self) -> IdentityCache<'_> {
        IdentityCache::new(&self.conn)
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
    pub fn compare_scans(
        &self,
        old_id: &Uuid,
        new_id: &Uuid,
    ) -> Result<Vec<DeltaEntry>, CoreError> {
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

    #[test]
    fn identity_cache_accessible() {
        use adpa_core::model::Sid;
        let db = Database::open_in_memory().unwrap();
        let result = db
            .identity_cache()
            .lookup(&Sid("S-1-5-21-1-2-3-1000".to_owned()))
            .unwrap();
        assert!(result.is_none());
    }
}
