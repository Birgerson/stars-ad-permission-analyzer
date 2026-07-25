// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! `Scanner` trait implementation — a deliberate, dormant extension point.
//!
//! [`NtfsScanner`] is the workspace's implementation of the architectural
//! [`Scanner`] trait that `AGENTS.md` requires ("new scanners must be
//! addable through a scanner interface"). It reads exactly **one** path.
//!
//! It is **not** the production path and has no callers outside its own
//! tests: tree scans go through [`crate::walker::walk_tree`] /
//! [`crate::acl::read_file_system_object_cached`], which add recursion,
//! cycle detection, cancellation and the shared SD cache. This module
//! exists so a future scanner (e.g. a registry or a remote scanner) can be
//! added behind the same trait without reshaping the architecture — the same
//! kind of documented seam as `update_manager` (known-limitations L12).
//!
//! Recorded here because an undocumented trait impl with no callers reads
//! like dead code and invites deletion (fs_scanner review 2026-07-25, FS-4).

use adpa_core::{
    error::CoreError,
    model::FileSystemObject,
    traits::{ScanRequest, ScanResult, Scanner},
};

use crate::acl;

/// Single-path NTFS scanner behind the architectural [`Scanner`] trait.
/// See the module documentation for why this is a seam, not the live path.
pub struct NtfsScanner;

impl Scanner for NtfsScanner {
    /// Reads the DACL and attributes of the target path and returns them as a
    /// `FileSystemObject`. Permission evaluation runs on this result in the
    /// `permission_engine` crate.
    fn scan(&self, request: ScanRequest) -> Result<ScanResult, CoreError> {
        let fso = acl::read_file_system_object(&request.target)?;
        Ok(ScanResult {
            objects: vec![fso],
            errors: Vec::new(),
        })
    }
}

/// Reads a single file system object (owner SID, DACL entries, attributes).
///
/// Unlike [`NtfsScanner`] this **is** production API: the CLI `analyze`
/// path and the GUI worker (single-path analysis, trustee view) call it.
/// It is the un-cached single-shot counterpart to
/// [`crate::acl::read_file_system_object_cached`], which tree scans use with
/// a shared [`crate::acl::SdCache`].
pub fn read_fso(path: &str) -> Result<FileSystemObject, CoreError> {
    acl::read_file_system_object(path)
}

#[cfg(test)]
mod tests {
    use super::NtfsScanner;
    use adpa_core::traits::{ScanRequest, Scanner};

    #[test]
    fn scan_returns_target_object() {
        // F5 regression: a successful scan must return the read FSO instead of
        // an empty list.
        let result = NtfsScanner
            .scan(ScanRequest {
                target: "C:\\Windows".to_string(),
            })
            .expect("scanning C:\\Windows must succeed");
        assert_eq!(result.objects.len(), 1, "scan must return exactly one FSO");
        assert_eq!(result.objects[0].path.0, "C:\\Windows");
        assert!(result.objects[0].is_directory);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn scan_nonexistent_target_returns_err() {
        let result = NtfsScanner.scan(ScanRequest {
            target: "C:\\__nonexistent_adpa_xyz_8f3a__".to_string(),
        });
        assert!(result.is_err(), "non-existent target must produce Err");
    }
}
