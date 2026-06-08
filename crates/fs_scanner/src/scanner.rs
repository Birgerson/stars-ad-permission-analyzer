// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

use adpa_core::{
    error::CoreError,
    model::FileSystemObject,
    traits::{ScanRequest, ScanResult, Scanner},
};

use crate::acl;

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

/// Reads a file system object with owner SID, DACL entries and attributes.
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
