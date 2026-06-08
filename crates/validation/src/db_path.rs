// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Validierung von Datenbank-Zielpfaden.
//! Validation of database target paths.
//!
//! existierendes Zielverzeichnis.
//! The database path is a write target and therefore subject to the same
//! policy as export paths: absolute path, known extension, existing parent
//! directory.

use adpa_core::error::CoreError;
use std::path::{Path, PathBuf};

/// Validierter Datenbank-Zielpfad.
/// Validated database target path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDbPath(pub PathBuf);

/// Allowed file extensions for SQLite databases.
const ALLOWED_EXTENSIONS: &[&str] = &["db", "sqlite", "sqlite3"];

/// Validates a user-supplied database path.
///
/// - bekannte Endung (.db, .sqlite, .sqlite3) / recognized extension
/// - Zielverzeichnis existiert / parent directory exists
pub fn validate_db_path(input: &str) -> Result<ValidatedDbPath, CoreError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CoreError::Validation(
            "Database path must not be empty".into(),
        ));
    }
    if trimmed.contains('\0') {
        return Err(CoreError::Validation(
            "Database path must not contain null bytes".into(),
        ));
    }

    // Absolute path: drive letter (C:\) or UNC (\\server\share).
    let is_unc = trimmed.starts_with(r"\\");
    let is_drive_absolute = trimmed.len() >= 3
        && trimmed.as_bytes()[0].is_ascii_alphabetic()
        && trimmed[1..].starts_with(":\\");
    if !is_unc && !is_drive_absolute {
        return Err(CoreError::Validation(format!(
            "Database path must be an absolute path (e.g. C:\\data\\stars.db): {trimmed}"
        )));
    }

    let path = PathBuf::from(trimmed);

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase());
    match ext.as_deref() {
        Some(e) if ALLOWED_EXTENSIONS.contains(&e) => {}
        _ => {
            return Err(CoreError::Validation(format!(
                "Database path must have a recognized extension (.db, .sqlite, .sqlite3): {trimmed}"
            )));
        }
    }

    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    if parent.as_os_str().is_empty() || !parent.exists() {
        return Err(CoreError::Validation(format!(
            "Database directory does not exist: {}",
            parent.display()
        )));
    }

    Ok(ValidatedDbPath(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_path_rejected() {
        assert!(validate_db_path("").is_err());
        assert!(validate_db_path("   ").is_err());
    }

    #[test]
    fn relative_path_rejected() {
        assert!(validate_db_path(r"data\stars.db").is_err());
        assert!(validate_db_path("stars.db").is_err());
        assert!(validate_db_path(r"..\stars.db").is_err());
    }

    #[test]
    fn unknown_extension_rejected() {
        let tmp = std::env::temp_dir().join("stars_data.txt");
        assert!(validate_db_path(&tmp.to_string_lossy()).is_err());
    }

    #[test]
    fn nonexistent_directory_rejected() {
        assert!(validate_db_path(r"C:\__no_such_dir_9a8b7c__\stars.db").is_err());
    }

    #[test]
    fn null_byte_rejected() {
        assert!(validate_db_path("C:\\data\u{0}\\stars.db").is_err());
    }

    #[test]
    fn absolute_path_with_existing_parent_accepted() {
        let tmp = std::env::temp_dir().join("adpa_test_validation_db.db");
        let result = validate_db_path(&tmp.to_string_lossy());
        assert!(result.is_ok(), "temp dir exists, .db extension is valid");
    }

    #[test]
    fn sqlite_extension_accepted() {
        let tmp = std::env::temp_dir().join("adpa_test_validation.sqlite3");
        assert!(validate_db_path(&tmp.to_string_lossy()).is_ok());
    }
}
