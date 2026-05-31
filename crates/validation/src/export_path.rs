use adpa_core::error::CoreError;
use std::path::{Path, PathBuf};

/// Validierter Export-Zielpfad.
/// Validated export target path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedExportPath(pub PathBuf);

/// Zulässige Dateiendungen für Exporte / Allowed file extensions for exports
const ALLOWED_EXTENSIONS: &[&str] = &["csv", "html", "json"];

/// Ergebnis der Exportpfad-Validierung — unterscheidet neue von bereits vorhandenen Dateien.
/// Result of export path validation — distinguishes new from already-existing files.
#[derive(Debug)]
pub enum ExportPathStatus {
    /// Path is valid; the target file does not yet exist.
    New(ValidatedExportPath),
    /// Path is valid; the target file already exists and would be overwritten.
    Exists(ValidatedExportPath),
}

impl ExportPathStatus {
    pub fn path(&self) -> &ValidatedExportPath {
        match self {
            ExportPathStatus::New(p) | ExportPathStatus::Exists(p) => p,
        }
    }
}

/// Validates a user-supplied export path.
///
/// Checks:
/// - Not empty, no null bytes
/// - Extension is one of: .csv, .html, .json
/// - Parent directory exists
///
/// Returns `ExportPathStatus::Exists` when the target file is already present
/// so the caller can ask the user for confirmation before overwriting.
pub fn validate_export_path(input: &str) -> Result<ExportPathStatus, CoreError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CoreError::Validation(
            "Export path must not be empty".into(),
        ));
    }
    if trimmed.contains('\0') {
        return Err(CoreError::Validation(
            "Export path must not contain null bytes".into(),
        ));
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
                "Export path must have a recognized extension (.csv, .html, .json): {trimmed}"
            )));
        }
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = if parent == Path::new("") {
        Path::new(".")
    } else {
        parent
    };
    if !parent.exists() {
        return Err(CoreError::Validation(format!(
            "Export directory does not exist: {}",
            parent.display()
        )));
    }

    let validated = ValidatedExportPath(path.clone());
    if path.exists() {
        Ok(ExportPathStatus::Exists(validated))
    } else {
        Ok(ExportPathStatus::New(validated))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_path_rejected() {
        assert!(validate_export_path("").is_err());
    }

    #[test]
    fn unknown_extension_rejected() {
        assert!(validate_export_path(r"C:\reports\output.txt").is_err());
    }

    #[test]
    fn no_extension_rejected() {
        assert!(validate_export_path(r"C:\reports\output").is_err());
    }

    #[test]
    fn nonexistent_directory_rejected() {
        // Use a path whose parent cannot exist on any machine
        let result = validate_export_path(r"C:\__no_such_dir_7f3a9b__\report.csv");
        assert!(result.is_err());
    }

    #[test]
    fn existing_directory_with_csv_accepted() {
        // Write to a temp-style path whose parent (system temp) is guaranteed to exist
        let tmp = std::env::temp_dir().join("adpa_test_export_validation.csv");
        let input = tmp.to_string_lossy().into_owned();
        let result = validate_export_path(&input);
        // Parent (temp dir) exists, so should be Ok
        assert!(result.is_ok());
        // Clean up if the file was created (it won't be — validate doesn't write)
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn existing_file_returns_exists_status() {
        let tmp = std::env::temp_dir().join("adpa_test_export_exists.html");
        std::fs::write(&tmp, b"").unwrap();
        let input = tmp.to_string_lossy().into_owned();
        let result = validate_export_path(&input).unwrap();
        assert!(matches!(result, ExportPathStatus::Exists(_)));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn new_file_returns_new_status() {
        let tmp = std::env::temp_dir().join("adpa_test_export_new_file_abc123.json");
        // Ensure file doesn't exist
        let _ = std::fs::remove_file(&tmp);
        let input = tmp.to_string_lossy().into_owned();
        let result = validate_export_path(&input).unwrap();
        assert!(matches!(result, ExportPathStatus::New(_)));
    }
}
