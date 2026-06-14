// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Manifest schema for signed update packages.
//!
//!
//! A manifest fully describes an update: target version, channel, platform
//! constraint, file list with SHA-256 hashes, and a separately stored Base64
//! signature over the canonicalized manifest. The cryptographic backend
//! (Ed25519 / RSA-PSS / …) lives in the `SignatureVerifier` trait, not in
//! the manifest, so the verifier can be swapped without breaking the schema.

use adpa_core::error::CoreError;
use serde::{Deserialize, Serialize};

use crate::UpdateChannel;

/// In Windows-Pfadkomponenten verbotene Zeichen — gleicher Satz wie in
/// Characters forbidden inside Windows path components — same set as in
/// [`validation::path`] so manifest paths are not accepted more leniently
/// than user-supplied paths.
const FORBIDDEN_PATH_CHARS: &[char] = &['<', '>', '"', '|', '?', '*'];

/// Endung.
/// Reserved Windows device names (case-insensitive). A segment whose stem
/// matches one of these is invalid regardless of its extension.
const RESERVED_DEVICE_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
    "COM8", "COM9", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Pfadangriffe.
///
///
/// Lehnt ab:
/// - Null-Bytes
///
///
/// Validates a relative manifest target path against Windows-specific
/// path-shape attacks.
///
/// Accepts: `bin/stars.exe`, `bin\stars.exe`, `docs/en/handbook.html`.
///
/// Rejects:
/// - empty paths
/// - absolute paths with drive letters (`C:\…`, `c:foo` — via the `:`
///   ban in segments)
/// - UNC prefixes (`\\…`, `//…`) and long-path prefixes (`\\?\…`)
/// - `.` and `..` segments (traversal)
/// - empty segments (`a//b`, `a\\\\b`) — prevents UNC spoofing
/// - reserved Windows device names (`NUL`, `CON`, `COM1`, …)
/// - ADS notation (`file.txt:ads`) — same `:` filter as for drives
/// - characters in [`FORBIDDEN_PATH_CHARS`] and control characters
/// - NUL bytes
///
/// Closes ChatGPT code review 2026-05-31 finding 6.
pub fn validate_manifest_relative_path(path: &str) -> Result<(), CoreError> {
    if path.is_empty() {
        return Err(CoreError::Validation("file.path must not be empty".into()));
    }
    if path.contains('\0') {
        return Err(CoreError::Validation(format!(
            "file path '{path}' must not contain null bytes"
        )));
    }
    // Catch the long-path prefix before the `\`-split kicks in.
    if path.starts_with(r"\\?\") || path.starts_with("//?/") {
        return Err(CoreError::Validation(format!(
            "file path '{path}' must be relative (Windows long-path prefix not allowed)"
        )));
    }
    // UNC prefix.
    if path.starts_with(r"\\") || path.starts_with("//") {
        return Err(CoreError::Validation(format!(
            "file path '{path}' must be relative (UNC prefix not allowed)"
        )));
    }
    // zeigen.
    // Leading separators — path would otherwise point outside the
    // install tree.
    if path.starts_with('\\') || path.starts_with('/') {
        return Err(CoreError::Validation(format!(
            "file path '{path}' must be relative (leading separator not allowed)"
        )));
    }
    // Check each segment — we accept both `\` and `/` as separators
    // because manifests may be written platform-neutrally (installation
    // still runs on Windows).
    let segments: Vec<&str> = path.split(['\\', '/']).collect();
    for segment in &segments {
        check_manifest_segment(segment, path)?;
    }
    Ok(())
}

fn check_manifest_segment(segment: &str, full_path: &str) -> Result<(), CoreError> {
    if segment.is_empty() {
        return Err(CoreError::Validation(format!(
            "file path '{full_path}' contains an empty segment (consecutive separators)"
        )));
    }
    if segment == "." || segment == ".." {
        return Err(CoreError::Validation(format!(
            "file path '{full_path}' contains a '{segment}' segment — traversal not allowed"
        )));
    }
    if let Some(c) = segment.chars().find(|c| c.is_control()) {
        return Err(CoreError::Validation(format!(
            "file path '{full_path}' segment '{segment}' contains a control character (U+{:04X})",
            c as u32
        )));
    }
    if let Some(bad) = segment.chars().find(|c| FORBIDDEN_PATH_CHARS.contains(c)) {
        return Err(CoreError::Validation(format!(
            "file path '{full_path}' segment '{segment}' contains a forbidden character '{bad}'"
        )));
    }
    // `:` covers both drive letters (`C:`) and ADS notation
    // (`file.txt:ads`) — neither is acceptable in a manifest.
    if segment.contains(':') {
        return Err(CoreError::Validation(format!(
            "file path '{full_path}' segment '{segment}' must not contain ':'"
        )));
    }
    // Reserved Windows device name — check the stem without extension.
    let stem = segment.split('.').next().unwrap_or(segment);
    if RESERVED_DEVICE_NAMES
        .iter()
        .any(|r| r.eq_ignore_ascii_case(stem))
    {
        return Err(CoreError::Validation(format!(
            "file path '{full_path}' segment '{segment}' uses reserved Windows device name '{stem}'"
        )));
    }
    Ok(())
}

/// Allowed target platforms — matches the Windows-only read-only constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetPlatform {
    #[serde(rename = "windows-x86_64")]
    WindowsX86_64,
    #[serde(rename = "windows-aarch64")]
    WindowsAarch64,
}

/// Per-file entry inside an update package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFile {
    /// Relative target path inside the installation directory.
    pub path: String,
    /// SHA-256 als lowercase-Hex-String (64 Zeichen).
    /// SHA-256 as a lowercase hex string (64 characters).
    pub sha256: String,
    /// File size in bytes — additional sanity check against truncated
    /// downloads before any hashing happens.
    pub size_bytes: u64,
}

/// Complete, validatable update manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateManifest {
    /// Schema version of the manifest itself — decoupled from the application version.
    /// Manifest schema version itself — decoupled from app version.
    pub manifest_version: u32,
    /// Target application version (SemVer recommended, not enforced).
    pub app_version: String,
    pub channel: UpdateChannel,
    pub platform: TargetPlatform,
    /// ISO-8601 timestamp of the manifest. The verifier checks it against
    /// the system clock and optional anti-rollback markers.
    pub issued_at: String,
    pub files: Vec<ManifestFile>,
    /// Base64-encoded signature over the canonicalized manifest body
    /// (everything without the `signature` field itself).
    pub signature: String,
}

impl UpdateManifest {
    /// Parses and validates a manifest from JSON.
    pub fn from_json(input: &str) -> Result<Self, CoreError> {
        let parsed: Self = serde_json::from_str(input)
            .map_err(|e| CoreError::Validation(format!("Invalid manifest JSON: {e}")))?;
        parsed.validate_schema()?;
        Ok(parsed)
    }

    /// Structural validation — before any further processing.
    /// Structural validation — runs before any further processing.
    ///
    /// Pure schema check; signature and file hashes are the verifier's job.
    pub fn validate_schema(&self) -> Result<(), CoreError> {
        if self.manifest_version == 0 {
            return Err(CoreError::Validation(
                "manifest_version must be >= 1".into(),
            ));
        }
        if self.app_version.trim().is_empty() {
            return Err(CoreError::Validation(
                "app_version must not be empty".into(),
            ));
        }
        if self.issued_at.trim().is_empty() {
            return Err(CoreError::Validation("issued_at must not be empty".into()));
        }
        if self.signature.trim().is_empty() {
            return Err(CoreError::Validation(
                "signature must not be empty — unsigned manifests are rejected".into(),
            ));
        }
        if self.files.is_empty() {
            return Err(CoreError::Validation(
                "files must contain at least one entry".into(),
            ));
        }
        for f in &self.files {
            // Windows-safe path validation: blocks absolute paths, drive
            // letters, UNC/long-path prefixes, `.`/`..`, empty segments,
            // `:` (drive/ADS), reserved device names and forbidden chars.
            validate_manifest_relative_path(&f.path)?;
            // SHA-256 als Hex: exakt 64 Zeichen, alle hex.
            // SHA-256 as hex: exactly 64 chars, all hex digits.
            if f.sha256.len() != 64 || !f.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(CoreError::Validation(format!(
                    "file '{}' has invalid sha256 (must be 64 hex chars)",
                    f.path
                )));
            }
            if f.size_bytes == 0 {
                return Err(CoreError::Validation(format!(
                    "file '{}' size_bytes must be > 0",
                    f.path
                )));
            }
        }
        Ok(())
    }

    ///
    ///
    /// Canonical JSON representation of the signable manifest body.
    ///
    /// We strip the `signature` field and serialize the remaining fields
    /// deterministically. This is the input the `SignatureVerifier` checks
    /// the Base64 signature against.
    pub fn signable_bytes(&self) -> Result<Vec<u8>, CoreError> {
        let mut clone = self.clone();
        clone.signature = String::new();
        // serde_json writes fields in struct order — for fixed structs that
        // is deterministic enough for our purposes.
        serde_json::to_vec(&clone)
            .map_err(|e| CoreError::Validation(format!("Cannot canonicalize manifest: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest_json() -> String {
        r#"{
            "manifest_version": 1,
            "app_version": "0.3.0",
            "channel": "Stable",
            "platform": "windows-x86_64",
            "issued_at": "2026-05-25T12:00:00Z",
            "files": [
                {
                    "path": "stars.exe",
                    "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                    "size_bytes": 1024
                }
            ],
            "signature": "AAAA"
        }"#
        .to_owned()
    }

    #[test]
    fn parses_valid_manifest() {
        let m = UpdateManifest::from_json(&valid_manifest_json()).unwrap();
        assert_eq!(m.app_version, "0.3.0");
        assert_eq!(m.platform, TargetPlatform::WindowsX86_64);
        assert_eq!(m.files.len(), 1);
    }

    #[test]
    fn rejects_unsigned_manifest() {
        let json = valid_manifest_json().replace("\"AAAA\"", "\"\"");
        let err = UpdateManifest::from_json(&json).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("signature must not be empty"),
            "unsigned manifests must be rejected, got: {msg}"
        );
    }

    #[test]
    fn rejects_short_sha256() {
        let json = valid_manifest_json().replace(
            "0000000000000000000000000000000000000000000000000000000000000000",
            "deadbeef",
        );
        let err = UpdateManifest::from_json(&json).unwrap_err();
        assert!(format!("{err}").contains("invalid sha256"));
    }

    #[test]
    fn rejects_path_traversal() {
        let json = valid_manifest_json().replace("stars.exe", "../etc/payload.exe");
        let err = UpdateManifest::from_json(&json).unwrap_err();
        // New error message from validate_manifest_relative_path; phrased
        // more precisely than the old "path traversal" substring.
        assert!(format!("{err}").contains("traversal"));
    }

    #[test]
    fn rejects_zero_byte_file() {
        let json = valid_manifest_json().replace("\"size_bytes\": 1024", "\"size_bytes\": 0");
        let err = UpdateManifest::from_json(&json).unwrap_err();
        assert!(format!("{err}").contains("size_bytes"));
    }

    // ----------------------------------------------------------------
    // Finding 6 — Windows-sichere Pfadvalidierung
    // Finding 6 — Windows-safe path validation
    // ----------------------------------------------------------------

    #[test]
    fn relative_path_accepts_normal_relative_paths() {
        for ok in &[
            "stars.exe",
            "bin/stars.exe",
            "bin\\stars.exe",
            "docs/en/handbook.html",
            "docs\\en\\handbook.html",
            "data/x.bin",
            "a/b/c/d/e/file.txt",
        ] {
            validate_manifest_relative_path(ok)
                .unwrap_or_else(|e| panic!("expected '{ok}' to be valid, got: {e}"));
        }
    }

    #[test]
    fn relative_path_rejects_absolute_with_drive_letter() {
        for bad in &[r"C:\Temp\evil.exe", r"c:\foo", r"D:\stars.exe"] {
            assert!(
                validate_manifest_relative_path(bad).is_err(),
                "must reject absolute drive path: {bad}"
            );
        }
    }

    #[test]
    fn relative_path_rejects_drive_relative_with_colon() {
        // `C:evil.exe` is Windows "drive-relative": not absolute in the
        for bad in &["C:evil.exe", "c:foo", "Z:weird"] {
            assert!(
                validate_manifest_relative_path(bad).is_err(),
                "must reject drive-relative path: {bad}"
            );
        }
    }

    #[test]
    fn relative_path_rejects_parent_dir_traversal() {
        for bad in &[r"dir\..\x", "dir/../x", "..", "../etc/passwd", r"..\evil"] {
            let err = validate_manifest_relative_path(bad).unwrap_err();
            assert!(
                format!("{err}").contains("traversal"),
                "must flag traversal for '{bad}', got: {err}"
            );
        }
    }

    #[test]
    fn relative_path_rejects_current_dir_segment() {
        for bad in &[r".\x", "./x", "a/./b"] {
            let err = validate_manifest_relative_path(bad).unwrap_err();
            assert!(
                format!("{err}").contains("traversal"),
                "must flag '.' segment for '{bad}', got: {err}"
            );
        }
    }

    #[test]
    fn relative_path_rejects_reserved_device_names() {
        for bad in &["NUL", "CON", "AUX", "PRN", "COM1", "LPT9", "nul.exe"] {
            assert!(
                validate_manifest_relative_path(bad).is_err(),
                "must reject reserved device name: {bad}"
            );
        }
    }

    #[test]
    fn relative_path_rejects_ads_notation() {
        // Alternate Data Streams: `file.txt:ads` would write to a hidden
        // NTFS stream — clear no in a manifest.
        let err = validate_manifest_relative_path("file.txt:ads").unwrap_err();
        assert!(format!("{err}").contains("':'"));
    }

    #[test]
    fn relative_path_rejects_unc_prefix() {
        for bad in &[r"\\server\share\file.exe", "//server/share/file.exe"] {
            assert!(
                validate_manifest_relative_path(bad).is_err(),
                "must reject UNC prefix: {bad}"
            );
        }
    }

    #[test]
    fn relative_path_rejects_long_path_prefix() {
        for bad in &[r"\\?\C:\evil.exe", r"\\?\UNC\srv\sh\x", "//?/C:/evil.exe"] {
            assert!(
                validate_manifest_relative_path(bad).is_err(),
                "must reject long-path prefix: {bad}"
            );
        }
    }

    #[test]
    fn relative_path_rejects_leading_separator() {
        for bad in &["/abs/path", "\\abs\\path"] {
            assert!(
                validate_manifest_relative_path(bad).is_err(),
                "must reject leading separator: {bad}"
            );
        }
    }

    #[test]
    fn relative_path_rejects_empty_segments() {
        for bad in &["a//b", "a\\\\b", "x/", "y\\"] {
            assert!(
                validate_manifest_relative_path(bad).is_err(),
                "must reject empty segment in: {bad:?}"
            );
        }
    }

    #[test]
    fn relative_path_rejects_forbidden_chars() {
        for bad in &[
            "bad<name",
            "bad>name",
            "bad\"name",
            "bad|name",
            "bad?name",
            "bad*name",
        ] {
            assert!(
                validate_manifest_relative_path(bad).is_err(),
                "must reject forbidden char in: {bad}"
            );
        }
    }

    #[test]
    fn relative_path_rejects_control_chars_and_null() {
        assert!(validate_manifest_relative_path("bad\x07name").is_err());
        assert!(validate_manifest_relative_path("bad\0byte").is_err());
    }

    #[test]
    fn relative_path_rejects_empty() {
        let err = validate_manifest_relative_path("").unwrap_err();
        assert!(format!("{err}").contains("not be empty"));
    }

    #[test]
    fn signable_bytes_omit_signature_field() {
        let m = UpdateManifest::from_json(&valid_manifest_json()).unwrap();
        let bytes = m.signable_bytes().unwrap();
        let as_str = String::from_utf8(bytes).unwrap();
        // sonst signiert man sich selbst.
        // The `signature` field must be empty in the signable body —
        // otherwise the signature would cover itself.
        assert!(as_str.contains("\"signature\":\"\""));
        assert!(!as_str.contains("AAAA"));
    }
}
