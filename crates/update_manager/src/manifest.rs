//! Manifest-Schema für signierte Update-Pakete.
//! Manifest schema for signed update packages.
//!
//! Ein Manifest beschreibt ein Update vollständig: Zielversion, Kanal,
//! Plattform-Constraint, Liste der enthaltenen Dateien mit SHA-256-Hash
//! und eine getrennt gespeicherte Signatur (Base64) über das kanonisierte
//! Manifest. Die eigentliche Krypto-Backend-Wahl (Ed25519 / RSA-PSS / …)
//! steckt im `SignatureVerifier`-Trait und nicht im Manifest selbst — so
//! kann der Verifier ausgetauscht werden, ohne das Schema zu brechen.
//!
//! A manifest fully describes an update: target version, channel, platform
//! constraint, file list with SHA-256 hashes, and a separately stored Base64
//! signature over the canonicalized manifest. The cryptographic backend
//! (Ed25519 / RSA-PSS / …) lives in the `SignatureVerifier` trait, not in
//! the manifest, so the verifier can be swapped without breaking the schema.

use adpa_core::error::CoreError;
use serde::{Deserialize, Serialize};

use crate::UpdateChannel;

/// Erlaubte Zielplattformen — entspricht der Read-only-Constraint von Windows.
/// Allowed target platforms — matches the Windows-only read-only constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetPlatform {
    #[serde(rename = "windows-x86_64")]
    WindowsX86_64,
    #[serde(rename = "windows-aarch64")]
    WindowsAarch64,
}

/// Eintrag pro Datei innerhalb eines Update-Pakets.
/// Per-file entry inside an update package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFile {
    /// Relativer Zielpfad innerhalb des Installationsverzeichnisses.
    /// Relative target path inside the installation directory.
    pub path: String,
    /// SHA-256 als lowercase-Hex-String (64 Zeichen).
    /// SHA-256 as a lowercase hex string (64 characters).
    pub sha256: String,
    /// Dateigröße in Byte — zusätzlicher Sanity-Check gegen abgeschnittene
    /// Downloads, bevor überhaupt gehasht wird.
    /// File size in bytes — additional sanity check against truncated
    /// downloads before any hashing happens.
    pub size_bytes: u64,
}

/// Vollständiges, validierbares Update-Manifest.
/// Complete, validatable update manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateManifest {
    /// Schemaversion des Manifests selbst — entkoppelt von Anwendungsversion.
    /// Manifest schema version itself — decoupled from app version.
    pub manifest_version: u32,
    /// Zielversion der Anwendung (SemVer-Empfehlung, nicht erzwungen).
    /// Target application version (SemVer recommended, not enforced).
    pub app_version: String,
    pub channel: UpdateChannel,
    pub platform: TargetPlatform,
    /// ISO-8601-Zeitstempel des Manifests. Wird im Verifier gegen die System-
    /// uhr und gegen ggf. anti-rollback-Marker geprüft.
    /// ISO-8601 timestamp of the manifest. The verifier checks it against
    /// the system clock and optional anti-rollback markers.
    pub issued_at: String,
    pub files: Vec<ManifestFile>,
    /// Base64-kodierte Signatur über den kanonisierten Manifest-Body
    /// (alles ohne das Feld `signature` selbst).
    /// Base64-encoded signature over the canonicalized manifest body
    /// (everything without the `signature` field itself).
    pub signature: String,
}

impl UpdateManifest {
    /// Parst und validiert ein Manifest aus JSON.
    /// Parses and validates a manifest from JSON.
    pub fn from_json(input: &str) -> Result<Self, CoreError> {
        let parsed: Self = serde_json::from_str(input)
            .map_err(|e| CoreError::Validation(format!("Invalid manifest JSON: {e}")))?;
        parsed.validate_schema()?;
        Ok(parsed)
    }

    /// Strukturelle Validierung — vor jeder weiteren Verarbeitung.
    /// Structural validation — runs before any further processing.
    ///
    /// Reine Schema-Prüfung; Signatur und Datei-Hashes prüft der Verifier.
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
            if f.path.trim().is_empty() {
                return Err(CoreError::Validation("file.path must not be empty".into()));
            }
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
            // Pfad-Traversal verhindern. Eine harmlos aussehende `..`-Sequenz
            // im Manifest darf nie aus dem Installationsverzeichnis zeigen.
            // Prevent path traversal. A harmless-looking `..` sequence in the
            // manifest must never point outside the install directory.
            if f.path.contains("..") || f.path.starts_with('/') || f.path.starts_with('\\') {
                return Err(CoreError::Validation(format!(
                    "file '{}' contains unsafe path traversal",
                    f.path
                )));
            }
        }
        Ok(())
    }

    /// Kanonisierte JSON-Repräsentation des signierbaren Manifest-Body.
    ///
    /// Wir entfernen das Feld `signature` und serialisieren die übrigen
    /// Felder deterministisch. Das ist die Eingabe, gegen die der
    /// `SignatureVerifier` die Base64-Signatur prüft.
    ///
    /// Canonical JSON representation of the signable manifest body.
    ///
    /// We strip the `signature` field and serialize the remaining fields
    /// deterministically. This is the input the `SignatureVerifier` checks
    /// the Base64 signature against.
    pub fn signable_bytes(&self) -> Result<Vec<u8>, CoreError> {
        let mut clone = self.clone();
        clone.signature = String::new();
        // serde_json schreibt Felder in Struktur-Reihenfolge — bei festen
        // Strukturen ist das deterministisch genug für unsere Zwecke.
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
        assert!(format!("{err}").contains("path traversal"));
    }

    #[test]
    fn rejects_zero_byte_file() {
        let json = valid_manifest_json().replace("\"size_bytes\": 1024", "\"size_bytes\": 0");
        let err = UpdateManifest::from_json(&json).unwrap_err();
        assert!(format!("{err}").contains("size_bytes"));
    }

    #[test]
    fn signable_bytes_omit_signature_field() {
        let m = UpdateManifest::from_json(&valid_manifest_json()).unwrap();
        let bytes = m.signable_bytes().unwrap();
        let as_str = String::from_utf8(bytes).unwrap();
        // Das Feld `signature` muss leer im signable body sein —
        // sonst signiert man sich selbst.
        // The `signature` field must be empty in the signable body —
        // otherwise the signature would cover itself.
        assert!(as_str.contains("\"signature\":\"\""));
        assert!(!as_str.contains("AAAA"));
    }
}
