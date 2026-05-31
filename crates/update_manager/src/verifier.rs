//! Signaturprüfung als pluggable Trait.
//! Signature verification as a pluggable trait.
//!
//! Wir trennen die Manifest-Schema-Prüfung (rein strukturell) von der
//! kryptografischen Verifikation (algorithmus-spezifisch). Ein produktiver
//! Verifier (z. B. Ed25519 mit fest verdrahtetem Public-Key) wird später
//! hinter diesem Trait implementiert; bis dahin steht ein Reject-By-Default-
//! Stub bereit, damit kein ungeprüftes Update durchrutschen kann.
//!
//! We separate manifest schema validation (purely structural) from
//! cryptographic verification (algorithm-specific). A production verifier
//! (e.g. Ed25519 with a hard-wired public key) will be implemented behind
//! this trait later; until then a reject-by-default stub is in place so no
//! unverified update can sneak through.

use adpa_core::error::CoreError;
use sha2::{Digest, Sha256};

use crate::manifest::{ManifestFile, UpdateManifest};

/// Backend für die Signaturprüfung. Implementierungen wählen den
/// kryptografischen Algorithmus (Ed25519, RSA-PSS, …) und tragen den
/// Public-Key.
///
/// Signature verification backend. Implementations choose the cryptographic
/// algorithm (Ed25519, RSA-PSS, …) and carry the public key.
pub trait SignatureVerifier: Send + Sync {
    /// Prüft die Base64-Signatur `signature_b64` gegen den Body `body`.
    /// Verifies the Base64 signature `signature_b64` against the body `body`.
    fn verify(&self, body: &[u8], signature_b64: &str) -> Result<(), CoreError>;
}

/// Reject-by-default-Verifier — lehnt jede Signatur ab. Wird als Default
/// genutzt, solange kein produktiver Verifier konfiguriert ist. Verhindert,
/// dass ein nicht konfiguriertes System versehentlich Updates akzeptiert.
///
/// Reject-by-default verifier — refuses any signature. Used as the default
/// while no production verifier is configured. Prevents an unconfigured
/// system from accidentally accepting updates.
pub struct RejectAllVerifier;

impl SignatureVerifier for RejectAllVerifier {
    fn verify(&self, _body: &[u8], _signature_b64: &str) -> Result<(), CoreError> {
        Err(CoreError::Validation(
            "no signature verifier configured — refusing to trust update manifest".into(),
        ))
    }
}

/// Berechnet SHA-256 eines Byte-Slices und gibt das Ergebnis als
/// lowercase-Hex zurück. Wird sowohl für Datei-Hashes als auch in Tests
/// verwendet.
///
/// Computes SHA-256 of a byte slice and returns the result as lowercase
/// hex. Used both for file hashes and in tests.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Prüft eine einzelne Datei gegen ihren Manifest-Eintrag (Größe + SHA-256).
/// Verifies a single file against its manifest entry (size + SHA-256).
pub fn verify_file_bytes(entry: &ManifestFile, content: &[u8]) -> Result<(), CoreError> {
    if content.len() as u64 != entry.size_bytes {
        return Err(CoreError::Validation(format!(
            "file '{}': size mismatch (expected {}, got {})",
            entry.path,
            entry.size_bytes,
            content.len()
        )));
    }
    let actual = sha256_hex(content);
    if actual != entry.sha256.to_ascii_lowercase() {
        return Err(CoreError::Validation(format!(
            "file '{}': sha256 mismatch (expected {}, got {})",
            entry.path, entry.sha256, actual
        )));
    }
    Ok(())
}

/// Komplette Prüfung eines Manifests: Schema → Signatur → optional
/// Dateiinhalte. Der Caller liefert die Datei-Bytes als (path, content)-
/// Paare; fehlende Dateien führen zu einem Fehler.
///
/// Complete manifest check: schema → signature → optional file contents.
/// The caller supplies file bytes as (path, content) pairs; missing files
/// produce an error.
pub fn verify_manifest<V: SignatureVerifier>(
    manifest: &UpdateManifest,
    verifier: &V,
    file_contents: &[(&str, &[u8])],
) -> Result<(), CoreError> {
    manifest.validate_schema()?;
    let body = manifest.signable_bytes()?;
    verifier.verify(&body, &manifest.signature)?;

    for entry in &manifest.files {
        let content = file_contents
            .iter()
            .find(|(p, _)| *p == entry.path)
            .map(|(_, c)| *c)
            .ok_or_else(|| {
                CoreError::Validation(format!(
                    "file '{}' listed in manifest but not provided to verifier",
                    entry.path
                ))
            })?;
        verify_file_bytes(entry, content)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{TargetPlatform, UpdateManifest};
    use crate::UpdateChannel;

    /// Test-Verifier, der jede nicht leere Signatur akzeptiert — ausschließlich
    /// zum Testen der Workflow-Verkettung. NICHT für produktive Nutzung.
    /// Test-only verifier accepting any non-empty signature — only for testing
    /// the workflow chain. NOT for production use.
    struct AcceptAnyVerifier;
    impl SignatureVerifier for AcceptAnyVerifier {
        fn verify(&self, _body: &[u8], sig: &str) -> Result<(), CoreError> {
            if sig.is_empty() {
                Err(CoreError::Validation("empty signature".into()))
            } else {
                Ok(())
            }
        }
    }

    fn manifest_for(path: &str, content: &[u8]) -> UpdateManifest {
        UpdateManifest {
            manifest_version: 1,
            app_version: "0.3.0".into(),
            channel: UpdateChannel::Stable,
            platform: TargetPlatform::WindowsX86_64,
            issued_at: "2026-05-25T12:00:00Z".into(),
            files: vec![ManifestFile {
                path: path.into(),
                sha256: sha256_hex(content),
                size_bytes: content.len() as u64,
            }],
            signature: "fake-signature".into(),
        }
    }

    #[test]
    fn sha256_hex_known_vector() {
        // "abc" → ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn reject_all_verifier_blocks_everything() {
        let r = RejectAllVerifier;
        let err = r.verify(b"body", "sig").unwrap_err();
        assert!(format!("{err}").contains("no signature verifier configured"));
    }

    #[test]
    fn verify_file_bytes_accepts_matching_content() {
        let content = b"hello world";
        let entry = ManifestFile {
            path: "x.bin".into(),
            sha256: sha256_hex(content),
            size_bytes: content.len() as u64,
        };
        verify_file_bytes(&entry, content).unwrap();
    }

    #[test]
    fn verify_file_bytes_rejects_size_mismatch() {
        let content = b"hello world";
        let mut entry = ManifestFile {
            path: "x.bin".into(),
            sha256: sha256_hex(content),
            size_bytes: 999,
        };
        entry.size_bytes = 999;
        let err = verify_file_bytes(&entry, content).unwrap_err();
        assert!(format!("{err}").contains("size mismatch"));
    }

    #[test]
    fn verify_file_bytes_rejects_hash_mismatch() {
        let content = b"hello world";
        let entry = ManifestFile {
            path: "x.bin".into(),
            // intentionally wrong hash
            sha256: "0".repeat(64),
            size_bytes: content.len() as u64,
        };
        let err = verify_file_bytes(&entry, content).unwrap_err();
        assert!(format!("{err}").contains("sha256 mismatch"));
    }

    #[test]
    fn verify_manifest_full_flow_succeeds() {
        let content: &[u8] = b"hello world";
        let m = manifest_for("stars.exe", content);
        verify_manifest(&m, &AcceptAnyVerifier, &[("stars.exe", content)]).unwrap();
    }

    #[test]
    fn verify_manifest_rejects_when_signature_verifier_fails() {
        let content: &[u8] = b"hello world";
        let mut m = manifest_for("stars.exe", content);
        m.signature = String::new();
        // Schema-Validierung greift bereits vor dem Signatur-Verifier.
        // Schema validation triggers before the signature verifier.
        let err = verify_manifest(&m, &AcceptAnyVerifier, &[("stars.exe", content)]).unwrap_err();
        assert!(format!("{err}").contains("signature must not be empty"));
    }

    #[test]
    fn verify_manifest_rejects_when_file_content_missing() {
        let content: &[u8] = b"hello world";
        let m = manifest_for("stars.exe", content);
        let err = verify_manifest(&m, &AcceptAnyVerifier, &[]).unwrap_err();
        assert!(format!("{err}").contains("not provided to verifier"));
    }

    #[test]
    fn verify_manifest_rejects_when_file_bytes_tampered() {
        let original: &[u8] = b"hello world";
        let tampered: &[u8] = b"hello WORLD";
        let m = manifest_for("stars.exe", original);
        let err = verify_manifest(&m, &AcceptAnyVerifier, &[("stars.exe", tampered)]).unwrap_err();
        assert!(format!("{err}").contains("sha256 mismatch"));
    }

    /// Per-Default rejected: ohne konfigurierten Verifier akzeptiert das
    /// System nichts. Das ist die wichtigste Sicherheitseigenschaft.
    /// Reject-by-default: without a configured verifier the system accepts
    /// nothing. This is the single most important security property.
    #[test]
    fn default_verifier_rejects_even_well_formed_manifest() {
        let content: &[u8] = b"hello world";
        let m = manifest_for("stars.exe", content);
        let err = verify_manifest(&m, &RejectAllVerifier, &[("stars.exe", content)]).unwrap_err();
        assert!(format!("{err}").contains("no signature verifier configured"));
    }
}
