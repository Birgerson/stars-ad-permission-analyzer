// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Signature verification as a pluggable trait.
//!
//! kryptografischen Verifikation (algorithmus-spezifisch). Ein produktiver
//!
//! We separate manifest schema validation (purely structural) from
//! cryptographic verification (algorithm-specific). A production verifier
//! (e.g. Ed25519 with a hard-wired public key) will be implemented behind
//! this trait later; until then a reject-by-default stub is in place so no
//! unverified update can sneak through.

use std::cmp::Ordering;

use adpa_core::error::CoreError;
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};

use crate::manifest::{ManifestFile, TargetPlatform, UpdateManifest};
use crate::UpdateChannel;

/// Public-Key.
///
/// Signature verification backend. Implementations choose the cryptographic
/// algorithm (Ed25519, RSA-PSS, …) and carry the public key.
pub trait SignatureVerifier: Send + Sync {
    /// Verifies the Base64 signature `signature_b64` against the body `body`.
    fn verify(&self, body: &[u8], signature_b64: &str) -> Result<(), CoreError>;
}

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

/// verwendet.
///
/// Computes SHA-256 of a byte slice and returns the result as lowercase
/// hex. Used both for file hashes and in tests.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

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

///
/// [`verify_update_policy`].
///
///
/// Integrity check for a manifest: schema → signature → file contents.
///
/// This function covers only cryptographic and structural correctness —
/// it does not decide whether the update applies to the current
/// installation (platform, channel, version, time). That policy check is
/// the job of [`verify_update_policy`].
///
/// The caller supplies file bytes as `(path, content)` pairs; missing
/// files produce an error.
///
/// Closes ChatGPT code review 2026-05-31 finding 7 (formerly
/// `verify_manifest`, which was misleadingly described as a "complete
/// check").
pub fn verify_manifest_integrity<V: SignatureVerifier>(
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

///
/// [`verify_update_policy`].
///
/// Policy context for releasing a manifest for installation.
///
/// Separates cryptographic integrity (see [`verify_manifest_integrity`])
/// from applicability on the target system: platform, channel, version
/// ordering and the time window. The caller builds this context from its
/// running configuration and the system clock and passes it to
/// [`verify_update_policy`].
#[derive(Debug, Clone)]
pub struct UpdatePolicyContext {
    /// Aktuell installierte Version (dotted numeric, z. B. `1.0.0`).
    /// Currently installed version (dotted numeric, e.g. `1.0.0`).
    pub current_version: String,
    /// Platform of the running installation.
    pub current_platform: TargetPlatform,
    /// Update channel released by the caller.
    pub allowed_channel: UpdateChannel,
    /// When `false`, manifests with a lower or equal version are rejected
    /// (no downgrade, no re-install).
    pub allow_downgrade: bool,
    /// `Utc::now()`, in Tests deterministisch.
    /// Reference time for the `issued_at` check — `Utc::now()` in
    /// production, deterministic in tests.
    pub now_utc: DateTime<Utc>,
    /// Maximum `now - issued_at` distance; older manifests are rejected.
    /// Negative values are illegal.
    pub max_age: Duration,
    /// Maximum `issued_at - now` distance; manifests issued further in
    /// the future are rejected (clock-skew tolerance).
    pub max_future_skew: Duration,
}

///
/// It validates in this order:
///
///    Zukunft.
///
/// Checks whether an integrity-verified manifest applies to the running
/// installation. Does not replace [`verify_manifest_integrity`] — both
/// must pass before an update is allowed. Validates, in order:
///
/// 1. Platform matches `current_platform`.
/// 2. Manifest channel matches `allowed_channel`.
/// 3. `app_version` is higher (numeric dotted) than `current_version`,
///    unless `allow_downgrade == true`.
/// 4. `issued_at` is ISO-8601 parsable.
/// 5. `issued_at` is no further than `max_future_skew` in the future.
/// 6. `issued_at` is no further than `max_age` in the past.
pub fn verify_update_policy(
    manifest: &UpdateManifest,
    policy: &UpdatePolicyContext,
) -> Result<(), CoreError> {
    if manifest.platform != policy.current_platform {
        return Err(CoreError::Validation(format!(
            "manifest platform {:?} does not match current platform {:?}",
            manifest.platform, policy.current_platform
        )));
    }
    if manifest.channel != policy.allowed_channel {
        return Err(CoreError::Validation(format!(
            "manifest channel {:?} does not match allowed channel {:?}",
            manifest.channel, policy.allowed_channel
        )));
    }
    let ordering = compare_dotted_versions(&manifest.app_version, &policy.current_version)?;
    if !policy.allow_downgrade && ordering != Ordering::Greater {
        return Err(CoreError::Validation(format!(
            "manifest app_version '{}' is not newer than current '{}' (downgrade not allowed)",
            manifest.app_version, policy.current_version
        )));
    }
    let issued_at = manifest.issued_at.parse::<DateTime<Utc>>().map_err(|e| {
        CoreError::Validation(format!(
            "manifest issued_at '{}' is not a valid ISO-8601 UTC timestamp: {e}",
            manifest.issued_at
        ))
    })?;
    if issued_at > policy.now_utc + policy.max_future_skew {
        return Err(CoreError::Validation(format!(
            "manifest issued_at '{}' is further than the allowed clock-skew tolerance ({}s) in the future",
            manifest.issued_at,
            policy.max_future_skew.num_seconds()
        )));
    }
    if policy.now_utc - issued_at > policy.max_age {
        return Err(CoreError::Validation(format!(
            "manifest issued_at '{}' is older than max_age ({}s) — refusing as potentially stale or replayed",
            manifest.issued_at,
            policy.max_age.num_seconds()
        )));
    }
    Ok(())
}

/// Vergleicht zwei punktgetrennte numerische Versionsstrings (z. B.
///
/// Compares two dotted-numeric version strings (e.g. `1.10.0` vs
/// `1.9.5`). Pre-release suffixes after `-` are dropped for comparison
/// because the project currently ships only plain
/// `major.minor.patch` versions. Non-numeric segments produce a
/// validation error — the caller must ensure both sides parse.
fn compare_dotted_versions(a: &str, b: &str) -> Result<Ordering, CoreError> {
    let trim_prerelease = |s: &str| {
        s.split('-')
            .next()
            .unwrap_or(s)
            .split('+')
            .next()
            .unwrap_or(s)
            .to_owned()
    };
    let a_core = trim_prerelease(a);
    let b_core = trim_prerelease(b);
    let parse = |s: &str| -> Result<Vec<u64>, CoreError> {
        s.split('.')
            .map(|seg| {
                seg.parse::<u64>().map_err(|e| {
                    CoreError::Validation(format!(
                        "version segment '{seg}' in '{s}' is not numeric: {e}"
                    ))
                })
            })
            .collect()
    };
    let a_parts = parse(&a_core)?;
    let b_parts = parse(&b_core)?;
    // Pad to the same length with 0 — `1.0` and `1.0.0` are equal.
    let len = a_parts.len().max(b_parts.len());
    for i in 0..len {
        let av = a_parts.get(i).copied().unwrap_or(0);
        let bv = b_parts.get(i).copied().unwrap_or(0);
        match av.cmp(&bv) {
            Ordering::Equal => continue,
            other => return Ok(other),
        }
    }
    Ok(Ordering::Equal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{TargetPlatform, UpdateManifest};
    use crate::UpdateChannel;

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
        verify_manifest_integrity(&m, &AcceptAnyVerifier, &[("stars.exe", content)]).unwrap();
    }

    #[test]
    fn verify_manifest_rejects_when_signature_verifier_fails() {
        let content: &[u8] = b"hello world";
        let mut m = manifest_for("stars.exe", content);
        m.signature = String::new();
        // Schema validation triggers before the signature verifier.
        let err = verify_manifest_integrity(&m, &AcceptAnyVerifier, &[("stars.exe", content)])
            .unwrap_err();
        assert!(format!("{err}").contains("signature must not be empty"));
    }

    #[test]
    fn verify_manifest_rejects_when_file_content_missing() {
        let content: &[u8] = b"hello world";
        let m = manifest_for("stars.exe", content);
        let err = verify_manifest_integrity(&m, &AcceptAnyVerifier, &[]).unwrap_err();
        assert!(format!("{err}").contains("not provided to verifier"));
    }

    #[test]
    fn verify_manifest_rejects_when_file_bytes_tampered() {
        let original: &[u8] = b"hello world";
        let tampered: &[u8] = b"hello WORLD";
        let m = manifest_for("stars.exe", original);
        let err = verify_manifest_integrity(&m, &AcceptAnyVerifier, &[("stars.exe", tampered)])
            .unwrap_err();
        assert!(format!("{err}").contains("sha256 mismatch"));
    }

    /// Reject-by-default: without a configured verifier the system accepts
    /// nothing. This is the single most important security property.
    #[test]
    fn default_verifier_rejects_even_well_formed_manifest() {
        let content: &[u8] = b"hello world";
        let m = manifest_for("stars.exe", content);
        let err = verify_manifest_integrity(&m, &RejectAllVerifier, &[("stars.exe", content)])
            .unwrap_err();
        assert!(format!("{err}").contains("no signature verifier configured"));
    }

    // ----------------------------------------------------------------
    // Finding 7 — verify_update_policy
    // ----------------------------------------------------------------

    fn fixed_now() -> DateTime<Utc> {
        "2026-06-01T12:00:00Z".parse().unwrap()
    }

    fn base_policy() -> UpdatePolicyContext {
        UpdatePolicyContext {
            current_version: "1.0.0".into(),
            current_platform: TargetPlatform::WindowsX86_64,
            allowed_channel: UpdateChannel::Stable,
            allow_downgrade: false,
            now_utc: fixed_now(),
            max_age: Duration::days(90),
            max_future_skew: Duration::minutes(5),
        }
    }

    fn policy_manifest(version: &str, issued_at: &str) -> UpdateManifest {
        UpdateManifest {
            manifest_version: 1,
            app_version: version.into(),
            channel: UpdateChannel::Stable,
            platform: TargetPlatform::WindowsX86_64,
            issued_at: issued_at.into(),
            files: vec![ManifestFile {
                path: "stars.exe".into(),
                sha256: sha256_hex(b"x"),
                size_bytes: 1,
            }],
            signature: "fake".into(),
        }
    }

    #[test]
    fn policy_accepts_newer_version_on_matching_platform_and_channel() {
        let m = policy_manifest("1.1.0", "2026-06-01T11:00:00Z");
        verify_update_policy(&m, &base_policy()).unwrap();
    }

    #[test]
    fn policy_rejects_wrong_platform() {
        let mut m = policy_manifest("1.1.0", "2026-06-01T11:00:00Z");
        m.platform = TargetPlatform::WindowsAarch64;
        let err = verify_update_policy(&m, &base_policy()).unwrap_err();
        assert!(format!("{err}").contains("platform"));
    }

    #[test]
    fn policy_rejects_wrong_channel() {
        let mut m = policy_manifest("1.1.0", "2026-06-01T11:00:00Z");
        m.channel = UpdateChannel::Preview;
        let err = verify_update_policy(&m, &base_policy()).unwrap_err();
        assert!(format!("{err}").contains("channel"));
    }

    #[test]
    fn policy_rejects_downgrade_by_default() {
        let m = policy_manifest("0.9.0", "2026-06-01T11:00:00Z");
        let err = verify_update_policy(&m, &base_policy()).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("not newer") && msg.contains("downgrade not allowed"),
            "got: {msg}"
        );
    }

    #[test]
    fn policy_rejects_equal_version() {
        // A re-install must not slip through — `current == manifest` is not
        let m = policy_manifest("1.0.0", "2026-06-01T11:00:00Z");
        let err = verify_update_policy(&m, &base_policy()).unwrap_err();
        assert!(format!("{err}").contains("not newer"));
    }

    #[test]
    fn policy_accepts_downgrade_when_explicitly_allowed() {
        let m = policy_manifest("0.9.0", "2026-06-01T11:00:00Z");
        let mut policy = base_policy();
        policy.allow_downgrade = true;
        verify_update_policy(&m, &policy).unwrap();
    }

    #[test]
    fn policy_rejects_issued_at_in_far_future() {
        // Toleranz hinaus.
        // One hour ahead of `now_utc` — well past the five-minute skew
        // tolerance.
        let m = policy_manifest("1.1.0", "2026-06-01T13:00:00Z");
        let err = verify_update_policy(&m, &base_policy()).unwrap_err();
        assert!(format!("{err}").contains("future"));
    }

    #[test]
    fn policy_accepts_issued_at_within_skew_tolerance() {
        // Two minutes ahead — within the default tolerance.
        let m = policy_manifest("1.1.0", "2026-06-01T12:02:00Z");
        verify_update_policy(&m, &base_policy()).unwrap();
    }

    #[test]
    fn policy_rejects_issued_at_too_old() {
        // 120 days before `now_utc` — well past `max_age = 90 days`.
        let m = policy_manifest("1.1.0", "2026-02-01T11:00:00Z");
        let err = verify_update_policy(&m, &base_policy()).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("older than max_age") || msg.contains("stale"),
            "got: {msg}"
        );
    }

    #[test]
    fn policy_rejects_invalid_iso8601_issued_at() {
        let m = policy_manifest("1.1.0", "yesterday");
        let err = verify_update_policy(&m, &base_policy()).unwrap_err();
        assert!(format!("{err}").contains("ISO-8601"));
    }

    #[test]
    fn compare_dotted_versions_orders_numerically() {
        assert_eq!(
            compare_dotted_versions("1.10.0", "1.9.5").unwrap(),
            Ordering::Greater
        );
        assert_eq!(
            compare_dotted_versions("1.2.3", "1.2.3").unwrap(),
            Ordering::Equal
        );
        assert_eq!(
            compare_dotted_versions("1.2", "1.2.0").unwrap(),
            Ordering::Equal
        );
        assert_eq!(
            compare_dotted_versions("0.9.0", "1.0.0").unwrap(),
            Ordering::Less
        );
    }

    #[test]
    fn compare_dotted_versions_strips_prerelease_for_compare() {
        // `1.1.0-rc1` and `1.1.0` compare as equal — deliberate simplification
        // until the project ships real SemVer pre-releases.
        assert_eq!(
            compare_dotted_versions("1.1.0-rc1", "1.1.0").unwrap(),
            Ordering::Equal
        );
    }
}
