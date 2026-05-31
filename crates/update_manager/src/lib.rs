//! update_manager — sichere Update- und Patch-Installation, Signaturprüfung, Rollback
//! update_manager — secure update and patch installation, signature verification, rollback

pub mod manager;
pub mod manifest;
pub mod verifier;

pub use manager::{UpdateChannel, UpdateManager};
pub use manifest::{ManifestFile, TargetPlatform, UpdateManifest};
pub use verifier::{sha256_hex, verify_manifest, RejectAllVerifier, SignatureVerifier};
