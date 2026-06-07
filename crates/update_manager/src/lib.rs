// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! update_manager — secure update and patch installation, signature verification, rollback

pub mod manager;
pub mod manifest;
pub mod verifier;

pub use manager::{UpdateChannel, UpdateManager};
pub use manifest::{ManifestFile, TargetPlatform, UpdateManifest};
pub use verifier::{
    sha256_hex, verify_manifest_integrity, verify_update_policy, RejectAllVerifier,
    SignatureVerifier, UpdatePolicyContext,
};
