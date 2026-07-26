// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! update_manager — secure update and patch installation, signature verification, rollback

pub mod checker;
pub mod manager;
pub mod manifest;
pub mod verifier;
pub mod version;

pub use checker::{
    check_release_source, evaluate_release_tag, parse_latest_release, UpdateCheckResult,
    DEFAULT_UPDATE_SOURCE,
};
pub use manager::{UpdateChannel, UpdateManager};
pub use manifest::{ManifestFile, TargetPlatform, UpdateManifest};
pub use verifier::{
    sha256_hex, verify_manifest_integrity, verify_update_policy, RejectAllVerifier,
    SignatureVerifier, UpdatePolicyContext,
};
