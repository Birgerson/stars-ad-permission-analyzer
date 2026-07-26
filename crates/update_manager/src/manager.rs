// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Update manager — architecture placeholder for the **install** flow.
//!
//! This module is a planned architectural component (AGENTS.md §13).
//! Its public methods return an error and must not be called in
//! production workflows until the implementation is complete. The
//! read-only **update check** is NOT a placeholder — it lives in
//! [`crate::checker`] and is consumed by CLI and GUI.
//!
//! Planned requirements for the install flow, still open:
//! - a production [`crate::verifier::SignatureVerifier`] with a pinned
//!   public key (today only [`crate::verifier::RejectAllVerifier`]
//!   exists — reject-by-default),
//! - signed update feed / manifest download for the configured channel,
//! - safe application shutdown or restart request before installing,
//! - rollback path on a failed installation,
//! - update logging without credentials (AGENTS.md update rules).

use adpa_core::error::CoreError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum UpdateChannel {
    #[default]
    Stable,
    Preview,
    Internal,
    Offline,
}

pub struct UpdateManager {
    pub channel: UpdateChannel,
}

impl UpdateManager {
    pub fn new(channel: UpdateChannel) -> Self {
        Self { channel }
    }

    /// Checks a signed update feed for installable updates.
    ///
    /// **Not yet implemented.** Always returns `Err`. This is the future
    /// signed-feed flow; the plain "is a newer version published?" check
    /// is implemented in [`crate::checker`] and needs no signature
    /// because it installs nothing.
    pub fn check_for_updates(&self) -> Result<Option<String>, CoreError> {
        Err(CoreError::Validation(
            "UpdateManager.check_for_updates: not yet implemented — \
             requires signed update feed, signature verification, and channel \
             configuration. For the read-only version check use crate::checker."
                .into(),
        ))
    }

    /// Verifies signature and checksum of an update package.
    ///
    /// **Not yet implemented.** Always returns `Err`.
    pub fn verify_package(&self, _path: &str) -> Result<(), CoreError> {
        Err(CoreError::Validation(
            "UpdateManager.verify_package: not yet implemented — \
             requires code-signing certificate and SHA-256 checksum validation"
                .into(),
        ))
    }
}
