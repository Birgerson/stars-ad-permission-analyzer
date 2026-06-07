// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Update-Manager — Architektur-Platzhalter.
//! Update manager — architecture placeholder.
//!
//! **Status: Nicht implementiert / Not yet implemented.**
//!
//! abgeschlossen ist.
//!
//! This crate is a planned architectural component (AGENTS.md §13).
//! Public methods return `Err(UpdateNotYetImplemented)` and must not be called
//! in production workflows until the implementation is complete.
//!
//! Planned requirements, still open:
//! - Rollback-Pfad bei fehlgeschlagenem Update.
//! - Keine Zugangsdaten in Update-Logs speichern.

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

    /// Checks for available updates without installing them.
    ///
    /// **Not yet implemented.** Always returns `Err`.
    pub fn check_for_updates(&self) -> Result<Option<String>, CoreError> {
        Err(CoreError::Validation(
            "UpdateManager.check_for_updates: not yet implemented — \
             requires signed update feed, signature verification, and channel configuration"
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
