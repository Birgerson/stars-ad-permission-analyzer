// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Update-Manager — Architektur-Platzhalter.
//! Update manager — architecture placeholder.
//!
//! **Status: Nicht implementiert / Not yet implemented.**
//!
//! Dieser Crate ist als fester Architektur-Baustein vorgesehen (AGENTS.md §13).
//! Die öffentlichen Methoden geben `Err(UpdateNotYetImplemented)` zurück und
//! dürfen im produktiven Workflow nicht aufgerufen werden, bis die Implementierung
//! abgeschlossen ist.
//!
//! This crate is a planned architectural component (AGENTS.md §13).
//! Public methods return `Err(UpdateNotYetImplemented)` and must not be called
//! in production workflows until the implementation is complete.
//!
//! Geplante Pflichtanforderungen (noch offen / planned requirements, still open):
//! - Updates müssen digital signiert und die Signatur geprüft werden.
//! - SHA-256-Prüfsumme vor der Installation verifizieren.
//! - Update-Quelle konfigurierbar, aber gegen ein Schema validiert.
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

    /// Prüft verfügbare Updates, ohne sie zu installieren.
    /// Checks for available updates without installing them.
    ///
    /// **Noch nicht implementiert.** Gibt immer `Err` zurück.
    /// **Not yet implemented.** Always returns `Err`.
    pub fn check_for_updates(&self) -> Result<Option<String>, CoreError> {
        Err(CoreError::Validation(
            "UpdateManager.check_for_updates: not yet implemented — \
             requires signed update feed, signature verification, and channel configuration"
                .into(),
        ))
    }

    /// Prüft Signatur und Prüfsumme eines Update-Pakets.
    /// Verifies signature and checksum of an update package.
    ///
    /// **Noch nicht implementiert.** Gibt immer `Err` zurück.
    /// **Not yet implemented.** Always returns `Err`.
    pub fn verify_package(&self, _path: &str) -> Result<(), CoreError> {
        Err(CoreError::Validation(
            "UpdateManager.verify_package: not yet implemented — \
             requires code-signing certificate and SHA-256 checksum validation"
                .into(),
        ))
    }
}
