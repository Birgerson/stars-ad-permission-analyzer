// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("AD connection error: {0}")]
    AdConnection(String),

    #[error("LDAP-Abfragefehler / LDAP query error: {0}")]
    LdapQuery(String),

    #[error("SID-Auflösungsfehler / SID resolution error: {0}")]
    SidResolution(String),

    #[error("Zugriff verweigert / Access denied: {0}")]
    AccessDenied(String),

    #[error("Pfad nicht gefunden / Path not found: {0}")]
    PathNotFound(String),

    #[error("Ungültiger Security Descriptor / Invalid security descriptor: {0}")]
    InvalidSecurityDescriptor(String),

    #[error("Nicht unterstützter ACE-Typ / Unsupported ACE type: {0}")]
    UnsupportedAceType(String),

    #[error("Freigabe-Enumerationsfehler / Share enumeration error: {0}")]
    ShareEnumeration(String),

    #[error("Datenbankfehler / Database error: {0}")]
    Database(String),

    #[error("Exportfehler / Export error: {0}")]
    Export(String),

    #[error("Abgebrochen / Cancellation requested")]
    Cancelled,

    #[error("Validation error: {0}")]
    Validation(String),
}
