// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("AD connection error: {0}")]
    AdConnection(String),

    #[error("LDAP query error: {0}")]
    LdapQuery(String),

    #[error("SID resolution error: {0}")]
    SidResolution(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Path not found: {0}")]
    PathNotFound(String),

    #[error("Invalid security descriptor: {0}")]
    InvalidSecurityDescriptor(String),

    #[error("Unsupported ACE type: {0}")]
    UnsupportedAceType(String),

    #[error("Share enumeration error: {0}")]
    ShareEnumeration(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Export error: {0}")]
    Export(String),

    #[error("Cancellation requested")]
    Cancelled,

    #[error("Validation error: {0}")]
    Validation(String),
}
