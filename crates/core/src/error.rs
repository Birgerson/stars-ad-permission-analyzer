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

    /// A reparse point (junction / symlink) targets a directory that is an
    /// ancestor of the current traversal chain — descending would recurse
    /// forever. Typed so audit consumers can distinguish a real cycle from
    /// a mere duplicate route (deep review 2026-07-04, F2).
    #[error("Reparse cycle: {0}")]
    ReparseCycle(String),

    /// A reparse point targets a directory that was already enumerated in
    /// this scan under a different namespace path. Not a cycle: the target
    /// content exists in the result once; this route is recorded instead
    /// of being enumerated again (deep review 2026-07-04, F2).
    #[error("Duplicate reparse target: {0}")]
    ReparseDuplicateTarget(String),
}
