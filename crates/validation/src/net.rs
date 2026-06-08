// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Validation of network and directory inputs (SMB, LDAP, DN).
//!
//! These inputs are passed to system and network APIs (NetAPI, LDAP) and must
//! therefore be formally checked and length-bounded before processing.

use adpa_core::error::CoreError;

const MAX_HOST_LEN: usize = 255;
const MAX_SHARE_LEN: usize = 80;
const MAX_DN_LEN: usize = 1024;
const MAX_QUERY_LEN: usize = 256;

/// Validated server/host name (SMB or LDAP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedServerName(pub String);

/// Validierter SMB-Freigabename.
/// Validated SMB share name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedShareName(pub String);

/// Validated distinguished name (base DN or bind DN).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDn(pub String);

/// Validated identity search query for the AD search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedIdentityQuery(pub String);

/// Checks a host name: non-empty, length-bounded, no control/path characters,
/// only letters, digits, '.', '-', and '_'.
fn check_hostname(trimmed: &str, label: &str) -> Result<(), CoreError> {
    if trimmed.is_empty() {
        return Err(CoreError::Validation(format!("{label} must not be empty")));
    }
    if trimmed.len() > MAX_HOST_LEN {
        return Err(CoreError::Validation(format!(
            "{label} must not exceed {MAX_HOST_LEN} characters"
        )));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(CoreError::Validation(format!(
            "{label} must not contain control characters"
        )));
    }
    if trimmed.contains('\\') || trimmed.contains('/') {
        return Err(CoreError::Validation(format!(
            "{label} must be a host name without path separators: {trimmed}"
        )));
    }
    if let Some(bad) = trimmed
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')))
    {
        return Err(CoreError::Validation(format!(
            "{label} contains an invalid character '{bad}': {trimmed}"
        )));
    }
    Ok(())
}

/// Validates an SMB server name before it is passed to the NetAPI.
pub fn validate_smb_server(input: &str) -> Result<ValidatedServerName, CoreError> {
    let trimmed = input.trim();
    check_hostname(trimmed, "SMB server name")?;
    Ok(ValidatedServerName(trimmed.to_string()))
}

/// Validates an LDAP endpoint (host name or IP) before it is used for the
/// connection.
pub fn validate_ldap_endpoint(input: &str) -> Result<ValidatedServerName, CoreError> {
    let trimmed = input.trim();
    check_hostname(trimmed, "LDAP server")?;
    Ok(ValidatedServerName(trimmed.to_string()))
}

/// Validates an SMB share name.
///
/// Share names must not contain path separators or Windows-reserved characters
/// and are limited to 80 characters.
pub fn validate_share_name(input: &str) -> Result<ValidatedShareName, CoreError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CoreError::Validation("Share name must not be empty".into()));
    }
    if trimmed.len() > MAX_SHARE_LEN {
        return Err(CoreError::Validation(format!(
            "Share name must not exceed {MAX_SHARE_LEN} characters"
        )));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(CoreError::Validation(
            "Share name must not contain control characters".into(),
        ));
    }
    const FORBIDDEN: &[char] = &[
        '\\', '/', '"', '[', ']', ':', '|', '<', '>', '+', '=', ';', ',', '*', '?',
    ];
    if let Some(bad) = trimmed.chars().find(|c| FORBIDDEN.contains(c)) {
        return Err(CoreError::Validation(format!(
            "Share name contains a forbidden character '{bad}': {trimmed}"
        )));
    }
    Ok(ValidatedShareName(trimmed.to_string()))
}

/// Validates a distinguished name (base DN or bind DN).
///
/// Checks form and length; rejects control characters and obviously
/// malformed DNs before they reach the LDAP server.
pub fn validate_dn(input: &str) -> Result<ValidatedDn, CoreError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CoreError::Validation(
            "Distinguished name must not be empty".into(),
        ));
    }
    if trimmed.len() > MAX_DN_LEN {
        return Err(CoreError::Validation(format!(
            "Distinguished name must not exceed {MAX_DN_LEN} characters"
        )));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(CoreError::Validation(
            "Distinguished name must not contain control characters".into(),
        ));
    }
    // A DN is composed of 'attribute=value' parts; at least one '=' is mandatory.
    // A DN consists of 'attribute=value' components; at least one '=' is required.
    if !trimmed.contains('=') {
        return Err(CoreError::Validation(format!(
            "Distinguished name must contain at least one 'attribute=value' component: {trimmed}"
        )));
    }
    if trimmed.starts_with(',') || trimmed.ends_with(',') {
        return Err(CoreError::Validation(format!(
            "Distinguished name must not start or end with a comma: {trimmed}"
        )));
    }
    Ok(ValidatedDn(trimmed.to_string()))
}

/// Validates a query for the AD identity search.
///
/// The value is checked before filter escaping: non-empty, length-bounded,
/// no control characters.
pub fn validate_identity_query(input: &str) -> Result<ValidatedIdentityQuery, CoreError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CoreError::Validation(
            "Search query must not be empty".into(),
        ));
    }
    if trimmed.len() > MAX_QUERY_LEN {
        return Err(CoreError::Validation(format!(
            "Search query must not exceed {MAX_QUERY_LEN} characters"
        )));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(CoreError::Validation(
            "Search query must not contain control characters".into(),
        ));
    }
    Ok(ValidatedIdentityQuery(trimmed.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smb_server_hostname_accepted() {
        assert!(validate_smb_server("fileserver.corp.local").is_ok());
        assert!(validate_smb_server("FS01").is_ok());
        assert!(validate_smb_server("10.0.0.5").is_ok());
    }

    #[test]
    fn smb_server_empty_rejected() {
        assert!(validate_smb_server("").is_err());
        assert!(validate_smb_server("   ").is_err());
    }

    #[test]
    fn smb_server_with_path_separator_rejected() {
        assert!(validate_smb_server(r"\\fileserver").is_err());
        assert!(validate_smb_server("server/share").is_err());
    }

    #[test]
    fn smb_server_with_control_char_rejected() {
        assert!(validate_smb_server("server\u{7}name").is_err());
        assert!(validate_smb_server("server\tname").is_err());
    }

    #[test]
    fn smb_server_with_space_rejected() {
        assert!(validate_smb_server("file server").is_err());
    }

    #[test]
    fn smb_server_overlong_rejected() {
        let long = "a".repeat(MAX_HOST_LEN + 1);
        assert!(validate_smb_server(&long).is_err());
    }

    // --- Share name ---

    #[test]
    fn share_name_simple_accepted() {
        assert!(validate_share_name("Data").is_ok());
        assert!(validate_share_name("Public$").is_ok());
    }

    #[test]
    fn share_name_empty_rejected() {
        assert!(validate_share_name("").is_err());
    }

    #[test]
    fn share_name_with_separator_rejected() {
        assert!(validate_share_name(r"Data\Sub").is_err());
        assert!(validate_share_name("Data/Sub").is_err());
    }

    #[test]
    fn share_name_with_forbidden_char_rejected() {
        assert!(validate_share_name("Data*").is_err());
        assert!(validate_share_name("Da:ta").is_err());
    }

    #[test]
    fn share_name_with_control_char_rejected() {
        assert!(validate_share_name("Da\u{0}ta").is_err());
    }

    #[test]
    fn share_name_overlong_rejected() {
        let long = "a".repeat(MAX_SHARE_LEN + 1);
        assert!(validate_share_name(&long).is_err());
    }

    // --- LDAP endpoint ---

    #[test]
    fn ldap_endpoint_hostname_accepted() {
        assert!(validate_ldap_endpoint("dc01.corp.local").is_ok());
        assert!(validate_ldap_endpoint("192.168.1.10").is_ok());
    }

    #[test]
    fn ldap_endpoint_empty_rejected() {
        assert!(validate_ldap_endpoint("").is_err());
    }

    #[test]
    fn ldap_endpoint_with_scheme_rejected() {
        // A scheme prefix contains '/' which is a path separator.
        assert!(validate_ldap_endpoint("ldaps://dc01").is_err());
    }

    #[test]
    fn ldap_endpoint_with_control_char_rejected() {
        assert!(validate_ldap_endpoint("dc01\ncorp").is_err());
    }

    // --- DN ---

    #[test]
    fn dn_base_accepted() {
        assert!(validate_dn("DC=corp,DC=local").is_ok());
        assert!(validate_dn("CN=Administrator,CN=Users,DC=corp,DC=local").is_ok());
    }

    #[test]
    fn dn_empty_rejected() {
        assert!(validate_dn("").is_err());
    }

    #[test]
    fn dn_without_equals_rejected() {
        assert!(validate_dn("just-a-name").is_err());
    }

    #[test]
    fn dn_with_control_char_rejected() {
        assert!(validate_dn("DC=corp\u{0},DC=local").is_err());
    }

    #[test]
    fn dn_trailing_comma_rejected() {
        assert!(validate_dn("DC=corp,DC=local,").is_err());
    }

    #[test]
    fn dn_overlong_rejected() {
        let long = format!("DC={}", "a".repeat(MAX_DN_LEN));
        assert!(validate_dn(&long).is_err());
    }

    // --- Identity query ---

    #[test]
    fn identity_query_simple_accepted() {
        assert!(validate_identity_query("Mustermann").is_ok());
        assert!(validate_identity_query("max.mustermann").is_ok());
    }

    #[test]
    fn identity_query_empty_rejected() {
        assert!(validate_identity_query("").is_err());
        assert!(validate_identity_query("   ").is_err());
    }

    #[test]
    fn identity_query_with_control_char_rejected() {
        assert!(validate_identity_query("name\u{0}").is_err());
    }

    #[test]
    fn identity_query_overlong_rejected() {
        let long = "a".repeat(MAX_QUERY_LEN + 1);
        assert!(validate_identity_query(&long).is_err());
    }
}
