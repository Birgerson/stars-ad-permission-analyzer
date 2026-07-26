// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Validation of update-source URLs for the manual update check
//! (AGENTS.md: "the update source must be configurable, but validated";
//! ADR 0061).
//!
//! The source is only ever *read* — Stars downloads nothing and installs
//! nothing — but the URL still gates what the check talks to, so it is
//! validated like every other user input:
//!
//! - **HTTPS only.** A plain-`http` source could be tampered with in
//!   transit and would teach users that unencrypted update endpoints are
//!   acceptable. `file://`, UNC and everything else are rejected too;
//!   an offline/file-based check is a separate, deliberate feature.
//! - **No embedded credentials** (`https://user:pass@host/…`) — update
//!   credentials must never live in a URL (they end up in logs, shell
//!   history and screenshots).
//! - **No fragment** (`#…`) — meaningless for an API endpoint.
//! - **No whitespace or control characters**, non-empty host, and a
//!   2048-character cap (practical URL limit).

use adpa_core::error::CoreError;

/// Validated HTTPS update-source URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedUpdateSource(pub String);

/// Maximum accepted URL length (practical interoperability limit).
const MAX_URL_LEN: usize = 2048;

/// Validates a user-supplied update-source URL.
pub fn validate_update_source(input: &str) -> Result<ValidatedUpdateSource, CoreError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CoreError::Validation(
            "Update source must not be empty".into(),
        ));
    }
    if trimmed.len() > MAX_URL_LEN {
        return Err(CoreError::Validation(format!(
            "Update source exceeds {MAX_URL_LEN} characters"
        )));
    }
    if let Some(c) = trimmed.chars().find(|c| c.is_control() || *c == ' ') {
        return Err(CoreError::Validation(format!(
            "Update source must not contain whitespace or control characters \
             (found U+{:04X})",
            c as u32
        )));
    }

    // Scheme: HTTPS only. Compare case-insensitively per RFC 3986 §3.1.
    let lower = trimmed.to_ascii_lowercase();
    let rest = match lower.strip_prefix("https://") {
        Some(r) => r,
        None => {
            return Err(CoreError::Validation(format!(
                "Update source must be an https:// URL (got '{trimmed}') — \
                 plain http, file paths and UNC paths are not accepted"
            )));
        }
    };

    // Authority = everything up to the first '/', '?' or '#'.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err(CoreError::Validation(
            "Update source has an empty host".into(),
        ));
    }
    if authority.contains('@') {
        return Err(CoreError::Validation(
            "Update source must not embed credentials (user:password@host) — \
             they would leak into logs and shell history"
                .into(),
        ));
    }
    if trimmed.contains('#') {
        return Err(CoreError::Validation(
            "Update source must not contain a fragment ('#…')".into(),
        ));
    }

    Ok(ValidatedUpdateSource(trimmed.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_github_api_url() {
        let v = validate_update_source(
            "https://api.github.com/repos/Birgerson/stars-ad-permission-analyzer/releases/latest",
        )
        .unwrap();
        assert!(v.0.starts_with("https://api.github.com/"));
    }

    #[test]
    fn accepts_internal_https_host_with_query() {
        validate_update_source("https://updates.corp.local/stars/latest?channel=stable").unwrap();
    }

    #[test]
    fn trims_surrounding_whitespace() {
        let v = validate_update_source("  https://api.github.com/x  ").unwrap();
        assert_eq!(v.0, "https://api.github.com/x");
    }

    #[test]
    fn rejects_plain_http() {
        let err = validate_update_source("http://api.github.com/x").unwrap_err();
        assert!(format!("{err}").contains("https://"));
    }

    #[test]
    fn rejects_file_and_unc_sources() {
        assert!(validate_update_source("file:///C:/updates/latest.json").is_err());
        assert!(validate_update_source(r"\\server\share\latest.json").is_err());
        assert!(validate_update_source("ftp://host/x").is_err());
    }

    #[test]
    fn rejects_embedded_credentials() {
        let err = validate_update_source("https://user:secret@host/api").unwrap_err();
        assert!(
            format!("{err}").contains("credentials"),
            "must name the credential problem"
        );
    }

    #[test]
    fn rejects_fragment() {
        let err = validate_update_source("https://host/api#frag").unwrap_err();
        assert!(format!("{err}").contains("fragment"));
    }

    #[test]
    fn rejects_empty_host_and_empty_input() {
        assert!(validate_update_source("https:///path").is_err());
        assert!(validate_update_source("").is_err());
        assert!(validate_update_source("   ").is_err());
    }

    #[test]
    fn rejects_inner_whitespace_and_control_chars() {
        assert!(validate_update_source("https://host/a b").is_err());
        assert!(validate_update_source("https://host/a\tb").is_err());
        assert!(validate_update_source("https://host/a\nb").is_err());
    }

    #[test]
    fn rejects_over_long_url() {
        let long = format!("https://host/{}", "a".repeat(3000));
        let err = validate_update_source(&long).unwrap_err();
        assert!(format!("{err}").contains("2048"));
    }

    #[test]
    fn scheme_check_is_case_insensitive() {
        validate_update_source("HTTPS://api.github.com/x").unwrap();
    }
}
