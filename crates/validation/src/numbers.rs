// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

use adpa_core::error::CoreError;

/// Scan depth with defined minimum and maximum values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanDepth(pub u32);

/// Thread limit with defined minimum and maximum values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadLimit(pub u16);

/// LDAP operation timeout in seconds, with defined minimum and maximum values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LdapTimeout(pub u64);

const MAX_SCAN_DEPTH: u32 = 512;
const MAX_THREAD_LIMIT: u16 = 256;
const MIN_THREAD_LIMIT: u16 = 1;
const MIN_LDAP_TIMEOUT_SECS: u64 = 1;
const MAX_LDAP_TIMEOUT_SECS: u64 = 600;

pub fn validate_scan_depth(value: u32) -> Result<ScanDepth, CoreError> {
    if value > MAX_SCAN_DEPTH {
        return Err(CoreError::Validation(format!(
            "Scan depth {value} exceeds maximum of {MAX_SCAN_DEPTH}"
        )));
    }
    Ok(ScanDepth(value))
}

///
/// 11: Eingaben validieren).
///
/// Like [`validate_scan_depth`], but for `Option<u32>` — `None` stays
/// `None` (= unbounded depth), `Some(d)` goes through the validator. Used
/// at the CLI/GUI input boundary so scan depth does not flow into
/// `WalkConfig` unchecked (AGENTS.md DoD point 11: validate inputs).
pub fn validate_optional_scan_depth(value: Option<u32>) -> Result<Option<ScanDepth>, CoreError> {
    value.map(validate_scan_depth).transpose()
}

pub fn validate_thread_limit(value: u16) -> Result<ThreadLimit, CoreError> {
    if value < MIN_THREAD_LIMIT {
        return Err(CoreError::Validation(format!(
            "Thread limit {value} is below minimum of {MIN_THREAD_LIMIT}"
        )));
    }
    if value > MAX_THREAD_LIMIT {
        return Err(CoreError::Validation(format!(
            "Thread limit {value} exceeds maximum of {MAX_THREAD_LIMIT}"
        )));
    }
    Ok(ThreadLimit(value))
}

/// Validates an LDAP operation timeout in seconds.
///
/// Rejects `0` (a zero timeout would fire immediately and fail every
/// query) and values above [`MAX_LDAP_TIMEOUT_SECS`] (an unbounded wait
/// would defeat the "scans must stay bounded and abortable" rule). When
/// the caller passes no value the built-in default of 10s applies (see
/// `LdapConfig`); this validator only guards an explicit override.
pub fn validate_ldap_timeout(value: u64) -> Result<LdapTimeout, CoreError> {
    if value < MIN_LDAP_TIMEOUT_SECS {
        return Err(CoreError::Validation(format!(
            "LDAP timeout {value}s is below minimum of {MIN_LDAP_TIMEOUT_SECS}s"
        )));
    }
    if value > MAX_LDAP_TIMEOUT_SECS {
        return Err(CoreError::Validation(format!(
            "LDAP timeout {value}s exceeds maximum of {MAX_LDAP_TIMEOUT_SECS}s"
        )));
    }
    Ok(LdapTimeout(value))
}

/// Like [`validate_ldap_timeout`], but for `Option<u64>` — `None` keeps
/// the built-in default (10s), `Some(t)` goes through the validator. Used
/// at the CLI/GUI input boundary so the timeout does not flow into
/// `LdapConfig` unchecked (AGENTS.md DoD point 11: validate inputs).
pub fn validate_optional_ldap_timeout(
    value: Option<u64>,
) -> Result<Option<LdapTimeout>, CoreError> {
    value.map(validate_ldap_timeout).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_scan_depth_accepted() {
        assert!(validate_scan_depth(0).is_ok());
    }

    #[test]
    fn max_scan_depth_accepted() {
        assert!(validate_scan_depth(MAX_SCAN_DEPTH).is_ok());
    }

    #[test]
    fn excessive_scan_depth_rejected() {
        assert!(validate_scan_depth(MAX_SCAN_DEPTH + 1).is_err());
    }

    #[test]
    fn zero_threads_rejected() {
        assert!(validate_thread_limit(0).is_err());
    }

    #[test]
    fn valid_thread_limit_accepted() {
        assert!(validate_thread_limit(8).is_ok());
    }

    #[test]
    fn excessive_threads_rejected() {
        assert!(validate_thread_limit(MAX_THREAD_LIMIT + 1).is_err());
    }

    // --- validate_optional_scan_depth (Finding 3) ---

    #[test]
    fn optional_scan_depth_none_passes_through() {
        // None = "unbounded" must be accepted by the validator.
        let result = validate_optional_scan_depth(None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn optional_scan_depth_some_within_limit_accepted() {
        let result = validate_optional_scan_depth(Some(50)).unwrap();
        assert_eq!(result.map(|d| d.0), Some(50));
    }

    #[test]
    fn optional_scan_depth_some_at_boundary_accepted() {
        let result = validate_optional_scan_depth(Some(MAX_SCAN_DEPTH)).unwrap();
        assert_eq!(result.map(|d| d.0), Some(MAX_SCAN_DEPTH));
    }

    #[test]
    fn optional_scan_depth_some_above_limit_rejected() {
        assert!(validate_optional_scan_depth(Some(MAX_SCAN_DEPTH + 1)).is_err());
        // Very large values are rejected hard, not silently clamped — the
        // caller is meant to notice the error.
        assert!(validate_optional_scan_depth(Some(u32::MAX)).is_err());
    }

    // --- validate_ldap_timeout / validate_optional_ldap_timeout ---

    #[test]
    fn zero_ldap_timeout_rejected() {
        // A zero timeout would fire immediately and fail every query.
        assert!(validate_ldap_timeout(0).is_err());
    }

    #[test]
    fn min_ldap_timeout_accepted() {
        assert!(validate_ldap_timeout(MIN_LDAP_TIMEOUT_SECS).is_ok());
    }

    #[test]
    fn max_ldap_timeout_accepted() {
        assert!(validate_ldap_timeout(MAX_LDAP_TIMEOUT_SECS).is_ok());
    }

    #[test]
    fn excessive_ldap_timeout_rejected() {
        assert!(validate_ldap_timeout(MAX_LDAP_TIMEOUT_SECS + 1).is_err());
    }

    #[test]
    fn optional_ldap_timeout_none_passes_through() {
        // None = "keep the built-in default" must be accepted by the validator.
        let result = validate_optional_ldap_timeout(None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn optional_ldap_timeout_some_within_limit_accepted() {
        let result = validate_optional_ldap_timeout(Some(30)).unwrap();
        assert_eq!(result.map(|t| t.0), Some(30));
    }

    #[test]
    fn optional_ldap_timeout_some_above_limit_rejected() {
        assert!(validate_optional_ldap_timeout(Some(MAX_LDAP_TIMEOUT_SECS + 1)).is_err());
        // Very large values are rejected hard, not silently clamped.
        assert!(validate_optional_ldap_timeout(Some(u64::MAX)).is_err());
    }
}
