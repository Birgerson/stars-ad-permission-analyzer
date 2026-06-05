// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

use adpa_core::error::CoreError;

/// Scan-Tiefe mit definiertem Minimal- und Maximalwert
/// Scan depth with defined minimum and maximum values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanDepth(pub u32);

/// Thread-Limit mit definiertem Minimal- und Maximalwert
/// Thread limit with defined minimum and maximum values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadLimit(pub u16);

const MAX_SCAN_DEPTH: u32 = 512;
const MAX_THREAD_LIMIT: u16 = 256;
const MIN_THREAD_LIMIT: u16 = 1;

pub fn validate_scan_depth(value: u32) -> Result<ScanDepth, CoreError> {
    if value > MAX_SCAN_DEPTH {
        return Err(CoreError::Validation(format!(
            "Scan depth {value} exceeds maximum of {MAX_SCAN_DEPTH}"
        )));
    }
    Ok(ScanDepth(value))
}

/// Wie [`validate_scan_depth`], aber für `Option<u32>` — `None` bleibt
/// `None` (= unbegrenzte Tiefe), `Some(d)` läuft durch den Validator.
///
/// Wird von CLI und GUI-Worker am Eingangs-Boundary verwendet, damit die
/// Scan-Tiefe nicht ungeprüft in `WalkConfig` wandert (AGENTS.md DoD-Punkt
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
        // None = „unbegrenzt" muss vom Validator akzeptiert werden.
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
        // Auch sehr große Werte werden hart abgewiesen, nicht stillschweigend
        // auf MAX gedeckelt — der Aufrufer soll den Fehler bemerken.
        // Very large values are rejected hard, not silently clamped — the
        // caller is meant to notice the error.
        assert!(validate_optional_scan_depth(Some(u32::MAX)).is_err());
    }
}
