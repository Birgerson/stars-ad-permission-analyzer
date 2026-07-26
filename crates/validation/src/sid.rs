// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

use adpa_core::{error::CoreError, model::Sid};

/// Validated SID — must match the S-1-... format
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedSid(pub String);

/// Validates a SID string and returns a [`ValidatedSid`].
///
/// The syntax check is delegated to [`Sid::try_new`] — the single
/// canonical SID validator in the workspace (engine review 2026-06-12
/// finding 4). This wrapper exists so callers that want the distinct
/// `ValidatedSid` marker type keep working.
pub fn validate_sid(input: &str) -> Result<ValidatedSid, CoreError> {
    let sid = Sid::try_new(input)?;
    Ok(ValidatedSid(sid.0))
}

/// True when the input is *meant* as a SID — case-insensitive `S-1-`
/// prefix. Classification only: [`validate_sid`] / [`Sid::try_new`] still
/// enforce the canonical uppercase form and produce the precise rejection.
///
/// Lives here because CLI and GUI both dispatch "SID or name?" and must
/// answer it identically (cli review 2026-07-26 CLI-2 fixed the CLI;
/// gui review GUI-4 found the same case-sensitive dispatch in the GUI).
/// Without this, a lowercase `s-1-5-21-…` runs into *name* resolution and
/// fails with a misleading "LSA name lookup failed" instead of a clear
/// "invalid SID" message.
///
/// Panic-safe on multi-byte input: `get(..4)` returns `None` when byte 4
/// is not a character boundary.
pub fn looks_like_sid(input: &str) -> bool {
    input
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case("S-1-"))
}

impl From<ValidatedSid> for Sid {
    fn from(v: ValidatedSid) -> Self {
        Sid(v.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- looks_like_sid (CLI-2 / GUI-4 shared dispatch) ---

    #[test]
    fn looks_like_sid_is_case_insensitive() {
        assert!(looks_like_sid("S-1-5-21-1-2-3-1000"));
        assert!(looks_like_sid("s-1-5-21-1-2-3-1000"));
        assert!(looks_like_sid("S-1-5-18"));
        assert!(!looks_like_sid("alice"));
        assert!(!looks_like_sid("S-2-anything"));
        assert!(!looks_like_sid("S-1"));
        assert!(!looks_like_sid(""));
        // Multi-byte character straddling the prefix window must not panic.
        assert!(!looks_like_sid("S€-1"));
    }

    /// The point of the shared helper: a lowercase SID is classified as a
    /// SID and therefore reaches `validate_sid`, which rejects it with the
    /// precise message — instead of running into name resolution.
    #[test]
    fn lowercase_sid_is_classified_then_precisely_rejected() {
        let input = "s-1-5-21-1-2-3-1000";
        assert!(looks_like_sid(input));
        let err = validate_sid(input).unwrap_err();
        assert!(
            format!("{err}").contains("S-1-"),
            "rejection must name the canonical prefix"
        );
    }

    #[test]
    fn well_known_sid_accepted() {
        let result = validate_sid("S-1-5-18");
        assert!(result.is_ok());
    }

    #[test]
    fn user_sid_accepted() {
        let result = validate_sid("S-1-5-21-3623811015-3361044348-30300820-1013");
        assert!(result.is_ok());
    }

    #[test]
    fn empty_sid_rejected() {
        let result = validate_sid("");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_prefix_rejected() {
        let result = validate_sid("X-1-5-18");
        assert!(result.is_err());
    }

    #[test]
    fn sid_with_too_few_components_rejected() {
        // S-1-5 has no sub-authority → invalid
        let result = validate_sid("S-1-5");
        assert!(result.is_err());
    }

    #[test]
    fn sid_with_non_numeric_component_rejected() {
        let result = validate_sid("S-1-5-abc");
        assert!(result.is_err());
    }

    #[test]
    fn sid_with_whitespace_trimmed_and_accepted() {
        let result = validate_sid("  S-1-5-18  ");
        assert!(result.is_ok());
    }
}
