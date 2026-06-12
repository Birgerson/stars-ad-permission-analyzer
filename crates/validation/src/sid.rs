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

impl From<ValidatedSid> for Sid {
    fn from(v: ValidatedSid) -> Self {
        Sid(v.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
