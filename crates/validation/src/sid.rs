// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

use adpa_core::{error::CoreError, model::Sid};

/// Validierte SID — muss dem Format S-1-... entsprechen
/// Validated SID — must match the S-1-... format
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedSid(pub String);

pub fn validate_sid(input: &str) -> Result<ValidatedSid, CoreError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CoreError::Validation("SID must not be empty".into()));
    }
    if !trimmed.starts_with("S-1-") {
        return Err(CoreError::Validation(format!(
            "Invalid SID format (must start with 'S-1-'): {trimmed}"
        )));
    }
    let parts: Vec<&str> = trimmed.split('-').collect();
    // Minimum: S-1-<authority>-<sub-authority> → 4 components
    if parts.len() < 4 {
        return Err(CoreError::Validation(format!(
            "SID has too few components (minimum S-1-X-Y): {trimmed}"
        )));
    }
    // Every component after the leading 'S' must be numeric
    for part in &parts[1..] {
        if part.parse::<u64>().is_err() {
            return Err(CoreError::Validation(format!(
                "SID contains non-numeric component '{part}': {trimmed}"
            )));
        }
    }
    Ok(ValidatedSid(trimmed.to_string()))
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
