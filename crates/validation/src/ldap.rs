// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

use adpa_core::error::CoreError;

/// Validated LDAP filter — prevents injection from unchecked user input
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedLdapFilter(pub String);

const FORBIDDEN_CHARS: &[char] = &['(', ')', '*', '\\', '\0'];

pub fn validate_ldap_filter(input: &str) -> Result<ValidatedLdapFilter, CoreError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CoreError::Validation(
            "LDAP filter must not be empty".into(),
        ));
    }
    for ch in FORBIDDEN_CHARS {
        if trimmed.contains(*ch) {
            return Err(CoreError::Validation(format!(
                "LDAP filter contains forbidden character '{ch}': {trimmed}"
            )));
        }
    }
    Ok(ValidatedLdapFilter(trimmed.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_name_accepted() {
        let result = validate_ldap_filter("Administrator");
        assert!(result.is_ok());
    }

    #[test]
    fn injection_attempt_rejected() {
        let result = validate_ldap_filter("*)(uid=*))(|(uid=*");
        assert!(result.is_err());
    }

    #[test]
    fn empty_filter_rejected() {
        let result = validate_ldap_filter("");
        assert!(result.is_err());
    }
}
