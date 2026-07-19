// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! LDAP filter safety — the single home for neutralizing user input before
//! it is placed into an LDAP search filter (AGENTS.md: LDAP filters must not
//! be assembled from unchecked user input).
//!
//! Review finding V1: this used to hold a reject-based `validate_ldap_filter`
//! that nothing called, while the real, correct escaping lived privately in
//! `ad_resolver::ldap_client`. The escaper now lives here — the crate the
//! architecture designates for it — and `ad_resolver` calls it.

/// Escapes the five characters that are special in an LDAP filter assertion
/// value (RFC 4515 §3): `*`, `(`, `)`, `\`, and NUL. Each is replaced by its
/// `\`-prefixed two-digit hex form, so an attacker-supplied value (a user
/// name, UPN, DN, or search term) becomes a **literal** match and cannot
/// alter the filter's structure.
///
/// This is applied at every filter-building site in `ad_resolver`
/// (`(sAMAccountName=<v>)`, `(userPrincipalName=<v>)`, the display-name
/// search, escaped DNs). Wildcards that the code itself adds *around* an
/// escaped value (e.g. `*<escaped>*`) stay effective, because only the
/// value's own `*` is escaped.
pub fn escape_filter_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_value_is_unchanged() {
        assert_eq!(escape_filter_value("Administrator"), "Administrator");
        assert_eq!(
            escape_filter_value("max.mustermann@corp.local"),
            "max.mustermann@corp.local"
        );
    }

    #[test]
    fn each_special_char_is_escaped() {
        assert_eq!(escape_filter_value("*"), "\\2a");
        assert_eq!(escape_filter_value("("), "\\28");
        assert_eq!(escape_filter_value(")"), "\\29");
        assert_eq!(escape_filter_value("\\"), "\\5c");
        assert_eq!(escape_filter_value("\0"), "\\00");
    }

    #[test]
    fn injection_payload_is_neutralized() {
        // The classic LDAP filter-injection payload becomes a literal
        // string: no unescaped parens or wildcards survive to change the
        // filter's meaning.
        let escaped = escape_filter_value("*)(uid=*))(|(uid=*");
        assert!(!escaped.contains('('), "'(' must not survive: {escaped}");
        assert!(!escaped.contains(')'), "')' must not survive: {escaped}");
        assert!(!escaped.contains('*'), "'*' must not survive: {escaped}");
        assert!(escaped.contains("\\2a") && escaped.contains("\\28") && escaped.contains("\\29"));
    }
}
