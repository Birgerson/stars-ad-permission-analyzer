// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! SID-Konvertierungslogik zwischen Windows-SID-String und binärem LDAP-Format.
//! SID conversion logic between Windows SID string and binary LDAP format.
//!
//! Windows SID-Format: S-R-I-S1-S2-...-Sn
//!   R  = Revision (immer 1)
//!   I  = Identifier Authority (meistens 5 für NT Authority)
//!   Sn = Sub-Authorities (32-bit little-endian)
//!
//! Binary layout:
//!   Byte 0:   Revision
//!   Byte 1:   Sub-authority count
//!   Bytes 2-7: Identifier authority (big-endian, 6 bytes)
//!   Bytes 8+:  Sub-authorities (4 bytes each, little-endian)

use adpa_core::error::CoreError;

/// Konvertiert einen SID-String in LDAP-Escape-Bytes für einen Filter.
/// Converts a SID string into LDAP-escaped bytes for use in a search filter.
///
/// Beispiel / Example:
/// `"S-1-5-18"` → `"\01\01\00\00\00\00\00\05\12\00\00\00"`
pub fn sid_str_to_ldap_filter(sid: &str) -> Result<String, CoreError> {
    let bytes = sid_str_to_bytes(sid)?;
    Ok(bytes_to_ldap_escape(&bytes))
}

/// Konvertiert einen SID-String in sein binäres Byte-Format.
/// Converts a SID string to its binary byte representation.
pub fn sid_str_to_bytes(sid: &str) -> Result<Vec<u8>, CoreError> {
    let parts: Vec<&str> = sid.trim().split('-').collect();
    // Mindestformat: S-R-I (d.h. mindestens 3 Teile)
    // Minimum format: S-R-I (at least 3 parts)
    if parts.len() < 3 || parts[0] != "S" {
        return Err(CoreError::SidResolution(format!(
            "Ungültiges SID-Format / Invalid SID format: {sid}"
        )));
    }

    let revision: u8 = parts[1].parse().map_err(|_| {
        CoreError::SidResolution(format!(
            "Ungültige Revision in SID / Invalid revision: {sid}"
        ))
    })?;

    let authority: u64 = parts[2].parse().map_err(|_| {
        CoreError::SidResolution(format!(
            "Ungültige Identifier Authority / Invalid identifier authority: {sid}"
        ))
    })?;

    let sub_authorities: Vec<u32> = parts[3..]
        .iter()
        .map(|s| {
            s.parse::<u32>().map_err(|_| {
                CoreError::SidResolution(format!(
                    "Ungültige Sub-Authority / Invalid sub-authority in SID: {sid}"
                ))
            })
        })
        .collect::<Result<_, _>>()?;

    let mut bytes = Vec::with_capacity(8 + sub_authorities.len() * 4);
    bytes.push(revision);
    bytes.push(sub_authorities.len() as u8);

    // Identifier Authority: 6 Bytes big-endian
    // Identifier Authority: 6 bytes big-endian
    bytes.push(((authority >> 40) & 0xFF) as u8);
    bytes.push(((authority >> 32) & 0xFF) as u8);
    bytes.push(((authority >> 24) & 0xFF) as u8);
    bytes.push(((authority >> 16) & 0xFF) as u8);
    bytes.push(((authority >> 8) & 0xFF) as u8);
    bytes.push((authority & 0xFF) as u8);

    // Sub-Authorities: je 4 Bytes little-endian
    // Sub-Authorities: 4 bytes each, little-endian
    for sa in &sub_authorities {
        bytes.extend_from_slice(&sa.to_le_bytes());
    }

    Ok(bytes)
}

/// Konvertiert binäre SID-Bytes zurück in den kanonischen SID-String.
/// Converts binary SID bytes back into the canonical SID string.
pub fn bytes_to_sid_str(bytes: &[u8]) -> Result<String, CoreError> {
    if bytes.len() < 8 {
        return Err(CoreError::SidResolution(
            "SID-Byte-Sequenz zu kurz / SID byte sequence too short".into(),
        ));
    }

    let revision = bytes[0];
    let sub_authority_count = bytes[1] as usize;

    let expected_len = 8 + sub_authority_count * 4;
    if bytes.len() < expected_len {
        return Err(CoreError::SidResolution(format!(
            "SID-Daten unvollständig / SID data incomplete: expected {expected_len} bytes, got {}",
            bytes.len()
        )));
    }

    // Identifier Authority (Bytes 2-7, big-endian)
    let mut authority: u64 = 0;
    for b in &bytes[2..8] {
        authority = (authority << 8) | *b as u64;
    }

    let mut sid = format!("S-{revision}-{authority}");

    for i in 0..sub_authority_count {
        let offset = 8 + i * 4;
        let sa = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        sid.push('-');
        sid.push_str(&sa.to_string());
    }

    Ok(sid)
}

/// Gibt LDAP-escaped Hex-Sequenz für Binärdaten zurück (\xx\xx...).
/// Returns LDAP-escaped hex sequence for binary data (\xx\xx...).
fn bytes_to_ldap_escape(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Bekannte Well-Known SIDs für deterministische Tests
    // Known well-known SIDs for deterministic tests

    #[test]
    fn local_system_sid_roundtrip() {
        // S-1-5-18 = Local System
        let bytes = sid_str_to_bytes("S-1-5-18").unwrap();
        let back = bytes_to_sid_str(&bytes).unwrap();
        assert_eq!(back, "S-1-5-18");
    }

    #[test]
    fn everyone_sid_roundtrip() {
        // S-1-1-0 = Everyone
        let bytes = sid_str_to_bytes("S-1-1-0").unwrap();
        let back = bytes_to_sid_str(&bytes).unwrap();
        assert_eq!(back, "S-1-1-0");
    }

    #[test]
    fn domain_user_sid_roundtrip() {
        // Typische Domänen-Benutzer-SID
        // Typical domain user SID
        let sid = "S-1-5-21-3623811015-3361044348-30300820-1013";
        let bytes = sid_str_to_bytes(sid).unwrap();
        let back = bytes_to_sid_str(&bytes).unwrap();
        assert_eq!(back, sid);
    }

    #[test]
    fn local_system_ldap_filter_not_empty() {
        let filter = sid_str_to_ldap_filter("S-1-5-18").unwrap();
        assert!(!filter.is_empty());
        // S-1-5-18: 1 Revision + 1 SubAuthCount + 6 Authority + 1*4 SubAuth = 12 Bytes
        // S-1-5-18: 1 revision + 1 sub-auth count + 6 authority + 1*4 sub-auth = 12 bytes
        // 12 Bytes * 3 Zeichen (\xx) = 36 Zeichen / chars
        assert_eq!(filter.len(), 12 * 3);
    }

    #[test]
    fn domain_sid_ldap_filter_length() {
        // S-1-5-21-...-rid hat 28 Bytes = 28 * 3 = 84 Zeichen
        // S-1-5-21-...-rid has 28 bytes = 28 * 3 = 84 chars
        let sid = "S-1-5-21-3623811015-3361044348-30300820-1013";
        let filter = sid_str_to_ldap_filter(sid).unwrap();
        assert_eq!(filter.len(), 28 * 3);
    }

    #[test]
    fn invalid_prefix_rejected() {
        assert!(sid_str_to_bytes("X-1-5-18").is_err());
    }

    #[test]
    fn empty_sid_rejected() {
        assert!(sid_str_to_bytes("").is_err());
    }

    #[test]
    fn too_short_bytes_rejected() {
        assert!(bytes_to_sid_str(&[1, 1, 0]).is_err());
    }

    #[test]
    fn ldap_escape_format_correct() {
        // \01\05 = revision 1, 1 sub-authority
        let result = sid_str_to_ldap_filter("S-1-5-18").unwrap();
        // Revision=1, SubAuthCount=1, Authority=5, SubAuth=18
        assert!(result.starts_with("\\01\\01"));
    }
}
