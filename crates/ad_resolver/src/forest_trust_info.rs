// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Parser for `msDS-TrustForestTrustInfo` (ADR 0084, known limitation L4).
//!
//! The attribute of a forest trust's `trustedDomain` object lists the
//! namespaces and the domains of the trusted forest (MS-ADTS 6.1.6.9.3):
//!
//! ```text
//! Version u32 (= 1) | RecordCount u32 | Record*
//! Record: RecordLen u32 | Flags u32 | Timestamp u64 | RecordType u8 | data
//!   0 / 1  top-level name / exclusion: NameLen u32 | UTF-8 name
//!   2      domain: SidLen u32 | SID | DnsNameLen u32 | UTF-8 | NetbiosNameLen u32 | UTF-8
//! ```
//!
//! `RecordLen` counts the bytes after itself. Lab finding 2026-10-24 (Server
//! 2022, de and en-us, both sides of the trust): the **last** record carries
//! `RecordLen` 0. So every known record is read by its structure; a non-zero
//! `RecordLen` must match it, and the whole value must be consumed exactly.
//! An unknown record type can only be skipped by a non-zero `RecordLen`.
//! Any other deviation is an error — the caller then reports the forest's
//! domains as unknown instead of guessing.

use adpa_core::model::{ForestTrustDomain, Sid};

use crate::sid_util::bytes_to_sid_str;

/// Upper bound for the record count — far above any real forest, low enough
/// that a corrupt count cannot drive the parser.
const MAX_RECORDS: u32 = 10_000;
/// Longest DNS name (RFC 1035).
const MAX_NAME_LEN: u32 = 255;
/// A SID has at most 15 sub-authorities: 8 + 15 * 4 bytes.
const MAX_SID_LEN: u32 = 68;

const TYPE_TOP_LEVEL_NAME: u8 = 0;
const TYPE_TOP_LEVEL_NAME_EX: u8 = 1;
const TYPE_DOMAIN_INFO: u8 = 2;

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.data.len())
            .ok_or_else(|| format!("truncated at byte {} ({what})", self.pos))?;
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u32(&mut self, what: &str) -> Result<u32, String> {
        let b = self.take(4, what)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u8(&mut self, what: &str) -> Result<u8, String> {
        Ok(self.take(1, what)?[0])
    }

    fn name(&mut self, what: &str) -> Result<String, String> {
        let len = self.u32(what)?;
        if len == 0 || len > MAX_NAME_LEN {
            return Err(format!("{what}: length {len} outside 1–{MAX_NAME_LEN}"));
        }
        let b = self.take(len as usize, what)?;
        let s = std::str::from_utf8(b).map_err(|_| format!("{what}: not valid UTF-8"))?;
        if s.chars().any(char::is_control) {
            return Err(format!("{what}: contains control characters"));
        }
        Ok(s.to_owned())
    }
}

/// Parses the value of `msDS-TrustForestTrustInfo` and returns the domain
/// records (namespace records are validated and skipped). Pure.
pub fn parse_forest_trust_info(data: &[u8]) -> Result<Vec<ForestTrustDomain>, String> {
    let mut r = Reader { data, pos: 0 };
    let version = r.u32("version")?;
    if version != 1 {
        return Err(format!("unsupported version {version}"));
    }
    let count = r.u32("record count")?;
    if count > MAX_RECORDS {
        return Err(format!("record count {count} above {MAX_RECORDS}"));
    }
    let mut domains = Vec::new();
    for i in 0..count {
        let record_len = r.u32("record length")?;
        let start = r.pos;
        let flags = r.u32("flags")?;
        r.take(8, "timestamp")?;
        let record_type = r.u8("record type")?;
        match record_type {
            TYPE_TOP_LEVEL_NAME | TYPE_TOP_LEVEL_NAME_EX => {
                r.name("top-level name")?;
            }
            TYPE_DOMAIN_INFO => {
                let sid_len = r.u32("SID length")?;
                if !(8..=MAX_SID_LEN).contains(&sid_len) {
                    return Err(format!(
                        "record {i}: SID length {sid_len} outside 8–{MAX_SID_LEN}"
                    ));
                }
                let sid_bytes = r.take(sid_len as usize, "SID")?;
                if 8 + usize::from(sid_bytes[1]) * 4 != sid_bytes.len() {
                    return Err(format!(
                        "record {i}: SID length {sid_len} does not match its sub-authority count"
                    ));
                }
                let sid = bytes_to_sid_str(sid_bytes).map_err(|e| format!("record {i}: {e}"))?;
                let dns_name = r.name("DNS name")?;
                let netbios_name = r.name("NetBIOS name")?;
                domains.push(ForestTrustDomain {
                    dns_name,
                    netbios_name,
                    sid: Sid(sid),
                    flags,
                });
            }
            other => {
                // Unknown type: skippable only by a stated length.
                if record_len == 0 {
                    return Err(format!(
                        "record {i}: unknown record type {other} without a record length"
                    ));
                }
                let read = r.pos - start;
                let rest = (record_len as usize).checked_sub(read).ok_or_else(|| {
                    format!("record {i}: record length {record_len} shorter than its header")
                })?;
                r.take(rest, "unknown record")?;
            }
        }
        let read = r.pos - start;
        if record_len != 0 && record_len as usize != read {
            return Err(format!(
                "record {i}: record length {record_len} but {read} bytes of record data"
            ));
        }
    }
    if r.pos != data.len() {
        return Err(format!(
            "{} trailing byte(s) after {count} record(s)",
            data.len() - r.pos
        ));
    }
    Ok(domains)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Lab value 2026-10-24: corp.test's trust object for partner.test
    /// (forest root partner.test + child.partner.test). The last record has
    /// RecordLen 0, as Windows writes it.
    const CORP_TO_PARTNER: &str = "01000000030000001D00000000000000D763DD014B33595A000C000000706172746E65722E746573744800000000000000D763DD014B33595A02180000000104000000000005150000004F8584CDAD62C0985D470607120000006368696C642E706172746E65722E74657374050000004348494C440000000000000000D763DD014B33595A0218000000010400000000000515000000CC61A2E1698119C5FA11DE840C000000706172746E65722E7465737407000000504152544E4552";
    /// Lab value 2026-10-24: partner.test's trust object for corp.test.
    const PARTNER_TO_CORP: &str = "01000000020000001A00000000000000D663DD01D01001B20009000000636F72702E746573740000000000000000D663DD01D01001B2021800000001040000000000051500000071ED263D76AAAC5562F5609509000000636F72702E7465737404000000434F5250";

    #[test]
    fn lab_value_lists_both_domains_of_the_partner_forest() {
        let d = parse_forest_trust_info(&hex(CORP_TO_PARTNER)).unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].dns_name, "child.partner.test");
        assert_eq!(d[0].netbios_name, "CHILD");
        assert_eq!(d[0].sid.0, "S-1-5-21-3448014159-2562745005-117851997");
        assert_eq!(d[1].dns_name, "partner.test");
        assert_eq!(d[1].netbios_name, "PARTNER");
        assert_eq!(d[1].sid.0, "S-1-5-21-3785515468-3306783081-2229146106");
        assert!(d.iter().all(ForestTrustDomain::sid_enabled));
    }

    #[test]
    fn lab_value_of_the_other_side_parses() {
        let d = parse_forest_trust_info(&hex(PARTNER_TO_CORP)).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].dns_name, "corp.test");
        assert_eq!(d[0].sid.0, "S-1-5-21-1025961329-1437379190-2506159458");
    }

    #[test]
    fn every_truncation_is_an_error_never_a_shorter_list() {
        let full = hex(CORP_TO_PARTNER);
        for n in 0..full.len() {
            assert!(
                parse_forest_trust_info(&full[..n]).is_err(),
                "a value cut to {n} bytes must not parse"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_an_error() {
        let mut v = hex(PARTNER_TO_CORP);
        v.push(0);
        assert!(parse_forest_trust_info(&v).is_err());
    }

    #[test]
    fn a_wrong_record_length_is_an_error() {
        let mut v = hex(CORP_TO_PARTNER);
        v[8] = 0x1C; // first record: 29 -> 28
        assert!(parse_forest_trust_info(&v).is_err());
    }

    #[test]
    fn another_version_is_an_error() {
        let mut v = hex(PARTNER_TO_CORP);
        v[0] = 2;
        assert!(parse_forest_trust_info(&v).is_err());
    }

    #[test]
    fn a_sid_length_that_does_not_match_the_sid_is_an_error() {
        let mut v = hex(PARTNER_TO_CORP);
        // Second record's SID: sub-authority count 4 -> 3, length stays 24.
        let pos = v
            .windows(4)
            .position(|w| w == [0x01, 0x04, 0x00, 0x00])
            .unwrap();
        v[pos + 1] = 3;
        assert!(parse_forest_trust_info(&v).is_err());
    }

    #[test]
    fn an_unknown_record_type_is_skipped_only_by_its_length() {
        // Header + one record of type 9 with 3 data bytes.
        let mut with_len = vec![1, 0, 0, 0, 1, 0, 0, 0];
        with_len.extend_from_slice(&16u32.to_le_bytes());
        with_len.extend_from_slice(&[0; 12]);
        with_len.push(9);
        with_len.extend_from_slice(&[7, 7, 7]);
        assert_eq!(parse_forest_trust_info(&with_len).unwrap(), Vec::new());

        let mut without_len = with_len.clone();
        without_len[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse_forest_trust_info(&without_len).is_err());
    }

    #[test]
    fn an_absurd_record_count_is_an_error() {
        let v = [1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(parse_forest_trust_info(&v).is_err());
    }

    #[test]
    fn a_disabled_domain_keeps_its_flags() {
        let mut v = hex(PARTNER_TO_CORP);
        // Second record's flags (record header at 8 + 4 + 26 = 38, flags after its length).
        v[42] = 0x01;
        let d = parse_forest_trust_info(&v).unwrap();
        assert_eq!(d[0].flags, 0x1);
        assert!(!d[0].sid_enabled());
    }
}
