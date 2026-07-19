// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Read-only Active Directory trust inventory (known-limitations L4).
//!
//! Stars reads the domain's `trustedDomain` objects and surfaces their
//! `trustDirection` / `trustAttributes` so an auditor can see whether a trust
//! is configured to filter SIDs (quarantine) or gate authentication
//! (selective authentication) — the configuration that decides whether a
//! cross-forest or historical SID is actually honored at runtime.
//!
//! Stars never modifies a trust, and it deliberately does **not** model the
//! runtime filter effect: detecting that would require a synthetic logon,
//! which violates the read-only principle. This module only *reads and
//! reports*.

use adpa_core::error::CoreError;
use adpa_core::model::{DomainTrust, Sid, TrustAttributes, TrustDirection};

use crate::config::LdapConfig;
use crate::ldap_client::{self, RawEntry};
use crate::sid_util::bytes_to_sid_str;

/// Parses a raw `trustedDomain` LDAP entry into a [`DomainTrust`]. Returns
/// `None` when the entry carries no `trustPartner` (not a usable trust
/// record). A missing or unreadable `trustDirection` is reported as
/// `Unknown`, never silently conflated with the real "disabled" state.
pub fn parse_trust(entry: &RawEntry) -> Option<DomainTrust> {
    let partner = entry.first_attr("trustPartner")?.trim().to_string();
    if partner.is_empty() {
        return None;
    }
    let flat_name = entry
        .first_attr("flatName")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let direction = entry
        .first_attr("trustDirection")
        .and_then(|s| s.trim().parse::<u32>().ok())
        .map(TrustDirection::from_code)
        // A missing/unreadable direction stays visibly "unknown" instead of
        // masquerading as the real "disabled" (code 0) — no silent misreport.
        .unwrap_or(TrustDirection::Unknown(u32::MAX));
    let attributes = entry
        .first_attr("trustAttributes")
        .and_then(|s| s.trim().parse::<u32>().ok())
        .map(TrustAttributes::from_bits)
        .unwrap_or_default();
    let sid = entry
        .first_bin_attr("securityIdentifier")
        .and_then(|b| bytes_to_sid_str(b).ok())
        .map(Sid);
    Some(DomainTrust {
        partner,
        flat_name,
        direction,
        attributes,
        sid,
    })
}

/// Reads and returns the domain's trust inventory (L4). Connects with the
/// given config, subtree-searches the `trustedDomain` objects under the
/// configured base DN (which should be the domain root), parses them, and
/// returns them sorted by partner name. The whole connect + search +
/// disconnect is wrapped in the configured LDAP timeout. Read-only.
pub async fn resolve_domain_trusts(config: &LdapConfig) -> Result<Vec<DomainTrust>, CoreError> {
    let entries =
        ldap_client::with_timeout("domain_trusts", ldap_client::ldap_timeout(config), async {
            let mut conn = ldap_client::connect(config).await?;
            let entries = ldap_client::search_domain_trusts(&mut conn, &config.base_dn).await;
            ldap_client::disconnect(conn).await;
            entries
        })
        .await?;

    let mut trusts: Vec<DomainTrust> = entries.iter().filter_map(parse_trust).collect();
    trusts.sort_by_key(|t| t.partner.to_lowercase());
    Ok(trusts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn entry_with(attrs: &[(&str, &str)], sid_bytes: Option<Vec<u8>>) -> RawEntry {
        let mut a: HashMap<String, Vec<String>> = HashMap::new();
        for (k, v) in attrs {
            a.insert((*k).to_string(), vec![(*v).to_string()]);
        }
        let mut bin: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        if let Some(b) = sid_bytes {
            bin.insert("securityIdentifier".to_string(), vec![b]);
        }
        RawEntry {
            dn: "CN=res.lab,CN=System,DC=corp,DC=lab".to_string(),
            attrs: a,
            bin_attrs: bin,
        }
    }

    #[test]
    fn parse_trust_reads_direction_attributes_and_partner() {
        // Bidirectional forest trust with SID filtering enabled
        // (trustAttributes 12 = FOREST_TRANSITIVE 0x8 | QUARANTINED_DOMAIN 0x4).
        let entry = entry_with(
            &[
                ("trustPartner", "res.lab"),
                ("flatName", "RES"),
                ("trustDirection", "3"),
                ("trustAttributes", "12"),
            ],
            None,
        );
        let t = parse_trust(&entry).expect("a trustPartner entry parses");
        assert_eq!(t.partner, "res.lab");
        assert_eq!(t.flat_name.as_deref(), Some("RES"));
        assert_eq!(t.direction, TrustDirection::Bidirectional);
        assert!(t.attributes.forest_transitive());
        assert!(t.attributes.sid_filtering_enabled());
        assert!(!t.attributes.selective_authentication());
    }

    #[test]
    fn parse_trust_without_partner_is_none() {
        let entry = entry_with(&[("trustDirection", "3")], None);
        assert!(parse_trust(&entry).is_none());
    }

    #[test]
    fn parse_trust_missing_direction_is_unknown_not_disabled() {
        let entry = entry_with(&[("trustPartner", "ext.lab")], None);
        let t = parse_trust(&entry).unwrap();
        // Must never be reported as the real "disabled" (code 0).
        assert!(matches!(t.direction, TrustDirection::Unknown(_)));
        assert_ne!(t.direction, TrustDirection::Disabled);
    }
}
