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
//! For a forest trust it also reads the domains of the trusted forest
//! (`msDS-TrustForestTrustInfo`, ADR 0084), so a SID of any of them is
//! recognised as a SID of a trusted domain.
//!
//! Stars never modifies a trust. What a trust does to a token at runtime is
//! modelled only where it was measured in the lab (ADR 0078, 0079, 0084);
//! a synthetic logon to find out would violate the read-only principle. This
//! module only *reads and reports*.

use adpa_core::error::CoreError;
use adpa_core::model::{DomainTrust, Sid, TrustAttributes, TrustDirection};

use crate::config::LdapConfig;
use crate::forest_trust_info::parse_forest_trust_info;
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
    // ADR 0084: the domains of a trusted forest. Read only for a forest
    // trust; a missing or broken value is kept as a reason, never as an
    // empty forest.
    let (forest_domains, forest_info_error) = if attributes.forest_transitive() {
        match entry.first_bin_attr("msDS-TrustForestTrustInfo") {
            Some(b) => match parse_forest_trust_info(b) {
                Ok(d) => (d, None),
                Err(e) => (
                    Vec::new(),
                    Some(format!(
                        "msDS-TrustForestTrustInfo could not be parsed: {e}"
                    )),
                ),
            },
            None => (
                Vec::new(),
                Some(
                    "msDS-TrustForestTrustInfo was not returned (missing, or not readable \
                     for the bind account)"
                        .to_owned(),
                ),
            ),
        }
    } else {
        (Vec::new(), None)
    };
    Some(DomainTrust {
        partner,
        flat_name,
        direction,
        attributes,
        sid,
        forest_domains,
        forest_info_error,
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

    /// ADR 0084: a forest trust carries the domains of the trusted forest.
    #[test]
    fn parse_trust_reads_the_domains_of_a_forest_trust() {
        // Lab value (partner.test's trust object for corp.test).
        let ftinfo = "01000000020000001A00000000000000D663DD01D01001B20009000000636F72702E746573740000000000000000D663DD01D01001B2021800000001040000000000051500000071ED263D76AAAC5562F5609509000000636F72702E7465737404000000434F5250";
        let bytes: Vec<u8> = (0..ftinfo.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&ftinfo[i..i + 2], 16).unwrap())
            .collect();
        let mut entry = entry_with(
            &[("trustPartner", "corp.test"), ("trustAttributes", "8")],
            None,
        );
        entry
            .bin_attrs
            .insert("msDS-TrustForestTrustInfo".to_string(), vec![bytes]);
        let t = parse_trust(&entry).unwrap();
        assert_eq!(t.forest_domains.len(), 1);
        assert_eq!(t.forest_domains[0].dns_name, "corp.test");
        assert!(t.forest_info_error.is_none());
    }

    /// A forest trust without readable forest information says so — an
    /// empty list alone would read as "a forest without domains".
    #[test]
    fn a_forest_trust_without_forest_information_carries_the_reason() {
        let entry = entry_with(
            &[("trustPartner", "partner.test"), ("trustAttributes", "8")],
            None,
        );
        let t = parse_trust(&entry).unwrap();
        assert!(t.forest_domains.is_empty());
        assert!(t
            .forest_info_error
            .as_deref()
            .is_some_and(|e| e.contains("not returned")));

        let mut broken = entry_with(
            &[("trustPartner", "partner.test"), ("trustAttributes", "8")],
            None,
        );
        broken
            .bin_attrs
            .insert("msDS-TrustForestTrustInfo".to_string(), vec![vec![1, 0]]);
        let t = parse_trust(&broken).unwrap();
        assert!(t
            .forest_info_error
            .as_deref()
            .is_some_and(|e| e.contains("could not be parsed")));
    }

    #[test]
    fn an_external_trust_has_no_forest_information_and_no_error() {
        let entry = entry_with(
            &[("trustPartner", "ext.test"), ("trustAttributes", "4")],
            None,
        );
        let t = parse_trust(&entry).unwrap();
        assert!(t.forest_domains.is_empty());
        assert!(t.forest_info_error.is_none());
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
