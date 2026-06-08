// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! LdapResolver — implements IdentityResolver via LDAP against Active Directory.
//!
//! Domain rules implemented here:
//!
//!   SID is the primary technical identity, not the display name.
//!   Disabled users are detected and marked.
//!   Orphaned SIDs (no AD object found) are marked as Unknown.
//!   Transitive group membership is resolved server-side via
//!   `LDAP_MATCHING_RULE_IN_CHAIN`, which avoids `memberOf` range
//!   retrieval (AD truncates beyond ~1500 values) and the per-level
//!   N+1 recursion. Cycles cannot occur in this scheme.
//!   SID-to-Identity resolutions are cached.
//!   The primary group of a user is handled separately because it is
//!   modelled via `primaryGroupID` (not `member`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use adpa_core::{
    error::CoreError,
    model::{GroupMembership, Identity, IdentityKind, MembershipPath, MembershipPathSource, Sid},
    traits::IdentityResolver,
};

use crate::{
    config::LdapConfig,
    ldap_client::{self, RawEntry},
    sid_util::bytes_to_sid_str,
};

/// AD userAccountControl bit for disabled accounts.
const UAC_ACCOUNT_DISABLE: u32 = 0x0002;

/// Implements IdentityResolver via LDAP with an in-memory cache.
pub struct LdapResolver {
    config: Arc<LdapConfig>,
    /// Cache: SID-String → Identity
    identity_cache: Arc<Mutex<HashMap<String, Identity>>>,
}

impl LdapResolver {
    /// Creates a new LdapResolver with the given configuration.
    pub fn new(config: LdapConfig) -> Self {
        Self {
            config: Arc::new(config),
            identity_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Raw LDAP UPN lookup. Consumed by [`crate::principal`].
    pub async fn lookup_by_upn_raw(&self, upn: &str) -> Result<Option<(Sid, Identity)>, CoreError> {
        ldap_client::with_timeout(
            "lookup_by_upn_raw",
            ldap_client::ldap_timeout(&self.config),
            async {
                let mut ldap = ldap_client::connect(&self.config).await?;
                let result = ldap_client::search_by_upn(&mut ldap, &self.config.base_dn, upn).await;
                ldap_client::disconnect(ldap).await;

                match result? {
                    None => Ok(None),
                    Some(entry) => {
                        let sid = extract_sid_from_entry(&entry).ok_or_else(|| {
                            CoreError::SidResolution(format!("No objectSid for UPN: {upn}"))
                        })?;
                        let identity = parse_identity_from_entry(&entry, &sid);
                        self.identity_cache
                            .lock()
                            .await
                            .insert(sid.0.clone(), identity.clone());
                        Ok(Some((sid, identity)))
                    }
                }
            },
        )
        .await
    }

    /// Raw LDAP SAM lookup — returns all matches.
    pub async fn lookup_all_by_sam_raw(
        &self,
        sam: &str,
    ) -> Result<Vec<(Sid, Identity)>, CoreError> {
        ldap_client::with_timeout(
            "lookup_all_by_sam_raw",
            ldap_client::ldap_timeout(&self.config),
            async {
                let mut ldap = ldap_client::connect(&self.config).await?;
                let result =
                    ldap_client::search_all_by_samaccount(&mut ldap, &self.config.base_dn, sam)
                        .await;
                ldap_client::disconnect(ldap).await;
                let entries = result?;
                let mut out = Vec::with_capacity(entries.len());
                for entry in entries {
                    let sid = match extract_sid_from_entry(&entry) {
                        Some(s) => s,
                        None => continue,
                    };
                    let identity = parse_identity_from_entry(&entry, &sid);
                    out.push((sid, identity));
                }
                Ok(out)
            },
        )
        .await
    }

    /// Returns the number of cached identities (for tests and diagnostics).
    pub async fn cache_size(&self) -> usize {
        self.identity_cache.lock().await.len()
    }

    /// Resolves an identity — first from cache, then via LDAP.
    async fn resolve_identity_internal(&self, sid: &Sid) -> Result<Identity, CoreError> {
        // Check cache hit
        {
            let cache = self.identity_cache.lock().await;
            if let Some(identity) = cache.get(&sid.0) {
                debug!("Cache-Treffer / cache hit: {}", sid.0);
                return Ok(identity.clone());
            }
        }

        // (review finding 5).
        // Bound the whole operation against the configured timeout
        // (review finding 5).
        let identity = ldap_client::with_timeout(
            "resolve_identity",
            ldap_client::ldap_timeout(&self.config),
            async {
                let mut ldap = ldap_client::connect(&self.config).await?;
                let result =
                    ldap_client::search_by_sid(&mut ldap, &self.config.base_dn, &sid.0).await;
                ldap_client::disconnect(ldap).await;

                Ok(match result? {
                    Some(entry) => parse_identity_from_entry(&entry, sid),
                    None => {
                        // Orphaned SID — no AD object found
                        warn!("Verwaiste SID / Orphaned SID: {}", sid.0);
                        Identity {
                            sid: sid.clone(),
                            name: None,
                            domain: None,
                            kind: IdentityKind::Orphaned,
                            disabled: false,
                            user_principal_name: None,
                        }
                    }
                })
            },
        )
        .await?;

        // Review 2026-06-04 round 3 finding 1 (cache poisoning):
        //
        // Review 2026-06-04 round 3 finding 1 (cache poisoning):
        // `Orphaned` identities were cached unconditionally. A
        // subsequent `lookup_via_lsa` that built an LSA-only identity
        // on LDAP miss had no way to overwrite the cache — the next
        // consumer for the same SID got the stale `Orphaned`. Fix: do
        // not persist `Orphaned`. The next call gets a fresh chance.
        if identity.kind != IdentityKind::Orphaned {
            self.identity_cache
                .lock()
                .await
                .insert(sid.0.clone(), identity.clone());
        }

        Ok(identity)
    }

    ///
    /// `complete = false` with source [`MembershipPathSource::LdapMatchingRule`]
    ///
    /// Resolves all group memberships transitively — server-side via
    /// `LDAP_MATCHING_RULE_IN_CHAIN`, plus the primary group (which is not
    /// linked via `member`) and its transitive parents.
    ///
    /// In addition, each membership carries a concrete
    /// [`MembershipPath`] reconstructed from the `memberOf` edges:
    /// starting from the user's direct `memberOf` set, a BFS through each
    /// group's `memberOf` finds the shortest chain to the target group.
    /// When reconstruction is not possible (e.g. because an intermediate
    /// group's `memberOf` was truncated by the server), the path stays
    /// two SIDs long and is marked `complete = false` with source
    /// [`MembershipPathSource::LdapMatchingRule`] — transitive membership
    /// is certain, the concrete route is not.
    async fn resolve_memberships_internal(
        &self,
        sid: &Sid,
    ) -> Result<Vec<GroupMembership>, CoreError> {
        // — guard for review finding 5.
        // Bound the whole membership resolution against the configured
        // timeout (review finding 5).
        ldap_client::with_timeout(
            "resolve_memberships",
            ldap_client::ldap_timeout(&self.config),
            self.resolve_memberships_inner(sid),
        )
        .await
    }

    async fn resolve_memberships_inner(
        &self,
        sid: &Sid,
    ) -> Result<Vec<GroupMembership>, CoreError> {
        let mut ldap = ldap_client::connect(&self.config).await?;

        // 1) Load the principal entry.
        // 1) Load the principal entry.
        let Some(entry) =
            ldap_client::search_by_sid(&mut ldap, &self.config.base_dn, &sid.0).await?
        else {
            ldap_client::disconnect(ldap).await;
            return Ok(Vec::new());
        };

        // 2) Resolve the primary group (separate from the `member` chain).
        let primary_group_sid =
            resolve_primary_group(&entry, &self.config.base_dn, &mut ldap).await;

        // 3) Server-side transitive membership of the principal.
        let transitive_groups = ldap_client::search_transitive_groups_for_member(
            &mut ldap,
            &self.config.base_dn,
            &entry.dn,
        )
        .await?;

        // 4) Primary group entry and its transitive parents — needed to
        //    correctly reconstruct chains that run through the primary
        //    group.
        let (pg_entry, pg_parents) = if let Some(ref pg_sid) = primary_group_sid {
            let pg_entry =
                ldap_client::search_by_sid(&mut ldap, &self.config.base_dn, &pg_sid.0).await?;
            let parents = if let Some(ref e) = pg_entry {
                ldap_client::search_transitive_groups_for_member(
                    &mut ldap,
                    &self.config.base_dn,
                    &e.dn,
                )
                .await?
            } else {
                Vec::new()
            };
            (pg_entry, parents)
        } else {
            (None, Vec::new())
        };

        ldap_client::disconnect(ldap).await;

        // 5) Forward-Graph aufbauen: group_dn → Liste von Eltern-DNs (aus
        //    deren `memberOf`-Attribut). Eine Kante G_x → G_y bedeutet
        // 5) Build the forward graph: group_dn → list of parent DNs (from
        //    its `memberOf` attribute). Edge G_x → G_y means "G_x is a
        //    direct member of G_y", i.e. "G_y contains G_x". SID and name
        //    indices kept in parallel.
        let mut forward: HashMap<String, Vec<String>> = HashMap::new();
        let mut dn_to_sid: HashMap<String, Sid> = HashMap::new();
        let mut dn_to_name: HashMap<String, Option<String>> = HashMap::new();

        let mut register_group_entry = |g: &ldap_client::RawEntry| {
            let dn_key = g.dn.to_ascii_lowercase();
            if dn_to_sid.contains_key(&dn_key) {
                return;
            }
            if let Some(sid) = extract_sid_from_entry(g) {
                let name = g
                    .first_attr("sAMAccountName")
                    .or_else(|| g.first_attr("cn"))
                    .map(str::to_owned);
                dn_to_sid.insert(dn_key.clone(), sid);
                dn_to_name.insert(dn_key.clone(), name);
                let parents: Vec<String> = g
                    .all_attr("memberOf")
                    .iter()
                    .map(|d| d.to_ascii_lowercase())
                    .collect();
                forward.insert(dn_key, parents);
            }
        };

        for g in &transitive_groups {
            register_group_entry(g);
        }
        for g in &pg_parents {
            register_group_entry(g);
        }
        if let Some(ref e) = pg_entry {
            register_group_entry(e);
        }

        // 6) BFS starting nodes: the user's direct groups (`memberOf` of
        //    the principal) plus the primary group (if known). Both count
        //    as hop 1 from the user.
        let direct_dns_lc: HashSet<String> = entry
            .all_attr("memberOf")
            .iter()
            .map(|dn| dn.to_ascii_lowercase())
            .collect();

        let primary_dn_lc: Option<String> = pg_entry.as_ref().map(|e| e.dn.to_ascii_lowercase());

        //    reconstruct the concrete DN chains.
        // 7) Multi-source BFS — track each reached DN's predecessor in
        //    `came_from`. Concrete DN chains can then be reconstructed.
        let mut came_from: HashMap<String, Option<String>> = HashMap::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        for d in direct_dns_lc.iter() {
            if dn_to_sid.contains_key(d) {
                came_from.insert(d.clone(), None);
                queue.push_back(d.clone());
            }
        }
        if let Some(ref d) = primary_dn_lc {
            if dn_to_sid.contains_key(d) && !came_from.contains_key(d) {
                came_from.insert(d.clone(), None);
                queue.push_back(d.clone());
            }
        }
        while let Some(node) = queue.pop_front() {
            if let Some(parents) = forward.get(&node) {
                for p in parents {
                    if !dn_to_sid.contains_key(p) {
                        continue;
                    }
                    if came_from.contains_key(p) {
                        continue;
                    }
                    came_from.insert(p.clone(), Some(node.clone()));
                    queue.push_back(p.clone());
                }
            }
        }

        // 8) Assemble memberships and attach paths.
        let mut memberships = Vec::new();
        let mut visited: HashSet<String> = HashSet::new();
        visited.insert(sid.0.clone());

        let user_name = entry
            .first_attr("sAMAccountName")
            .or_else(|| entry.first_attr("cn"))
            .map(str::to_owned);

        // Helper closure: reconstruct the BFS path to group_dn as a SID
        // chain prefixed with the user. Returns None when group_dn was
        // not reached.
        let reconstruct = |group_dn_lc: &str| -> Option<(Vec<Sid>, Vec<Option<String>>)> {
            if !came_from.contains_key(group_dn_lc) {
                return None;
            }
            let mut chain_dns: Vec<String> = Vec::new();
            let mut cur = group_dn_lc.to_owned();
            chain_dns.push(cur.clone());
            while let Some(Some(prev)) = came_from.get(&cur) {
                chain_dns.push(prev.clone());
                cur = prev.clone();
            }
            chain_dns.reverse(); // jetzt Hop-1 → ... → Ziel / now hop-1 → ... → target
            let mut nodes = Vec::with_capacity(chain_dns.len() + 1);
            let mut names = Vec::with_capacity(chain_dns.len() + 1);
            nodes.push(sid.clone());
            names.push(user_name.clone());
            for d in &chain_dns {
                if let Some(s) = dn_to_sid.get(d) {
                    nodes.push(s.clone());
                    names.push(dn_to_name.get(d).cloned().flatten());
                } else {
                    return None;
                }
            }
            Some((nodes, names))
        };

        // 8a) Primary group as its own membership (direct).
        if let Some(ref pg_sid) = primary_group_sid {
            if visited.insert(pg_sid.0.clone()) {
                let pg_name = pg_entry
                    .as_ref()
                    .and_then(|e| {
                        e.first_attr("sAMAccountName")
                            .or_else(|| e.first_attr("cn"))
                    })
                    .map(str::to_owned);
                memberships.push(GroupMembership {
                    member_sid: sid.clone(),
                    group_sid: pg_sid.clone(),
                    direct: true,
                    group_name: pg_name.clone(),
                    path: Some(MembershipPath {
                        nodes: vec![sid.clone(), pg_sid.clone()],
                        names: vec![user_name.clone(), pg_name],
                        source: MembershipPathSource::PrimaryGroup,
                        complete: true,
                    }),
                });
            }
        }

        // 8b) Transitive memberships of the principal.
        for group_entry in &transitive_groups {
            let group_sid = match extract_sid_from_entry(group_entry) {
                Some(s) => s,
                None => continue,
            };
            if !visited.insert(group_sid.0.clone()) {
                continue;
            }
            let dn_lc = group_entry.dn.to_ascii_lowercase();
            let direct = direct_dns_lc.contains(&dn_lc);
            let group_name = group_entry
                .first_attr("sAMAccountName")
                .or_else(|| group_entry.first_attr("cn"))
                .map(str::to_owned);

            let path = match reconstruct(&dn_lc) {
                Some((nodes, names)) => MembershipPath {
                    nodes,
                    names,
                    source: MembershipPathSource::DomainGroup,
                    complete: true,
                },
                None => {
                    // Transitive membership is certain (it is in the
                    // result set) but intermediate hops are unknown —
                    // typically due to a truncated memberOf in an
                    // intermediate group.
                    debug!(
                        target_dn = %group_entry.dn,
                        "could not reconstruct concrete membership path"
                    );
                    MembershipPath {
                        nodes: vec![sid.clone(), group_sid.clone()],
                        names: vec![user_name.clone(), group_name.clone()],
                        source: MembershipPathSource::LdapMatchingRule,
                        complete: false,
                    }
                }
            };

            memberships.push(GroupMembership {
                member_sid: sid.clone(),
                group_sid,
                direct,
                group_name,
                path: Some(path),
            });
        }

        // 8c) Transitive parents of the primary group (separate chain
        //     that runs through the primary group).
        for parent_entry in &pg_parents {
            let parent_sid = match extract_sid_from_entry(parent_entry) {
                Some(s) => s,
                None => continue,
            };
            if !visited.insert(parent_sid.0.clone()) {
                continue;
            }
            let dn_lc = parent_entry.dn.to_ascii_lowercase();
            let group_name = parent_entry
                .first_attr("sAMAccountName")
                .or_else(|| parent_entry.first_attr("cn"))
                .map(str::to_owned);
            let path = match reconstruct(&dn_lc) {
                Some((nodes, names)) => MembershipPath {
                    nodes,
                    names,
                    source: MembershipPathSource::DomainGroup,
                    complete: true,
                },
                None => MembershipPath {
                    nodes: vec![sid.clone(), parent_sid.clone()],
                    names: vec![user_name.clone(), group_name.clone()],
                    source: MembershipPathSource::LdapMatchingRule,
                    complete: false,
                },
            };
            memberships.push(GroupMembership {
                member_sid: sid.clone(),
                group_sid: parent_sid,
                direct: false,
                group_name,
                path: Some(path),
            });
        }

        Ok(memberships)
    }
}

#[async_trait]
impl IdentityResolver for LdapResolver {
    async fn resolve_identity(&self, sid: &Sid) -> Result<Identity, CoreError> {
        self.resolve_identity_internal(sid).await
    }

    async fn resolve_group_memberships(
        &self,
        sid: &Sid,
    ) -> Result<Vec<GroupMembership>, CoreError> {
        self.resolve_memberships_internal(sid).await
    }
}

// --- Hilfsfunktionen / Helper functions ---

/// Parses an Identity from an LDAP entry.
fn parse_identity_from_entry(entry: &RawEntry, sid: &Sid) -> Identity {
    let name = entry
        .first_attr("sAMAccountName")
        .or_else(|| entry.first_attr("cn"))
        .map(String::from);

    let domain = dn_to_domain(&entry.dn);

    let user_principal_name = entry
        .first_attr("userPrincipalName")
        .filter(|s| !s.is_empty())
        .map(String::from);

    let object_classes: Vec<&str> = entry
        .attrs
        .get("objectClass")
        .map(|v| v.iter().map(String::as_str).collect())
        .unwrap_or_default();

    let kind = classify_identity(&object_classes);

    let disabled = entry
        .first_attr("userAccountControl")
        .and_then(|v| v.parse::<u32>().ok())
        .map(|uac| uac & UAC_ACCOUNT_DISABLE != 0)
        .unwrap_or(false);

    Identity {
        sid: sid.clone(),
        name,
        domain,
        kind,
        disabled,
        user_principal_name,
    }
}

/// Determines the IdentityKind from objectClass values.
fn classify_identity(object_classes: &[&str]) -> IdentityKind {
    if object_classes.contains(&"computer") {
        IdentityKind::Computer
    } else if object_classes.contains(&"group") {
        IdentityKind::Group
    } else if object_classes.contains(&"user") {
        IdentityKind::User
    } else {
        IdentityKind::Unknown
    }
}

/// Extracts the SID from an LDAP entry (binary objectSid attribute).
pub fn extract_sid_from_entry(entry: &RawEntry) -> Option<Sid> {
    let bytes = entry.first_bin_attr("objectSid")?;
    match bytes_to_sid_str(bytes) {
        Ok(sid_str) => Some(Sid(sid_str)),
        Err(e) => {
            warn!("SID conversion failed: {e}");
            None
        }
    }
}

/// Extracts the domain name from a distinguished name.
///
/// "CN=User,CN=Users,DC=testdomain,DC=local" → Some("testdomain.local")
fn dn_to_domain(dn: &str) -> Option<String> {
    let dc_parts: Vec<&str> = dn
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            part.strip_prefix("DC=")
        })
        .collect();

    if dc_parts.is_empty() {
        None
    } else {
        Some(dc_parts.join("."))
    }
}

/// Resolves the primary group of a user (not included in memberOf).
///
/// Primary group = domain SID + primaryGroupID as RID.
async fn resolve_primary_group(
    entry: &RawEntry,
    base_dn: &str,
    ldap: &mut ldap3::Ldap,
) -> Option<Sid> {
    let primary_group_id: u32 = entry
        .first_attr("primaryGroupID")
        .and_then(|v| v.parse().ok())?;

    // Derive domain SID from user SID (all sub-authorities except the last RID)
    let user_sid_bytes = entry.first_bin_attr("objectSid")?;
    let user_sid_str = bytes_to_sid_str(user_sid_bytes).ok()?;

    let mut parts: Vec<&str> = user_sid_str.split('-').collect();
    if parts.len() < 4 {
        return None;
    }
    // Letzten Teil (RID) durch primaryGroupID ersetzen
    // Replace last part (RID) with primaryGroupID
    *parts.last_mut()? = "";
    let domain_sid_prefix = parts[..parts.len() - 1].join("-");
    let primary_group_sid_str = format!("{domain_sid_prefix}-{primary_group_id}");

    // Validate that this group actually exists
    match ldap_client::search_by_sid(ldap, base_dn, &primary_group_sid_str).await {
        Ok(Some(_)) => Some(Sid(primary_group_sid_str)),
        Ok(None) => {
            warn!("Primary group not found: {primary_group_sid_str}");
            None
        }
        Err(e) => {
            warn!("Primary group search failed: {e}");
            None
        }
    }
}

// --- Integrationstests ---
//
// --- Integration tests ---
// These tests require a running TESTDOMAIN environment and are marked #[ignore]
// by default. Run with: cargo test -- --ignored
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LdapConfig;

    fn test_config() -> Option<LdapConfig> {
        let server = std::env::var("DEVMS_TEST_LDAP_SERVER").ok()?;
        let base_dn = std::env::var("DEVMS_TEST_LDAP_BASE_DN").ok()?;
        let bind_dn = std::env::var("DEVMS_TEST_LDAP_BIND_DN").ok()?;
        let password = std::env::var("DEVMS_TEST_LDAP_PASSWORD").ok()?;
        // DEVMS_TEST_LDAP_INSECURE=1 allows plain LDAP for test environments without LDAPS
        let insecure = std::env::var("DEVMS_TEST_LDAP_INSECURE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if insecure {
            Some(LdapConfig::new_insecure(
                &server, &base_dn, &bind_dn, &password,
            ))
        } else {
            Some(LdapConfig::new(&server, &base_dn, &bind_dn, &password))
        }
    }

    #[tokio::test]
    #[ignore = "Erfordert laufende TESTDOMAIN-Umgebung / Requires running TESTDOMAIN environment"]
    async fn resolve_administrator_identity() {
        let Some(cfg) = test_config() else { return };
        let base_dn = cfg.base_dn.clone();
        let resolver = LdapResolver::new(cfg.clone());
        // Administrator SID always starts with S-1-5-21-...-500
        // Administrator SID always ends with -500
        // We first search by sAMAccountName to get the SID
        let mut ldap = ldap_client::connect(&cfg).await.unwrap();
        let entry = ldap_client::search_by_samaccount(&mut ldap, &base_dn, "Administrator")
            .await
            .unwrap()
            .expect("Administrator must exist");
        ldap_client::disconnect(ldap).await;

        let sid = extract_sid_from_entry(&entry).expect("Administrator must have SID");
        let identity = resolver.resolve_identity(&sid).await.unwrap();

        assert_eq!(identity.kind, IdentityKind::User);
        assert!(!identity.disabled);
        assert_eq!(identity.name.as_deref(), Some("Administrator"));
    }

    #[tokio::test]
    #[ignore = "Erfordert laufende TESTDOMAIN-Umgebung / Requires running TESTDOMAIN environment"]
    async fn resolve_group_memberships_max_mustermann() {
        let Some(cfg) = test_config() else { return };
        let base_dn = cfg.base_dn.clone();
        let resolver = LdapResolver::new(cfg.clone());

        let mut ldap = ldap_client::connect(&cfg).await.unwrap();
        let entry = ldap_client::search_by_samaccount(&mut ldap, &base_dn, "max.mustermann")
            .await
            .unwrap()
            .expect("max.mustermann must exist");
        ldap_client::disconnect(ldap).await;

        let sid = extract_sid_from_entry(&entry).unwrap();
        let memberships = resolver.resolve_group_memberships(&sid).await.unwrap();

        let group_names: Vec<String> = {
            let mut ldap2 = ldap_client::connect(&cfg).await.unwrap();
            let mut names = Vec::new();
            for m in &memberships {
                if let Ok(Some(e)) =
                    ldap_client::search_by_sid(&mut ldap2, &base_dn, &m.group_sid.0).await
                {
                    if let Some(n) = e.first_attr("sAMAccountName") {
                        names.push(n.to_string());
                    }
                }
            }
            ldap_client::disconnect(ldap2).await;
            names
        };

        // Basic check: at least Domain Users (primary group) must be resolved.
        assert!(
            !group_names.is_empty(),
            "At least one group must be resolved"
        );
        assert!(
            group_names.contains(&"Domain Users".to_string()),
            "Domain Users (primary group) must always be present"
        );

        // (scripts/test-env/02-setup-ad-objects.ps1) angelegte AD-Struktur:
        //   max.mustermann → GRP_IT_Admins   (direct)
        //   max.mustermann → GRP_Development (direct)
        //   GRP_IT_Admins  → GRP_FullAccess_FS    (nested)
        //   GRP_Development → GRP_ShareAccess_SMB (nested)
        //
        // These asserts depend on Finding 8 — transitive resolution now runs
        assert!(
            group_names.contains(&"GRP_IT_Admins".to_string()),
            "GRP_IT_Admins (direkt) fehlt — vorhandene Gruppen: {group_names:?}"
        );
        assert!(
            group_names.contains(&"GRP_Development".to_string()),
            "GRP_Development (direkt) fehlt — vorhandene Gruppen: {group_names:?}"
        );
        assert!(
            group_names.contains(&"GRP_FullAccess_FS".to_string()),
            "GRP_FullAccess_FS (transitiv) fehlt — vorhandene Gruppen: {group_names:?}"
        );
        assert!(
            group_names.contains(&"GRP_ShareAccess_SMB".to_string()),
            "GRP_ShareAccess_SMB (transitiv) fehlt — vorhandene Gruppen: {group_names:?}"
        );

        // GRP_ShareAccess_SMB als direct=false.
        // Verify direct flag: GRP_IT_Admins and GRP_Development must be
        // direct=true, while GRP_FullAccess_FS and GRP_ShareAccess_SMB must
        // be direct=false.
        let mut direct_by_name: std::collections::HashMap<String, bool> =
            std::collections::HashMap::new();
        {
            let mut ldap3 = ldap_client::connect(&cfg).await.unwrap();
            for m in &memberships {
                if let Ok(Some(e)) =
                    ldap_client::search_by_sid(&mut ldap3, &base_dn, &m.group_sid.0).await
                {
                    if let Some(n) = e.first_attr("sAMAccountName") {
                        direct_by_name.insert(n.to_string(), m.direct);
                    }
                }
            }
            ldap_client::disconnect(ldap3).await;
        }
        assert_eq!(
            direct_by_name.get("GRP_IT_Admins"),
            Some(&true),
            "GRP_IT_Admins must be direct=true"
        );
        assert_eq!(
            direct_by_name.get("GRP_Development"),
            Some(&true),
            "GRP_Development must be direct=true"
        );
        assert_eq!(
            direct_by_name.get("GRP_FullAccess_FS"),
            Some(&false),
            "GRP_FullAccess_FS must be direct=false (transitive)"
        );
        assert_eq!(
            direct_by_name.get("GRP_ShareAccess_SMB"),
            Some(&false),
            "GRP_ShareAccess_SMB must be direct=false (transitive)"
        );
    }

    #[tokio::test]
    #[ignore = "Erfordert laufende TESTDOMAIN-Umgebung / Requires running TESTDOMAIN environment"]
    async fn orphaned_sid_returns_unknown() {
        let Some(cfg) = test_config() else { return };
        let resolver = LdapResolver::new(cfg);
        // SID that definitely does not exist in the test domain (valid u32 sub-authorities).
        let fake_sid = Sid("S-1-5-21-1111111111-2222222222-3333333333-9999".to_string());
        let identity = resolver.resolve_identity(&fake_sid).await.unwrap();
        assert_eq!(identity.kind, IdentityKind::Orphaned);
    }

    #[tokio::test]
    #[ignore = "Erfordert laufende TESTDOMAIN-Umgebung / Requires running TESTDOMAIN environment"]
    async fn identity_is_cached_after_first_lookup() {
        let Some(cfg) = test_config() else { return };
        let base_dn = cfg.base_dn.clone();
        let resolver = LdapResolver::new(cfg.clone());

        let mut ldap = ldap_client::connect(&cfg).await.unwrap();
        let entry = ldap_client::search_by_samaccount(&mut ldap, &base_dn, "anna.schmidt")
            .await
            .unwrap()
            .unwrap();
        ldap_client::disconnect(ldap).await;

        let sid = extract_sid_from_entry(&entry).unwrap();

        assert_eq!(resolver.cache_size().await, 0);
        resolver.resolve_identity(&sid).await.unwrap();
        assert_eq!(resolver.cache_size().await, 1);
        // Second call: must come from cache, cache size stays 1
        resolver.resolve_identity(&sid).await.unwrap();
        assert_eq!(resolver.cache_size().await, 1);
    }

    #[test]
    fn dn_to_domain_correct() {
        let dn = "CN=max.mustermann,CN=Users,DC=testdomain,DC=local";
        assert_eq!(dn_to_domain(dn), Some("testdomain.local".to_string()));
    }

    #[test]
    fn dn_to_domain_single_dc() {
        let dn = "CN=obj,DC=corp";
        assert_eq!(dn_to_domain(dn), Some("corp".to_string()));
    }

    #[test]
    fn dn_to_domain_no_dc_returns_none() {
        let dn = "CN=obj,OU=users";
        assert_eq!(dn_to_domain(dn), None);
    }

    #[test]
    fn classify_user() {
        assert_eq!(
            classify_identity(&["top", "person", "user"]),
            IdentityKind::User
        );
    }

    #[test]
    fn classify_group() {
        assert_eq!(classify_identity(&["top", "group"]), IdentityKind::Group);
    }

    #[test]
    fn classify_computer_over_user() {
        assert_eq!(
            classify_identity(&["top", "person", "user", "computer"]),
            IdentityKind::Computer
        );
    }
}
