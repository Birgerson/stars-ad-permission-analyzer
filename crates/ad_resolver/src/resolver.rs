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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use adpa_core::{
    error::CoreError,
    model::{
        GroupMembership, Identity, IdentityKind, MemberNode, MemberVia, MembershipHop,
        MembershipPath, MembershipPathSource, Sid,
    },
    traits::{GroupMembershipResolution, IdentityResolver},
};

use crate::{
    config::LdapConfig,
    ldap_client::{self, RawEntry},
    principal::SidDomainRelation,
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

    /// Enumerate the **direct members** of a group (reverse direction).
    ///
    /// Looks the group up by SID to get its DN, then combines two sources so no
    /// member is silently missed (ADR 0055):
    /// 1. the `member` back-link (`(memberOf=<groupDN>)`, paged) —
    ///    `MemberVia::Direct`;
    /// 2. `primaryGroupID` members (`(primaryGroupID=<RID>)`, paged) —
    ///    `MemberVia::PrimaryGroup` — which are **not** in `member`.
    ///
    /// If exactly one of the two searches fails the other's results are still
    /// returned, with an `incomplete` reason (graceful degradation, no silent
    /// skip). If the group itself is not found, that is an error. Members are
    /// deduplicated by SID (a member cannot legitimately be in both sets, but
    /// the guard keeps the count honest).
    pub async fn enumerate_group_members(
        &self,
        group_sid: &Sid,
    ) -> Result<GroupMemberEnumeration, CoreError> {
        let rid = rid_from_sid(group_sid).ok_or_else(|| {
            CoreError::SidResolution(format!("Cannot derive RID from group SID: {}", group_sid.0))
        })?;
        ldap_client::with_timeout(
            "enumerate_group_members",
            ldap_client::ldap_timeout(&self.config),
            async {
                let mut ldap = ldap_client::connect(&self.config).await?;
                let base_dn = &self.config.base_dn;

                // 1. Resolve the group's DN (needed for the memberOf back-link).
                let group_entry =
                    match ldap_client::search_by_sid(&mut ldap, base_dn, &group_sid.0).await {
                        Ok(Some(e)) => e,
                        Ok(None) => {
                            ldap_client::disconnect(ldap).await;
                            return Err(CoreError::SidResolution(format!(
                                "Group not found in the configured base: {}",
                                group_sid.0
                            )));
                        }
                        Err(e) => {
                            ldap_client::disconnect(ldap).await;
                            return Err(e);
                        }
                    };
                let group_dn = group_entry.dn.clone();
                // A universal group queried over a plain domain bind cannot
                // see members from other domains of the forest (other
                // partitions) — surfaced as a marker, never silently
                // (review 2026-07-03, finding F2).
                let universal_on_domain_bind =
                    is_universal_group_entry(&group_entry) && !self.config.global_catalog;

                // 2. Direct members via the memberOf back-link, and
                // 3. primaryGroupID members — degrade gracefully if one fails.
                let backlink =
                    ldap_client::search_members_by_backlink(&mut ldap, base_dn, &group_dn).await;
                let primary = ldap_client::search_by_primary_group(&mut ldap, base_dn, rid).await;
                ldap_client::disconnect(ldap).await;

                let mut members: Vec<MemberNode> = Vec::new();
                let mut seen: HashSet<String> = HashSet::new();
                let mut incomplete: Option<String> = None;

                match backlink {
                    Ok(entries) => {
                        push_member_entries(&entries, MemberVia::Direct, &mut members, &mut seen)
                    }
                    Err(e) => incomplete = Some(format!("member back-link search failed: {e}")),
                }
                match primary {
                    Ok(entries) => {
                        // `primaryGroupID` holds a bare RID, which is NOT
                        // forest-unique (513 = Domain Users in every domain).
                        // On a Global Catalog bind the search base is empty →
                        // forest-wide, so the query would also match users of
                        // OTHER domains whose own group happens to carry the
                        // same RID — false positives. A primary member lies by
                        // definition in its group's domain, so filter the hits
                        // to the group's domain-SID prefix (Fable review
                        // 2026-07-03, finding F1).
                        let same_domain = filter_same_domain(entries, group_sid);
                        push_member_entries(
                            &same_domain,
                            MemberVia::PrimaryGroup,
                            &mut members,
                            &mut seen,
                        )
                    }
                    Err(e) => {
                        let msg = format!("primaryGroupID search failed: {e}");
                        incomplete = Some(match incomplete {
                            Some(prev) => format!("{prev}; {msg}"),
                            None => msg,
                        });
                    }
                }

                // Both failed → hard error rather than an empty "0 members".
                if members.is_empty() && incomplete.is_some() {
                    return Err(CoreError::LdapQuery(format!(
                        "member enumeration failed: {}",
                        incomplete.unwrap_or_default()
                    )));
                }

                Ok(GroupMemberEnumeration {
                    members,
                    incomplete,
                    universal_on_domain_bind,
                })
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

    /// Classifies a SID the directory holds no object for (ADR 0064, lab
    /// finding AD3-1): does it belong to the configured domain — and does
    /// the configured base cover that domain completely — to a trusted
    /// domain, or to another domain? Read-only (a base search for the
    /// domain SID, a subtree search for the trust objects). Every read
    /// problem yields `Unknown`, so a miss never counts as proof that an
    /// account is gone unless the directory confirmed the domain.
    pub async fn classify_unresolved_sid(&self, sid: &Sid) -> SidDomainRelation {
        let Some(sid_domain) = account_domain_of(sid) else {
            return SidDomainRelation::Unknown {
                reason: format!("{} is not a domain account SID", sid.0),
            };
        };
        let result = ldap_client::with_timeout(
            "classify_unresolved_sid",
            ldap_client::ldap_timeout(&self.config),
            async {
                let mut ldap = ldap_client::connect(&self.config).await?;
                let relation = self.classify_with(&mut ldap, &sid_domain).await;
                ldap_client::disconnect(ldap).await;
                relation
            },
        )
        .await;
        match result {
            Ok(relation) => relation,
            Err(e) => SidDomainRelation::Unknown {
                reason: format!("the directory context could not be read: {e}"),
            },
        }
    }

    async fn classify_with(
        &self,
        ldap: &mut ldap3::Ldap,
        sid_domain: &str,
    ) -> Result<SidDomainRelation, CoreError> {
        if self.config.global_catalog {
            // Forest-wide bind: the identity search already covered every
            // domain of the forest, so a SID of a forest domain is gone.
            let forest = ldap_client::search_forest_domain_sids(ldap, &self.config.base_dn).await?;
            if forest
                .iter()
                .filter(|d| is_domain_sid(d))
                .any(|d| d.eq_ignore_ascii_case(sid_domain))
            {
                return Ok(SidDomainRelation::ConfiguredDomainWholeBase);
            }
            return Ok(SidDomainRelation::OtherDomain {
                domain_sid: sid_domain.to_owned(),
            });
        }
        let Some(root) = domain_root_dn(&self.config.base_dn) else {
            return Ok(SidDomainRelation::Unknown {
                reason: format!(
                    "the configured base '{}' names no domain (no DC= components)",
                    self.config.base_dn
                ),
            });
        };
        let domain_sid = ldap_client::search_domain_sid(ldap, &root)
            .await?
            .filter(|d| is_domain_sid(d));
        let Some(domain_sid) = domain_sid else {
            return Ok(SidDomainRelation::Unknown {
                reason: format!("the domain SID of '{root}' could not be read"),
            });
        };
        if domain_sid.eq_ignore_ascii_case(sid_domain) {
            return Ok(if dn_eq(&self.config.base_dn, &root) {
                SidDomainRelation::ConfiguredDomainWholeBase
            } else {
                SidDomainRelation::ConfiguredDomainPartialBase {
                    base_dn: self.config.base_dn.clone(),
                }
            });
        }
        let trusts = ldap_client::search_domain_trusts(ldap, &root).await?;
        for trust in trusts.iter().filter_map(crate::trusts::parse_trust) {
            if trust
                .sid
                .as_ref()
                .is_some_and(|s| s.0.eq_ignore_ascii_case(sid_domain))
            {
                return Ok(SidDomainRelation::TrustedDomain {
                    partner: trust.partner,
                });
            }
        }
        Ok(SidDomainRelation::OtherDomain {
            domain_sid: sid_domain.to_owned(),
        })
    }

    /// `true` when the configuration targets the Global Catalog.
    pub fn is_global_catalog(&self) -> bool {
        self.config.global_catalog
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
                debug!("Cache hit: {}", sid.0);
                return Ok(identity.clone());
            }
        }

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
                        warn!("Orphaned SID: {}", sid.0);
                        Identity {
                            sid: sid.clone(),
                            name: None,
                            domain: None,
                            kind: IdentityKind::Orphaned,
                            disabled: false,
                            user_principal_name: None,
                            sid_history_count: 0,
                            sid_history: Vec::new(),
                        }
                    }
                })
            },
        )
        .await?;

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

    /// Resolves all group memberships transitively — server-side via
    /// `LDAP_MATCHING_RULE_IN_CHAIN`, plus the primary group (which is not
    /// linked via `member`) and its transitive parents.
    ///
    /// In addition, each membership carries a concrete
    /// [`MembershipPath`] reconstructed from the `memberOf` edges: one
    /// shortest chain, chosen by a fixed rule so repeated runs show the same
    /// chain, plus every further group through which the principal also
    /// enters the target (`also_via`, ADR 0063). When reconstruction is not
    /// possible (e.g. because an intermediate group's `memberOf` was
    /// truncated by the server), the path stays two SIDs long and is marked
    /// `complete = false` with source
    /// [`MembershipPathSource::LdapMatchingRule`] — transitive membership
    /// is certain, the concrete route is not.
    async fn resolve_memberships_internal(
        &self,
        sid: &Sid,
    ) -> Result<GroupMembershipResolution, CoreError> {
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
    ) -> Result<GroupMembershipResolution, CoreError> {
        let mut ldap = ldap_client::connect(&self.config).await?;

        // 1) Load the principal entry.
        let Some(mut entry) =
            ldap_client::search_by_sid(&mut ldap, &self.config.base_dn, &sid.0).await?
        else {
            ldap_client::disconnect(ldap).await;
            // ADR 0066: never an empty membership list that looks complete.
            return Ok(GroupMembershipResolution {
                memberships: Vec::new(),
                gaps: vec![format!(
                    "the account object of {} was not found by the group search under '{}' — \
                     no group membership could be resolved",
                    sid.0, self.config.base_dn
                )],
            });
        };

        // 2) Resolve the primary group (separate from the `member` chain).
        let primary = resolve_primary_group(&entry, &self.config.base_dn, &mut ldap).await;

        // 3) Server-side transitive membership of the principal.
        let mut transitive_groups = ldap_client::search_transitive_groups_for_member(
            &mut ldap,
            &self.config.base_dn,
            &entry.dn,
        )
        .await?;

        // 4) Transitive parents of the primary group — needed to correctly
        //    reconstruct chains that run through the primary group.
        let (primary, mut pg_parents, mut gaps) = match primary {
            PrimaryGroupLookup::Found { sid: pg_sid, entry } => {
                let parents = ldap_client::search_transitive_groups_for_member(
                    &mut ldap,
                    &self.config.base_dn,
                    &entry.dn,
                )
                .await?;
                (Some((pg_sid, Some(entry))), parents, Vec::new())
            }
            PrimaryGroupLookup::NotApplicable => (None, Vec::new(), Vec::new()),
            PrimaryGroupLookup::Missing { reason } => (None, Vec::new(), vec![reason]),
        };

        // 4b) ADR 0066: a `memberOf` larger than the server's MaxValRange
        //     arrives as `memberOf;range=0-1499`; complete it so direct
        //     memberships and further routes are not lost.
        ldap_client::complete_ranged_attribute(&mut ldap, &mut entry, "memberOf").await?;
        for group in transitive_groups.iter_mut().chain(pg_parents.iter_mut()) {
            ldap_client::complete_ranged_attribute(&mut ldap, group, "memberOf").await?;
        }
        let mut primary = primary;
        if let Some((_, Some(pg_entry))) = primary.as_mut() {
            ldap_client::complete_ranged_attribute(&mut ldap, pg_entry, "memberOf").await?;
        }

        ldap_client::disconnect(ldap).await;

        // 5)–8) Assemble the memberships with concrete, reproducible chains
        //       (ADR 0063). Pure function — no LDAP — so the route choice is
        //       unit-tested independently of server answer order.
        let primary_ref = primary
            .as_ref()
            .map(|(pg_sid, pg_entry)| (pg_sid.clone(), pg_entry.as_ref()));
        let assembled =
            assemble_memberships(sid, &entry, primary_ref, &transitive_groups, &pg_parents);
        gaps.extend(assembled.gaps);
        Ok(GroupMembershipResolution {
            memberships: assembled.memberships,
            gaps,
        })
    }
}

/// Outcome of the primary-group lookup (ADR 0066): a missing primary group
/// is a visible gap, never a silently shorter token.
enum PrimaryGroupLookup {
    /// The principal has no primary group (e.g. it is itself a group).
    NotApplicable,
    Found {
        sid: Sid,
        entry: RawEntry,
    },
    /// A user or computer whose primary group could not be read.
    Missing {
        reason: String,
    },
}

/// Display name of a directory entry: `sAMAccountName`, else `cn`.
fn entry_display_name(entry: &RawEntry) -> Option<String> {
    entry
        .first_attr("sAMAccountName")
        .or_else(|| entry.first_attr("cn"))
        .map(str::to_owned)
}

/// Lower-cased, sorted, de-duplicated `memberOf` DNs of an entry — the
/// outgoing "is a direct member of" edges of the membership graph. Sorting
/// here is what makes the route reconstruction independent of the order in
/// which the server returns attribute values (ADR 0063).
fn sorted_member_of(entry: &RawEntry) -> Vec<String> {
    let set: BTreeSet<String> = entry
        .all_attr("memberOf")
        .iter()
        .map(|dn| dn.to_ascii_lowercase())
        .collect();
    set.into_iter().collect()
}

/// One group of the principal's membership closure.
struct ClosureGroup<'a> {
    entry: &'a RawEntry,
    sid: Sid,
    name: Option<String>,
    /// Lower-cased DNs of the groups this group is a direct member of.
    parents: Vec<String>,
}

/// Hop distances, chosen predecessors and reverse edges over the
/// principal's membership closure — the deterministic route table of
/// ADR 0063.
#[derive(Debug, Default)]
struct RouteTable {
    /// Hops from the principal (direct groups and the primary group = 1).
    dist: BTreeMap<String, usize>,
    /// Chosen predecessor per reached group; `None` = the principal itself.
    pred: BTreeMap<String, Option<String>>,
    /// Reverse edges: group DN → sorted DNs of the closure groups that are
    /// direct members of it.
    children: BTreeMap<String, Vec<String>>,
}

impl RouteTable {
    /// Builds the table from the closure (DN → group) and the hop-1 seeds.
    ///
    /// Root cause of the run-to-run variation fixed here (lab campaign
    /// 2026-10-10): the previous breadth-first search took its start nodes
    /// from a `HashSet`, whose iteration order is randomised per process.
    /// When a group was reachable through several equally short chains, the
    /// chain that happened to be expanded first won — a different, equally
    /// valid chain on every run. Now distances come from a plain BFS (order
    /// does not affect distances), and the predecessor of each group is
    /// chosen by an explicit rule: among the member groups exactly one hop
    /// closer to the principal, the one with the alphabetically first
    /// (lower-cased) distinguished name.
    fn build(closure: &BTreeMap<String, ClosureGroup<'_>>, seeds: &BTreeSet<String>) -> Self {
        let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (dn, group) in closure {
            for parent in &group.parents {
                if closure.contains_key(parent) {
                    children.entry(parent.clone()).or_default().push(dn.clone());
                }
            }
        }
        // `closure` iterates in DN order, so every child list is already
        // sorted; sort + dedup anyway so the invariant does not hinge on it.
        for list in children.values_mut() {
            list.sort();
            list.dedup();
        }

        let mut dist: BTreeMap<String, usize> = BTreeMap::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        for seed in seeds {
            if closure.contains_key(seed) && !dist.contains_key(seed) {
                dist.insert(seed.clone(), 1);
                queue.push_back(seed.clone());
            }
        }
        while let Some(node) = queue.pop_front() {
            let Some(d) = dist.get(&node).copied() else {
                continue;
            };
            let Some(group) = closure.get(&node) else {
                continue;
            };
            for parent in &group.parents {
                if closure.contains_key(parent) && !dist.contains_key(parent) {
                    dist.insert(parent.clone(), d + 1);
                    queue.push_back(parent.clone());
                }
            }
        }

        let mut pred: BTreeMap<String, Option<String>> = BTreeMap::new();
        for (dn, d) in &dist {
            if *d == 1 {
                pred.insert(dn.clone(), None);
                continue;
            }
            // Distances are exact, so at least one member group sits at
            // d - 1; `children` is sorted, so the first hit is the
            // alphabetically first DN.
            let chosen = children.get(dn).and_then(|kids| {
                kids.iter()
                    .find(|kid| dist.get(*kid).copied() == Some(d - 1))
                    .cloned()
            });
            pred.insert(dn.clone(), chosen);
        }

        Self {
            dist,
            pred,
            children,
        }
    }

    /// DN chain from hop 1 to `target` (inclusive), or `None` when `target`
    /// was not reached from the principal's direct groups.
    fn chain_to(&self, target: &str) -> Option<Vec<String>> {
        let mut chain = vec![target.to_owned()];
        let mut current = target.to_owned();
        loop {
            match self.pred.get(&current)? {
                None => break,
                Some(prev) => {
                    // Distances strictly decrease along `pred`, so this
                    // terminates; the length bound is a defensive guard.
                    if chain.len() > self.dist.len() {
                        return None;
                    }
                    chain.push(prev.clone());
                    current = prev.clone();
                }
            }
        }
        chain.reverse();
        Some(chain)
    }

    /// Closure groups that are direct members of `target`, except `skip`
    /// (the last hop of the shown chain) — the further routes into the group.
    fn other_entries(&self, target: &str, skip: Option<&str>) -> Vec<String> {
        self.children
            .get(target)
            .map(|kids| {
                kids.iter()
                    .filter(|kid| Some(kid.as_str()) != skip)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Assembles the principal's group memberships from the raw LDAP results:
/// the primary group, every group of the transitive closure, and for each a
/// concrete chain plus the further routes into it (ADR 0063).
///
/// Deterministic by construction — every collection that influences the
/// output is ordered (`BTreeMap`/`BTreeSet`, sorted vectors), so the same
/// directory state always yields byte-identical memberships, whatever order
/// the server returned entries or attribute values in. Output order: the
/// primary group first, then by hop distance, then by name
/// (case-insensitive) and DN; groups whose chain could not be reconstructed
/// come last.
fn assemble_memberships(
    sid: &Sid,
    principal: &RawEntry,
    primary: Option<(Sid, Option<&RawEntry>)>,
    transitive_groups: &[RawEntry],
    pg_parents: &[RawEntry],
) -> AssembledMemberships {
    // Closure: every group the principal is in, keyed by lower-cased DN.
    let mut closure: BTreeMap<String, ClosureGroup<'_>> = BTreeMap::new();
    let mut without_sid: BTreeSet<String> = BTreeSet::new();
    let primary_entry = primary.as_ref().and_then(|(_, e)| *e);
    for entry in transitive_groups
        .iter()
        .chain(pg_parents.iter())
        .chain(primary_entry)
    {
        let dn = entry.dn.to_ascii_lowercase();
        if closure.contains_key(&dn) {
            continue;
        }
        let Some(group_sid) = extract_sid_from_entry(entry) else {
            // ADR 0066: a group the principal is in, but whose SID cannot
            // be read, is missing from the token — say so.
            without_sid.insert(entry.dn.clone());
            continue;
        };
        // A cyclic nesting returns the principal as its own "group"; it is
        // not a membership.
        if group_sid == *sid {
            continue;
        }
        closure.insert(
            dn,
            ClosureGroup {
                entry,
                sid: group_sid,
                name: entry_display_name(entry),
                parents: sorted_member_of(entry),
            },
        );
    }

    // ADR 0066: memberships in groups that are not part of the resolved
    // set — typically outside the configured LDAP base or in another
    // domain — are not in the token either.
    let principal_dn = principal.dn.to_ascii_lowercase();
    // Original spelling of every referenced DN, for a readable gap reason.
    let original_dn: BTreeMap<String, String> = std::iter::once(principal)
        .chain(closure.values().map(|g| g.entry))
        .flat_map(|e| e.all_attr("memberOf").iter())
        .map(|dn| (dn.to_ascii_lowercase(), dn.clone()))
        .collect();
    let mut outside: BTreeSet<String> = BTreeSet::new();
    for dn in sorted_member_of(principal)
        .iter()
        .chain(closure.values().flat_map(|g| g.parents.iter()))
    {
        if !closure.contains_key(dn)
            && *dn != principal_dn
            && !without_sid.iter().any(|w| w.eq_ignore_ascii_case(dn))
        {
            outside.insert(original_dn.get(dn).cloned().unwrap_or_else(|| dn.clone()));
        }
    }
    let mut gaps: Vec<String> = Vec::new();
    if !without_sid.is_empty() {
        gaps.push(format!(
            "{} group(s) of the transitive result have no readable objectSid and are not \
             in the evaluated token: {}",
            without_sid.len(),
            summarize_dns(&without_sid)
        ));
    }
    if !outside.is_empty() {
        gaps.push(format!(
            "the account is (directly or through its groups) a member of {} group(s) outside \
             the resolved set — typically outside the configured LDAP base or in another \
             domain — which are not in the evaluated token: {}",
            outside.len(),
            summarize_dns(&outside)
        ));
    }

    // Hop-1 seeds: the principal's direct groups plus the primary group.
    let direct_dns: BTreeSet<String> = sorted_member_of(principal).into_iter().collect();
    let primary_dn: Option<String> = primary_entry.map(|e| e.dn.to_ascii_lowercase());
    let mut seeds = direct_dns.clone();
    if let Some(dn) = &primary_dn {
        seeds.insert(dn.clone());
    }
    let routes = RouteTable::build(&closure, &seeds);

    let principal_name = entry_display_name(principal);
    let hops = |dns: &[String]| -> Vec<MembershipHop> {
        dns.iter()
            .filter_map(|dn| closure.get(dn))
            .map(|g| MembershipHop {
                sid: g.sid.clone(),
                name: g.name.clone(),
            })
            .collect()
    };

    let mut memberships = Vec::new();

    // Primary group: its own membership via `primaryGroupID`, listed first.
    let primary_sid = primary.as_ref().map(|(s, _)| s.clone());
    if let Some(pg_sid) = &primary_sid {
        if *pg_sid != *sid {
            let pg_name = primary_entry.and_then(entry_display_name);
            let (gh_count, gh_values) = primary_entry
                .map(parse_sid_history)
                .unwrap_or((0, Vec::new()));
            let also_via = primary_dn
                .as_deref()
                .map(|dn| hops(&routes.other_entries(dn, None)))
                .unwrap_or_default();
            memberships.push(GroupMembership {
                member_sid: sid.clone(),
                group_sid: pg_sid.clone(),
                direct: true,
                group_name: pg_name.clone(),
                path: Some(MembershipPath {
                    nodes: vec![sid.clone(), pg_sid.clone()],
                    names: vec![principal_name.clone(), pg_name],
                    source: MembershipPathSource::PrimaryGroup,
                    complete: true,
                    also_via,
                }),
                group_sid_history_count: gh_count,
                group_sid_history: gh_values,
            });
        }
    }

    // Every other closure group, ordered by distance, name, DN.
    let mut rest: Vec<(&String, &ClosureGroup<'_>)> = closure
        .iter()
        .filter(|(_, g)| Some(&g.sid) != primary_sid.as_ref())
        .collect();
    rest.sort_by(|(a_dn, a), (b_dn, b)| {
        let a_dist = routes.dist.get(*a_dn).copied().unwrap_or(usize::MAX);
        let b_dist = routes.dist.get(*b_dn).copied().unwrap_or(usize::MAX);
        let a_name = a.name.as_deref().unwrap_or("").to_lowercase();
        let b_name = b.name.as_deref().unwrap_or("").to_lowercase();
        a_dist
            .cmp(&b_dist)
            .then_with(|| a_name.cmp(&b_name))
            .then_with(|| a_dn.cmp(b_dn))
    });

    for (dn, group) in rest {
        let direct = direct_dns.contains(dn);
        let path = match routes.chain_to(dn) {
            Some(chain) => {
                let mut nodes = Vec::with_capacity(chain.len() + 1);
                let mut names = Vec::with_capacity(chain.len() + 1);
                nodes.push(sid.clone());
                names.push(principal_name.clone());
                for hop in &chain {
                    // Every chain DN comes from the route table, which only
                    // holds closure DNs.
                    if let Some(g) = closure.get(hop) {
                        nodes.push(g.sid.clone());
                        names.push(g.name.clone());
                    }
                }
                let last_hop = chain.len().checked_sub(2).and_then(|i| chain.get(i));
                MembershipPath {
                    nodes,
                    names,
                    source: MembershipPathSource::DomainGroup,
                    complete: true,
                    also_via: hops(&routes.other_entries(dn, last_hop.map(String::as_str))),
                }
            }
            None => {
                // Membership is certain (in the transitive result set), the
                // hops are not — typically a truncated `memberOf` on an
                // intermediate group.
                debug!(
                    target_dn = %group.entry.dn,
                    "could not reconstruct concrete membership path"
                );
                MembershipPath {
                    nodes: vec![sid.clone(), group.sid.clone()],
                    names: vec![principal_name.clone(), group.name.clone()],
                    source: MembershipPathSource::LdapMatchingRule,
                    complete: false,
                    also_via: hops(&routes.other_entries(dn, None)),
                }
            }
        };
        // ADR 0059: the group's own historical SIDs go into the token.
        let (gh_count, gh_values) = parse_sid_history(group.entry);
        memberships.push(GroupMembership {
            member_sid: sid.clone(),
            group_sid: group.sid.clone(),
            direct,
            group_name: group.name.clone(),
            path: Some(path),
            group_sid_history_count: gh_count,
            group_sid_history: gh_values,
        });
    }

    AssembledMemberships { memberships, gaps }
}

/// Memberships plus the gaps found while assembling them (ADR 0066).
struct AssembledMemberships {
    memberships: Vec<GroupMembership>,
    gaps: Vec<String>,
}

/// First three DNs of a set, then "(+N more)" — keeps a gap reason short
/// while naming concrete objects.
fn summarize_dns(dns: &BTreeSet<String>) -> String {
    let shown: Vec<&str> = dns.iter().take(3).map(String::as_str).collect();
    let mut text = shown.join("; ");
    if dns.len() > 3 {
        text.push_str(&format!(" (+{} more)", dns.len() - 3));
    }
    text
}

#[async_trait]
impl IdentityResolver for LdapResolver {
    async fn resolve_identity(&self, sid: &Sid) -> Result<Identity, CoreError> {
        self.resolve_identity_internal(sid).await
    }

    async fn resolve_group_memberships(
        &self,
        sid: &Sid,
    ) -> Result<GroupMembershipResolution, CoreError> {
        self.resolve_memberships_internal(sid).await
    }
}

// --- Hilfsfunktionen / Helper functions ---

/// Parses an Identity from an LDAP entry.
/// Result of [`LdapResolver::enumerate_group_members`]: the direct members
/// plus an optional reason the enumeration was incomplete (one of the two
/// source searches failed but the other succeeded).
#[derive(Debug, Clone)]
pub struct GroupMemberEnumeration {
    pub members: Vec<MemberNode>,
    pub incomplete: Option<String>,
    /// `true` when the group is a **universal** group and the bind was a plain
    /// domain bind — members from other domains of the forest are then not
    /// visible (surfaced as a marker by [`Self::into_report`]).
    pub universal_on_domain_bind: bool,
}

/// Universal bit (0x8) of the `groupType` attribute. `groupType` is a signed
/// value (the 0x80000000 security bit makes security groups negative), so it
/// is parsed as `i64`. Absent/unparsable → `false` (no marker rather than a
/// false alarm; the attribute is readable for any bind that can read the
/// group entry itself).
fn is_universal_group_entry(entry: &RawEntry) -> bool {
    entry
        .first_attr("groupType")
        .and_then(|v| v.parse::<i64>().ok())
        .map(|gt| gt & 0x8 != 0)
        .unwrap_or(false)
}

impl GroupMemberEnumeration {
    /// Assembles the shared [`GroupMembersReport`] for the given group:
    /// sorts members by name (case-insensitive, SID as tie-break) for stable
    /// output, and derives the diagnostics — a neutral primary-group inclusion
    /// note when any member came via `primaryGroupID`, and the incompleteness
    /// marker when a source search failed. Pure (no I/O), so the diagnostics
    /// logic is unit-tested without a directory.
    pub fn into_report(mut self, group: Identity) -> adpa_core::model::GroupMembersReport {
        use adpa_core::model::{GroupMembersReport, MemberVia, PermissionDiagnostic};

        self.members.sort_by(|a, b| {
            let an = a.identity.name.as_deref().unwrap_or("").to_lowercase();
            let bn = b.identity.name.as_deref().unwrap_or("").to_lowercase();
            an.cmp(&bn)
                .then_with(|| a.identity.sid.0.cmp(&b.identity.sid.0))
        });

        let via_primary = self
            .members
            .iter()
            .filter(|m| matches!(m.via, MemberVia::PrimaryGroup))
            .count();

        let mut diagnostics = Vec::new();
        if via_primary > 0 {
            diagnostics
                .push(PermissionDiagnostic::MembersViaPrimaryGroupIncluded { count: via_primary });
        }
        if let Some(reason) = self.incomplete {
            diagnostics.push(PermissionDiagnostic::GroupMemberEnumerationIncomplete { reason });
        }
        if self.universal_on_domain_bind {
            diagnostics.push(PermissionDiagnostic::UniversalGroupCrossDomainMembersNotVisible);
        }

        GroupMembersReport {
            group,
            members: self.members,
            diagnostics,
        }
    }
}

/// Extracts the RID (last SID component) as a number — the value AD stores in
/// `primaryGroupID`. `None` if the SID has no numeric final component.
fn rid_from_sid(sid: &Sid) -> Option<u32> {
    sid.0.rsplit('-').next().and_then(|r| r.parse::<u32>().ok())
}

/// The SID minus its final (RID) component — the domain identifier
/// (`S-1-5-21-a-b-c-513` → `S-1-5-21-a-b-c`). `None` for a SID without a `-`.
fn sid_domain_prefix(sid: &Sid) -> Option<&str> {
    sid.0.rsplit_once('-').map(|(prefix, _rid)| prefix)
}

/// Keeps only the entries whose `objectSid` shares the group's domain-SID
/// prefix. A `primaryGroupID` search matches a bare RID, which is not
/// forest-unique — on a forest-wide (GC) base it would return users of other
/// domains whose group carries the same RID. A primary member always lives in
/// its group's own domain, so this filter is exact, never lossy. Entries
/// without a decodable SID are dropped (they would be skipped downstream
/// anyway).
fn filter_same_domain(entries: Vec<RawEntry>, group_sid: &Sid) -> Vec<RawEntry> {
    let Some(group_domain) = sid_domain_prefix(group_sid).map(str::to_owned) else {
        return entries;
    };
    entries
        .into_iter()
        .filter(|e| {
            extract_sid_from_entry(e)
                .and_then(|s| sid_domain_prefix(&s).map(|p| p == group_domain))
                .unwrap_or(false)
        })
        .collect()
}

/// Builds [`MemberNode`]s from raw LDAP entries, tagging each with `via`,
/// skipping entries without an `objectSid`, and deduplicating by SID against
/// `seen` (a member cannot be both a `member` and a primary-group member, but
/// the guard keeps the count honest and the output stable).
fn push_member_entries(
    entries: &[RawEntry],
    via: MemberVia,
    out: &mut Vec<MemberNode>,
    seen: &mut HashSet<String>,
) {
    for entry in entries {
        let Some(sid) = extract_sid_from_entry(entry) else {
            continue;
        };
        if !seen.insert(sid.0.clone()) {
            continue;
        }
        let identity = parse_identity_from_entry(entry, &sid);
        out.push(MemberNode {
            identity,
            via,
            children: vec![],
        });
    }
}

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

    // sIDHistory: parse the values so the engine can evaluate them into the
    // token (ADR 0056). The count stays the authoritative total: a malformed
    // value is skipped with a warning and the difference between count and
    // parsed values surfaces as SidHistoryPresent ("not evaluated").
    let (sid_history_count, sid_history) = parse_sid_history(entry);

    Identity {
        sid: sid.clone(),
        name,
        domain,
        kind,
        disabled,
        user_principal_name,
        sid_history_count,
        sid_history,
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
    } else if object_classes.contains(&"foreignSecurityPrincipal") {
        // Cross-forest trust principal represented as an FSP object in
        // the home domain (CN=ForeignSecurityPrincipals,…). The real
        // principal type lives in the trust forest; callers should
        // enrich via LSA when possible (known-limitations L1).
        IdentityKind::ForeignSecurityPrincipal
    } else {
        IdentityKind::Unknown
    }
}

/// Parses the multi-valued binary `sIDHistory` attribute of an entry into
/// `(authoritative total, parsed values)` — shared by the identity parser
/// (ADR 0056) and the group-membership construction (ADR 0059). A
/// malformed value is skipped with a warning; the count keeps it visible
/// as "present, not evaluated".
fn parse_sid_history(entry: &RawEntry) -> (usize, Vec<Sid>) {
    let count = entry.value_count("sIDHistory");
    let values: Vec<Sid> = entry
        .all_values("sIDHistory")
        .into_iter()
        .filter_map(|bytes| match bytes_to_sid_str(bytes) {
            Ok(s) => Some(Sid(s)),
            Err(e) => {
                warn!(
                    dn = %entry.dn,
                    error = %e,
                    "Malformed sIDHistory value skipped — it stays un-evaluated"
                );
                None
            }
        })
        .collect();
    (count, values)
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

/// Domain part of a domain-account SID (`S-1-5-21-a-b-c-RID` →
/// `S-1-5-21-a-b-c`), `None` for any other SID shape. Validates every
/// component as a number so a malformed value never classifies.
fn account_domain_of(sid: &Sid) -> Option<String> {
    let parts: Vec<&str> = sid.0.split('-').collect();
    if parts.len() != 8 || !parts[0].eq_ignore_ascii_case("S") || parts[1..4] != ["1", "5", "21"] {
        return None;
    }
    if !parts[4..]
        .iter()
        .all(|p| !p.is_empty() && p.parse::<u32>().is_ok())
    {
        return None;
    }
    Some(parts[..7].join("-"))
}

/// `true` for a domain SID of the shape `S-1-5-21-a-b-c`.
fn is_domain_sid(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    parts.len() == 7
        && parts[0].eq_ignore_ascii_case("S")
        && parts[1..4] == ["1", "5", "21"]
        && parts[4..]
            .iter()
            .all(|p| !p.is_empty() && p.parse::<u32>().is_ok())
}

/// The domain-root DN of a base DN — its `DC=` components
/// (`OU=Lab,DC=corp,DC=test` → `DC=corp,DC=test`). `None` without any.
fn domain_root_dn(base_dn: &str) -> Option<String> {
    let dcs: Vec<&str> = base_dn
        .split(',')
        .map(str::trim)
        .filter(|rdn| {
            rdn.get(..3)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("DC="))
        })
        .collect();
    if dcs.is_empty() {
        None
    } else {
        Some(dcs.join(","))
    }
}

/// Case- and whitespace-insensitive DN comparison (RDN by RDN).
fn dn_eq(a: &str, b: &str) -> bool {
    let norm = |dn: &str| -> Vec<String> {
        dn.split(',')
            .map(|rdn| {
                rdn.trim()
                    .replace(" =", "=")
                    .replace("= ", "=")
                    .to_ascii_lowercase()
            })
            .collect()
    };
    norm(a) == norm(b)
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

/// Resolves the primary group of a user or computer (not in `memberOf`).
///
/// Primary group = domain SID + `primaryGroupID` as RID. Every way this can
/// fail for an account that must have one is a visible gap (ADR 0066) —
/// until v1.9.0 a missing primary group (e.g. Domain Users outside a base
/// that is only an OU) silently dropped it from the token.
async fn resolve_primary_group(
    entry: &RawEntry,
    base_dn: &str,
    ldap: &mut ldap3::Ldap,
) -> PrimaryGroupLookup {
    let classes: Vec<&str> = entry
        .attrs
        .get("objectClass")
        .map(|v| v.iter().map(String::as_str).collect())
        .unwrap_or_default();
    let is_account = matches!(
        classify_identity(&classes),
        IdentityKind::User | IdentityKind::Computer
    );
    let Some(raw_id) = entry.first_attr("primaryGroupID") else {
        return if is_account {
            PrimaryGroupLookup::Missing {
                reason: format!(
                    "the primaryGroupID of {} is not readable — its primary group is not in \
                     the evaluated token",
                    entry.dn
                ),
            }
        } else {
            PrimaryGroupLookup::NotApplicable
        };
    };
    let Ok(primary_group_id) = raw_id.trim().parse::<u32>() else {
        return PrimaryGroupLookup::Missing {
            reason: format!(
                "the primaryGroupID '{raw_id}' of {} is not a number — its primary group is \
                 not in the evaluated token",
                entry.dn
            ),
        };
    };

    // Domain SID = the account SID without its RID.
    let Some(domain_sid_prefix) = extract_sid_from_entry(entry).and_then(|s| account_domain_of(&s))
    else {
        return PrimaryGroupLookup::Missing {
            reason: format!(
                "the domain of {} could not be derived from its objectSid — its primary group \
                 is not in the evaluated token",
                entry.dn
            ),
        };
    };
    let primary_group_sid_str = format!("{domain_sid_prefix}-{primary_group_id}");

    match ldap_client::search_by_sid(ldap, base_dn, &primary_group_sid_str).await {
        Ok(Some(pg_entry)) => PrimaryGroupLookup::Found {
            sid: Sid(primary_group_sid_str),
            entry: pg_entry,
        },
        Ok(None) => {
            warn!("Primary group not found: {primary_group_sid_str}");
            PrimaryGroupLookup::Missing {
                reason: format!(
                    "the primary group {primary_group_sid_str} was not found under the \
                     configured LDAP base '{base_dn}' — it is not in the evaluated token"
                ),
            }
        }
        Err(e) => {
            warn!("Primary group search failed: {e}");
            PrimaryGroupLookup::Missing {
                reason: format!(
                    "the primary group {primary_group_sid_str} could not be read ({e}) — it is \
                     not in the evaluated token"
                ),
            }
        }
    }
}

// --- Integration tests ---
// These tests require a running TESTDOMAIN environment and are marked #[ignore]
// by default. Run with: cargo test -- --ignored
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LdapConfig;

    // --- Unit tests (no LDAP needed): sIDHistory count from the entry ---

    #[test]
    fn parse_identity_reads_sid_history_values() {
        // Two binary sIDHistory values → count 2 AND both values parsed
        // into `sid_history` (ADR 0056).
        let old_a = "S-1-5-21-900-901-902-1104";
        let old_b = "S-1-5-21-900-901-902-1105";
        let mut bin = HashMap::new();
        bin.insert(
            "sIDHistory".to_string(),
            vec![
                crate::sid_util::sid_str_to_bytes(old_a).expect("encode test SID"),
                crate::sid_util::sid_str_to_bytes(old_b).expect("encode test SID"),
            ],
        );
        let mut attrs = HashMap::new();
        attrs.insert("sAMAccountName".to_string(), vec!["mig01".to_string()]);
        let entry = RawEntry {
            dn: "CN=mig01,DC=res,DC=lab".to_string(),
            attrs,
            bin_attrs: bin,
        };
        let id = parse_identity_from_entry(&entry, &Sid("S-1-5-21-1-2-3-1000".into()));
        assert_eq!(id.sid_history_count, 2);
        assert_eq!(
            id.sid_history,
            vec![Sid(old_a.to_string()), Sid(old_b.to_string())]
        );
    }

    #[test]
    fn parse_identity_keeps_count_when_a_sid_history_value_is_malformed() {
        // One valid + one malformed value: the count stays 2 (authoritative
        // total), only the valid value is parsed — the difference is what
        // SidHistoryPresent reports as "not evaluated" (ADR 0056).
        let old_a = "S-1-5-21-900-901-902-1104";
        let mut bin = HashMap::new();
        bin.insert(
            "sIDHistory".to_string(),
            vec![
                crate::sid_util::sid_str_to_bytes(old_a).expect("encode test SID"),
                vec![0xFFu8, 0x00], // not a valid SID structure
            ],
        );
        let mut attrs = HashMap::new();
        attrs.insert("sAMAccountName".to_string(), vec!["mig02".to_string()]);
        let entry = RawEntry {
            dn: "CN=mig02,DC=res,DC=lab".to_string(),
            attrs,
            bin_attrs: bin,
        };
        let id = parse_identity_from_entry(&entry, &Sid("S-1-5-21-1-2-3-1002".into()));
        assert_eq!(id.sid_history_count, 2);
        assert_eq!(id.sid_history, vec![Sid(old_a.to_string())]);
    }

    #[test]
    fn parse_identity_without_sid_history_is_zero() {
        let mut attrs = HashMap::new();
        attrs.insert("sAMAccountName".to_string(), vec!["normal".to_string()]);
        let entry = RawEntry {
            dn: "CN=normal,DC=res,DC=lab".to_string(),
            attrs,
            bin_attrs: HashMap::new(),
        };
        let id = parse_identity_from_entry(&entry, &Sid("S-1-5-21-1-2-3-1001".into()));
        assert_eq!(id.sid_history_count, 0);
        assert!(id.sid_history.is_empty());
    }

    // --- Group → Members (reverse view): pure helpers, no LDAP ---

    /// Little (SID string, sAMAccountName) → RawEntry with a decodable
    /// objectSid. `sid_bytes` is a synthetic marker; `extract_sid_from_entry`
    /// must map it back to `sid_str` for the test to be meaningful, so we set
    /// the SID via a real byte encoding path is overkill — instead we assert on
    /// name/via/dedup using a fixed, unique byte tag per entry and read the
    /// resulting SID through the same decoder used in production.
    fn member_entry(name: &str, sid_bytes: Vec<u8>) -> RawEntry {
        let mut attrs = HashMap::new();
        attrs.insert("sAMAccountName".to_string(), vec![name.to_string()]);
        attrs.insert("objectClass".to_string(), vec!["user".to_string()]);
        let mut bin = HashMap::new();
        bin.insert("objectSid".to_string(), vec![sid_bytes]);
        RawEntry {
            dn: format!("CN={name},DC=res,DC=lab"),
            attrs,
            bin_attrs: bin,
        }
    }

    // A minimal valid SID byte layout: revision(1) + subauth_count(1) +
    // 6-byte authority + N*4-byte subauthorities. Distinct RID → distinct SID.
    fn sid_bytes_with_rid(rid: u32) -> Vec<u8> {
        let mut b = vec![1u8, 2, 0, 0, 0, 0, 0, 5]; // rev=1, 2 subauths, authority 5
        b.extend_from_slice(&21u32.to_le_bytes());
        b.extend_from_slice(&rid.to_le_bytes());
        b
    }

    #[test]
    fn rid_from_sid_extracts_last_component() {
        assert_eq!(rid_from_sid(&Sid("S-1-5-21-1-2-3-513".into())), Some(513));
        assert_eq!(rid_from_sid(&Sid("S-1-5-32-544".into())), Some(544));
        assert_eq!(rid_from_sid(&Sid("not-a-sid".into())), None);
    }

    #[test]
    fn sid_domain_prefix_strips_the_rid() {
        assert_eq!(
            sid_domain_prefix(&Sid("S-1-5-21-1-2-3-513".into())),
            Some("S-1-5-21-1-2-3")
        );
        assert_eq!(
            sid_domain_prefix(&Sid("S-1-5-32-544".into())),
            Some("S-1-5-32")
        );
        assert_eq!(sid_domain_prefix(&Sid("nodash".into())), None);
    }

    /// SID bytes for arbitrary sub-authorities (authority 5) — lets a test
    /// build entries from DIFFERENT domains.
    fn sid_bytes(subauths: &[u32]) -> Vec<u8> {
        let mut b = vec![1u8, subauths.len() as u8, 0, 0, 0, 0, 0, 5];
        for s in subauths {
            b.extend_from_slice(&s.to_le_bytes());
        }
        b
    }

    #[test]
    fn filter_same_domain_drops_foreign_domain_primary_group_hits() {
        // Group: S-1-5-21-1-2-3-513 (Domain Users of domain 1-2-3).
        let group_sid = Sid("S-1-5-21-1-2-3-513".into());
        // Same-domain user (kept) vs. a user of ANOTHER domain whose own
        // Domain Users shares RID 513 — the GC false-positive case (F1).
        let same = member_entry("alice", sid_bytes(&[21, 1, 2, 3, 1104]));
        let foreign = member_entry("mallory", sid_bytes(&[21, 9, 9, 9, 1105]));
        let kept = filter_same_domain(vec![same, foreign], &group_sid);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].first_attr("sAMAccountName"), Some("alice"));
    }

    #[test]
    fn push_member_entries_tags_via_and_dedups_by_sid() {
        let direct = vec![
            member_entry("alice", sid_bytes_with_rid(1001)),
            member_entry("bob", sid_bytes_with_rid(1002)),
        ];
        // "bob" appears again in the primary-group set — must be deduped, and
        // the already-seen SID keeps its FIRST classification (Direct).
        let primary = vec![
            member_entry("bob", sid_bytes_with_rid(1002)),
            member_entry("carol", sid_bytes_with_rid(1003)),
        ];
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        push_member_entries(&direct, MemberVia::Direct, &mut out, &mut seen);
        push_member_entries(&primary, MemberVia::PrimaryGroup, &mut out, &mut seen);

        assert_eq!(out.len(), 3, "bob deduped");
        let carol = out
            .iter()
            .find(|m| m.identity.name.as_deref() == Some("carol"))
            .unwrap();
        assert!(matches!(carol.via, MemberVia::PrimaryGroup));
        let bob = out
            .iter()
            .find(|m| m.identity.name.as_deref() == Some("bob"))
            .unwrap();
        assert!(
            matches!(bob.via, MemberVia::Direct),
            "first classification wins"
        );
    }

    #[test]
    fn push_member_entries_skips_entries_without_sid() {
        let mut attrs = HashMap::new();
        attrs.insert("sAMAccountName".to_string(), vec!["ghost".to_string()]);
        let no_sid = RawEntry {
            dn: "CN=ghost,DC=res,DC=lab".to_string(),
            attrs,
            bin_attrs: HashMap::new(),
        };
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        push_member_entries(&[no_sid], MemberVia::Direct, &mut out, &mut seen);
        assert!(
            out.is_empty(),
            "entry without objectSid is skipped, not panicked on"
        );
    }

    fn grp_identity() -> Identity {
        Identity {
            sid: Sid("S-1-5-21-1-2-3-513".into()),
            name: Some("Domain Users".into()),
            domain: Some("res.lab".into()),
            kind: IdentityKind::Group,
            disabled: false,
            user_principal_name: None,
            sid_history_count: 0,
            sid_history: Vec::new(),
        }
    }

    fn node(name: &str, rid: u32, via: MemberVia) -> MemberNode {
        MemberNode {
            identity: Identity {
                sid: Sid(format!("S-1-5-21-1-2-3-{rid}")),
                name: Some(name.into()),
                domain: Some("res.lab".into()),
                kind: IdentityKind::User,
                disabled: false,
                user_principal_name: None,
                sid_history_count: 0,
                sid_history: Vec::new(),
            },
            via,
            children: vec![],
        }
    }

    // --- Unresolved-SID classification helpers (ADR 0064), no LDAP ---

    #[test]
    fn account_domain_of_accepts_only_domain_account_sids() {
        assert_eq!(
            account_domain_of(&Sid("S-1-5-21-111-222-333-1104".into())).as_deref(),
            Some("S-1-5-21-111-222-333")
        );
        for not_an_account in [
            "S-1-5-32-544",             // builtin alias
            "S-1-5-18",                 // SYSTEM
            "S-1-5-21-111-222-333",     // a domain SID, not an account
            "S-1-5-21-111-222-333-x",   // malformed RID
            "S-1-5-80-1-2-3-4-5",       // service SID
            "S-1-5-21-111-222-333-1-2", // too many parts
        ] {
            assert_eq!(
                account_domain_of(&Sid(not_an_account.into())),
                None,
                "{not_an_account}"
            );
        }
    }

    #[test]
    fn is_domain_sid_validates_shape_and_numbers() {
        assert!(is_domain_sid("S-1-5-21-111-222-333"));
        assert!(!is_domain_sid("S-1-5-21-111-222"));
        assert!(!is_domain_sid("S-1-5-21-111-222-333-500"));
        assert!(!is_domain_sid("S-1-5-21-111-abc-333"));
        assert!(!is_domain_sid(""));
    }

    #[test]
    fn domain_root_dn_keeps_only_dc_components() {
        assert_eq!(
            domain_root_dn("OU=Lab,DC=corp,DC=test").as_deref(),
            Some("DC=corp,DC=test")
        );
        assert_eq!(
            domain_root_dn("dc=corp, dc=test").as_deref(),
            Some("dc=corp,dc=test")
        );
        assert_eq!(domain_root_dn("OU=Lab"), None);
        assert_eq!(domain_root_dn(""), None);
    }

    #[test]
    fn dn_eq_ignores_case_and_spacing() {
        assert!(dn_eq("DC=corp,DC=test", "dc=corp, dc=test"));
        assert!(dn_eq("DC = corp,DC=test", "dc=corp,dc=test"));
        assert!(!dn_eq("OU=Lab,DC=corp,DC=test", "DC=corp,DC=test"));
    }

    // --- Membership assembly: deterministic routes (ADR 0063), no LDAP ---

    const DOM: [u32; 4] = [21, 1, 2, 3];

    fn dn_of(name: &str) -> String {
        format!("CN={name},OU=Groups,DC=corp,DC=test")
    }

    fn sid_of(rid: u32) -> Sid {
        Sid(format!("S-1-5-21-1-2-3-{rid}"))
    }

    /// Group (or principal) entry with a decodable objectSid and the given
    /// `memberOf` parents (by CN, in exactly the given order).
    fn graph_entry(name: &str, rid: u32, member_of: &[&str]) -> RawEntry {
        let mut attrs = HashMap::new();
        attrs.insert("sAMAccountName".to_string(), vec![name.to_string()]);
        if !member_of.is_empty() {
            attrs.insert(
                "memberOf".to_string(),
                member_of.iter().map(|p| dn_of(p)).collect(),
            );
        }
        let mut bin = HashMap::new();
        let mut subauths = DOM.to_vec();
        subauths.push(rid);
        bin.insert("objectSid".to_string(), vec![sid_bytes(&subauths)]);
        RawEntry {
            dn: dn_of(name),
            attrs,
            bin_attrs: bin,
        }
    }

    fn membership_for(ms: &[GroupMembership], rid: u32) -> &GroupMembership {
        let sid = sid_of(rid);
        ms.iter()
            .find(|m| m.group_sid == sid)
            .unwrap_or_else(|| panic!("no membership for RID {rid}"))
    }

    fn chain_names(m: &GroupMembership) -> Vec<String> {
        m.path
            .as_ref()
            .expect("path")
            .names
            .iter()
            .map(|n| n.clone().unwrap_or_default())
            .collect()
    }

    fn also_via_names(m: &GroupMembership) -> Vec<String> {
        m.path
            .as_ref()
            .expect("path")
            .also_via
            .iter()
            .map(|h| h.name.clone().unwrap_or_default())
            .collect()
    }

    #[test]
    fn equal_length_routes_choose_the_same_chain_whatever_the_input_order() {
        // Root cause of the lab finding: u → {gA, gB} → gTarget offers two
        // equally short chains. Every permutation of the server's answer
        // (entry order and memberOf value order) must yield the same output:
        // the alphabetically first predecessor (gA), with gB disclosed as a
        // further route.
        let orders: [(&[&str], [usize; 3]); 4] = [
            (&["gA", "gB"], [0, 1, 2]),
            (&["gB", "gA"], [2, 1, 0]),
            (&["gA", "gB"], [1, 2, 0]),
            (&["gB", "gA"], [2, 0, 1]),
        ];
        let mut rendered: Vec<String> = Vec::new();
        for (user_member_of, perm) in orders {
            let user = graph_entry("u", 1000, user_member_of);
            let groups = [
                graph_entry("gA", 1101, &["gTarget"]),
                graph_entry("gB", 1102, &["gTarget"]),
                graph_entry("gTarget", 1200, &[]),
            ];
            let mut ordered: Vec<RawEntry> = Vec::new();
            let mut pool: Vec<Option<RawEntry>> = groups.into_iter().map(Some).collect();
            for i in perm {
                ordered.push(pool[i].take().expect("each index once"));
            }
            let ms = assemble_memberships(&sid_of(1000), &user, None, &ordered, &[]).memberships;
            let target = membership_for(&ms, 1200);
            assert_eq!(chain_names(target), ["u", "gA", "gTarget"]);
            assert_eq!(also_via_names(target), ["gB"]);
            assert!(!target.direct);
            rendered.push(format!("{ms:?}"));
        }
        assert!(
            rendered.windows(2).all(|w| w[0] == w[1]),
            "output must not depend on server answer order"
        );
    }

    #[test]
    fn also_via_includes_longer_routes_into_the_target() {
        // gTarget is two hops away via gA, and four hops away via
        // gC → gD → gE. The longer route is still a real route: removing
        // the user from gA does not remove the membership.
        let user = graph_entry("u", 1000, &["gA", "gC"]);
        let groups = vec![
            graph_entry("gA", 1101, &["gTarget"]),
            graph_entry("gC", 1103, &["gD"]),
            graph_entry("gD", 1104, &["gE"]),
            graph_entry("gE", 1105, &["gTarget"]),
            graph_entry("gTarget", 1200, &[]),
        ];
        let ms = assemble_memberships(&sid_of(1000), &user, None, &groups, &[]).memberships;
        let target = membership_for(&ms, 1200);
        assert_eq!(chain_names(target), ["u", "gA", "gTarget"]);
        assert_eq!(also_via_names(target), ["gE"]);
        let e = membership_for(&ms, 1105);
        assert_eq!(chain_names(e), ["u", "gC", "gD", "gE"]);
        assert!(also_via_names(e).is_empty());
    }

    #[test]
    fn direct_membership_also_reached_through_nesting_names_the_nested_route() {
        let user = graph_entry("u", 1000, &["gTarget", "gA"]);
        let groups = vec![
            graph_entry("gA", 1101, &["gTarget"]),
            graph_entry("gTarget", 1200, &[]),
        ];
        let ms = assemble_memberships(&sid_of(1000), &user, None, &groups, &[]).memberships;
        let target = membership_for(&ms, 1200);
        assert!(target.direct);
        assert_eq!(chain_names(target), ["u", "gTarget"]);
        assert_eq!(also_via_names(target), ["gA"]);
    }

    #[test]
    fn primary_group_comes_first_and_carries_its_parents() {
        // Primary group "Domain Users" (not in memberOf) is nested in gX;
        // gX must be reached through it.
        let user = graph_entry("u", 1000, &["gB"]);
        let du = graph_entry("Domain Users", 513, &["gX"]);
        let groups = vec![graph_entry("gB", 1102, &[])];
        let parents = vec![graph_entry("gX", 1300, &[])];
        let ms = assemble_memberships(
            &sid_of(1000),
            &user,
            Some((sid_of(513), Some(&du))),
            &groups,
            &parents,
        )
        .memberships;
        assert_eq!(ms[0].group_sid, sid_of(513));
        assert_eq!(
            ms[0].path.as_ref().expect("path").source,
            MembershipPathSource::PrimaryGroup
        );
        assert!(ms[0].direct);
        let x = membership_for(&ms, 1300);
        assert_eq!(chain_names(x), ["u", "Domain Users", "gX"]);
        assert!(!x.direct);
        // Hop-1 groups before hop-2 groups.
        let order: Vec<Sid> = ms.iter().map(|m| m.group_sid.clone()).collect();
        assert_eq!(order, [sid_of(513), sid_of(1102), sid_of(1300)]);
    }

    #[test]
    fn group_without_reconstructable_chain_is_marked_incomplete() {
        // gOrphanChain is in the transitive result, but no memberOf edge
        // leads there (e.g. a truncated memberOf on an intermediate group).
        let user = graph_entry("u", 1000, &["gA"]);
        let groups = vec![
            graph_entry("gA", 1101, &[]),
            graph_entry("gOrphanChain", 1400, &[]),
        ];
        let ms = assemble_memberships(&sid_of(1000), &user, None, &groups, &[]).memberships;
        let m = membership_for(&ms, 1400);
        let path = m.path.as_ref().expect("path");
        assert!(!path.complete);
        assert_eq!(path.source, MembershipPathSource::LdapMatchingRule);
        // Unreachable groups sort after every reachable one.
        assert_eq!(ms.last().map(|m| &m.group_sid), Some(&sid_of(1400)));
    }

    #[test]
    fn cyclic_nesting_terminates_and_never_lists_the_principal_itself() {
        // Group principal gP ∈ gA ∈ gP: the transitive search returns gP
        // itself; that is not a membership.
        let principal = graph_entry("gP", 1500, &["gA"]);
        let groups = vec![
            graph_entry("gA", 1101, &["gP"]),
            graph_entry("gP", 1500, &["gA"]),
        ];
        let ms = assemble_memberships(&sid_of(1500), &principal, None, &groups, &[]).memberships;
        assert_eq!(ms.len(), 1);
        assert_eq!(chain_names(&ms[0]), ["gP", "gA"]);
    }

    // --- ADR 0066: gaps are reported, never dropped ---

    #[test]
    fn group_without_readable_sid_is_reported_as_a_gap() {
        let user = graph_entry("u", 1000, &["gA", "gBroken"]);
        let mut broken = graph_entry("gBroken", 1101, &[]);
        broken.bin_attrs.clear(); // objectSid not readable
        let groups = vec![graph_entry("gA", 1100, &[]), broken];
        let assembled = assemble_memberships(&sid_of(1000), &user, None, &groups, &[]);
        assert_eq!(assembled.memberships.len(), 1);
        assert_eq!(assembled.gaps.len(), 1, "{:?}", assembled.gaps);
        assert!(assembled.gaps[0].contains("no readable objectSid"));
        assert!(assembled.gaps[0].contains("CN=gBroken"));
    }

    #[test]
    fn membership_outside_the_resolved_set_is_reported_as_a_gap() {
        // gA is a member of gOutside, which the transitive search did not
        // return (e.g. outside the configured base): it is missing from the
        // token and must be named.
        let user = graph_entry("u", 1000, &["gA", "gElsewhere"]);
        let groups = vec![graph_entry("gA", 1100, &["gOutside"])];
        let assembled = assemble_memberships(&sid_of(1000), &user, None, &groups, &[]);
        assert_eq!(assembled.gaps.len(), 1, "{:?}", assembled.gaps);
        let gap = &assembled.gaps[0];
        assert!(gap.contains("2 group(s) outside the resolved set"), "{gap}");
        assert!(
            gap.contains("CN=gOutside,OU=Groups") && gap.contains("CN=gElsewhere,OU=Groups"),
            "{gap}"
        );
    }

    #[test]
    fn complete_closure_has_no_gaps() {
        let user = graph_entry("u", 1000, &["gA"]);
        let groups = vec![
            graph_entry("gA", 1100, &["gB"]),
            graph_entry("gB", 1200, &[]),
        ];
        let assembled = assemble_memberships(&sid_of(1000), &user, None, &groups, &[]);
        assert!(assembled.gaps.is_empty(), "{:?}", assembled.gaps);
        // A cyclic nesting back to a group principal is not "outside".
        let principal = graph_entry("gP", 1500, &["gA"]);
        let cyclic = vec![
            graph_entry("gA", 1100, &["gP"]),
            graph_entry("gP", 1500, &["gA"]),
        ];
        let assembled = assemble_memberships(&sid_of(1500), &principal, None, &cyclic, &[]);
        assert!(assembled.gaps.is_empty(), "{:?}", assembled.gaps);
    }

    #[test]
    fn summarize_dns_names_three_and_counts_the_rest() {
        let dns: BTreeSet<String> = (1..=5).map(|i| format!("CN=g{i}")).collect();
        assert_eq!(summarize_dns(&dns), "CN=g1; CN=g2; CN=g3 (+2 more)");
    }

    #[test]
    fn many_permutations_of_a_dense_graph_give_identical_output() {
        // 24 groups, 3–4 parents each, many equal-length alternatives. A
        // fixed-seed shuffle of entry order and memberOf value order must
        // never change the result.
        let names: Vec<String> = (0..24).map(|i| format!("g{i:02}")).collect();
        let parents_of = |i: usize| -> Vec<String> {
            [i + 3, i + 5, i + 7, i + 11]
                .iter()
                .filter(|p| **p < 24)
                .map(|p| names[*p].clone())
                .collect()
        };
        let mut seed: u64 = 0x5EED;
        let mut next = move || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) as usize
        };
        let mut reference: Option<String> = None;
        for _ in 0..40 {
            let mut idx: Vec<usize> = (0..24).collect();
            for k in (1..idx.len()).rev() {
                idx.swap(k, next() % (k + 1));
            }
            let entries: Vec<RawEntry> = idx
                .iter()
                .map(|&i| {
                    let mut ps = parents_of(i);
                    let rot = if ps.is_empty() { 0 } else { next() % ps.len() };
                    ps.rotate_left(rot);
                    let refs: Vec<&str> = ps.iter().map(String::as_str).collect();
                    graph_entry(&names[i], 2000 + i as u32, &refs)
                })
                .collect();
            let mut direct = vec!["g00", "g01", "g02"];
            direct.rotate_left(next() % 3);
            let user = graph_entry("u", 1000, &direct);
            let ms = assemble_memberships(&sid_of(1000), &user, None, &entries, &[]).memberships;
            assert_eq!(ms.len(), 24);
            let rendered = format!("{ms:?}");
            match &reference {
                None => reference = Some(rendered),
                Some(r) => assert_eq!(r, &rendered, "permutation changed the output"),
            }
        }
    }

    #[test]
    fn into_report_sorts_by_name_and_flags_primary_group_inclusion() {
        use adpa_core::model::PermissionDiagnostic;
        let enumeration = GroupMemberEnumeration {
            members: vec![
                node("charlie", 1003, MemberVia::PrimaryGroup),
                node("alice", 1001, MemberVia::Direct),
                node("bob", 1002, MemberVia::PrimaryGroup),
            ],
            incomplete: None,
            universal_on_domain_bind: false,
        };
        let report = enumeration.into_report(grp_identity());
        let names: Vec<_> = report
            .members
            .iter()
            .map(|m| m.identity.name.clone().unwrap())
            .collect();
        assert_eq!(names, vec!["alice", "bob", "charlie"], "sorted by name");
        let (total, via_primary) = report.direct_counts();
        assert_eq!((total, via_primary), (3, 2));
        assert!(report.diagnostics.iter().any(|d| matches!(
            d,
            PermissionDiagnostic::MembersViaPrimaryGroupIncluded { count: 2 }
        )));
    }

    #[test]
    fn into_report_propagates_incompleteness() {
        use adpa_core::model::PermissionDiagnostic;
        let enumeration = GroupMemberEnumeration {
            members: vec![node("alice", 1001, MemberVia::Direct)],
            incomplete: Some("primaryGroupID search failed: timeout".into()),
            universal_on_domain_bind: false,
        };
        let report = enumeration.into_report(grp_identity());
        assert!(report.diagnostics.iter().any(|d| matches!(
            d,
            PermissionDiagnostic::GroupMemberEnumerationIncomplete { .. }
        )));
        // No primary-group members here → no inclusion note.
        assert!(!report.diagnostics.iter().any(|d| matches!(
            d,
            PermissionDiagnostic::MembersViaPrimaryGroupIncluded { .. }
        )));
    }

    #[test]
    fn is_universal_group_entry_reads_the_0x8_bit() {
        let entry = |group_type: &str| {
            let mut attrs = HashMap::new();
            attrs.insert("groupType".to_string(), vec![group_type.to_string()]);
            RawEntry {
                dn: "CN=G,DC=res,DC=lab".to_string(),
                attrs,
                bin_attrs: HashMap::new(),
            }
        };
        // -2147483640 = 0x80000008 (universal security group).
        assert!(is_universal_group_entry(&entry("-2147483640")));
        // -2147483646 = 0x80000002 (global security group).
        assert!(!is_universal_group_entry(&entry("-2147483646")));
        // 8 = universal distribution group.
        assert!(is_universal_group_entry(&entry("8")));
        // Absent attribute → no marker (no false alarm).
        let empty = RawEntry {
            dn: "CN=G,DC=res,DC=lab".to_string(),
            attrs: HashMap::new(),
            bin_attrs: HashMap::new(),
        };
        assert!(!is_universal_group_entry(&empty));
    }

    #[test]
    fn into_report_marks_universal_group_on_domain_bind() {
        use adpa_core::model::PermissionDiagnostic;
        let enumeration = GroupMemberEnumeration {
            members: vec![node("alice", 1001, MemberVia::Direct)],
            incomplete: None,
            universal_on_domain_bind: true,
        };
        let report = enumeration.into_report(grp_identity());
        assert!(report.diagnostics.iter().any(|d| matches!(
            d,
            PermissionDiagnostic::UniversalGroupCrossDomainMembersNotVisible
        )));
    }

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
    #[ignore = "Requires a running TESTDOMAIN environment (set DEVMS_TEST_LDAP_*) — run with `cargo test -- --ignored`"]
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
    #[ignore = "Requires a running TESTDOMAIN environment (set DEVMS_TEST_LDAP_*) — run with `cargo test -- --ignored`"]
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
        let memberships = resolver
            .resolve_group_memberships(&sid)
            .await
            .unwrap()
            .memberships;

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
            "GRP_IT_Admins (direct) missing — present groups: {group_names:?}"
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
    #[ignore = "Requires a running TESTDOMAIN environment (set DEVMS_TEST_LDAP_*) — run with `cargo test -- --ignored`"]
    async fn orphaned_sid_returns_unknown() {
        let Some(cfg) = test_config() else { return };
        let resolver = LdapResolver::new(cfg);
        // SID that definitely does not exist in the test domain (valid u32 sub-authorities).
        let fake_sid = Sid("S-1-5-21-1111111111-2222222222-3333333333-9999".to_string());
        let identity = resolver.resolve_identity(&fake_sid).await.unwrap();
        assert_eq!(identity.kind, IdentityKind::Orphaned);
    }

    #[tokio::test]
    #[ignore = "Requires a running TESTDOMAIN environment (set DEVMS_TEST_LDAP_*) — run with `cargo test -- --ignored`"]
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
