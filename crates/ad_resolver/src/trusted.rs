// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Accounts of a trusted domain (ADR 0078, known limitation L15).
//!
//! When the identity is a SID the configured domain classifies as belonging
//! to a **trusted** domain, and a connection to a domain controller of that
//! domain is configured, the account is resolved there and its token is
//! built the way Windows builds it for a resource in the configured
//! (resource) domain — measured in the lab (Authz on DC-01, 2026-10-17):
//!
//! 1. **Home domain:** the account and its global and universal security
//!    groups — exactly the set the trusted DC itself hands to other domains
//!    (`tokenGroupsGlobalAndUniversal`). The builtin and domain-local groups
//!    of the home domain apply only inside it and are left out (named).
//! 2. **SID filtering:** a quarantined trust (`trustAttributes` 0x4) removes
//!    every SID that does not belong to the trusted domain itself, including
//!    `sIDHistory` values. On any other trust a SID of a third domain is not
//!    modelled: it is left out and reported as a gap, so the result says it
//!    is not determinable instead of guessing.
//! 3. **Resource domain:** the domain-local groups of the configured domain
//!    that contain one of the remaining SIDs as a Foreign Security Principal
//!    (transitively), with the chain continuing from the home-domain path.
//!
//! Builtin and local groups of the target server (e.g. `BUILTIN\Users`
//! through Authenticated Users) come from the frontends' local-group
//! expansion by SID, exactly as for any other account.
//!
//! Strictly read-only: two directory connections, searches only.

use std::collections::HashSet;
use std::sync::Arc;

use adpa_core::error::CoreError;
use adpa_core::model::{
    GroupMembership, Identity, IdentityKind, MembershipPath, MembershipPathSource, Sid,
    TrustAttributes,
};
use adpa_core::traits::{IdentityResolver, TrustedDomainProvenance};
use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::debug;

use crate::principal::{
    disabled_from_ldap, push_diagnostics, GroupResolutionStatus, IdentityScopeStatus,
    PrincipalResolution, TrustContext, TrustedDomainBackend, TrustedForest,
};
use crate::resolver::{account_domain_of, LdapResolver};

/// `name (SID)` or the bare SID.
fn display(sid: &Sid, name: Option<&str>) -> String {
    match name {
        Some(n) if !n.is_empty() => format!("{n} ({})", sid.0),
        _ => sid.0.clone(),
    }
}

/// Outcome of keeping only the memberships that cross the trust.
#[derive(Debug, Default)]
pub struct CrossTrustSelection {
    /// Memberships whose group is in `tokenGroupsGlobalAndUniversal`.
    pub kept: Vec<GroupMembership>,
    /// Memberships that apply only inside the home domain (builtin and
    /// domain-local groups) — `name (SID)`, deduplicated, first-seen order.
    pub home_only: Vec<String>,
    /// SIDs the DC lists as crossing the trust but for which the membership
    /// walk found no entry (no chain known).
    pub without_chain: Vec<Sid>,
}

/// Step 1: keep the memberships whose group the trusted DC hands to other
/// domains. Pure — no LDAP.
pub fn select_cross_domain_memberships(
    memberships: Vec<GroupMembership>,
    global_and_universal: &[String],
) -> CrossTrustSelection {
    let crossing: HashSet<String> = global_and_universal
        .iter()
        .map(|s| s.to_ascii_uppercase())
        .collect();
    let mut out = CrossTrustSelection::default();
    let mut seen_home: HashSet<String> = HashSet::new();
    let mut seen_kept: HashSet<String> = HashSet::new();
    for m in memberships {
        let key = m.group_sid.0.to_ascii_uppercase();
        if crossing.contains(&key) {
            seen_kept.insert(key);
            out.kept.push(m);
        } else if seen_home.insert(key) {
            out.home_only
                .push(display(&m.group_sid, m.group_name.as_deref()));
        }
    }
    for sid in global_and_universal {
        if !seen_kept.contains(&sid.to_ascii_uppercase()) {
            out.without_chain.push(Sid(sid.clone()));
        }
    }
    out
}

/// Outcome of the trust's SID filtering.
#[derive(Debug, Default, PartialEq)]
pub struct SidFilterOutcome {
    /// SIDs the quarantine removes — `name (SID)`.
    pub filtered: Vec<String>,
    /// SIDs whose fate is not modelled — of a third domain on a trust
    /// without quarantine, or of no enabled domain of a trusted forest.
    /// Left out and reported as gaps.
    pub not_modelled: Vec<String>,
}

/// `true` when `sid` belongs to the domain `domain_sid`.
fn of_domain(sid: &Sid, domain_sid: &str) -> bool {
    account_domain_of(sid).is_some_and(|d| d.eq_ignore_ascii_case(domain_sid))
}

/// Step 2: applies the trust's SID filtering to the identity's own
/// `sIDHistory` and to the kept memberships (group SID and the group's
/// `sIDHistory`). Removed values are taken out of both the list and the
/// count, so they do not reappear as "not evaluated". Pure — no LDAP.
///
/// - SIDs of the account's own domain always pass.
/// - Forest trust (ADR 0084, lab 2026-10-24, real SMB logons): SIDs of every
///   domain of the trusted forest whose SID its forest trust information
///   lists as enabled pass — `PARTNER\pt_user02` reached a corp.test folder
///   through `CHILD\UG_CH_Forest`. Every other SID is not modelled.
/// - Quarantined trust that is no forest trust (ADR 0078, measured): every
///   other SID is removed. Quarantine on a forest trust was not measured, so
///   there the other SIDs are not modelled either.
/// - Any other trust: every other SID is not modelled.
pub fn apply_sid_filtering(
    identity: &mut Identity,
    memberships: &mut Vec<GroupMembership>,
    trusted_domain_sid: &str,
    attributes: TrustAttributes,
    forest: Option<&TrustedForest>,
) -> SidFilterOutcome {
    let quarantined = attributes.sid_filtering_enabled() && !attributes.forest_transitive();
    let forest = forest.filter(|_| attributes.forest_transitive());
    let mut out = SidFilterOutcome::default();
    let drop_it = |sid: &Sid, name: Option<&str>, out: &mut SidFilterOutcome| -> bool {
        if of_domain(sid, trusted_domain_sid) {
            return false;
        }
        if let (Some(f), Some(d)) = (forest, account_domain_of(sid)) {
            if f.contains(&d) {
                return false;
            }
        }
        let shown = display(sid, name);
        if quarantined {
            out.filtered.push(shown);
        } else {
            out.not_modelled.push(shown);
        }
        true
    };
    let before = identity.sid_history.len();
    identity
        .sid_history
        .retain(|h| !drop_it(h, Some("sIDHistory of the account"), &mut out));
    let removed = before - identity.sid_history.len();
    identity.sid_history_count = identity.sid_history_count.saturating_sub(removed);

    memberships.retain(|m| !drop_it(&m.group_sid, m.group_name.as_deref(), &mut out));
    for m in memberships.iter_mut() {
        let before = m.group_sid_history.len();
        let label = format!(
            "sIDHistory of {}",
            m.group_name.as_deref().unwrap_or(&m.group_sid.0)
        );
        m.group_sid_history
            .retain(|h| !drop_it(h, Some(&label), &mut out));
        let removed = before - m.group_sid_history.len();
        m.group_sid_history_count = m.group_sid_history_count.saturating_sub(removed);
    }
    out
}

/// Reader-facing gap for a SID whose fate across the trust is not modelled.
fn not_modelled_gap(shown: &str, trust: &TrustContext) -> String {
    match &trust.forest {
        Some(f) if trust.attributes.forest_transitive() => match &f.info_error {
            None => format!(
                "{shown} belongs to no domain of the trusted forest {} whose SID its forest \
                 trust information lists as enabled; whether the trust's SID filtering lets it \
                 through is not modelled, so it was left out",
                f.trust_partner
            ),
            Some(e) => format!(
                "{shown} belongs to another domain than {}; the domains of the trusted forest \
                 {} are not known ({e}), so whether the trust's SID filtering lets it through \
                 is not known — it was left out",
                trust.partner, f.trust_partner
            ),
        },
        _ => format!(
            "{shown} belongs to neither {} nor the configured domain; whether the trust's SID \
             filtering lets it through is not modelled, so it was left out",
            trust.partner
        ),
    }
}

/// Step 3: continues a resource-domain membership of `via` (an FSP chain
/// that starts at `via`) from the account's home-domain path to `via`.
/// `home_path` is `None` when `via` is the account itself. Pure — no LDAP.
pub fn chain_through(
    account: &Sid,
    home_path: Option<&GroupMembership>,
    resource: GroupMembership,
) -> GroupMembership {
    let Some(home) = home_path else {
        // The account's own FSP: the resource chain already starts at it.
        return GroupMembership {
            member_sid: account.clone(),
            ..resource
        };
    };
    let path = match (&home.path, &resource.path) {
        (Some(h), Some(r)) => {
            let mut nodes = h.nodes.clone();
            let mut names = h.names.clone();
            names.resize(nodes.len(), None);
            let mut r_names = r.names.clone();
            r_names.resize(r.nodes.len(), None);
            nodes.extend(r.nodes.iter().skip(1).cloned());
            names.extend(r_names.into_iter().skip(1));
            Some(MembershipPath {
                nodes,
                names,
                source: MembershipPathSource::DomainGroup,
                complete: h.complete && r.complete,
                also_via: r.also_via.clone(),
            })
        }
        _ => None,
    };
    GroupMembership {
        member_sid: account.clone(),
        direct: false,
        path,
        ..resource
    }
}

/// Second directory connection to a domain controller of a trusted domain
/// plus the configured (resource) domain's resolver, for the FSP lookups.
pub struct LdapTrustedDomainBackend {
    trusted: Arc<LdapResolver>,
    resource: Arc<LdapResolver>,
    served: Mutex<Option<Result<String, String>>>,
}

impl LdapTrustedDomainBackend {
    pub fn new(trusted: Arc<LdapResolver>, resource: Arc<LdapResolver>) -> Self {
        Self {
            trusted,
            resource,
            served: Mutex::new(None),
        }
    }
}

#[async_trait]
impl TrustedDomainBackend for LdapTrustedDomainBackend {
    async fn served_domain_sid(&self) -> Result<String, String> {
        let mut cached = self.served.lock().await;
        if let Some(v) = cached.as_ref() {
            return v.clone();
        }
        let v = match self.trusted.configured_domain_sid().await {
            Ok(Some(sid)) => Ok(sid),
            Ok(None) => {
                Err("the directory returned no domain SID for the configured base".to_owned())
            }
            Err(e) => {
                debug!(error = %e, "trusted-domain connection: domain SID not readable");
                Err(e.to_string())
            }
        };
        *cached = Some(v.clone());
        v
    }

    async fn resolve_account(
        &self,
        sid: &Sid,
        trust: &TrustContext,
    ) -> Result<PrincipalResolution, CoreError> {
        // The account in its own domain.
        let mut identity = self.trusted.resolve_identity(sid).await?;
        if identity.kind == IdentityKind::Orphaned {
            return Err(CoreError::Validation(format!(
                "no account with SID {} exists in {}",
                sid.0, trust.partner
            )));
        }
        if identity.domain.is_none() {
            identity.domain = Some(trust.partner.clone());
        }

        // Step 1: its groups there, restricted to what crosses the trust.
        let home = self.trusted.resolve_group_memberships(sid).await?;
        // ADR 0084: the set that crosses the trust comes from the DC's own
        // tokenGroupsGlobalAndUniversal below, read or the resolution fails —
        // so the gaps that only concern which groups the token holds (e.g. a
        // universal group of another domain of the forest, outside this
        // domain's partition) are settled by it. Every other gap stays.
        let token_set: HashSet<&String> = home.token_set_gaps.iter().collect();
        let mut gaps: Vec<String> = home
            .gaps
            .iter()
            .filter(|g| !token_set.contains(g))
            .cloned()
            .collect();
        let mut excluded = home.excluded_groups;
        let global_and_universal = self
            .trusted
            .token_groups_global_and_universal(sid)
            .await?
            .ok_or_else(|| {
                CoreError::LdapQuery(format!(
                    "the domain controller of {} did not return tokenGroupsGlobalAndUniversal \
                     for {} — which of its groups cross the trust is unknown",
                    trust.partner, sid.0
                ))
            })?;
        let selection = select_cross_domain_memberships(home.memberships, &global_and_universal);
        let mut memberships = selection.kept;
        for group_sid in selection.without_chain {
            let name = self
                .trusted
                .resolve_identity(&group_sid)
                .await
                .ok()
                .and_then(|i| i.name);
            memberships.push(GroupMembership {
                member_sid: sid.clone(),
                group_sid,
                direct: false,
                group_name: name,
                path: None,
                group_sid_history_count: 0,
                group_sid_history: Vec::new(),
            });
        }

        // Step 2: the trust's SID filtering.
        let filter = apply_sid_filtering(
            &mut identity,
            &mut memberships,
            &trust.domain_sid,
            trust.attributes,
            trust.forest.as_ref(),
        );
        for s in &filter.not_modelled {
            gaps.push(not_modelled_gap(s, trust));
        }

        // Step 3: domain-local groups of the resource domain through FSPs.
        let mut crossing: Vec<(Sid, Option<GroupMembership>)> = vec![(sid.clone(), None)];
        let mut seen: HashSet<String> = HashSet::new();
        for m in &memberships {
            if seen.insert(m.group_sid.0.to_ascii_uppercase()) {
                crossing.push((m.group_sid.clone(), Some(m.clone())));
            }
        }
        let mut resource_memberships = Vec::new();
        for (via, home_path) in crossing {
            if !self.resource.has_object_for_sid(&via).await? {
                continue; // no FSP in the resource domain: no group there
            }
            let r = self.resource.resolve_group_memberships(&via).await?;
            gaps.extend(r.gaps);
            excluded.extend(r.excluded_groups);
            for m in r.memberships {
                resource_memberships.push(chain_through(sid, home_path.as_ref(), m));
            }
        }
        memberships.extend(resource_memberships);

        // ADR 0079 (lab 2026-10-17, real SMB logons): the token of an account
        // of a trusted domain holds `This Organization` — or, when the trust
        // uses Selective Authentication, `Other Organization` instead. Both
        // decided, so ACEs for either are exact for this account.
        let (org_sid, org_name) = if trust.attributes.selective_authentication() {
            ("S-1-5-1000", "NT AUTHORITY\\Other Organization")
        } else {
            ("S-1-5-15", "NT AUTHORITY\\This Organization")
        };
        let org = Sid(org_sid.to_owned());
        memberships.push(GroupMembership {
            member_sid: sid.clone(),
            group_sid: org.clone(),
            direct: true,
            group_name: Some(org_name.to_owned()),
            path: Some(MembershipPath {
                nodes: vec![sid.clone(), org],
                names: vec![identity.name.clone(), Some(org_name.to_owned())],
                source: MembershipPathSource::TrustedDomainLogon,
                complete: true,
                also_via: Vec::new(),
            }),
            group_sid_history_count: 0,
            group_sid_history: Vec::new(),
        });

        let disabled_status = disabled_from_ldap(&identity);
        let scope = IdentityScopeStatus::ResolvedInTrustedDomain {
            domain: trust.partner.clone(),
        };
        let mut diagnostics = Vec::with_capacity(2);
        push_diagnostics(&mut diagnostics, &scope, disabled_status, identity.disabled);
        debug!(
            sid = %sid.0,
            groups = memberships.len(),
            home_only = selection.home_only.len(),
            filtered = filter.filtered.len(),
            "resolved an account of a trusted domain (ADR 0078)"
        );
        Ok(PrincipalResolution {
            sid: sid.clone(),
            identity,
            memberships,
            scope_status: scope,
            group_resolution_status: GroupResolutionStatus::LdapRecursive,
            disabled_status,
            diagnostics,
            resolved_via_fsp: false,
            resolved_via_global_catalog: false,
            group_resolution_gaps: gaps,
            excluded_groups: excluded,
            trusted_domain: Some(TrustedDomainProvenance {
                domain: trust.partner.clone(),
                home_only_groups: selection.home_only,
                sid_filtered: filter.filtered,
                selective_authentication: trust.attributes.selective_authentication(),
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXT: &str = "S-1-5-21-1667335488-272840759-1416816776";
    const OTHER: &str = "S-1-5-21-9-9-9";

    fn sid(s: &str) -> Sid {
        Sid(s.to_owned())
    }

    fn member(group: &str, name: &str, nodes: &[&str]) -> GroupMembership {
        GroupMembership {
            member_sid: sid(&format!("{EXT}-1105")),
            group_sid: sid(group),
            direct: nodes.len() == 2,
            group_name: Some(name.to_owned()),
            path: Some(MembershipPath {
                nodes: nodes.iter().map(|n| sid(n)).collect(),
                names: nodes.iter().map(|_| None).collect(),
                source: MembershipPathSource::DomainGroup,
                complete: true,
                also_via: Vec::new(),
            }),
            group_sid_history_count: 0,
            group_sid_history: Vec::new(),
        }
    }

    fn user() -> Identity {
        Identity {
            sid: sid(&format!("{EXT}-1105")),
            name: Some("ext_partner01".into()),
            domain: Some("ext.test".into()),
            kind: IdentityKind::User,
            disabled: false,
            user_principal_name: None,
            sid_history_count: 0,
            sid_history: Vec::new(),
        }
    }

    /// Lab measurement 2026-10-17: tokenGroups of ext_partner01 holds
    /// BUILTIN\Users and DL_ExtLocal; tokenGroupsGlobalAndUniversal does not,
    /// and Windows does not put them into a corp.test token.
    #[test]
    fn only_groups_that_cross_the_trust_are_kept() {
        let u = format!("{EXT}-1105");
        let memberships = vec![
            member(
                &format!("{EXT}-513"),
                "Domain Users",
                &[&u, &format!("{EXT}-513")],
            ),
            member(
                "S-1-5-32-545",
                "BUILTIN\\Users",
                &[&u, &format!("{EXT}-513"), "S-1-5-32-545"],
            ),
            member(
                &format!("{EXT}-1113"),
                "DL_ExtLocal",
                &[&u, &format!("{EXT}-1113")],
            ),
            member(
                &format!("{EXT}-1112"),
                "UG_ExtUniversal",
                &[&u, &format!("{EXT}-1112")],
            ),
        ];
        let tggu = vec![format!("{EXT}-1112"), format!("{EXT}-513")];
        let s = select_cross_domain_memberships(memberships, &tggu);
        let kept: Vec<_> = s.kept.iter().map(|m| m.group_sid.0.clone()).collect();
        assert_eq!(kept, [format!("{EXT}-513"), format!("{EXT}-1112")]);
        assert_eq!(
            s.home_only,
            [
                "BUILTIN\\Users (S-1-5-32-545)".to_owned(),
                format!("DL_ExtLocal ({EXT}-1113)")
            ]
        );
        assert!(s.without_chain.is_empty());
    }

    /// A group the DC hands across the trust is never dropped because the
    /// membership walk missed it — it is kept without a chain.
    #[test]
    fn a_crossing_group_without_chain_is_kept() {
        let s = select_cross_domain_memberships(Vec::new(), &[format!("{EXT}-1114")]);
        assert_eq!(s.without_chain, [sid(&format!("{EXT}-1114"))]);
    }

    #[test]
    fn quarantine_removes_every_sid_of_another_domain() {
        let mut id = user();
        id.sid_history = vec![sid(&format!("{OTHER}-1500")), sid(&format!("{EXT}-1600"))];
        id.sid_history_count = 2;
        let mut g = member(&format!("{EXT}-1110"), "GG_ExtPartners", &[]);
        g.group_sid_history = vec![sid(&format!("{OTHER}-77"))];
        g.group_sid_history_count = 1;
        let mut ms = vec![g, member(&format!("{OTHER}-1112"), "UG_Forest", &[])];
        let out = apply_sid_filtering(&mut id, &mut ms, EXT, TrustAttributes::from_bits(0x4), None);
        assert_eq!(id.sid_history, [sid(&format!("{EXT}-1600"))]);
        assert_eq!(
            id.sid_history_count, 1,
            "removed values leave the count too"
        );
        assert_eq!(ms.len(), 1);
        assert!(ms[0].group_sid_history.is_empty());
        assert_eq!(ms[0].group_sid_history_count, 0);
        assert_eq!(out.filtered.len(), 3);
        assert!(out.not_modelled.is_empty());
    }

    /// Without quarantine Stars does not know what the trust lets through:
    /// a third-domain SID is left out and reported (never silently).
    #[test]
    fn without_quarantine_a_third_domain_sid_is_not_modelled() {
        let mut id = user();
        let mut ms = vec![member(&format!("{OTHER}-1112"), "UG_Forest", &[])];
        let out = apply_sid_filtering(&mut id, &mut ms, EXT, TrustAttributes::from_bits(0x8), None);
        assert!(ms.is_empty());
        assert!(out.filtered.is_empty());
        assert_eq!(out.not_modelled, [format!("UG_Forest ({OTHER}-1112)")]);
    }

    #[test]
    fn sids_of_the_trusted_domain_pass_any_trust() {
        let mut id = user();
        let mut ms = vec![member(&format!("{EXT}-1110"), "GG_ExtPartners", &[])];
        for bits in [0x4, 0x8, 0x0] {
            let out = apply_sid_filtering(
                &mut id,
                &mut ms,
                EXT,
                TrustAttributes::from_bits(bits),
                None,
            );
            assert_eq!(ms.len(), 1);
            assert_eq!(out, SidFilterOutcome::default());
        }
    }

    fn forest(domains: &[&str], info_error: Option<&str>) -> TrustedForest {
        TrustedForest {
            trust_partner: "partner.test".to_owned(),
            domain_sids: domains.iter().map(|d| (*d).to_owned()).collect(),
            info_error: info_error.map(str::to_owned),
        }
    }

    /// ADR 0084, lab 2026-10-24 (real SMB logon): `PARTNER\pt_user02` holds
    /// `CHILD\UG_CH_Forest` in its token at a corp.test resource — a SID of
    /// another domain of the trusted forest passes the forest trust.
    #[test]
    fn a_forest_trust_lets_the_sids_of_its_forest_domains_pass() {
        let mut id = user();
        id.sid_history = vec![sid(&format!("{OTHER}-1500"))];
        id.sid_history_count = 1;
        let mut ms = vec![
            member(&format!("{EXT}-1110"), "GG_Root", &[]),
            member(&format!("{OTHER}-1107"), "UG_CH_Forest", &[]),
            member("S-1-5-21-7-7-7-1200", "UG_ThirdForest", &[]),
        ];
        let f = forest(&[EXT, OTHER], None);
        let out = apply_sid_filtering(
            &mut id,
            &mut ms,
            EXT,
            TrustAttributes::from_bits(0x8),
            Some(&f),
        );
        assert_eq!(
            id.sid_history.len(),
            1,
            "a history SID of a forest domain passes"
        );
        assert_eq!(ms.len(), 2);
        assert!(out.filtered.is_empty());
        assert_eq!(out.not_modelled, ["UG_ThirdForest (S-1-5-21-7-7-7-1200)"]);
    }

    /// The forest list counts only on a forest trust, and quarantine on a
    /// forest trust (not measured) removes nothing — it is not modelled.
    #[test]
    fn quarantine_on_a_forest_trust_is_not_modelled() {
        let f = forest(&[EXT], None);
        let mut id = user();
        let mut ms = vec![member(&format!("{OTHER}-1112"), "UG_Other", &[])];
        let out = apply_sid_filtering(
            &mut id,
            &mut ms,
            EXT,
            TrustAttributes::from_bits(0xC),
            Some(&f),
        );
        assert!(out.filtered.is_empty());
        assert_eq!(out.not_modelled.len(), 1);

        // A forest passed for a trust that is no forest trust is ignored.
        let g = forest(&[EXT, OTHER], None);
        let mut ms = vec![member(&format!("{OTHER}-1112"), "UG_Other", &[])];
        let out = apply_sid_filtering(
            &mut id,
            &mut ms,
            EXT,
            TrustAttributes::from_bits(0x4),
            Some(&g),
        );
        assert_eq!(
            out.filtered.len(),
            1,
            "external quarantine still removes it"
        );
    }

    #[test]
    fn the_not_modelled_gap_names_the_forest_and_unknown_forest_information() {
        let mut trust = TrustContext {
            partner: "child.partner.test".to_owned(),
            domain_sid: OTHER.to_owned(),
            attributes: TrustAttributes::from_bits(0x8),
            forest: Some(forest(&[EXT, OTHER], None)),
        };
        let g = not_modelled_gap("X (S-1-5-21-7-7-7-1)", &trust);
        assert!(
            g.contains("no domain of the trusted forest partner.test"),
            "{g}"
        );
        trust.forest = Some(forest(&[], Some("not returned")));
        let g = not_modelled_gap("X (S-1-5-21-7-7-7-1)", &trust);
        assert!(g.contains("are not known (not returned)"), "{g}");
        trust.forest = None;
        trust.attributes = TrustAttributes::from_bits(0x0);
        let g = not_modelled_gap("X (S-1-5-21-7-7-7-1)", &trust);
        assert!(g.contains("belongs to neither child.partner.test"), "{g}");
    }

    /// The resource-domain chain continues the home-domain path:
    /// user → GG_ExtAuditors → GG_ExtNested → gt_DL_trust → gt_DL_trust_outer.
    #[test]
    fn resource_chain_continues_the_home_path() {
        let u = format!("{EXT}-1108");
        let home = member(
            &format!("{EXT}-1114"),
            "GG_ExtNested",
            &[&u, &format!("{EXT}-1111"), &format!("{EXT}-1114")],
        );
        let mut resource = member(
            "S-1-5-21-1-2-3-16186",
            "gt_DL_trust_outer",
            &[
                &format!("{EXT}-1114"),
                "S-1-5-21-1-2-3-16185",
                "S-1-5-21-1-2-3-16186",
            ],
        );
        resource.member_sid = sid(&format!("{EXT}-1114"));
        let m = chain_through(&sid(&u), Some(&home), resource);
        assert_eq!(m.member_sid, sid(&u));
        assert!(!m.direct);
        let nodes: Vec<_> = m
            .path
            .as_ref()
            .unwrap()
            .nodes
            .iter()
            .map(|n| n.0.clone())
            .collect();
        assert_eq!(
            nodes,
            [
                u.clone(),
                format!("{EXT}-1111"),
                format!("{EXT}-1114"),
                "S-1-5-21-1-2-3-16185".to_owned(),
                "S-1-5-21-1-2-3-16186".to_owned()
            ]
        );
        assert_eq!(m.path.unwrap().names.len(), 5);
    }

    #[test]
    fn the_accounts_own_fsp_keeps_its_chain() {
        let u = format!("{EXT}-1106");
        let mut resource = member(
            "S-1-5-21-1-2-3-16160",
            "DL_X",
            &[&u, "S-1-5-21-1-2-3-16160"],
        );
        resource.member_sid = sid(&u);
        let m = chain_through(&sid(&u), None, resource.clone());
        assert_eq!(m.member_sid, resource.member_sid);
        assert_eq!(m.group_sid, resource.group_sid);
        assert_eq!(m.direct, resource.direct);
        assert_eq!(m.path, resource.path);
    }
}
