// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Input forms (`DOMAIN\user`, UPN, plain `sAMAccountName`, direct
//! SID, GUI Name → SID-Workflow).
//!
//! `lookup_via_*`-Helfern in [`crate::resolver::LdapResolver`] plus
//! [`IdentityKind::Orphaned`]. Review 2026-06-04 round 3
//! gemeinsam nutzen.
//!
//! Unified principal resolution — the single pipeline for all input
//! forms (`DOMAIN\user`, UPN, plain `sAMAccountName`, direct SID, GUI
//! name → SID workflow).
//!
//! Background: until v1.4.1 the logic was scattered across three
//! `lookup_via_*` helpers in [`crate::resolver::LdapResolver`] plus a
//! side path in the GUI (`resolve_name_to_sid` → SID-only string,
//! followed by `resolver.resolve_identity(&sid)`). Result: the
//! multi-domain / trust fallback only fired for `DOMAIN\user`, not for
//! the other three input forms — a real trust principal was classified
//! either correctly as an LSA-only identity or silently as
//! [`IdentityKind::Orphaned`] depending on the input form. Review
//! 2026-06-04 round 3 finding 1 surfaced this architectural defect;
//! this module closes it through a **single** pipeline shared between
//! CLI and GUI.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, warn};

use adpa_core::error::CoreError;
use adpa_core::model::{GroupMembership, Identity, IdentityKind, PermissionDiagnostic, Sid};

/// `@` → Upn, `S-1-…` → Sid, sonst → SamAccount).
///
/// User-supplied input. `Auto` is classified at run time by syntax.
#[derive(Debug, Clone)]
pub enum PrincipalInput {
    /// Raw input; dispatcher decides by syntax.
    Auto(String),
    /// Explicit `DOMAIN\user` — LSA-first path.
    DomainQualified(String),
    /// Explizit `user@domain.tld`.
    /// Explicit `user@domain.tld`.
    Upn(String),
    /// Explizit nur `sAMAccountName`.
    /// Explicit `sAMAccountName` only.
    SamAccount(String),
    /// Explizit eine SID (`S-1-…`).
    /// Explicit SID (`S-1-…`).
    Sid(Sid),
    /// [`IdentityScopeStatus::OutsideConfiguredLdapBase`] markiert
    /// GUI name search.
    DisplayName(String),
}

impl PrincipalInput {
    /// Identity-Dispatch).
    /// Classifies `Auto` by syntax; trims whitespace first.
    pub fn classify(self) -> Result<Self, CoreError> {
        match self {
            Self::Auto(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(CoreError::Validation(
                        "Empty identity input — provide DOMAIN\\user, user@domain.tld, sAMAccountName or SID"
                            .to_owned(),
                    ));
                }
                if trimmed.starts_with("S-1-") {
                    Ok(Self::Sid(Sid(trimmed.to_owned())))
                } else if trimmed.contains('\\') {
                    Ok(Self::DomainQualified(trimmed.to_owned()))
                } else if trimmed.contains('@') {
                    Ok(Self::Upn(trimmed.to_owned()))
                } else {
                    Ok(Self::SamAccount(trimmed.to_owned()))
                }
            }
            other => Ok(other),
        }
    }
}

///
/// Classifies the identity resolution outcome relative to the
/// configured LDAP scope. Replaces the former overloaded
/// [`IdentityKind::Orphaned`] variant which conflated two
/// semantically different cases (truly orphaned SID vs. real user from
/// a trust domain outside the configured `base_dn`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityScopeStatus {
    /// `IdentityKind` classification).
    /// LDAP hit inside the configured `base_dn`.
    InsideConfiguredLdapBase,
    /// Domain indexiert. Identity stammt aus LSA-Reverse-Lookup;
    /// LDAP miss, but LSA resolved the SID — typical in multi-domain
    /// forests / trusts.
    OutsideConfiguredLdapBase,
    /// LDAP miss AND LSA miss. Truly orphaned SID.
    OrphanedSid,
    /// LDAP connection itself failed.
    LookupFailed { reason: String },
}

/// `group_resolution_via_sam_fallback`.
/// Status of the group resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupResolutionStatus {
    /// `LDAP_MATCHING_RULE_IN_CHAIN`. Komplett.
    /// Recursive LDAP resolution. Complete.
    LdapRecursive,
    /// SAM/NetAPI path: only direct domain groups + local group chains.
    SamFlat,
    /// Resolution failed.
    Failed { reason: String },
    /// Deliberately skipped.
    NotAttempted,
}

/// zusammenfallen.
/// Tri-state for the `disabled` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisabledStatus {
    Known(bool),
    Unknown,
}

impl DisabledStatus {
    /// Bool accessor with conservative default.
    pub fn as_bool_conservative(self) -> bool {
        matches!(self, Self::Known(true))
    }
}

/// `PermissionEvaluationInput`-Konstruktion teilen.
/// Complete principal resolution outcome.
#[derive(Debug, Clone)]
pub struct PrincipalResolution {
    pub sid: Sid,
    pub identity: Identity,
    pub memberships: Vec<GroupMembership>,
    pub scope_status: IdentityScopeStatus,
    pub group_resolution_status: GroupResolutionStatus,
    pub disabled_status: DisabledStatus,
    /// Pre-collected diagnostic markers.
    pub diagnostics: Vec<PermissionDiagnostic>,
    /// `true` when the identity was resolved through a Foreign Security
    /// Principal object in the home domain (known-limitations L1).
    /// Home-domain group memberships were resolved through the FSP
    /// object; trust-forest memberships are unknown.
    pub resolved_via_fsp: bool,
    /// `true` when group memberships were resolved through a Global
    /// Catalog bind (known-limitations L2) — only universal group
    /// memberships replicate fully to the GC.
    pub resolved_via_global_catalog: bool,
}

impl PrincipalResolution {
    /// Status-Feldern ableiten.
    /// Derives the engine flags from the resolution status — the
    /// single official source for the corresponding
    /// `PermissionEvaluationInput` fields.
    pub fn engine_flags(&self) -> EngineFlags {
        // Review 2026-06-04 round 4 finding 1: LookupFailed,
        // daraus IdentityLookupFailed / GroupResolutionFailed-Marker.
        // Review round 4 finding 1.
        let identity_lookup_failure_reason = match &self.scope_status {
            IdentityScopeStatus::LookupFailed { reason } => Some(reason.clone()),
            _ => None,
        };
        let group_resolution_failure_reason = match &self.group_resolution_status {
            GroupResolutionStatus::Failed { reason } => Some(reason.clone()),
            // NotAttempted in the Outside path is structurally incomplete.
            GroupResolutionStatus::NotAttempted
                if matches!(
                    self.scope_status,
                    IdentityScopeStatus::OutsideConfiguredLdapBase
                ) =>
            {
                Some(
                    "group resolution skipped: identity is outside the configured LDAP base"
                        .to_owned(),
                )
            }
            _ => None,
        };
        EngineFlags {
            identity_not_in_configured_ldap_base: matches!(
                self.scope_status,
                IdentityScopeStatus::OutsideConfiguredLdapBase
            ),
            identity_disabled_status_unknown: matches!(
                self.disabled_status,
                DisabledStatus::Unknown
            ),
            group_resolution_via_sam_fallback: matches!(
                self.group_resolution_status,
                GroupResolutionStatus::SamFlat
            ),
            identity_lookup_failure_reason,
            group_resolution_failure_reason,
            identity_resolved_via_fsp: self.resolved_via_fsp,
            group_resolution_via_global_catalog: self.resolved_via_global_catalog,
        }
    }
}

/// Flag bundle fed into `PermissionEvaluationInput`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineFlags {
    pub identity_not_in_configured_ldap_base: bool,
    pub identity_disabled_status_unknown: bool,
    pub group_resolution_via_sam_fallback: bool,
    /// Engine pushes `PermissionDiagnostic::IdentityLookupFailed`;
    /// the risk engine marks derived findings incomplete. Default `None`.
    pub identity_lookup_failure_reason: Option<String>,
    pub group_resolution_failure_reason: Option<String>,
    /// Engine pushes
    /// `PermissionDiagnostic::IdentityResolvedViaForeignSecurityPrincipal`.
    pub identity_resolved_via_fsp: bool,
    /// Engine pushes
    /// `PermissionDiagnostic::GroupResolutionViaGlobalCatalog`.
    pub group_resolution_via_global_catalog: bool,
}

// ---------------------------------------------------------------------------
// Backend traits — the abstraction layer that makes phase 2 testable.
// ---------------------------------------------------------------------------

/// LDAP backend the principal resolver consumes.
#[async_trait]
pub trait IdentityBackend: Send + Sync {
    /// als `Err` propagiert.
    /// SID → Identity inside the configured LDAP base.
    async fn lookup_identity_by_sid(&self, sid: &Sid) -> Result<Option<Identity>, CoreError>;

    /// UPN → (SID, Identity).
    /// UPN → (SID, Identity).
    async fn lookup_identity_by_upn(&self, upn: &str)
        -> Result<Option<(Sid, Identity)>, CoreError>;

    /// [`PrincipalResolver::resolve`]).
    /// `sAMAccountName` → all matching identities (caller dedupes).
    async fn lookup_identities_by_sam(&self, sam: &str) -> Result<Vec<(Sid, Identity)>, CoreError>;

    /// Recursive group resolution.
    async fn resolve_memberships(&self, sid: &Sid) -> Result<Vec<GroupMembership>, CoreError>;

    /// `true` when this backend searches the whole forest (Global
    /// Catalog bind). Identity misses then mean "not in the forest"
    /// rather than "outside the configured base", and group
    /// memberships are potentially incomplete (only universal groups
    /// replicate fully to the GC). Default: `false`.
    fn is_forest_wide(&self) -> bool {
        false
    }
}

/// LSA backend for Windows reverse lookups.
pub trait LsaBackend: Send + Sync {
    /// Name → SID.
    fn lookup_sid_for_name(&self, name: &str) -> Result<Sid, CoreError>;

    /// LDAP-Miss.
    /// SID → account info for the LSA-only identity build path.
    fn lookup_account_for_sid(&self, sid: &Sid) -> Result<LsaAccountInfo, CoreError>;
}

/// Reduced account info DTO.
#[derive(Debug, Clone)]
pub struct LsaAccountInfo {
    pub name: String,
    pub domain: String,
    pub kind: IdentityKind,
}

// ---------------------------------------------------------------------------
// Adapter: bestehender LdapResolver als IdentityBackend.
// Adapter: existing LdapResolver as IdentityBackend.
// ---------------------------------------------------------------------------

/// Adapter that exposes [`crate::resolver::LdapResolver`] as an
/// [`IdentityBackend`].
pub struct LdapIdentityBackend {
    inner: Arc<crate::resolver::LdapResolver>,
}

impl LdapIdentityBackend {
    pub fn new(resolver: Arc<crate::resolver::LdapResolver>) -> Self {
        Self { inner: resolver }
    }
}

#[async_trait]
impl IdentityBackend for LdapIdentityBackend {
    async fn lookup_identity_by_sid(&self, sid: &Sid) -> Result<Option<Identity>, CoreError> {
        use adpa_core::traits::IdentityResolver;
        // einsteht.
        // `resolve_identity` returns an `Orphaned` identity on miss;
        // here we translate that to `None`.
        let identity = self.inner.resolve_identity(sid).await?;
        if identity.kind == IdentityKind::Orphaned {
            Ok(None)
        } else {
            Ok(Some(identity))
        }
    }

    async fn lookup_identity_by_upn(
        &self,
        upn: &str,
    ) -> Result<Option<(Sid, Identity)>, CoreError> {
        self.inner.lookup_by_upn_raw(upn).await
    }

    async fn lookup_identities_by_sam(&self, sam: &str) -> Result<Vec<(Sid, Identity)>, CoreError> {
        self.inner.lookup_all_by_sam_raw(sam).await
    }

    async fn resolve_memberships(&self, sid: &Sid) -> Result<Vec<GroupMembership>, CoreError> {
        use adpa_core::traits::IdentityResolver;
        self.inner.resolve_group_memberships(sid).await
    }

    fn is_forest_wide(&self) -> bool {
        self.inner.is_global_catalog()
    }
}

// ---------------------------------------------------------------------------
// LSA-Backend-Implementierungen (Windows / Non-Windows).
// LSA backend implementations (Windows / non-Windows).
// ---------------------------------------------------------------------------

/// Produktiv-LSA-Backend (Windows). Delegiert an `crate::sam`.
/// Production LSA backend (Windows).
#[cfg(windows)]
pub struct WindowsLsaBackend;

#[cfg(windows)]
impl LsaBackend for WindowsLsaBackend {
    fn lookup_sid_for_name(&self, name: &str) -> Result<Sid, CoreError> {
        crate::sam::lookup_sid_for_account(None, name)
    }

    fn lookup_account_for_sid(&self, sid: &Sid) -> Result<LsaAccountInfo, CoreError> {
        let info = crate::sam::lookup_account_for_sid(&sid.0)?;
        Ok(LsaAccountInfo {
            name: info.name,
            domain: info.domain,
            kind: info.kind,
        })
    }
}

/// Non-Windows stub.
#[cfg(not(windows))]
pub struct NoLsaBackend;

#[cfg(not(windows))]
impl LsaBackend for NoLsaBackend {
    fn lookup_sid_for_name(&self, _name: &str) -> Result<Sid, CoreError> {
        Err(CoreError::Validation(
            "Name-based identity input requires Windows LSA — not available on this platform"
                .to_owned(),
        ))
    }

    fn lookup_account_for_sid(&self, _sid: &Sid) -> Result<LsaAccountInfo, CoreError> {
        Err(CoreError::Validation(
            "LSA reverse lookup requires Windows — not available on this platform".to_owned(),
        ))
    }
}

// ---------------------------------------------------------------------------
// PrincipalResolver — the central pipeline.
// ---------------------------------------------------------------------------

///
///
///
/// Orchestrates the five-step principal resolution pipeline shared by
/// CLI and GUI.
pub struct PrincipalResolver<B, L>
where
    B: IdentityBackend,
    L: LsaBackend,
{
    identity_backend: B,
    lsa_backend: Option<L>,
}

impl<B, L> PrincipalResolver<B, L>
where
    B: IdentityBackend,
    L: LsaBackend,
{
    pub fn new(identity_backend: B, lsa_backend: Option<L>) -> Self {
        Self {
            identity_backend,
            lsa_backend,
        }
    }

    /// Full resolution — the single public entry point.
    pub async fn resolve(&self, input: PrincipalInput) -> Result<PrincipalResolution, CoreError> {
        let classified = input.classify()?;
        match classified {
            PrincipalInput::Auto(_) => unreachable!("classify() removes Auto"),
            PrincipalInput::DomainQualified(name) => self.resolve_by_lsa_name(&name).await,
            PrincipalInput::DisplayName(name) => self.resolve_by_lsa_name(&name).await,
            PrincipalInput::Upn(upn) => self.resolve_by_upn(&upn).await,
            PrincipalInput::SamAccount(sam) => self.resolve_by_sam(&sam).await,
            PrincipalInput::Sid(sid) => self.resolve_by_sid(sid).await,
        }
    }

    /// `DOMAIN\user` / GUI display name → LSA-first.
    async fn resolve_by_lsa_name(&self, name: &str) -> Result<PrincipalResolution, CoreError> {
        let lsa = self.lsa_backend.as_ref().ok_or_else(|| {
            CoreError::Validation(
                "Name-based identity input requires Windows LSA — not available on this platform"
                    .to_owned(),
            )
        })?;
        let sid = lsa.lookup_sid_for_name(name)?;
        // bitgenau identisch.
        // Then we run the same path as for direct SIDs — that contains
        // the LDAP / LSA cross-check. Behavior between
        // "DOMAIN\user given" and "name → LSA-SID → analysis" stays
        // bit-identical.
        self.resolve_by_sid(sid).await
    }

    /// [`IdentityScopeStatus::LookupFailed`] marker with a clear reason.
    /// UPN path. No LSA cross-check possible — miss → `LookupFailed`.
    async fn resolve_by_upn(&self, upn: &str) -> Result<PrincipalResolution, CoreError> {
        match self.identity_backend.lookup_identity_by_upn(upn).await? {
            Some((sid, identity)) => {
                let (memberships, group_status) = self.resolve_groups(&sid).await;
                let disabled_status = disabled_from_ldap(&identity);
                let mut diagnostics = Vec::with_capacity(2);
                push_diagnostics(
                    &mut diagnostics,
                    &IdentityScopeStatus::InsideConfiguredLdapBase,
                    disabled_status,
                    identity.disabled,
                );
                Ok(PrincipalResolution {
                    sid,
                    identity,
                    memberships,
                    scope_status: IdentityScopeStatus::InsideConfiguredLdapBase,
                    group_resolution_status: group_status,
                    disabled_status,
                    diagnostics,
                    resolved_via_fsp: false,
                    resolved_via_global_catalog: self.identity_backend.is_forest_wide(),
                })
            }
            None => {
                // UPN missing — return a clean error rather than
                // fabricating a fallback identity. The hint depends on
                // the bind scope: against a Global Catalog the search
                // was already forest-wide (known-limitations L2).
                if self.identity_backend.is_forest_wide() {
                    Err(CoreError::Validation(format!(
                        "UPN '{upn}' not found in the Global Catalog — the \
                         search was forest-wide. Check the spelling or use \
                         DOMAIN\\user / direct SID."
                    )))
                } else {
                    Err(CoreError::Validation(format!(
                        "UPN '{upn}' not found under the configured LDAP base. \
                         For forest-wide UPN resolution bind against a Global \
                         Catalog (--global-catalog, port 3269/3268) or use \
                         DOMAIN\\user / direct SID."
                    )))
                }
            }
        }
    }

    /// Plain `sAMAccountName` → LDAP-Eindeutigkeitssuche.
    /// Plain `sAMAccountName` path.
    async fn resolve_by_sam(&self, sam: &str) -> Result<PrincipalResolution, CoreError> {
        let entries = self.identity_backend.lookup_identities_by_sam(sam).await?;
        if entries.len() > 1 {
            return Err(CoreError::Validation(format!(
                "Ambiguous sAMAccountName '{sam}' — {} matches found. \
                 Use 'DOMAIN\\user' or 'user@domain.tld' to disambiguate.",
                entries.len()
            )));
        }
        match entries.into_iter().next() {
            Some((sid, identity)) => {
                let (memberships, group_status) = self.resolve_groups(&sid).await;
                let disabled_status = disabled_from_ldap(&identity);
                let mut diagnostics = Vec::with_capacity(2);
                push_diagnostics(
                    &mut diagnostics,
                    &IdentityScopeStatus::InsideConfiguredLdapBase,
                    disabled_status,
                    identity.disabled,
                );
                Ok(PrincipalResolution {
                    sid,
                    identity,
                    memberships,
                    scope_status: IdentityScopeStatus::InsideConfiguredLdapBase,
                    group_resolution_status: group_status,
                    disabled_status,
                    diagnostics,
                    resolved_via_fsp: false,
                    resolved_via_global_catalog: self.identity_backend.is_forest_wide(),
                })
            }
            None => Err(CoreError::Validation(format!(
                "sAMAccountName '{sam}' not found under the configured LDAP base."
            ))),
        }
    }

    /// Direct SID path → LDAP, on miss LSA reverse cross-check.
    async fn resolve_by_sid(&self, sid: Sid) -> Result<PrincipalResolution, CoreError> {
        let ldap_result = self.identity_backend.lookup_identity_by_sid(&sid).await;

        match ldap_result {
            Ok(Some(identity)) => {
                // Known-limitations L1: a hit can be the Foreign Security
                // Principal object standing in for a cross-forest trust
                // principal — handled by a dedicated path that enriches
                // the identity via LSA and flags the trust-side gap.
                if identity.kind == IdentityKind::ForeignSecurityPrincipal {
                    return self.resolve_fsp_hit(sid, identity).await;
                }
                let (memberships, group_status) = self.resolve_groups(&sid).await;
                let disabled_status = disabled_from_ldap(&identity);
                let mut diagnostics = Vec::with_capacity(2);
                push_diagnostics(
                    &mut diagnostics,
                    &IdentityScopeStatus::InsideConfiguredLdapBase,
                    disabled_status,
                    identity.disabled,
                );
                Ok(PrincipalResolution {
                    sid,
                    identity,
                    memberships,
                    scope_status: IdentityScopeStatus::InsideConfiguredLdapBase,
                    group_resolution_status: group_status,
                    disabled_status,
                    diagnostics,
                    resolved_via_fsp: false,
                    resolved_via_global_catalog: self.identity_backend.is_forest_wide(),
                })
            }
            Ok(None) => self.fall_back_to_lsa(&sid).await,
            Err(e) => {
                // `Orphaned` verwandeln. ScopeStatus =
                warn!(
                    sid = %sid.0,
                    error = %e,
                    "PrincipalResolver: LDAP lookup failed — emitting LookupFailed scope status"
                );
                Ok(self.failed_lookup_resolution(sid, e.to_string()))
            }
        }
    }

    /// LDAP miss + LSA cross-check.
    async fn fall_back_to_lsa(&self, sid: &Sid) -> Result<PrincipalResolution, CoreError> {
        let lsa = match self.lsa_backend.as_ref() {
            Some(b) => b,
            None => {
                debug!(
                    sid = %sid.0,
                    "LDAP miss and no LSA backend — emitting OrphanedSid"
                );
                return Ok(self.orphaned_resolution(sid.clone()));
            }
        };

        match lsa.lookup_account_for_sid(sid) {
            Ok(account) => {
                let identity = Identity {
                    sid: sid.clone(),
                    name: if account.name.is_empty() {
                        None
                    } else {
                        Some(account.name)
                    },
                    domain: if account.domain.is_empty() {
                        None
                    } else {
                        Some(account.domain)
                    },
                    kind: account.kind,
                    disabled: false,
                    user_principal_name: None,
                };
                let scope = IdentityScopeStatus::OutsideConfiguredLdapBase;
                // Memberships unknown from LDAP; flagged NotAttempted.
                let mut diagnostics = Vec::with_capacity(2);
                let disabled_status = DisabledStatus::Unknown;
                push_diagnostics(&mut diagnostics, &scope, disabled_status, false);
                Ok(PrincipalResolution {
                    sid: sid.clone(),
                    identity,
                    memberships: Vec::new(),
                    scope_status: scope,
                    group_resolution_status: GroupResolutionStatus::NotAttempted,
                    disabled_status,
                    diagnostics,
                    resolved_via_fsp: false,
                    resolved_via_global_catalog: false,
                })
            }
            Err(_) => {
                debug!(sid = %sid.0, "LDAP miss and LSA miss — OrphanedSid");
                Ok(self.orphaned_resolution(sid.clone()))
            }
        }
    }

    /// LDAP hit on a Foreign Security Principal object
    /// (known-limitations L1).
    ///
    /// The FSP stands in for a cross-forest trust principal: its
    /// `objectSid` is the trust SID, and home-domain group memberships
    /// run through the FSP's DN. Three things differ from a normal hit:
    ///
    /// 1. The FSP carries no usable display data (its CN is the raw SID
    ///    string, kind would be `ForeignSecurityPrincipal`) — enrich the
    ///    identity via LSA reverse lookup when a backend is available so
    ///    the auditor sees `TRUSTDOM\user` and the real principal type.
    /// 2. The FSP has no `userAccountControl` — the disabled state of
    ///    the real principal lives in the trust forest. Report
    ///    `DisabledStatus::Unknown` instead of silently claiming
    ///    "active".
    /// 3. Home-domain groups resolve through the FSP DN (the regular
    ///    transitive chain search works), but the principal's
    ///    memberships **in its own forest** are unknown — flagged via
    ///    `resolved_via_fsp` so the engine pushes the structured marker
    ///    and risk findings are treated as incomplete.
    async fn resolve_fsp_hit(
        &self,
        sid: Sid,
        fsp_identity: Identity,
    ) -> Result<PrincipalResolution, CoreError> {
        // Home-domain memberships via the FSP object's DN.
        let (memberships, group_status) = self.resolve_groups(&sid).await;

        // LSA enrichment: real name / domain / kind from the trust.
        let identity = match self.lsa_backend.as_ref() {
            Some(lsa) => match lsa.lookup_account_for_sid(&sid) {
                Ok(account) => Identity {
                    sid: sid.clone(),
                    name: if account.name.is_empty() {
                        fsp_identity.name.clone()
                    } else {
                        Some(account.name)
                    },
                    domain: if account.domain.is_empty() {
                        fsp_identity.domain.clone()
                    } else {
                        Some(account.domain)
                    },
                    kind: account.kind,
                    disabled: false,
                    user_principal_name: None,
                },
                Err(e) => {
                    debug!(sid = %sid.0, error = %e, "FSP hit: LSA enrichment failed — keeping FSP identity");
                    fsp_identity
                }
            },
            None => fsp_identity,
        };

        // The FSP carries no userAccountControl — disabled state unknown.
        let disabled_status = DisabledStatus::Unknown;
        let scope = IdentityScopeStatus::InsideConfiguredLdapBase;
        let mut diagnostics = Vec::with_capacity(3);
        push_diagnostics(&mut diagnostics, &scope, disabled_status, false);
        diagnostics.push(PermissionDiagnostic::IdentityResolvedViaForeignSecurityPrincipal);

        debug!(
            sid = %sid.0,
            home_groups = memberships.len(),
            "Resolved cross-forest principal via FSP object"
        );

        Ok(PrincipalResolution {
            sid,
            identity,
            memberships,
            scope_status: scope,
            group_resolution_status: group_status,
            disabled_status,
            diagnostics,
            resolved_via_fsp: true,
            resolved_via_global_catalog: self.identity_backend.is_forest_wide(),
        })
    }

    /// Helper: recursive groups via the LDAP backend.
    async fn resolve_groups(&self, sid: &Sid) -> (Vec<GroupMembership>, GroupResolutionStatus) {
        match self.identity_backend.resolve_memberships(sid).await {
            Ok(m) => (m, GroupResolutionStatus::LdapRecursive),
            Err(e) => {
                warn!(sid = %sid.0, error = %e, "Group resolution failed");
                (
                    Vec::new(),
                    GroupResolutionStatus::Failed {
                        reason: e.to_string(),
                    },
                )
            }
        }
    }

    fn orphaned_resolution(&self, sid: Sid) -> PrincipalResolution {
        let identity = Identity {
            sid: sid.clone(),
            name: None,
            domain: None,
            kind: IdentityKind::Orphaned,
            disabled: false,
            user_principal_name: None,
        };
        PrincipalResolution {
            sid,
            identity,
            memberships: Vec::new(),
            scope_status: IdentityScopeStatus::OrphanedSid,
            group_resolution_status: GroupResolutionStatus::NotAttempted,
            disabled_status: DisabledStatus::Unknown,
            diagnostics: Vec::new(),
            resolved_via_fsp: false,
            resolved_via_global_catalog: false,
        }
    }

    fn failed_lookup_resolution(&self, sid: Sid, reason: String) -> PrincipalResolution {
        let identity = Identity {
            sid: sid.clone(),
            name: None,
            domain: None,
            kind: IdentityKind::Unknown,
            disabled: false,
            user_principal_name: None,
        };
        PrincipalResolution {
            sid,
            identity,
            memberships: Vec::new(),
            scope_status: IdentityScopeStatus::LookupFailed { reason },
            group_resolution_status: GroupResolutionStatus::NotAttempted,
            disabled_status: DisabledStatus::Unknown,
            diagnostics: Vec::new(),
            resolved_via_fsp: false,
            resolved_via_global_catalog: false,
        }
    }
}

/// Reads `disabled` from an LDAP-sourced identity.
fn disabled_from_ldap(identity: &Identity) -> DisabledStatus {
    DisabledStatus::Known(identity.disabled)
}

/// Pushes the two structured markers matching the scope status.
fn push_diagnostics(
    diagnostics: &mut Vec<PermissionDiagnostic>,
    scope: &IdentityScopeStatus,
    disabled_status: DisabledStatus,
    identity_disabled: bool,
) {
    if matches!(scope, IdentityScopeStatus::OutsideConfiguredLdapBase) {
        diagnostics.push(PermissionDiagnostic::IdentityNotInConfiguredLdapBase);
    }
    if matches!(disabled_status, DisabledStatus::Unknown) {
        diagnostics.push(PermissionDiagnostic::IdentityDisabledStatusUnknown);
    } else if identity_disabled {
        diagnostics.push(PermissionDiagnostic::IdentityDisabled);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory LDAP fake.
    struct FakeLdapBackend {
        by_sid: HashMap<String, Identity>,
        by_upn: HashMap<String, (Sid, Identity)>,
        by_sam: HashMap<String, Vec<(Sid, Identity)>>,
        memberships: HashMap<String, Vec<GroupMembership>>,
        force_error: Mutex<Option<CoreError>>,
    }

    impl FakeLdapBackend {
        fn new() -> Self {
            Self {
                by_sid: HashMap::new(),
                by_upn: HashMap::new(),
                by_sam: HashMap::new(),
                memberships: HashMap::new(),
                force_error: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl IdentityBackend for FakeLdapBackend {
        async fn lookup_identity_by_sid(&self, sid: &Sid) -> Result<Option<Identity>, CoreError> {
            if let Some(e) = self.force_error.lock().unwrap().take() {
                return Err(e);
            }
            Ok(self.by_sid.get(&sid.0).cloned())
        }

        async fn lookup_identity_by_upn(
            &self,
            upn: &str,
        ) -> Result<Option<(Sid, Identity)>, CoreError> {
            Ok(self.by_upn.get(upn).cloned())
        }

        async fn lookup_identities_by_sam(
            &self,
            sam: &str,
        ) -> Result<Vec<(Sid, Identity)>, CoreError> {
            Ok(self.by_sam.get(sam).cloned().unwrap_or_default())
        }

        async fn resolve_memberships(&self, sid: &Sid) -> Result<Vec<GroupMembership>, CoreError> {
            Ok(self.memberships.get(&sid.0).cloned().unwrap_or_default())
        }
    }

    /// In-Memory-LSA-Fake.
    /// In-memory LSA fake.
    struct FakeLsaBackend {
        name_to_sid: HashMap<String, Sid>,
        sid_to_account: HashMap<String, LsaAccountInfo>,
    }

    impl FakeLsaBackend {
        fn new() -> Self {
            Self {
                name_to_sid: HashMap::new(),
                sid_to_account: HashMap::new(),
            }
        }
    }

    impl LsaBackend for FakeLsaBackend {
        fn lookup_sid_for_name(&self, name: &str) -> Result<Sid, CoreError> {
            self.name_to_sid
                .get(name)
                .cloned()
                .ok_or_else(|| CoreError::SidResolution(format!("fake LSA: unknown name '{name}'")))
        }

        fn lookup_account_for_sid(&self, sid: &Sid) -> Result<LsaAccountInfo, CoreError> {
            self.sid_to_account.get(&sid.0).cloned().ok_or_else(|| {
                CoreError::SidResolution(format!("fake LSA: unknown SID '{}'", sid.0))
            })
        }
    }

    fn mk_identity(sid: &str, name: &str, domain: &str, kind: IdentityKind) -> Identity {
        Identity {
            sid: Sid(sid.to_owned()),
            name: Some(name.to_owned()),
            domain: Some(domain.to_owned()),
            kind,
            disabled: false,
            user_principal_name: None,
        }
    }

    fn mk_lsa(name: &str, domain: &str, kind: IdentityKind) -> LsaAccountInfo {
        LsaAccountInfo {
            name: name.to_owned(),
            domain: domain.to_owned(),
            kind,
        }
    }

    // -----------------------------------------------------------------
    // Test matrix from review 2026-06-04 round 3 — six cases.
    // -----------------------------------------------------------------

    /// 1) `DOMAIN\user` LDAP hit: Inside, no markers, Known.
    #[tokio::test]
    async fn domain_user_ldap_hit_is_inside_base() {
        let sid = Sid("S-1-5-21-1-1-1-1001".to_owned());
        let mut ldap = FakeLdapBackend::new();
        ldap.by_sid.insert(
            sid.0.clone(),
            mk_identity(&sid.0, "alice", "EXAMPLE", IdentityKind::User),
        );
        let mut lsa = FakeLsaBackend::new();
        lsa.name_to_sid
            .insert("EXAMPLE\\alice".to_owned(), sid.clone());

        let resolver = PrincipalResolver::new(ldap, Some(lsa));
        let res = resolver
            .resolve(PrincipalInput::DomainQualified("EXAMPLE\\alice".to_owned()))
            .await
            .expect("resolution must succeed");
        assert_eq!(
            res.scope_status,
            IdentityScopeStatus::InsideConfiguredLdapBase
        );
        assert_eq!(res.disabled_status, DisabledStatus::Known(false));
        assert!(
            res.diagnostics.is_empty(),
            "no diagnostics expected, got {:?}",
            res.diagnostics
        );
        let flags = res.engine_flags();
        assert!(!flags.identity_not_in_configured_ldap_base);
        assert!(!flags.identity_disabled_status_unknown);
    }

    /// 2) `DOMAIN\user` with LDAP miss + LSA hit (multi-domain forest):
    ///    ScopeStatus = OutsideConfiguredLdapBase, beide Marker gesetzt.
    /// 2) `DOMAIN\user` LDAP miss + LSA hit: Outside, markers set.
    #[tokio::test]
    async fn domain_user_ldap_miss_with_lsa_hit_is_outside_base() {
        let sid = Sid("S-1-5-21-9-9-9-1001".to_owned());
        let ldap = FakeLdapBackend::new(); // bewusst leer
        let mut lsa = FakeLsaBackend::new();
        lsa.name_to_sid
            .insert("TRUSTED\\alice".to_owned(), sid.clone());
        lsa.sid_to_account.insert(
            sid.0.clone(),
            mk_lsa("alice", "TRUSTED", IdentityKind::User),
        );

        let resolver = PrincipalResolver::new(ldap, Some(lsa));
        let res = resolver
            .resolve(PrincipalInput::DomainQualified("TRUSTED\\alice".to_owned()))
            .await
            .expect("resolution must succeed");
        assert_eq!(
            res.scope_status,
            IdentityScopeStatus::OutsideConfiguredLdapBase
        );
        assert_eq!(res.identity.name.as_deref(), Some("alice"));
        assert_eq!(res.identity.domain.as_deref(), Some("TRUSTED"));
        assert_eq!(res.disabled_status, DisabledStatus::Unknown);
        assert!(
            res.diagnostics
                .contains(&PermissionDiagnostic::IdentityNotInConfiguredLdapBase),
            "Outside scope must push IdentityNotInConfiguredLdapBase"
        );
        let flags = res.engine_flags();
        assert!(flags.identity_not_in_configured_ldap_base);
        assert!(flags.identity_disabled_status_unknown);
    }

    /// 3) Direct SID + LDAP miss + LSA hit: Outside.
    #[tokio::test]
    async fn direct_sid_ldap_miss_with_lsa_hit_is_outside_base() {
        let sid = Sid("S-1-5-21-9-9-9-1002".to_owned());
        let ldap = FakeLdapBackend::new();
        let mut lsa = FakeLsaBackend::new();
        lsa.sid_to_account
            .insert(sid.0.clone(), mk_lsa("bob", "TRUSTED", IdentityKind::User));

        let resolver = PrincipalResolver::new(ldap, Some(lsa));
        let res = resolver
            .resolve(PrincipalInput::Sid(sid.clone()))
            .await
            .expect("resolution must succeed");
        assert_eq!(
            res.scope_status,
            IdentityScopeStatus::OutsideConfiguredLdapBase,
            "direct SID with LDAP miss + LSA hit must be Outside, not Orphaned — this is the core fix from review 2026-06-04 round 3 finding 1"
        );
        assert!(res
            .diagnostics
            .contains(&PermissionDiagnostic::IdentityNotInConfiguredLdapBase));
    }

    /// 4) GUI Name → SID-Workflow (PrincipalInput::DisplayName):
    ///    selbe Semantik wie `DomainQualified`.
    /// 4) GUI display name → SID workflow: same semantics.
    #[tokio::test]
    async fn display_name_workflow_uses_lsa_then_cross_checks() {
        let sid = Sid("S-1-5-21-9-9-9-1003".to_owned());
        let ldap = FakeLdapBackend::new();
        let mut lsa = FakeLsaBackend::new();
        lsa.name_to_sid.insert("charlie".to_owned(), sid.clone());
        lsa.sid_to_account.insert(
            sid.0.clone(),
            mk_lsa("charlie", "TRUSTED", IdentityKind::User),
        );

        let resolver = PrincipalResolver::new(ldap, Some(lsa));
        let res = resolver
            .resolve(PrincipalInput::DisplayName("charlie".to_owned()))
            .await
            .expect("resolution must succeed");
        assert_eq!(
            res.scope_status,
            IdentityScopeStatus::OutsideConfiguredLdapBase
        );
        assert_eq!(res.identity.name.as_deref(), Some("charlie"));
    }

    /// 5) UPN outside configured base: explicit error pointing at GC.
    #[tokio::test]
    async fn upn_outside_configured_base_returns_explicit_error() {
        let ldap = FakeLdapBackend::new();
        let lsa = FakeLsaBackend::new();

        let resolver = PrincipalResolver::new(ldap, Some(lsa));
        let err = resolver
            .resolve(PrincipalInput::Upn("alice@trusted.example".to_owned()))
            .await
            .expect_err("UPN miss must return Validation error, not Orphaned fallback");
        let msg = err.to_string();
        assert!(
            msg.contains("Global Catalog") || msg.contains("port 3268"),
            "UPN miss error message must point at the GC workaround, got: {msg}"
        );
    }

    /// 6) Unknown SID — both miss: real Orphaned.
    #[tokio::test]
    async fn unknown_sid_with_no_lsa_match_is_orphaned() {
        let sid = Sid("S-1-5-21-1-1-1-99999".to_owned());
        let ldap = FakeLdapBackend::new();
        let lsa = FakeLsaBackend::new(); // does not know the SID

        let resolver = PrincipalResolver::new(ldap, Some(lsa));
        let res = resolver
            .resolve(PrincipalInput::Sid(sid.clone()))
            .await
            .expect("resolution must succeed");
        assert_eq!(res.scope_status, IdentityScopeStatus::OrphanedSid);
        assert_eq!(res.identity.kind, IdentityKind::Orphaned);
        assert!(
            res.diagnostics.is_empty(),
            "Orphaned must NOT emit Outside marker"
        );
        let flags = res.engine_flags();
        assert!(!flags.identity_not_in_configured_ldap_base);
        assert!(flags.identity_disabled_status_unknown);
    }

    /// `disabled_status_unknown` bleibt false.
    /// LDAP-disabled account: `IdentityDisabled` marker, no Unknown.
    #[tokio::test]
    async fn ldap_disabled_account_pushes_identity_disabled_marker() {
        let sid = Sid("S-1-5-21-1-1-1-1005".to_owned());
        let mut ldap = FakeLdapBackend::new();
        let mut id = mk_identity(&sid.0, "stale", "EXAMPLE", IdentityKind::User);
        id.disabled = true;
        ldap.by_sid.insert(sid.0.clone(), id);

        let resolver = PrincipalResolver::new(ldap, Some(FakeLsaBackend::new()));
        let res = resolver
            .resolve(PrincipalInput::Sid(sid))
            .await
            .expect("resolution must succeed");
        assert!(res
            .diagnostics
            .contains(&PermissionDiagnostic::IdentityDisabled));
        assert_eq!(res.disabled_status, DisabledStatus::Known(true));
        let flags = res.engine_flags();
        assert!(!flags.identity_disabled_status_unknown);
    }

    /// Ohne LSA-Backend (Non-Windows): LDAP-Miss → echte Orphan.
    /// No LSA backend: LDAP miss → real Orphaned.
    #[tokio::test]
    async fn ldap_miss_without_lsa_backend_is_orphaned() {
        let sid = Sid("S-1-5-21-1-1-1-1006".to_owned());
        let ldap = FakeLdapBackend::new();
        let resolver: PrincipalResolver<_, FakeLsaBackend> = PrincipalResolver::new(ldap, None);
        let res = resolver
            .resolve(PrincipalInput::Sid(sid))
            .await
            .expect("resolution must succeed");
        assert_eq!(res.scope_status, IdentityScopeStatus::OrphanedSid);
    }

    /// LDAP-Bind-/Verbindungsfehler: ScopeStatus = LookupFailed,
    /// LDAP error: LookupFailed, no LSA reclassification. Plus
    /// LDAP error → LookupFailed + engine_flags carry the reason.
    #[tokio::test]
    async fn ldap_error_yields_lookup_failed_not_orphaned() {
        let sid = Sid("S-1-5-21-1-1-1-1007".to_owned());
        let ldap = FakeLdapBackend::new();
        *ldap.force_error.lock().unwrap() =
            Some(CoreError::LdapQuery("simulated bind failure".to_owned()));
        let resolver = PrincipalResolver::new(ldap, Some(FakeLsaBackend::new()));
        let res = resolver
            .resolve(PrincipalInput::Sid(sid))
            .await
            .expect("resolution must succeed (error becomes LookupFailed scope)");
        match &res.scope_status {
            IdentityScopeStatus::LookupFailed { reason } => {
                assert!(
                    reason.contains("simulated bind failure"),
                    "reason must carry the underlying error, got: {reason}"
                );
            }
            other => panic!("expected LookupFailed, got: {other:?}"),
        }
        let flags = res.engine_flags();
        assert!(
            flags
                .identity_lookup_failure_reason
                .as_deref()
                .map(|s| s.contains("simulated bind failure"))
                .unwrap_or(false),
            "engine_flags() must carry the LDAP lookup failure reason — closing review round 4 finding 1"
        );
    }

    /// rauskommen.
    /// Identity hit + group resolution error → engine_flags carries the
    /// group resolution failure reason.
    #[tokio::test]
    async fn group_resolution_error_after_identity_hit_carries_reason() {
        let sid = Sid("S-1-5-21-1-1-1-1008".to_owned());
        struct GroupFailingBackend {
            sid: Sid,
            identity: Identity,
        }
        #[async_trait]
        impl IdentityBackend for GroupFailingBackend {
            async fn lookup_identity_by_sid(
                &self,
                sid: &Sid,
            ) -> Result<Option<Identity>, CoreError> {
                if sid.0 == self.sid.0 {
                    Ok(Some(self.identity.clone()))
                } else {
                    Ok(None)
                }
            }
            async fn lookup_identity_by_upn(
                &self,
                _upn: &str,
            ) -> Result<Option<(Sid, Identity)>, CoreError> {
                Ok(None)
            }
            async fn lookup_identities_by_sam(
                &self,
                _sam: &str,
            ) -> Result<Vec<(Sid, Identity)>, CoreError> {
                Ok(Vec::new())
            }
            async fn resolve_memberships(
                &self,
                _sid: &Sid,
            ) -> Result<Vec<GroupMembership>, CoreError> {
                Err(CoreError::LdapQuery(
                    "simulated group resolution timeout".to_owned(),
                ))
            }
        }
        let backend = GroupFailingBackend {
            sid: sid.clone(),
            identity: mk_identity(&sid.0, "alice", "EXAMPLE", IdentityKind::User),
        };
        let resolver = PrincipalResolver::new(backend, Some(FakeLsaBackend::new()));
        let res = resolver
            .resolve(PrincipalInput::Sid(sid))
            .await
            .expect("resolution must succeed");
        assert_eq!(
            res.scope_status,
            IdentityScopeStatus::InsideConfiguredLdapBase
        );
        match &res.group_resolution_status {
            GroupResolutionStatus::Failed { reason } => {
                assert!(
                    reason.contains("simulated group resolution timeout"),
                    "reason must carry the underlying error, got: {reason}"
                );
            }
            other => panic!("expected Failed, got: {other:?}"),
        }
        let flags = res.engine_flags();
        assert!(
            flags.group_resolution_failure_reason.is_some(),
            "engine_flags() must carry the group resolution failure reason"
        );
        assert!(
            flags.identity_lookup_failure_reason.is_none(),
            "identity lookup did not fail — flag must remain None"
        );
    }

    /// `IdentityScopeStatus::OutsideConfiguredLdapBase` with
    /// otherwise).
    #[tokio::test]
    async fn outside_base_with_skipped_groups_yields_group_failure_reason() {
        let sid = Sid("S-1-5-21-9-9-9-1009".to_owned());
        let ldap = FakeLdapBackend::new(); // leer
        let mut lsa = FakeLsaBackend::new();
        lsa.sid_to_account
            .insert(sid.0.clone(), mk_lsa("bob", "TRUSTED", IdentityKind::User));
        let resolver = PrincipalResolver::new(ldap, Some(lsa));
        let res = resolver
            .resolve(PrincipalInput::Sid(sid))
            .await
            .expect("resolution must succeed");
        assert_eq!(
            res.scope_status,
            IdentityScopeStatus::OutsideConfiguredLdapBase
        );
        let flags = res.engine_flags();
        assert!(
            flags.group_resolution_failure_reason.is_some(),
            "Outside-base + NotAttempted must produce a group resolution failure reason"
        );
    }

    /// Ambiguous SAM → uniqueness error.
    #[tokio::test]
    async fn ambiguous_sam_returns_uniqueness_error() {
        let mut ldap = FakeLdapBackend::new();
        let id_a = mk_identity("S-1-5-21-1-1-1-A", "alice", "DOMA", IdentityKind::User);
        let id_b = mk_identity("S-1-5-21-1-1-1-B", "alice", "DOMB", IdentityKind::User);
        ldap.by_sam.insert(
            "alice".to_owned(),
            vec![
                (Sid("S-1-5-21-1-1-1-A".to_owned()), id_a),
                (Sid("S-1-5-21-1-1-1-B".to_owned()), id_b),
            ],
        );
        let resolver = PrincipalResolver::new(ldap, Some(FakeLsaBackend::new()));
        let err = resolver
            .resolve(PrincipalInput::Auto("alice".to_owned()))
            .await
            .expect_err("ambiguous SAM must error");
        assert!(err.to_string().contains("Ambiguous"));
    }

    /// `Auto` classification + trim.
    #[test]
    fn auto_dispatcher_classifies_by_syntax_and_trims() {
        match PrincipalInput::Auto("  S-1-5-18  ".to_owned())
            .classify()
            .unwrap()
        {
            PrincipalInput::Sid(s) => assert_eq!(s.0, "S-1-5-18"),
            other => panic!("expected Sid, got {other:?}"),
        }
        match PrincipalInput::Auto("  EXAMPLE\\alice  ".to_owned())
            .classify()
            .unwrap()
        {
            PrincipalInput::DomainQualified(s) => assert_eq!(s, "EXAMPLE\\alice"),
            other => panic!("expected DomainQualified, got {other:?}"),
        }
        match PrincipalInput::Auto("  alice@example.com  ".to_owned())
            .classify()
            .unwrap()
        {
            PrincipalInput::Upn(s) => assert_eq!(s, "alice@example.com"),
            other => panic!("expected Upn, got {other:?}"),
        }
        match PrincipalInput::Auto("  alice  ".to_owned())
            .classify()
            .unwrap()
        {
            PrincipalInput::SamAccount(s) => assert_eq!(s, "alice"),
            other => panic!("expected SamAccount, got {other:?}"),
        }
        assert!(PrincipalInput::Auto("   ".to_owned()).classify().is_err());
    }

    // -----------------------------------------------------------------
    // Known-limitations L1: Foreign Security Principal resolution.
    // -----------------------------------------------------------------

    /// FSP hit with LSA enrichment: the LDAP hit is the FSP object
    /// (kind = ForeignSecurityPrincipal, CN = raw SID string), the LSA
    /// supplies the real trust-principal data, and the home-domain
    /// group resolved through the FSP DN lands in the memberships.
    #[tokio::test]
    async fn fsp_hit_resolves_home_domain_groups_with_lsa_enrichment() {
        let sid = Sid("S-1-5-21-7-7-7-1501".to_owned());
        let home_group = Sid("S-1-5-21-1-1-1-2000".to_owned());
        let mut ldap = FakeLdapBackend::new();
        // The FSP object as the LDAP SID search returns it: CN is the
        // raw SID string, objectClass foreignSecurityPrincipal.
        ldap.by_sid.insert(
            sid.0.clone(),
            mk_identity(
                &sid.0,
                &sid.0,
                "home.example",
                IdentityKind::ForeignSecurityPrincipal,
            ),
        );
        // Home-domain group membership resolved through the FSP DN.
        ldap.memberships.insert(
            sid.0.clone(),
            vec![GroupMembership {
                member_sid: sid.clone(),
                group_sid: home_group.clone(),
                direct: true,
                group_name: Some("HomeDomain-FileAdmins".to_owned()),
                path: None,
            }],
        );
        let mut lsa = FakeLsaBackend::new();
        lsa.sid_to_account
            .insert(sid.0.clone(), mk_lsa("mm0501", "T1LAB", IdentityKind::User));

        let resolver = PrincipalResolver::new(ldap, Some(lsa));
        let res = resolver
            .resolve(PrincipalInput::Sid(sid.clone()))
            .await
            .expect("resolution must succeed");

        // LSA enrichment: real principal data instead of the FSP shell.
        assert_eq!(res.identity.name.as_deref(), Some("mm0501"));
        assert_eq!(res.identity.domain.as_deref(), Some("T1LAB"));
        assert_eq!(res.identity.kind, IdentityKind::User);
        // Home-domain groups are in the token.
        assert_eq!(res.memberships.len(), 1);
        assert_eq!(res.memberships[0].group_sid, home_group);
        // The trust-side gap is flagged.
        assert!(res.resolved_via_fsp);
        assert!(res.diagnostics.iter().any(|d| matches!(
            d,
            PermissionDiagnostic::IdentityResolvedViaForeignSecurityPrincipal
        )));
        // FSP carries no userAccountControl — disabled state unknown.
        assert_eq!(res.disabled_status, DisabledStatus::Unknown);
        let flags = res.engine_flags();
        assert!(flags.identity_resolved_via_fsp);
        assert!(flags.identity_disabled_status_unknown);
    }

    /// FSP hit without an LSA backend: the FSP identity is kept as the
    /// honest fallback (kind ForeignSecurityPrincipal, SID-string name)
    /// and the marker still fires.
    #[tokio::test]
    async fn fsp_hit_without_lsa_keeps_fsp_identity_and_marker() {
        let sid = Sid("S-1-5-21-7-7-7-1502".to_owned());
        let mut ldap = FakeLdapBackend::new();
        ldap.by_sid.insert(
            sid.0.clone(),
            mk_identity(
                &sid.0,
                &sid.0,
                "home.example",
                IdentityKind::ForeignSecurityPrincipal,
            ),
        );
        let resolver = PrincipalResolver::new(ldap, None::<FakeLsaBackend>);
        let res = resolver
            .resolve(PrincipalInput::Sid(sid))
            .await
            .expect("resolution must succeed");
        assert_eq!(res.identity.kind, IdentityKind::ForeignSecurityPrincipal);
        assert!(res.resolved_via_fsp);
        assert!(res.diagnostics.iter().any(|d| matches!(
            d,
            PermissionDiagnostic::IdentityResolvedViaForeignSecurityPrincipal
        )));
    }

    // -----------------------------------------------------------------
    // Known-limitations L2: Global Catalog bind.
    // -----------------------------------------------------------------

    /// Forest-wide fake backend wrapping the standard fake.
    struct ForestWideFake(FakeLdapBackend);

    #[async_trait]
    impl IdentityBackend for ForestWideFake {
        async fn lookup_identity_by_sid(&self, sid: &Sid) -> Result<Option<Identity>, CoreError> {
            self.0.lookup_identity_by_sid(sid).await
        }
        async fn lookup_identity_by_upn(
            &self,
            upn: &str,
        ) -> Result<Option<(Sid, Identity)>, CoreError> {
            self.0.lookup_identity_by_upn(upn).await
        }
        async fn lookup_identities_by_sam(
            &self,
            sam: &str,
        ) -> Result<Vec<(Sid, Identity)>, CoreError> {
            self.0.lookup_identities_by_sam(sam).await
        }
        async fn resolve_memberships(&self, sid: &Sid) -> Result<Vec<GroupMembership>, CoreError> {
            self.0.resolve_memberships(sid).await
        }
        fn is_forest_wide(&self) -> bool {
            true
        }
    }

    /// GC hit: memberships resolve, the resolution is flagged
    /// resolved_via_global_catalog and the engine flag follows.
    #[tokio::test]
    async fn gc_hit_flags_group_resolution_via_global_catalog() {
        let sid = Sid("S-1-5-21-2-2-2-1001".to_owned());
        let mut ldap = FakeLdapBackend::new();
        ldap.by_sid.insert(
            sid.0.clone(),
            mk_identity(&sid.0, "bob", "CHILD", IdentityKind::User),
        );
        let resolver = PrincipalResolver::new(ForestWideFake(ldap), None::<FakeLsaBackend>);
        let res = resolver
            .resolve(PrincipalInput::Sid(sid))
            .await
            .expect("resolution must succeed");
        assert!(res.resolved_via_global_catalog);
        assert!(res.engine_flags().group_resolution_via_global_catalog);
    }

    /// Non-GC hit: the flag stays off (regression guard).
    #[tokio::test]
    async fn regular_hit_does_not_flag_global_catalog() {
        let sid = Sid("S-1-5-21-2-2-2-1002".to_owned());
        let mut ldap = FakeLdapBackend::new();
        ldap.by_sid.insert(
            sid.0.clone(),
            mk_identity(&sid.0, "carol", "EXAMPLE", IdentityKind::User),
        );
        let resolver = PrincipalResolver::new(ldap, None::<FakeLsaBackend>);
        let res = resolver
            .resolve(PrincipalInput::Sid(sid))
            .await
            .expect("resolution must succeed");
        assert!(!res.resolved_via_global_catalog);
        assert!(!res.engine_flags().group_resolution_via_global_catalog);
    }

    /// UPN miss against the GC names the forest-wide scope instead of
    /// recommending a GC bind the caller is already using.
    #[tokio::test]
    async fn gc_upn_miss_reports_forest_wide_error() {
        let resolver = PrincipalResolver::new(
            ForestWideFake(FakeLdapBackend::new()),
            None::<FakeLsaBackend>,
        );
        let err = resolver
            .resolve(PrincipalInput::Upn("ghost@nowhere.lab".to_owned()))
            .await
            .expect_err("UPN miss must be an error");
        let msg = err.to_string();
        assert!(
            msg.contains("forest-wide"),
            "GC miss must say the search was already forest-wide; got: {msg}"
        );
        assert!(
            !msg.contains("--global-catalog"),
            "GC miss must not recommend the flag that is already active; got: {msg}"
        );
    }
}
