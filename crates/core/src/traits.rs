// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

use std::collections::BTreeMap;

use async_trait::async_trait;

use crate::error::CoreError;
use crate::model::{
    AccessContext, AceOutcome, EffectivePermission, FileSystemObject, GroupMembership, Identity,
    LocalGroupEvalStatus, PathTrustees, RemoteUacFiltering, RiskFinding, ScanError,
    ShareMaskStatus, Sid,
};

pub struct ScanRequest {
    pub target: String,
}

/// Result of a scan: raw file system objects plus errors encountered while reading.
/// Effective permission computation happens afterwards in the evaluator — the
/// scanner only produces the input data.
pub struct ScanResult {
    pub objects: Vec<FileSystemObject>,
    pub errors: Vec<ScanError>,
}

/// Provenance and incompleteness flags produced by identity + group
/// resolution and consumed by the permission engine to decide which
/// incompleteness diagnostics to push.
///
/// Grouped into one bundle (review finding C1) instead of a dozen loose
/// fields on [`PermissionEvaluationInput`]. `ad_resolver::EngineFlags` is a
/// re-export of this type, so the resolver produces exactly what the engine
/// reads — no field-by-field copy. Every field defaults to "complete /
/// known", so a caller that resolved cleanly via LDAP can use
/// `ResolutionProvenance::default()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolutionProvenance {
    /// `true` when group resolution ran through the SAM/LSA fallback
    /// (`NetUserGetGroups`) instead of LDAP. Nested domain groups are then
    /// not recursively resolved and the token SID set may be incomplete;
    /// the engine pushes `DomainGroupRecursionIncomplete`. Closes review
    /// finding 6.
    pub group_resolution_via_sam_fallback: bool,
    /// `true` when the identity was resolved via LSA but the configured LDAP
    /// `base_dn` does not index that SID (typical in multi-domain forests).
    /// The engine pushes `IdentityNotInConfiguredLdapBase`. Closes review
    /// 2026-06-04 round 2 finding 1.
    pub identity_not_in_configured_ldap_base: bool,
    /// `true` when the `disabled` flag on the identity could not be reliably
    /// determined (e.g. SAM path without `NetUserGetInfo`). Closes review
    /// 2026-06-04 round 2 finding 5.
    pub identity_disabled_status_unknown: bool,
    /// `Some(reason)` when the LDAP identity lookup failed with a technical
    /// error. The engine pushes `IdentityLookupFailed`; risk findings are
    /// flagged incomplete.
    pub identity_lookup_failure_reason: Option<String>,
    /// `Some(reason)` when recursive group resolution failed or was
    /// deliberately skipped while groups would have mattered. Marker +
    /// risk-incomplete propagation.
    pub group_resolution_failure_reason: Option<String>,
    /// `true` when the identity was resolved through a Foreign Security
    /// Principal object in the home domain (cross-forest trust user).
    /// Home-domain groups were resolved via the FSP; the principal's
    /// memberships in its own forest are unknown. The engine pushes
    /// `IdentityResolvedViaForeignSecurityPrincipal`. Closes
    /// known-limitations entry L1.
    pub identity_resolved_via_fsp: bool,
    /// `true` when group memberships were resolved through a Global Catalog
    /// bind. Only universal group memberships replicate fully to the GC; the
    /// engine pushes `GroupResolutionViaGlobalCatalog`. Closes
    /// known-limitations entry L2.
    pub group_resolution_via_global_catalog: bool,
    /// `Some(reason)` when the SID could not be resolved and the evidence
    /// does not show that the account no longer exists (trusted or other
    /// domain, partial LDAP base, domain unknown). The engine pushes
    /// `IdentityNotResolvable`; the result is incomplete (ADR 0064, lab
    /// finding AD3-1).
    pub identity_unresolvable_reason: Option<String>,
    /// Reasons why groups may be missing from an otherwise successful group
    /// resolution — a primary group that could not be read, a group without
    /// a readable SID, memberships in groups outside the resolved set, a
    /// local group whose SID could not be looked up (ADR 0066). The engine
    /// pushes one `GroupResolutionIncomplete` per reason.
    pub group_resolution_gaps: Vec<String>,
    /// Groups of the transitive directory result that are **not** in the
    /// token: distribution groups and groups reached only through one
    /// (ADR 0067). The engine pushes `NonSecurityGroupsExcluded` so the
    /// exclusion is visible.
    pub excluded_non_security_groups: Vec<String>,
    /// ADR 0078 (L15): `Some` when the identity is an account of a trusted
    /// domain that was resolved on a domain controller of that domain. The
    /// engine pushes `TrustedDomainAccountResolved` (informational) and —
    /// only when the trust uses Selective Authentication, which Stars does
    /// not model — `TrustBoundaryEffectsNotModeled`. `None` everywhere else,
    /// so no other result changes.
    pub trusted_domain: Option<TrustedDomainProvenance>,
}

/// ADR 0079 (L4): the outcome of the Selective Authentication check for an
/// account of a trusted domain on the target server — "Allowed to
/// authenticate" on the target computer's object, evaluated for the
/// account's token. `None` in the evaluation input when the trust does not
/// use Selective Authentication (or the account is not of a trusted domain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectiveAuthenticationCheck {
    /// The right is granted; `via` is `name (SID)` of the deciding trustee.
    Allowed { server: String, via: String },
    /// No ACE grants it to the token (or a Deny decides): the logon fails.
    Denied { server: String },
    /// Not decidable — the computer object or its permissions could not be
    /// read, or an ACE for a SID whose presence is uncertain decides.
    Unknown { server: String, reason: String },
}

/// How an account of a trusted domain was resolved (ADR 0078).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedDomainProvenance {
    /// DNS name of the trusted domain (`trustPartner`).
    pub domain: String,
    /// Memberships that apply only inside the trusted domain (its builtin
    /// and domain-local groups) — left out of the token, named here.
    pub home_only_groups: Vec<String>,
    /// SIDs the trust's SID filtering (quarantine) removes.
    pub sid_filtered: Vec<String>,
    /// `true` when the trust uses Selective Authentication.
    pub selective_authentication: bool,
}

/// Group memberships of a principal plus every reason the set may be
/// incomplete although the resolution itself succeeded (ADR 0066). A gap is
/// never dropped silently: it becomes a `GroupResolutionIncomplete` marker
/// and makes the result not determinable.
#[derive(Debug, Clone, Default)]
pub struct GroupMembershipResolution {
    pub memberships: Vec<GroupMembership>,
    /// Reader-facing reasons why groups may be missing from `memberships`.
    pub gaps: Vec<String>,
    /// Groups left out because Windows does not put them into the token —
    /// distribution groups and groups reached only through one (ADR 0067).
    pub excluded_groups: Vec<String>,
}

pub struct PermissionEvaluationInput {
    pub identity: Identity,
    pub group_memberships: Vec<GroupMembership>,
    /// The file system object to analyze, including DACL and owner.
    pub file_system_object: FileSystemObject,
    /// Status of the share side (no SMB / applied with mask / read failed).
    /// Replaces the former `Option<AccessMask>` and makes "no context"
    /// unambiguously distinguishable from "read failed".
    pub share_status: ShareMaskStatus,
    /// SIDs of local groups on the target server in which the user is a member
    /// (e.g. `BUILTIN\Administrators`). If this is empty, ACEs that only apply
    /// via local server groups are missed.
    pub local_group_sids: Vec<Sid>,
    /// Status of the local-group resolution — `NotAvailable` marks the result
    /// as incomplete (see [`LocalGroupEvalStatus`]). The caller sets this; the
    /// engine forwards it unchanged.
    pub local_group_status: LocalGroupEvalStatus,
    /// SIDs of local groups the user is in **only** through a logon-dependent
    /// well-known SID (e.g. a group containing `INTERACTIVE` when the access
    /// context is unspecified, ADR 0068). Not in the token as a fact: ACEs
    /// for them are bounded like ACEs for logon-dependent well-known SIDs
    /// (ADR 0065). Empty by default.
    pub logon_dependent_group_sids: Vec<Sid>,
    /// Groups User Account Control may filter out of the token (deny-only):
    /// the UAC-filtered groups of a local account of the target server
    /// (ADR 0070). Deny ACEs for them apply; Allow ACEs bound the result.
    /// Empty by default.
    pub uac_filtered_group_sids: Vec<Sid>,
    /// Remote UAC decided from the target's policies (ADR 0076): `Filtered`
    /// makes `uac_filtered_group_sids` certainly deny-only (their Allow ACEs
    /// do not apply), `Unknown` keeps them bounded. Callers pass
    /// `NotFiltered` with an empty `uac_filtered_group_sids`.
    pub remote_uac: RemoteUacFiltering,
    /// ADR 0072 / L17: `EveryoneIncludesAnonymous` read from the target —
    /// `Some(true)` puts Everyone into an anonymous token, `Some(false)`
    /// leaves it out; `None` (not read) keeps it bounded.
    pub anonymous_everyone: Option<bool>,
    /// ADR 0077: what each share ACE decided (from the share scanner, same
    /// DACL read as the share mask) — merged into the result's trace so NTFS
    /// and share ACEs are linked to the token groups the same way.
    pub share_trace: Vec<AceOutcome>,
    /// ADR 0079 (L4): the Selective Authentication check for an account of a
    /// trusted domain on the target server. `None` — the default — for every
    /// other account and trust, so nothing changes there.
    pub selective_authentication: Option<SelectiveAuthenticationCheck>,
    /// Access context (local interactive / remote SMB / unspecified).
    /// Controls which well-known SIDs are added to the token implicitly
    /// (e.g. `NETWORK` for SMB, `INTERACTIVE` for local). The default
    /// (`Unspecified`) behaves as before — only `Everyone` and
    /// `Authenticated Users` are added.
    pub access_context: AccessContext,
    /// Number of share ACEs the share DACL parser could not interpret
    /// (e.g. object, callback or vendor-specific ACEs). When >0 the
    /// engine pushes a `PermissionDiagnostic::UnsupportedShareAces`
    /// into the result; risk findings derived from this permission are
    /// then flagged `incomplete`. Default 0 (none).
    pub unsupported_share_ace_count: usize,
    /// Optional SID-to-name lookup table for the explanation text. The
    /// key is the canonical SID string (same as `Sid::0`), the value is
    /// the display name (e.g. `Domain Admins` or
    /// `BUILTIN\Administrators`). The engine consults this table for every
    /// SID that appears in `PermissionPath::steps` (user, groups, ACE
    /// trustees); a SID without an entry falls back to showing the raw
    /// SID. Defaulting to empty keeps existing callers compatible.
    pub sid_names: BTreeMap<String, String>,
    /// Provenance / incompleteness flags from identity and group resolution
    /// (review finding C1 — grouped instead of a dozen loose booleans). See
    /// [`ResolutionProvenance`]; `ad_resolver::EngineFlags` is a re-export of
    /// that type, so the resolver's output slots in directly.
    pub resolution: ResolutionProvenance,
}

pub struct RiskContext {
    pub findings: Vec<EffectivePermission>,
}

/// Export call target. Round-8 follow-up finding 1: the `Exporter`
/// trait now carries the overwrite policy itself so direct trait
/// consumers cannot accidentally truncate existing audit reports.
///
/// - `File(path)` is the conservative default: fails if the target
///   file already exists (`OpenOptions::create_new`). This matches the
///   CLI-without-`--force` and the GUI behaviour.
/// - `FileOverwrite(path)` is the explicit opt-in: truncates an
///   existing file. CLI with `--force` deliberately picks this, the
///   GUI never does.
pub enum ExportTarget {
    File(std::path::PathBuf),
    FileOverwrite(std::path::PathBuf),
}

#[derive(Default)]
pub struct AnalysisResult {
    pub permissions: Vec<EffectivePermission>,
    pub risk_findings: Vec<RiskFinding>,
    /// Path-centric trustee listing (ACEs without an identity context).
    /// Used by the exporter to render the second audit question "who has
    /// any access?" per path. Empty when the caller does not need it —
    /// does not break existing constructions.
    pub path_trustees: Vec<PathTrustees>,
}

/// Reads and analyzes file system objects or shares.
pub trait Scanner {
    fn scan(&self, request: ScanRequest) -> Result<ScanResult, CoreError>;
}

/// Resolves SIDs to identities and determines group memberships via LDAP/AD.
///
/// All methods are async because AD queries are I/O-bound.
// `async_trait` desugars each method to return a `#[must_use]`-annotated
// boxed future, then puts its own `#[must_use]` (no message) on the
// generated function — clippy's `double_must_use` (new in Rust 1.99,
// 2026-09-28) flags that redundant, message-less pair. No correctness
// issue: the generated future is still `#[must_use]`.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait IdentityResolver: Send + Sync {
    /// Resolves a SID to a full identity (name, domain, kind, status).
    async fn resolve_identity(&self, sid: &Sid) -> Result<Identity, CoreError>;

    /// Determines all group memberships recursively (direct and transitive),
    /// with every reason the set may be incomplete (ADR 0066).
    async fn resolve_group_memberships(
        &self,
        sid: &Sid,
    ) -> Result<GroupMembershipResolution, CoreError>;
}

/// Calculates effective permissions from identity, groups, and ACL entries.
pub trait PermissionEvaluator {
    fn evaluate(&self, input: PermissionEvaluationInput) -> Result<EffectivePermission, CoreError>;
}

/// Evaluates analysis results against a single risk rule.
pub trait RiskRule {
    fn evaluate(&self, context: &RiskContext) -> Vec<RiskFinding>;
}

/// Exports analysis results to a target format.
pub trait Exporter {
    fn export(&self, result: &AnalysisResult, target: ExportTarget) -> Result<(), CoreError>;
}
