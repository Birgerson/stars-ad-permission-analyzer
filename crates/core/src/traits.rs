// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

use std::collections::BTreeMap;

use async_trait::async_trait;

use crate::error::CoreError;
use crate::model::{
    AccessContext, EffectivePermission, FileSystemObject, GroupMembership, Identity,
    LocalGroupEvalStatus, PathTrustees, RiskFinding, ScanError, ShareMaskStatus, Sid,
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
    /// Access context (local interactive / remote SMB / unspecified).
    /// Controls which well-known SIDs are added to the token implicitly
    /// (e.g. `NETWORK` for SMB, `INTERACTIVE` for local). The default
    /// (`Unspecified`) behaves as before — only `Everyone` and
    /// `Authenticated Users` are added.
    pub access_context: AccessContext,
    /// Engine pusht bei >0 einen `PermissionDiagnostic::UnsupportedShareAces`
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
    /// back to showing the raw SID. Defaulting to empty keeps existing
    /// callers compatible.
    pub sid_names: BTreeMap<String, String>,
    /// compatible. Closes review finding 6.
    /// `true` when group resolution runs through the SAM/LSA fallback
    /// (`NetUserGetGroups`) instead of LDAP. In that case **nested domain
    /// groups are not recursively resolved** and the token SID set may be
    /// incomplete. The engine then pushes a
    /// `PermissionDiagnostic::DomainGroupRecursionIncomplete` into the
    /// result so audit consumers treat the finding as incomplete.
    /// Defaulting to `false` (LDAP path) keeps existing callers
    /// compatible. Closes review finding 6.
    pub group_resolution_via_sam_fallback: bool,
    /// `PermissionDiagnostic::IdentityNotInConfiguredLdapBase`. Default
    /// `false`. Closes review finding 1, 2026-06-04 round 2.
    /// `true` when the identity was resolved via LSA but the configured
    /// LDAP `base_dn` does not index that SID (typical in multi-domain
    /// forests). The engine then pushes a
    /// `PermissionDiagnostic::IdentityNotInConfiguredLdapBase`. Default
    /// `false`. Closes review 2026-06-04 round 2 finding 1.
    pub identity_not_in_configured_ldap_base: bool,
    /// Default `false`. Closes review finding 5, 2026-06-04 round 2.
    /// `true` when the `disabled` flag on the identity could not be
    /// reliably determined (e.g. SAM path without `NetUserGetInfo`).
    /// Default `false`. Closes review 2026-06-04 round 2 finding 5.
    pub identity_disabled_status_unknown: bool,
    /// Risk-Engine markiert abgeleitete Findings als
    /// `incomplete = true`. Default `None`. Closes
    /// Review finding 1, 2026-06-04 round 4.
    /// `Some(reason)` when the LDAP identity lookup failed with a
    /// technical error. The engine pushes an `IdentityLookupFailed`
    /// marker; risk findings are flagged incomplete. Default `None`.
    pub identity_lookup_failure_reason: Option<String>,
    /// Engine pusht dann einen
    /// Risk-Engine markiert abgeleitete Findings als
    /// `incomplete = true`. Default `None`.
    /// `Some(reason)` when recursive group resolution failed or was
    /// deliberately skipped while groups would have mattered. Marker +
    /// risk-incomplete propagation.
    pub group_resolution_failure_reason: Option<String>,
    /// `true` when the identity was resolved through a Foreign Security
    /// Principal object in the home domain (cross-forest trust user).
    /// Home-domain groups were resolved via the FSP; the principal's
    /// memberships in its own forest are unknown. The engine pushes a
    /// `PermissionDiagnostic::IdentityResolvedViaForeignSecurityPrincipal`
    /// and risk findings are flagged incomplete. Default `false`.
    /// Closes known-limitations entry L1.
    pub identity_resolved_via_fsp: bool,
}

pub struct RiskContext {
    pub findings: Vec<EffectivePermission>,
}

///
///
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
    /// Konstruktionen.
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
#[async_trait]
pub trait IdentityResolver: Send + Sync {
    /// Resolves a SID to a full identity (name, domain, kind, status).
    async fn resolve_identity(&self, sid: &Sid) -> Result<Identity, CoreError>;

    /// Determines all group memberships recursively (direct and transitive).
    async fn resolve_group_memberships(&self, sid: &Sid)
        -> Result<Vec<GroupMembership>, CoreError>;
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
