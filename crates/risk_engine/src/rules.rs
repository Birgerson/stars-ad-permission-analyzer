// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Risk rules for NTFS and share permission analysis.

use adpa_core::{
    model::{EffectivePermission, IdentityKind, RiskFinding, RiskSeverity},
    traits::{RiskContext, RiskRule},
};
// Only the tests name diagnostic variants now that is_incomplete delegates to
// EffectivePermission::is_incomplete.
#[cfg(test)]
use adpa_core::model::PermissionDiagnostic;

/// Marks a finding as incomplete when the underlying evaluation has gaps —
/// any of:
/// - the share DACL could not be read (effective_mask is only an NTFS lower
///   bound),
/// - the DACL contained ACE types the parser could not evaluate
///   (object/callback/conditional ACEs); a hidden Deny among them could flip
///   the computed result, or
/// - the local server groups could not be resolved; ACEs targeting local
///   groups (e.g. local Administrators) are then invisible and the effective
///   rights may be too low.
fn is_incomplete(p: &EffectivePermission) -> bool {
    // Single source of truth lives on the model: an EffectivePermission knows
    // whether its own evaluation was complete (share-read failure, unevaluable
    // ACE types, missing local groups, or any incompleteness-trigger
    // diagnostic such as SAM fallback / FSP / GC / sIDHistory). The per-marker
    // warning-vs-info split is `PermissionDiagnostic::is_incompleteness_trigger`.
    p.is_incomplete()
}
use permission_engine::mask::{
    FILE_APPEND_DATA, FILE_DELETE, FILE_DELETE_CHILD, FILE_WRITE_DAC, FILE_WRITE_DATA,
    FILE_WRITE_OWNER, MASK_FULL_CONTROL, MASK_MODIFY, MASK_WRITE,
};

/// Bits that grant the ability to create or alter file *content*:
/// `FILE_WRITE_DATA` (overwrite) and `FILE_APPEND_DATA` (append, or create
/// inside a folder). Deliberately excludes `FILE_WRITE_EA` and
/// `FILE_WRITE_ATTRIBUTES`: attribute/EA writes cannot change file content,
/// and reporting them as "write access" would overstate the finding
/// (risk_engine review 2026-07-25, RK-1/RK-3). Shared by `WriteAccessRule`
/// (PARTIAL_WRITE branch) and `BroadGroupWriteRule` so both answer the same
/// question: "can this principal change what is stored?"
const CONTENT_WRITE_BITS: u32 = FILE_WRITE_DATA | FILE_APPEND_DATA;

// ---------------------------------------------------------------------------
// Known well-known SIDs
// ---------------------------------------------------------------------------

const SID_EVERYONE: &str = "S-1-1-0";
const SID_AUTHENTICATED_USERS: &str = "S-1-5-11";
const SID_ANONYMOUS_LOGON: &str = "S-1-5-7";
const SID_NETWORK: &str = "S-1-5-2";

/// Path keywords that indicate sensitive data.
const SENSITIVE_KEYWORDS: &[&str] = &[
    "password",
    "passwort",
    "pwd",
    "login",
    "credential",
    "credentials",
    "secret",
    "secrets",
    "token",
    "api-key",
    "apikey",
    "keyfile",
    "private-key",
    "ssh-key",
    "private_key",
    "ssh_key",
];

// Author / AGPL attribution marker (see ENGINE_ATTRIBUTION in engine.rs).
// Embedded openly in the compiled binary via `#[used]` so attribution
// survives into the shipped artifact. Data only, never read by logic.
#[used]
static RISK_ATTRIBUTION: &str = "Stars risk engine - (c) Birger Labinsch - AGPL-3.0; this attribution marker must survive into derivative works.";

// ---------------------------------------------------------------------------
// RuleRegistry
// ---------------------------------------------------------------------------

/// Manages and executes all registered risk rules.
#[derive(Default)]
pub struct RuleRegistry {
    rules: Vec<Box<dyn RiskRule>>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Creates a registry with all built-in default rules.
    pub fn with_defaults() -> Self {
        let mut r = Self::new();
        r.register(Box::new(FullControlRule));
        r.register(Box::new(WriteAccessRule));
        r.register(Box::new(AdminRightsRule));
        r.register(Box::new(BroadGroupWriteRule));
        r.register(Box::new(DirectUserAceRule));
        r.register(Box::new(SensitivePathRule));
        r
    }

    pub fn register(&mut self, rule: Box<dyn RiskRule>) {
        self.rules.push(rule);
    }

    pub fn evaluate_all(&self, context: &RiskContext) -> Vec<RiskFinding> {
        self.rules
            .iter()
            .flat_map(|r| r.evaluate(context))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Rule 1: Full Control — CRITICAL
// ---------------------------------------------------------------------------

/// Reports paths where the user has Full Control.
pub struct FullControlRule;

impl RiskRule for FullControlRule {
    fn evaluate(&self, context: &RiskContext) -> Vec<RiskFinding> {
        context
            .findings
            .iter()
            .filter(|p| p.effective_mask.0 & MASK_FULL_CONTROL == MASK_FULL_CONTROL)
            .map(|p| {
                let name = p.identity.name.as_deref().unwrap_or(&p.identity.sid.0);
                RiskFinding {
                    rule_id: "FULL_CONTROL".to_string(),
                    severity: RiskSeverity::Critical,
                    description: format!(
                        "'{name}' has Full Control — can read, write, delete and change permissions"
                    ),
                    affected_path: Some(p.path.clone()),
                    affected_identity: Some(p.identity.sid.clone()),
                    incomplete: is_incomplete(p),
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Rule 2: Write access — HIGH (composite) / MEDIUM (partial content write)
// ---------------------------------------------------------------------------

/// Reports write access below Full Control, in two forms:
///
/// - `WRITE_ACCESS` (High): the effective mask carries the full Modify or
///   Write composite — the classic checkbox-level grant.
/// - `PARTIAL_WRITE` (Medium): the effective mask carries content-write bits
///   (`FILE_WRITE_DATA` / `FILE_APPEND_DATA`) *without* the full composite —
///   "special permissions", e.g. an append-only drop-box folder.
///
/// Review 2026-07-25 finding RK-1: before the PARTIAL_WRITE branch existed, a
/// principal with bare content-write bits triggered no rule at all — a
/// content-writable path produced an empty risk report.
pub struct WriteAccessRule;

impl RiskRule for WriteAccessRule {
    fn evaluate(&self, context: &RiskContext) -> Vec<RiskFinding> {
        context
            .findings
            .iter()
            .filter_map(|p| {
                let m = p.effective_mask.0;
                // Full Control is reported as CRITICAL by FullControlRule.
                if m & MASK_FULL_CONTROL == MASK_FULL_CONTROL {
                    return None;
                }
                let name = p.identity.name.as_deref().unwrap_or(&p.identity.sid.0);
                if m & MASK_MODIFY == MASK_MODIFY || m & MASK_WRITE == MASK_WRITE {
                    let level = if m & MASK_MODIFY == MASK_MODIFY {
                        "Modify"
                    } else {
                        "Write"
                    };
                    return Some(RiskFinding {
                        rule_id: "WRITE_ACCESS".to_string(),
                        severity: RiskSeverity::High,
                        description: format!(
                            "'{name}' has {level} access — can create or modify files"
                        ),
                        affected_path: Some(p.path.clone()),
                        affected_identity: Some(p.identity.sid.clone()),
                        incomplete: is_incomplete(p),
                    });
                }
                if m & CONTENT_WRITE_BITS != 0 {
                    let bits = content_write_bit_names(m);
                    return Some(RiskFinding {
                        rule_id: "PARTIAL_WRITE".to_string(),
                        severity: RiskSeverity::Medium,
                        description: format!(
                            "'{name}' can write file content via special permissions ({bits}) \
                             without the full Write composite"
                        ),
                        affected_path: Some(p.path.clone()),
                        affected_identity: Some(p.identity.sid.clone()),
                        incomplete: is_incomplete(p),
                    });
                }
                None
            })
            .collect()
    }
}

/// Names the content-write bits present in `mask`, for PARTIAL_WRITE
/// descriptions. Only called when at least one bit is set.
fn content_write_bit_names(mask: u32) -> String {
    let mut names = Vec::new();
    if mask & FILE_WRITE_DATA != 0 {
        names.push("FILE_WRITE_DATA");
    }
    if mask & FILE_APPEND_DATA != 0 {
        names.push("FILE_APPEND_DATA");
    }
    names.join(" + ")
}

// ---------------------------------------------------------------------------
// Rule 3: Admin-relevant single rights — HIGH / MEDIUM
// ---------------------------------------------------------------------------

/// Reports individual destructive or administrative rights that are not
/// necessarily covered by the composite Modify/Write masks.
///
/// `WRITE_DAC` and `WRITE_OWNER` lie outside Modify and Write — a principal
/// holding only those bits would otherwise not surface as a risk at all,
/// even though it can change permissions or take ownership.
pub struct AdminRightsRule;

impl RiskRule for AdminRightsRule {
    fn evaluate(&self, context: &RiskContext) -> Vec<RiskFinding> {
        let mut out = Vec::new();
        for p in &context.findings {
            let m = p.effective_mask.0;
            // Full Control is already reported as CRITICAL by FullControlRule — do
            // not break it down again here to avoid duplicate findings.
            if m & MASK_FULL_CONTROL == MASK_FULL_CONTROL {
                continue;
            }
            let name = p.identity.name.as_deref().unwrap_or(&p.identity.sid.0);

            if m & FILE_WRITE_DAC != 0 {
                out.push(RiskFinding {
                    rule_id: "PERMISSION_CHANGE".to_string(),
                    severity: RiskSeverity::High,
                    description: format!(
                        "'{name}' can change permissions (WRITE_DAC) — enables privilege escalation"
                    ),
                    affected_path: Some(p.path.clone()),
                    affected_identity: Some(p.identity.sid.clone()),
                    incomplete: is_incomplete(p),
                });
            }
            if m & FILE_WRITE_OWNER != 0 {
                out.push(RiskFinding {
                    rule_id: "OWNER_CHANGE".to_string(),
                    severity: RiskSeverity::High,
                    description: format!(
                        "'{name}' can take ownership (WRITE_OWNER) — enables privilege escalation"
                    ),
                    affected_path: Some(p.path.clone()),
                    affected_identity: Some(p.identity.sid.clone()),
                    incomplete: is_incomplete(p),
                });
            }
            if m & FILE_DELETE != 0 {
                out.push(RiskFinding {
                    rule_id: "DELETE_RIGHT".to_string(),
                    severity: RiskSeverity::Medium,
                    description: format!("'{name}' can delete this object (DELETE)"),
                    affected_path: Some(p.path.clone()),
                    affected_identity: Some(p.identity.sid.clone()),
                    incomplete: is_incomplete(p),
                });
            }
            if m & FILE_DELETE_CHILD != 0 {
                out.push(RiskFinding {
                    rule_id: "DELETE_CHILD_RIGHT".to_string(),
                    severity: RiskSeverity::Medium,
                    description: format!("'{name}' can delete child objects (DELETE_CHILD)"),
                    affected_path: Some(p.path.clone()),
                    affected_identity: Some(p.identity.sid.clone()),
                    incomplete: is_incomplete(p),
                });
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Rule 4: Broad group write — CRITICAL
// ---------------------------------------------------------------------------

/// Reports when write access originated from a broad-group ACE (Everyone, Authenticated Users,
/// etc.) — even when the queried identity is a regular user.
pub struct BroadGroupWriteRule;

impl RiskRule for BroadGroupWriteRule {
    fn evaluate(&self, context: &RiskContext) -> Vec<RiskFinding> {
        let broad_sids = [
            SID_EVERYONE,
            SID_AUTHENTICATED_USERS,
            SID_ANONYMOUS_LOGON,
            SID_NETWORK,
        ];
        // Review 2026-06-08 finding 1: gate on write bits actually present in
        // the final effective mask (not the composite MASK_WRITE, which
        // shares READ_CONTROL/SYNCHRONIZE with Read), and require the
        // contributing broad SID's ACE mask to overlap them — otherwise an
        // NTFS Allow whose write bits got capped away by Share Read would
        // still trigger.
        //
        // Review 2026-07-25 finding RK-3: narrowed further to
        // CONTENT_WRITE_BITS. "Everyone can write attributes/EAs" is not
        // "write access affecting all users" — the Critical claim must match
        // a capability that can alter file content. EA/attribute-only ACEs
        // stay fully visible in the permission view; they are just not this
        // risk finding.
        context
            .findings
            .iter()
            .filter_map(|p| {
                let eff_w = p.effective_mask.0 & CONTENT_WRITE_BITS;
                if eff_w == 0 {
                    return None;
                }
                // RK-9: bind the matched broad ACE once — the previous
                // filter/map pair ran the same `find` twice and papered over
                // the impossible miss with `unwrap_or("")`.
                let broad = p.contributing_sids.iter().find(|cs| {
                    broad_sids.contains(&cs.sid.0.as_str()) && (cs.mask.0 & eff_w) != 0
                })?;
                // RK-3 (honest wording): name the audience of the broad SID
                // precisely — "all users in the domain" was wrong for
                // Anonymous Logon and NETWORK.
                let (sid_name, scope) = match broad.sid.0.as_str() {
                    SID_EVERYONE => ("Everyone", "every user, including guests"),
                    SID_AUTHENTICATED_USERS => (
                        "Authenticated Users",
                        "every authenticated user in the domain",
                    ),
                    SID_ANONYMOUS_LOGON => ("Anonymous Logon", "unauthenticated clients"),
                    SID_NETWORK => ("NETWORK", "every user connecting over the network"),
                    other => (other, "a broad built-in principal"),
                };
                let identity_name = p.identity.name.as_deref().unwrap_or(&p.identity.sid.0);
                Some(RiskFinding {
                    rule_id: "BROAD_GROUP_WRITE".to_string(),
                    severity: RiskSeverity::Critical,
                    description: format!(
                        "'{identity_name}' has write access via '{sid_name}' — affects {scope}"
                    ),
                    affected_path: Some(p.path.clone()),
                    affected_identity: Some(p.identity.sid.clone()),
                    incomplete: is_incomplete(p),
                })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Rule 5: Direct user ACE — LOW
// ---------------------------------------------------------------------------

/// Reports when a user has a direct explicit ACE (best practice: groups only).
///
/// Relies on the result's structured `matched_aces` instead of the explanation
/// text — robust against localization and format changes. Catches direct Allow
/// *and* Deny ACEs, since both violate the best-practice principle.
///
/// Review 2026-07-25 finding RK-2: fires only for leaf principals (`User`,
/// `Computer`). When the analyzed identity is itself a group, a direct ACE on
/// that group SID is exactly how AGDLP assigns permissions — not a finding.
/// For `WellKnown`, `ForeignSecurityPrincipal`, `Orphaned` and `Unknown` the
/// rule stays silent too: it cannot honestly claim "user" there.
///
/// Review 2026-07-25 finding RK-6: deliberately no `effective_mask > 0` gate.
/// A direct Deny ACE that removes *all* access (typical "lock out this
/// employee quickly" leftover) is still a direct ACE on the user and must
/// stay visible — the management smell is the ACE itself, not the resulting
/// access.
pub struct DirectUserAceRule;

impl RiskRule for DirectUserAceRule {
    fn evaluate(&self, context: &RiskContext) -> Vec<RiskFinding> {
        context
            .findings
            .iter()
            .filter(|p| {
                matches!(
                    p.identity.kind,
                    IdentityKind::User | IdentityKind::Computer
                ) && p
                    .matched_aces
                    .iter()
                    .any(|ace| !ace.inherited && ace.sid.0 == p.identity.sid.0)
            })
            .map(|p| {
                let name = p.identity.name.as_deref().unwrap_or(&p.identity.sid.0);
                RiskFinding {
                    rule_id: "DIRECT_USER_ACE".to_string(),
                    severity: RiskSeverity::Low,
                    description: format!(
                        "'{name}' has a direct explicit ACE — best practice is to assign permissions via groups"
                    ),
                    affected_path: Some(p.path.clone()),
                    affected_identity: Some(p.identity.sid.clone()),
                    // The direct ACE itself exists on the NTFS layer
                    // independent of share status. But when the evaluation had
                    // gaps elsewhere (e.g. share DACL not readable) the finding
                    // is just as `incomplete` as every other finding for the
                    // same permission — consistent with `is_incomplete`.
                    incomplete: is_incomplete(p),
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Rule 6: Sensitive path names — MEDIUM
// ---------------------------------------------------------------------------

/// Reports paths whose name suggests sensitive data.
pub struct SensitivePathRule;

impl RiskRule for SensitivePathRule {
    fn evaluate(&self, context: &RiskContext) -> Vec<RiskFinding> {
        context
            .findings
            .iter()
            .filter(|p| {
                // Follow-up finding 3 (review 2026-05-25): the rule
                // claims "has access" — so only emit a finding when the
                // identity actually has access. Otherwise a deny-all
                // result would be misreported as a positive risk.
                if p.effective_mask.0 == 0 {
                    return false;
                }
                let lower = p.path.0.to_lowercase();
                SENSITIVE_KEYWORDS.iter().any(|kw| lower.contains(kw))
            })
            .map(|p| {
                let name = p.identity.name.as_deref().unwrap_or(&p.identity.sid.0);
                let keyword = SENSITIVE_KEYWORDS
                    .iter()
                    .find(|kw| p.path.0.to_lowercase().contains(**kw))
                    .copied()
                    .unwrap_or("sensitive");
                RiskFinding {
                    rule_id: "SENSITIVE_PATH".to_string(),
                    severity: RiskSeverity::Medium,
                    description: format!(
                        "Path contains keyword '{keyword}' — may contain credentials or secrets; '{name}' has access"
                    ),
                    affected_path: Some(p.path.clone()),
                    affected_identity: Some(p.identity.sid.clone()),
                    // The path name is an NTFS property, but the "has access"
                    // claim relies on `effective_mask`. When the share DACL
                    // could not be read, real SMB access could be more
                    // restrictive. So the finding must be marked `incomplete`
                    // like every other risk for the same permission whenever
                    // the evaluation had gaps.
                    incomplete: is_incomplete(p),
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use adpa_core::{
        model::{
            AccessMask, AceEntry, AceKind, ContributingAce, EffectivePermission, Identity,
            IdentityKind, NormalizedPath, PermissionPath, Sid,
        },
        traits::RiskContext,
    };
    use permission_engine::mask::{
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_EA, MASK_FULL_CONTROL, MASK_MODIFY, MASK_READ,
    };

    const USER_SID: &str = "S-1-5-21-1000-1000-1000-1001";

    fn perm(sid: &str, mask: u32, path: &str, steps: Vec<String>) -> EffectivePermission {
        perm_cs(sid, mask, path, steps, vec![])
    }

    fn perm_cs(
        sid: &str,
        mask: u32,
        path: &str,
        steps: Vec<String>,
        contributing_sids: Vec<ContributingAce>,
    ) -> EffectivePermission {
        perm_ma(sid, mask, path, steps, contributing_sids, vec![])
    }

    fn perm_ma(
        sid: &str,
        mask: u32,
        path: &str,
        steps: Vec<String>,
        contributing_sids: Vec<ContributingAce>,
        matched_aces: Vec<AceEntry>,
    ) -> EffectivePermission {
        EffectivePermission {
            identity: Identity {
                sid: Sid(sid.to_string()),
                name: Some(sid.to_string()),
                domain: None,
                kind: IdentityKind::User,
                disabled: false,
                user_principal_name: None,
                sid_history_count: 0,
                sid_history: Vec::new(),
            },
            path: NormalizedPath(path.to_string()),
            ntfs_mask: AccessMask(mask),
            share_mask: None,
            effective_mask: AccessMask(mask),
            path_explanation: PermissionPath { steps },
            share_status: adpa_core::model::ShareEvalStatus::NotApplicable,
            local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
            contributing_sids,
            unsupported_ace_count: 0,
            matched_aces,
            diagnostics: vec![],
        }
    }

    /// Builds an ACE entry for the DirectUserAceRule tests.
    fn ace_entry(sid: &str, kind: AceKind, inherited: bool) -> AceEntry {
        AceEntry {
            kind,
            sid: Sid(sid.to_string()),
            mask: AccessMask(MASK_READ),
            inherited,
            inheritance_flags: 0,
            propagation_flags: 0,
        }
    }

    fn ctx(permissions: Vec<EffectivePermission>) -> RiskContext {
        RiskContext {
            findings: permissions,
        }
    }

    #[test]
    fn unsupported_aces_mark_finding_incomplete() {
        let mut p = perm(USER_SID, MASK_FULL_CONTROL, r"C:\data", vec![]);
        p.unsupported_ace_count = 1;
        let r = FullControlRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert!(
            r[0].incomplete,
            "unsupported ACE -> finding must be marked incomplete"
        );
    }

    /// Follow-up finding 2: same logic for the share side. If
    /// `EffectivePermission.diagnostics` carries an `UnsupportedShareAces`
    /// marker, the finding must be flagged incomplete.
    #[test]
    fn unsupported_share_aces_diagnostic_marks_finding_incomplete() {
        let mut p = perm(USER_SID, MASK_FULL_CONTROL, r"C:\data", vec![]);
        p.diagnostics = vec![PermissionDiagnostic::UnsupportedShareAces { count: 2 }];
        let r = FullControlRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert!(
            r[0].incomplete,
            "UnsupportedShareAces diagnostic -> finding must be incomplete"
        );
    }

    #[test]
    fn non_canonical_dacl_diagnostic_alone_does_not_mark_incomplete() {
        // Important: NonCanonicalDaclOrder is audit info, not a correctness
        // issue (the engine still evaluates stored-order correctly). Risk
        // findings on such paths must remain "confirmed".
        let mut p = perm(USER_SID, MASK_FULL_CONTROL, r"C:\data", vec![]);
        p.diagnostics = vec![PermissionDiagnostic::NonCanonicalDaclOrder { at_index: 1 }];
        let r = FullControlRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert!(
            !r[0].incomplete,
            "NonCanonicalDaclOrder alone must NOT flag incomplete"
        );
    }

    /// ADR 0052 (L3): a sIDHistory marker means the effective right may be
    /// understated — risk findings on that path must be incomplete.
    #[test]
    fn sid_history_present_diagnostic_marks_finding_incomplete() {
        let mut p = perm(USER_SID, MASK_FULL_CONTROL, r"C:\data", vec![]);
        p.diagnostics = vec![PermissionDiagnostic::SidHistoryPresent { count: 1 }];
        let r = FullControlRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert!(
            r[0].incomplete,
            "SidHistoryPresent diagnostic -> finding must be incomplete"
        );
    }

    /// ADR 0056: SidHistoryEvaluated means the historical SIDs WERE part
    /// of the evaluated token — the result is exact, so the marker alone
    /// must NOT flag a finding incomplete.
    #[test]
    fn sid_history_evaluated_diagnostic_alone_does_not_mark_incomplete() {
        let mut p = perm(USER_SID, MASK_FULL_CONTROL, r"C:\data", vec![]);
        p.diagnostics = vec![PermissionDiagnostic::SidHistoryEvaluated { count: 1 }];
        let r = FullControlRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert!(
            !r[0].incomplete,
            "SidHistoryEvaluated alone must NOT flag incomplete"
        );
    }

    /// ADR 0059: GroupSidHistoryEvaluated means the groups' historical
    /// SIDs WERE in the token — exact, must NOT flag incomplete.
    #[test]
    fn group_sid_history_evaluated_diagnostic_alone_does_not_mark_incomplete() {
        let mut p = perm(USER_SID, MASK_FULL_CONTROL, r"C:\data", vec![]);
        p.diagnostics = vec![PermissionDiagnostic::GroupSidHistoryEvaluated {
            groups: 1,
            count: 1,
        }];
        let r = FullControlRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert!(
            !r[0].incomplete,
            "GroupSidHistoryEvaluated alone must NOT flag incomplete"
        );
    }

    /// ADR 0059: un-evaluated group history means the right may be
    /// understated — the finding must be incomplete.
    #[test]
    fn group_sid_history_present_diagnostic_marks_finding_incomplete() {
        let mut p = perm(USER_SID, MASK_FULL_CONTROL, r"C:\data", vec![]);
        p.diagnostics = vec![PermissionDiagnostic::GroupSidHistoryPresent { count: 1 }];
        let r = FullControlRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert!(
            r[0].incomplete,
            "GroupSidHistoryPresent -> finding must be incomplete"
        );
    }

    /// ADR 0052 (L4): TrustBoundaryEffectsNotModeled is informational —
    /// it fires beside the FSP / outside-base markers, which already flag
    /// incompleteness, so alone it must NOT mark a finding incomplete.
    #[test]
    fn trust_boundary_effects_diagnostic_alone_does_not_mark_incomplete() {
        let mut p = perm(USER_SID, MASK_FULL_CONTROL, r"C:\data", vec![]);
        p.diagnostics = vec![PermissionDiagnostic::TrustBoundaryEffectsNotModeled];
        let r = FullControlRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert!(
            !r[0].incomplete,
            "TrustBoundaryEffectsNotModeled alone must NOT flag incomplete"
        );
    }

    #[test]
    fn finding_complete_when_no_share_or_unsupported_issue() {
        let p = perm(USER_SID, MASK_FULL_CONTROL, r"C:\data", vec![]);
        let r = FullControlRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert!(!r[0].incomplete);
    }

    #[test]
    fn full_control_flagged_as_critical() {
        let r = FullControlRule.evaluate(&ctx(vec![perm(
            USER_SID,
            MASK_FULL_CONTROL,
            r"C:\data",
            vec![],
        )]));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, RiskSeverity::Critical);
        assert_eq!(r[0].rule_id, "FULL_CONTROL");
    }

    #[test]
    fn modify_flagged_as_high_not_full_control() {
        let findings = vec![perm(USER_SID, MASK_MODIFY, r"C:\data", vec![])];
        assert_eq!(WriteAccessRule.evaluate(&ctx(findings.clone())).len(), 1);
        assert!(FullControlRule.evaluate(&ctx(findings)).is_empty());
    }

    #[test]
    fn read_only_not_flagged_as_write() {
        assert!(WriteAccessRule
            .evaluate(&ctx(vec![perm(USER_SID, MASK_READ, r"C:\data", vec![])]))
            .is_empty());
    }

    // --- WriteAccessRule: partial content write (review 2026-07-25, RK-1) ---

    /// RK-1: content-write bits without the full Write composite must be
    /// reported. Before the PARTIAL_WRITE branch existed, a principal with
    /// bare FILE_WRITE_DATA triggered no rule at all — a content-writable
    /// path produced an empty risk report.
    #[test]
    fn write_data_without_composite_flagged_as_partial_write() {
        let r = WriteAccessRule.evaluate(&ctx(vec![perm(
            USER_SID,
            MASK_READ | FILE_WRITE_DATA,
            r"C:\data",
            vec![],
        )]));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "PARTIAL_WRITE");
        assert_eq!(r[0].severity, RiskSeverity::Medium);
        assert!(
            r[0].description.contains("FILE_WRITE_DATA"),
            "description must name the exact bit, got: {}",
            r[0].description
        );
    }

    /// RK-1: append-only (FILE_APPEND_DATA without FILE_WRITE_DATA) — the
    /// classic drop-box folder.
    #[test]
    fn append_only_flagged_as_partial_write() {
        let r = WriteAccessRule.evaluate(&ctx(vec![perm(
            USER_SID,
            MASK_READ | FILE_APPEND_DATA,
            r"C:\upload",
            vec![],
        )]));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "PARTIAL_WRITE");
        assert!(
            r[0].description.contains("FILE_APPEND_DATA"),
            "description must name the exact bit, got: {}",
            r[0].description
        );
    }

    /// RK-1 boundary: attribute/EA writes cannot change file content and
    /// must NOT be reported as write access — the deliberate
    /// CONTENT_WRITE_BITS exclusion.
    #[test]
    fn attribute_and_ea_write_only_not_flagged_as_partial_write() {
        assert!(WriteAccessRule
            .evaluate(&ctx(vec![perm(
                USER_SID,
                MASK_READ | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA,
                r"C:\data",
                vec![],
            )]))
            .is_empty());
    }

    /// The full composite must keep reporting WRITE_ACCESS (High), never the
    /// weaker PARTIAL_WRITE — exactly one finding per permission.
    #[test]
    fn full_write_composite_reports_write_access_not_partial_write() {
        let r =
            WriteAccessRule.evaluate(&ctx(vec![perm(USER_SID, MASK_WRITE, r"C:\data", vec![])]));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "WRITE_ACCESS");
        assert_eq!(r[0].severity, RiskSeverity::High);
    }

    /// PARTIAL_WRITE follows the same confidence model as every other rule:
    /// share DACL unreadable → finding flagged incomplete.
    #[test]
    fn partial_write_marks_finding_incomplete_on_share_read_failed() {
        let mut p = perm(USER_SID, MASK_READ | FILE_APPEND_DATA, r"C:\upload", vec![]);
        p.share_status = adpa_core::model::ShareEvalStatus::ReadFailed("access denied".to_owned());
        let r = WriteAccessRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "PARTIAL_WRITE");
        assert!(r[0].incomplete);
    }

    // --- AdminRightsRule: destructive/administrative single rights ---

    #[test]
    fn write_dac_only_flagged_as_permission_change() {
        let r = AdminRightsRule.evaluate(&ctx(vec![perm(
            USER_SID,
            FILE_WRITE_DAC,
            r"C:\data",
            vec![],
        )]));
        assert_eq!(r.len(), 1, "WRITE_DAC alone must produce a finding");
        assert_eq!(r[0].rule_id, "PERMISSION_CHANGE");
        assert_eq!(r[0].severity, RiskSeverity::High);
    }

    #[test]
    fn write_owner_only_flagged_as_owner_change() {
        let r = AdminRightsRule.evaluate(&ctx(vec![perm(
            USER_SID,
            FILE_WRITE_OWNER,
            r"C:\data",
            vec![],
        )]));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "OWNER_CHANGE");
        assert_eq!(r[0].severity, RiskSeverity::High);
    }

    #[test]
    fn delete_only_flagged_as_delete_right() {
        let r =
            AdminRightsRule.evaluate(&ctx(vec![perm(USER_SID, FILE_DELETE, r"C:\data", vec![])]));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "DELETE_RIGHT");
        assert_eq!(r[0].severity, RiskSeverity::Medium);
    }

    #[test]
    fn delete_child_only_flagged_as_delete_child_right() {
        let r = AdminRightsRule.evaluate(&ctx(vec![perm(
            USER_SID,
            FILE_DELETE_CHILD,
            r"C:\data",
            vec![],
        )]));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "DELETE_CHILD_RIGHT");
        assert_eq!(r[0].severity, RiskSeverity::Medium);
    }

    #[test]
    fn write_dac_not_part_of_modify_or_write_masks() {
        assert!(WriteAccessRule
            .evaluate(&ctx(vec![perm(USER_SID, FILE_WRITE_DAC, r"C:\d", vec![])]))
            .is_empty());
    }

    #[test]
    fn admin_rule_skips_full_control_to_avoid_double_report() {
        let r = AdminRightsRule.evaluate(&ctx(vec![perm(
            USER_SID,
            MASK_FULL_CONTROL,
            r"C:\data",
            vec![],
        )]));
        assert!(r.is_empty(), "Full Control must not be broken down again");
    }

    #[test]
    fn admin_rule_ignores_read_only() {
        assert!(AdminRightsRule
            .evaluate(&ctx(vec![perm(USER_SID, MASK_READ, r"C:\data", vec![])]))
            .is_empty());
    }

    #[test]
    fn admin_rule_reports_delete_for_modify_mask() {
        let r =
            AdminRightsRule.evaluate(&ctx(vec![perm(USER_SID, MASK_MODIFY, r"C:\data", vec![])]));
        assert_eq!(r.len(), 1, "Modify exposes exactly the DELETE right");
        assert_eq!(r[0].rule_id, "DELETE_RIGHT");
    }

    #[test]
    fn admin_rule_reports_each_dangerous_bit_separately() {
        let mask = FILE_WRITE_DAC | FILE_WRITE_OWNER | FILE_DELETE | FILE_DELETE_CHILD;
        let r = AdminRightsRule.evaluate(&ctx(vec![perm(USER_SID, mask, r"C:\d", vec![])]));
        assert_eq!(r.len(), 4, "each dangerous bit yields its own finding");
        assert!(r.iter().any(|f| f.rule_id == "PERMISSION_CHANGE"));
        assert!(r.iter().any(|f| f.rule_id == "OWNER_CHANGE"));
        assert!(r.iter().any(|f| f.rule_id == "DELETE_RIGHT"));
        assert!(r.iter().any(|f| f.rule_id == "DELETE_CHILD_RIGHT"));
    }

    // BroadGroupWriteRule: fires only when a broad-SID ACE actually contributed write bits.

    fn ace(sid: &str, mask: u32) -> ContributingAce {
        ContributingAce {
            sid: Sid(sid.to_string()),
            mask: AccessMask(mask),
        }
    }

    #[test]
    fn everyone_write_flagged_as_critical() {
        let r = BroadGroupWriteRule.evaluate(&ctx(vec![perm_cs(
            SID_EVERYONE,
            MASK_MODIFY,
            r"C:\data",
            vec![],
            vec![ace(SID_EVERYONE, MASK_MODIFY)],
        )]));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, RiskSeverity::Critical);
        assert_eq!(r[0].rule_id, "BROAD_GROUP_WRITE");
    }

    /// Regression: normal user gets write access via an Everyone ACE.
    /// The rule must fire even when the identity SID is not itself a broad principal.
    #[test]
    fn normal_user_write_via_everyone_ace_flagged() {
        let r = BroadGroupWriteRule.evaluate(&ctx(vec![perm_cs(
            USER_SID,
            MASK_MODIFY,
            r"C:\data",
            vec![],
            vec![ace(SID_EVERYONE, MASK_MODIFY)],
        )]));
        assert_eq!(
            r.len(),
            1,
            "expected BROAD_GROUP_WRITE for normal user with Everyone ACE"
        );
        assert_eq!(r[0].rule_id, "BROAD_GROUP_WRITE");
        assert_eq!(r[0].severity, RiskSeverity::Critical);
        assert!(
            r[0].description.contains("Everyone"),
            "description should name the broad SID, got: {}",
            r[0].description
        );
    }

    /// Write access via a specific group (no broad SID) must not fire.
    #[test]
    fn write_via_specific_group_not_flagged() {
        assert!(BroadGroupWriteRule
            .evaluate(&ctx(vec![perm_cs(
                USER_SID,
                MASK_MODIFY,
                r"C:\data",
                vec![],
                vec![ace("S-1-5-21-1000-1000-1000-5000", MASK_MODIFY)]
            )]))
            .is_empty());
    }

    /// Regression test for the reported false positive:
    /// Everyone contributes only Read; Modify comes from a specific group.
    /// BroadGroupWriteRule must NOT fire.
    #[test]
    fn everyone_read_specific_group_write_no_broad_group_write() {
        let contributing = vec![
            ace(SID_EVERYONE, MASK_READ),
            ace("S-1-5-21-1000-1000-1000-5000", MASK_MODIFY),
        ];
        assert!(
            BroadGroupWriteRule
                .evaluate(&ctx(vec![perm_cs(
                    USER_SID,
                    MASK_MODIFY,
                    r"C:\data",
                    vec![],
                    contributing,
                )]))
                .is_empty(),
            "BROAD_GROUP_WRITE must not fire when Everyone only contributed Read bits"
        );
    }

    /// Review 2026-06-08 finding 1: NTFS grants Everyone Modify, but the
    /// SMB share caps the final effective permission to Read. Pre-fix,
    /// the rule fired because `effective_mask & MASK_WRITE` was non-zero
    /// (READ_CONTROL/SYNCHRONIZE bits overlap with Read), so a Read-only
    /// effective permission was reported as critical broad write — a
    /// false-positive in exactly the NTFS+SMB combination Stars audits.
    /// Post-fix, the rule must use write-specific effective bits.
    #[test]
    fn ntfs_modify_via_everyone_but_share_read_no_broad_group_write() {
        // The permission as the engine would emit it after NTFS Modify
        // ∩ Share Read = Read & Execute. NTFS mask carries Everyone's
        // Modify, share mask carries Read, effective is Read.
        let mut p = perm_cs(
            USER_SID,
            MASK_MODIFY,
            r"C:\share-data",
            vec![],
            vec![ace(SID_EVERYONE, MASK_MODIFY)],
        );
        p.ntfs_mask = AccessMask(MASK_MODIFY);
        p.share_mask = Some(AccessMask(MASK_READ));
        p.effective_mask = AccessMask(MASK_READ);
        assert!(
            BroadGroupWriteRule.evaluate(&ctx(vec![p])).is_empty(),
            "BROAD_GROUP_WRITE must not fire when the final effective permission \
             is Read, even when NTFS alone gave Everyone Modify"
        );
    }

    /// Review 2026-07-25 finding RK-3: "Everyone can write attributes/EAs"
    /// is not content write — the Critical BROAD_GROUP_WRITE claim ("has
    /// write access") must not fire on it. The ACE itself stays visible in
    /// the permission view.
    #[test]
    fn everyone_attribute_write_only_no_broad_group_write() {
        let mask = MASK_READ | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA;
        assert!(BroadGroupWriteRule
            .evaluate(&ctx(vec![perm_cs(
                USER_SID,
                mask,
                r"C:\data",
                vec![],
                vec![ace(SID_EVERYONE, mask)],
            )]))
            .is_empty());
    }

    /// RK-3 counterpart: append-only via Everyone IS content write and must
    /// keep firing as Critical.
    #[test]
    fn everyone_append_only_flagged_as_critical() {
        let mask = MASK_READ | FILE_APPEND_DATA;
        let r = BroadGroupWriteRule.evaluate(&ctx(vec![perm_cs(
            USER_SID,
            mask,
            r"C:\upload",
            vec![],
            vec![ace(SID_EVERYONE, mask)],
        )]));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "BROAD_GROUP_WRITE");
        assert_eq!(r[0].severity, RiskSeverity::Critical);
    }

    /// RK-3 (honest wording): the description must name the audience of the
    /// matched broad SID — Anonymous Logon means unauthenticated clients,
    /// not "all users in the domain".
    #[test]
    fn anonymous_write_description_names_unauthenticated_clients() {
        let r = BroadGroupWriteRule.evaluate(&ctx(vec![perm_cs(
            USER_SID,
            MASK_MODIFY,
            r"C:\data",
            vec![],
            vec![ace(SID_ANONYMOUS_LOGON, MASK_MODIFY)],
        )]));
        assert_eq!(r.len(), 1);
        assert!(
            r[0].description.contains("unauthenticated clients"),
            "description must state the real audience, got: {}",
            r[0].description
        );
    }

    /// ChatGPT review 2026-06-04 round 2, finding 4: when the engine
    /// sets `PermissionDiagnostic::DomainGroupRecursionIncomplete`
    /// (SAM/LSA fallback without LDAP), risk findings for that
    /// permission must carry `incomplete = true` — otherwise a
    /// FULL_CONTROL finding can appear as confirmed despite the
    /// domain group recursion being incomplete. ADR 0033 requires
    /// this; before this test code and ADR were inconsistent.
    #[test]
    fn full_control_marks_finding_incomplete_on_sam_fallback_diagnostic() {
        use adpa_core::model::PermissionDiagnostic;
        let mut p = perm(USER_SID, MASK_FULL_CONTROL, r"C:\data", vec![]);
        p.diagnostics
            .push(PermissionDiagnostic::DomainGroupRecursionIncomplete);
        let r = FullControlRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert!(
            r[0].incomplete,
            "DomainGroupRecursionIncomplete -> finding must be flagged incomplete (review 2026-06-04 round 2 finding 4)"
        );
    }

    /// Review 2026-06-04 round 2 finding 1: `IdentityNotInConfiguredLdapBase`
    /// means LSA resolved the SID but the LDAP `base_dn` does not index
    /// it. Cross-domain group recursion is incomplete — risk findings
    /// must be marked `incomplete` just like for the SAM fallback.
    #[test]
    fn full_control_marks_finding_incomplete_on_identity_not_in_ldap_base() {
        use adpa_core::model::PermissionDiagnostic;
        let mut p = perm(USER_SID, MASK_FULL_CONTROL, r"C:\data", vec![]);
        p.diagnostics
            .push(PermissionDiagnostic::IdentityNotInConfiguredLdapBase);
        let r = FullControlRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert!(
            r[0].incomplete,
            "IdentityNotInConfiguredLdapBase -> finding must be flagged incomplete (review 2026-06-04 round 2 finding 1)"
        );
    }

    /// Review 2026-06-04 round 2 finding 5: `IdentityDisabledStatusUnknown`
    /// is informational only — it signals "`disabled` could not be
    /// determined" but the ACL evaluation is complete. Risk findings
    /// must **not** be marked `incomplete = true` because of this
    /// marker alone.
    #[test]
    fn full_control_does_not_mark_incomplete_on_disabled_status_unknown_alone() {
        use adpa_core::model::PermissionDiagnostic;
        let mut p = perm(USER_SID, MASK_FULL_CONTROL, r"C:\data", vec![]);
        p.diagnostics
            .push(PermissionDiagnostic::IdentityDisabledStatusUnknown);
        let r = FullControlRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert!(
            !r[0].incomplete,
            "IdentityDisabledStatusUnknown alone is informational and must NOT mark incomplete (review 2026-06-04 round 2 finding 5)"
        );
    }

    /// Review 2026-06-04 round 4 finding 1: `IdentityLookupFailed` →
    /// incomplete.
    #[test]
    fn full_control_marks_finding_incomplete_on_identity_lookup_failed() {
        use adpa_core::model::PermissionDiagnostic;
        let mut p = perm(USER_SID, MASK_FULL_CONTROL, r"C:\data", vec![]);
        p.diagnostics
            .push(PermissionDiagnostic::IdentityLookupFailed {
                reason: "LDAP bind failed".to_owned(),
            });
        let r = FullControlRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert!(
            r[0].incomplete,
            "IdentityLookupFailed -> finding must be flagged incomplete (review 2026-06-04 round 4 finding 1)"
        );
    }

    /// Known-limitations L1: identity resolved through a Foreign
    /// Security Principal — trust-forest memberships are unknown, so
    /// derived findings must be flagged incomplete.
    #[test]
    fn full_control_marks_finding_incomplete_on_fsp_resolution() {
        use adpa_core::model::PermissionDiagnostic;
        let mut p = perm(USER_SID, MASK_FULL_CONTROL, r"C:\data", vec![]);
        p.diagnostics
            .push(PermissionDiagnostic::IdentityResolvedViaForeignSecurityPrincipal);
        let r = FullControlRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert!(
            r[0].incomplete,
            "IdentityResolvedViaForeignSecurityPrincipal -> finding must be flagged incomplete (L1)"
        );
    }

    /// Known-limitations L2: memberships from a Global Catalog bind are
    /// potentially partial — derived findings must be flagged incomplete.
    #[test]
    fn full_control_marks_finding_incomplete_on_gc_resolution() {
        use adpa_core::model::PermissionDiagnostic;
        let mut p = perm(USER_SID, MASK_FULL_CONTROL, r"C:\data", vec![]);
        p.diagnostics
            .push(PermissionDiagnostic::GroupResolutionViaGlobalCatalog);
        let r = FullControlRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert!(
            r[0].incomplete,
            "GroupResolutionViaGlobalCatalog -> finding must be flagged incomplete (L2)"
        );
    }

    /// Review 2026-06-04 round 4 finding 1: `GroupResolutionFailed` →
    /// incomplete.
    #[test]
    fn full_control_marks_finding_incomplete_on_group_resolution_failed() {
        use adpa_core::model::PermissionDiagnostic;
        let mut p = perm(USER_SID, MASK_FULL_CONTROL, r"C:\data", vec![]);
        p.diagnostics
            .push(PermissionDiagnostic::GroupResolutionFailed {
                reason: "LDAP group query timed out".to_owned(),
            });
        let r = FullControlRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert!(
            r[0].incomplete,
            "GroupResolutionFailed -> finding must be flagged incomplete (review 2026-06-04 round 4 finding 1)"
        );
    }

    /// mark `incomplete` on `ShareEvalStatus::ReadFailed` so the
    /// confidence model is consistent across all risk rules.
    #[test]
    fn direct_user_ace_marks_finding_incomplete_on_share_read_failed() {
        let mut p = perm_ma(
            USER_SID,
            MASK_READ,
            r"C:\data",
            vec![],
            vec![],
            vec![ace_entry(USER_SID, AceKind::Allow, false)],
        );
        p.share_status = adpa_core::model::ShareEvalStatus::ReadFailed("access denied".to_owned());
        let r = DirectUserAceRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert!(
            r[0].incomplete,
            "ReadFailed -> finding must be flagged incomplete (review finding 4)"
        );
    }

    #[test]
    fn direct_user_ace_flagged_as_low() {
        let r = DirectUserAceRule.evaluate(&ctx(vec![perm_ma(
            USER_SID,
            MASK_READ,
            r"C:\data",
            vec![],
            vec![],
            vec![ace_entry(USER_SID, AceKind::Allow, false)],
        )]));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, RiskSeverity::Low);
        assert_eq!(r[0].rule_id, "DIRECT_USER_ACE");
    }

    #[test]
    fn group_ace_not_flagged_as_direct() {
        assert!(DirectUserAceRule
            .evaluate(&ctx(vec![perm_ma(
                USER_SID,
                MASK_READ,
                r"C:\data",
                vec![],
                vec![],
                vec![ace_entry("S-1-5-21-9999", AceKind::Allow, false)],
            )]))
            .is_empty());
    }

    #[test]
    fn direct_user_deny_ace_flagged() {
        let r = DirectUserAceRule.evaluate(&ctx(vec![perm_ma(
            USER_SID,
            MASK_READ,
            r"C:\data",
            vec![],
            vec![],
            vec![ace_entry(USER_SID, AceKind::Deny, false)],
        )]));
        assert_eq!(r.len(), 1, "direct explicit Deny ACE must be flagged");
    }

    #[test]
    fn inherited_user_ace_not_flagged_as_direct() {
        assert!(DirectUserAceRule
            .evaluate(&ctx(vec![perm_ma(
                USER_SID,
                MASK_READ,
                r"C:\data",
                vec![],
                vec![],
                vec![ace_entry(USER_SID, AceKind::Allow, true)],
            )]))
            .is_empty());
    }

    #[test]
    fn direct_user_ace_independent_of_explanation_text() {
        // Regression: the rule must not depend on the explanation text. Even with
        // empty/localized steps the structured ACE must suffice.
        let r = DirectUserAceRule.evaluate(&ctx(vec![perm_ma(
            USER_SID,
            MASK_READ,
            r"C:\data",
            vec!["Allow ACE [explicit] for someone else".to_string()],
            vec![],
            vec![ace_entry(USER_SID, AceKind::Allow, false)],
        )]));
        assert_eq!(r.len(), 1, "rule must rely on matched_aces, not on text");
    }

    #[test]
    fn no_matched_aces_means_no_direct_finding() {
        assert!(DirectUserAceRule
            .evaluate(&ctx(vec![perm(USER_SID, MASK_READ, r"C:\data", vec![])]))
            .is_empty());
    }

    /// Follow-up finding 2: `matched_aces` must no longer carry INHERIT_ONLY
    /// entries — the engine filters them out. This test documents the
    /// downstream consequence: an explicit user ACE that only applies to
    /// children has no effect on the current object and must not trigger a
    /// `DIRECT_USER_ACE` finding.
    #[test]
    fn inherit_only_explicit_user_ace_does_not_trigger_direct_user_finding() {
        // We simulate what the engine produces AFTER the fix: matched_aces
        // only contains ACEs that actually affect the object. The explicit
        // IO user ACE is therefore absent — only a group ACE that carries
        // the effective permission remains.
        let r = DirectUserAceRule.evaluate(&ctx(vec![perm_ma(
            USER_SID,
            MASK_READ,
            r"C:\data",
            vec![],
            vec![],
            // Only the effective group ACE remains in matched_aces.
            vec![ace_entry("S-1-5-21-9999", AceKind::Allow, false)],
        )]));
        assert!(
            r.is_empty(),
            "DirectUserAceRule must not fire when the only direct user ACE \
             was INHERIT_ONLY and therefore filtered out of matched_aces by \
             the engine"
        );
    }

    /// Review 2026-07-25 finding RK-2: when the analyzed identity is itself
    /// a group, a direct ACE on that group SID is exactly how AGDLP assigns
    /// permissions — not a finding. Before the kind guard, analyzing a group
    /// produced a false "best practice violated" report for the correct
    /// configuration.
    #[test]
    fn direct_ace_on_analyzed_group_identity_not_flagged() {
        let group_sid = "S-1-5-21-1000-1000-1000-2001";
        let mut p = perm_ma(
            group_sid,
            MASK_MODIFY,
            r"C:\data",
            vec![],
            vec![],
            vec![ace_entry(group_sid, AceKind::Allow, false)],
        );
        p.identity.kind = IdentityKind::Group;
        assert!(
            DirectUserAceRule.evaluate(&ctx(vec![p])).is_empty(),
            "a group's own direct ACE is best practice, not a finding"
        );
    }

    /// RK-2: computers are leaf principals like users — the best-practice
    /// rule applies to them unchanged.
    #[test]
    fn direct_ace_on_computer_identity_flagged() {
        let mut p = perm_ma(
            USER_SID,
            MASK_READ,
            r"C:\data",
            vec![],
            vec![],
            vec![ace_entry(USER_SID, AceKind::Allow, false)],
        );
        p.identity.kind = IdentityKind::Computer;
        let r = DirectUserAceRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].rule_id, "DIRECT_USER_ACE");
    }

    /// RK-2: for non-leaf kinds (well-known, FSP, orphaned, unknown) the
    /// rule cannot honestly claim "user has a direct ACE" — it stays silent.
    #[test]
    fn direct_ace_on_non_leaf_kinds_not_flagged() {
        for kind in [
            IdentityKind::WellKnown,
            IdentityKind::ForeignSecurityPrincipal,
            IdentityKind::Orphaned,
            IdentityKind::Unknown,
        ] {
            let mut p = perm_ma(
                USER_SID,
                MASK_READ,
                r"C:\data",
                vec![],
                vec![],
                vec![ace_entry(USER_SID, AceKind::Allow, false)],
            );
            p.identity.kind = kind.clone();
            assert!(
                DirectUserAceRule.evaluate(&ctx(vec![p])).is_empty(),
                "kind {kind:?} must not produce DIRECT_USER_ACE"
            );
        }
    }

    /// Review 2026-07-25 finding RK-6: a direct Deny ACE that removes ALL
    /// access (effective mask 0 — the typical "lock out this employee
    /// quickly" leftover) is still a direct ACE on the user. The old
    /// `effective_mask > 0` gate silently hid exactly this case.
    #[test]
    fn full_deny_direct_user_ace_still_flagged() {
        let r = DirectUserAceRule.evaluate(&ctx(vec![perm_ma(
            USER_SID,
            0,
            r"C:\data",
            vec![],
            vec![],
            vec![ace_entry(USER_SID, AceKind::Deny, false)],
        )]));
        assert_eq!(r.len(), 1, "full-deny direct ACE must remain visible");
        assert_eq!(r[0].rule_id, "DIRECT_USER_ACE");
        assert_eq!(r[0].severity, RiskSeverity::Low);
    }

    #[test]
    fn sensitive_path_flagged() {
        let r = SensitivePathRule.evaluate(&ctx(vec![perm(
            USER_SID,
            MASK_READ,
            r"C:\data\passwords\backup",
            vec![],
        )]));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].severity, RiskSeverity::Medium);
    }

    /// ChatGPT review 2026-05-31 finding 3: SensitivePathRule must mark
    /// the finding as `incomplete` when `ShareEvalStatus::ReadFailed`,
    /// because `effective_mask` is then only an NTFS lower bound.
    #[test]
    fn sensitive_path_marks_finding_incomplete_on_share_read_failed() {
        let mut p = perm(USER_SID, MASK_READ, r"C:\data\secrets\report", vec![]);
        p.share_status = adpa_core::model::ShareEvalStatus::ReadFailed("access denied".to_owned());
        let r = SensitivePathRule.evaluate(&ctx(vec![p]));
        assert_eq!(r.len(), 1);
        assert!(
            r[0].incomplete,
            "ReadFailed -> finding must be flagged incomplete (review finding 3)"
        );
    }

    /// Follow-up finding 3 (review 2026-05-25): SensitivePathRule must
    /// only fire when the identity actually has access. Effective mask
    /// 0 = no access → no finding. Previously the rule would fire on
    /// path name alone and report "has access" — a false positive.
    #[test]
    fn sensitive_path_with_zero_effective_mask_not_flagged() {
        let r = SensitivePathRule.evaluate(&ctx(vec![perm(
            USER_SID,
            0, // effective_mask = 0 — no access
            r"C:\data\passwords\backup",
            vec![],
        )]));
        assert!(
            r.is_empty(),
            "SensitivePathRule must not fire when effective_mask = 0 — \
             no access means no 'has access' risk"
        );
    }

    /// Regression: even with zero NTFS mask plus non-empty share mask
    /// (a theoretical edge case) the effective result governs.
    #[test]
    fn sensitive_path_uses_effective_not_ntfs_mask() {
        // perm() sets ntfs_mask = effective_mask = mask — we construct
        // a permission with different values directly here.
        let mut p = perm(USER_SID, MASK_FULL_CONTROL, r"C:\data\secrets", vec![]);
        p.effective_mask = AccessMask(0); // NTFS Full Control but Share/Combine = 0
        let r = SensitivePathRule.evaluate(&ctx(vec![p]));
        assert!(
            r.is_empty(),
            "What counts is the effective mask, not the raw NTFS mask"
        );
    }

    #[test]
    fn normal_path_not_sensitive() {
        assert!(SensitivePathRule
            .evaluate(&ctx(vec![perm(
                USER_SID,
                MASK_READ,
                r"C:\data\reports",
                vec![]
            )]))
            .is_empty());
    }

    #[test]
    fn registry_with_defaults_runs_all_rules() {
        let findings = vec![
            perm(USER_SID, MASK_FULL_CONTROL, r"C:\data", vec![]),
            perm(USER_SID, MASK_READ, r"C:\data\passwords", vec![]),
        ];
        let results = RuleRegistry::with_defaults().evaluate_all(&ctx(findings));
        assert!(results.iter().any(|f| f.rule_id == "FULL_CONTROL"));
        assert!(results.iter().any(|f| f.rule_id == "SENSITIVE_PATH"));
    }
}
