// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Formatted console output for the analyze command.

use adpa_core::model::{
    AceKind, EffectivePermission, FileSystemObject, GroupMembership, PermissionDiagnostic,
    RiskFinding, RiskSeverity,
};
use permission_engine::NormalizedRights;

const W: usize = 65;
const HEAVY: char = '═';
const LIGHT: char = '─';

fn heavy_line() -> String {
    HEAVY.to_string().repeat(W)
}

fn light_line() -> String {
    LIGHT.to_string().repeat(W)
}

fn header(title: &str) {
    println!("{}", heavy_line());
    println!("  {title}");
    println!("{}", heavy_line());
}

fn section(title: &str) {
    println!();
    println!("  {title}");
    println!("  {}", light_line().chars().take(W - 2).collect::<String>());
}

///
///
/// Returns the plain-text description of the DACL state for console display.
///
/// - `null_dacl == true` → unrestricted full access (NULL DACL)
/// - otherwise empty DACL → no access
/// - otherwise → `None`, the caller renders the individual ACEs.
pub(crate) fn dacl_state_label(null_dacl: bool, dacl_is_empty: bool) -> Option<&'static str> {
    if null_dacl {
        Some("(NULL DACL — unrestricted / Full Control for everyone)")
    } else if dacl_is_empty {
        Some("(empty DACL — no access)")
    } else {
        None
    }
}

pub fn print_report(
    fso: &FileSystemObject,
    user_input: &str,
    result: &EffectivePermission,
    memberships: &[GroupMembership],
    ad_connected: bool,
) {
    println!();
    header("AD Permission Analyzer  \u{00B7}  Effective Rights Report");

    section("Identity");
    println!("  Path      : {}", fso.path.0);
    let user_name = result.identity.name.as_deref().unwrap_or(user_input);
    let domain_prefix = result
        .identity
        .domain
        .as_ref()
        .map(|d| format!("{d}\\"))
        .unwrap_or_default();
    println!("  User      : {domain_prefix}{user_name}");
    println!("            : ({})", result.identity.sid.0);
    let status = if result.identity.disabled {
        "DISABLED"
    } else {
        "Active"
    };
    let kind = format!("{:?}", result.identity.kind);
    println!("  Status    : {status}  ·  Kind: {kind}");

    if !ad_connected {
        println!();
        println!("  [!] No AD connection — group memberships not resolved.");
        println!("      Results may be incomplete.");
    }

    if !memberships.is_empty() {
        section(&format!("Resolved Groups ({})", memberships.len()));
        for gm in memberships {
            let via = if gm.direct {
                "direct    "
            } else {
                "transitive"
            };
            println!("  [{}]  {}", via, gm.group_sid.0);
        }
    }

    // --- DACL ---
    section(&format!("DACL  —  {}", fso.path.0));
    let owner = fso
        .owner_sid
        .as_ref()
        .map(|s| s.0.as_str())
        .unwrap_or("(unknown)");
    let inherit = if fso.inheritance_disabled {
        "Protected (inheritance disabled)"
    } else {
        "Active (inheriting from parent)"
    };
    println!("  Owner       : {owner}");
    println!("  Inheritance : {inherit}");

    // Show all ACEs
    //
    // Important: NULL DACL ≠ empty DACL. NULL DACL means "no access control"
    // (full access for everyone), an empty DACL means "no access for anyone".
    if let Some(label) = dacl_state_label(fso.null_dacl, fso.dacl.is_empty()) {
        println!("  {label}");
    } else {
        println!();
        println!("  {:5}  {:8}  {:10}  SID", "Kind", "Scope", "Rights");
        println!("  {}", light_line().chars().take(W - 2).collect::<String>());
        for ace in &fso.dacl {
            let kind = match ace.kind {
                AceKind::Allow => "Allow",
                AceKind::Deny => "DENY ",
            };
            let scope = if ace.inherited {
                "inherited"
            } else {
                "explicit "
            };
            let rights = NormalizedRights::new(ace.mask.0);
            println!(
                "  {}  {}  {:13}  {}",
                kind,
                scope,
                rights.display_name(),
                ace.sid.0
            );
        }
    }

    // Diagnostic: ACE types the parser could not evaluate. Their presence means
    // the DACL evaluation is potentially incomplete.
    if !fso.unsupported_aces.is_empty() {
        section("Unsupported ACEs (diagnostic — not evaluated)");
        println!(
            "  [!] {} ACE(s) on this path could not be interpreted.",
            fso.unsupported_aces.len()
        );
        println!("      Effective rights below may be incomplete.");
        println!();
        println!("  {:9}  {:7}  Mask", "AceType", "Flags");
        println!("  {}", light_line().chars().take(W - 2).collect::<String>());
        for u in &fso.unsupported_aces {
            println!(
                "  {:<9}  0x{:02X}     0x{:08X}",
                u.ace_type, u.flags, u.mask
            );
        }
    }

    // --- Strukturierte Diagnose-Marker (ADR 0021 + 0024) ---
    //
    // Structured diagnostic markers (ADR 0021 + 0024). Previously these
    // were only visible in JSON/CSV/HTML/GUI; the CLI output omitted them.
    // To give a CLI auditor the same information as the export formats we
    // list the diagnostics variants here.
    if !result.diagnostics.is_empty() {
        section("Diagnostics (structured)");
        for d in &result.diagnostics {
            match d {
                PermissionDiagnostic::NonCanonicalDaclOrder { at_index } => {
                    println!("  [i] Non-canonical DACL ordering at ACE index {at_index}.");
                    println!("      Windows AccessCheck walks in stored order — the result is");
                    println!("      exact but may differ from canonicalized expectations.");
                }
                PermissionDiagnostic::UnsupportedShareAces { count } => {
                    println!("  [!] {count} share ACE(s) of unsupported type were skipped.");
                    println!("      Share mask is potentially incomplete; risk findings are");
                    println!("      flagged 'incomplete' for this path.");
                }
                PermissionDiagnostic::UnsupportedNtfsAces { count } => {
                    println!(
                        "  [!] {count} NTFS ACE(s) could not be evaluated (object / callback /"
                    );
                    println!("      conditional / vendor-specific). The displayed effective");
                    println!(
                        "      permission is a LOWER-CONFIDENCE APPROXIMATION — a hidden Deny"
                    );
                    println!("      among them could change the result. Risk findings are flagged");
                    println!("      'incomplete' for this path.");
                }
                PermissionDiagnostic::DomainGroupRecursionIncomplete => {
                    println!("  [!] Group resolution ran through the SAM/LSA fallback (no LDAP).");
                    println!("      NetUserGetGroups returns only direct global groups — nested");
                    println!("      domain groups are not recursively resolved. ACEs targeting");
                    println!("      deeply nested groups may be missed.");
                }
                PermissionDiagnostic::IdentityDisabled => {
                    println!("  [i] Identity is flagged as disabled in AD (ACCOUNTDISABLE).");
                    println!("      Computed rights are ACL-theoretically correct, but the");
                    println!("      account normally cannot authenticate / access SMB.");
                }
                PermissionDiagnostic::IdentityNotInConfiguredLdapBase => {
                    println!("  [!] Identity was resolved via Windows LSA but the configured");
                    println!("      LDAP base DN does not index that SID (typical for multi-");
                    println!("      domain forests or trusted domains). Domain group recursion");
                    println!("      ran only through the user's home domain — nested cross-");
                    println!("      domain memberships may be missing. Treat as incomplete.");
                }
                PermissionDiagnostic::IdentityDisabledStatusUnknown => {
                    println!("  [i] The 'disabled' flag for this identity could not be");
                    println!("      determined (SAM/LSA fallback without NetUserGetInfo, or");
                    println!("      LDAP did not return the user object). Computed rights are");
                    println!("      ACL-theoretically correct, but whether the account is");
                    println!("      enabled is unknown.");
                }
                PermissionDiagnostic::IdentityLookupFailed { reason } => {
                    println!("  [!] LDAP identity lookup failed: {reason}.");
                    println!("      The analysis ran with a placeholder identity and an empty");
                    println!("      token; ACEs targeting domain groups may be missing. Treat");
                    println!("      as incomplete.");
                }
                PermissionDiagnostic::GroupResolutionFailed { reason } => {
                    println!("  [!] Recursive group resolution failed or was skipped: {reason}.");
                    println!("      ACEs on domain groups may be missing from the computed");
                    println!("      effective right. Treat as incomplete.");
                }
                PermissionDiagnostic::OwnerRightsAceApplied => {
                    println!("  [i] OWNER RIGHTS (S-1-3-4) ACE present and the identity is the");
                    println!("      object's owner. That DACL entry governs the owner's rights;");
                    println!("      the implicit READ_CONTROL + WRITE_DAC owner grant was");
                    println!("      suppressed. The evaluation is exact — informational only.");
                }
                PermissionDiagnostic::IdentityResolvedViaForeignSecurityPrincipal => {
                    println!("  [!] Identity is a trust-forest principal found as a Foreign");
                    println!("      Security Principal object in the home domain. Home-domain");
                    println!("      groups were resolved through the FSP — but the principal's");
                    println!("      memberships in its own forest are unknown. Treat as");
                    println!("      incomplete.");
                }
                PermissionDiagnostic::GroupResolutionViaGlobalCatalog => {
                    println!("  [!] Group memberships were resolved through a Global Catalog");
                    println!("      bind. Only universal group memberships replicate fully to");
                    println!("      the GC — global and domain-local memberships of foreign");
                    println!("      domains can be missing. Treat as incomplete.");
                }
                PermissionDiagnostic::PersistedEvidenceDecodeFailed { detail } => {
                    println!("  [!] A persisted (historical) row could not be fully decoded:");
                    println!("      {detail}.");
                    println!("      The reconstructed result may be less complete than it was");
                    println!("      originally stored. Treat as incomplete.");
                }
                PermissionDiagnostic::SidHistoryPresent { count } => {
                    println!("  [!] This identity carries {count} historical SID(s) (sIDHistory).");
                    println!("      ACEs that reference a historical SID are not evaluated, but");
                    println!("      the real logon token still includes it — effective rights");
                    println!("      may be understated. Treat as incomplete.");
                }
                PermissionDiagnostic::TrustBoundaryEffectsNotModeled => {
                    println!("  [i] Identity resolved across a domain / trust boundary (foreign");
                    println!("      security principal, or outside the configured LDAP base).");
                    println!("      If that boundary is a forest trust, SID filtering /");
                    println!("      quarantine and Selective Authentication may reduce actual");
                    println!("      access — these runtime trust effects are not modeled.");
                }
            }
        }
    }

    // --- Zutreffende ACEs / matching ACEs ---
    // Taken from the engine instead of rebuilding via build_token_sids —
    // otherwise local server group SIDs (which only the engine adds to the
    // token) would be missing here and a local-group ACE would be invisible
    // even though it contributed to the result.
    section("Matching ACEs (for this identity)");
    if result.matched_aces.is_empty() {
        println!("  (none)");
    } else {
        for ace in &result.matched_aces {
            let kind = match ace.kind {
                AceKind::Allow => "Allow",
                AceKind::Deny => "DENY ",
            };
            let scope = if ace.inherited {
                "[inherited]"
            } else {
                "[explicit] "
            };
            let rights = NormalizedRights::new(ace.mask.0);
            println!(
                "  {} {}  {}  \u{2192}  {} (0x{:08X})",
                kind,
                scope,
                ace.sid.0,
                rights.display_name(),
                ace.mask.0
            );
        }
    }

    section("Effective Rights");
    let ntfs = NormalizedRights::new(result.ntfs_mask.0);
    let eff = NormalizedRights::new(result.effective_mask.0);

    println!("  NTFS    : {}", ntfs);
    match result.share_mask {
        Some(s) => println!("  Share   : {}", NormalizedRights::new(s.0)),
        None => println!("  Share   : (not specified)"),
    }
    println!("  Result  : {}", eff);

    section("Explanation Path");
    for (i, step) in result.path_explanation.steps.iter().enumerate() {
        println!("  {}. {step}", i + 1);
    }

    println!();
    println!("{}", heavy_line());
    println!();
}

/// Short name of a risk severity for console output.
fn severity_label(sev: &RiskSeverity) -> &'static str {
    match sev {
        RiskSeverity::Critical => "CRITICAL",
        RiskSeverity::High => "HIGH",
        RiskSeverity::Medium => "MEDIUM",
        RiskSeverity::Low => "LOW",
        RiskSeverity::Info => "INFO",
    }
}

/// Prints the risk findings of a run to the console in a formatted block.
pub fn print_risk_findings(findings: &[RiskFinding]) {
    section(&format!("Risk Findings ({})", findings.len()));
    if findings.is_empty() {
        println!("  (none)");
        return;
    }
    for f in findings {
        let path = f
            .affected_path
            .as_ref()
            .map(|p| p.0.as_str())
            .unwrap_or("(no path)");
        // Treat 'critical from incomplete computation' like a confirmed finding.
        // Incomplete findings must be flagged — otherwise a Critical derived
        // from an incomplete computation looks like a confirmed finding.
        let incomplete_marker = if f.incomplete { "  [INCOMPLETE]" } else { "" };
        println!(
            "  [{:8}]  {:20}  {}{incomplete_marker}",
            severity_label(&f.severity),
            f.rule_id,
            f.description
        );
        println!("              {path}");
    }
}

#[cfg(test)]
mod tests {
    use super::dacl_state_label;

    #[test]
    fn null_dacl_is_full_control() {
        // null_dacl means full access, even when the DACL list is incidentally empty.
        assert_eq!(
            dacl_state_label(true, true),
            Some("(NULL DACL — unrestricted / Full Control for everyone)")
        );
        assert_eq!(
            dacl_state_label(true, false),
            Some("(NULL DACL — unrestricted / Full Control for everyone)")
        );
    }

    #[test]
    fn empty_dacl_is_deny_all_only_without_null() {
        // An empty DACL means deny-all only when the NULL DACL marker is not set.
        assert_eq!(
            dacl_state_label(false, true),
            Some("(empty DACL — no access)")
        );
    }

    #[test]
    fn populated_dacl_returns_none() {
        // ACE list present → caller renders the ACEs itself.
        assert_eq!(dacl_state_label(false, false), None);
    }
}
