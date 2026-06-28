// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! HTML report export — single self-contained file with embedded CSS.

use std::fmt::Write as FmtWrite;
use std::io::Write;

use adpa_core::{
    error::CoreError,
    model::{
        AceKind, EffectivePermission, LocalGroupEvalStatus, PathTrusteeEntry, PathTrustees,
        PermissionDiagnostic, RiskFinding, RiskSeverity, ShareEvalStatus, TrusteeCategory,
    },
    traits::{AnalysisResult, ExportTarget, Exporter},
};
use permission_engine::NormalizedRights;

pub struct HtmlExporter;

impl Exporter for HtmlExporter {
    fn export(&self, result: &AnalysisResult, target: ExportTarget) -> Result<(), CoreError> {
        let html = render_html(result)?;
        let mut f = crate::open_export_file(target)?;
        f.write_all(html.as_bytes())
            .map_err(|e| CoreError::Export(format!("Write failed: {e}")))?;
        Ok(())
    }
}

/// Renders the complete HTML report as a string.
pub fn render_html(result: &AnalysisResult) -> Result<String, CoreError> {
    let mut s = String::with_capacity(64 * 1024);

    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC");
    let total = result.permissions.len();
    let risk_count = result.risk_findings.len();
    let critical = result
        .risk_findings
        .iter()
        .filter(|f| f.severity == RiskSeverity::Critical)
        .count();
    let high = result
        .risk_findings
        .iter()
        .filter(|f| f.severity == RiskSeverity::High)
        .count();
    let medium = result
        .risk_findings
        .iter()
        .filter(|f| f.severity == RiskSeverity::Medium)
        .count();
    let diagnostics_count = result
        .permissions
        .iter()
        .filter(|p| has_diagnostics(p))
        .count();

    write_html_head(&mut s, now.to_string().as_str());
    write_summary(
        &mut s,
        total,
        risk_count,
        critical,
        high,
        medium,
        diagnostics_count,
    );
    write_risk_table(&mut s, &result.risk_findings)?;
    write_permissions_table(&mut s, &result.permissions)?;
    if !result.path_trustees.is_empty() {
        write_trustees_table(&mut s, &result.path_trustees)?;
    }
    write_html_foot(&mut s);

    Ok(s)
}

fn write_html_head(s: &mut String, timestamp: &str) {
    s.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Stars — AD Permission Analyzer Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,Helvetica,sans-serif;font-size:14px;background:#1a1a2e;color:#e0e0e0;padding:20px}
h1{font-size:22px;font-weight:600;color:#ffa726;margin-bottom:4px}
h2{font-size:16px;font-weight:600;color:#ffcc80;margin:20px 0 8px}
.subtitle{color:#888;font-size:12px;margin-bottom:20px}
.summary{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.card{background:#0d1b2a;border:1px solid #263248;border-radius:6px;padding:12px 18px;min-width:120px;text-align:center}
.card .num{font-size:28px;font-weight:700;line-height:1}
.card .lbl{font-size:11px;color:#888;margin-top:4px}
.critical .num{color:#F05252}
.high .num{color:#FB7335}
.medium .num{color:#F5A623}
.low .num{color:#34C759}
.info-card .num{color:#4DA3FF}
table{width:100%;border-collapse:collapse;background:#0d1b2a;border-radius:6px;overflow:hidden;margin-bottom:20px}
th{background:#263248;padding:8px 10px;text-align:left;font-size:12px;color:#ffcc80;font-weight:600}
td{padding:7px 10px;border-bottom:1px solid #1a2840;font-size:12px;vertical-align:top;word-break:break-word}
tr:last-child td{border-bottom:none}
tr:hover td{background:#111d2e}
.badge{display:inline-block;padding:2px 7px;border-radius:10px;font-size:11px;font-weight:600}
.badge-critical{background:#DC2626;color:#fff}
.badge-high{background:#EA580C;color:#fff}
.badge-medium{background:#D97706;color:#fff}
.badge-low{background:#16A34A;color:#fff}
.badge-neutral{background:#475569;color:#fff}
.badge-correct{background:#0067C0;color:#fff}
.badge-fc{background:#DC2626;color:#fff}
.badge-modify{background:#EA580C;color:#fff}
.badge-read{background:#16A34A;color:#fff}
.badge-write{background:#D97706;color:#fff}
.badge-special{background:#37474F;color:#fff}
.badge-none{background:#212121;color:#888}
.path{font-family:'Cascadia Code','Consolas',monospace;font-size:11px;color:#80cbc4}
.sid{font-family:monospace;font-size:11px;color:#b0bec5}
details summary{cursor:pointer;color:#64b5f6;font-size:11px}
details[open] summary{margin-bottom:4px}
.step{padding:2px 0;color:#cfd8dc;font-size:11px}
</style>
</head>
<body>
<h1>Stars — AD Permission Analyzer</h1>
"#);
    let _ = writeln!(s, "<p class=\"subtitle\">Report generated: {timestamp}</p>");
}

fn write_summary(
    s: &mut String,
    total: usize,
    risk_count: usize,
    critical: usize,
    high: usize,
    medium: usize,
    diagnostics: usize,
) {
    s.push_str("<h2>Summary</h2>\n<div class=\"summary\">\n");
    card(s, total, "Paths analyzed", "info-card");
    card(s, risk_count, "Risk findings", "high");
    card(s, critical, "Critical", "critical");
    card(s, high, "High", "high");
    card(s, medium, "Medium", "medium");
    //
    // Diagnostics card: number of paths with at least one incompleteness
    // marker (parser gap, unreadable share DACL, missing local groups,
    // non-canonical DACL, unsupported share ACEs). An audit reader can
    // immediately see whether findings rest on solid evaluation data.
    card(s, diagnostics, "Diagnostics", "medium");
    s.push_str("</div>\n");
}

/// True if the entry carries at least one incompleteness source.
fn has_diagnostics(p: &EffectivePermission) -> bool {
    p.unsupported_ace_count > 0
        || matches!(p.share_status, ShareEvalStatus::ReadFailed(_))
        || matches!(p.local_group_status, LocalGroupEvalStatus::NotAvailable(_))
        || !p.diagnostics.is_empty()
}

fn card(s: &mut String, n: usize, label: &str, class: &str) {
    let _ = writeln!(s, "<div class=\"card {class}\"><div class=\"num\">{n}</div><div class=\"lbl\">{label}</div></div>");
}

fn write_risk_table(s: &mut String, findings: &[RiskFinding]) -> Result<(), CoreError> {
    if findings.is_empty() {
        s.push_str("<h2>Risk Findings</h2>\n<p style=\"color:#66bb6a\">✓ No risk findings.</p>\n");
        return Ok(());
    }
    s.push_str("<h2>Risk Findings</h2>\n");
    s.push_str("<table><thead><tr><th>Severity</th><th>Rule</th><th>Description</th><th>Path</th><th>Confidence</th></tr></thead><tbody>\n");
    for f in findings {
        let badge = severity_badge(&f.severity);
        let path = f
            .affected_path
            .as_ref()
            .map(|p| p.0.as_str())
            .unwrap_or("—");
        // Incomplete findings must be visibly flagged — otherwise gaps in the
        // underlying evaluation go unnoticed in the report.
        let confidence = if f.incomplete {
            "<span class=\"badge badge-medium\" title=\"Underlying evaluation was incomplete — interpret cautiously\">⚠ incomplete</span>"
        } else {
            "<span class=\"badge badge-correct\">confirmed</span>"
        };
        writeln!(s,
            "<tr><td>{badge}</td><td><code>{}</code></td><td>{}</td><td class=\"path\">{}</td><td>{confidence}</td></tr>",
            escape_html(&f.rule_id), escape_html(&f.description), escape_html(path)
        ).map_err(|e| CoreError::Export(e.to_string()))?;
    }
    s.push_str("</tbody></table>\n");
    Ok(())
}

fn write_permissions_table(
    s: &mut String,
    permissions: &[adpa_core::model::EffectivePermission],
) -> Result<(), CoreError> {
    s.push_str("<h2>Effective Permissions</h2>\n");
    s.push_str("<table><thead><tr><th>Path</th><th>User</th><th>Effective</th><th>NTFS</th><th>Share</th><th>Diagnostics</th><th>Explanation</th></tr></thead><tbody>\n");
    for p in permissions {
        let eff = NormalizedRights::new(p.effective_mask.0);
        let ntfs = NormalizedRights::new(p.ntfs_mask.0);
        let share = p.share_mask.map(|m| NormalizedRights::new(m.0));
        let name = p.identity.name.as_deref().unwrap_or(&p.identity.sid.0);

        let steps_html: String = p
            .path_explanation
            .steps
            .iter()
            .map(|s| format!("<div class=\"step\">• {}</div>", escape_html(s)))
            .collect();

        // The diagnostics column unifies four incompleteness sources:
        //   1. Parser gap: unevaluated ACE types.
        //   2. Share DACL unreadable (ReadFailed).
        //   3. Local-group resolution failed (NotAvailable) — token may be
        //      incomplete, ACEs targeting local server groups missed.
        //   4. Structured diagnostic markers (follow-up finding 3) — today
        //      `NonCanonicalDaclOrder`. Marks DACLs Windows evaluates in
        //      stored order, which may differ from canonicalized expectations.
        let mut diag_parts: Vec<String> = Vec::new();
        if p.unsupported_ace_count > 0 {
            diag_parts.push(format!(
                "<span class=\"badge badge-medium\" title=\"DACL evaluation may be incomplete\">⚠ {} unsupported ACE(s)</span>",
                p.unsupported_ace_count
            ));
        }
        if let ShareEvalStatus::ReadFailed(reason) = &p.share_status {
            diag_parts.push(format!(
                "<span class=\"badge badge-high\" title=\"{}\">⚠ share DACL unreadable</span>",
                escape_html(reason)
            ));
        }
        if let LocalGroupEvalStatus::NotAvailable(reason) = &p.local_group_status {
            diag_parts.push(format!(
                "<span class=\"badge badge-neutral\" title=\"{}\">ℹ local groups unavailable</span>",
                escape_html(reason)
            ));
        }
        for d in &p.diagnostics {
            match d {
                PermissionDiagnostic::NonCanonicalDaclOrder { at_index } => {
                    diag_parts.push(format!(
                        "<span class=\"badge badge-neutral\" \
                         title=\"DACL is not in Windows-canonical order (first \
                         violating ACE at index {at_index}). Windows AccessCheck \
                         walks in stored order — the result is exact but may \
                         differ from canonicalized expectations.\">ℹ non-canonical DACL</span>"
                    ));
                }
                PermissionDiagnostic::UnsupportedShareAces { count } => {
                    diag_parts.push(format!(
                        "<span class=\"badge badge-medium\" \
                         title=\"The share DACL contained {count} ACE type(s) \
                         the parser could not interpret (object/callback/\
                         conditional or vendor-specific). The share mask is \
                         potentially incomplete.\">⚠ {count} unsupported share ACE(s)</span>"
                    ));
                }
                PermissionDiagnostic::UnsupportedNtfsAces { count } => {
                    diag_parts.push(format!(
                        "<span class=\"badge badge-medium\" \
                         title=\"The NTFS DACL contained {count} ACE type(s) \
                         the parser could not interpret (object/callback/\
                         conditional/Dynamic Access Control or vendor-specific). \
                         The displayed effective permission is a lower-confidence \
                         approximation — a hidden Deny among them could change \
                         the result.\">⚠ {count} unsupported NTFS ACE(s) — approximate result</span>"
                    ));
                }
                PermissionDiagnostic::DomainGroupRecursionIncomplete => {
                    diag_parts.push(
                        "<span class=\"badge badge-neutral\" \
                         title=\"Group resolution ran through the SAM/LSA \
                         fallback (no LDAP). NetUserGetGroups returns only \
                         direct global groups — nested domain groups are not \
                         recursively resolved. ACEs targeting deeply nested \
                         groups may be missed; treat the finding as \
                         incomplete.\">ℹ SAM fallback — nested groups not resolved</span>"
                            .to_string(),
                    );
                }
                PermissionDiagnostic::IdentityDisabled => {
                    diag_parts.push(
                        "<span class=\"badge badge-neutral\" \
                         title=\"The identity is flagged as disabled in AD \
                         (userAccountControl ACCOUNTDISABLE). Computed \
                         rights are ACL-theoretically correct, but the \
                         account normally cannot authenticate / access \
                         SMB.\">ℹ disabled account</span>"
                            .to_string(),
                    );
                }
                PermissionDiagnostic::IdentityNotInConfiguredLdapBase => {
                    diag_parts.push(
                        "<span class=\"badge badge-neutral\" \
                         title=\"The user was resolved via Windows LSA but \
                         the configured LDAP base DN does not index that \
                         SID (typical for multi-domain forests or trusted \
                         domains). Domain group recursion ran only through \
                         the user's home domain — nested cross-domain \
                         memberships may be missing. Treat the finding as \
                         incomplete.\">ℹ identity outside configured LDAP base</span>"
                            .to_string(),
                    );
                }
                PermissionDiagnostic::IdentityDisabledStatusUnknown => {
                    diag_parts.push(
                        "<span class=\"badge badge-neutral\" \
                         title=\"The 'disabled' flag for this identity \
                         could not be determined (e.g. SAM/LSA fallback \
                         without NetUserGetInfo, or LDAP did not return \
                         the user object). Computed rights are \
                         ACL-theoretically correct, but whether the \
                         account is enabled is unknown.\">ℹ disabled status unknown</span>"
                            .to_string(),
                    );
                }
                PermissionDiagnostic::IdentityLookupFailed { reason } => {
                    diag_parts.push(format!(
                        "<span class=\"badge badge-high\" \
                         title=\"LDAP identity lookup failed: {}. \
                         The analysis ran with a placeholder identity \
                         and an empty token; ACEs targeting domain \
                         groups may be missing. Treat as incomplete.\">\
                         ⚠ identity lookup failed</span>",
                        escape_html(reason)
                    ));
                }
                PermissionDiagnostic::GroupResolutionFailed { reason } => {
                    diag_parts.push(format!(
                        "<span class=\"badge badge-high\" \
                         title=\"Recursive group resolution failed or \
                         was skipped: {}. ACEs on domain groups may be \
                         missing from the computed effective right. \
                         Treat as incomplete.\">⚠ group resolution failed</span>",
                        escape_html(reason)
                    ));
                }
                PermissionDiagnostic::OwnerRightsAceApplied => {
                    diag_parts.push(
                        "<span class=\"badge badge-neutral\" \
                         title=\"The DACL contains an OWNER RIGHTS \
                         (S-1-3-4) entry and the analyzed identity is \
                         the object's owner. Per Windows semantics that \
                         entry governs the owner's rights — the implicit \
                         READ_CONTROL + WRITE_DAC owner grant was \
                         suppressed. The evaluation is exact; this is \
                         informational.\">ℹ OWNER RIGHTS ACE applied</span>"
                            .to_string(),
                    );
                }
                PermissionDiagnostic::IdentityResolvedViaForeignSecurityPrincipal => {
                    diag_parts.push(
                        "<span class=\"badge badge-neutral\" \
                         title=\"The identity is a principal from a \
                         trusted forest, found as a Foreign Security \
                         Principal object in the home domain. \
                         Home-domain group memberships were resolved \
                         through the FSP — but the principal's \
                         memberships in its own forest are unknown. \
                         Treat the finding as incomplete.\">ℹ resolved via FSP — trust-side groups unknown</span>"
                            .to_string(),
                    );
                }
                PermissionDiagnostic::GroupResolutionViaGlobalCatalog => {
                    diag_parts.push(
                        "<span class=\"badge badge-neutral\"                          title=\"Group memberships were resolved through                          a Global Catalog bind. Only universal group                          memberships replicate fully to the GC — global                          and domain-local memberships of foreign domains                          can be missing. Treat the finding as                          incomplete.\">ℹ groups via Global Catalog — may be partial</span>"
                            .to_string(),
                    );
                }
                PermissionDiagnostic::PersistedEvidenceDecodeFailed { detail } => {
                    diag_parts.push(format!(
                        "<span class=\"badge badge-high\" \
                         title=\"This historical row could not be fully decoded \
                         from the database: {}. The reconstructed result may be \
                         less complete than originally stored — treat as \
                         incomplete.\">⚠ persisted evidence decode failed</span>",
                        escape_html(detail)
                    ));
                }
                PermissionDiagnostic::SidHistoryPresent { count } => {
                    // High: an understated right is the "looks safe, isn't safe"
                    // case — the most dangerous to miss.
                    diag_parts.push(format!(
                        "<span class=\"badge badge-high\" \
                         title=\"This identity carries {count} historical SID(s) \
                         (sIDHistory). ACEs referencing a historical SID are not \
                         evaluated, but the real logon token includes it — \
                         effective rights may be understated. Treat as \
                         incomplete.\">⚠ {count} historical SID(s) not evaluated</span>"
                    ));
                }
                PermissionDiagnostic::TrustBoundaryEffectsNotModeled => {
                    diag_parts.push(
                        "<span class=\"badge badge-neutral\" \
                         title=\"The identity was resolved across a domain / trust \
                         boundary (foreign security principal, or outside the \
                         configured LDAP base). If that boundary is a forest trust, \
                         SID filtering / quarantine and Selective Authentication may \
                         reduce actual access — these runtime trust effects are not \
                         modeled, so the shown access can be too high for a \
                         cross-forest identity.\">ℹ trust-boundary effects not modeled</span>"
                            .to_string(),
                    );
                }
            }
        }
        let diagnostics = if diag_parts.is_empty() {
            "—".to_string()
        } else {
            diag_parts.join(" ")
        };

        writeln!(s,
            "<tr><td class=\"path\">{}</td><td><span title=\"{}\">{}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{diagnostics}</td><td><details><summary>show</summary>{steps_html}</details></td></tr>",
            escape_html(&p.path.0),
            escape_html(&p.identity.sid.0),
            escape_html(name),
            rights_badge(eff),
            rights_badge(ntfs),
            share.map(rights_badge).unwrap_or_else(|| "—".to_string()),
        ).map_err(|e| CoreError::Export(e.to_string()))?;
    }
    s.push_str("</tbody></table>\n");
    Ok(())
}

fn write_html_foot(s: &mut String) {
    s.push_str("<p style=\"color:#555;font-size:11px;margin-top:20px\">Generated by Stars — AD Permission Analyzer</p>\n</body>\n</html>\n");
}

/// Renders the path-centric trustee table per path — answers the second
/// audit question "who can access this path at all?".
fn write_trustees_table(s: &mut String, entries: &[PathTrustees]) -> Result<(), CoreError> {
    s.push_str("<h2>Who has access (trustees per path)</h2>\n");
    for entry in entries {
        if entry.trustees.is_empty() {
            continue;
        }
        writeln!(
            s,
            "<details><summary><strong>{}</strong> &nbsp;<span style=\"color:#6c7a89\">({} entries)</span></summary>",
            escape_html(&entry.path.0),
            entry.trustees.len()
        )
        .map_err(|e| CoreError::Export(e.to_string()))?;
        s.push_str("<table><thead><tr><th>Trustee</th><th>Kind</th><th>Rights</th><th>Mask</th><th>Source</th><th>Applies to</th><th>Layer</th></tr></thead><tbody>\n");
        for entry_ref in &entry.trustees {
            // Round-10 finding 4: two render paths — diagnostic rows are
            // visually different (yellowish background, italic, no
            // Allow/Deny label) so auditors immediately see this is not
            // an ACE but a hint.
            match entry_ref {
                PathTrusteeEntry::Diagnostic { category, message } => {
                    let category_label = match category {
                        TrusteeCategory::Ntfs => "NTFS",
                        TrusteeCategory::Share => "Share",
                    };
                    writeln!(
                        s,
                        "<tr style=\"background-color:#fff7d6\"><td colspan=\"6\"><em>&#9888; Diagnostic: {}</em></td><td>{}</td></tr>",
                        escape_html(message),
                        category_label,
                    )
                    .map_err(|e| CoreError::Export(e.to_string()))?;
                }
                PathTrusteeEntry::Ace(t) => {
                    let expanded = permission_engine::mask::expand_generic_rights(t.mask.0);
                    let rights = NormalizedRights::new(expanded);
                    let display = t.display_name.clone().unwrap_or_else(|| t.sid.0.clone());
                    let kind = match t.kind {
                        AceKind::Allow => {
                            "<span style=\"color:#278d4f;font-weight:700\">Allow</span>"
                        }
                        AceKind::Deny => {
                            "<span style=\"color:#c0392b;font-weight:700\">Deny</span>"
                        }
                    };
                    let source = if t.inherited { "inherited" } else { "explicit" };
                    let category = match t.category {
                        TrusteeCategory::Ntfs => "NTFS",
                        TrusteeCategory::Share => "Share",
                    };
                    let applies = if matches!(t.category, TrusteeCategory::Share) {
                        "Share".to_owned()
                    } else {
                        applies_to_label(t.inheritance_flags, t.propagation_flags)
                    };
                    writeln!(
                        s,
                        "<tr><td><span title=\"{}\">{}</span></td><td>{kind}</td><td>{}</td><td><code>0x{:08X}</code></td><td>{source}</td><td>{}</td><td>{category}</td></tr>",
                        escape_html(&t.sid.0),
                        escape_html(&display),
                        rights_badge(rights),
                        t.mask.0,
                        escape_html(&applies),
                    )
                    .map_err(|e| CoreError::Export(e.to_string()))?;
                }
            }
        }
        s.push_str("</tbody></table>\n</details>\n");
    }
    Ok(())
}

/// Windows-style "Applies to" label from the inheritance / propagation flags.
/// Mirrors the GUI logic (see `gui/src/worker.rs::applies_to_label`).
fn applies_to_label(inheritance_flags: u32, propagation_flags: u32) -> String {
    const OBJECT_INHERIT: u32 = 0x01;
    const CONTAINER_INHERIT: u32 = 0x02;
    const NO_PROPAGATE: u32 = 0x04;
    const INHERIT_ONLY: u32 = 0x08;
    let flags = inheritance_flags | propagation_flags;
    let container = flags & CONTAINER_INHERIT != 0;
    let object = flags & OBJECT_INHERIT != 0;
    let inherit_only = flags & INHERIT_ONLY != 0;
    let no_propagate = flags & NO_PROPAGATE != 0;
    let base = match (container, object, inherit_only) {
        (true, true, true) => "Subfolders and files only",
        (true, true, false) => "This folder, subfolders and files",
        (true, false, true) => "Subfolders only",
        (true, false, false) => "This folder and subfolders",
        (false, true, true) => "Files only",
        (false, true, false) => "This folder and files",
        (false, false, _) => "This folder only",
    };
    if no_propagate {
        format!("{base} (no propagation)")
    } else {
        base.to_owned()
    }
}

fn severity_badge(sev: &RiskSeverity) -> String {
    let (cls, label) = match sev {
        RiskSeverity::Critical => ("badge-critical", "CRITICAL"),
        RiskSeverity::High => ("badge-high", "HIGH"),
        RiskSeverity::Medium => ("badge-medium", "MEDIUM"),
        RiskSeverity::Low => ("badge-low", "LOW"),
        RiskSeverity::Info => ("badge-neutral", "INFO"),
    };
    format!("<span class=\"badge {cls}\">{label}</span>")
}

fn rights_badge(r: NormalizedRights) -> String {
    let (cls, label) = if r.is_full_control() {
        ("badge-fc", "Full Control")
    } else if r.is_modify() {
        ("badge-modify", "Modify")
    } else if r.is_read() && r.is_write() {
        ("badge-write", "Read+Write")
    } else if r.is_read() {
        ("badge-read", "Read")
    } else if r.is_write() {
        ("badge-write", "Write")
    } else if r.raw() == 0 {
        ("badge-none", "None")
    } else {
        ("badge-special", "Special")
    };
    format!("<span class=\"badge {cls}\">{label}</span>")
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::{write_permissions_table, write_risk_table};
    use adpa_core::model::{
        AccessMask, EffectivePermission, Identity, IdentityKind, LocalGroupEvalStatus,
        NormalizedPath, PermissionDiagnostic, PermissionPath, RiskFinding, RiskSeverity,
        ShareEvalStatus, Sid,
    };

    fn finding(rule_id: &str, sev: RiskSeverity, incomplete: bool) -> RiskFinding {
        RiskFinding {
            rule_id: rule_id.to_owned(),
            severity: sev,
            description: "desc".to_owned(),
            affected_path: Some(NormalizedPath("C:\\Test".to_owned())),
            affected_identity: Some(Sid("S-1-5-21-1-2-3-1000".to_owned())),
            incomplete,
        }
    }

    fn perm() -> EffectivePermission {
        EffectivePermission {
            identity: Identity {
                sid: Sid("S-1-5-21-1-2-3-1000".to_owned()),
                name: Some("test.user".to_owned()),
                domain: Some("TESTDOMAIN".to_owned()),
                kind: IdentityKind::User,
                disabled: false,
                user_principal_name: None,
                sid_history_count: 0,
            },
            path: NormalizedPath("C:\\Test".to_owned()),
            ntfs_mask: AccessMask(0x0012_0089),
            share_mask: None,
            effective_mask: AccessMask(0x0012_0089),
            path_explanation: PermissionPath { steps: vec![] },
            share_status: ShareEvalStatus::NotApplicable,
            local_group_status: LocalGroupEvalStatus::NotQueried,
            contributing_sids: vec![],
            unsupported_ace_count: 0,
            matched_aces: vec![],
            diagnostics: vec![],
        }
    }

    #[test]
    fn incomplete_finding_renders_incomplete_badge() {
        let mut s = String::new();
        write_risk_table(&mut s, &[finding("WRITE_ACCESS", RiskSeverity::High, true)])
            .expect("write_risk_table must succeed");
        assert!(
            s.contains("incomplete"),
            "incomplete finding must be visibly flagged in HTML, got: {s}"
        );
    }

    #[test]
    fn complete_finding_renders_confirmed_badge() {
        let mut s = String::new();
        write_risk_table(
            &mut s,
            &[finding("WRITE_ACCESS", RiskSeverity::High, false)],
        )
        .expect("write_risk_table must succeed");
        assert!(
            s.contains("confirmed"),
            "complete finding must show confirmed marker, got: {s}"
        );
        assert!(
            !s.contains("incomplete"),
            "complete finding must not show incomplete marker"
        );
    }

    /// Clean permission → Dash in the diagnostics column.
    #[test]
    fn permissions_table_dash_when_no_diagnostics() {
        let mut s = String::new();
        write_permissions_table(&mut s, &[perm()]).unwrap();
        // Search for the dash within a <td>—</td> cell — the column
        // explicitly emits "—" when there's nothing to report.
        assert!(
            s.contains("<td>—</td>"),
            "must show dash for clean row, got: {s}"
        );
        assert!(!s.contains("non-canonical"));
        assert!(!s.contains("local groups unavailable"));
    }

    /// Follow-up finding 3: NonCanonicalDaclOrder must appear as an HTML badge.
    #[test]
    fn permissions_table_renders_non_canonical_dacl_badge() {
        let mut p = perm();
        p.diagnostics = vec![PermissionDiagnostic::NonCanonicalDaclOrder { at_index: 2 }];
        let mut s = String::new();
        write_permissions_table(&mut s, &[p]).unwrap();
        assert!(
            s.contains("non-canonical DACL"),
            "must render non-canonical badge, got: {s}"
        );
        assert!(
            s.contains("at index 2"),
            "tooltip must mention the offending ACE index, got: {s}"
        );
    }

    /// `LocalGroupEvalStatus::NotAvailable` was previously not surfaced in the
    /// HTML diagnostics cell — gap from before follow-up finding 3.
    #[test]
    fn permissions_table_renders_local_group_failure_badge() {
        let mut p = perm();
        p.local_group_status =
            LocalGroupEvalStatus::NotAvailable("RPC server unavailable".to_owned());
        let mut s = String::new();
        write_permissions_table(&mut s, &[p]).unwrap();
        assert!(
            s.contains("local groups unavailable"),
            "must render local-group failure badge, got: {s}"
        );
        assert!(
            s.contains("RPC server unavailable"),
            "tooltip must include the failure reason, got: {s}"
        );
    }

    /// Stack test: multiple diagnostic sources rendered together in one cell.
    #[test]
    fn permissions_table_renders_combined_diagnostics() {
        let mut p = perm();
        p.unsupported_ace_count = 2;
        p.share_status = ShareEvalStatus::ReadFailed("access denied".to_owned());
        p.local_group_status =
            LocalGroupEvalStatus::NotAvailable("RPC server unavailable".to_owned());
        p.diagnostics = vec![
            PermissionDiagnostic::NonCanonicalDaclOrder { at_index: 0 },
            PermissionDiagnostic::UnsupportedShareAces { count: 5 },
        ];
        let mut s = String::new();
        write_permissions_table(&mut s, &[p]).unwrap();
        assert!(s.contains("2 unsupported ACE(s)"));
        assert!(s.contains("share DACL unreadable"));
        assert!(s.contains("local groups unavailable"));
        assert!(s.contains("non-canonical DACL"));
        assert!(s.contains("5 unsupported share ACE(s)"));
    }

    ///
    /// The summary header must include a Diagnostics card showing how many
    /// paths carry incompleteness markers. Without it an auditor would have
    /// to scan every row's diagnostic column to assess the evaluation basis.
    #[test]
    fn html_summary_includes_diagnostics_card() {
        use adpa_core::traits::AnalysisResult;

        let mut clean = perm();
        clean.path = NormalizedPath("C:\\Clean".to_owned());

        let mut flagged = perm();
        flagged.path = NormalizedPath("C:\\Flagged".to_owned());
        flagged.diagnostics = vec![PermissionDiagnostic::NonCanonicalDaclOrder { at_index: 0 }];

        let result = AnalysisResult {
            permissions: vec![clean, flagged],
            risk_findings: vec![],
            ..Default::default()
        };

        let html = super::render_html(&result).expect("render_html must succeed");
        assert!(
            html.contains(">Diagnostics<"),
            "summary must contain a Diagnostics card label, got: {html}"
        );
        // Exactly one path carries a marker → the card count must read "1".
        assert!(
            html.contains("<div class=\"num\">1</div><div class=\"lbl\">Diagnostics</div>"),
            "Diagnostics card must report count 1, got: {html}"
        );
    }

    /// Follow-up finding 2: dedicated test for the share diagnostic badge.
    #[test]
    fn permissions_table_renders_unsupported_share_aces_badge() {
        let mut p = perm();
        p.diagnostics = vec![PermissionDiagnostic::UnsupportedShareAces { count: 3 }];
        let mut s = String::new();
        write_permissions_table(&mut s, &[p]).unwrap();
        assert!(
            s.contains("3 unsupported share ACE(s)"),
            "must render unsupported-share-ACE badge with count, got: {s}"
        );
        assert!(
            s.contains("share mask is"),
            "tooltip must mention that the share mask may be incomplete"
        );
    }

    /// Round-8 follow-up finding 1: HTML exporter must not overwrite an
    /// existing target file when called with `ExportTarget::File`.
    #[test]
    fn html_refuses_overwrite_unless_explicitly_allowed() {
        use adpa_core::error::CoreError;
        use adpa_core::traits::{AnalysisResult, ExportTarget, Exporter};

        let mut tmp = std::env::temp_dir();
        tmp.push(format!(
            "adpa_html_overwrite_{}_{}.html",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::process::id()
        ));
        let sentinel = b"<!-- sentinel -->";
        std::fs::write(&tmp, sentinel).expect("write sentinel");

        let result = AnalysisResult::default();
        let refusal = super::HtmlExporter
            .export(&result, ExportTarget::File(tmp.clone()))
            .expect_err("File branch must refuse to overwrite an existing file");
        assert!(matches!(refusal, CoreError::Export(_)));
        let after_refusal = std::fs::read(&tmp).expect("read sentinel after refusal");
        assert_eq!(
            after_refusal, sentinel,
            "pre-existing HTML content must stay intact when overwrite refused"
        );

        super::HtmlExporter
            .export(&result, ExportTarget::FileOverwrite(tmp.clone()))
            .expect("FileOverwrite branch must succeed");
        let after_overwrite = std::fs::read_to_string(&tmp).expect("read after overwrite");
        assert!(
            after_overwrite.contains("<html"),
            "FileOverwrite must replace sentinel content with HTML report"
        );

        let _ = std::fs::remove_file(&tmp);
    }
}
