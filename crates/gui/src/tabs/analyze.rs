// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Analyze tab (`ui/tabs/analyze.slint`): one path and one account — the
//! effective right, its permission path, the share line and the
//! diagnostics — plus the path-centric "Who has access?" view. Its result
//! also feeds the Graph tab.

use std::cell::RefCell;
use std::sync::mpsc::Sender;

use adpa_core::model::{EffectivePermission, PermissionDiagnostic, ShareEvalStatus};
use permission_engine::NormalizedRights;
use slint::ComponentHandle;

use crate::identity_input::{
    empty_suggestion_model, filter_suggestions_model, resolve_name_to_sid,
    suggestions_model_from_search, MAX_SUGGESTIONS,
};
use crate::tabs::graph;
use crate::view_models::trustee_vm;
use crate::worker::{IdentitySearchResult, LdapParams, TrusteeRow, WorkerRequest};
use crate::{AnalyzeState, DiagnosticVm, MainWindow, StepVm, TrusteeRowVm};

thread_local! {
    /// Review CR-12: the full Analyze path (all view rows) of the last
    /// result; the shown model is filtered from it on toggle.
    static ANALYZE_STEPS: RefCell<Vec<StepVm>> = const { RefCell::new(Vec::new()) };
}

pub fn wire(ui: &MainWindow, req_tx: &Sender<WorkerRequest>) {
    // Name → SID: LSA lookup directly on the UI thread (LookupAccountNameW
    // is sub-millisecond, no worker round-trip needed).
    {
        let weak = ui.as_weak();
        ui.global::<AnalyzeState>()
            .on_resolve_name_clicked(move || {
                let Some(ui) = weak.upgrade() else { return };
                let name = ui.global::<AnalyzeState>().get_name().to_string();
                resolve_name_to_sid(
                    &name,
                    |sid| ui.global::<AnalyzeState>().set_sid(sid.into()),
                    |err| ui.global::<AnalyzeState>().set_name_error(err.into()),
                );
            });
    }

    // Live search: filter the cache on every keystroke and push the result
    // to the Slint property. An empty query auto-hides the suggestion
    // list (length == 0).
    {
        let weak = ui.as_weak();
        ui.global::<AnalyzeState>().on_name_edited(move |query| {
            let Some(ui) = weak.upgrade() else { return };
            ui.global::<AnalyzeState>()
                .set_suggestions(filter_suggestions_model(query.as_str()));
            // Typing switches back to the local autocomplete; drop any
            // lingering directory-search feedback.
            ui.global::<AnalyzeState>().set_search_status("".into());
        });
    }

    // Review CR-12: show / hide the memberships that did not matter.
    {
        let weak = ui.as_weak();
        ui.global::<AnalyzeState>().on_toggle_members(move || {
            let Some(ui) = weak.upgrade() else { return };
            let show_all = !ui.global::<AnalyzeState>().get_show_all_members();
            ui.global::<AnalyzeState>().set_show_all_members(show_all);
            let rows = ANALYZE_STEPS.with(|s| visible_steps(&s.borrow(), show_all));
            ui.global::<AnalyzeState>()
                .set_explanation(slint::ModelRc::new(slint::VecModel::from(rows)));
        });
    }

    // Click on a suggestion: take the name, close the list, immediately
    // resolve the SID — saves the user a second click.
    {
        let weak = ui.as_weak();
        ui.global::<AnalyzeState>()
            .on_pick_suggestion(move |name, sid| {
                let Some(ui) = weak.upgrade() else { return };
                ui.global::<AnalyzeState>().set_name(name.clone());
                ui.global::<AnalyzeState>()
                    .set_suggestions(empty_suggestion_model());
                ui.global::<AnalyzeState>().set_search_status("".into());
                // A live directory hit already carries its SID — fill it directly
                // and skip the LSA lookup, which cannot resolve a remote-domain
                // sAMAccountName from the local host. A local entry has an empty
                // sid and falls back to the LSA resolve below.
                if !sid.is_empty() {
                    ui.global::<AnalyzeState>().set_sid(sid);
                    ui.global::<AnalyzeState>().set_name_error("".into());
                    return;
                }
                let name_str = name.to_string();
                resolve_name_to_sid(
                    &name_str,
                    |sid| ui.global::<AnalyzeState>().set_sid(sid.into()),
                    |err| ui.global::<AnalyzeState>().set_name_error(err.into()),
                );
            });
    }

    // "Search AD": run a live LDAP directory search for the current identity
    // text and show the hits in the same picker list. Needs an LDAP mode; the
    // button is disabled otherwise, so this branch is the guard for the empty
    // query and for programmatic callers.
    {
        let search_tx = req_tx.clone();
        let weak = ui.as_weak();
        ui.global::<AnalyzeState>().on_search_directory_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let query = ui.global::<AnalyzeState>().get_name().to_string();
            if query.trim().is_empty() {
                ui.global::<AnalyzeState>().set_search_status(
                    "Enter a name (or part of one) to search the directory.".into(),
                );
                return;
            }
            let Some(ldap) = LdapParams::from_mode(
                ui.global::<AnalyzeState>().get_ldap_mode(),
                ui.global::<AnalyzeState>().get_ldap_server().to_string(),
                ui.global::<AnalyzeState>().get_ldap_base_dn().to_string(),
                ui.global::<AnalyzeState>().get_ldap_bind_dn().to_string(),
                ui.global::<AnalyzeState>().get_ldap_password().to_string(),
                ui.global::<AnalyzeState>().get_ldap_timeout(),
            ) else {
                ui.global::<AnalyzeState>().set_search_status(
                    "Directory search needs an LDAP mode (LDAPS / LDAP / Global Catalog / Signed). Select one above."
                        .into(),
                );
                return;
            };
            ui.global::<AnalyzeState>().set_name_error("".into());
            ui.global::<AnalyzeState>().set_search_status("Searching the directory…".into());
            if let Err(e) = search_tx.send(WorkerRequest::SearchIdentity { query, ldap }) {
                ui.global::<AnalyzeState>().set_search_status(format!("Worker not reachable: {e}").into());
            }
        });
    }

    // "Analyze": one path, one account.
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.global::<AnalyzeState>().on_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let path = ui.global::<AnalyzeState>().get_path().to_string();
            if path.trim().is_empty() {
                ui.global::<AnalyzeState>()
                    .set_status("Path is required.".into());
                ui.global::<AnalyzeState>().set_status_is_error(true);
                return;
            }

            // Identity: the Resolved-SID field takes precedence when set; otherwise
            // the RAW identity (name / DOMAIN\user / UPN / SID) is sent to the
            // worker, which dispatches it — with LDAP configured the principal
            // pipeline resolves a name itself, otherwise the local LSA/SAM path
            // does. No LSA pre-resolve here: it used to abort on identities only
            // LDAP can resolve, even with a sufficient LDAP mode configured
            // (review 2026-07-01 deep pass, finding 1). The "Resolve SID"
            // button remains the explicit LSA preview.
            let mut identity = ui.global::<AnalyzeState>().get_sid().to_string();
            if identity.trim().is_empty() {
                identity = ui.global::<AnalyzeState>().get_name().to_string();
                if identity.trim().is_empty() {
                    ui.global::<AnalyzeState>()
                        .set_status("Path and identity are required.".into());
                    ui.global::<AnalyzeState>().set_status_is_error(true);
                    return;
                }
                ui.global::<AnalyzeState>().set_name_error("".into());
            }

            // LDAP mode: 0 = off (SAM/LSA), 1 = LDAPS, 2 = plain LDAP,
            // 3 = Global Catalog (LDAPS 3269). Mapping lives in
            // LdapParams::from_mode so it is unit-tested without the UI.
            let ldap = LdapParams::from_mode(
                ui.global::<AnalyzeState>().get_ldap_mode(),
                ui.global::<AnalyzeState>().get_ldap_server().to_string(),
                ui.global::<AnalyzeState>().get_ldap_base_dn().to_string(),
                ui.global::<AnalyzeState>().get_ldap_bind_dn().to_string(),
                ui.global::<AnalyzeState>().get_ldap_password().to_string(),
                ui.global::<AnalyzeState>().get_ldap_timeout(),
            )
            .map(|l| {
                l.with_trust(
                    ui.global::<AnalyzeState>().get_trust_enabled(),
                    ui.global::<AnalyzeState>().get_trust_server().to_string(),
                    ui.global::<AnalyzeState>().get_trust_base_dn().to_string(),
                    ui.global::<AnalyzeState>().get_trust_bind_dn().to_string(),
                    ui.global::<AnalyzeState>().get_trust_password().to_string(),
                )
            });

            let (smb_server, share_name) = if ui.global::<AnalyzeState>().get_smb_enabled() {
                (
                    Some(ui.global::<AnalyzeState>().get_smb_server().to_string()),
                    Some(ui.global::<AnalyzeState>().get_smb_share().to_string()),
                )
            } else {
                (None, None)
            };

            ui.global::<AnalyzeState>().set_is_running(true);
            ui.global::<AnalyzeState>()
                .set_status("Analysis running...".into());
            ui.global::<AnalyzeState>().set_status_is_error(false);
            ui.global::<AnalyzeState>().set_rights_label("".into());
            ui.global::<AnalyzeState>().set_mask_hex("".into());
            ui.global::<AnalyzeState>().set_share_line("".into());
            ui.global::<AnalyzeState>()
                .set_explanation(slint::ModelRc::new(slint::VecModel::<StepVm>::default()));
            graph::clear(&ui, "Analysis running — the graph follows its result.");

            if let Err(e) = req_tx.send(WorkerRequest::Analyze {
                path,
                identity,
                ldap,
                smb_server,
                share_name,
            }) {
                ui.global::<AnalyzeState>().set_is_running(false);
                ui.global::<AnalyzeState>()
                    .set_status(format!("Worker not reachable: {e}").into());
                ui.global::<AnalyzeState>().set_status_is_error(true);
            }
        });
    }

    // "Who has access?" — path-centric trustee view. Needs no SID.
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.global::<AnalyzeState>().on_trustees_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let path = ui.global::<AnalyzeState>().get_path().to_string();
            if path.trim().is_empty() {
                ui.global::<AnalyzeState>()
                    .set_status("Path is required.".into());
                ui.global::<AnalyzeState>().set_status_is_error(true);
                return;
            }
            let (smb_server, share_name) = if ui.global::<AnalyzeState>().get_smb_enabled() {
                (
                    Some(ui.global::<AnalyzeState>().get_smb_server().to_string()),
                    Some(ui.global::<AnalyzeState>().get_smb_share().to_string()),
                )
            } else {
                (None, None)
            };
            ui.global::<AnalyzeState>().set_trustees_running(true);
            ui.global::<AnalyzeState>().set_has_trustees(false);
            ui.global::<AnalyzeState>()
                .set_status("Reading DACL...".into());
            ui.global::<AnalyzeState>().set_status_is_error(false);
            if let Err(e) = req_tx.send(WorkerRequest::AnalyzeTrustees {
                path,
                smb_server,
                share_name,
            }) {
                ui.global::<AnalyzeState>().set_trustees_running(false);
                ui.global::<AnalyzeState>()
                    .set_status(format!("Worker not reachable: {e}").into());
                ui.global::<AnalyzeState>().set_status_is_error(true);
            }
        });
    }
}

/// Shows a finished analysis — or why it failed — and hands the result to
/// the Graph tab.
pub fn apply_result(
    ui: &MainWindow,
    result: Result<EffectivePermission, String>,
    scan_run_id: Option<String>,
    persistence_error: Option<String>,
) {
    ui.global::<AnalyzeState>().set_is_running(false);
    match result {
        Ok(perm) => {
            let effective_raw = perm.effective_mask.0;
            let rights = NormalizedRights::new(effective_raw);
            // ADR 0065: never present an undeterminable value as the answer.
            let mut rights_label = if perm.effective_determinable() {
                format!("{} ({})", rights.display_name(), rights.label())
            } else {
                format!(
                    "{} — known data: {} ({})",
                    permission_engine::NOT_DETERMINABLE,
                    rights.display_name(),
                    rights.label()
                )
            };
            // ADR 0080: the rights stay; the headline says why Windows
            // programs fail.
            if let Some(suffix) = perm.synchronize_suffix() {
                rights_label.push_str(" — ");
                rights_label.push_str(suffix);
            }
            ui.global::<AnalyzeState>()
                .set_rights_label(rights_label.into());
            ui.global::<AnalyzeState>()
                .set_mask_hex(format!("0x{effective_raw:08X}").into());
            ui.global::<AnalyzeState>()
                .set_share_line(format_share_line(&perm).into());
            ui.global::<AnalyzeState>().set_show_all_members(false);
            let all = step_vms(&perm.path_explanation.steps);
            ui.global::<AnalyzeState>()
                .set_explanation(slint::ModelRc::new(slint::VecModel::from(visible_steps(
                    &all, false,
                ))));
            ANALYZE_STEPS.with(|s| *s.borrow_mut() = all);
            graph::show(ui, &perm);
            // GUI-1 (gui review 2026-07-26): surface the structured
            // diagnostics of this very result. Before this, the Analyze tab
            // — the single-path view an admin reaches for first — dropped
            // every marker: an understated right (unevaluated sIDHistory),
            // a failed group resolution or a flat SAM fallback all rendered
            // as a confident, clean "Analysis complete." The wording and the
            // severity mapping are the shared ones (`summary()` /
            // `diag_level`), so CLI, GUI and reports say the same thing.
            // ADR 0065: reasons that come from a status rather than a
            // marker (share DACL unreadable, local groups unavailable) are
            // listed first, so every "not determinable" has its reason here.
            let mut diagnostics: Vec<DiagnosticVm> = perm
                .uncertainty()
                .into_iter()
                .filter(|u| !perm.diagnostics.iter().any(|d| d.summary() == u.reason))
                .map(|u| DiagnosticVm {
                    text: u.reason.into(),
                    level: crate::worker::diag_level_for_ui(
                        adpa_core::model::DiagnosticSeverity::Concern,
                    ),
                })
                .collect();
            diagnostics.extend(perm.diagnostics.iter().map(|d| DiagnosticVm {
                text: d.summary().into(),
                level: crate::worker::diag_level_for_ui(d.severity()),
            }));
            ui.global::<AnalyzeState>()
                .set_diagnostics(slint::ModelRc::new(slint::VecModel::from(diagnostics)));
            // Analyze results are written to the scan history — required for
            // them to be comparable in the Delta tab.
            let (status, is_error) = match (scan_run_id, persistence_error) {
                (Some(_), _) => (
                    "Analysis complete — saved to scan history.".to_string(),
                    false,
                ),
                (None, Some(reason)) => (
                    format!("Analysis complete, but persistence failed: {reason}"),
                    true,
                ),
                (None, None) => ("Analysis complete.".to_string(), false),
            };
            ui.global::<AnalyzeState>().set_status(status.into());
            ui.global::<AnalyzeState>().set_status_is_error(is_error);
        }
        Err(e) => {
            // Clear stale markers from a previous run — a failed analysis
            // must not leave the last result's diagnostics on screen.
            ui.global::<AnalyzeState>()
                .set_diagnostics(slint::ModelRc::new(
                    slint::VecModel::<DiagnosticVm>::default(),
                ));
            graph::clear(ui, "No graph: the last analysis failed.");
            ui.global::<AnalyzeState>()
                .set_status(format!("Analysis failed: {e}").into());
            ui.global::<AnalyzeState>().set_status_is_error(true);
        }
    }
}

/// Fills the "Who has access?" list from the path's DACL.
pub fn handle_trustees_done(ui: &MainWindow, result: Result<Vec<TrusteeRow>, String>) {
    ui.global::<AnalyzeState>().set_trustees_running(false);
    match result {
        Ok(rows) => {
            let vms: Vec<TrusteeRowVm> = rows.into_iter().map(trustee_vm).collect();
            let len = vms.len();
            ui.global::<AnalyzeState>()
                .set_trustees(slint::ModelRc::new(slint::VecModel::from(vms)));
            ui.global::<AnalyzeState>().set_has_trustees(true);
            ui.global::<AnalyzeState>()
                .set_status(format!("{} ACE entries found on this path.", len).into());
            ui.global::<AnalyzeState>().set_status_is_error(false);
        }
        Err(e) => {
            ui.global::<AnalyzeState>().set_has_trustees(false);
            ui.global::<AnalyzeState>()
                .set_status(format!("Trustee evaluation failed: {e}").into());
            ui.global::<AnalyzeState>().set_status_is_error(true);
        }
    }
}

/// Consumes a live directory search: fills the picker list with the hits and
/// reports the outcome in `AnalyzeState.search-status` (match count, empty
/// result, or error). A failed search clears the list but never the fields.
pub fn handle_search_results(ui: &MainWindow, result: Result<Vec<IdentitySearchResult>, String>) {
    match result {
        Ok(list) => {
            let total = list.len();
            ui.global::<AnalyzeState>()
                .set_suggestions(suggestions_model_from_search(&list));
            let msg = if total == 0 {
                "No directory matches. Try a different name or check the LDAP settings.".to_string()
            } else if total > MAX_SUGGESTIONS {
                format!(
                    "Showing the first {MAX_SUGGESTIONS} of {total} matches — refine the name to narrow it down."
                )
            } else if total == 1 {
                "1 directory match.".to_string()
            } else {
                format!("{total} directory matches.")
            };
            ui.global::<AnalyzeState>().set_search_status(msg.into());
        }
        Err(e) => {
            ui.global::<AnalyzeState>()
                .set_suggestions(empty_suggestion_model());
            ui.global::<AnalyzeState>()
                .set_search_status(format!("Directory search failed: {e}").into());
        }
    }
}

/// The visible rows: collapsible memberships only when shown (review CR-12).
fn visible_steps(all: &[StepVm], show_all: bool) -> Vec<StepVm> {
    all.iter()
        .filter(|s| show_all || !s.collapsible)
        .cloned()
        .collect()
}

/// The Analyze path as view rows (review CR-12): one toggle line before the
/// first collapsible membership; which steps are collapsible is the
/// engine's rule (`collapsible_steps`), not the GUI's.
fn step_vms(steps: &[String]) -> Vec<StepVm> {
    let collapsible = permission_engine::engine::collapsible_steps(steps);
    let hidden = collapsible.iter().filter(|c| **c).count();
    let mut out = Vec::with_capacity(steps.len() + 1);
    let mut toggle_placed = false;
    for (i, (text, collapse)) in steps.iter().zip(&collapsible).enumerate() {
        if *collapse && !toggle_placed {
            out.push(StepVm {
                number: 0,
                text: slint::SharedString::new(),
                collapsible: false,
                toggle: true,
                hidden_count: i32::try_from(hidden).unwrap_or(i32::MAX),
            });
            toggle_placed = true;
        }
        out.push(StepVm {
            number: i32::try_from(i + 1).unwrap_or(i32::MAX),
            text: text.as_str().into(),
            collapsible: *collapse,
            toggle: false,
            hidden_count: 0,
        });
    }
    out
}

fn format_share_line(perm: &EffectivePermission) -> String {
    let line = format_share_line_layers(perm);
    if line.is_empty() {
        return line;
    }
    // ADR 0079: the logon decides before NTFS and share — the line must not
    // read as if their combination were the effective right.
    let logon = perm.diagnostics.iter().find_map(|d| match d {
        PermissionDiagnostic::SelectiveAuthenticationDenied { .. } => Some(
            " Selective Authentication refuses the logon, so the effective right is No access.",
        ),
        PermissionDiagnostic::SelectiveAuthenticationUnknown {
            affects_result: true,
            ..
        } => Some(
            " Whether Selective Authentication allows the logon is not determinable, so the effective right is not determinable.",
        ),
        // ADR 0079 addendum: the permissions grant nothing — exact.
        PermissionDiagnostic::SelectiveAuthenticationUnknown { .. } => Some(
            " Whether Selective Authentication allows the logon is not determinable; the permissions grant nothing here, so the effective right is No access either way.",
        ),
        _ => None,
    });
    match logon {
        Some(note) => format!("{line}{note}"),
        None => line,
    }
}

fn format_share_line_layers(perm: &EffectivePermission) -> String {
    let ntfs_label =
        permission_engine::rights_label_compact(perm.ntfs_mask.0, perm.ntfs_determinable());
    match &perm.share_status {
        ShareEvalStatus::NotApplicable => String::new(),
        ShareEvalStatus::Applied => {
            let share_label = perm
                .share_mask
                .as_ref()
                .map(|m| permission_engine::rights_label_compact(m.0, perm.share_determinable()))
                .unwrap_or_else(|| "—".to_owned());
            format!(
                "Share restriction applied: NTFS = {ntfs_label}, Share = {share_label}, effective = NTFS ∩ Share."
            )
        }
        ShareEvalStatus::Unrestricted => {
            format!(
                "Share has NULL DACL (no SMB restriction) — effective follows NTFS = {ntfs_label}."
            )
        }
        ShareEvalStatus::ReadFailed(reason) => {
            format!("Share permissions not determinable: {reason} — result may be incomplete.")
        }
    }
}

// GUI-6 (gui review 2026-07-26): the pure output formatters produce
// user-facing audit text and are worth pinning — a wrong share line is a
// wrong statement about permissions.
#[cfg(test)]
mod tests {
    use super::{format_share_line, step_vms, visible_steps, StepVm};
    use adpa_core::model::{
        AccessMask, EffectivePermission, Identity, IdentityKind, LocalGroupEvalStatus,
        NormalizedPath, PermissionPath, ShareEvalStatus, Sid,
    };

    fn perm(share_status: ShareEvalStatus, share_mask: Option<u32>) -> EffectivePermission {
        EffectivePermission {
            identity: Identity {
                sid: Sid("S-1-5-21-1-2-3-1000".to_owned()),
                name: Some("test.user".to_owned()),
                domain: None,
                kind: IdentityKind::User,
                disabled: false,
                user_principal_name: None,
                sid_history_count: 0,
                sid_history: Vec::new(),
            },
            path: NormalizedPath(r"C:\data".to_owned()),
            ntfs_mask: AccessMask(0x0012_0089),
            share_mask: share_mask.map(AccessMask),
            effective_mask: AccessMask(0x0012_0089),
            path_explanation: PermissionPath { steps: vec![] },
            share_status,
            local_group_status: LocalGroupEvalStatus::NotQueried,
            contributing_sids: vec![],
            unsupported_ace_count: 0,
            matched_aces: vec![],
            diagnostics: vec![],
            trace: Default::default(),
        }
    }

    /// No SMB context → no share line at all (the GUI hides the row).
    #[test]
    fn share_line_is_empty_without_smb_context() {
        assert!(format_share_line(&perm(ShareEvalStatus::NotApplicable, None)).is_empty());
    }

    /// The applied case must name BOTH layers and the combination rule —
    /// that is the sentence an auditor quotes.
    #[test]
    fn share_line_names_both_layers_when_applied() {
        let line = format_share_line(&perm(ShareEvalStatus::Applied, Some(0x0012_0089)));
        assert!(line.contains("NTFS = "), "must name the NTFS side: {line}");
        assert!(
            line.contains("Share = "),
            "must name the share side: {line}"
        );
        assert!(
            line.contains('∩'),
            "must state the restrictive combination: {line}"
        );
    }

    /// ADR 0079: a refused or unknown logon is named after the layers, so
    /// the line never reads as the effective right.
    #[test]
    fn share_line_names_a_refused_or_unknown_logon() {
        use adpa_core::model::PermissionDiagnostic;
        let mut p = perm(ShareEvalStatus::Applied, Some(0x0012_0089));
        p.diagnostics
            .push(PermissionDiagnostic::SelectiveAuthenticationDenied {
                server: "FS01".into(),
            });
        let line = format_share_line(&p);
        assert!(line.contains('∩') && line.ends_with("No access."), "{line}");
        let mut q = perm(ShareEvalStatus::Unrestricted, None);
        q.diagnostics
            .push(PermissionDiagnostic::SelectiveAuthenticationUnknown {
                server: "FS01".into(),
                reason: "x".into(),
                affects_result: true,
            });
        assert!(format_share_line(&q).ends_with("the effective right is not determinable."));
        // ADR 0079 addendum: nothing granted — No access either way.
        if let Some(PermissionDiagnostic::SelectiveAuthenticationUnknown {
            affects_result, ..
        }) = q.diagnostics.last_mut()
        {
            *affects_result = false;
        }
        assert!(format_share_line(&q).ends_with("No access either way."));
        // Without SMB context there is still no line.
        let mut r = perm(ShareEvalStatus::NotApplicable, None);
        r.diagnostics = p.diagnostics.clone();
        assert!(format_share_line(&r).is_empty());
    }

    /// NULL DACL means "no SMB restriction" — the opposite of an empty
    /// DACL. The wording must not blur that.
    #[test]
    fn share_line_explains_null_dacl_as_unrestricted() {
        let line = format_share_line(&perm(ShareEvalStatus::Unrestricted, None));
        assert!(line.contains("NULL DACL"), "got: {line}");
        assert!(line.contains("no SMB restriction"), "got: {line}");
    }

    /// A failed share read must say so AND carry the reason — the result
    /// is then an NTFS-only lower bound.
    #[test]
    fn share_line_surfaces_read_failure_with_reason() {
        let line = format_share_line(&perm(
            ShareEvalStatus::ReadFailed("access denied (5)".to_owned()),
            None,
        ));
        assert!(line.contains("access denied (5)"), "got: {line}");
        assert!(line.contains("incomplete"), "got: {line}");
    }

    /// Review CR-12: one toggle before the first collapsible membership,
    /// numbers as in the full path.
    #[test]
    fn step_vms_place_one_toggle_and_keep_the_numbering() {
        let mut steps = vec!["User: u (S-1-5-21-1-2-3-1000)".to_owned()];
        for i in 0..12 {
            steps.push(format!("Member of G{i} (S-1-5-21-1-2-3-{i}) [direct]"));
        }
        steps.push("NTFS effective: Read (0x00120089)".to_owned());
        let vms = step_vms(&steps);
        let toggles: Vec<&StepVm> = vms.iter().filter(|v| v.toggle).collect();
        assert_eq!(toggles.len(), 1);
        assert_eq!(toggles[0].hidden_count, 12);
        assert!(
            vms[1].toggle,
            "placed before the first collapsed membership"
        );
        assert_eq!(vms.last().unwrap().number, 14);
        assert!(!vms.last().unwrap().collapsible);
        let short = step_vms(&steps[..5]);
        assert!(short.iter().all(|v| !v.toggle && !v.collapsible));
        // Collapsed: user, toggle, effective step; expanded: everything.
        assert_eq!(visible_steps(&vms, false).len(), 3);
        assert_eq!(visible_steps(&vms, true).len(), vms.len());
    }
}
