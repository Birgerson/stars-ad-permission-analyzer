// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Scan Tree tab (`ui/tabs/scan.slint`): a whole tree for one account —
//! rows streamed in while the scan runs, scan errors, risk findings and
//! the report export.

use std::cell::RefCell;
use std::sync::mpsc::Sender;

use adpa_core::model::{RiskFinding, RiskSeverity};
use fs_scanner::CancellationToken;
use slint::ComponentHandle;

use crate::identity_input::{
    empty_suggestion_model, filter_suggestions_model, resolve_name_to_sid,
};
use crate::view_models::trustee_vm;
use crate::worker::{LdapParams, ReportFormat, ScanRow, WorkerRequest};
use crate::{
    DiagnosticVm, MainWindow, RiskItemVm, ScanErrorVm, ScanRowVm, ScanState, TrusteeRowVm,
};

/// Aggregates all scan intermediates that don't fit directly into a Slint
/// property — the unfiltered raw rows (for the filter) and the expanded
/// row state, both pure UI-side bookkeeping.
#[derive(Default)]
struct ScanUiState {
    all_rows: Vec<ScanRowVm>,
    all_errors: Vec<ScanErrorVm>,
    all_risks: Vec<RiskItemVm>,
}

thread_local! {
    static SCAN_STATE: RefCell<ScanUiState> = RefCell::new(ScanUiState::default());
}

pub fn wire(ui: &MainWindow, req_tx: &Sender<WorkerRequest>, cancel: CancellationToken) {
    // Name → SID helper (analogous to the Analyze tab).
    {
        let weak = ui.as_weak();
        ui.global::<ScanState>().on_resolve_name_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let name = ui.global::<ScanState>().get_name().to_string();
            resolve_name_to_sid(
                &name,
                |sid| ui.global::<ScanState>().set_sid(sid.into()),
                |err| ui.global::<ScanState>().set_name_error(err.into()),
            );
        });
    }

    // Live search analogous to the Analyze tab.
    {
        let weak = ui.as_weak();
        ui.global::<ScanState>().on_name_edited(move |query| {
            let Some(ui) = weak.upgrade() else { return };
            ui.global::<ScanState>()
                .set_suggestions(filter_suggestions_model(query.as_str()));
        });
    }

    {
        let weak = ui.as_weak();
        ui.global::<ScanState>().on_pick_suggestion(move |name| {
            let Some(ui) = weak.upgrade() else { return };
            ui.global::<ScanState>().set_name(name.clone());
            ui.global::<ScanState>()
                .set_suggestions(empty_suggestion_model());
            let name_str = name.to_string();
            resolve_name_to_sid(
                &name_str,
                |sid| ui.global::<ScanState>().set_sid(sid.into()),
                |err| ui.global::<ScanState>().set_name_error(err.into()),
            );
        });
    }

    // scan-clicked
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        let cancel = cancel.clone();
        ui.global::<ScanState>().on_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let root = ui.global::<ScanState>().get_root().to_string();
            if root.trim().is_empty() {
                ui.global::<ScanState>()
                    .set_status("Root path is required.".into());
                ui.global::<ScanState>().set_status_is_error(true);
                return;
            }

            // Identity: the Resolved-SID field takes precedence when set;
            // otherwise the RAW identity goes to the worker, which dispatches
            // it (LDAP principal pipeline or local LSA/SAM) — same as the
            // Analyze and Groups tabs (review 2026-07-01 deep pass, finding 1).
            let mut identity = ui.global::<ScanState>().get_sid().to_string();
            if identity.trim().is_empty() {
                identity = ui.global::<ScanState>().get_name().to_string();
                if identity.trim().is_empty() {
                    ui.global::<ScanState>()
                        .set_status("Root path and identity are required.".into());
                    ui.global::<ScanState>().set_status_is_error(true);
                    return;
                }
                ui.global::<ScanState>().set_name_error("".into());
            }

            let max_depth = if ui.global::<ScanState>().get_limit_depth() {
                let d = ui.global::<ScanState>().get_max_depth();
                if d > 0 {
                    Some(d as u32)
                } else {
                    None
                }
            } else {
                None
            };

            // LDAP mode analogous to the Analyze tab (0=off, 1=LDAPS,
            // 2=plain, 3=Global Catalog). Mapping in LdapParams::from_mode.
            let ldap = LdapParams::from_mode(
                ui.global::<ScanState>().get_ldap_mode(),
                ui.global::<ScanState>().get_ldap_server().to_string(),
                ui.global::<ScanState>().get_ldap_base_dn().to_string(),
                ui.global::<ScanState>().get_ldap_bind_dn().to_string(),
                ui.global::<ScanState>().get_ldap_password().to_string(),
                ui.global::<ScanState>().get_ldap_timeout(),
            )
            .map(|l| {
                l.with_trust(
                    ui.global::<ScanState>().get_trust_enabled(),
                    ui.global::<ScanState>().get_trust_server().to_string(),
                    ui.global::<ScanState>().get_trust_base_dn().to_string(),
                    ui.global::<ScanState>().get_trust_bind_dn().to_string(),
                    ui.global::<ScanState>().get_trust_password().to_string(),
                )
            });

            let (smb_server, share_name) = if ui.global::<ScanState>().get_smb_enabled() {
                (
                    Some(ui.global::<ScanState>().get_smb_server().to_string()),
                    Some(ui.global::<ScanState>().get_smb_share().to_string()),
                )
            } else {
                (None, None)
            };

            // Reset state for a fresh run.
            SCAN_STATE.with(|s| {
                let mut s = s.borrow_mut();
                s.all_rows.clear();
                s.all_errors.clear();
                s.all_risks.clear();
            });
            cancel.reset();

            ui.global::<ScanState>().set_is_running(true);
            ui.global::<ScanState>().set_done(false);
            ui.global::<ScanState>()
                .set_status("Scan running...".into());
            ui.global::<ScanState>().set_status_is_error(false);
            ui.global::<ScanState>().set_total(0);
            ui.global::<ScanState>().set_error_count(0);
            ui.global::<ScanState>().set_scan_run_id("".into());
            ui.global::<ScanState>().set_export_message("".into());
            ui.global::<ScanState>().set_export_is_error(false);
            ui.global::<ScanState>().set_rows(empty_row_model());
            ui.global::<ScanState>().set_errors(empty_error_model());
            ui.global::<ScanState>().set_risks(empty_risk_model());

            if let Err(e) = req_tx.send(WorkerRequest::Scan {
                root,
                identity,
                max_depth,
                smb_server,
                share_name,
                ldap,
            }) {
                ui.global::<ScanState>().set_is_running(false);
                ui.global::<ScanState>()
                    .set_status(format!("Worker not reachable: {e}").into());
                ui.global::<ScanState>().set_status_is_error(true);
            }
        });
    }

    // scan-cancel-clicked
    {
        let cancel = cancel.clone();
        ui.global::<ScanState>().on_cancel_clicked(move || {
            cancel.cancel();
        });
    }

    // scan-row-toggle: flips the expanded column of a row. The master
    // list lives in SCAN_STATE; we re-render the filtered view
    // afterwards.
    {
        let weak = ui.as_weak();
        ui.global::<ScanState>().on_row_toggle(move |index| {
            let Some(ui) = weak.upgrade() else { return };
            let filter = ui.global::<ScanState>().get_filter().to_string();
            SCAN_STATE.with(|s| {
                let mut s = s.borrow_mut();
                if let Some(real_index) = nth_matching_index(&s.all_rows, &filter, index as usize) {
                    s.all_rows[real_index].expanded = !s.all_rows[real_index].expanded;
                }
            });
            refresh_rows(&ui);
        });
    }

    // scan-filter-changed
    {
        let weak = ui.as_weak();
        ui.global::<ScanState>().on_filter_changed(move || {
            let Some(ui) = weak.upgrade() else { return };
            refresh_rows(&ui);
        });
    }

    // export-clicked
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.global::<ScanState>().on_export_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let output_path = ui.global::<ScanState>().get_export_path().to_string();
            if output_path.trim().is_empty() {
                ui.global::<ScanState>()
                    .set_export_message("Please specify a target file.".into());
                ui.global::<ScanState>().set_export_is_error(true);
                return;
            }
            // GUI-2: tell the user which format the extension selects
            // BEFORE the write — the export is format-aware now, so a
            // .csv target must not silently look like the HTML report.
            match ReportFormat::from_path(std::path::Path::new(output_path.trim())) {
                Ok(fmt) => {
                    ui.global::<ScanState>().set_export_message(
                        format!("Export running... ({})", fmt.description()).into(),
                    );
                    ui.global::<ScanState>().set_export_is_error(false);
                }
                Err(e) => {
                    ui.global::<ScanState>().set_export_message(e.into());
                    ui.global::<ScanState>().set_export_is_error(true);
                    return;
                }
            }
            if let Err(e) = req_tx.send(WorkerRequest::ExportReport { output_path }) {
                ui.global::<ScanState>()
                    .set_export_message(format!("Worker not reachable: {e}").into());
                ui.global::<ScanState>().set_export_is_error(true);
            }
        });
    }
}

/// Translates an index from the filtered view back to the index in the
/// unfiltered master list by walking to the `nth` match.
fn nth_matching_index(all: &[ScanRowVm], filter: &str, n: usize) -> Option<usize> {
    let filter = filter.trim().to_lowercase();
    if filter.is_empty() {
        return if n < all.len() { Some(n) } else { None };
    }
    all.iter()
        .enumerate()
        .filter(|(_, r)| r.path.to_lowercase().contains(&filter))
        .nth(n)
        .map(|(i, _)| i)
}

/// Re-renders the rows property from the master state + current filter.
fn refresh_rows(ui: &MainWindow) {
    let filter = ui
        .global::<ScanState>()
        .get_filter()
        .to_string()
        .trim()
        .to_lowercase();
    let filtered: Vec<ScanRowVm> = SCAN_STATE.with(|s| {
        let s = s.borrow();
        if filter.is_empty() {
            s.all_rows.clone()
        } else {
            s.all_rows
                .iter()
                .filter(|r| r.path.to_lowercase().contains(&filter))
                .cloned()
                .collect()
        }
    });
    ui.global::<ScanState>()
        .set_rows(slint::ModelRc::new(slint::VecModel::from(filtered)));
}

pub fn handle_item(ui: &MainWindow, row: ScanRow) {
    let mask_hex = format!("0x{:08X}", row.mask_raw);
    // The trustee list as rows — the same ones the Analyze tab shows.
    let trustee_vms: Vec<TrusteeRowVm> = row.trustees.into_iter().map(trustee_vm).collect();
    let vm = ScanRowVm {
        path: row.path.clone().into(),
        rights_label: row.rights_label.clone().into(),
        mask_hex: mask_hex.into(),
        steps: slint::ModelRc::new(slint::VecModel::from(
            row.steps
                .iter()
                .map(|s| slint::SharedString::from(s.as_str()))
                .collect::<Vec<_>>(),
        )),
        trustees: slint::ModelRc::new(slint::VecModel::from(trustee_vms)),
        expanded: false,
        has_diagnostic: row.diagnostic_count > 0 || row.unsupported_ace_count > 0,
        row_severity: row.row_severity,
        diagnostics: slint::ModelRc::new(slint::VecModel::from(
            row.diagnostics
                .iter()
                .map(|d| DiagnosticVm {
                    text: slint::SharedString::from(d.text.as_str()),
                    level: d.level,
                })
                .collect::<Vec<_>>(),
        )),
    };
    SCAN_STATE.with(|s| s.borrow_mut().all_rows.push(vm));
    let total = SCAN_STATE.with(|s| s.borrow().all_rows.len()) as i32;
    ui.global::<ScanState>().set_total(total);
    refresh_rows(ui);
}

pub fn handle_error(ui: &MainWindow, path: String, message: String) {
    let vm = ScanErrorVm {
        path: path.into(),
        message: message.into(),
    };
    SCAN_STATE.with(|s| s.borrow_mut().all_errors.push(vm));
    let errors = SCAN_STATE.with(|s| {
        let s = s.borrow();
        s.all_errors.clone()
    });
    let count = errors.len() as i32;
    ui.global::<ScanState>().set_error_count(count);
    ui.global::<ScanState>()
        .set_errors(slint::ModelRc::new(slint::VecModel::from(errors)));
}

pub fn handle_done(
    ui: &MainWindow,
    total: usize,
    errors: usize,
    scan_run_id: Option<String>,
    persistence_error: Option<String>,
    cancelled: bool,
) {
    ui.global::<ScanState>().set_is_running(false);
    ui.global::<ScanState>().set_done(true);
    ui.global::<ScanState>().set_total(total as i32);
    ui.global::<ScanState>().set_error_count(errors as i32);
    ui.global::<ScanState>()
        .set_scan_run_id(scan_run_id.unwrap_or_default().into());

    let mut parts: Vec<String> = Vec::new();
    if cancelled {
        parts.push("Scan cancelled — results are incomplete.".to_string());
    } else {
        parts.push("Scan complete.".to_string());
    }
    let had_persistence_error = persistence_error.is_some();
    if let Some(err) = persistence_error {
        parts.push(format!("Persistence failed: {err}"));
    }
    let is_error = cancelled || had_persistence_error;
    ui.global::<ScanState>().set_status(parts.join(" ").into());
    ui.global::<ScanState>().set_status_is_error(is_error);
}

pub fn handle_risk_findings(ui: &MainWindow, findings: Vec<RiskFinding>) {
    let vms: Vec<RiskItemVm> = findings
        .into_iter()
        .map(|f| {
            let (label, color) = severity_visual(&f.severity);
            RiskItemVm {
                severity_label: label.into(),
                severity_color: color,
                rule_id: f.rule_id.into(),
                description: f.description.into(),
                affected_path: f.affected_path.map(|p| p.0).unwrap_or_default().into(),
                incomplete: f.incomplete,
            }
        })
        .collect();
    SCAN_STATE.with(|s| s.borrow_mut().all_risks = vms.clone());
    ui.global::<ScanState>()
        .set_risks(slint::ModelRc::new(slint::VecModel::from(vms)));
}

pub fn handle_export_done(ui: &MainWindow, result: Result<(), String>) {
    match result {
        Ok(()) => {
            ui.global::<ScanState>()
                .set_export_message("✓ Export successful.".into());
            ui.global::<ScanState>().set_export_is_error(false);
        }
        Err(e) => {
            ui.global::<ScanState>()
                .set_export_message(format!("✗ Export failed: {e}").into());
            ui.global::<ScanState>().set_export_is_error(true);
        }
    }
}

fn severity_visual(severity: &RiskSeverity) -> (&'static str, slint::Color) {
    match severity {
        RiskSeverity::Info => ("Info", slint::Color::from_rgb_u8(0x55, 0x77, 0x99)),
        // Same saturated ramp as the diagnostics: green · amber · orange-red · red.
        RiskSeverity::Low => ("Low", slint::Color::from_rgb_u8(0x16, 0xA3, 0x4A)),
        RiskSeverity::Medium => ("Medium", slint::Color::from_rgb_u8(0xD9, 0x77, 0x06)),
        RiskSeverity::High => ("High", slint::Color::from_rgb_u8(0xEA, 0x58, 0x0C)),
        RiskSeverity::Critical => ("Critical", slint::Color::from_rgb_u8(0xDC, 0x26, 0x26)),
    }
}

fn empty_row_model() -> slint::ModelRc<ScanRowVm> {
    slint::ModelRc::new(slint::VecModel::<ScanRowVm>::from(Vec::<ScanRowVm>::new()))
}

fn empty_error_model() -> slint::ModelRc<ScanErrorVm> {
    slint::ModelRc::new(slint::VecModel::<ScanErrorVm>::from(
        Vec::<ScanErrorVm>::new(),
    ))
}

fn empty_risk_model() -> slint::ModelRc<RiskItemVm> {
    slint::ModelRc::new(slint::VecModel::<RiskItemVm>::from(Vec::<RiskItemVm>::new()))
}

#[cfg(test)]
mod tests {
    use super::severity_visual;
    use adpa_core::model::RiskSeverity;

    /// Every severity maps to its own label; nothing falls back silently.
    #[test]
    fn severity_visual_labels_are_distinct_and_complete() {
        let labels: Vec<&str> = [
            RiskSeverity::Info,
            RiskSeverity::Low,
            RiskSeverity::Medium,
            RiskSeverity::High,
            RiskSeverity::Critical,
        ]
        .iter()
        .map(|s| severity_visual(s).0)
        .collect();
        assert_eq!(labels, ["Info", "Low", "Medium", "High", "Critical"]);
    }
}
