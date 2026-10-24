// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Delta tab (`ui/tabs/delta.slint`): the stored scan history — two runs
//! compared, a run's scan errors, a run deleted.

use std::cell::RefCell;
use std::sync::mpsc::Sender;

use slint::ComponentHandle;

use crate::worker::{DeltaRow, RunErrorRow, ScanRunSummary, WorkerRequest};
use crate::{DeltaRowVm, DeltaState, MainWindow, RunErrorVm, ScanRunVm};

/// Backing store for the Delta tab. Slint properties hold the view; the
/// "source of truth" for selection lives here so the exclusive checkbox
/// behaviour (exactly one "old" and one "new" pick) does not need
/// Slint-side bookkeeping.
#[derive(Default)]
struct DeltaUiState {
    runs: Vec<ScanRunSummaryUi>,
    selected_old: Option<String>,
    selected_new: Option<String>,
}

#[derive(Clone)]
struct ScanRunSummaryUi {
    id: String,
    label: String,
    error_count: usize,
}

thread_local! {
    static DELTA_STATE: RefCell<DeltaUiState> = RefCell::new(DeltaUiState::default());
    /// Worker sender for the follow-up reload after a deletion
    /// (`handle_run_deleted`). Set in `wire`.
    static REQ_TX: RefCell<Option<Sender<WorkerRequest>>> = const { RefCell::new(None) };
}

pub fn wire(ui: &MainWindow, req_tx: &Sender<WorkerRequest>) {
    REQ_TX.with(|cell| *cell.borrow_mut() = Some(req_tx.clone()));

    // delta-load-runs-clicked: asks the worker for the scan history. The
    // answer arrives asynchronously as WorkerEvent::ScanRunsLoaded.
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.global::<DeltaState>().on_load_runs_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            ui.global::<DeltaState>().set_is_loading(true);
            ui.global::<DeltaState>()
                .set_status("Loading scan history...".into());
            ui.global::<DeltaState>().set_status_is_error(false);
            if let Err(e) = req_tx.send(WorkerRequest::ListScanRuns) {
                ui.global::<DeltaState>().set_is_loading(false);
                ui.global::<DeltaState>()
                    .set_status(format!("Worker not reachable: {e}").into());
                ui.global::<DeltaState>().set_status_is_error(true);
            }
        });
    }

    // delta-pick-old / delta-pick-new: exclusive toggle — clicking a row
    // sets that run as "old" or "new" and clears the corresponding flag
    // on every other row. Clicking the same row again clears the
    // selection.
    {
        let weak = ui.as_weak();
        ui.global::<DeltaState>().on_pick_old(move |id| {
            let Some(ui) = weak.upgrade() else { return };
            DELTA_STATE.with(|s| {
                let mut s = s.borrow_mut();
                let id_owned = id.to_string();
                if s.selected_old.as_deref() == Some(id_owned.as_str()) {
                    s.selected_old = None;
                } else {
                    s.selected_old = Some(id_owned);
                }
            });
            refresh_runs(&ui);
        });
    }
    {
        let weak = ui.as_weak();
        ui.global::<DeltaState>().on_pick_new(move |id| {
            let Some(ui) = weak.upgrade() else { return };
            DELTA_STATE.with(|s| {
                let mut s = s.borrow_mut();
                let id_owned = id.to_string();
                if s.selected_new.as_deref() == Some(id_owned.as_str()) {
                    s.selected_new = None;
                } else {
                    s.selected_new = Some(id_owned);
                }
            });
            refresh_runs(&ui);
        });
    }

    // delta-compare-clicked: read the two ids and dispatch to the worker.
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.global::<DeltaState>().on_compare_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let (old_id, new_id) = DELTA_STATE.with(|s| {
                let s = s.borrow();
                (s.selected_old.clone(), s.selected_new.clone())
            });
            let (Some(old_id), Some(new_id)) = (old_id, new_id) else {
                ui.global::<DeltaState>()
                    .set_status("Please select one scan run for 'Old' and one for 'New'.".into());
                ui.global::<DeltaState>().set_status_is_error(true);
                return;
            };
            if old_id == new_id {
                ui.global::<DeltaState>()
                    .set_status("'Old' and 'New' must be different runs.".into());
                ui.global::<DeltaState>().set_status_is_error(true);
                return;
            }
            ui.global::<DeltaState>().set_is_loading(true);
            ui.global::<DeltaState>()
                .set_status("Comparing runs...".into());
            ui.global::<DeltaState>().set_status_is_error(false);
            ui.global::<DeltaState>().set_has_result(false);
            if let Err(e) = req_tx.send(WorkerRequest::ComputeDelta {
                old_run_id: old_id,
                new_run_id: new_id,
            }) {
                ui.global::<DeltaState>().set_is_loading(false);
                ui.global::<DeltaState>()
                    .set_status(format!("Worker not reachable: {e}").into());
                ui.global::<DeltaState>().set_status_is_error(true);
            }
        });
    }

    // delta-delete-confirmed: fired by the confirmation dialog once the
    // user confirmed; only then does the worker see the request. The
    // follow-up actions (clearing selection, reloading the list) are
    // handled on WorkerEvent::ScanRunDeleted.
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.global::<DeltaState>().on_delete_confirmed(move |id| {
            let Some(ui) = weak.upgrade() else { return };
            let id_str = id.to_string();
            if id_str.is_empty() {
                return;
            }
            ui.global::<DeltaState>()
                .set_status("Deleting scan run...".into());
            ui.global::<DeltaState>().set_status_is_error(false);
            if let Err(e) = req_tx.send(WorkerRequest::DeleteScanRun { run_id: id_str }) {
                ui.global::<DeltaState>()
                    .set_status(format!("Worker not reachable: {e}").into());
                ui.global::<DeltaState>().set_status_is_error(true);
            }
        });
    }

    // Per-run error view (persistence review 2026-07-26, PS-1): show the
    // stored scan errors of a historical run. The panel opens immediately
    // with the run's label; the rows arrive via
    // WorkerEvent::RunErrorsLoaded.
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.global::<DeltaState>()
            .on_show_errors(move |run_id, label| {
                let Some(ui) = weak.upgrade() else { return };
                let id_str = run_id.to_string();
                if id_str.is_empty() {
                    return;
                }
                ui.global::<DeltaState>()
                    .set_run_errors(slint::ModelRc::new(slint::VecModel::<RunErrorVm>::default()));
                ui.global::<DeltaState>().set_errors_title(label);
                if let Err(e) = req_tx.send(WorkerRequest::ListRunErrors { run_id: id_str }) {
                    ui.global::<DeltaState>().set_errors_title("".into());
                    ui.global::<DeltaState>()
                        .set_status(format!("Worker not reachable: {e}").into());
                    ui.global::<DeltaState>().set_status_is_error(true);
                }
            });
    }
}

fn refresh_runs(ui: &MainWindow) {
    let vms: Vec<ScanRunVm> = DELTA_STATE.with(|s| {
        let s = s.borrow();
        s.runs
            .iter()
            .map(|r| ScanRunVm {
                id: r.id.clone().into(),
                label: r.label.clone().into(),
                selected_as_old: s.selected_old.as_deref() == Some(r.id.as_str()),
                selected_as_new: s.selected_new.as_deref() == Some(r.id.as_str()),
                error_count: r.error_count.min(i32::MAX as usize) as i32,
            })
            .collect()
    });
    ui.global::<DeltaState>()
        .set_scan_runs(slint::ModelRc::new(slint::VecModel::from(vms)));
}

pub fn handle_runs_loaded(ui: &MainWindow, result: Result<Vec<ScanRunSummary>, String>) {
    ui.global::<DeltaState>().set_is_loading(false);
    match result {
        Ok(runs) if runs.is_empty() => {
            DELTA_STATE.with(|s| {
                let mut s = s.borrow_mut();
                s.runs.clear();
                s.selected_old = None;
                s.selected_new = None;
            });
            refresh_runs(ui);
            ui.global::<DeltaState>()
                .set_status("No scan runs stored — run a scan first.".into());
            ui.global::<DeltaState>().set_status_is_error(false);
        }
        Ok(runs) => {
            DELTA_STATE.with(|s| {
                let mut s = s.borrow_mut();
                s.runs = runs
                    .into_iter()
                    .map(|r| ScanRunSummaryUi {
                        id: r.id,
                        label: format!(
                            "{}  —  {}  ({} errors)",
                            r.started_at, r.target, r.error_count
                        ),
                        error_count: r.error_count,
                    })
                    .collect();
                // Drop selections that point at runs which no longer exist.
                let ids: std::collections::HashSet<String> =
                    s.runs.iter().map(|r| r.id.clone()).collect();
                if s.selected_old.as_ref().is_some_and(|id| !ids.contains(id)) {
                    s.selected_old = None;
                }
                if s.selected_new.as_ref().is_some_and(|id| !ids.contains(id)) {
                    s.selected_new = None;
                }
            });
            refresh_runs(ui);
            ui.global::<DeltaState>().set_status(
                "Scan runs loaded. Check one for 'Old' and one for 'New', then compare.".into(),
            );
            ui.global::<DeltaState>().set_status_is_error(false);
        }
        Err(e) => {
            ui.global::<DeltaState>()
                .set_status(format!("Loading failed: {e}").into());
            ui.global::<DeltaState>().set_status_is_error(true);
        }
    }
}

/// Reacts to a worker-completed scan-run deletion. Updates the status line,
/// clears local selection state and triggers a fresh history reload so the
/// list is up-to-date without another click on "Load scan history".
pub fn handle_run_deleted(ui: &MainWindow, run_id: &str, result: Result<(), String>) {
    match result {
        Ok(()) => {
            DELTA_STATE.with(|s| {
                let mut s = s.borrow_mut();
                s.runs.retain(|r| r.id != run_id);
                if s.selected_old.as_deref() == Some(run_id) {
                    s.selected_old = None;
                }
                if s.selected_new.as_deref() == Some(run_id) {
                    s.selected_new = None;
                }
            });
            refresh_runs(ui);
            ui.global::<DeltaState>()
                .set_status("Scan run removed.".into());
            ui.global::<DeltaState>().set_status_is_error(false);
            // If a delta result was still visible in the frame, it might
            // refer to the just-deleted run — hide it to be safe. Same for
            // the per-run error panel.
            ui.global::<DeltaState>().set_has_result(false);
            ui.global::<DeltaState>().set_errors_title("".into());
            // Reload the list in background so the GUI state is guaranteed
            // to match the DB.
            REQ_TX.with(|cell| {
                if let Some(tx) = cell.borrow().as_ref() {
                    let _ = tx.send(WorkerRequest::ListScanRuns);
                }
            });
        }
        Err(e) => {
            ui.global::<DeltaState>()
                .set_status(format!("Delete failed: {e}").into());
            ui.global::<DeltaState>().set_status_is_error(true);
        }
    }
}

/// Fills the Delta tab's per-run error panel (persistence review
/// 2026-07-26, PS-1). The panel title was already set by the click
/// handler; a load failure closes the panel and surfaces the reason in
/// the tab status instead of leaving a silent "Loading…".
pub fn handle_run_errors_loaded(ui: &MainWindow, result: Result<Vec<RunErrorRow>, String>) {
    match result {
        Ok(rows) => {
            let vms: Vec<RunErrorVm> = rows
                .into_iter()
                .map(|r| RunErrorVm {
                    path: r.path.into(),
                    message: r.message.into(),
                })
                .collect();
            ui.global::<DeltaState>()
                .set_run_errors(slint::ModelRc::new(slint::VecModel::from(vms)));
        }
        Err(e) => {
            ui.global::<DeltaState>().set_errors_title("".into());
            ui.global::<DeltaState>()
                .set_status(format!("Scan errors could not be loaded: {e}").into());
            ui.global::<DeltaState>().set_status_is_error(true);
        }
    }
}

pub fn handle_computed(ui: &MainWindow, result: Result<Vec<DeltaRow>, String>) {
    ui.global::<DeltaState>().set_is_loading(false);
    match result {
        Ok(rows) => {
            let mut added = 0;
            let mut removed = 0;
            let mut changed = 0;
            let vms: Vec<DeltaRowVm> = rows
                .into_iter()
                .map(|r| {
                    let color = match r.kind_label.as_str() {
                        "Added" => {
                            added += 1;
                            slint::Color::from_rgb_u8(0x27, 0x8d, 0x4f)
                        }
                        "Removed" => {
                            removed += 1;
                            slint::Color::from_rgb_u8(0xc0, 0x39, 0x2b)
                        }
                        _ => {
                            changed += 1;
                            slint::Color::from_rgb_u8(0xc6, 0x89, 0x10)
                        }
                    };
                    DeltaRowVm {
                        path: r.path.into(),
                        kind_label: r.kind_label.into(),
                        kind_color: color,
                        old_rights: r.old_rights.into(),
                        new_rights: r.new_rights.into(),
                    }
                })
                .collect();
            ui.global::<DeltaState>().set_added_count(added);
            ui.global::<DeltaState>().set_removed_count(removed);
            ui.global::<DeltaState>().set_changed_count(changed);
            ui.global::<DeltaState>()
                .set_rows(slint::ModelRc::new(slint::VecModel::from(vms)));
            ui.global::<DeltaState>().set_has_result(true);
            ui.global::<DeltaState>()
                .set_status("Comparison complete.".into());
            ui.global::<DeltaState>().set_status_is_error(false);
        }
        Err(e) => {
            ui.global::<DeltaState>().set_has_result(false);
            ui.global::<DeltaState>()
                .set_status(format!("Comparison failed: {e}").into());
            ui.global::<DeltaState>().set_status_is_error(true);
        }
    }
}
