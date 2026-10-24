// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Info tab (`ui/tabs/info.slint`): author, license, read-only limits and
//! the manual update check (ADR 0061).

use std::sync::mpsc::Sender;

use slint::ComponentHandle;

use crate::worker::{UpdateCheckRow, WorkerRequest};
use crate::{InfoState, MainWindow};

pub fn wire(ui: &MainWindow, req_tx: &Sender<WorkerRequest>) {
    // Default update source for the manual check — user-editable,
    // validated in the worker on every check.
    ui.global::<InfoState>()
        .set_update_source(update_manager::DEFAULT_UPDATE_SOURCE.into());

    // Manual update check: send the user-edited source to the worker;
    // validation and the network call happen there so the GUI never blocks
    // on the 10-second timeout.
    let weak = ui.as_weak();
    let req_tx = req_tx.clone();
    ui.global::<InfoState>().on_check_update(move |source| {
        let Some(ui) = weak.upgrade() else { return };
        ui.global::<InfoState>()
            .set_update_status("Checking…".into());
        ui.global::<InfoState>().set_update_status_is_error(false);
        if let Err(e) = req_tx.send(WorkerRequest::CheckUpdate {
            source: source.to_string(),
        }) {
            ui.global::<InfoState>()
                .set_update_status(format!("Worker not reachable: {e}").into());
            ui.global::<InfoState>().set_update_status_is_error(true);
        }
    });
}

/// Renders the manual update-check outcome (ADR 0061). Every path is
/// explicit — up to date, update available (with the release page), or the
/// honest error (offline DC, invalid source).
pub fn handle_update_check_done(ui: &MainWindow, result: Result<UpdateCheckRow, String>) {
    match result {
        Ok(r) if r.update_available => {
            let mut text = format!("Update available: {} (installed: {}).", r.latest, r.current);
            if let Some(url) = &r.release_url {
                text.push_str(&format!(" Release page: {url}"));
            }
            text.push_str(" Stars downloads and installs nothing — get it from the release page.");
            ui.global::<InfoState>().set_update_status(text.into());
            ui.global::<InfoState>().set_update_status_is_error(false);
        }
        Ok(r) => {
            ui.global::<InfoState>().set_update_status(
                format!("Stars is up to date (installed: {}).", r.current).into(),
            );
            ui.global::<InfoState>().set_update_status_is_error(false);
        }
        Err(e) => {
            ui.global::<InfoState>()
                .set_update_status(format!("Update check failed: {e}").into());
            ui.global::<InfoState>().set_update_status_is_error(true);
        }
    }
}
