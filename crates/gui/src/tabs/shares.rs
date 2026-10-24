// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Shares tab (`ui/tabs/shares.slint`): a server's SMB shares and their
//! share-level DACL.

use std::sync::mpsc::Sender;

use slint::ComponentHandle;

use crate::worker::{SharesViewData, WorkerRequest};
use crate::{MainWindow, ShareAceVm, ShareVm, SharesState};

pub fn wire(ui: &MainWindow, req_tx: &Sender<WorkerRequest>) {
    let weak = ui.as_weak();
    let req_tx = req_tx.clone();
    ui.global::<SharesState>().on_list_clicked(move || {
        let Some(ui) = weak.upgrade() else { return };
        let server = ui.global::<SharesState>().get_server().to_string();
        if server.trim().is_empty() {
            ui.global::<SharesState>()
                .set_status("Server is required.".into());
            ui.global::<SharesState>().set_status_is_error(true);
            return;
        }
        ui.global::<SharesState>().set_is_running(true);
        ui.global::<SharesState>().set_has_result(false);
        ui.global::<SharesState>()
            .set_status("Listing shares...".into());
        ui.global::<SharesState>().set_status_is_error(false);
        if let Err(e) = req_tx.send(WorkerRequest::ListShares { server }) {
            ui.global::<SharesState>().set_is_running(false);
            ui.global::<SharesState>()
                .set_status(format!("Worker not reachable: {e}").into());
            ui.global::<SharesState>().set_status_is_error(true);
        }
    });
}

pub fn handle_done(ui: &MainWindow, result: Result<SharesViewData, String>) {
    ui.global::<SharesState>().set_is_running(false);
    match result {
        Ok(data) => {
            let status = if data.errors.is_empty() {
                format!("{} share(s) found", data.shares.len())
            } else {
                format!(
                    "{} share(s) found, {} could not be read",
                    data.shares.len(),
                    data.errors.len()
                )
            };
            ui.global::<SharesState>().set_status(status.into());
            // Read failures are part of the result, not a hard error — but
            // they must not look like a clean run.
            ui.global::<SharesState>()
                .set_status_is_error(!data.errors.is_empty());
            ui.global::<SharesState>()
                .set_result_server(data.server.into());
            ui.global::<SharesState>().set_admin_count(data.admin_count);
            let vms: Vec<ShareVm> = data
                .shares
                .into_iter()
                .map(|s| {
                    let aces: Vec<ShareAceVm> = s
                        .aces
                        .into_iter()
                        .map(|a| ShareAceVm {
                            kind: a.kind.into(),
                            trustee: a.trustee.into(),
                            sid: a.sid.into(),
                            rights: a.rights_label.into(),
                            mask: a.mask_hex.into(),
                        })
                        .collect();
                    ShareVm {
                        name: s.name.into(),
                        unc: s.unc_path.into(),
                        local: s.local_path.into(),
                        is_admin: s.is_admin,
                        is_hidden: s.is_hidden,
                        dacl_status: s.dacl_status.into(),
                        dacl_level: s.dacl_status_level,
                        aces: slint::ModelRc::new(slint::VecModel::from(aces)),
                        unsupported: s.unsupported_count,
                    }
                })
                .collect();
            ui.global::<SharesState>()
                .set_shares(slint::ModelRc::new(slint::VecModel::from(vms)));
            let errors: Vec<slint::SharedString> =
                data.errors.into_iter().map(|e| e.into()).collect();
            ui.global::<SharesState>()
                .set_errors(slint::ModelRc::new(slint::VecModel::from(errors)));
            ui.global::<SharesState>().set_has_result(true);
        }
        Err(e) => {
            ui.global::<SharesState>().set_has_result(false);
            ui.global::<SharesState>().set_status(e.into());
            ui.global::<SharesState>().set_status_is_error(true);
        }
    }
}
