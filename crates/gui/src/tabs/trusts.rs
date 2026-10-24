// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Trusts tab (`ui/tabs/trusts.slint`): the domain's trust inventory
//! (read-only, L4).

use std::sync::mpsc::Sender;

use slint::ComponentHandle;

use crate::worker::{LdapParams, TrustRow, WorkerRequest};
use crate::{MainWindow, TrustVm, TrustsState};

pub fn wire(ui: &MainWindow, req_tx: &Sender<WorkerRequest>) {
    let weak = ui.as_weak();
    let req_tx = req_tx.clone();
    ui.global::<TrustsState>().on_list_clicked(move || {
        let Some(ui) = weak.upgrade() else { return };
        // The Trusts selector has no "Off" entry (LDAP is mandatory), so
        // its index 0–3 maps onto `from_mode`'s LDAP modes 1–4.
        let ldap = LdapParams::from_mode(
            ui.global::<TrustsState>().get_ldap_mode() + 1,
            ui.global::<TrustsState>().get_ldap_server().to_string(),
            ui.global::<TrustsState>().get_ldap_base_dn().to_string(),
            ui.global::<TrustsState>().get_ldap_bind_dn().to_string(),
            ui.global::<TrustsState>().get_ldap_password().to_string(),
            ui.global::<TrustsState>().get_ldap_timeout(),
        );
        ui.global::<TrustsState>().set_is_running(true);
        ui.global::<TrustsState>().set_has_result(false);
        ui.global::<TrustsState>()
            .set_status("Reading trusts...".into());
        ui.global::<TrustsState>().set_status_is_error(false);
        if let Err(e) = req_tx.send(WorkerRequest::ListTrusts { ldap }) {
            ui.global::<TrustsState>().set_is_running(false);
            ui.global::<TrustsState>()
                .set_status(format!("Worker not reachable: {e}").into());
            ui.global::<TrustsState>().set_status_is_error(true);
        }
    });
}

pub fn handle_done(ui: &MainWindow, result: Result<Vec<TrustRow>, String>) {
    ui.global::<TrustsState>().set_is_running(false);
    match result {
        Ok(rows) => {
            let flagged = rows
                .iter()
                .filter(|t| t.sid_filtering || t.selective_auth || !t.forest_info_error.is_empty())
                .count();
            let status = if flagged > 0 {
                format!(
                    "{} trust(s) — {flagged} with SID filtering, Selective Authentication or \
                     unknown forest domains",
                    rows.len()
                )
            } else {
                format!("{} trust(s)", rows.len())
            };
            ui.global::<TrustsState>().set_status(status.into());
            ui.global::<TrustsState>().set_status_is_error(false);
            let vms: Vec<TrustVm> = rows
                .into_iter()
                .map(|t| TrustVm {
                    partner: t.partner.into(),
                    flat_name: t.flat_name.into(),
                    direction: t.direction.into(),
                    attributes: t.attributes.into(),
                    raw_hex: t.raw_hex.into(),
                    sid: t.sid.into(),
                    sid_filtering: t.sid_filtering,
                    selective_auth: t.selective_auth,
                    forest: t.forest,
                    forest_domains: slint::ModelRc::new(slint::VecModel::from(
                        t.forest_domains
                            .into_iter()
                            .map(slint::SharedString::from)
                            .collect::<Vec<_>>(),
                    )),
                    forest_info_error: t.forest_info_error.into(),
                })
                .collect();
            ui.global::<TrustsState>()
                .set_trusts(slint::ModelRc::new(slint::VecModel::from(vms)));
            ui.global::<TrustsState>().set_has_result(true);
        }
        Err(e) => {
            ui.global::<TrustsState>().set_has_result(false);
            ui.global::<TrustsState>().set_status(e.into());
            ui.global::<TrustsState>().set_status_is_error(true);
        }
    }
}
