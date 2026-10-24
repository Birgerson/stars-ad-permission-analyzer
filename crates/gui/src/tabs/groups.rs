// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Groups tab (`ui/tabs/groups.slint`): the recursive group memberships of
//! an account, or the members of a group — no path, no ACL.

use std::sync::mpsc::Sender;

use slint::ComponentHandle;

use crate::identity_input::{empty_suggestion_model, filter_suggestions_model_kinds};
use crate::worker::{GroupsViewData, LdapParams, WorkerRequest};
use crate::{DiagnosticVm, GroupMemberVm, GroupsState, MainWindow};

pub fn wire(ui: &MainWindow, req_tx: &Sender<WorkerRequest>) {
    // Same live suggestion list as Analyze, from the same cache.
    {
        let weak = ui.as_weak();
        ui.global::<GroupsState>().on_name_edited(move |query| {
            let Some(ui) = weak.upgrade() else { return };
            // Members direction expects a group — suggest only groups then.
            let groups_only = ui.global::<GroupsState>().get_direction() == 1;
            ui.global::<GroupsState>()
                .set_suggestions(filter_suggestions_model_kinds(query.as_str(), groups_only));
        });
    }
    {
        let weak = ui.as_weak();
        ui.global::<GroupsState>().on_pick_suggestion(move |name| {
            let Some(ui) = weak.upgrade() else { return };
            // The Groups view resolves on "Show groups", so picking only fills
            // the field and closes the list — no eager SID lookup needed.
            ui.global::<GroupsState>().set_identity(name);
            ui.global::<GroupsState>()
                .set_suggestions(empty_suggestion_model());
        });
    }

    // Identity → recursive group memberships, or group → its members.
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.global::<GroupsState>().on_resolve_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let identity = ui.global::<GroupsState>().get_identity().to_string();
            if identity.trim().is_empty() {
                ui.global::<GroupsState>()
                    .set_status("Identity is required.".into());
                ui.global::<GroupsState>().set_status_is_error(true);
                return;
            }
            let ldap = LdapParams::from_mode(
                ui.global::<GroupsState>().get_ldap_mode(),
                ui.global::<GroupsState>().get_ldap_server().to_string(),
                ui.global::<GroupsState>().get_ldap_base_dn().to_string(),
                ui.global::<GroupsState>().get_ldap_bind_dn().to_string(),
                ui.global::<GroupsState>().get_ldap_password().to_string(),
                ui.global::<GroupsState>().get_ldap_timeout(),
            )
            .map(|l| {
                l.with_trust(
                    ui.global::<GroupsState>().get_trust_enabled(),
                    ui.global::<GroupsState>().get_trust_server().to_string(),
                    ui.global::<GroupsState>().get_trust_base_dn().to_string(),
                    ui.global::<GroupsState>().get_trust_bind_dn().to_string(),
                    ui.global::<GroupsState>().get_trust_password().to_string(),
                )
            });
            let members_direction = ui.global::<GroupsState>().get_direction() == 1;
            ui.global::<GroupsState>().set_is_running(true);
            ui.global::<GroupsState>().set_has_result(false);
            ui.global::<GroupsState>().set_status(
                if members_direction {
                    "Enumerating group members..."
                } else {
                    "Resolving group memberships..."
                }
                .into(),
            );
            ui.global::<GroupsState>().set_status_is_error(false);
            // Pass the raw identity (name / DOMAIN\user / UPN / SID) instead of
            // pre-resolving it via the local LSA. With LDAP configured the
            // worker's principal pipeline resolves a name itself, so the Groups
            // tab reaches cross-domain / GC / LDAP-only identities exactly like
            // the CLI (review 2026-07-01 finding 1); without LDAP the worker
            // still uses the local LSA/SAM path.
            let request = if members_direction {
                WorkerRequest::ResolveGroupMembers { identity, ldap }
            } else {
                WorkerRequest::ResolveGroups { identity, ldap }
            };
            if let Err(e) = req_tx.send(request) {
                ui.global::<GroupsState>().set_is_running(false);
                ui.global::<GroupsState>()
                    .set_status(format!("Worker not reachable: {e}").into());
                ui.global::<GroupsState>().set_status_is_error(true);
            }
        });
    }
}

/// Populates the Groups tab from a finished membership resolution.
pub fn handle_done(ui: &MainWindow, result: Result<GroupsViewData, String>) {
    ui.global::<GroupsState>().set_is_running(false);
    match result {
        Ok(data) => {
            ui.global::<GroupsState>().set_has_result(true);
            ui.global::<GroupsState>().set_status_is_error(false);
            // Tie the labels to what was actually computed, not the current
            // toggle (the user may flip the toggle before re-running).
            ui.global::<GroupsState>()
                .set_result_is_members(data.is_members);
            let status = if data.is_members {
                let via_primary = data.total - data.direct;
                format!(
                    "{} member(s) — {} direct, {} via primaryGroupID",
                    data.total, data.direct, via_primary
                )
            } else {
                format!("{} group(s) — {} direct", data.total, data.direct)
            };
            ui.global::<GroupsState>().set_status(status.into());
            ui.global::<GroupsState>()
                .set_identity_label(data.identity_label.into());
            ui.global::<GroupsState>()
                .set_identity_sid(data.identity_sid.into());
            // No enabled/disabled status for non-account kinds (groups): show
            // just the kind rather than a meaningless "Active".
            let meta = if data.status.is_empty() {
                data.kind.clone()
            } else {
                format!("{} \u{00B7} {}", data.status, data.kind)
            };
            ui.global::<GroupsState>().set_identity_meta(meta.into());
            ui.global::<GroupsState>()
                .set_ad_connected(data.ad_connected);
            ui.global::<GroupsState>()
                .set_sid_history(data.sid_history_count);
            ui.global::<GroupsState>().set_total(data.total);
            ui.global::<GroupsState>().set_direct(data.direct);

            ui.global::<GroupsState>()
                .set_has_privileged(!data.privileged.is_empty());
            let priv_model: Vec<slint::SharedString> =
                data.privileged.into_iter().map(|p| p.into()).collect();
            ui.global::<GroupsState>()
                .set_privileged(slint::ModelRc::new(slint::VecModel::from(priv_model)));

            let group_vms: Vec<GroupMemberVm> = data
                .groups
                .into_iter()
                .map(|g| GroupMemberVm {
                    name: g.name.into(),
                    sid: g.sid.into(),
                    origin: g.origin.into(),
                    privileged: g.privileged,
                    role: g.role.into(),
                })
                .collect();
            ui.global::<GroupsState>()
                .set_groups(slint::ModelRc::new(slint::VecModel::from(group_vms)));

            let diag_vms: Vec<DiagnosticVm> = data
                .diagnostics
                .into_iter()
                .map(|d| DiagnosticVm {
                    text: d.text.into(),
                    level: d.level,
                })
                .collect();
            ui.global::<GroupsState>()
                .set_diagnostics(slint::ModelRc::new(slint::VecModel::from(diag_vms)));
        }
        Err(e) => {
            ui.global::<GroupsState>().set_has_result(false);
            ui.global::<GroupsState>().set_status(e.into());
            ui.global::<GroupsState>().set_status_is_error(true);
        }
    }
}
