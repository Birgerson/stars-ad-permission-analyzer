// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! adpa-gui — Graphical interface for the AD Permission Analyzer (Slint).
//!
//! Logfile, panic hook and MessageBox fallback are kept from the eframe
//! predecessors — they are independent of the GUI toolkit and reliably
//! surface startup problems on a bare server.

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod worker;

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use adpa_core::model::{
    EffectivePermission, PermissionDiagnostic, RiskFinding, RiskSeverity, ShareEvalStatus,
};
use fs_scanner::CancellationToken;
use permission_engine::NormalizedRights;

use crate::worker::{
    spawn_worker, DeltaRow, GroupsViewData, IdentitySearchResult, IdentitySuggestion, LdapParams,
    NotifyFn, ReportFormat, RunErrorRow, ScanRow, ScanRunSummary, SharesViewData, TrustRow,
    TrusteeRow, UpdateCheckRow, WorkerEvent, WorkerRequest,
};

// The UI (window, tabs, components, theme) lives in ui/*.slint. The macro
// compiles it into the types used here (MainWindow, the view-model structs,
// Theme) — `slint-build` would do the same but pulls ~60 extra build-time
// crates (image codecs, rayon) that this UI does not need.
slint::slint! {
    export * from "../ui/app.slint";
}

/// Returns the log directory (`%LOCALAPPDATA%\Stars\logs`).
fn log_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = base.join("Stars").join("logs");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn main() {
    let dir = log_dir();
    let file_appender = tracing_appender::rolling::never(&dir, "stars-gui.log");
    let (file_writer, _guard) = tracing_appender::non_blocking(file_appender);

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(file_writer);

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .init();

    let log_path = dir.join("stars-gui.log");
    std::panic::set_hook(Box::new({
        let log_path = log_path.clone();
        move |info| {
            let payload = info
                .payload()
                .downcast_ref::<&'static str>()
                .map(|s| s.to_string())
                .or_else(|| info.payload().downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-string panic payload>".to_string());
            let location = info
                .location()
                .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
                .unwrap_or_else(|| "<unknown>".to_string());
            tracing::error!(target: "stars-gui", "panic at {location}: {payload}");
            // The hook fires for ANY panic — including a runtime panic on the
            // worker thread — so the title must not claim "at startup" (deep
            // review 2026-07-01, finding 6).
            show_fatal_dialog(
                "Stars — unexpected error",
                &format!(
                    "The application has crashed.\n\nLocation: {location}\nReason: {payload}\n\nDetails: {}",
                    log_path.display()
                ),
            );
        }
    }));

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        log_dir = %dir.display(),
        "starting adpa-gui (slint software backend)"
    );

    std::env::set_var("SLINT_BACKEND", "winit-software");
    // Force fluent style so default widget text colors stay legible
    // regardless of the host system theme.
    std::env::set_var("SLINT_STYLE", "fluent");
    // Slint normally derives the std-widget color scheme from the OS
    // theme. On Windows Server hosts that yields a dark palette and
    // light grey text disappears on our light background. Pin it.
    std::env::set_var("SLINT_COLOR_SCHEME", "light");

    if let Err(e) = run_ui(&log_path) {
        tracing::error!(error = %e, "Slint UI failed");
        show_fatal_dialog(
            "Stars — startup failed",
            &format!(
                "The GUI backend could not be initialized.\n\nReason: {e}\n\nDetails: {}",
                log_path.display()
            ),
        );
    }
}

/// Aggregates all scan intermediates that don't fit directly into a Slint
/// property — the unfiltered raw rows (for the filter) and the expanded
/// row state, both pure UI-side bookkeeping.
#[derive(Default)]
struct ScanUiState {
    all_rows: Vec<ScanRowVm>,
    all_errors: Vec<ScanErrorVm>,
    all_risks: Vec<RiskItemVm>,
}

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
    static EVENT_RX: RefCell<Option<Receiver<WorkerEvent>>> = const { RefCell::new(None) };
    /// Worker sender for follow-up actions inside event handlers (e.g.
    /// re-load the scan history after a deletion). Populated in `run_ui`
    /// right after `spawn_worker`.
    static REQ_TX: RefCell<Option<Sender<WorkerRequest>>> = const { RefCell::new(None) };
    static SCAN_STATE: RefCell<ScanUiState> = RefCell::new(ScanUiState::default());
    static DELTA_STATE: RefCell<DeltaUiState> = RefCell::new(DeltaUiState::default());
    /// Pre-loaded identity list for the live search. Filled once after
    /// app start; keystroke filtering runs purely locally against this
    /// cache without a worker round-trip.
    static IDENTITY_CACHE: RefCell<Vec<IdentitySuggestion>> = const { RefCell::new(Vec::new()) };
    /// Review CR-12: the full Analyze path (all view rows) of the last
    /// result; the shown model is filtered from it on toggle.
    static ANALYZE_STEPS: RefCell<Vec<StepVm>> = const { RefCell::new(Vec::new()) };
    /// The result the Graph tab shows, so "Show all groups" can redraw it.
    static GRAPH_RESULT: RefCell<Option<EffectivePermission>> = const { RefCell::new(None) };
}

/// The visible rows: collapsible memberships only when shown (review CR-12).
fn visible_steps(all: &[StepVm], show_all: bool) -> Vec<StepVm> {
    all.iter()
        .filter(|s| show_all || !s.collapsible)
        .cloned()
        .collect()
}

fn run_ui(_log_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let ui = MainWindow::new()?;

    // App version from Cargo metadata into the GUI. Without this the
    // HeaderBar version badge stays hidden behind its `if != ""` guard.
    ui.set_app_version(format!("v{}", env!("CARGO_PKG_VERSION")).into());
    // Default update source for the Info tab's manual check (ADR 0061) —
    // user-editable, validated in the worker on every check.
    ui.set_i_update_source(update_manager::DEFAULT_UPDATE_SOURCE.into());

    // notify callback: wakes the GUI thread once the worker has sent an
    // event. Slint's `invoke_from_event_loop` is callable from any thread
    // and runs the closure on the UI thread.
    let weak = ui.as_weak();
    let notify: NotifyFn = Arc::new({
        let weak = weak.clone();
        move || {
            let weak = weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(handle) = weak.upgrade() {
                    pump_worker_events(&handle);
                }
            });
        }
    });

    let (req_tx, evt_rx, cancel) = spawn_worker(notify);
    EVENT_RX.with(|cell| *cell.borrow_mut() = Some(evt_rx));
    REQ_TX.with(|cell| *cell.borrow_mut() = Some(req_tx.clone()));

    wire_analyze_tab(&ui, req_tx.clone());
    wire_scan_tab(&ui, req_tx.clone(), cancel);
    wire_delta_tab(&ui, req_tx.clone());

    // Pre-load the identity list once so the live search can show
    // suggestions from the first keystroke. If the call fails the GUI
    // keeps running without suggestions — SID input and the
    let _ = req_tx.send(WorkerRequest::ListIdentities);

    ui.run()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Analyze tab wiring
// ---------------------------------------------------------------------------

fn wire_analyze_tab(ui: &MainWindow, req_tx: std::sync::mpsc::Sender<WorkerRequest>) {
    // Name → SID: LSA lookup directly on the UI thread (LookupAccountNameW
    // is sub-millisecond, no worker round-trip needed).
    {
        let weak = ui.as_weak();
        ui.on_resolve_name_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let name = ui.get_a_name().to_string();
            resolve_name_to_sid(
                &name,
                |sid| ui.set_a_sid(sid.into()),
                |err| ui.set_a_name_error(err.into()),
            );
        });
    }

    // Live search: filter the cache on every keystroke and push the result
    // to the Slint property. An empty query auto-hides the suggestion
    // list (length == 0).
    {
        let weak = ui.as_weak();
        ui.on_analyze_name_edited(move |query| {
            let Some(ui) = weak.upgrade() else { return };
            ui.set_a_suggestions(filter_suggestions_model(query.as_str()));
            // Typing switches back to the local autocomplete; drop any
            // lingering directory-search feedback.
            ui.set_a_search_status("".into());
        });
    }

    // Click on a suggestion: take the name, close the list, immediately
    // resolve the SID — saves the user a second click.
    // Review CR-12: show / hide the memberships that did not matter.
    {
        let weak = ui.as_weak();
        let weak_graph = ui.as_weak();
        ui.on_gr_toggle_all_groups(move || {
            let Some(ui) = weak_graph.upgrade() else {
                return;
            };
            // Another layout: the selected box no longer exists.
            ui.set_gr_selected(-1);
            let perm = GRAPH_RESULT.with(|g| g.borrow().clone());
            if let Some(perm) = perm {
                draw_graph(&ui, &perm);
            }
        });
        // ADR 0081: a click selects a box (its full text, every route through
        // it bright); a second click on it clears the selection.
        let weak_node = ui.as_weak();
        ui.on_gr_node_clicked(move |index| {
            let Some(ui) = weak_node.upgrade() else {
                return;
            };
            let selected = if ui.get_gr_selected() == index {
                -1
            } else {
                index
            };
            ui.set_gr_selected(selected);
            let perm = GRAPH_RESULT.with(|g| g.borrow().clone());
            if let Some(perm) = perm {
                draw_graph(&ui, &perm);
            }
        });
        let weak_save = ui.as_weak();
        ui.on_gr_save_svg(move || {
            let Some(ui) = weak_save.upgrade() else {
                return;
            };
            let perm = GRAPH_RESULT.with(|g| g.borrow().clone());
            let outcome = match perm {
                None => Err("There is no graph to save — run an analysis first.".to_owned()),
                Some(perm) => {
                    let opts = viz::GraphOptions {
                        all_groups: ui.get_gr_all_groups(),
                        caption: true,
                    };
                    match viz::permission_graph_with(&perm, opts) {
                        Some(graph) => save_graph_svg(
                            ui.get_gr_save_path().as_str(),
                            &graph.to_svg_with(&viz::RenderOptions::default()),
                        ),
                        None => Err("This result has no graph to save.".to_owned()),
                    }
                }
            };
            match outcome {
                Ok(msg) => {
                    ui.set_gr_save_error(false);
                    ui.set_gr_save_status(msg.into());
                }
                Err(msg) => {
                    ui.set_gr_save_error(true);
                    ui.set_gr_save_status(msg.into());
                }
            }
        });
        ui.on_a_toggle_members(move || {
            let Some(ui) = weak.upgrade() else { return };
            let show_all = !ui.get_a_show_all_members();
            ui.set_a_show_all_members(show_all);
            let rows = ANALYZE_STEPS.with(|s| visible_steps(&s.borrow(), show_all));
            ui.set_a_explanation(slint::ModelRc::new(slint::VecModel::from(rows)));
        });
    }
    {
        let weak = ui.as_weak();
        ui.on_pick_analyze_suggestion(move |name, sid| {
            let Some(ui) = weak.upgrade() else { return };
            ui.set_a_name(name.clone());
            ui.set_a_suggestions(empty_suggestion_model());
            ui.set_a_search_status("".into());
            // A live directory hit already carries its SID — fill it directly
            // and skip the LSA lookup, which cannot resolve a remote-domain
            // sAMAccountName from the local host. A local entry has an empty
            // sid and falls back to the LSA resolve below.
            if !sid.is_empty() {
                ui.set_a_sid(sid);
                ui.set_a_name_error("".into());
                return;
            }
            let name_str = name.to_string();
            resolve_name_to_sid(
                &name_str,
                |sid| ui.set_a_sid(sid.into()),
                |err| ui.set_a_name_error(err.into()),
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
        ui.on_search_directory_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let query = ui.get_a_name().to_string();
            if query.trim().is_empty() {
                ui.set_a_search_status(
                    "Enter a name (or part of one) to search the directory.".into(),
                );
                return;
            }
            let Some(ldap) = LdapParams::from_mode(
                ui.get_a_ldap_mode(),
                ui.get_a_ldap_server().to_string(),
                ui.get_a_ldap_base_dn().to_string(),
                ui.get_a_ldap_bind_dn().to_string(),
                ui.get_a_ldap_password().to_string(),
                ui.get_a_ldap_timeout(),
            ) else {
                ui.set_a_search_status(
                    "Directory search needs an LDAP mode (LDAPS / LDAP / Global Catalog / Signed). Select one above."
                        .into(),
                );
                return;
            };
            ui.set_a_name_error("".into());
            ui.set_a_search_status("Searching the directory…".into());
            if let Err(e) = search_tx.send(WorkerRequest::SearchIdentity { query, ldap }) {
                ui.set_a_search_status(format!("Worker not reachable: {e}").into());
            }
        });
    }

    // Groups tab: same live suggestion list as Analyze, from the same cache.
    {
        let weak = ui.as_weak();
        ui.on_groups_name_edited(move |query| {
            let Some(ui) = weak.upgrade() else { return };
            // Members direction expects a group — suggest only groups then.
            let groups_only = ui.get_g_direction() == 1;
            ui.set_g_suggestions(filter_suggestions_model_kinds(query.as_str(), groups_only));
        });
    }
    {
        let weak = ui.as_weak();
        ui.on_pick_groups_suggestion(move |name| {
            let Some(ui) = weak.upgrade() else { return };
            // The Groups view resolves on "Show groups", so picking only fills
            // the field and closes the list — no eager SID lookup needed.
            ui.set_g_identity(name);
            ui.set_g_suggestions(empty_suggestion_model());
        });
    }

    let analyze_tx = req_tx.clone();
    let weak = ui.as_weak();
    ui.on_analyze_clicked(move || {
        let req_tx = &analyze_tx;
        let Some(ui) = weak.upgrade() else { return };
        let path = ui.get_a_path().to_string();
        if path.trim().is_empty() {
            ui.set_a_status("Path is required.".into());
            ui.set_a_status_is_error(true);
            return;
        }

        // Identity: the Resolved-SID field takes precedence when set; otherwise
        // the RAW identity (name / DOMAIN\user / UPN / SID) is sent to the
        // worker, which dispatches it — with LDAP configured the principal
        // pipeline resolves a name itself, otherwise the local LSA/SAM path
        // does. No LSA pre-resolve here: it used to abort on identities only
        // LDAP can resolve, even with a sufficient LDAP mode configured
        // (review 2026-07-01 deep pass, finding 1). The "🔍 Resolve SID"
        // button remains the explicit LSA preview.
        let mut identity = ui.get_a_sid().to_string();
        if identity.trim().is_empty() {
            identity = ui.get_a_name().to_string();
            if identity.trim().is_empty() {
                ui.set_a_status("Path and identity are required.".into());
                ui.set_a_status_is_error(true);
                return;
            }
            ui.set_a_name_error("".into());
        }

        // LDAP mode: 0 = off (SAM/LSA), 1 = LDAPS, 2 = plain LDAP,
        // 3 = Global Catalog (LDAPS 3269). Mapping lives in
        // LdapParams::from_mode so it is unit-tested without the UI.
        let ldap = LdapParams::from_mode(
            ui.get_a_ldap_mode(),
            ui.get_a_ldap_server().to_string(),
            ui.get_a_ldap_base_dn().to_string(),
            ui.get_a_ldap_bind_dn().to_string(),
            ui.get_a_ldap_password().to_string(),
            ui.get_a_ldap_timeout(),
        )
        .map(|l| {
            l.with_trust(
                ui.get_a_trust_enabled(),
                ui.get_a_trust_server().to_string(),
                ui.get_a_trust_base_dn().to_string(),
                ui.get_a_trust_bind_dn().to_string(),
                ui.get_a_trust_password().to_string(),
            )
        });

        let (smb_server, share_name) = if ui.get_a_smb_enabled() {
            (
                Some(ui.get_a_smb_server().to_string()),
                Some(ui.get_a_smb_share().to_string()),
            )
        } else {
            (None, None)
        };

        ui.set_a_is_running(true);
        ui.set_a_status("Analysis running...".into());
        ui.set_a_status_is_error(false);
        ui.set_a_rights_label("".into());
        ui.set_a_mask_hex("".into());
        ui.set_a_share_line("".into());
        ui.set_a_explanation(slint::ModelRc::new(slint::VecModel::<StepVm>::default()));
        clear_graph(&ui, "Analysis running — the graph follows its result.");

        if let Err(e) = req_tx.send(WorkerRequest::Analyze {
            path,
            identity,
            ldap,
            smb_server,
            share_name,
        }) {
            ui.set_a_is_running(false);
            ui.set_a_status(format!("Worker not reachable: {e}").into());
            ui.set_a_status_is_error(true);
        }
    });

    // "Who has access?" — path-centric trustee view. Needs no SID.
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.on_analyze_trustees_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let path = ui.get_a_path().to_string();
            if path.trim().is_empty() {
                ui.set_a_status("Path is required.".into());
                ui.set_a_status_is_error(true);
                return;
            }
            let (smb_server, share_name) = if ui.get_a_smb_enabled() {
                (
                    Some(ui.get_a_smb_server().to_string()),
                    Some(ui.get_a_smb_share().to_string()),
                )
            } else {
                (None, None)
            };
            ui.set_a_trustees_running(true);
            ui.set_a_has_trustees(false);
            ui.set_a_status("Reading DACL...".into());
            ui.set_a_status_is_error(false);
            if let Err(e) = req_tx.send(WorkerRequest::AnalyzeTrustees {
                path,
                smb_server,
                share_name,
            }) {
                ui.set_a_trustees_running(false);
                ui.set_a_status(format!("Worker not reachable: {e}").into());
                ui.set_a_status_is_error(true);
            }
        });
    }

    // Groups tab — identity → recursive group memberships (no path/ACL).
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.on_groups_resolve_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let identity = ui.get_g_identity().to_string();
            if identity.trim().is_empty() {
                ui.set_g_status("Identity is required.".into());
                ui.set_g_status_is_error(true);
                return;
            }
            let ldap = LdapParams::from_mode(
                ui.get_g_ldap_mode(),
                ui.get_g_ldap_server().to_string(),
                ui.get_g_ldap_base_dn().to_string(),
                ui.get_g_ldap_bind_dn().to_string(),
                ui.get_g_ldap_password().to_string(),
                ui.get_g_ldap_timeout(),
            )
            .map(|l| {
                l.with_trust(
                    ui.get_g_trust_enabled(),
                    ui.get_g_trust_server().to_string(),
                    ui.get_g_trust_base_dn().to_string(),
                    ui.get_g_trust_bind_dn().to_string(),
                    ui.get_g_trust_password().to_string(),
                )
            });
            let members_direction = ui.get_g_direction() == 1;
            ui.set_g_is_running(true);
            ui.set_g_has_result(false);
            ui.set_g_status(
                if members_direction {
                    "Enumerating group members..."
                } else {
                    "Resolving group memberships..."
                }
                .into(),
            );
            ui.set_g_status_is_error(false);
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
                ui.set_g_is_running(false);
                ui.set_g_status(format!("Worker not reachable: {e}").into());
                ui.set_g_status_is_error(true);
            }
        });
    }

    // Trusts tab — the domain's trust inventory (read-only, L4).
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.on_trusts_list_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            // The Trusts selector has no "Off" entry (LDAP is mandatory), so
            // its index 0–3 maps onto `from_mode`'s LDAP modes 1–4.
            let ldap = LdapParams::from_mode(
                ui.get_t_ldap_mode() + 1,
                ui.get_t_ldap_server().to_string(),
                ui.get_t_ldap_base_dn().to_string(),
                ui.get_t_ldap_bind_dn().to_string(),
                ui.get_t_ldap_password().to_string(),
                ui.get_t_ldap_timeout(),
            );
            ui.set_t_is_running(true);
            ui.set_t_has_result(false);
            ui.set_t_status("Reading trusts...".into());
            ui.set_t_status_is_error(false);
            if let Err(e) = req_tx.send(WorkerRequest::ListTrusts { ldap }) {
                ui.set_t_is_running(false);
                ui.set_t_status(format!("Worker not reachable: {e}").into());
                ui.set_t_status_is_error(true);
            }
        });
    }

    // Shares tab — a server's SMB shares and their share-level DACL.
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.on_shares_list_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let server = ui.get_sh_server().to_string();
            if server.trim().is_empty() {
                ui.set_sh_status("Server is required.".into());
                ui.set_sh_status_is_error(true);
                return;
            }
            ui.set_sh_is_running(true);
            ui.set_sh_has_result(false);
            ui.set_sh_status("Listing shares...".into());
            ui.set_sh_status_is_error(false);
            if let Err(e) = req_tx.send(WorkerRequest::ListShares { server }) {
                ui.set_sh_is_running(false);
                ui.set_sh_status(format!("Worker not reachable: {e}").into());
                ui.set_sh_status_is_error(true);
            }
        });
    }
}

fn handle_trusts_done(ui: &MainWindow, result: Result<Vec<TrustRow>, String>) {
    ui.set_t_is_running(false);
    match result {
        Ok(rows) => {
            let flagged = rows
                .iter()
                .filter(|t| t.sid_filtering || t.selective_auth)
                .count();
            let status = if flagged > 0 {
                format!(
                    "{} trust(s) — {flagged} with SID filtering or Selective Authentication",
                    rows.len()
                )
            } else {
                format!("{} trust(s)", rows.len())
            };
            ui.set_t_status(status.into());
            ui.set_t_status_is_error(false);
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
                })
                .collect();
            ui.set_t_trusts(slint::ModelRc::new(slint::VecModel::from(vms)));
            ui.set_t_has_result(true);
        }
        Err(e) => {
            ui.set_t_has_result(false);
            ui.set_t_status(e.into());
            ui.set_t_status_is_error(true);
        }
    }
}

fn handle_shares_done(ui: &MainWindow, result: Result<SharesViewData, String>) {
    ui.set_sh_is_running(false);
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
            ui.set_sh_status(status.into());
            // Read failures are part of the result, not a hard error — but
            // they must not look like a clean run.
            ui.set_sh_status_is_error(!data.errors.is_empty());
            ui.set_sh_result_server(data.server.into());
            ui.set_sh_admin_count(data.admin_count);
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
            ui.set_sh_shares(slint::ModelRc::new(slint::VecModel::from(vms)));
            let errors: Vec<slint::SharedString> =
                data.errors.into_iter().map(|e| e.into()).collect();
            ui.set_sh_errors(slint::ModelRc::new(slint::VecModel::from(errors)));
            ui.set_sh_has_result(true);
        }
        Err(e) => {
            ui.set_sh_has_result(false);
            ui.set_sh_status(e.into());
            ui.set_sh_status_is_error(true);
        }
    }
}

fn handle_trustees_done(ui: &MainWindow, result: Result<Vec<TrusteeRow>, String>) {
    ui.set_a_trustees_running(false);
    match result {
        Ok(rows) => {
            let vms: Vec<TrusteeRowVm> = rows
                .into_iter()
                .map(|r| {
                    let kind_color = match r.kind.as_str() {
                        "Allow" => slint::Color::from_rgb_u8(0x27, 0x8d, 0x4f),
                        "Deny" => slint::Color::from_rgb_u8(0xc0, 0x39, 0x2b),
                        _ => slint::Color::from_rgb_u8(0x6c, 0x7a, 0x89),
                    };
                    TrusteeRowVm {
                        display_name: r.display_name.into(),
                        sid: r.sid.into(),
                        kind: r.kind.into(),
                        kind_color,
                        rights_label: r.rights_label.into(),
                        mask_hex: r.mask_hex.into(),
                        source: r.source.into(),
                        applies_to: r.applies_to.into(),
                        category: r.category.into(),
                    }
                })
                .collect();
            let len = vms.len();
            ui.set_a_trustees(slint::ModelRc::new(slint::VecModel::from(vms)));
            ui.set_a_has_trustees(true);
            ui.set_a_status(format!("{} ACE entries found on this path.", len).into());
            ui.set_a_status_is_error(false);
        }
        Err(e) => {
            ui.set_a_has_trustees(false);
            ui.set_a_status(format!("Trustee evaluation failed: {e}").into());
            ui.set_a_status_is_error(true);
        }
    }
}

/// Populates the Groups tab from a finished membership resolution.
fn handle_groups_done(ui: &MainWindow, result: Result<GroupsViewData, String>) {
    ui.set_g_is_running(false);
    match result {
        Ok(data) => {
            ui.set_g_has_result(true);
            ui.set_g_status_is_error(false);
            // Tie the labels to what was actually computed, not the current
            // toggle (the user may flip the toggle before re-running).
            ui.set_g_result_is_members(data.is_members);
            let status = if data.is_members {
                let via_primary = data.total - data.direct;
                format!(
                    "{} member(s) — {} direct, {} via primaryGroupID",
                    data.total, data.direct, via_primary
                )
            } else {
                format!("{} group(s) — {} direct", data.total, data.direct)
            };
            ui.set_g_status(status.into());
            ui.set_g_identity_label(data.identity_label.into());
            ui.set_g_identity_sid(data.identity_sid.into());
            // No enabled/disabled status for non-account kinds (groups): show
            // just the kind rather than a meaningless "Active".
            let meta = if data.status.is_empty() {
                data.kind.clone()
            } else {
                format!("{} \u{00B7} {}", data.status, data.kind)
            };
            ui.set_g_identity_meta(meta.into());
            ui.set_g_ad_connected(data.ad_connected);
            ui.set_g_sid_history(data.sid_history_count);
            ui.set_g_total(data.total);
            ui.set_g_direct(data.direct);

            ui.set_g_has_privileged(!data.privileged.is_empty());
            let priv_model: Vec<slint::SharedString> =
                data.privileged.into_iter().map(|p| p.into()).collect();
            ui.set_g_privileged(slint::ModelRc::new(slint::VecModel::from(priv_model)));

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
            ui.set_g_groups(slint::ModelRc::new(slint::VecModel::from(group_vms)));

            let diag_vms: Vec<DiagnosticVm> = data
                .diagnostics
                .into_iter()
                .map(|d| DiagnosticVm {
                    text: d.text.into(),
                    level: d.level,
                })
                .collect();
            ui.set_g_diagnostics(slint::ModelRc::new(slint::VecModel::from(diag_vms)));
        }
        Err(e) => {
            ui.set_g_has_result(false);
            ui.set_g_status(e.into());
            ui.set_g_status_is_error(true);
        }
    }
}

/// The memberships no ACE on this object names, for the line under the
/// graph — empty when there are none.
fn further_groups_text(groups: &[String]) -> String {
    if groups.is_empty() {
        return String::new();
    }
    // Names only — the SIDs are in the boxes ("Show all groups"), the
    // Analyze path and the Groups tab.
    let names: Vec<&str> = groups
        .iter()
        .map(|g| match g.rfind(" (S-") {
            Some(i) => &g[..i],
            None => g.as_str(),
        })
        .collect();
    format!(
        "Further groups of the account — no ACE on this object names them, so they do not change this result ({}): {}",
        names.len(),
        names.join(" · ")
    )
}

/// ADR 0077: no graph shown, with the reason why.
fn clear_graph(ui: &MainWindow, caption: &str) {
    GRAPH_RESULT.with(|g| *g.borrow_mut() = None);
    ui.set_gr_further_groups("".into());
    ui.set_gr_has_graph(false);
    ui.set_gr_image(slint::Image::default());
    ui.set_gr_image_dark(slint::Image::default());
    ui.set_gr_texts(slint::ModelRc::new(
        slint::VecModel::<GraphTextVm>::default(),
    ));
    ui.set_gr_nodes(slint::ModelRc::new(
        slint::VecModel::<GraphNodeVm>::default(),
    ));
    ui.set_gr_selected(-1);
    ui.set_gr_detail("".into());
    ui.set_gr_caption(caption.into());
}

/// `#rrggbb` → a Slint colour (the graph palette is fixed hex).
fn hex_colour(hex: &str) -> slint::Color {
    let v = u32::from_str_radix(hex.trim_start_matches('#'), 16).unwrap_or(0x00_80_80_80);
    slint::Color::from_rgb_u8((v >> 16) as u8, (v >> 8) as u8, v as u8)
}

/// ADR 0081: writes a saved permission graph — the path validated like a
/// report export (existing directory, `.svg` only), never overwriting a file
/// (`create_new` also covers a file created between check and write).
fn save_graph_svg(path: &str, svg: &str) -> Result<String, String> {
    use std::io::Write as _;
    use validation::export_path::{validate_svg_export_path, ExportPathStatus};
    let status = validate_svg_export_path(path).map_err(|e| format!("Invalid file: {e}"))?;
    if let ExportPathStatus::Exists(p) = &status {
        return Err(format!(
            "Target file already exists: {}. Pick a different name or delete the file first.",
            p.0.display()
        ));
    }
    let target = status.path().0.clone();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
        .map_err(|e| format!("Could not create {}: {e}", target.display()))?;
    file.write_all(svg.as_bytes())
        .map_err(|e| format!("Could not write {}: {e}", target.display()))?;
    Ok(format!("Graph saved: {}", target.display()))
}

/// ADR 0077: the Graph tab shows the permission graph of this result —
/// the layout from `viz`, the same one the HTML report embeds as SVG. The
/// shapes come as a text-free SVG and the texts are drawn natively on top,
/// at the layout's coordinates. No graph is drawn for a result without a
/// trace; a render failure is said, not hidden.
fn apply_graph(ui: &MainWindow, perm: &EffectivePermission) {
    GRAPH_RESULT.with(|g| *g.borrow_mut() = Some(perm.clone()));
    // A new result: nothing selected, no stale save message.
    ui.set_gr_selected(-1);
    ui.set_gr_save_status("".into());
    draw_graph(ui, perm);
}

/// Draws `perm` with the current "Show all groups" setting and selection —
/// the shapes in both palettes (Slint picks by `Theme.dark`), the texts with
/// both colours, and every box as a click target (ADR 0081).
fn draw_graph(ui: &MainWindow, perm: &EffectivePermission) {
    let opts = viz::GraphOptions {
        all_groups: ui.get_gr_all_groups(),
        caption: false,
    };
    let Some(graph) = viz::permission_graph_with(perm, opts) else {
        clear_graph(
            ui,
            "No graph for this result: no ACE on this object reaches the account or its groups. The permission path in the Analyze tab explains the result (for example a missing or empty DACL).",
        );
        return;
    };
    let boxes = graph.node_boxes();
    let selected = usize::try_from(ui.get_gr_selected())
        .ok()
        .filter(|i| *i < boxes.len());
    let render = |dark: bool| viz::RenderOptions {
        dark,
        highlight: selected,
        responsive: false,
    };
    let light =
        slint::Image::load_from_svg_data(graph.to_svg_shapes_with(&render(false)).as_bytes());
    let dark = slint::Image::load_from_svg_data(graph.to_svg_shapes_with(&render(true)).as_bytes());
    match (light, dark) {
        (Ok(light), Ok(dark)) => {
            ui.set_gr_image(light);
            ui.set_gr_image_dark(dark);
            let lit = graph.route_nodes(selected);
            let texts: Vec<GraphTextVm> = graph
                .texts
                .iter()
                .map(|t| GraphTextVm {
                    x: t.x as f32,
                    // Baseline (SVG) to the top of the text box: one font
                    // size up is close enough for 12 px Segoe UI.
                    y: (t.baseline - viz::FONT_SIZE) as f32,
                    text: t.text.as_str().into(),
                    bold: t.style.bold(),
                    color_light: hex_colour(t.style.colour_in(false)),
                    color_dark: hex_colour(t.style.colour_in(true)),
                    faded: t.node.is_some_and(|i| !lit.get(i).copied().unwrap_or(true)),
                })
                .collect();
            ui.set_gr_texts(slint::ModelRc::new(slint::VecModel::from(texts)));
            let nodes: Vec<GraphNodeVm> = boxes
                .iter()
                .enumerate()
                .map(|(i, b)| GraphNodeVm {
                    x: b.x as f32,
                    y: b.y as f32,
                    w: b.w as f32,
                    h: b.h as f32,
                    index: i32::try_from(i).unwrap_or(i32::MAX),
                })
                .collect();
            ui.set_gr_nodes(slint::ModelRc::new(slint::VecModel::from(nodes)));
            ui.set_gr_selected(selected.map_or(-1, |i| i32::try_from(i).unwrap_or(-1)));
            ui.set_gr_detail(
                selected
                    .map(|i| boxes[i].title.clone())
                    .unwrap_or_default()
                    .into(),
            );
            // The list is for the compact view; with every group drawn it
            // would only repeat the boxes.
            let further = if opts.all_groups {
                String::new()
            } else {
                further_groups_text(&graph.further_groups)
            };
            ui.set_gr_further_groups(further.into());
            ui.set_gr_has_graph(true);
            ui.set_gr_caption(
                format!(
                    "Permission graph — {} on {}",
                    perm.identity
                        .name
                        .as_deref()
                        .unwrap_or(&perm.identity.sid.0),
                    perm.path.0
                )
                .into(),
            );
        }
        (Err(e), _) | (_, Err(e)) => {
            tracing::warn!("permission graph could not be rendered: {e}");
            clear_graph(
                ui,
                "The graph could not be rendered; the permission path in the Analyze tab is complete. The HTML report embeds the graph as well.",
            );
        }
    }
}

fn apply_analyze_result(
    ui: &MainWindow,
    result: Result<EffectivePermission, String>,
    scan_run_id: Option<String>,
    persistence_error: Option<String>,
) {
    ui.set_a_is_running(false);
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
            ui.set_a_rights_label(rights_label.into());
            ui.set_a_mask_hex(format!("0x{effective_raw:08X}").into());
            ui.set_a_share_line(format_share_line(&perm).into());
            ui.set_a_show_all_members(false);
            let all = step_vms(&perm.path_explanation.steps);
            ui.set_a_explanation(slint::ModelRc::new(slint::VecModel::from(visible_steps(
                &all, false,
            ))));
            ANALYZE_STEPS.with(|s| *s.borrow_mut() = all);
            apply_graph(ui, &perm);
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
            ui.set_a_diagnostics(slint::ModelRc::new(slint::VecModel::from(diagnostics)));
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
            ui.set_a_status(status.into());
            ui.set_a_status_is_error(is_error);
        }
        Err(e) => {
            // Clear stale markers from a previous run — a failed analysis
            // must not leave the last result's diagnostics on screen.
            ui.set_a_diagnostics(slint::ModelRc::new(
                slint::VecModel::<DiagnosticVm>::default(),
            ));
            clear_graph(ui, "No graph: the last analysis failed.");
            ui.set_a_status(format!("Analysis failed: {e}").into());
            ui.set_a_status_is_error(true);
        }
    }
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

// ---------------------------------------------------------------------------
// Scan tab wiring
// ---------------------------------------------------------------------------

fn wire_scan_tab(
    ui: &MainWindow,
    req_tx: std::sync::mpsc::Sender<WorkerRequest>,
    cancel: CancellationToken,
) {
    // Name → SID helper (analogous to the Analyze tab).
    {
        let weak = ui.as_weak();
        ui.on_resolve_scan_name_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let name = ui.get_s_name().to_string();
            resolve_name_to_sid(
                &name,
                |sid| ui.set_s_sid(sid.into()),
                |err| ui.set_s_name_error(err.into()),
            );
        });
    }

    // Live search analogous to the Analyze tab.
    {
        let weak = ui.as_weak();
        ui.on_scan_name_edited(move |query| {
            let Some(ui) = weak.upgrade() else { return };
            ui.set_s_suggestions(filter_suggestions_model(query.as_str()));
        });
    }

    {
        let weak = ui.as_weak();
        ui.on_pick_scan_suggestion(move |name| {
            let Some(ui) = weak.upgrade() else { return };
            ui.set_s_name(name.clone());
            ui.set_s_suggestions(empty_suggestion_model());
            let name_str = name.to_string();
            resolve_name_to_sid(
                &name_str,
                |sid| ui.set_s_sid(sid.into()),
                |err| ui.set_s_name_error(err.into()),
            );
        });
    }

    // scan-clicked
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        let cancel = cancel.clone();
        ui.on_scan_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let root = ui.get_s_root().to_string();
            if root.trim().is_empty() {
                ui.set_s_status("Root path is required.".into());
                ui.set_s_status_is_error(true);
                return;
            }

            // Identity: the Resolved-SID field takes precedence when set;
            // otherwise the RAW identity goes to the worker, which dispatches
            // it (LDAP principal pipeline or local LSA/SAM) — same as the
            // Analyze and Groups tabs (review 2026-07-01 deep pass, finding 1).
            let mut identity = ui.get_s_sid().to_string();
            if identity.trim().is_empty() {
                identity = ui.get_s_name().to_string();
                if identity.trim().is_empty() {
                    ui.set_s_status("Root path and identity are required.".into());
                    ui.set_s_status_is_error(true);
                    return;
                }
                ui.set_s_name_error("".into());
            }

            let max_depth = if ui.get_s_limit_depth() {
                let d = ui.get_s_max_depth();
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
                ui.get_s_ldap_mode(),
                ui.get_s_ldap_server().to_string(),
                ui.get_s_ldap_base_dn().to_string(),
                ui.get_s_ldap_bind_dn().to_string(),
                ui.get_s_ldap_password().to_string(),
                ui.get_s_ldap_timeout(),
            )
            .map(|l| {
                l.with_trust(
                    ui.get_s_trust_enabled(),
                    ui.get_s_trust_server().to_string(),
                    ui.get_s_trust_base_dn().to_string(),
                    ui.get_s_trust_bind_dn().to_string(),
                    ui.get_s_trust_password().to_string(),
                )
            });

            let (smb_server, share_name) = if ui.get_s_smb_enabled() {
                (
                    Some(ui.get_s_smb_server().to_string()),
                    Some(ui.get_s_smb_share().to_string()),
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

            ui.set_s_is_running(true);
            ui.set_s_done(false);
            ui.set_s_status("Scan running...".into());
            ui.set_s_status_is_error(false);
            ui.set_s_total(0);
            ui.set_s_error_count(0);
            ui.set_s_scan_run_id("".into());
            ui.set_s_export_message("".into());
            ui.set_s_export_is_error(false);
            ui.set_s_rows(empty_row_model());
            ui.set_s_errors(empty_error_model());
            ui.set_s_risks(empty_risk_model());

            if let Err(e) = req_tx.send(WorkerRequest::Scan {
                root,
                identity,
                max_depth,
                smb_server,
                share_name,
                ldap,
            }) {
                ui.set_s_is_running(false);
                ui.set_s_status(format!("Worker not reachable: {e}").into());
                ui.set_s_status_is_error(true);
            }
        });
    }

    // scan-cancel-clicked
    {
        let cancel = cancel.clone();
        ui.on_scan_cancel_clicked(move || {
            cancel.cancel();
        });
    }

    // gefilterten View neu.
    // scan-row-toggle: flips the expanded column of a row. The master
    // list lives in SCAN_STATE; we re-render the filtered view
    // afterwards.
    {
        let weak = ui.as_weak();
        ui.on_scan_row_toggle(move |index| {
            let Some(ui) = weak.upgrade() else { return };
            let filter = ui.get_s_filter().to_string();
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
        ui.on_scan_filter_changed(move || {
            let Some(ui) = weak.upgrade() else { return };
            refresh_rows(&ui);
        });
    }

    // export-clicked
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.on_export_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let output_path = ui.get_s_export_path().to_string();
            if output_path.trim().is_empty() {
                ui.set_s_export_message("Please specify a target file.".into());
                ui.set_s_export_is_error(true);
                return;
            }
            // GUI-2: tell the user which format the extension selects
            // BEFORE the write — the export is format-aware now, so a
            // .csv target must not silently look like the HTML report.
            match ReportFormat::from_path(std::path::Path::new(output_path.trim())) {
                Ok(fmt) => {
                    ui.set_s_export_message(
                        format!("Export running... ({})", fmt.description()).into(),
                    );
                    ui.set_s_export_is_error(false);
                }
                Err(e) => {
                    ui.set_s_export_message(e.into());
                    ui.set_s_export_is_error(true);
                    return;
                }
            }
            if let Err(e) = req_tx.send(WorkerRequest::ExportReport { output_path }) {
                ui.set_s_export_message(format!("Worker not reachable: {e}").into());
                ui.set_s_export_is_error(true);
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
    let filter = ui.get_s_filter().to_string().trim().to_lowercase();
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
    ui.set_s_rows(slint::ModelRc::new(slint::VecModel::from(filtered)));
}

fn handle_scan_item(ui: &MainWindow, row: ScanRow) {
    let mask_hex = format!("0x{:08X}", row.mask_raw);
    // Convert the trustee list to the slint model — same colour logic as the
    // Analyze tab (Allow green, Deny red, anything else grey).
    let trustee_vms: Vec<TrusteeRowVm> = row
        .trustees
        .into_iter()
        .map(|t| {
            let kind_color = match t.kind.as_str() {
                "Allow" => slint::Color::from_rgb_u8(0x27, 0x8d, 0x4f),
                "Deny" => slint::Color::from_rgb_u8(0xc0, 0x39, 0x2b),
                _ => slint::Color::from_rgb_u8(0x6c, 0x7a, 0x89),
            };
            TrusteeRowVm {
                display_name: t.display_name.into(),
                sid: t.sid.into(),
                kind: t.kind.into(),
                kind_color,
                rights_label: t.rights_label.into(),
                mask_hex: t.mask_hex.into(),
                source: t.source.into(),
                applies_to: t.applies_to.into(),
                category: t.category.into(),
            }
        })
        .collect();
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
    ui.set_s_total(total);
    refresh_rows(ui);
}

fn handle_scan_error(ui: &MainWindow, path: String, message: String) {
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
    ui.set_s_error_count(count);
    ui.set_s_errors(slint::ModelRc::new(slint::VecModel::from(errors)));
}

fn handle_scan_done(
    ui: &MainWindow,
    total: usize,
    errors: usize,
    scan_run_id: Option<String>,
    persistence_error: Option<String>,
    cancelled: bool,
) {
    ui.set_s_is_running(false);
    ui.set_s_done(true);
    ui.set_s_total(total as i32);
    ui.set_s_error_count(errors as i32);
    ui.set_s_scan_run_id(scan_run_id.unwrap_or_default().into());

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
    ui.set_s_status(parts.join(" ").into());
    ui.set_s_status_is_error(is_error);
}

fn handle_risk_findings(ui: &MainWindow, findings: Vec<RiskFinding>) {
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
    ui.set_s_risks(slint::ModelRc::new(slint::VecModel::from(vms)));
}

fn handle_export_done(ui: &MainWindow, result: Result<(), String>) {
    match result {
        Ok(()) => {
            ui.set_s_export_message("✓ Export successful.".into());
            ui.set_s_export_is_error(false);
        }
        Err(e) => {
            ui.set_s_export_message(format!("✗ Export failed: {e}").into());
            ui.set_s_export_is_error(true);
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

// ---------------------------------------------------------------------------
// Delta tab wiring
// ---------------------------------------------------------------------------

fn wire_delta_tab(ui: &MainWindow, req_tx: std::sync::mpsc::Sender<WorkerRequest>) {
    // delta-load-runs-clicked: asks the worker for the scan history. The
    // answer arrives asynchronously as WorkerEvent::ScanRunsLoaded.
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.on_delta_load_runs_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            ui.set_d_is_loading(true);
            ui.set_d_status("Loading scan history...".into());
            ui.set_d_status_is_error(false);
            if let Err(e) = req_tx.send(WorkerRequest::ListScanRuns) {
                ui.set_d_is_loading(false);
                ui.set_d_status(format!("Worker not reachable: {e}").into());
                ui.set_d_status_is_error(true);
            }
        });
    }

    // delta-pick-old / delta-pick-new: exclusive toggle — clicking a row
    // sets that run as "old" or "new" and clears the corresponding flag
    // on every other row. Clicking the same row again clears the
    // selection.
    {
        let weak = ui.as_weak();
        ui.on_delta_pick_old(move |id| {
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
            refresh_delta_runs(&ui);
        });
    }
    {
        let weak = ui.as_weak();
        ui.on_delta_pick_new(move |id| {
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
            refresh_delta_runs(&ui);
        });
    }

    // delta-compare-clicked: read the two ids and dispatch to the worker.
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.on_delta_compare_clicked(move || {
            let Some(ui) = weak.upgrade() else { return };
            let (old_id, new_id) = DELTA_STATE.with(|s| {
                let s = s.borrow();
                (s.selected_old.clone(), s.selected_new.clone())
            });
            let (Some(old_id), Some(new_id)) = (old_id, new_id) else {
                ui.set_d_status("Please select one scan run for 'Old' and one for 'New'.".into());
                ui.set_d_status_is_error(true);
                return;
            };
            if old_id == new_id {
                ui.set_d_status("'Old' and 'New' must be different runs.".into());
                ui.set_d_status_is_error(true);
                return;
            }
            ui.set_d_is_loading(true);
            ui.set_d_status("Comparing runs...".into());
            ui.set_d_status_is_error(false);
            ui.set_d_has_result(false);
            if let Err(e) = req_tx.send(WorkerRequest::ComputeDelta {
                old_run_id: old_id,
                new_run_id: new_id,
            }) {
                ui.set_d_is_loading(false);
                ui.set_d_status(format!("Worker not reachable: {e}").into());
                ui.set_d_status_is_error(true);
            }
        });
    }

    // delta-delete-confirmed: fired by the confirmation dialog after the
    // follow-up actions (clearing selection, reloading the list) are
    // handled by the event handler on WorkerEvent::ScanRunDeleted.
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.on_delta_delete_confirmed(move |id| {
            let Some(ui) = weak.upgrade() else { return };
            let id_str = id.to_string();
            if id_str.is_empty() {
                return;
            }
            ui.set_d_status("Deleting scan run...".into());
            ui.set_d_status_is_error(false);
            if let Err(e) = req_tx.send(WorkerRequest::DeleteScanRun { run_id: id_str }) {
                ui.set_d_status(format!("Worker not reachable: {e}").into());
                ui.set_d_status_is_error(true);
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
        ui.on_delta_show_errors(move |run_id, label| {
            let Some(ui) = weak.upgrade() else { return };
            let id_str = run_id.to_string();
            if id_str.is_empty() {
                return;
            }
            ui.set_d_run_errors(slint::ModelRc::new(slint::VecModel::<RunErrorVm>::default()));
            ui.set_d_errors_title(label);
            if let Err(e) = req_tx.send(WorkerRequest::ListRunErrors { run_id: id_str }) {
                ui.set_d_errors_title("".into());
                ui.set_d_status(format!("Worker not reachable: {e}").into());
                ui.set_d_status_is_error(true);
            }
        });
    }

    // Manual update check (ADR 0061): send the user-edited source to the
    // worker; validation and the network call happen there so the GUI
    // never blocks on the 10-second timeout.
    {
        let weak = ui.as_weak();
        let req_tx = req_tx.clone();
        ui.on_info_check_update(move |source| {
            let Some(ui) = weak.upgrade() else { return };
            ui.set_i_update_status("Checking…".into());
            ui.set_i_update_status_is_error(false);
            if let Err(e) = req_tx.send(WorkerRequest::CheckUpdate {
                source: source.to_string(),
            }) {
                ui.set_i_update_status(format!("Worker not reachable: {e}").into());
                ui.set_i_update_status_is_error(true);
            }
        });
    }
}

fn refresh_delta_runs(ui: &MainWindow) {
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
    ui.set_d_scan_runs(slint::ModelRc::new(slint::VecModel::from(vms)));
}

fn handle_scan_runs_loaded(ui: &MainWindow, result: Result<Vec<ScanRunSummary>, String>) {
    ui.set_d_is_loading(false);
    match result {
        Ok(runs) if runs.is_empty() => {
            DELTA_STATE.with(|s| {
                let mut s = s.borrow_mut();
                s.runs.clear();
                s.selected_old = None;
                s.selected_new = None;
            });
            refresh_delta_runs(ui);
            ui.set_d_status("No scan runs stored — run a scan first.".into());
            ui.set_d_status_is_error(false);
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
            refresh_delta_runs(ui);
            ui.set_d_status(
                "Scan runs loaded. Check one for 'Old' and one for 'New', then compare.".into(),
            );
            ui.set_d_status_is_error(false);
        }
        Err(e) => {
            ui.set_d_status(format!("Loading failed: {e}").into());
            ui.set_d_status_is_error(true);
        }
    }
}

/// Reacts to a worker-completed scan-run deletion. Updates the status line,
/// clears local selection state and triggers a fresh history reload so the
/// list is up-to-date without requiring another click on "Load scan history
fn handle_scan_run_deleted(ui: &MainWindow, run_id: &str, result: Result<(), String>) {
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
            refresh_delta_runs(ui);
            ui.set_d_status("Scan run removed.".into());
            ui.set_d_status_is_error(false);
            // If a delta result was still visible in the frame, it might
            // refer to the just-deleted run — hide it to be safe. Same for
            // the per-run error panel.
            ui.set_d_has_result(false);
            ui.set_d_errors_title("".into());
            // Reload the list in background so the GUI state is guaranteed
            // to match the DB.
            REQ_TX.with(|cell| {
                if let Some(tx) = cell.borrow().as_ref() {
                    let _ = tx.send(WorkerRequest::ListScanRuns);
                }
            });
        }
        Err(e) => {
            ui.set_d_status(format!("Delete failed: {e}").into());
            ui.set_d_status_is_error(true);
        }
    }
}

/// Fills the Delta tab's per-run error panel (persistence review
/// 2026-07-26, PS-1). The panel title was already set by the click
/// handler; a load failure closes the panel and surfaces the reason in
/// the tab status instead of leaving a silent "Loading…".
fn handle_run_errors_loaded(ui: &MainWindow, result: Result<Vec<RunErrorRow>, String>) {
    match result {
        Ok(rows) => {
            let vms: Vec<RunErrorVm> = rows
                .into_iter()
                .map(|r| RunErrorVm {
                    path: r.path.into(),
                    message: r.message.into(),
                })
                .collect();
            ui.set_d_run_errors(slint::ModelRc::new(slint::VecModel::from(vms)));
        }
        Err(e) => {
            ui.set_d_errors_title("".into());
            ui.set_d_status(format!("Scan errors could not be loaded: {e}").into());
            ui.set_d_status_is_error(true);
        }
    }
}

/// Renders the manual update-check outcome in the Info tab (ADR 0061).
/// Every path is explicit — up to date, update available (with the
/// release page), or the honest error (offline DC, invalid source).
fn handle_update_check_done(ui: &MainWindow, result: Result<UpdateCheckRow, String>) {
    match result {
        Ok(r) if r.update_available => {
            let mut text = format!("Update available: {} (installed: {}).", r.latest, r.current);
            if let Some(url) = &r.release_url {
                text.push_str(&format!(" Release page: {url}"));
            }
            text.push_str(" Stars downloads and installs nothing — get it from the release page.");
            ui.set_i_update_status(text.into());
            ui.set_i_update_status_is_error(false);
        }
        Ok(r) => {
            ui.set_i_update_status(
                format!("Stars is up to date (installed: {}).", r.current).into(),
            );
            ui.set_i_update_status_is_error(false);
        }
        Err(e) => {
            ui.set_i_update_status(format!("Update check failed: {e}").into());
            ui.set_i_update_status_is_error(true);
        }
    }
}

fn handle_delta_computed(ui: &MainWindow, result: Result<Vec<DeltaRow>, String>) {
    ui.set_d_is_loading(false);
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
            ui.set_d_added_count(added);
            ui.set_d_removed_count(removed);
            ui.set_d_changed_count(changed);
            ui.set_d_rows(slint::ModelRc::new(slint::VecModel::from(vms)));
            ui.set_d_has_result(true);
            ui.set_d_status("Comparison complete.".into());
            ui.set_d_status_is_error(false);
        }
        Err(e) => {
            ui.set_d_has_result(false);
            ui.set_d_status(format!("Comparison failed: {e}").into());
            ui.set_d_status_is_error(true);
        }
    }
}

// ---------------------------------------------------------------------------
// Event pump
// ---------------------------------------------------------------------------

fn pump_worker_events(ui: &MainWindow) {
    EVENT_RX.with(|cell| {
        let borrow = cell.borrow();
        let Some(rx) = borrow.as_ref() else { return };
        while let Ok(event) = rx.try_recv() {
            match event {
                WorkerEvent::AnalyzeDone {
                    result,
                    scan_run_id,
                    persistence_error,
                } => apply_analyze_result(ui, *result, scan_run_id, persistence_error),
                WorkerEvent::ScanItem(row) => handle_scan_item(ui, row),
                WorkerEvent::ScanError { path, message } => handle_scan_error(ui, path, message),
                WorkerEvent::ScanDone {
                    total,
                    errors,
                    scan_run_id,
                    persistence_error,
                    cancelled,
                } => handle_scan_done(ui, total, errors, scan_run_id, persistence_error, cancelled),
                WorkerEvent::RiskFindings(findings) => handle_risk_findings(ui, findings),
                WorkerEvent::ExportDone(result) => handle_export_done(ui, result),
                WorkerEvent::ScanRunsLoaded(result) => handle_scan_runs_loaded(ui, result),
                WorkerEvent::DeltaComputed(result) => handle_delta_computed(ui, result),
                WorkerEvent::ScanRunDeleted { run_id, result } => {
                    handle_scan_run_deleted(ui, &run_id, result)
                }
                WorkerEvent::RunErrorsLoaded(result) => handle_run_errors_loaded(ui, result),
                WorkerEvent::UpdateCheckDone(result) => handle_update_check_done(ui, result),
                WorkerEvent::IdentitiesLoaded(result) => handle_identities_loaded(ui, result),
                WorkerEvent::TrusteesDone(result) => handle_trustees_done(ui, result),
                WorkerEvent::GroupsDone(result) => handle_groups_done(ui, *result),
                WorkerEvent::SharesDone(result) => handle_shares_done(ui, *result),
                WorkerEvent::TrustsDone(result) => handle_trusts_done(ui, result),
                WorkerEvent::SearchResults(result) => handle_search_results(ui, result),
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn empty_suggestion_model() -> slint::ModelRc<IdentitySuggestionVm> {
    slint::ModelRc::new(slint::VecModel::<IdentitySuggestionVm>::from(Vec::<
        IdentitySuggestionVm,
    >::new()))
}

/// Filters the list cached in `IDENTITY_CACHE` against the query string
/// and returns a Slint ModelRc that can be assigned directly to a
/// `[IdentitySuggestionVm]` property. At most `MAX_SUGGESTIONS` entries so
/// the list stays scannable — typing more specifically narrows the
/// results.
const MAX_SUGGESTIONS: usize = 15;

fn filter_suggestions_model(query: &str) -> slint::ModelRc<IdentitySuggestionVm> {
    filter_suggestions_model_kinds(query, false)
}

/// `groups_only` keeps only group suggestions (`G` = domain/local group,
/// `L` = BUILTIN group) — used by the Groups tab's Members direction, where a
/// group is expected and user entries are noise (review 2026-07-03, F5).
fn filter_suggestions_model_kinds(
    query: &str,
    groups_only: bool,
) -> slint::ModelRc<IdentitySuggestionVm> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return empty_suggestion_model();
    }
    let suggestions: Vec<IdentitySuggestionVm> = IDENTITY_CACHE.with(|c| {
        c.borrow()
            .iter()
            .filter(|s| !groups_only || s.kind_icon == "G" || s.kind_icon == "L")
            .filter(|s| {
                s.qualified.to_lowercase().contains(&q) || s.name.to_lowercase().contains(&q)
            })
            .take(MAX_SUGGESTIONS)
            .map(|s| IdentitySuggestionVm {
                name: s.name.clone().into(),
                qualified: s.qualified.clone().into(),
                kind_icon: s.kind_icon.clone().into(),
                description: s.description.clone().into(),
                // Local entries have no pre-resolved SID; picking one runs an
                // LSA lookup (see on_pick_analyze_suggestion).
                sid: slint::SharedString::new(),
            })
            .collect()
    });
    slint::ModelRc::new(slint::VecModel::from(suggestions))
}

/// Builds the picker model from live directory-search hits, reusing the same
/// `IdentitySuggestionVm` rows the local autocomplete uses. Capped at
/// `MAX_SUGGESTIONS` so the list stays scannable. The SID travels in the row
/// so picking a hit fills the SID field directly (no LSA round-trip).
fn suggestions_model_from_search(
    results: &[IdentitySearchResult],
) -> slint::ModelRc<IdentitySuggestionVm> {
    let vms: Vec<IdentitySuggestionVm> = results
        .iter()
        .take(MAX_SUGGESTIONS)
        .map(|r| IdentitySuggestionVm {
            name: r.pick_name().into(),
            qualified: r.display_label().into(),
            kind_icon: r.kind_icon().into(),
            description: r.sid.clone().into(),
            sid: r.sid.clone().into(),
        })
        .collect();
    slint::ModelRc::new(slint::VecModel::from(vms))
}

/// Consumes a live directory search: fills the picker list with the hits and
/// reports the outcome in the `a-search-status` line (match count, empty
/// result, or error). A failed search clears the list but never the fields.
fn handle_search_results(ui: &MainWindow, result: Result<Vec<IdentitySearchResult>, String>) {
    match result {
        Ok(list) => {
            let total = list.len();
            ui.set_a_suggestions(suggestions_model_from_search(&list));
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
            ui.set_a_search_status(msg.into());
        }
        Err(e) => {
            ui.set_a_suggestions(empty_suggestion_model());
            ui.set_a_search_status(format!("Directory search failed: {e}").into());
        }
    }
}

fn handle_identities_loaded(_ui: &MainWindow, result: Result<Vec<IdentitySuggestion>, String>) {
    match result {
        Ok(list) => {
            let count = list.len();
            IDENTITY_CACHE.with(|c| *c.borrow_mut() = list);
            tracing::info!(target: "stars-gui", count, "identity cache populated");
        }
        Err(e) => {
            // Cache stays empty; the live search just shows no
            // because it only uses LookupAccountNameW.
            tracing::warn!(target: "stars-gui", error = %e, "identity enumeration failed — live search disabled");
        }
    }
}

/// Windows-only.
/// Translates a user/group name to a SID via the local LSA
/// (`LookupAccountNameW`). Success calls `on_sid` with the resolved SID,
/// failure calls `on_error` with a short localized message. Empty input
/// is treated as an error ("Bitte Namen eingeben"). On non-Windows the
/// function deliberately does not exist — the entire SAM path is
/// Windows-only.
#[cfg(windows)]
fn resolve_name_to_sid(
    name: &str,
    mut on_sid: impl FnMut(String),
    mut on_error: impl FnMut(String),
) {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        on_error(
            "Please enter a user or group name. \
             Accepted formats: DOMAIN\\user, user@domain.lab, \
             plain sAMAccountName (with LDAP server), or a raw SID (S-1-5-21-…)."
                .to_string(),
        );
        return;
    }
    match ad_resolver::lookup_sid_for_account(None, trimmed) {
        Ok(sid) => {
            on_sid(sid.0);
            on_error(String::new());
        }
        Err(e) => on_error(format!("'{trimmed}' could not be resolved: {e}")),
    }
}

#[cfg(not(windows))]
fn resolve_name_to_sid(
    _name: &str,
    mut _on_sid: impl FnMut(String),
    mut on_error: impl FnMut(String),
) {
    on_error("Name → SID resolution needs Windows (LSA API).".to_string());
}

/// Modal error dialog (Windows) or stderr output (other platforms).
#[cfg(windows)]
fn show_fatal_dialog(title: &str, message: &str) {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, MB_ICONERROR, MB_OK, MB_SETFOREGROUND, MB_TOPMOST,
    };

    fn to_wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let title_w = to_wide(title);
    let msg_w = to_wide(message);
    // SAFETY: Both pointers reference valid, null-terminated UTF-16 buffers
    // that live until the call returns. `hwnd` = 0 is allowed.
    unsafe {
        MessageBoxW(
            0 as _,
            msg_w.as_ptr(),
            title_w.as_ptr(),
            MB_OK | MB_ICONERROR | MB_TOPMOST | MB_SETFOREGROUND,
        );
    }
}

#[cfg(not(windows))]
fn show_fatal_dialog(title: &str, message: &str) {
    eprintln!("{title}\n\n{message}");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// GUI-6 (gui review 2026-07-26): `main.rs` had no tests at all. Most of it
// is the Slint macro and callback wiring, but the pure output formatters
// produce user-facing audit text and are worth pinning — a wrong share
// line is a wrong statement about permissions.

#[cfg(test)]
mod tests {
    use super::{format_share_line, save_graph_svg, severity_visual, step_vms, StepVm};
    use adpa_core::model::{
        AccessMask, EffectivePermission, Identity, IdentityKind, LocalGroupEvalStatus,
        NormalizedPath, PermissionPath, RiskSeverity, ShareEvalStatus, Sid,
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

    /// ADR 0081: a saved graph never overwrites a file, and only `.svg`
    /// is accepted.
    #[test]
    fn save_graph_svg_writes_new_files_only() {
        let dir = std::env::temp_dir();
        let target = dir.join(format!("adpa-graph-{}.svg", uuid::Uuid::new_v4()));
        let path = target.to_str().unwrap();
        let msg = save_graph_svg(path, "<svg/>").unwrap();
        assert!(msg.starts_with("Graph saved"), "{msg}");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "<svg/>");
        let again = save_graph_svg(path, "<svg>other</svg>").unwrap_err();
        assert!(again.contains("already exists"), "{again}");
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "<svg/>",
            "unchanged"
        );
        let _ = std::fs::remove_file(&target);
        let wrong = dir.join("adpa-graph.html");
        assert!(save_graph_svg(wrong.to_str().unwrap(), "<svg/>").is_err());
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
        assert_eq!(super::visible_steps(&vms, false).len(), 3);
        assert_eq!(super::visible_steps(&vms, true).len(), vms.len());
    }
}
