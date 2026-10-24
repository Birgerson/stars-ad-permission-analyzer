// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! adpa-gui — Graphical interface for the AD Permission Analyzer (Slint).
//!
//! Logfile, panic hook and MessageBox fallback are kept from the eframe
//! predecessors — they are independent of the GUI toolkit and reliably
//! surface startup problems on a bare server.
//!
//! This file only starts the GUI: it creates the window, starts the worker,
//! lets every tab wire itself (`tabs/`) and passes the worker's events to
//! the tab they belong to (ADR 0082).

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod identity_input;
mod tabs;
mod view_models;
mod worker;

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::sync::Arc;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::tabs::{analyze, delta, graph, groups, info, scan, shares, trusts};
use crate::worker::{spawn_worker, NotifyFn, WorkerEvent, WorkerRequest};

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

thread_local! {
    static EVENT_RX: RefCell<Option<Receiver<WorkerEvent>>> = const { RefCell::new(None) };
}

fn run_ui(_log_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let ui = MainWindow::new()?;

    // App version from Cargo metadata into the GUI. Without this the
    // HeaderBar version badge stays hidden behind its `if != ""` guard.
    ui.global::<AppState>()
        .set_version(format!("v{}", env!("CARGO_PKG_VERSION")).into());

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

    analyze::wire(&ui, &req_tx);
    graph::wire(&ui);
    groups::wire(&ui, &req_tx);
    scan::wire(&ui, &req_tx, cancel);
    delta::wire(&ui, &req_tx);
    trusts::wire(&ui, &req_tx);
    shares::wire(&ui, &req_tx);
    info::wire(&ui, &req_tx);

    // Pre-load the identity list once so the live search can show
    // suggestions from the first keystroke. If the call fails the GUI
    // keeps running without suggestions — the SID field and "Resolve SID"
    // work without the list.
    let _ = req_tx.send(WorkerRequest::ListIdentities);

    ui.run()?;
    Ok(())
}

/// Hands every pending worker event to the tab it belongs to.
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
                } => analyze::apply_result(ui, *result, scan_run_id, persistence_error),
                WorkerEvent::ScanItem(row) => scan::handle_item(ui, row),
                WorkerEvent::ScanError { path, message } => scan::handle_error(ui, path, message),
                WorkerEvent::ScanDone {
                    total,
                    errors,
                    scan_run_id,
                    persistence_error,
                    cancelled,
                } => {
                    scan::handle_done(ui, total, errors, scan_run_id, persistence_error, cancelled)
                }
                WorkerEvent::RiskFindings(findings) => scan::handle_risk_findings(ui, findings),
                WorkerEvent::ExportDone(result) => scan::handle_export_done(ui, result),
                WorkerEvent::ScanRunsLoaded(result) => delta::handle_runs_loaded(ui, result),
                WorkerEvent::DeltaComputed(result) => delta::handle_computed(ui, result),
                WorkerEvent::ScanRunDeleted { run_id, result } => {
                    delta::handle_run_deleted(ui, &run_id, result)
                }
                WorkerEvent::RunErrorsLoaded(result) => delta::handle_run_errors_loaded(ui, result),
                WorkerEvent::UpdateCheckDone(result) => info::handle_update_check_done(ui, result),
                WorkerEvent::IdentitiesLoaded(result) => {
                    identity_input::handle_identities_loaded(result)
                }
                WorkerEvent::TrusteesDone(result) => analyze::handle_trustees_done(ui, result),
                WorkerEvent::GroupsDone(result) => groups::handle_done(ui, *result),
                WorkerEvent::SharesDone(result) => shares::handle_done(ui, *result),
                WorkerEvent::TrustsDone(result) => trusts::handle_done(ui, result),
                WorkerEvent::SearchResults(result) => analyze::handle_search_results(ui, result),
            }
        }
    });
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
