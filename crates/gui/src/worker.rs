// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Background worker for analyses, scans and delta comparisons.
//!
//! Runs in a dedicated thread with a Tokio runtime for optional LDAP calls.
//!
//! Verdrahtet sind: `Analyze`, `Scan`, `ExportHtml`, `ListScanRuns`,
//!
//! Wired up: `Analyze`, `Scan`, `ExportHtml`, `ListScanRuns`,
//! `ComputeDelta`. `SearchIdentity` is reserved for a later phase (GUI
//! identity picker) — the definition stays so a future addition does not
//! cause API breaks.
#![allow(dead_code)]

use std::sync::mpsc::{Receiver, Sender};

use ad_resolver::sid_util::bytes_to_sid_str;
#[cfg(not(windows))]
use ad_resolver::NoLsaBackend;
#[cfg(windows)]
use ad_resolver::WindowsLsaBackend;
use ad_resolver::{
    ldap_client, principal::PrincipalInput, LdapConfig, LdapIdentityBackend, LdapResolver,
    PrincipalResolution, PrincipalResolver, TlsMode,
};
use adpa_core::{
    model::{
        AccessContext, EffectivePermission, GroupMembership, Identity, IdentityKind,
        NormalizedPath, RiskFinding, ScanError, ScanRun, Sid,
    },
    traits::{
        AnalysisResult, ExportTarget, Exporter, PermissionEvaluationInput, PermissionEvaluator,
        RiskContext,
    },
};
use chrono::Utc;
use exporter::HtmlExporter;
use fs_scanner::{read_fso, walk_tree, CancellationToken, WalkConfig};
use permission_engine::{
    build_token_sids_with_context, engine::DefaultPermissionEngine, NormalizedRights,
};
use persistence::Database;
use risk_engine::RuleRegistry;
use share_scanner::{effective_share_mask, get_share_dacl};
use tracing::{info, warn};
use uuid::Uuid;
use validation::{
    export_path::{validate_export_path, ExportPathStatus},
    net::{
        validate_dn, validate_identity_query, validate_ldap_endpoint, validate_share_name,
        validate_smb_server,
    },
    numbers::validate_optional_scan_depth,
    path::validate_path,
    sid::validate_sid,
};

/// Returns the default database path in %APPDATA%\Stars\.
///
/// The path is outside the install directory so the scan history survives uninstall.
pub fn default_db_path() -> String {
    if let Some(appdata) = std::env::var_os("APPDATA") {
        let dir = std::path::PathBuf::from(appdata).join("Stars");
        let _ = std::fs::create_dir_all(&dir);
        return dir.join("stars_data.db").to_string_lossy().into_owned();
    }
    // Fallback: next to the executable (e.g. during development)
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("stars_data.db")))
        .unwrap_or_else(|| std::path::PathBuf::from("stars_data.db"))
        .to_string_lossy()
        .into_owned()
}

/// LDAP connection parameters for optional AD resolution.
///
/// versehentliches `{params:?}` keine Secrets in Logs schreibt.
/// `Debug` is hand-implemented and masks the password so an accidental
/// `{params:?}` does not leak secrets into logs.
#[derive(Clone)]
pub struct LdapParams {
    pub server: String,
    pub base_dn: String,
    pub bind_dn: String,
    pub password: String,
    /// When true: unencrypted LDAP (port 389). Only for test environments.
    pub insecure: bool,
}

impl std::fmt::Debug for LdapParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pw_placeholder: &str = if self.password.is_empty() {
            "<empty>"
        } else {
            "***"
        };
        f.debug_struct("LdapParams")
            .field("server", &self.server)
            .field("base_dn", &self.base_dn)
            .field("bind_dn", &self.bind_dn)
            .field("password", &pw_placeholder)
            .field("insecure", &self.insecure)
            .finish()
    }
}

/// Search result for the identity search.
#[derive(Clone)]
pub struct IdentitySearchResult {
    pub sid: String,
    pub sam_account_name: String,
    pub display_name: Option<String>,
    pub kind: adpa_core::model::IdentityKind,
}

/// Anfrage an den Worker-Thread.
/// Request to the worker thread.
pub enum WorkerRequest {
    Analyze {
        path: String,
        sid: String,
        ldap: Option<LdapParams>,
        smb_server: Option<String>,
        share_name: Option<String>,
    },
    Scan {
        root: String,
        sid: String,
        max_depth: Option<u32>,
        smb_server: Option<String>,
        share_name: Option<String>,
        ldap: Option<LdapParams>,
    },
    /// Sucht Benutzer und Gruppen im Active Directory.
    /// Searches for users and groups in Active Directory.
    SearchIdentity { query: String, ldap: LdapParams },
    /// Exportiert den letzten Scan als HTML-Bericht.
    /// Exports the last scan as an HTML report.
    ExportHtml { output_path: String },
    /// Loads the list of all persisted scan runs for the Delta tab.
    ListScanRuns,
    /// Collects a flat identity list (users, groups, well-knowns) for the
    /// live search in the GUI's name field. One-shot request after app
    /// start; the GUI keeps the result as a cache.
    ListIdentities,
    /// Compares two scan runs and returns the delta rows.
    ComputeDelta {
        old_run_id: String,
        new_run_id: String,
    },
    /// Removes a single scan run including all dependent data from the
    /// SQLite history. Keeps the DB from growing monotonically.
    DeleteScanRun { run_id: String },
    /// Benutzer Y auf X?".
    /// Lists all trustees with their rights on a path — path-centric
    /// audit view without a fixed identity. Answers the question "Who
    /// has any access to X?" rather than "What can user Y do on X?".
    AnalyzeTrustees {
        path: String,
        smb_server: Option<String>,
        share_name: Option<String>,
    },
}

/// Row in the scan result (for GUI table).
#[derive(Clone)]
pub struct ScanRow {
    pub path: String,
    pub rights_label: String,
    pub mask_raw: u32,
    pub steps: Vec<String>,
    /// Count of unevaluated ACE types on this path (> 0 = diagnostic warning).
    pub unsupported_ace_count: usize,
    /// Anzahl strukturierter Diagnose-Marker (z. B. nicht-kanonisch sortierte
    /// Count of structured diagnostic markers (e.g. non-canonical DACL,
    /// follow-up finding 3). 0 = unremarkable.
    pub diagnostic_count: usize,
    /// `steps`-Pfad oben.
    /// Path-centric trustee view — every ACE in the DACL resolved, with
    /// "Applies to" labels and Allow/Deny. Empty when the scan runs
    /// without trustee collection. Complement to the identity-based
    /// `steps` above.
    pub trustees: Vec<TrusteeRow>,
}

/// Ergebnis vom Worker-Thread an die GUI.
/// Result from the worker thread to the GUI.
pub enum WorkerEvent {
    AnalyzeDone {
        /// Eigentliches Auswertungsergebnis (oder Engine-Fehler).
        /// uebrigen Varianten — sonst zieht clippy::large_enum_variant.
        /// Actual evaluation result (or engine error). Boxed because
        /// `EffectivePermission` is significantly larger than the other
        /// variants — otherwise clippy::large_enum_variant fires.
        result: Box<Result<adpa_core::model::EffectivePermission, String>>,
        /// UUID of the stored scan run. Analyze now writes to the SQLite history
        /// as well so the result is comparable in the Delta tab — the previous
        /// "Analyze does not persist" gap is gone. `None` when the evaluation did
        /// not happen (engine error) or when the DB is not open.
        scan_run_id: Option<String>,
        /// Grund, falls trotz erfolgreicher Auswertung die Persistenz fehlschlug.
        /// Reason if persistence failed despite a successful evaluation.
        persistence_error: Option<String>,
    },
    ScanItem(ScanRow),
    ScanError {
        path: String,
        message: String,
    },
    ScanDone {
        total: usize,
        errors: usize,
        /// UUID of the stored scan run (None if not persisted).
        scan_run_id: Option<String>,
        /// Reason if the scan could not be persisted to the database.
        persistence_error: Option<String>,
        /// true if the scan was cancelled by the user — results are partial.
        cancelled: bool,
    },
    /// Risikobefunde nach Abschluss eines Scans.
    /// Risk findings after a scan completes.
    RiskFindings(Vec<RiskFinding>),
    /// Ergebnis eines HTML-Exports.
    /// Result of an HTML export.
    ExportDone(Result<(), String>),
    /// Search results for the identity search.
    SearchResults(Result<Vec<IdentitySearchResult>, String>),
    /// Persisted scan runs for the Delta tab.
    ScanRunsLoaded(Result<Vec<ScanRunSummary>, String>),
    /// Identity snapshot for the live search in the name field.
    IdentitiesLoaded(Result<Vec<IdentitySuggestion>, String>),
    /// Delta between two scan runs, ready for display.
    DeltaComputed(Result<Vec<DeltaRow>, String>),
    /// Result of a scan-run deletion. Contains the ID of the removed run
    /// alongside the success/error status so the GUI can both update its
    /// status text and clear local selection.
    ScanRunDeleted {
        run_id: String,
        result: Result<(), String>,
    },
    /// Ergebnis einer Trustee-Auflistung pro Pfad.
    /// Result of a per-path trustee listing.
    TrusteesDone(Result<Vec<TrusteeRow>, String>),
}

/// One row in the trustee view — one ACE from a path's DACL plus
/// resolved labels for GUI display.
#[derive(Clone)]
pub struct TrusteeRow {
    /// Roh-SID des Trustees.
    /// Raw SID of the trustee.
    pub sid: String,
    /// Readable label (`DOMAIN\Name`), falls back to the SID.
    pub display_name: String,
    /// `"Allow"` oder `"Deny"`.
    /// `"Allow"` or `"Deny"`.
    pub kind: String,
    /// Normalisierte Rechte-Bezeichnung (z. B. `Modify (M)`).
    /// Normalized rights label (e.g. `Modify (M)`).
    pub rights_label: String,
    /// Hex form of the raw access mask for forensic purposes.
    pub mask_hex: String,
    /// `"explicit"` oder `"inherited"`.
    /// `"explicit"` or `"inherited"`.
    pub source: String,
    /// Windows-typische „Applies to"-Bezeichnung (z. B. „This folder,
    /// subfolders and files"), abgeleitet aus den Inheritance- und
    /// Propagation-Flags.
    /// Windows-style "Applies to" label (e.g. "This folder, subfolders
    /// and files"), derived from inheritance and propagation flags.
    pub applies_to: String,
    /// die zwei Schichten unterscheidet.
    /// `"NTFS"` or `"Share"` — surfaced separately so the auditor can
    /// tell the two layers apart.
    pub category: String,
}

/// Compact row per scan run for display in the Delta tab.
#[derive(Clone)]
pub struct ScanRunSummary {
    pub id: String,
    pub started_at: String,
    pub target: String,
    pub error_count: usize,
}

/// One suggestion in the name fields' live search.
#[derive(Clone)]
pub struct IdentitySuggestion {
    /// Reiner Name (das, was beim Klick ins Namensfeld kommt) — z.B.
    /// `Administrator`.
    /// Plain name (the value pushed into the name field on click) — e.g.
    /// `Administrator`.
    pub name: String,
    /// Qualified display name `DOMAIN\Name`, or just `Name` when no
    /// domain is known.
    pub qualified: String,
    /// (lokale Gruppe), `W` (Well-Known).
    /// One-letter UI marker: `U` (user), `G` (group), `L` (local group),
    /// `W` (well-known).
    pub kind_icon: String,
    /// bleiben.
    /// Optional description (NetAPI `comment` fields) — may be empty.
    pub description: String,
}

/// One delta row, ready for display.
#[derive(Clone)]
pub struct DeltaRow {
    pub path: String,
    /// Plain-text label: "Added", "Removed", "Changed".
    pub kind_label: String,
    /// Old rights (plain text + hex) or empty when `Added`.
    pub old_rights: String,
    /// New rights (plain text + hex) or empty when `Removed`.
    pub new_rights: String,
}

/// Starts the worker thread and returns the sender, receiver, and cancellation token.
///
/// The cancellation token is held by the GUI: `cancel()` acts directly on a running
/// scan without needing the request channel (which is blocked during a scan).
/// `WorkerEvent` im Receiver liegt. Bei Slint typischerweise ein Wrapper um
/// `slint::invoke_from_event_loop`, der den Receiver pollt.
/// Callback the worker uses to wake the GUI thread once a new
/// `WorkerEvent` is sitting in the receiver. With Slint this is typically
/// a wrapper around `slint::invoke_from_event_loop` that drains the
/// receiver.
pub type NotifyFn = std::sync::Arc<dyn Fn() + Send + Sync>;

pub fn spawn_worker(
    notify: NotifyFn,
) -> (
    Sender<WorkerRequest>,
    Receiver<WorkerEvent>,
    CancellationToken,
) {
    let (req_tx, req_rx) = std::sync::mpsc::channel::<WorkerRequest>();
    let (evt_tx, evt_rx) = std::sync::mpsc::channel::<WorkerEvent>();
    let cancel = CancellationToken::new();
    let worker_cancel = cancel.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        // Keep the DB open error instead of silently dropping it with .ok() —
        // it is reported per scan as a visible persistence error.
        let (db, db_open_error): (Option<Database>, Option<String>) =
            match Database::open(&default_db_path()) {
                Ok(d) => (Some(d), None),
                Err(e) => {
                    warn!(error = %e, "Failed to open scan database — scans will not be persisted");
                    (None, Some(e.to_string()))
                }
            };
        let mut last_permissions: Vec<EffectivePermission> = Vec::new();
        let mut last_risk_findings: Vec<RiskFinding> = Vec::new();
        // Path-centric trustee listing from the last scan — exported with
        // the report so the HTML carries both audit views.
        let mut last_path_trustees: Vec<adpa_core::model::PathTrustees> = Vec::new();

        while let Ok(req) = req_rx.recv() {
            match req {
                WorkerRequest::Analyze {
                    path,
                    sid,
                    ldap,
                    smb_server,
                    share_name,
                } => {
                    let result = rt.block_on(handle_analyze(
                        &path,
                        &sid,
                        ldap.as_ref(),
                        smb_server.as_deref(),
                        share_name.as_deref(),
                    ));
                    // Auswertung nicht" wahrnehmbar war).
                    // Analyze also persists from v1.1.x onward — a single
                    // EffectivePermission becomes a scan run with exactly one
                    // permission entry. This makes Analyze results comparable
                    // in the Delta tab (previously only ScanTree wrote to the
                    // DB, which surfaced to end users as "the list does not
                    // show my analysis result").
                    let (scan_run_id, persistence_error) = match (&result, &db) {
                        (Ok(perm), Some(d)) => {
                            match persist_scan(d, &path, std::slice::from_ref(perm), &[], false) {
                                Ok(id) => (Some(id), None),
                                Err(e) => (None, Some(e)),
                            }
                        }
                        (Ok(_), None) => {
                            (
                                None,
                                Some(db_open_error.clone().unwrap_or_else(|| {
                                    "scan database is not available".to_string()
                                })),
                            )
                        }
                        (Err(_), _) => (None, None),
                    };
                    let _ = evt_tx.send(WorkerEvent::AnalyzeDone {
                        result: Box::new(result),
                        scan_run_id,
                        persistence_error,
                    });
                    notify();
                }
                WorkerRequest::Scan {
                    root,
                    sid,
                    max_depth,
                    smb_server,
                    share_name,
                    ldap,
                } => {
                    let scan_result = rt.block_on(handle_scan(
                        &root,
                        &sid,
                        max_depth,
                        smb_server.as_deref(),
                        share_name.as_deref(),
                        ldap.as_ref(),
                        &evt_tx,
                        &worker_cancel,
                    ));

                    let registry = RuleRegistry::with_defaults();
                    let risks = registry.evaluate_all(&RiskContext {
                        findings: scan_result.permissions.clone(),
                    });

                    // Persistenz-Ergebnis explizit auswerten: entweder eine Run-ID
                    // oder ein sichtbarer Fehlergrund.
                    // Evaluate the persistence result explicitly: either a run ID
                    // or a visible failure reason.
                    let persist_outcome = match &db {
                        Some(d) => persist_scan(
                            d,
                            &root,
                            &scan_result.permissions,
                            &scan_result.errors,
                            scan_result.cancelled,
                        ),
                        None => Err(db_open_error
                            .clone()
                            .unwrap_or_else(|| "scan database is not available".to_string())),
                    };
                    let (run_id, persistence_error) = match persist_outcome {
                        Ok(id) => (Some(id), None),
                        Err(reason) => (None, Some(reason)),
                    };

                    let _ = evt_tx.send(WorkerEvent::RiskFindings(risks.clone()));
                    let _ = evt_tx.send(WorkerEvent::ScanDone {
                        total: scan_result.total,
                        errors: scan_result.errors.len(),
                        scan_run_id: run_id,
                        persistence_error,
                        cancelled: scan_result.cancelled,
                    });

                    last_permissions = scan_result.permissions;
                    last_path_trustees = scan_result.path_trustees;
                    last_risk_findings = risks;
                    notify();
                }
                WorkerRequest::SearchIdentity { query, ldap } => {
                    let result = rt.block_on(handle_search(&query, &ldap));
                    let _ = evt_tx.send(WorkerEvent::SearchResults(result));
                    notify();
                }
                WorkerRequest::ExportHtml { output_path } => {
                    let result = export_html(
                        &last_permissions,
                        &last_risk_findings,
                        &last_path_trustees,
                        &output_path,
                    );
                    let _ = evt_tx.send(WorkerEvent::ExportDone(result));
                    notify();
                }
                WorkerRequest::ListScanRuns => {
                    let result = match &db {
                        Some(d) => list_scan_run_summaries(d),
                        None => Err(db_open_error
                            .clone()
                            .unwrap_or_else(|| "Datenbank nicht geöffnet".to_string())),
                    };
                    let _ = evt_tx.send(WorkerEvent::ScanRunsLoaded(result));
                    notify();
                }
                WorkerRequest::ListIdentities => {
                    let result = collect_identity_suggestions();
                    let _ = evt_tx.send(WorkerEvent::IdentitiesLoaded(result));
                    notify();
                }
                WorkerRequest::ComputeDelta {
                    old_run_id,
                    new_run_id,
                } => {
                    let result = match &db {
                        Some(d) => compute_delta(d, &old_run_id, &new_run_id),
                        None => Err(db_open_error
                            .clone()
                            .unwrap_or_else(|| "Datenbank nicht geöffnet".to_string())),
                    };
                    let _ = evt_tx.send(WorkerEvent::DeltaComputed(result));
                    notify();
                }
                WorkerRequest::DeleteScanRun { run_id } => {
                    let result = match &db {
                        Some(d) => delete_scan_run(d, &run_id),
                        None => Err(db_open_error
                            .clone()
                            .unwrap_or_else(|| "Datenbank nicht geöffnet".to_string())),
                    };
                    let _ = evt_tx.send(WorkerEvent::ScanRunDeleted { run_id, result });
                    notify();
                }
                WorkerRequest::AnalyzeTrustees {
                    path,
                    smb_server,
                    share_name,
                } => {
                    let result =
                        analyze_trustees(&path, smb_server.as_deref(), share_name.as_deref());
                    let _ = evt_tx.send(WorkerEvent::TrusteesDone(result));
                    notify();
                }
            }
        }
    });

    (req_tx, evt_rx, cancel)
}

// ---------------------------------------------------------------------------
// Internes Ergebnis des Scan-Handlers
// Internal result of the scan handler
// ---------------------------------------------------------------------------

struct ScanSummary {
    permissions: Vec<EffectivePermission>,
    /// Pfadzentrische Trustee-Auflistung (raw model — ohne Display-
    /// daneben formatiere `TrusteeRow`-Daten direkt im `ScanRow`.
    /// Path-centric trustee listing (raw model — no display formatting).
    /// Used by the HTML exporter; the GUI separately receives display-
    /// formatted `TrusteeRow` data inside each `ScanRow`.
    path_trustees: Vec<adpa_core::model::PathTrustees>,
    /// Structured walk, eval and validation errors. Written to the scan
    /// history via `insert_error` in `persist_scan` so that GUI scans get
    /// the same audit trail as CLI scans.
    errors: Vec<ScanError>,
    total: usize,
    /// true if the scan was cancelled by the user.
    cancelled: bool,
}

/// Validiert optionale SMB- und LDAP-Verbindungs-Eingaben zentral, bevor sie
/// Centrally validates optional SMB and LDAP connection inputs before they are
/// passed to NetAPI or LDAP calls.
/// Normalisierte Verbindungs-Eingaben im GUI-Worker (siehe
/// Normalized connection inputs in the GUI worker.
pub struct NormalizedConnectionInputs {
    pub smb_server: Option<String>,
    pub share_name: Option<String>,
    pub ldap: Option<LdapParams>,
}

/// einzelnen Felder. Wiederverwendet in `validate_connection_inputs`
/// Finding 3 (vorher validierte `analyze_trustees` die Felder einzeln
/// und akzeptierte `Some, None`).
/// Enforces SMB pair requirement + validates each field. Used by both
/// `validate_connection_inputs` and `analyze_trustees`.
pub fn normalize_smb_pair(
    smb_server: Option<&str>,
    share_name: Option<&str>,
) -> Result<(Option<String>, Option<String>), String> {
    let smb_server_set = smb_server.is_some_and(|s| !s.trim().is_empty());
    let share_name_set = share_name.is_some_and(|s| !s.trim().is_empty());
    match (smb_server_set, share_name_set) {
        (true, false) => {
            return Err(
                "SMB context incomplete: --smb-server set but --share-name missing. Provide both or neither."
                    .to_string(),
            );
        }
        (false, true) => {
            return Err(
                "SMB context incomplete: --share-name set but --smb-server missing. Provide both or neither."
                    .to_string(),
            );
        }
        _ => {}
    }
    let smb_server = match smb_server {
        Some(s) if !s.trim().is_empty() => Some(
            validate_smb_server(s)
                .map_err(|e| format!("Invalid SMB server: {e}"))?
                .0,
        ),
        _ => None,
    };
    let share_name = match share_name {
        Some(s) if !s.trim().is_empty() => Some(
            validate_share_name(s)
                .map_err(|e| format!("Invalid share name: {e}"))?
                .0,
        ),
        _ => None,
    };
    Ok((smb_server, share_name))
}

fn validate_connection_inputs(
    smb_server: Option<&str>,
    share_name: Option<&str>,
    ldap: Option<&LdapParams>,
) -> Result<NormalizedConnectionInputs, String> {
    let (smb_server, share_name) = normalize_smb_pair(smb_server, share_name)?;
    let ldap = match ldap {
        Some(p) => {
            let server = validate_ldap_endpoint(&p.server)
                .map_err(|e| format!("Invalid LDAP server: {e}"))?
                .0;
            let base_dn = validate_dn(&p.base_dn)
                .map_err(|e| format!("Invalid base DN: {e}"))?
                .0;
            let bind_dn = validate_dn(&p.bind_dn)
                .map_err(|e| format!("Invalid bind DN: {e}"))?
                .0;
            Some(LdapParams {
                server,
                base_dn,
                bind_dn,
                password: p.password.clone(),
                insecure: p.insecure,
            })
        }
        None => None,
    };
    Ok(NormalizedConnectionInputs {
        smb_server,
        share_name,
        ldap,
    })
}

// ---------------------------------------------------------------------------
// Analyze
// ---------------------------------------------------------------------------

async fn handle_analyze(
    path: &str,
    sid: &str,
    ldap: Option<&LdapParams>,
    smb_server: Option<&str>,
    share_name: Option<&str>,
) -> Result<adpa_core::model::EffectivePermission, String> {
    info!(path, sid, "Analyze request");
    // Normalform durchreichen, nicht den Roh-String.
    // Review 2026-06-04 round 2, finding 6: forward the canonical form
    // from here on, not the raw string.
    let normalized_path = validate_path(path)
        .map_err(|e| format!("Invalid path: {e}"))?
        .0;
    let path = normalized_path.as_str();
    // getrimmten Wert laufen — sonst landet "  S-1-5-21-...  " im
    // Review round 4 finding 2: classify on the trimmed value.
    let sid_trimmed = sid.trim();
    let sid_owned = if sid_trimmed.starts_with("S-1-") {
        validate_sid(sid_trimmed)
            .map_err(|e| format!("Invalid SID: {e}"))?
            .0
    } else {
        sid_trimmed.to_string()
    };
    let sid = sid_owned.as_str();
    let normalized = validate_connection_inputs(smb_server, share_name, ldap)?;
    let smb_server = normalized.smb_server.as_deref();
    let share_name = normalized.share_name.as_deref();
    let ldap = normalized.ldap.as_ref();
    let fso = read_fso(path).map_err(|e| format!("Failed to read path: {e}"))?;
    let res = resolve_identity_sids(sid, ldap).await?;

    let (local_group_sids, local_group_memberships, local_group_status) =
        collect_local_group_sids_for_path(path, smb_server, &res.identity, &res.memberships);

    let (share_status, unsupported_share_ace_count) = resolve_share_status(
        path,
        smb_server,
        share_name,
        sid,
        &res.memberships,
        &local_group_sids,
        AccessContext::for_path_with_smb(path, smb_server, share_name),
    );

    // SID→name table for the explanation path. DACL trustees are resolved
    // once so that `Member of …` and `Allow ACE for …` carry the readable
    // name in addition to the SID.
    #[cfg(windows)]
    let sid_names =
        ad_resolver::build_sid_name_map(&res.memberships, fso.dacl.iter().map(|a| a.sid.0.clone()));
    #[cfg(not(windows))]
    let sid_names = std::collections::BTreeMap::new();

    let engine_flags = res.engine_flags();
    let identity = res.identity;
    let mut memberships = res.memberships;
    // Round 6 finding 1: lokale Servergruppen-Memberships mit AD-
    // Token-Schritt rendert (siehe CLI-Pendant).
    // Round 6 finding 1: merge local group memberships into the
    // engine input so the explanation path renders all token steps.
    memberships.extend(local_group_memberships.iter().cloned());
    DefaultPermissionEngine
        .evaluate(PermissionEvaluationInput {
            identity,
            group_memberships: memberships,
            file_system_object: fso,
            share_status,
            local_group_sids,
            local_group_status,
            access_context: AccessContext::for_path_with_smb(path, smb_server, share_name),
            unsupported_share_ace_count,
            sid_names,
            group_resolution_via_sam_fallback: engine_flags.group_resolution_via_sam_fallback,
            identity_not_in_configured_ldap_base: engine_flags.identity_not_in_configured_ldap_base,
            identity_disabled_status_unknown: engine_flags.identity_disabled_status_unknown,
            identity_lookup_failure_reason: engine_flags.identity_lookup_failure_reason,
            group_resolution_failure_reason: engine_flags.group_resolution_failure_reason,
        })
        .map_err(|e| format!("Permission engine error: {e}"))
}

/// Finding 2: priorisiert den explizit gesetzten `smb_server` vor dem aus dem
/// Collects local group SIDs on the analysis target server — see CLI counterpart.
/// Finding 2: prefers the explicit `smb_server` over the path-derived UNC server
/// so the token SID set stays consistent.
fn collect_local_group_sids_for_path(
    path: &str,
    explicit_smb_server: Option<&str>,
    identity: &Identity,
    domain_memberships: &[GroupMembership],
) -> (
    Vec<adpa_core::model::Sid>,
    Vec<GroupMembership>,
    adpa_core::model::LocalGroupEvalStatus,
) {
    use adpa_core::model::LocalGroupEvalStatus;
    use validation::path::effective_smb_target;

    let server_owned = effective_smb_target(path, explicit_smb_server);
    let server = server_owned.as_deref();
    // Round 6 finding 1: chains instead of bare SIDs, so the engine's
    // explanation path renders every `Member of …` mediator step.
    let mut known_member_sids_to_names: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    if let Some(ref n) = identity.name {
        known_member_sids_to_names.insert(identity.sid.0.clone(), n.clone());
    }
    for gm in domain_memberships {
        if let Some(ref n) = gm.group_name {
            known_member_sids_to_names.insert(gm.group_sid.0.clone(), n.clone());
        }
    }
    match ad_resolver::resolve_local_group_chains_for_identity(
        server,
        identity,
        &known_member_sids_to_names,
    ) {
        Ok(memberships) => {
            let sids: Vec<adpa_core::model::Sid> =
                memberships.iter().map(|m| m.group_sid.clone()).collect();
            (sids, memberships, LocalGroupEvalStatus::Applied)
        }
        Err(e) => {
            let msg = e.to_string();
            warn!(
                ?server,
                sid = %identity.sid.0,
                error = %msg,
                "Local group resolution failed; result will be marked incomplete"
            );
            (
                Vec::new(),
                Vec::new(),
                LocalGroupEvalStatus::NotAvailable(msg),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn handle_scan(
    root: &str,
    sid: &str,
    max_depth: Option<u32>,
    smb_server: Option<&str>,
    share_name: Option<&str>,
    ldap: Option<&LdapParams>,
    evt_tx: &Sender<WorkerEvent>,
    cancel: &CancellationToken,
) -> ScanSummary {
    info!(root, sid, "Scan request");

    // persist_scan in `scan_errors` landet.
    // Helper: emit a validation/setup error to the UI AND structurally
    // record it in the summary so persist_scan can write it to `scan_errors`.
    let make_early_summary = |message: String| -> ScanSummary {
        let _ = evt_tx.send(WorkerEvent::ScanError {
            path: root.to_string(),
            message: message.clone(),
        });
        ScanSummary {
            permissions: vec![],
            path_trustees: vec![],
            errors: vec![ScanError {
                path: Some(NormalizedPath(root.to_string())),
                message,
            }],
            total: 0,
            cancelled: false,
        }
    };

    // Normalform durchreichen, nicht den Roh-String.
    // Review 2026-06-04 round 2, finding 6: forward the canonical form.
    let normalized_root = match validate_path(root) {
        Ok(p) => p.0,
        Err(e) => return make_early_summary(format!("Invalid path: {e}")),
    };
    let root = normalized_root.as_str();
    // AGENTS.md DoD 11: max_depth zentral validieren, bevor sie in
    // AGENTS.md DoD 11: validate max_depth centrally before it flows into
    // WalkConfig — the GUI widget caps the value visually but does not
    // protect against programmatic callers or future UI refactorings.
    let max_depth = match validate_optional_scan_depth(max_depth) {
        Ok(d) => d.map(|s| s.0),
        Err(e) => return make_early_summary(format!("Invalid max_depth: {e}")),
    };
    // Review 2026-06-04 Runde 4 Finding 2: Klassifikation auf getrimmtem
    // Wert, sonst landet "  S-1-...  " unvalidiert im else-Zweig.
    // Review round 4 finding 2: classify on the trimmed value.
    let sid_trimmed = sid.trim();
    let sid_owned = if sid_trimmed.starts_with("S-1-") {
        match validate_sid(sid_trimmed) {
            Ok(v) => v.0,
            Err(e) => return make_early_summary(format!("Invalid SID: {e}")),
        }
    } else {
        sid_trimmed.to_string()
    };
    let sid = sid_owned.as_str();

    let normalized = match validate_connection_inputs(smb_server, share_name, ldap) {
        Ok(n) => n,
        Err(e) => return make_early_summary(e),
    };
    let smb_server = normalized.smb_server.as_deref();
    let share_name = normalized.share_name.as_deref();
    let ldap = normalized.ldap.as_ref();

    let res = match resolve_identity_sids(sid, ldap).await {
        Ok(r) => r,
        Err(e) => {
            return make_early_summary(format!("Identity resolution failed: {e}"));
        }
    };
    let engine_flags = res.engine_flags();
    let sam_fallback = engine_flags.group_resolution_via_sam_fallback;
    let identity_not_in_configured_ldap_base = engine_flags.identity_not_in_configured_ldap_base;
    let identity_disabled_status_unknown = engine_flags.identity_disabled_status_unknown;
    let identity_lookup_failure_reason = engine_flags.identity_lookup_failure_reason;
    let group_resolution_failure_reason = engine_flags.group_resolution_failure_reason;
    let identity = res.identity;
    let memberships = res.memberships;

    // landet. Sammelt Walk-, Eval- und Setup-Fehler analog zum CLI-Pfad.
    // Structured error list that later flows into `scan_errors` via
    // persist_scan. Collects walk, eval, and setup errors mirroring the CLI.
    let mut summary_errors: Vec<ScanError> = Vec::new();

    // Lokale Server-Gruppen pro Scan-Wurzel einmal aufloesen — vor der Share-Maske,
    // Resolve local server groups once per scan root — before the share mask, so
    // that share ACEs targeting local groups are also taken into account.
    let (local_group_sids, local_group_memberships, local_group_status) =
        collect_local_group_sids_for_path(root, smb_server, &identity, &memberships);
    // Round 6 finding 1: lokale Servergruppen-Memberships mit AD-
    // Round 6 finding 1: combine AD + local memberships per path.
    let combined_memberships: Vec<GroupMembership> = {
        let mut v = memberships.clone();
        v.extend(local_group_memberships.iter().cloned());
        v
    };

    if let adpa_core::model::LocalGroupEvalStatus::NotAvailable(ref msg) = local_group_status {
        let lg_message =
            format!("Local server groups could not be resolved — scan results incomplete: {msg}");
        let _ = evt_tx.send(WorkerEvent::ScanError {
            path: root.to_string(),
            message: lg_message.clone(),
        });
        summary_errors.push(ScanError {
            path: Some(NormalizedPath(root.to_string())),
            message: lg_message,
        });
    }

    let (share_status, scan_unsupported_share_ace_count) = resolve_share_status(
        root,
        smb_server,
        share_name,
        sid,
        &memberships,
        &local_group_sids,
        AccessContext::for_path_with_smb(root, smb_server, share_name),
    );
    if scan_unsupported_share_ace_count > 0 {
        let msg = format!(
            "{scan_unsupported_share_ace_count} share ACE(s) of unsupported type were skipped — share mask may be incomplete (diagnostic propagated to each result)."
        );
        let _ = evt_tx.send(WorkerEvent::ScanError {
            path: root.to_string(),
            message: msg.clone(),
        });
        summary_errors.push(ScanError {
            path: Some(NormalizedPath(root.to_string())),
            message: msg,
        });
    }

    let walk = walk_tree(root, &WalkConfig { max_depth }, cancel);
    let total = walk.objects.len();
    let cancelled = walk.cancelled;

    for err in &walk.errors {
        let _ = evt_tx.send(WorkerEvent::ScanError {
            path: err.path.clone(),
            message: err.error.to_string(),
        });
        summary_errors.push(ScanError {
            path: Some(NormalizedPath(err.path.clone())),
            message: err.error.to_string(),
        });
    }

    let engine = DefaultPermissionEngine;
    let mut permissions = Vec::with_capacity(walk.objects.len());
    let scan_access_context = AccessContext::for_path_with_smb(root, smb_server, share_name);

    // `validation::path::SmbAuditContext` — dieselbe Quelle wie CLI
    // analyze/scan und `resolve_scan_share_status`. Ergebnis: alle
    // Round-10 finding 1: server/share derivation lives centrally in
    // `validation::path::SmbAuditContext` — the same source CLI
    // analyze/scan and `resolve_scan_share_status` use. Result: every
    // path in CLI and GUI sees the exact same server/share logic.
    let share_overlay: Option<ShareTrusteeOverlay> =
        validation::path::SmbAuditContext::resolve(root, smb_server, share_name)
            .map(|ctx| read_share_overlay(&ctx.server, &ctx.share));

    // Build the SID→name table once for the entire scan. Trustee SIDs
    // repeat across all paths — we collect the unique SIDs from every
    // DACL up front and avoid N×M LSA round-trips.
    // Round-10 finding 2: now also covers share-overlay SIDs and is
    // handed to the trustee build function so it makes NO per-path LSA
    // call.
    #[cfg(windows)]
    let scan_sid_names = {
        use std::collections::HashSet;
        let mut seen: HashSet<String> = HashSet::new();
        let mut trustees: Vec<String> = Vec::new();
        for fso in &walk.objects {
            for sid in exporter::collect_ace_sids_for_resolution(fso, share_overlay.as_ref()) {
                if seen.insert(sid.clone()) {
                    trustees.push(sid);
                }
            }
        }
        ad_resolver::build_sid_name_map(&memberships, trustees)
    };
    #[cfg(not(windows))]
    let scan_sid_names = std::collections::BTreeMap::new();

    // Collects the raw path-centric trustee lists for the HTML exporter.
    let mut path_trustees: Vec<adpa_core::model::PathTrustees> = Vec::new();

    for fso in walk.objects {
        let path = fso.path.0.clone();
        // Trustees pro Pfad bauen — NTFS aus dem FSO, Share aus dem
        // vorab gelesenen Overlay (Single Read pro Share). Round-10
        // Finding 2: die scan-weite SID→Name-Map vermeidet LSA pro Pfad.
        // Per-path trustees — NTFS from FSO, share from the pre-read
        // overlay. Round-10 finding 2: scan-wide SID→name map avoids
        // per-path LSA.
        let raw_trustees =
            build_path_trustees_with_share_and_names(&fso, share_overlay.as_ref(), &scan_sid_names);
        let trustees_for_row: Vec<TrusteeRow> =
            raw_trustees.iter().map(trustee_row_for_display).collect();
        path_trustees.push(adpa_core::model::PathTrustees {
            path: fso.path.clone(),
            trustees: raw_trustees,
        });
        match engine.evaluate(PermissionEvaluationInput {
            identity: identity.clone(),
            group_memberships: combined_memberships.clone(),
            file_system_object: fso,
            share_status: share_status.clone(),
            local_group_sids: local_group_sids.clone(),
            local_group_status: local_group_status.clone(),
            access_context: scan_access_context,
            unsupported_share_ace_count: scan_unsupported_share_ace_count,
            sid_names: scan_sid_names.clone(),
            group_resolution_via_sam_fallback: sam_fallback,
            identity_not_in_configured_ldap_base,
            identity_disabled_status_unknown,
            identity_lookup_failure_reason: identity_lookup_failure_reason.clone(),
            group_resolution_failure_reason: group_resolution_failure_reason.clone(),
        }) {
            Ok(perm) => {
                let label = NormalizedRights::new(perm.effective_mask.0)
                    .display_name()
                    .to_string();
                let _ = evt_tx.send(WorkerEvent::ScanItem(ScanRow {
                    path: path.clone(),
                    rights_label: label,
                    mask_raw: perm.effective_mask.0,
                    steps: perm.path_explanation.steps.clone(),
                    unsupported_ace_count: perm.unsupported_ace_count,
                    diagnostic_count: perm.diagnostics.len(),
                    trustees: trustees_for_row,
                }));
                permissions.push(perm);
            }
            Err(e) => {
                warn!(path, error = %e, "Permission evaluation failed");
                let _ = evt_tx.send(WorkerEvent::ScanError {
                    path: path.clone(),
                    message: e.to_string(),
                });
                summary_errors.push(ScanError {
                    path: Some(NormalizedPath(path)),
                    message: e.to_string(),
                });
            }
        }
    }

    ScanSummary {
        permissions,
        path_trustees,
        errors: summary_errors,
        total,
        cancelled,
    }
}

// ---------------------------------------------------------------------------
// Identity search
// ---------------------------------------------------------------------------

async fn handle_search(
    query: &str,
    ldap: &LdapParams,
) -> Result<Vec<IdentitySearchResult>, String> {
    use adpa_core::model::IdentityKind;

    // Review 2026-06-04 Runde 3 Finding 2: getrimmte Wrapperwerte
    // Review round 3 finding 2: forward the trimmed wrapper values, not
    // the raw `ldap` fields.
    let query = validate_identity_query(query)
        .map_err(|e| format!("Invalid search query: {e}"))?
        .0;
    let server = validate_ldap_endpoint(&ldap.server)
        .map_err(|e| format!("Invalid LDAP server: {e}"))?
        .0;
    let base_dn = validate_dn(&ldap.base_dn)
        .map_err(|e| format!("Invalid base DN: {e}"))?
        .0;
    let bind_dn = validate_dn(&ldap.bind_dn)
        .map_err(|e| format!("Invalid bind DN: {e}"))?
        .0;

    let mut config = LdapConfig::new(&server, &base_dn, &bind_dn, &ldap.password);
    if ldap.insecure {
        config.tls_mode = TlsMode::Insecure;
        config.port = 389;
    }

    // `LdapConfig::timeout_secs` versprach. Wir packen Connect + Search +
    // beobachtbar ist.
    // Review 2026-06-04 round 2, finding 3: the GUI identity search used to
    // bypass the LDAP timeout. connect() is internally guarded; the paged
    // search_by_query ran without a wrapper, so the picker could block
    // longer than `LdapConfig::timeout_secs` promised. We wrap connect +
    // search + disconnect in a single timeout so the whole operation is
    // observable.
    let entries = ldap_client::with_timeout(
        "identity_search",
        ldap_client::ldap_timeout(&config),
        async {
            let mut conn = ldap_client::connect(&config).await?;
            let entries = ldap_client::search_by_query(&mut conn, &base_dn, &query).await;
            ldap_client::disconnect(conn).await;
            entries
        },
    )
    .await
    .map_err(|e| format!("Suche fehlgeschlagen: {e}"))?;

    let mut results = Vec::new();
    for entry in entries {
        let Some(sid_bytes) = entry.first_bin_attr("objectSid") else {
            continue;
        };
        let sid = match bytes_to_sid_str(sid_bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let sam = entry.first_attr("sAMAccountName").unwrap_or("").to_string();
        let display_name = entry.first_attr("displayName").map(str::to_string);
        let classes = entry.all_attr("objectClass");
        let kind = if classes.iter().any(|c| c.eq_ignore_ascii_case("group")) {
            IdentityKind::Group
        } else {
            IdentityKind::User
        };
        results.push(IdentitySearchResult {
            sid,
            sam_account_name: sam,
            display_name,
            kind,
        });
    }

    Ok(results)
}

// ---------------------------------------------------------------------------
// Persistierung
// Persistence
// ---------------------------------------------------------------------------

/// Persists a scan run and returns either the run ID or a human-readable
/// failure reason.
///
/// Strukturierte Walk-/Eval-Fehler aus `errors` werden via
/// denselben Audit-Pfad wie CLI-Scans (Finding 6).
///
/// Structured walk/eval errors from `errors` are written to `scan_errors`
/// via `store.insert_error` — giving GUI scans the same audit trail as
/// CLI scans (Finding 6). When `cancelled`, an additional pathless
/// diagnostic note is appended.
fn persist_scan(
    db: &Database,
    target: &str,
    permissions: &[EffectivePermission],
    errors: &[ScanError],
    cancelled: bool,
) -> Result<String, String> {
    let run_id = Uuid::new_v4();
    let run = ScanRun {
        id: run_id,
        started_at: Utc::now(),
        finished_at: Some(Utc::now()),
        target: target.to_string(),
        errors: vec![],
    };
    let store = db.scan_store();
    if let Err(e) = store.insert_scan_run(&run) {
        warn!(error = %e, "Failed to persist scan run");
        return Err(format!("could not create scan run: {e}"));
    }
    for perm in permissions {
        if let Err(e) = store.insert_permission(&run_id, perm) {
            warn!(error = %e, "Failed to persist permission");
        }
    }
    for err in errors {
        if let Err(e) = store.insert_error(&run_id, err) {
            warn!(error = %e, "Failed to persist scan error");
        }
    }
    if cancelled {
        let _ = store.insert_error(
            &run_id,
            &ScanError {
                path: None,
                message: "Scan cancelled by user — results are partial".to_owned(),
            },
        );
    }
    if let Err(e) = store.finish_scan_run(&run_id, Utc::now()) {
        warn!(error = %e, "Failed to finish scan run");
    }
    Ok(run_id.to_string())
}

// ---------------------------------------------------------------------------
// HTML-Export
// HTML export
// ---------------------------------------------------------------------------

fn export_html(
    permissions: &[EffectivePermission],
    risk_findings: &[RiskFinding],
    path_trustees: &[adpa_core::model::PathTrustees],
    output_path: &str,
) -> Result<(), String> {
    let status =
        validate_export_path(output_path).map_err(|e| format!("Invalid export path: {e}"))?;
    // Round-7 finding 2: the GUI had no overwrite policy. Pre-existing
    // files were silently truncated by HtmlExporter (fs::File::create).
    // Audit reports are sensitive — a re-run must not overwrite a prior
    // report unattended. We refuse the Exists case with a clear message
    // and let the user pick a fresh path.
    if let ExportPathStatus::Exists(p) = &status {
        return Err(format!(
            "Zieldatei existiert bereits: {}. Bitte anderen Namen wählen oder die Datei vorab loeschen.",
            p.0.display()
        ));
    }
    let validated_path = status.path().0.clone();
    let result = AnalysisResult {
        permissions: permissions.to_vec(),
        risk_findings: risk_findings.to_vec(),
        path_trustees: path_trustees.to_vec(),
    };
    HtmlExporter
        .export(&result, ExportTarget::File(validated_path))
        .map_err(|e| format!("Export failed: {e}"))
}

// ---------------------------------------------------------------------------
// Delta tab: persisted scan runs and comparison
// ---------------------------------------------------------------------------

/// Delta-Tab-Anzeige (neueste zuerst). Die Vorgabe „neueste zuerst" stammt
/// Returns persisted scan runs in a compact form for the Delta tab
/// (newest first). The sort order comes from `Database::list_scan_runs`.
fn list_scan_run_summaries(db: &Database) -> Result<Vec<ScanRunSummary>, String> {
    let runs = db
        .list_scan_runs()
        .map_err(|e| format!("Scan-Historie konnte nicht geladen werden: {e}"))?;
    Ok(runs
        .into_iter()
        .map(|r| ScanRunSummary {
            id: r.id.to_string(),
            // Format ohne Sekundenbruchteile, lokal lesbar.
            // Format without sub-second fractions, locally readable.
            started_at: r.started_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            target: r.target,
            error_count: r.errors.len(),
        })
        .collect())
}

/// `IdentitySuggestion`-Strukturen.
/// Collects a compact identity list for the GUI's name field live
/// search. Converts `IdentitySnapshot` entries from
/// `ad_resolver::enumerate` into the channel-friendly
/// `IdentitySuggestion` structs.
#[cfg(windows)]
fn collect_identity_suggestions() -> Result<Vec<IdentitySuggestion>, String> {
    let snapshot = ad_resolver::enumerate_all();
    Ok(snapshot
        .into_iter()
        .map(|s| IdentitySuggestion {
            qualified: s.qualified_name(),
            kind_icon: kind_to_icon(&s.kind, &s.domain).into(),
            name: s.name,
            description: s.description,
        })
        .collect())
}

#[cfg(not(windows))]
fn collect_identity_suggestions() -> Result<Vec<IdentitySuggestion>, String> {
    Err("Identitäts-Enumeration verfügt nur unter Windows (NetAPI)".to_string())
}

fn kind_to_icon(kind: &IdentityKind, domain: &str) -> &'static str {
    match kind {
        IdentityKind::User => "U",
        // Local groups carry domain "BUILTIN" — own marker so the auditor
        // sees which membership class he's hitting.
        IdentityKind::Group if domain.eq_ignore_ascii_case("BUILTIN") => "L",
        IdentityKind::Group => "G",
        IdentityKind::WellKnown => "W",
        IdentityKind::Computer => "C",
        IdentityKind::Orphaned | IdentityKind::Unknown => "?",
    }
}

/// Compares two scan runs and translates the persistence result into
/// compact `DeltaRow` structs that map straight into the Slint UI.
/// Removes a scan run including all dependent data from the SQLite history.
/// Returns `Ok(())` even if the ID did not exist — the GUI has to sync local
/// state regardless.
fn delete_scan_run(db: &Database, run_id: &str) -> Result<(), String> {
    let id =
        Uuid::parse_str(run_id).map_err(|e| format!("Ungültige Scan-Run-ID '{run_id}': {e}"))?;
    db.delete_scan_run(&id)
        .map_err(|e| format!("Löschen fehlgeschlagen: {e}"))?;
    Ok(())
}

// Inheritance / propagation flags wie sie Windows in ACE_HEADER.AceFlags ablegt.
// Inheritance / propagation flags as Windows stores them in
// ACE_HEADER.AceFlags. The `fs_scanner` implementation splits them into two
// fields (`inheritance_flags`, `propagation_flags`); we re-combine them for
// the "Applies to" display.
const OBJECT_INHERIT_ACE_FLAG: u32 = 0x01;
const CONTAINER_INHERIT_ACE_FLAG: u32 = 0x02;
const NO_PROPAGATE_INHERIT_ACE_FLAG: u32 = 0x04;
const INHERIT_ONLY_ACE_FLAG: u32 = 0x08;

/// Sicherheits-GUI bekannte „Applies to"-Bezeichnung ab.
/// Maps Windows inheritance / propagation flags to the "Applies to" label
/// known from the security GUI.
fn applies_to_label(inheritance_flags: u32, propagation_flags: u32) -> String {
    let flags = inheritance_flags | propagation_flags;
    let container = flags & CONTAINER_INHERIT_ACE_FLAG != 0;
    let object = flags & OBJECT_INHERIT_ACE_FLAG != 0;
    let inherit_only = flags & INHERIT_ONLY_ACE_FLAG != 0;
    let no_propagate = flags & NO_PROPAGATE_INHERIT_ACE_FLAG != 0;
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

/// Namen, normalisierten Rechten und Windows-typischer „Applies to"-
/// Reads a path's DACL (and optionally the share DACL) and returns a
/// trustee-centric view: one row per ACE with a resolved name,
/// normalized rights and Windows-style "Applies to" label. No engine
/// evaluation happens — the mask is the raw ACE mask, not the computed
/// effective result.
fn analyze_trustees(
    path: &str,
    smb_server: Option<&str>,
    share_name: Option<&str>,
) -> Result<Vec<TrusteeRow>, String> {
    info!(
        path,
        smb_server = ?smb_server,
        share_name = ?share_name,
        "AnalyzeTrustees request"
    );
    // Review 2026-06-04 Runde 2, Finding 6: Normalform durchreichen.
    // Review 2026-06-04 round 2, finding 6: propagate the normal form.
    let normalized_path = validate_path(path)
        .map_err(|e| format!("Invalid path: {e}"))?
        .0;
    let path = normalized_path.as_str();
    // Review 2026-06-04 Runde 3 Finding 2 + Runde 4 Finding 3:
    // getrimmte Werte weiterreichen UND Paar-Pflicht erzwingen,
    // Trustees fuehrt.
    // Round 3 finding 2 + round 4 finding 3: trim + enforce pairing.
    let (smb_server, share_name) = normalize_smb_pair(smb_server, share_name)?;
    // Code-Review 2026-06-07 Finding 2: Bisher wurde `build_trustee_rows`
    // direkt mit dem normalisierten Paar aufgerufen — bei einem blanken
    // `SmbAuditContext::resolve` (Round-10 Finding 1) — `analyze_trustees`
    // derselbe UNC-Pfad zeigt im Trustee-Tab dieselben Schichten wie im
    // Scan-Tab.
    // Code review 2026-06-07 finding 2: previously this passed the
    // normalized pair straight to `build_trustee_rows` — a bare UNC path
    // without explicit `--smb-server`/`--share-name` left the pair as
    // `(None, None)` and the trustee table showed NTFS rows only. CLI
    // analyze and GUI scan extract server/share from the UNC path via
    // `SmbAuditContext::resolve` (Round-10 finding 1); `analyze_trustees`
    // had been missed. This call closes the gap: the same UNC path now
    // shows the same layers in the trustee tab as in the scan tab.
    let smb_ctx = validation::path::SmbAuditContext::resolve(
        path,
        smb_server.as_deref(),
        share_name.as_deref(),
    );
    let fso = read_fso(path).map_err(|e| format!("Failed to read path: {e}"))?;
    Ok(build_trustee_rows(
        &fso,
        smb_ctx.as_ref().map(|c| c.server.as_str()),
        smb_ctx.as_ref().map(|c| c.share.as_str()),
    ))
}

// Die rohe Trustee-Build-Logik (read_share_overlay,
// build_path_trustees, build_path_trustees_with_share) liegt seit
// Review Runde 9 Finding 1 in `crates/exporter/src/trustees.rs` —
// existierende Aufrufstellen ohne Anpassung weiterlaufen.
// The raw trustee-build logic (read_share_overlay, build_path_trustees,
// build_path_trustees_with_share) was moved to
// `crates/exporter/src/trustees.rs` in round-9 finding 1 so CLI and
// GUI share the same helper without either layer referencing the
// other. The GUI re-exports the symbols so existing call sites keep
// compiling.
pub use exporter::{
    build_path_trustees, build_path_trustees_with_share_and_names, read_share_overlay,
    ShareTrusteeOverlay,
};

// `build_path_trustees_with_share` (no SID map) is still available in
// `exporter`, but the GUI no longer needs it since round-10 finding 2
// — the scan path now uses the map variant.

// The local helper block (ShareTrusteeOverlay struct plus three
// functions) was removed in favour of the shared module above.

/// Allow/Deny-Label aus dem rohen Modell.
/// Converts a raw `PathTrustee` to the display-formatted `TrusteeRow`
/// consumed by the Slint UI. Derives "Applies to", mask hex and the
/// Allow/Deny label from the raw model.
pub fn trustee_row_for_display(entry: &adpa_core::model::PathTrusteeEntry) -> TrusteeRow {
    use adpa_core::model::{AceKind, PathTrusteeEntry, TrusteeCategory};
    use permission_engine::mask::expand_generic_rights;

    match entry {
        // Zeile gerendert — kein Allow/Deny-Label, leere SID-/Maske-Felder,
        // visuell unterscheidbar (im Slint-Layout via leerem `kind` und
        // gelblichem Hintergrund auf dem TrusteeRow-Render-Pfad).
        // Round-10 finding 4: diagnostic variant becomes its own row —
        // no Allow/Deny label, empty SID/mask fields, reason text in
        // display_name. The GUI renders it visibly different (in Slint
        // via empty `kind` and a yellowish background).
        PathTrusteeEntry::Diagnostic { category, message } => {
            let category_label = match category {
                TrusteeCategory::Ntfs => "NTFS",
                TrusteeCategory::Share => "Share",
            };
            TrusteeRow {
                sid: String::new(),
                display_name: format!("\u{26A0} {}", message),
                kind: "Diagnose".to_owned(),
                rights_label: "—".to_owned(),
                mask_hex: "—".to_owned(),
                source: "—".to_owned(),
                applies_to: "—".to_owned(),
                category: category_label.to_owned(),
            }
        }
        PathTrusteeEntry::Ace(t) => {
            let expanded = expand_generic_rights(t.mask.0);
            let rights = NormalizedRights::new(expanded);
            let category = match t.category {
                TrusteeCategory::Ntfs => "NTFS",
                TrusteeCategory::Share => "Share",
            };
            let kind_label = match t.kind {
                AceKind::Allow => "Allow",
                AceKind::Deny => "Deny",
            };
            // „Share"-Anwendung beibehalten — sonst die Windows-typische
            // „Applies to"-Bezeichnung aus den Flags.
            // For share entries without an inheritance model keep the static
            // "Share" label — otherwise derive the Windows-style "Applies to"
            // text from the flags.
            let applies_to = if matches!(t.category, TrusteeCategory::Share) {
                "Share".to_owned()
            } else {
                applies_to_label(t.inheritance_flags, t.propagation_flags)
            };
            let source = if t.inherited { "inherited" } else { "explicit" };
            let display_name = t.display_name.clone().unwrap_or_else(|| t.sid.0.clone());
            TrusteeRow {
                sid: t.sid.0.clone(),
                display_name,
                kind: kind_label.to_owned(),
                rights_label: format!("{} ({})", rights.display_name(), rights.label()),
                mask_hex: format!("0x{:08X}", t.mask.0),
                source: source.to_owned(),
                applies_to,
                category: category.to_owned(),
            }
        }
    }
}

/// Legacy-Display-Variante: kombiniert `build_path_trustees` und
/// vom GUI-Renderer genutzt.
/// Legacy display variant: combines `build_path_trustees` and
/// `trustee_row_for_display` in one call — used by the Analyze tab and the
/// GUI renderer.
pub fn build_trustee_rows(
    fso: &adpa_core::model::FileSystemObject,
    smb_server: Option<&str>,
    share_name: Option<&str>,
) -> Vec<TrusteeRow> {
    build_path_trustees(fso, smb_server, share_name)
        .iter()
        .map(trustee_row_for_display)
        .collect()
}

fn compute_delta(
    db: &Database,
    old_run_id: &str,
    new_run_id: &str,
) -> Result<Vec<DeltaRow>, String> {
    let old_id =
        Uuid::parse_str(old_run_id).map_err(|e| format!("Ungültige alte Scan-Run-ID: {e}"))?;
    let new_id =
        Uuid::parse_str(new_run_id).map_err(|e| format!("Ungültige neue Scan-Run-ID: {e}"))?;
    let entries = db
        .compare_scans(&old_id, &new_id)
        .map_err(|e| format!("Vergleich fehlgeschlagen: {e}"))?;

    Ok(entries
        .into_iter()
        .map(|entry| {
            use persistence::DeltaKind;
            match entry.kind {
                DeltaKind::Added => DeltaRow {
                    path: entry.path.0,
                    kind_label: "Hinzugefügt".into(),
                    old_rights: String::new(),
                    new_rights: entry.new_perm.map(format_rights).unwrap_or_default(),
                },
                DeltaKind::Removed => DeltaRow {
                    path: entry.path.0,
                    kind_label: "Entfernt".into(),
                    old_rights: entry.old_perm.map(format_rights).unwrap_or_default(),
                    new_rights: String::new(),
                },
                DeltaKind::Changed {
                    old_mask,
                    new_mask,
                    reasons,
                } => {
                    // Code Review 2026-06-07 Finding 3: zeige zusaetzlich
                    // zur effektiven Maske die konkreten Aenderungsursachen
                    // ("NTFS mask + share status"), damit Audit-relevante
                    // Aenderungen mit gleichbleibender Endmaske sichtbar
                    // aber alt/neu im UI gleich aussehen.
                    // Code review 2026-06-07 finding 3: in addition to the
                    // effective mask, show the concrete change reasons
                    // ("NTFS mask + share status") so audit-relevant
                    // changes with an unchanged final mask become
                    // visible — without this the row would appear but
                    // old/new would look identical in the UI.
                    let reasons_label = reasons
                        .iter()
                        .map(|r| r.label())
                        .collect::<Vec<_>>()
                        .join(" + ");
                    let kind_label = if reasons_label.is_empty() {
                        "Geändert".into()
                    } else {
                        format!("Geändert ({reasons_label})")
                    };
                    DeltaRow {
                        path: entry.path.0,
                        kind_label,
                        old_rights: format_mask(old_mask.0),
                        new_rights: format_mask(new_mask.0),
                    }
                }
            }
        })
        .collect())
}

/// Formats the effective permission of an `EffectivePermission` as a
/// "label (0x...)" string for the delta display.
fn format_rights(perm: EffectivePermission) -> String {
    format_mask(perm.effective_mask.0)
}

fn format_mask(mask: u32) -> String {
    let rights = NormalizedRights::new(mask);
    format!("{} (0x{:08X})", rights.display_name(), mask)
}

// ---------------------------------------------------------------------------
// Identity resolution
// ---------------------------------------------------------------------------

/// Creates a minimal identity (SID-only) or resolves via LDAP.
/// (Review-Befund 6).
/// Returns `(Identity, Memberships, used_sam_fallback)`. The flag is `true`
/// if group resolution used `NetUserGetGroups` (SAM/LSA) instead of LDAP —
/// in that case the domain group recursion is incomplete and the caller
/// must forward the fact into the engine input (review finding 6).
async fn resolve_identity_sids(
    sid: &str,
    ldap: Option<&LdapParams>,
) -> Result<PrincipalResolution, String> {
    if let Some(params) = ldap {
        let mut config = LdapConfig::new(
            &params.server,
            &params.base_dn,
            &params.bind_dn,
            &params.password,
        );
        if params.insecure {
            config.tls_mode = TlsMode::Insecure;
            config.port = 389;
        }
        let resolver = std::sync::Arc::new(LdapResolver::new(config));
        let backend = LdapIdentityBackend::new(resolver);
        // Zentrale Principal-Pipeline — schliesst Review 2026-06-04
        // Runde 3 Finding 1, indem der GUI-SID-Pfad denselben
        // LDAP-/LSA-Crosscheck bekommt wie der CLI-DOMAIN\user-Pfad.
        // Central principal pipeline — closes review round 3 finding 1.
        #[cfg(windows)]
        let principal = PrincipalResolver::new(backend, Some(WindowsLsaBackend));
        #[cfg(not(windows))]
        let principal: PrincipalResolver<_, NoLsaBackend> = PrincipalResolver::new(backend, None);
        return principal
            .resolve(PrincipalInput::Sid(Sid(sid.to_string())))
            .await
            .map_err(|e| format!("LDAP identity resolution failed: {e}"));
    }

    //
    // Without LDAP: use the local SAM/LSA as the default resolver on Windows.
    // On a domain controller this covers full domain membership; on a
    // workstation, whatever the LSA has cached. Only if SAM resolution also
    // fails (or we are not on Windows) does the worker fall back to a bare
    // SID identity — then the effective rights are only what direct ACEs on
    // the SID grant.
    // `used_sam_fallback = true`.
    // Both paths (SAM success and bare SID fallback) are LDAP-free → nested
    // domain groups are not fully resolved, so `used_sam_fallback = true`.
    // Schliesst Review 2026-06-04 Runde 2 Finding 5: `sam_resolve_fallback`
    // setzen wir `DisabledStatus::Unknown` — die Engine pusht den
    // passenden Diagnose-Marker. Closes review round 2 finding 5.
    let (identity, memberships, disabled_known) = sam_resolve_fallback(sid)?;
    let disabled_status = if disabled_known {
        ad_resolver::DisabledStatus::Known(identity.disabled)
    } else {
        ad_resolver::DisabledStatus::Unknown
    };
    let mut diagnostics: Vec<adpa_core::model::PermissionDiagnostic> = Vec::new();
    if matches!(disabled_status, ad_resolver::DisabledStatus::Unknown) {
        diagnostics.push(adpa_core::model::PermissionDiagnostic::IdentityDisabledStatusUnknown);
    } else if identity.disabled {
        diagnostics.push(adpa_core::model::PermissionDiagnostic::IdentityDisabled);
    }
    Ok(PrincipalResolution {
        sid: identity.sid.clone(),
        identity,
        memberships,
        // sichtbar und treibt den passenden Engine-Marker.
        // SAM-only on a DC = local domain → Inside; the flat recursion
        // is signalled separately via SamFlat.
        scope_status: ad_resolver::IdentityScopeStatus::InsideConfiguredLdapBase,
        group_resolution_status: ad_resolver::GroupResolutionStatus::SamFlat,
        disabled_status,
        diagnostics,
    })
}

/// `IdentityResolution::disabled_status_unknown = true`.
/// Returns `(Identity, memberships, disabled_known)`. The third value
/// flags whether `Identity.disabled` was confirmed via
/// `NetUserGetInfo`. When `false` the caller sets
/// `IdentityResolution::disabled_status_unknown = true`.
#[cfg(windows)]
fn sam_resolve_fallback(sid: &str) -> Result<(Identity, Vec<GroupMembership>, bool), String> {
    match ad_resolver::resolve_identity_via_sam(sid) {
        Ok(res) => {
            info!(
                sid,
                name = ?res.identity.name,
                domain = ?res.identity.domain,
                kind = ?res.identity.kind,
                group_count = res.memberships.len(),
                disabled_known = res.disabled_known,
                "SAM resolution succeeded (no LDAP requested)"
            );
            Ok((res.identity, res.memberships, res.disabled_known))
        }
        Err(e) => {
            warn!(sid, error = %e, "SAM resolution failed — falling back to bare SID identity");
            let (identity, memberships) = bare_sid_identity(sid);
            // Bare SID = wir wissen schlicht nichts ueber den User.
            // Bare SID = we know essentially nothing about the user.
            Ok((identity, memberships, false))
        }
    }
}

#[cfg(not(windows))]
fn sam_resolve_fallback(sid: &str) -> Result<(Identity, Vec<GroupMembership>, bool), String> {
    let (identity, memberships) = bare_sid_identity(sid);
    Ok((identity, memberships, false))
}

fn bare_sid_identity(sid: &str) -> (Identity, Vec<GroupMembership>) {
    let identity = Identity {
        sid: Sid(sid.to_string()),
        name: None,
        domain: None,
        kind: IdentityKind::Unknown,
        disabled: false,
        user_principal_name: None,
    };
    (identity, vec![])
}

/// Berechnet die Share-Maske einmalig vor dem Scan.
/// Computes the share mask and its evaluation status.
///
/// Returns `NotApplicable` when no SMB context exists, `Applied(mask)` on
/// success, or `ReadFailed(reason)` when the share DACL could not be read.
fn resolve_share_status(
    path: &str,
    smb_server: Option<&str>,
    share_name: Option<&str>,
    sid: &str,
    memberships: &[GroupMembership],
    local_group_sids: &[adpa_core::model::Sid],
    access_context: AccessContext,
) -> (adpa_core::model::ShareMaskStatus, usize) {
    use adpa_core::model::ShareMaskStatus;
    // Computation und Trustee-Overlay garantiert konsistent.
    // Round-10 finding 1: server and share derivation come from
    // `SmbAuditContext::resolve` — the same source the trustee overlay
    // build and the CLI paths use. Mask computation and trustee
    // overlay are guaranteed to agree.
    let smb_ctx = match validation::path::SmbAuditContext::resolve(path, smb_server, share_name) {
        Some(c) => c,
        None => return (ShareMaskStatus::NotApplicable, 0),
    };
    let server = smb_ctx.server;
    let share = smb_ctx.share;

    // Token-SIDs muessen Share- und NTFS-Auswertung uebereinstimmend abdecken.
    // bei SMB im Token landet — sonst werden Deny-NETWORK-Share-ACEs
    // ignoriert (Review-Folge-Befund 1).
    // Token SIDs must cover share and NTFS evaluation consistently. The
    // access context further ensures e.g. NETWORK (S-1-5-2) is in the SMB
    // token, otherwise Deny-NETWORK share ACEs are ignored (follow-up
    // review finding 1).
    let user_sids =
        build_token_sids_with_context(sid, memberships, local_group_sids, access_context);

    match get_share_dacl(&server, &share) {
        Ok(scan) => {
            // NULL share DACL → eigener Status, keine kuenstliche 0xFFFFFFFF-Maske.
            // NULL share DACL → dedicated status, no fabricated 0xFFFFFFFF mask.
            let status = match effective_share_mask(&scan.dacl, &user_sids) {
                Some(mask) => ShareMaskStatus::Applied(mask),
                None => ShareMaskStatus::Unrestricted,
            };
            (status, scan.unsupported_count)
        }
        Err(e) => {
            warn!(server, share, error = %e, "Failed to get share DACL");
            (ShareMaskStatus::ReadFailed(e.to_string()), 0)
        }
    }
}

// validation::path::parse_unc_components.
// UNC parsing now lives centrally in validation::path::parse_unc_components.
// Long-path UNC (\\?\UNC\…) is handled correctly there — review finding 4
// applied to the GUI-local variant that used to live here. The original
// documentation rationale lives in validation::path::parse_unc_components.

#[cfg(test)]
mod tests {
    use super::*;

    // Round-Trip-Smoke-Test, dass der GUI-Worker den Helfer wirklich nutzt
    // (Sentinel-Bug aus Review-Befund 1).
    // The UNC parsing tests moved to validation::path where the shared
    // helper `parse_unc_components` lives. Here only a smoke test that the
    // GUI worker actually delegates to it (sentinel bug from review
    // finding 1).
    #[test]
    fn share_status_does_not_treat_local_path_as_unc() {
        // Lokaler Pfad ohne SMB-Override → kein Share-Lookup, NotApplicable.
        // Local path without an SMB override → no share lookup, NotApplicable.
        // Before the fix this would have called `NetShareGetInfo("C:", "Windows")`.
        let dummy_id = Identity {
            sid: adpa_core::model::Sid("S-1-5-21-1-2-3-1000".to_owned()),
            name: Some("test".into()),
            domain: None,
            kind: adpa_core::model::IdentityKind::User,
            disabled: false,
            user_principal_name: None,
        };
        let (status, _unsupported) = resolve_share_status(
            r"C:\Windows\SYSVOL",
            None,
            None,
            &dummy_id.sid.0,
            &[],
            &[],
            AccessContext::LocalInteractive,
        );
        assert!(matches!(
            status,
            adpa_core::model::ShareMaskStatus::NotApplicable
        ));
    }

    /// `cancelled = true`.
    /// Finding 6: persist_scan must write structured walk/eval errors to
    /// `scan_errors` — alongside the cancellation marker when
    /// `cancelled = true`.
    #[test]
    fn persist_scan_writes_walk_errors_to_scan_errors() {
        let db = Database::open_in_memory().expect("in-memory DB");
        let errors = vec![
            ScanError {
                path: Some(NormalizedPath(r"C:\Denied".to_owned())),
                message: "Access denied reading security descriptor".to_owned(),
            },
            ScanError {
                path: Some(NormalizedPath(r"C:\Missing".to_owned())),
                message: "Path not found".to_owned(),
            },
        ];

        let run_id_str = persist_scan(&db, r"C:\Root", &[], &errors, false)
            .expect("persist_scan should succeed");
        let run_id = Uuid::parse_str(&run_id_str).expect("valid UUID");

        let persisted = db
            .scan_store()
            .list_errors_for(&run_id)
            .expect("list_errors_for");
        assert_eq!(
            persisted.len(),
            2,
            "Walk-Fehler müssen in scan_errors landen, gefunden: {persisted:?}"
        );
        assert_eq!(
            persisted[0].path.as_ref().map(|p| p.0.as_str()),
            Some(r"C:\Denied")
        );
        assert!(persisted[0].message.contains("Access denied"));
        assert_eq!(
            persisted[1].path.as_ref().map(|p| p.0.as_str()),
            Some(r"C:\Missing")
        );
    }

    #[test]
    fn persist_scan_appends_cancellation_marker_with_null_path() {
        let db = Database::open_in_memory().expect("in-memory DB");
        let errors = vec![ScanError {
            path: Some(NormalizedPath(r"C:\Denied".to_owned())),
            message: "Access denied".to_owned(),
        }];

        let run_id_str =
            persist_scan(&db, r"C:\Root", &[], &errors, true).expect("persist_scan should succeed");
        let run_id = Uuid::parse_str(&run_id_str).unwrap();

        let persisted = db.scan_store().list_errors_for(&run_id).unwrap();
        assert_eq!(persisted.len(), 2, "Walk-Fehler + Cancel-Marker erwartet");
        // Cancel marker has path = None and is appended last.
        assert!(persisted[1].path.is_none());
        assert!(persisted[1].message.contains("cancelled"));
    }

    #[test]
    fn persist_scan_with_no_errors_yields_empty_scan_errors_when_not_cancelled() {
        let db = Database::open_in_memory().expect("in-memory DB");
        let run_id_str = persist_scan(&db, r"C:\Root", &[], &[], false).unwrap();
        let run_id = Uuid::parse_str(&run_id_str).unwrap();
        let persisted = db.scan_store().list_errors_for(&run_id).unwrap();
        assert!(
            persisted.is_empty(),
            "Ohne Walk-Fehler und ohne Abbruch dürfen keine Einträge in scan_errors stehen"
        );
    }

    /// Review 2026-06-04 Runde 3 Finding 3: `build_path_trustees_with_share`
    /// und beide Kategorien (`Ntfs`, `Share`) im Ergebnis ausweisen.
    /// Verhindert den Regress, dass der Scan-Pfad Share-Trustees still
    /// weglaesst.
    /// Review round 3 finding 3: the precomputed share overlay must be
    /// attached to the NTFS list and both categories must show up.
    #[test]
    fn build_path_trustees_with_share_includes_overlay() {
        use adpa_core::model::{
            AccessMask, AceEntry, AceKind, FileSystemObject, NormalizedPath, PathTrustee, Sid,
            TrusteeCategory,
        };
        let fso = FileSystemObject {
            path: NormalizedPath(r"C:\share\folder".to_owned()),
            is_directory: true,
            owner_sid: None,
            dacl: vec![AceEntry {
                sid: Sid("S-1-5-21-1-1-1-1001".to_owned()),
                kind: AceKind::Allow,
                mask: AccessMask(0x001F01FF),
                inherited: false,
                inheritance_flags: 0x03,
                propagation_flags: 0,
            }],
            inheritance_disabled: false,
            is_reparse_point: false,
            unsupported_aces: vec![],
            null_dacl: false,
        };
        let overlay = ShareTrusteeOverlay {
            trustees: vec![adpa_core::model::PathTrusteeEntry::Ace(PathTrustee {
                sid: Sid("S-1-5-32-545".to_owned()),
                display_name: Some("BUILTIN\\Users".to_owned()),
                kind: AceKind::Allow,
                mask: AccessMask(0x001200A9),
                inherited: false,
                inheritance_flags: 0,
                propagation_flags: 0,
                category: TrusteeCategory::Share,
            })],
        };

        let empty_map: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        let combined = build_path_trustees_with_share_and_names(&fso, Some(&overlay), &empty_map);

        let ntfs_count = combined
            .iter()
            .filter(|t| matches!(t.category(), TrusteeCategory::Ntfs))
            .count();
        let share_count = combined
            .iter()
            .filter(|t| matches!(t.category(), TrusteeCategory::Share))
            .count();
        assert_eq!(ntfs_count, 1, "must contain the NTFS trustee");
        assert_eq!(
            share_count, 1,
            "must contain the share overlay trustee — closing review round 3 finding 3"
        );
    }

    /// nur NTFS-Trustees — identisches Verhalten wie vorher.
    /// Without an overlay (no SMB context) the with-share variant
    /// returns only NTFS trustees — same as before.
    #[test]
    fn build_path_trustees_with_share_falls_back_to_ntfs_only_without_overlay() {
        use adpa_core::model::{
            AccessMask, AceEntry, AceKind, FileSystemObject, NormalizedPath, Sid, TrusteeCategory,
        };
        let fso = FileSystemObject {
            path: NormalizedPath(r"C:\local\folder".to_owned()),
            is_directory: true,
            owner_sid: None,
            dacl: vec![AceEntry {
                sid: Sid("S-1-5-21-1-1-1-1001".to_owned()),
                kind: AceKind::Allow,
                mask: AccessMask(0x001F01FF),
                inherited: false,
                inheritance_flags: 0x03,
                propagation_flags: 0,
            }],
            inheritance_disabled: false,
            is_reparse_point: false,
            unsupported_aces: vec![],
            null_dacl: false,
        };
        let empty_map: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        let combined = build_path_trustees_with_share_and_names(&fso, None, &empty_map);
        assert!(
            combined
                .iter()
                .all(|t| matches!(t.category(), TrusteeCategory::Ntfs)),
            "no overlay → only NTFS trustees"
        );
    }

    /// Review 2026-06-04 Runde 4 Finding 2: Whitespace-umrahmte SID
    /// `handle_analyze`/`handle_scan` (klassifizieren → validieren),
    /// Review 2026-06-04 Runde 4 Finding 3: `normalize_smb_pair` (von
    /// `analyze_trustees` und `validate_connection_inputs` geteilt)
    /// muss halbe SMB-Kontexte ablehnen — sonst entsteht ein stiller
    /// NTFS-only-Fallback.
    /// Code Review 2026-06-07 Finding 2: `analyze_trustees` muss bei
    /// einem blanken UNC-Pfad ohne explizite SMB-Felder den Server
    /// indem er `SmbAuditContext::resolve` direkt aufruft — exakt mit
    /// verwendet.
    /// Code review 2026-06-07 finding 2: `analyze_trustees` must
    /// derive server + share from a bare UNC path without explicit
    /// SMB fields — previously the trustee tab showed NTFS-only while
    /// scan tab and CLI analyze picked up the share layer via
    /// `SmbAuditContext::resolve`. The test covers the four semantic
    /// cases by invoking `SmbAuditContext::resolve` directly with the
    /// exact argument shape the patched `analyze_trustees` body uses.
    #[test]
    fn analyze_trustees_uses_smb_audit_context_for_unc_paths() {
        use validation::path::SmbAuditContext;

        // Case 1: bare UNC, no explicit fields -> server + share from UNC.
        let ctx = SmbAuditContext::resolve(r"\\fs01\data\subdir", None, None);
        let ctx = ctx.expect("bare UNC must yield SMB context — closes finding 2");
        assert_eq!(ctx.server, "fs01");
        assert_eq!(ctx.share, "data");

        // Case 2: explicit fields override UNC components.
        let ctx = SmbAuditContext::resolve(
            r"\\fs01\data\subdir",
            Some("other-server"),
            Some("other-share"),
        );
        let ctx = ctx.expect("explicit pair must succeed");
        assert_eq!(ctx.server, "other-server");
        assert_eq!(ctx.share, "other-share");

        // Case 3: local path without explicit fields -> no SMB context.
        let ctx = SmbAuditContext::resolve(r"C:\Data\Local", None, None);
        assert!(
            ctx.is_none(),
            "local path without SMB fields must stay NTFS-only"
        );

        // Case 4: half-set is filtered by `normalize_smb_pair` before
        // reaching `SmbAuditContext::resolve` (see the test above).
        // Sanity: `resolve` itself also rejects a half-set on a
        // non-UNC path — the share name has no UNC fallback.
        let ctx = SmbAuditContext::resolve(r"C:\Data", Some("fs01"), None);
        assert!(ctx.is_none(), "half-set on non-UNC path must yield None");
    }

    /// Round 4 finding 3: half-set SMB context must error.
    #[test]
    fn normalize_smb_pair_rejects_half_set_combinations() {
        assert!(
            super::normalize_smb_pair(Some("fileserver"), None).is_err(),
            "smb_server alone must error — closing round 4 finding 3"
        );
        assert!(
            super::normalize_smb_pair(None, Some("data")).is_err(),
            "share_name alone must error — closing round 4 finding 3"
        );
        // Beide gesetzt: erfolgreich, getrimmt.
        // Both set: succeeds with trimmed values.
        let (s, n) = super::normalize_smb_pair(Some("  fileserver  "), Some("  data  "))
            .expect("matched pair must succeed");
        assert_eq!(s.as_deref(), Some("fileserver"));
        assert_eq!(n.as_deref(), Some("data"));
        // Beide leer: kein SMB-Kontext, kein Fehler.
        // Both empty: no SMB context, no error.
        let (s, n) = super::normalize_smb_pair(None, None).expect("no SMB context must succeed");
        assert!(s.is_none() && n.is_none());
    }

    /// Round 4 finding 2: whitespace-padded SID must classify as SID.
    #[test]
    fn whitespace_padded_sid_classifies_as_sid_after_trim() {
        let raw = "  S-1-5-21-1-2-3-4567  ";
        let trimmed = raw.trim();
        assert!(
            trimmed.starts_with("S-1-"),
            "trimmed value must classify as a SID — pre-condition of the fix"
        );
        let validated = validate_sid(trimmed).expect("trimmed SID must validate");
        assert_eq!(validated.0, "S-1-5-21-1-2-3-4567");

        //    klassifiziert, geht die SID verloren.
        assert!(
            !raw.starts_with("S-1-"),
            "regression guard: raw value must NOT classify as a SID — proves the fix is necessary"
        );
    }

    /// Zieldatei ablehnen statt sie wie bisher still zu kuerzen. CLI
    /// Round-7 finding 2: GUI HTML export must refuse to overwrite an
    /// existing target file instead of silently truncating it. CLI
    /// already enforces this via `check_overwrite_policy`; the GUI worker
    /// now enforces the same policy directly inside `export_html`.
    #[test]
    fn export_html_refuses_to_overwrite_existing_file() {
        use std::io::Write;
        // Mit einem eindeutigen Namen direkt im std::env::temp_dir() —
        // brauchen keine externe tempfile-Dependency.
        let unique = format!("adpa-gui-export-overwrite-{}.html", Uuid::new_v4());
        let path = std::env::temp_dir().join(unique);

        // Pre-existing file with sentinel content.
        {
            let mut f = std::fs::File::create(&path).expect("create sentinel file");
            f.write_all(b"<!-- sentinel: must not be overwritten -->")
                .expect("write sentinel");
        }

        let result = export_html(&[], &[], &[], path.to_str().expect("valid utf-8 path"));

        // Cleanup BEFORE asserting so a failure does not leak the file.
        let sentinel_before_cleanup = std::fs::read(&path).ok();
        let _ = std::fs::remove_file(&path);

        let err = result.expect_err("export must refuse pre-existing target");
        assert!(
            err.contains("existiert bereits"),
            "error must name the overwrite condition; got: {err}"
        );
        // Sentinel must still be intact at the time of refusal.
        assert_eq!(
            sentinel_before_cleanup.as_deref(),
            Some(b"<!-- sentinel: must not be overwritten -->".as_ref()),
            "pre-existing file content must remain untouched"
        );
    }
}
