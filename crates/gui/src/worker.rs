//! Hintergrund-Worker für Analysen, Scans und Delta-Vergleiche.
//! Background worker for analyses, scans and delta comparisons.
//!
//! Läuft in einem eigenen Thread mit Tokio-Runtime für optionale LDAP-Aufrufe.
//! Runs in a dedicated thread with a Tokio runtime for optional LDAP calls.
//!
//! Verdrahtet sind: `Analyze`, `Scan`, `ExportHtml`, `ListScanRuns`,
//! `ComputeDelta`. `SearchIdentity` bleibt für eine spätere Phase
//! (Identitäts-Picker in der GUI) reserviert — die Definition bleibt
//! stehen, damit der spätere Anbau keine API-Brüche erzeugt.
//!
//! Wired up: `Analyze`, `Scan`, `ExportHtml`, `ListScanRuns`,
//! `ComputeDelta`. `SearchIdentity` is reserved for a later phase (GUI
//! identity picker) — the definition stays so a future addition does not
//! cause API breaks.
#![allow(dead_code)]

use std::sync::mpsc::{Receiver, Sender};

use ad_resolver::sid_util::bytes_to_sid_str;
use ad_resolver::{
    format_account_for_local_groups, ldap_client, resolve_local_group_sids, LdapConfig,
    LdapResolver, TlsMode,
};
use adpa_core::{
    model::{
        AccessContext, EffectivePermission, GroupMembership, Identity, IdentityKind,
        NormalizedPath, RiskFinding, ScanError, ScanRun, Sid,
    },
    traits::{
        AnalysisResult, ExportTarget, Exporter, IdentityResolver, PermissionEvaluationInput,
        PermissionEvaluator, RiskContext,
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
    export_path::validate_export_path,
    net::{
        validate_dn, validate_identity_query, validate_ldap_endpoint, validate_share_name,
        validate_smb_server,
    },
    numbers::validate_optional_scan_depth,
    path::validate_path,
    sid::validate_sid,
};

/// Gibt den Standard-Datenbankpfad in %APPDATA%\Stars\ zurück.
/// Returns the default database path in %APPDATA%\Stars\.
///
/// Der Pfad liegt außerhalb des Installationsverzeichnisses, damit die
/// Scan-Historie eine Deinstallation überlebt.
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

/// LDAP-Verbindungsparameter für optionale AD-Auflösung.
/// LDAP connection parameters for optional AD resolution.
///
/// `Debug` ist hand-implementiert und maskiert das Passwort, damit ein
/// versehentliches `{params:?}` keine Secrets in Logs schreibt.
/// `Debug` is hand-implemented and masks the password so an accidental
/// `{params:?}` does not leak secrets into logs.
#[derive(Clone)]
pub struct LdapParams {
    pub server: String,
    pub base_dn: String,
    pub bind_dn: String,
    pub password: String,
    /// Wenn true: unverschlüsseltes LDAP (Port 389). Nur für Testumgebungen.
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

/// Suchergebnis für die Identitätssuche.
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
    /// Lädt die Liste aller persistierten Scan-Läufe für den Delta-Tab.
    /// Loads the list of all persisted scan runs for the Delta tab.
    ListScanRuns,
    /// Sammelt eine flache Identitäts-Liste (User, Gruppen, Well-Knowns)
    /// für die Live-Suche im Namensfeld der GUI. Einmalige Anforderung
    /// nach App-Start; die GUI hält das Ergebnis als Cache.
    /// Collects a flat identity list (users, groups, well-knowns) for the
    /// live search in the GUI's name field. One-shot request after app
    /// start; the GUI keeps the result as a cache.
    ListIdentities,
    /// Vergleicht zwei Scan-Läufe und liefert die Delta-Zeilen zurück.
    /// Compares two scan runs and returns the delta rows.
    ComputeDelta {
        old_run_id: String,
        new_run_id: String,
    },
}

/// Zeile im Scan-Ergebnis (für GUI-Tabelle).
/// Row in the scan result (for GUI table).
#[derive(Clone)]
pub struct ScanRow {
    pub path: String,
    pub rights_label: String,
    pub mask_raw: u32,
    pub steps: Vec<String>,
    /// Anzahl nicht ausgewerteter ACE-Typen auf diesem Pfad (> 0 = Diagnosewarnung).
    /// Count of unevaluated ACE types on this path (> 0 = diagnostic warning).
    pub unsupported_ace_count: usize,
    /// Anzahl strukturierter Diagnose-Marker (z. B. nicht-kanonisch sortierte
    /// DACL, Folge-Befund 3). 0 = unauffällig.
    /// Count of structured diagnostic markers (e.g. non-canonical DACL,
    /// follow-up finding 3). 0 = unremarkable.
    pub diagnostic_count: usize,
}

/// Ergebnis vom Worker-Thread an die GUI.
/// Result from the worker thread to the GUI.
pub enum WorkerEvent {
    AnalyzeDone(Result<adpa_core::model::EffectivePermission, String>),
    ScanItem(ScanRow),
    ScanError {
        path: String,
        message: String,
    },
    ScanDone {
        total: usize,
        errors: usize,
        /// UUID des gespeicherten Scan-Laufs (None wenn nicht gespeichert).
        /// UUID of the stored scan run (None if not persisted).
        scan_run_id: Option<String>,
        /// Grund, falls der Scan nicht in der Datenbank gespeichert werden konnte.
        /// Reason if the scan could not be persisted to the database.
        persistence_error: Option<String>,
        /// true wenn der Scan vom Benutzer abgebrochen wurde — Ergebnisse sind partiell.
        /// true if the scan was cancelled by the user — results are partial.
        cancelled: bool,
    },
    /// Risikobefunde nach Abschluss eines Scans.
    /// Risk findings after a scan completes.
    RiskFindings(Vec<RiskFinding>),
    /// Ergebnis eines HTML-Exports.
    /// Result of an HTML export.
    ExportDone(Result<(), String>),
    /// Suchergebnisse für die Identitätssuche.
    /// Search results for the identity search.
    SearchResults(Result<Vec<IdentitySearchResult>, String>),
    /// Persistierte Scan-Läufe für den Delta-Tab.
    /// Persisted scan runs for the Delta tab.
    ScanRunsLoaded(Result<Vec<ScanRunSummary>, String>),
    /// Identitäts-Snapshot für die Live-Suche im Namensfeld.
    /// Identity snapshot for the live search in the name field.
    IdentitiesLoaded(Result<Vec<IdentitySuggestion>, String>),
    /// Delta zwischen zwei Scan-Läufen, bereit für die Anzeige.
    /// Delta between two scan runs, ready for display.
    DeltaComputed(Result<Vec<DeltaRow>, String>),
}

/// Kompakte Zeile pro Scan-Lauf für die Anzeige im Delta-Tab.
/// Compact row per scan run for display in the Delta tab.
#[derive(Clone)]
pub struct ScanRunSummary {
    pub id: String,
    pub started_at: String,
    pub target: String,
    pub error_count: usize,
}

/// Ein einzelner Vorschlag in der Live-Suche der Namensfelder.
/// One suggestion in the name fields' live search.
#[derive(Clone)]
pub struct IdentitySuggestion {
    /// Reiner Name (das, was beim Klick ins Namensfeld kommt) — z.B.
    /// `Administrator`.
    /// Plain name (the value pushed into the name field on click) — e.g.
    /// `Administrator`.
    pub name: String,
    /// Qualifizierter Anzeige­name `DOMÄNE\Name`, oder nur `Name`, wenn
    /// keine Domäne bekannt ist.
    /// Qualified display name `DOMAIN\Name`, or just `Name` when no
    /// domain is known.
    pub qualified: String,
    /// Ein-Buchstaben-Marker für die UI: `U` (User), `G` (Group), `L`
    /// (lokale Gruppe), `W` (Well-Known).
    /// One-letter UI marker: `U` (user), `G` (group), `L` (local group),
    /// `W` (well-known).
    pub kind_icon: String,
    /// Optionale Beschreibung (`comment`-Felder der NetAPI) — kann leer
    /// bleiben.
    /// Optional description (NetAPI `comment` fields) — may be empty.
    pub description: String,
}

/// Eine Delta-Zeile, bereits für die Anzeige aufbereitet.
/// One delta row, ready for display.
#[derive(Clone)]
pub struct DeltaRow {
    pub path: String,
    /// Klartext-Label: "Hinzugefügt", "Entfernt", "Geändert".
    /// Plain-text label: "Added", "Removed", "Changed".
    pub kind_label: String,
    /// Alte Rechte (Klartext + Hex) oder leer, wenn `Added`.
    /// Old rights (plain text + hex) or empty when `Added`.
    pub old_rights: String,
    /// Neue Rechte (Klartext + Hex) oder leer, wenn `Removed`.
    /// New rights (plain text + hex) or empty when `Removed`.
    pub new_rights: String,
}

/// Startet den Worker-Thread und gibt Sender, Receiver und das Abbruch-Token zurück.
/// Starts the worker thread and returns the sender, receiver, and cancellation token.
///
/// Das Abbruch-Token wird von der GUI gehalten: `cancel()` wirkt direkt auf einen
/// laufenden Scan, ohne den (während des Scans blockierten) Request-Kanal zu benötigen.
/// The cancellation token is held by the GUI: `cancel()` acts directly on a running
/// scan without needing the request channel (which is blocked during a scan).
/// Callback, mit dem der Worker die GUI-Thread aufweckt, sobald ein neues
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
        // DB-Open-Fehler festhalten, statt ihn mit .ok() still zu verwerfen —
        // er wird pro Scan als sichtbarer Persistenzfehler gemeldet.
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
                    let _ = evt_tx.send(WorkerEvent::AnalyzeDone(result));
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
                    last_risk_findings = risks;
                    notify();
                }
                WorkerRequest::SearchIdentity { query, ldap } => {
                    let result = rt.block_on(handle_search(&query, &ldap));
                    let _ = evt_tx.send(WorkerEvent::SearchResults(result));
                    notify();
                }
                WorkerRequest::ExportHtml { output_path } => {
                    let result = export_html(&last_permissions, &last_risk_findings, &output_path);
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
    /// Strukturierte Walk-, Eval- und Validierungs-Fehler. Werden in
    /// `persist_scan` per `insert_error` in die Scan-Historie geschrieben,
    /// damit GUI-Scans denselben Audit-Pfad haben wie CLI-Scans.
    /// Structured walk, eval and validation errors. Written to the scan
    /// history via `insert_error` in `persist_scan` so that GUI scans get
    /// the same audit trail as CLI scans.
    errors: Vec<ScanError>,
    total: usize,
    /// true wenn der Scan vom Benutzer abgebrochen wurde.
    /// true if the scan was cancelled by the user.
    cancelled: bool,
}

/// Validiert optionale SMB- und LDAP-Verbindungs-Eingaben zentral, bevor sie
/// an NetAPI- oder LDAP-Aufrufe übergeben werden.
/// Centrally validates optional SMB and LDAP connection inputs before they are
/// passed to NetAPI or LDAP calls.
fn validate_connection_inputs(
    smb_server: Option<&str>,
    share_name: Option<&str>,
    ldap: Option<&LdapParams>,
) -> Result<(), String> {
    if let Some(s) = smb_server {
        validate_smb_server(s).map_err(|e| format!("Invalid SMB server: {e}"))?;
    }
    if let Some(s) = share_name {
        validate_share_name(s).map_err(|e| format!("Invalid share name: {e}"))?;
    }
    if let Some(p) = ldap {
        validate_ldap_endpoint(&p.server).map_err(|e| format!("Invalid LDAP server: {e}"))?;
        validate_dn(&p.base_dn).map_err(|e| format!("Invalid base DN: {e}"))?;
        validate_dn(&p.bind_dn).map_err(|e| format!("Invalid bind DN: {e}"))?;
    }
    Ok(())
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
    validate_path(path).map_err(|e| format!("Invalid path: {e}"))?;
    if sid.starts_with("S-1-") {
        validate_sid(sid).map_err(|e| format!("Invalid SID: {e}"))?;
    }
    validate_connection_inputs(smb_server, share_name, ldap)?;
    let fso = read_fso(path).map_err(|e| format!("Failed to read path: {e}"))?;
    let (identity, memberships) = resolve_identity_sids(sid, ldap).await?;

    // Lokale Server-Gruppen vor der Share-Maske bestimmen — siehe CLI-Pendant.
    // Resolve local server groups before the share mask — see CLI counterpart.
    let (local_group_sids, local_group_status) = collect_local_group_sids_for_path(path, &identity);

    let (share_status, unsupported_share_ace_count) = resolve_share_status(
        path,
        smb_server,
        share_name,
        sid,
        &memberships,
        &local_group_sids,
        AccessContext::for_path(path),
    );

    // SID→Name-Tabelle für den Erklärungspfad. Die DACL-Trustees werden
    // jetzt einmal aufgelöst, damit `Member of …` und `Allow ACE for …`
    // den lesbaren Namen mit anzeigen statt nur die SID.
    // SID→name table for the explanation path. DACL trustees are resolved
    // once so that `Member of …` and `Allow ACE for …` carry the readable
    // name in addition to the SID.
    #[cfg(windows)]
    let sid_names =
        ad_resolver::build_sid_name_map(&memberships, fso.dacl.iter().map(|a| a.sid.0.clone()));
    #[cfg(not(windows))]
    let sid_names = std::collections::BTreeMap::new();

    DefaultPermissionEngine
        .evaluate(PermissionEvaluationInput {
            identity,
            group_memberships: memberships,
            file_system_object: fso,
            share_status,
            local_group_sids,
            local_group_status,
            access_context: AccessContext::for_path(path),
            unsupported_share_ace_count,
            sid_names,
        })
        .map_err(|e| format!("Permission engine error: {e}"))
}

/// Sammelt lokale Gruppen-SIDs auf dem Zielserver der Analyse — siehe CLI-Pendant.
/// Collects local group SIDs on the analysis target server — see CLI counterpart.
fn collect_local_group_sids_for_path(
    path: &str,
    identity: &Identity,
) -> (
    Vec<adpa_core::model::Sid>,
    adpa_core::model::LocalGroupEvalStatus,
) {
    use adpa_core::model::LocalGroupEvalStatus;

    let server_owned = unc_components(path).map(|(s, _)| s);
    let server = server_owned.as_deref();
    let Some(account) = format_account_for_local_groups(identity) else {
        return (Vec::new(), LocalGroupEvalStatus::NotQueried);
    };
    match resolve_local_group_sids(server, &account) {
        Ok(v) => (v, LocalGroupEvalStatus::Applied),
        Err(e) => {
            let msg = e.to_string();
            warn!(?server, account, error = %msg, "Local group resolution failed; result will be marked incomplete");
            (Vec::new(), LocalGroupEvalStatus::NotAvailable(msg))
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

    // Helfer: einen Validierungs-/Setup-Fehler sowohl an die UI senden als
    // auch strukturiert in die Summary aufnehmen, damit er später per
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
            errors: vec![ScanError {
                path: Some(NormalizedPath(root.to_string())),
                message,
            }],
            total: 0,
            cancelled: false,
        }
    };

    if let Err(e) = validate_path(root) {
        return make_early_summary(format!("Invalid path: {e}"));
    }
    // AGENTS.md DoD 11: max_depth zentral validieren, bevor sie in
    // WalkConfig wandert — GUI-Widget begrenzt zwar visuell, schützt aber
    // nicht vor programmatischen Aufrufen oder zukünftigen UI-Refactorings.
    // AGENTS.md DoD 11: validate max_depth centrally before it flows into
    // WalkConfig — the GUI widget caps the value visually but does not
    // protect against programmatic callers or future UI refactorings.
    let max_depth = match validate_optional_scan_depth(max_depth) {
        Ok(d) => d.map(|s| s.0),
        Err(e) => return make_early_summary(format!("Invalid max_depth: {e}")),
    };
    if sid.starts_with("S-1-") {
        if let Err(e) = validate_sid(sid) {
            return make_early_summary(format!("Invalid SID: {e}"));
        }
    }

    if let Err(e) = validate_connection_inputs(smb_server, share_name, ldap) {
        return make_early_summary(e);
    }

    let (identity, memberships) = match resolve_identity_sids(sid, ldap).await {
        Ok(pair) => pair,
        Err(e) => {
            return make_early_summary(format!("Identity resolution failed: {e}"));
        }
    };

    // Strukturierte Fehlerliste, die später per persist_scan in `scan_errors`
    // landet. Sammelt Walk-, Eval- und Setup-Fehler analog zum CLI-Pfad.
    // Structured error list that later flows into `scan_errors` via
    // persist_scan. Collects walk, eval, and setup errors mirroring the CLI.
    let mut summary_errors: Vec<ScanError> = Vec::new();

    // Lokale Server-Gruppen pro Scan-Wurzel einmal aufloesen — vor der Share-Maske,
    // damit Share-ACEs auf lokale Gruppen ebenfalls beruecksichtigt werden.
    // Resolve local server groups once per scan root — before the share mask, so
    // that share ACEs targeting local groups are also taken into account.
    let (local_group_sids, local_group_status) = collect_local_group_sids_for_path(root, &identity);

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
        AccessContext::for_path(root),
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
    let scan_access_context = AccessContext::for_path(root);

    // SID→Name-Tabelle einmal für den gesamten Scan aufbauen. Trustee-SIDs
    // wiederholen sich quer über alle Pfade — wir sammeln unique SIDs aus
    // allen DACLs vorab und vermeiden N×M LSA-Aufrufe.
    // Build the SID→name table once for the entire scan. Trustee SIDs
    // repeat across all paths — we collect the unique SIDs from every
    // DACL up front and avoid N×M LSA round-trips.
    #[cfg(windows)]
    let scan_sid_names = {
        use std::collections::HashSet;
        let mut seen: HashSet<String> = HashSet::new();
        let trustees: Vec<String> = walk
            .objects
            .iter()
            .flat_map(|fso| fso.dacl.iter())
            .filter_map(|ace| {
                if seen.insert(ace.sid.0.clone()) {
                    Some(ace.sid.0.clone())
                } else {
                    None
                }
            })
            .collect();
        ad_resolver::build_sid_name_map(&memberships, trustees)
    };
    #[cfg(not(windows))]
    let scan_sid_names = std::collections::BTreeMap::new();

    for fso in walk.objects {
        let path = fso.path.0.clone();
        match engine.evaluate(PermissionEvaluationInput {
            identity: identity.clone(),
            group_memberships: memberships.clone(),
            file_system_object: fso,
            share_status: share_status.clone(),
            local_group_sids: local_group_sids.clone(),
            local_group_status: local_group_status.clone(),
            access_context: scan_access_context,
            unsupported_share_ace_count: scan_unsupported_share_ace_count,
            sid_names: scan_sid_names.clone(),
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
        errors: summary_errors,
        total,
        cancelled,
    }
}

// ---------------------------------------------------------------------------
// Identitätssuche
// Identity search
// ---------------------------------------------------------------------------

async fn handle_search(
    query: &str,
    ldap: &LdapParams,
) -> Result<Vec<IdentitySearchResult>, String> {
    use adpa_core::model::IdentityKind;

    validate_identity_query(query).map_err(|e| format!("Invalid search query: {e}"))?;
    validate_ldap_endpoint(&ldap.server).map_err(|e| format!("Invalid LDAP server: {e}"))?;
    validate_dn(&ldap.base_dn).map_err(|e| format!("Invalid base DN: {e}"))?;
    validate_dn(&ldap.bind_dn).map_err(|e| format!("Invalid bind DN: {e}"))?;

    let mut config = LdapConfig::new(&ldap.server, &ldap.base_dn, &ldap.bind_dn, &ldap.password);
    if ldap.insecure {
        config.tls_mode = TlsMode::Insecure;
        config.port = 389;
    }
    let mut conn = ldap_client::connect(&config)
        .await
        .map_err(|e| format!("LDAP: {e}"))?;

    let entries = ldap_client::search_by_query(&mut conn, &ldap.base_dn, query)
        .await
        .map_err(|e| format!("Suche fehlgeschlagen: {e}"))?;

    ldap_client::disconnect(conn).await;

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

/// Speichert einen Scan-Lauf und gibt entweder die Run-ID oder einen
/// menschenlesbaren Fehlergrund zurück.
/// Persists a scan run and returns either the run ID or a human-readable
/// failure reason.
///
/// Strukturierte Walk-/Eval-Fehler aus `errors` werden via
/// `store.insert_error` in `scan_errors` abgelegt — damit haben GUI-Scans
/// denselben Audit-Pfad wie CLI-Scans (Finding 6).
/// Bei `cancelled` wird zusätzlich ein Diagnosehinweis ohne Pfad ergänzt.
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
    output_path: &str,
) -> Result<(), String> {
    let status =
        validate_export_path(output_path).map_err(|e| format!("Invalid export path: {e}"))?;
    let validated_path = status.path().0.clone();
    let result = AnalysisResult {
        permissions: permissions.to_vec(),
        risk_findings: risk_findings.to_vec(),
    };
    HtmlExporter
        .export(&result, ExportTarget::File(validated_path))
        .map_err(|e| format!("Export failed: {e}"))
}

// ---------------------------------------------------------------------------
// Delta-Tab: Persistierte Scan-Läufe und Vergleich
// Delta tab: persisted scan runs and comparison
// ---------------------------------------------------------------------------

/// Liefert die persistierten Scan-Läufe in einer kompakten Form für die
/// Delta-Tab-Anzeige (neueste zuerst). Die Vorgabe „neueste zuerst" stammt
/// aus `Database::list_scan_runs`, das die Sortierung schon vornimmt.
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

/// Sammelt eine kompakte Identitäts-Liste für die Live-Suche im
/// Namensfeld der GUI. Konvertiert die `IdentitySnapshot`-Einträge aus
/// `ad_resolver::enumerate` in die channel-tauglichen
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
        // Lokale Gruppen tragen Domäne "BUILTIN" — eigene Markierung,
        // damit der Auditor sieht, welche Mitgliedschaftsklasse er trifft.
        // Local groups carry domain "BUILTIN" — own marker so the auditor
        // sees which membership class he's hitting.
        IdentityKind::Group if domain.eq_ignore_ascii_case("BUILTIN") => "L",
        IdentityKind::Group => "G",
        IdentityKind::WellKnown => "W",
        IdentityKind::Computer => "C",
        IdentityKind::Orphaned | IdentityKind::Unknown => "?",
    }
}

/// Vergleicht zwei Scan-Läufe und übersetzt das Persistence-Ergebnis in
/// kompakte `DeltaRow`-Strukturen, die direkt in die Slint-UI fließen.
/// Compares two scan runs and translates the persistence result into
/// compact `DeltaRow` structs that map straight into the Slint UI.
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
                DeltaKind::Changed { old_mask, new_mask } => DeltaRow {
                    path: entry.path.0,
                    kind_label: "Geändert".into(),
                    old_rights: format_mask(old_mask.0),
                    new_rights: format_mask(new_mask.0),
                },
            }
        })
        .collect())
}

/// Formatiert die effektive Berechtigung eines `EffectivePermission` als
/// "Klartext (0x...)"-String für die Delta-Anzeige.
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
// Identitätsauflösung
// Identity resolution
// ---------------------------------------------------------------------------

/// Erstellt eine minimale Identität (SID-only) oder löst via LDAP auf.
/// Creates a minimal identity (SID-only) or resolves via LDAP.
async fn resolve_identity_sids(
    sid: &str,
    ldap: Option<&LdapParams>,
) -> Result<(Identity, Vec<GroupMembership>), String> {
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
        let resolver = LdapResolver::new(config);
        let sid_obj = Sid(sid.to_string());
        let identity = resolver
            .resolve_identity(&sid_obj)
            .await
            .map_err(|e| format!("LDAP identity resolution failed: {e}"))?;
        let memberships = resolver
            .resolve_group_memberships(&sid_obj)
            .await
            .map_err(|e| format!("LDAP group resolution failed: {e}"))?;
        return Ok((identity, memberships));
    }

    // Ohne LDAP: auf Windows die lokale SAM/LSA als Default-Auflöser nutzen.
    // Auf einem Domain Controller deckt das die volle Domänenmitgliedschaft
    // ab; auf einer Workstation, was die LSA gerade gecacht hat. Erst wenn
    // auch die SAM-Auflösung scheitert (oder wir nicht unter Windows sind),
    // fällt der Worker auf eine nackte SID-Identität zurück — dann sind die
    // effektiven Rechte nur das, was Direkt-ACEs auf die SID erlauben.
    //
    // Without LDAP: use the local SAM/LSA as the default resolver on Windows.
    // On a domain controller this covers full domain membership; on a
    // workstation, whatever the LSA has cached. Only if SAM resolution also
    // fails (or we are not on Windows) does the worker fall back to a bare
    // SID identity — then the effective rights are only what direct ACEs on
    // the SID grant.
    sam_resolve_fallback(sid)
}

#[cfg(windows)]
fn sam_resolve_fallback(sid: &str) -> Result<(Identity, Vec<GroupMembership>), String> {
    match ad_resolver::resolve_identity_via_sam(sid) {
        Ok(pair) => {
            info!(
                sid,
                name = ?pair.0.name,
                domain = ?pair.0.domain,
                kind = ?pair.0.kind,
                group_count = pair.1.len(),
                "SAM resolution succeeded (no LDAP requested)"
            );
            Ok(pair)
        }
        Err(e) => {
            warn!(sid, error = %e, "SAM resolution failed — falling back to bare SID identity");
            Ok(bare_sid_identity(sid))
        }
    }
}

#[cfg(not(windows))]
fn sam_resolve_fallback(sid: &str) -> Result<(Identity, Vec<GroupMembership>), String> {
    Ok(bare_sid_identity(sid))
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
    let (server, share) = match (smb_server, share_name) {
        (Some(s), Some(n)) => (s.to_string(), n.to_string()),
        _ => match unc_components(path) {
            Some(pair) => pair,
            None => return (ShareMaskStatus::NotApplicable, 0),
        },
    };

    // Token-SIDs muessen Share- und NTFS-Auswertung uebereinstimmend abdecken.
    // Der Access-Context sorgt zusätzlich dafür, dass z. B. NETWORK (S-1-5-2)
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

/// Zerlegt einen UNC-Pfad in (Server, Share). Lokale Pfade (`C:\…`) liefern
/// `None`, damit kein Share-Lookup auf einem Disk-Buchstaben gestartet wird —
/// vorher landete `C:\Windows` als `NetShareGetInfo("C:", "Windows")` im
/// share_scanner und wurde mit "Status 53" abgewiesen, obwohl der Aufrufer
/// gar keinen Share-Kontext angefragt hatte.
/// Splits a UNC path into (server, share). Local paths (`C:\…`) return
/// `None` so no share lookup is started on a drive letter — previously
/// `C:\Windows` was forwarded as `NetShareGetInfo("C:", "Windows")` to the
/// share_scanner and rejected with "status 53", even though the caller had
/// not asked for a share context at all.
fn unc_components(path: &str) -> Option<(String, String)> {
    let bytes = path.as_bytes();
    let has_unc_prefix =
        matches!(bytes.first(), Some(b'\\' | b'/')) && matches!(bytes.get(1), Some(b'\\' | b'/'));
    if !has_unc_prefix {
        return None;
    }
    let stripped = path.trim_start_matches(['\\', '/']);
    let mut parts = stripped.splitn(3, ['\\', '/']);
    let server = parts.next().filter(|s| !s.is_empty())?.to_owned();
    let share = parts.next().filter(|s| !s.is_empty())?.to_owned();
    Some((server, share))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: lokale Pfade dürfen `unc_components` nicht passieren —
    /// sonst landet z. B. `C:\Windows` als `NetShareGetInfo("C:", "Windows")`
    /// im share_scanner und der Aufrufer sieht einen erfundenen Share-Fehler,
    /// obwohl SMB gar nicht angefragt war.
    /// Regression: local paths must not pass `unc_components` — otherwise
    /// e.g. `C:\Windows` ends up as `NetShareGetInfo("C:", "Windows")` in
    /// the share_scanner and the caller sees a fabricated share error even
    /// though SMB was not requested at all.
    #[test]
    fn unc_components_rejects_local_paths() {
        assert_eq!(unc_components(r"C:\Windows"), None);
        assert_eq!(unc_components(r"D:\Daten\Abteilung"), None);
        assert_eq!(unc_components(r"\singlebackslash\foo"), None);
        assert_eq!(unc_components(""), None);
    }

    #[test]
    fn unc_components_accepts_unc_paths() {
        assert_eq!(
            unc_components(r"\\server\share\sub"),
            Some(("server".to_string(), "share".to_string()))
        );
        assert_eq!(
            unc_components("//server/share"),
            Some(("server".to_string(), "share".to_string()))
        );
        assert_eq!(
            unc_components(r"\\fileserver\Buchhaltung"),
            Some(("fileserver".to_string(), "Buchhaltung".to_string()))
        );
    }

    /// Finding 6: persist_scan muss strukturierte Walk-/Eval-Fehler in
    /// `scan_errors` ablegen — zusätzlich zum Abbruch-Marker, falls
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
        // Cancel-Marker hat path = None und wird zuletzt eingefügt.
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
}
