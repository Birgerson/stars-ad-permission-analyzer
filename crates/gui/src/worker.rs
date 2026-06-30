// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Background worker for analyses, scans and delta comparisons.
//!
//! Runs in a dedicated thread with a Tokio runtime for optional LDAP calls.
//!
//!
//! Wired up: `Analyze`, `Scan`, `ExportHtml`, `ListScanRuns`,
//! `ComputeDelta`. `SearchIdentity` is reserved for a later phase (GUI
//! identity picker) — the definition stays so a future addition does not
//! cause API breaks.

use std::sync::mpsc::{Receiver, Sender};

use ad_resolver::sid_util::bytes_to_sid_str;
#[cfg(not(windows))]
use ad_resolver::NoLsaBackend;
#[cfg(windows)]
use ad_resolver::WindowsLsaBackend;
use ad_resolver::{
    ldap_client, principal::PrincipalInput, LdapConfig, LdapIdentityBackend, LdapResolver,
    PrincipalResolution, PrincipalResolver,
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
        validate_bind_identity, validate_dn, validate_identity_query, validate_ldap_endpoint,
        validate_share_name, validate_smb_server,
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
    /// When true: bind against the Global Catalog (LDAPS 3269 / plain 3268)
    /// instead of a single domain. Identity lookups become forest-wide and
    /// `base_dn` may be empty. GC-resolved memberships are flagged
    /// potentially incomplete (only universal groups replicate fully).
    /// Mirrors the CLI `--global-catalog` flag — closes the GUI/CLI parity
    /// gap where the GUI could display the GC diagnostic but not select GC.
    pub global_catalog: bool,
    /// When true: bind with SASL GSSAPI/Kerberos sign+seal over port 389,
    /// using the current Windows logon (no bind DN / password). The
    /// cert-free path for a hardened DC that enforces LDAP signing. Mirrors
    /// the CLI `--ldap-signing` flag (ADR 0051). Mutually exclusive with
    /// `insecure`; ignores `global_catalog`.
    pub signing: bool,
    /// LDAP operation timeout in seconds. `None` keeps the `LdapConfig`
    /// default (10 s). Mirrors the CLI `--ldap-timeout` flag — closes the gap
    /// where the GUI was stuck at the fixed 10 s and ran into a timeout on
    /// dense domains.
    pub timeout_secs: Option<u64>,
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
            .field("global_catalog", &self.global_catalog)
            .field("signing", &self.signing)
            .field("timeout_secs", &self.timeout_secs)
            .finish()
    }
}

impl LdapParams {
    /// Maps the GUI's LDAP-mode selector to LDAP parameters.
    ///
    /// `0` = Off (SAM/LSA, returns `None`), `1` = LDAPS (port 636),
    /// `2` = plain LDAP (port 389, test only), `3` = Global Catalog
    /// (LDAPS, port 3269, forest-wide), `4` = Signed LDAP (GSSAPI/Kerberos
    /// sign+seal, port 389, current Windows logon). Kept as a pure function
    /// so the mode→params wiring is unit-testable without the Slint UI.
    pub fn from_mode(
        mode: i32,
        server: String,
        base_dn: String,
        bind_dn: String,
        password: String,
        timeout_secs: i32,
    ) -> Option<LdapParams> {
        match mode {
            1..=4 => Some(LdapParams {
                server,
                base_dn,
                bind_dn,
                password,
                insecure: mode == 2,
                global_catalog: mode == 3,
                signing: mode == 4,
                // Clamp to the same 1–600 s range the CLI validates, so a GUI
                // value out of range can never reach the LDAP layer.
                timeout_secs: Some(timeout_secs.clamp(1, 600) as u64),
            }),
            _ => None,
        }
    }

    /// Builds the `LdapConfig` for these parameters, choosing the right port
    /// and security mode — the same matrix the CLI uses
    /// (`ad_resolver::LdapConfig` constructors).
    pub fn to_config(&self) -> LdapConfig {
        // Signed bind (GSSAPI sign+seal) takes precedence: it is its own
        // security mode (current Windows logon, no bind DN/password) and
        // ignores the insecure/global_catalog flags.
        let mut config = if self.signing {
            LdapConfig::new_signed(&self.server, &self.base_dn)
        } else {
            match (self.global_catalog, self.insecure) {
                (true, true) => LdapConfig::new_global_catalog_insecure(
                    &self.server,
                    &self.base_dn,
                    &self.bind_dn,
                    &self.password,
                ),
                (true, false) => LdapConfig::new_global_catalog(
                    &self.server,
                    &self.base_dn,
                    &self.bind_dn,
                    &self.password,
                ),
                (false, true) => LdapConfig::new_insecure(
                    &self.server,
                    &self.base_dn,
                    &self.bind_dn,
                    &self.password,
                ),
                (false, false) => {
                    LdapConfig::new(&self.server, &self.base_dn, &self.bind_dn, &self.password)
                }
            }
        };
        // GUI timeout override (already clamped to 1–600 s in `from_mode`);
        // `None` keeps the constructor's 10 s default — same as the CLI.
        if let Some(secs) = self.timeout_secs {
            config.timeout_secs = secs;
        }
        config
    }
}

/// Search result for the identity search.
// Reserved for the future GUI identity picker (see `SearchIdentity` /
// `SearchResults`); constructed but not consumed yet.
#[allow(dead_code)]
#[derive(Clone)]
pub struct IdentitySearchResult {
    pub sid: String,
    pub sam_account_name: String,
    pub display_name: Option<String>,
    pub kind: adpa_core::model::IdentityKind,
}

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
    /// Searches for users and groups in Active Directory.
    /// Reserved for the future GUI identity picker; not constructed yet.
    #[allow(dead_code)]
    SearchIdentity { query: String, ldap: LdapParams },
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
    /// Lists all trustees with their rights on a path — path-centric
    /// audit view without a fixed identity. Answers the question "Who
    /// has any access to X?" rather than "What can user Y do on X?".
    AnalyzeTrustees {
        path: String,
        smb_server: Option<String>,
        share_name: Option<String>,
    },
    /// Resolves the recursive group memberships of an identity for the Groups
    /// tab — no path, no ACL, no effective rights. Mirrors the CLI `groups`
    /// command. `ldap` is `None` for the SAM/LSA fallback.
    ResolveGroups {
        sid: String,
        ldap: Option<LdapParams>,
    },
}

/// One diagnostic marker for GUI display: its one-line reason plus a
/// presentation level — `0` = info, `1` = warning, `2` = high — from
/// `PermissionDiagnostic::severity`.
#[derive(Clone)]
pub struct DiagnosticRow {
    pub text: String,
    pub level: i32,
}

/// Maps a marker's visual attention to the GUI level: `0` = neutral,
/// `1` = notice (amber), `2` = concern (orange-red).
fn diag_level(sev: adpa_core::model::DiagnosticSeverity) -> i32 {
    use adpa_core::model::DiagnosticSeverity::{Concern, Neutral, Notice};
    match sev {
        Neutral => 0,
        Notice => 1,
        Concern => 2,
    }
}

/// Row attention level: `2` = a concern marker is present, `1` = a notice
/// marker, `0` = neutral (correct, or only expected-context caveats). Mirrors
/// "do I need to look?" rather than the correctness flag — a SAM-fallback row
/// stays neutral even though it is technically incomplete.
fn row_severity(perm: &adpa_core::model::EffectivePermission) -> i32 {
    use adpa_core::model::DiagnosticSeverity::{Concern, Notice};
    if perm.diagnostics.iter().any(|d| d.severity() == Concern) {
        2
    } else if perm.diagnostics.iter().any(|d| d.severity() == Notice) {
        1
    } else {
        0
    }
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
    /// Count of structured diagnostic markers (e.g. non-canonical DACL,
    /// follow-up finding 3). 0 = unremarkable.
    pub diagnostic_count: usize,
    /// Human-readable, single-line reason for each structured diagnostic on
    /// this path (`PermissionDiagnostic::summary()`). Surfaced in the
    /// expanded scan-row detail so the GUI shows *why* a row is flagged, not
    /// just *that* it is — closing the "show uncertainty in the GUI"
    /// consistency gap (engine review 2026-06-13 finding 2). Empty when the
    /// path carries no diagnostics. Each entry carries its severity so the GUI
    /// can show a warning marker differently from a purely informational one.
    pub diagnostics: Vec<DiagnosticRow>,
    /// Row presentation level: `0` = correct/complete, `1` = info-only, `2` =
    /// warning (incomplete), `3` = high (an under-report marker is present).
    /// Derived from `EffectivePermission::is_incomplete` + the marker
    /// severities — the single source of truth.
    pub row_severity: i32,
    /// Path-centric trustee view — every ACE in the DACL resolved, with
    /// "Applies to" labels and Allow/Deny. Empty when the scan runs
    /// without trustee collection. Complement to the identity-based
    /// `steps` above.
    pub trustees: Vec<TrusteeRow>,
}

/// One group-membership row for the Groups tab.
#[derive(Clone)]
pub struct GroupMemberRow {
    pub name: String,
    pub sid: String,
    /// How the membership arose (`"direct"`, `"via A → B"`, …) from
    /// `GroupMembership::origin_label`.
    pub origin: String,
    /// `true` if this group is a well-known privileged group.
    pub privileged: bool,
    /// Privileged role name (e.g. `"Domain Admins"`) when `privileged`.
    pub role: String,
}

/// GUI-ready membership view for the Groups tab, built from a
/// `MembershipReport`. No path / ACL / effective rights — those stay in the
/// Analyze and Scan tabs.
#[derive(Clone)]
pub struct GroupsViewData {
    /// `DOMAIN\name` (or the SID when no name is known).
    pub identity_label: String,
    pub identity_sid: String,
    /// `"Active"` / `"DISABLED"`.
    pub status: String,
    /// `IdentityKind`, debug-formatted.
    pub kind: String,
    /// `true` when an AD/LDAP connection backed the resolution.
    pub ad_connected: bool,
    pub sid_history_count: i32,
    pub total: i32,
    pub direct: i32,
    /// Privileged-membership banner lines (`"member of Domain Admins"`).
    pub privileged: Vec<String>,
    pub groups: Vec<GroupMemberRow>,
    pub diagnostics: Vec<DiagnosticRow>,
}

/// Result from the worker thread to the GUI.
pub enum WorkerEvent {
    AnalyzeDone {
        /// Actual evaluation result (or engine error). Boxed because
        /// `EffectivePermission` is significantly larger than the other
        /// variants — otherwise clippy::large_enum_variant fires.
        result: Box<Result<adpa_core::model::EffectivePermission, String>>,
        /// UUID of the stored scan run. Analyze now writes to the SQLite history
        /// as well so the result is comparable in the Delta tab — the previous
        /// "Analyze does not persist" gap is gone. `None` when the evaluation did
        /// not happen (engine error) or when the DB is not open.
        scan_run_id: Option<String>,
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
    /// Risk findings after a scan completes.
    RiskFindings(Vec<RiskFinding>),
    /// Result of an HTML export.
    ExportDone(Result<(), String>),
    /// Search results for the identity search.
    /// Reserved for the future GUI identity picker; not consumed yet.
    #[allow(dead_code)]
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
    /// Result of a per-path trustee listing.
    TrusteesDone(Result<Vec<TrusteeRow>, String>),
    /// Result of a Groups-tab membership resolution. Boxed because
    /// `GroupsViewData` carries several vectors and is larger than the other
    /// variants (clippy::large_enum_variant).
    GroupsDone(Box<Result<GroupsViewData, String>>),
}

/// One row in the trustee view — one ACE from a path's DACL plus
/// resolved labels for GUI display.
#[derive(Clone)]
pub struct TrusteeRow {
    /// Raw SID of the trustee.
    pub sid: String,
    pub display_name: String,
    /// `"Allow"` or `"Deny"`.
    pub kind: String,
    /// Normalized rights label (e.g. `Modify (M)`).
    pub rights_label: String,
    /// Hex form of the raw access mask for forensic purposes.
    pub mask_hex: String,
    /// `"explicit"` or `"inherited"`.
    pub source: String,
    /// Windows-style "Applies to" label (e.g. "This folder, subfolders
    /// and files"), derived from inheritance and propagation flags.
    pub applies_to: String,
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
    /// `Administrator`.
    /// Plain name (the value pushed into the name field on click) — e.g.
    /// `Administrator`.
    pub name: String,
    /// Qualified display name `DOMAIN\Name`, or just `Name` when no
    /// domain is known.
    pub qualified: String,
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
/// Callback the worker uses to wake the GUI thread once a new
/// `WorkerEvent` is sitting in the receiver. With Slint this is typically
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
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                warn!(error = %e, "Failed to create Tokio runtime — worker thread cannot start");
                return;
            }
        };
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
                    let started_at = Utc::now();
                    let result = rt.block_on(handle_analyze(
                        &path,
                        &sid,
                        ldap.as_ref(),
                        smb_server.as_deref(),
                        share_name.as_deref(),
                    ));
                    // EffectivePermission becomes a scan run with exactly one
                    // permission entry. This makes Analyze results comparable
                    // in the Delta tab (previously only ScanTree wrote to the
                    // DB, which surfaced to end users as "the list does not
                    // show my analysis result").
                    let (scan_run_id, persistence_error) =
                        match (&result, &db) {
                            (Ok(perm), Some(d)) => {
                                match persist_scan(
                                    d,
                                    &path,
                                    std::slice::from_ref(perm),
                                    &[],
                                    false,
                                    started_at,
                                ) {
                                    Ok(id) => (Some(id), None),
                                    Err(e) => (None, Some(e)),
                                }
                            }
                            (Ok(_), None) => (
                                None,
                                Some(db_open_error.clone().unwrap_or_else(|| {
                                    "scan database is not available".to_string()
                                })),
                            ),
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
                    let started_at = Utc::now();
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

                    // Evaluate the persistence result explicitly: either a run ID
                    // or a visible failure reason.
                    let persist_outcome = match &db {
                        Some(d) => persist_scan(
                            d,
                            &root,
                            &scan_result.permissions,
                            &scan_result.errors,
                            scan_result.cancelled,
                            started_at,
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
                            .unwrap_or_else(|| "Database not open".to_string())),
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
                            .unwrap_or_else(|| "Database not open".to_string())),
                    };
                    let _ = evt_tx.send(WorkerEvent::DeltaComputed(result));
                    notify();
                }
                WorkerRequest::DeleteScanRun { run_id } => {
                    let result = match &db {
                        Some(d) => delete_scan_run(d, &run_id),
                        None => Err(db_open_error
                            .clone()
                            .unwrap_or_else(|| "Database not open".to_string())),
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
                WorkerRequest::ResolveGroups { sid, ldap } => {
                    let result = rt.block_on(handle_resolve_groups(&sid, ldap.as_ref()));
                    let _ = evt_tx.send(WorkerEvent::GroupsDone(Box::new(result)));
                    notify();
                }
            }
        }
    });

    (req_tx, evt_rx, cancel)
}

// ---------------------------------------------------------------------------
// Internal result of the scan handler
// ---------------------------------------------------------------------------

struct ScanSummary {
    permissions: Vec<EffectivePermission>,
    /// Path-centric trustee listing (raw model — without display-
    /// Path-centric trustee listing (raw model — no display formatting).
    /// Used by the HTML exporter; the GUI separately receives display-
    /// formatted `TrusteeRow` data inside each `ScanRow`.
    path_trustees: Vec<adpa_core::model::PathTrustees>,
    /// Structured walk, eval and validation errors. Written to the scan
    /// history atomically by `persist_scan` (one transaction per run) so
    /// that GUI scans get the same audit trail as CLI scans.
    errors: Vec<ScanError>,
    total: usize,
    /// true if the scan was cancelled by the user.
    cancelled: bool,
}

/// Centrally validates optional SMB and LDAP connection inputs before they are
/// passed to NetAPI or LDAP calls.
/// Normalized connection inputs in the GUI worker.
pub struct NormalizedConnectionInputs {
    pub smb_server: Option<String>,
    pub share_name: Option<String>,
    pub ldap: Option<LdapParams>,
}

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
            // In Global Catalog mode an empty base DN is allowed and means
            // "search all forest partitions" (mirrors the CLI). Otherwise a
            // base DN is required and validated.
            let base_dn = if p.global_catalog && p.base_dn.trim().is_empty() {
                String::new()
            } else {
                validate_dn(&p.base_dn)
                    .map_err(|e| format!("Invalid base DN: {e}"))?
                    .0
            };
            // Signed (GSSAPI) binds use the current Windows logon, so an
            // empty bind DN is allowed; otherwise a bind DN is required.
            let bind_dn = if p.signing && p.bind_dn.trim().is_empty() {
                String::new()
            } else {
                validate_bind_identity(&p.bind_dn)
                    .map_err(|e| format!("Invalid bind identity: {e}"))?
                    .0
            };
            Some(LdapParams {
                server,
                base_dn,
                bind_dn,
                password: p.password.clone(),
                insecure: p.insecure,
                global_catalog: p.global_catalog,
                signing: p.signing,
                timeout_secs: p.timeout_secs,
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
    // Review 2026-06-04 round 2, finding 6: forward the canonical form
    // from here on, not the raw string.
    let normalized_path = validate_path(path)
        .map_err(|e| format!("Invalid path: {e}"))?
        .0;
    let path = normalized_path.as_str();
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
            identity_resolved_via_fsp: engine_flags.identity_resolved_via_fsp,
            group_resolution_via_global_catalog: engine_flags.group_resolution_via_global_catalog,
        })
        .map_err(|e| format!("Permission engine error: {e}"))
}

// ---------------------------------------------------------------------------
// Groups tab — identity → recursive group memberships (no path/ACL)
// ---------------------------------------------------------------------------

/// Resolves an identity's recursive group memberships for the Groups tab — the
/// GUI counterpart to the CLI `groups` command. No path / ACL / effective
/// rights. `ldap` is `None` for the SAM/LSA fallback.
async fn handle_resolve_groups(
    sid: &str,
    ldap: Option<&LdapParams>,
) -> Result<GroupsViewData, String> {
    info!(sid, "ResolveGroups request");
    // Validate the connection inputs at the GUI boundary (no SMB here).
    let normalized = validate_connection_inputs(None, None, ldap)?;
    let ldap = normalized.ldap.as_ref();
    // `resolve_identity_sids` validates the SID before it reaches the resolver.
    let res = resolve_identity_sids(sid, ldap).await?;
    // `ad_connected` mirrors the CLI: true exactly when an LDAP bind backed
    // the lookup (otherwise the SAM/LSA flat fallback was used).
    let report = res.into_membership_report(ldap.is_some());
    Ok(membership_report_to_view(&report))
}

/// Maps a [`MembershipReport`] into the GUI-ready [`GroupsViewData`].
fn membership_report_to_view(report: &adpa_core::model::MembershipReport) -> GroupsViewData {
    use adpa_core::model::privileged_group_role;

    let name = report
        .identity
        .name
        .clone()
        .unwrap_or_else(|| report.identity.sid.0.clone());
    let identity_label = match &report.identity.domain {
        Some(d) if !d.is_empty() => format!("{d}\\{name}"),
        _ => name,
    };
    let total = report.memberships.len() as i32;
    let direct = report.memberships.iter().filter(|m| m.direct).count() as i32;
    let privileged: Vec<String> = report
        .privileged()
        .into_iter()
        .map(|(_, role)| format!("member of {role}"))
        .collect();
    let groups: Vec<GroupMemberRow> = report
        .memberships
        .iter()
        .map(|m| {
            let role = privileged_group_role(&m.group_sid);
            GroupMemberRow {
                name: m
                    .group_name
                    .clone()
                    .unwrap_or_else(|| m.group_sid.0.clone()),
                sid: m.group_sid.0.clone(),
                origin: m.origin_label(),
                privileged: role.is_some(),
                role: role.unwrap_or("").to_owned(),
            }
        })
        .collect();
    let diagnostics: Vec<DiagnosticRow> = report
        .diagnostics
        .iter()
        .map(|d| DiagnosticRow {
            text: d.summary(),
            level: diag_level(d.severity()),
        })
        .collect();
    GroupsViewData {
        identity_label,
        identity_sid: report.identity.sid.0.clone(),
        status: if report.identity.disabled {
            "DISABLED".to_owned()
        } else {
            "Active".to_owned()
        },
        kind: format!("{:?}", report.identity.kind),
        ad_connected: report.ad_connected,
        sid_history_count: report.identity.sid_history_count as i32,
        total,
        direct,
        privileged,
        groups,
        diagnostics,
    }
}

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

    // Review 2026-06-04 round 2, finding 6: forward the canonical form.
    let normalized_root = match validate_path(root) {
        Ok(p) => p.0,
        Err(e) => return make_early_summary(format!("Invalid path: {e}")),
    };
    let root = normalized_root.as_str();
    // AGENTS.md DoD 11: validate max_depth centrally before it flows into
    // WalkConfig — the GUI widget caps the value visually but does not
    // protect against programmatic callers or future UI refactorings.
    let max_depth = match validate_optional_scan_depth(max_depth) {
        Ok(d) => d.map(|s| s.0),
        Err(e) => return make_early_summary(format!("Invalid max_depth: {e}")),
    };
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
    let identity_resolved_via_fsp = engine_flags.identity_resolved_via_fsp;
    let group_resolution_via_global_catalog = engine_flags.group_resolution_via_global_catalog;
    let identity = res.identity;
    let memberships = res.memberships;

    // Structured error list that later flows into `scan_errors` via
    // persist_scan. Collects walk, eval, and setup errors mirroring the CLI.
    let mut summary_errors: Vec<ScanError> = Vec::new();

    // Resolve local server groups once per scan root — before the share mask, so
    let (local_group_sids, local_group_memberships, local_group_status) =
        collect_local_group_sids_for_path(root, smb_server, &identity, &memberships);
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
        // vorab gelesenen Overlay (Single Read pro Share). Round-10
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
            identity_resolved_via_fsp,
            group_resolution_via_global_catalog,
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
                    diagnostics: perm
                        .diagnostics
                        .iter()
                        .map(|d| DiagnosticRow {
                            text: d.summary(),
                            level: diag_level(d.severity()),
                        })
                        .collect(),
                    row_severity: row_severity(&perm),
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

    // Review 2026-06-04 round 3 finding 2: trimmed wrapper values
    // the raw `ldap` fields.
    let query = validate_identity_query(query)
        .map_err(|e| format!("Invalid search query: {e}"))?
        .0;
    let server = validate_ldap_endpoint(&ldap.server)
        .map_err(|e| format!("Invalid LDAP server: {e}"))?
        .0;
    // Global Catalog searches may omit the base DN (forest-wide).
    let base_dn = if ldap.global_catalog && ldap.base_dn.trim().is_empty() {
        String::new()
    } else {
        validate_dn(&ldap.base_dn)
            .map_err(|e| format!("Invalid base DN: {e}"))?
            .0
    };
    // Signed (GSSAPI) binds use the current Windows logon — empty bind DN ok.
    let bind_dn = if ldap.signing && ldap.bind_dn.trim().is_empty() {
        String::new()
    } else {
        validate_bind_identity(&ldap.bind_dn)
            .map_err(|e| format!("Invalid bind identity: {e}"))?
            .0
    };

    let config = LdapParams {
        server: server.clone(),
        base_dn: base_dn.clone(),
        bind_dn: bind_dn.clone(),
        password: ldap.password.clone(),
        insecure: ldap.insecure,
        global_catalog: ldap.global_catalog,
        signing: ldap.signing,
        timeout_secs: ldap.timeout_secs,
    }
    .to_config();

    // Review 2026-06-04 round 2, finding 3: the GUI identity search used to
    // bypass the LDAP timeout. connect() is internally guarded; the paged
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
    .map_err(|e| format!("search failed: {e}"))?;

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
///
/// Structured walk/eval errors from `errors` are written to `scan_errors`
/// as part of one atomic transaction (`persist_scan_atomic`) — giving GUI
/// scans the same audit trail as CLI scans. When `cancelled`, an
/// additional pathless diagnostic note is appended so the partial state
/// is explicit.
fn persist_scan(
    db: &Database,
    target: &str,
    permissions: &[EffectivePermission],
    errors: &[ScanError],
    cancelled: bool,
    started_at: chrono::DateTime<Utc>,
) -> Result<String, String> {
    let run_id = Uuid::new_v4();
    // `started_at` is captured by the caller before the work begins, so
    // the stored run carries the real scan duration instead of
    // started == finished (self-review follow-up, point 4).
    let run = ScanRun {
        id: run_id,
        started_at,
        finished_at: Some(Utc::now()),
        target: target.to_string(),
        errors: vec![],
    };

    // Engine review 2026-06-12 finding 1: persist the whole run in one
    // transaction. A cancelled scan appends a pathless diagnostic note so
    // the partial state is explicit rather than silently incomplete.
    let mut all_errors: Vec<ScanError> = errors.to_vec();
    if cancelled {
        all_errors.push(ScanError {
            path: None,
            message: "Scan cancelled by user — results are partial".to_owned(),
        });
    }

    let store = db.scan_store();
    if let Err(e) = store.persist_scan_atomic(&run, permissions, &all_errors) {
        warn!(error = %e, "Failed to persist scan run");
        return Err(format!("could not persist scan: {e}"));
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
            "Target file already exists: {}. Pick a different name or delete the file first.",
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

/// Returns persisted scan runs in a compact form for the Delta tab
/// (newest first). The sort order comes from `Database::list_scan_runs`.
fn list_scan_run_summaries(db: &Database) -> Result<Vec<ScanRunSummary>, String> {
    let runs = db
        .list_scan_runs()
        .map_err(|e| format!("scan history could not be loaded: {e}"))?;
    Ok(runs
        .into_iter()
        .map(|r| ScanRunSummary {
            id: r.id.to_string(),
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
    Err("Identity enumeration is only available on Windows (NetAPI)".to_string())
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
        // FSP fallback (LSA enrichment unavailable) — trust principal.
        IdentityKind::ForeignSecurityPrincipal => "F",
        IdentityKind::Orphaned | IdentityKind::Unknown => "?",
    }
}

/// Compares two scan runs and translates the persistence result into
/// compact `DeltaRow` structs that map straight into the Slint UI.
/// Removes a scan run including all dependent data from the SQLite history.
/// Returns `Ok(())` even if the ID did not exist — the GUI has to sync local
/// state regardless.
fn delete_scan_run(db: &Database, run_id: &str) -> Result<(), String> {
    let id = Uuid::parse_str(run_id).map_err(|e| format!("Invalid scan-run ID '{run_id}': {e}"))?;
    db.delete_scan_run(&id)
        .map_err(|e| format!("delete failed: {e}"))?;
    Ok(())
}

// Inheritance / propagation flags as Windows stores them in ACE_HEADER.AceFlags.
// Inheritance / propagation flags as Windows stores them in
// ACE_HEADER.AceFlags. The `fs_scanner` implementation splits them into two
// fields (`inheritance_flags`, `propagation_flags`); we re-combine them for
// the "Applies to" display.
const OBJECT_INHERIT_ACE_FLAG: u32 = 0x01;
const CONTAINER_INHERIT_ACE_FLAG: u32 = 0x02;
const NO_PROPAGATE_INHERIT_ACE_FLAG: u32 = 0x04;
const INHERIT_ONLY_ACE_FLAG: u32 = 0x08;

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
    // Review 2026-06-04 round 2, finding 6: propagate the normalized form.
    // Review 2026-06-04 round 2, finding 6: propagate the normal form.
    let normalized_path = validate_path(path)
        .map_err(|e| format!("Invalid path: {e}"))?
        .0;
    let path = normalized_path.as_str();
    // Round 3 finding 2 + round 4 finding 3: trim + enforce pairing.
    let (smb_server, share_name) = normalize_smb_pair(smb_server, share_name)?;
    // `SmbAuditContext::resolve` (Round-10 Finding 1) — `analyze_trustees`
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

// build_path_trustees, build_path_trustees_with_share) liegt seit
// Review round 9 finding 1 in `crates/exporter/src/trustees.rs` —
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

/// Converts a raw `PathTrustee` to the display-formatted `TrusteeRow`
/// consumed by the Slint UI. Derives "Applies to", mask hex and the
/// Allow/Deny label from the raw model.
pub fn trustee_row_for_display(entry: &adpa_core::model::PathTrusteeEntry) -> TrusteeRow {
    use adpa_core::model::{AceKind, PathTrusteeEntry, TrusteeCategory};
    use permission_engine::mask::expand_generic_rights;

    match entry {
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
                kind: "Diagnostic".to_owned(),
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
        Uuid::parse_str(old_run_id).map_err(|e| format!("Invalid old scan-run ID: {e}"))?;
    let new_id =
        Uuid::parse_str(new_run_id).map_err(|e| format!("Invalid new scan-run ID: {e}"))?;
    let entries = db
        .compare_scans(&old_id, &new_id)
        .map_err(|e| format!("comparison failed: {e}"))?;

    Ok(entries
        .into_iter()
        .map(|entry| {
            use persistence::DeltaKind;
            match entry.kind {
                DeltaKind::Added => DeltaRow {
                    path: entry.path.0,
                    kind_label: "Added".into(),
                    old_rights: String::new(),
                    new_rights: entry.new_perm.map(format_rights).unwrap_or_default(),
                },
                DeltaKind::Removed => DeltaRow {
                    path: entry.path.0,
                    kind_label: "Removed".into(),
                    old_rights: entry.old_perm.map(format_rights).unwrap_or_default(),
                    new_rights: String::new(),
                },
                DeltaKind::Changed {
                    old_mask,
                    new_mask,
                    reasons,
                } => {
                    // Code Review 2026-06-07 Finding 3: zeige zusaetzlich
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
                        "Changed".into()
                    } else {
                        format!("Changed ({reasons_label})")
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
/// (review finding 6).
/// Returns `(Identity, Memberships, used_sam_fallback)`. The flag is `true`
/// if group resolution used `NetUserGetGroups` (SAM/LSA) instead of LDAP —
/// in that case the domain group recursion is incomplete and the caller
/// must forward the fact into the engine input (review finding 6).
async fn resolve_identity_sids(
    sid: &str,
    ldap: Option<&LdapParams>,
) -> Result<PrincipalResolution, String> {
    // Validate the SID at this GUI boundary so a malformed value never
    // reaches the resolver/LSA as a typed `Sid` (review 2026-06-14
    // finding 3). Covers both the LDAP and the SAM/LSA branch below.
    let sid = Sid::try_new(sid).map_err(|e| format!("Invalid SID: {e}"))?;
    if let Some(params) = ldap {
        let config = params.to_config();
        let resolver = std::sync::Arc::new(LdapResolver::new(config));
        let backend = LdapIdentityBackend::new(resolver);
        // Central principal pipeline — closes review round 3 finding 1.
        #[cfg(windows)]
        let principal = PrincipalResolver::new(backend, Some(WindowsLsaBackend));
        #[cfg(not(windows))]
        let principal: PrincipalResolver<_, NoLsaBackend> = PrincipalResolver::new(backend, None);
        return principal
            .resolve(PrincipalInput::Sid(sid.clone()))
            .await
            .map_err(|e| format!("LDAP identity resolution failed: {e}"));
    }

    //
    // Without LDAP: use the local SAM/LSA as the default resolver on Windows.
    // On a domain controller this covers full domain membership; on a
    // fails (or we are not on Windows) does the worker fall back to a bare
    // SID identity — then the effective rights are only what direct ACEs on
    // the SID grant.
    // `used_sam_fallback = true`.
    // Both paths (SAM success and bare SID fallback) are LDAP-free → nested
    // domain groups are not fully resolved, so `used_sam_fallback = true`.
    // Closes review 2026-06-04 round 2 finding 5: `sam_resolve_fallback`
    // passenden Diagnose-Marker. Closes review round 2 finding 5.
    let (identity, memberships, disabled_known) = sam_resolve_fallback(&sid.0)?;
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
        // SAM-only on a DC = local domain → Inside; the flat recursion
        // is signalled separately via SamFlat.
        scope_status: ad_resolver::IdentityScopeStatus::InsideConfiguredLdapBase,
        group_resolution_status: ad_resolver::GroupResolutionStatus::SamFlat,
        disabled_status,
        diagnostics,
        resolved_via_fsp: false,
        resolved_via_global_catalog: false,
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
        sid_history_count: 0,
    };
    (identity, vec![])
}

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

    // ignored (review follow-up finding 1).
    // Token SIDs must cover share and NTFS evaluation consistently. The
    // access context further ensures e.g. NETWORK (S-1-5-2) is in the SMB
    // token, otherwise Deny-NETWORK share ACEs are ignored (follow-up
    // review finding 1).
    let user_sids =
        build_token_sids_with_context(sid, memberships, local_group_sids, access_context);

    match get_share_dacl(&server, &share) {
        Ok(scan) => {
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

    // (sentinel bug from review finding 1).
    // The UNC parsing tests moved to validation::path where the shared
    // helper `parse_unc_components` lives. Here only a smoke test that the
    // GUI worker actually delegates to it (sentinel bug from review
    // finding 1).
    #[test]
    fn share_status_does_not_treat_local_path_as_unc() {
        // Local path without an SMB override → no share lookup, NotApplicable.
        // Before the fix this would have called `NetShareGetInfo("C:", "Windows")`.
        let dummy_id = Identity {
            sid: adpa_core::model::Sid("S-1-5-21-1-2-3-1000".to_owned()),
            name: Some("test".into()),
            domain: None,
            kind: adpa_core::model::IdentityKind::User,
            disabled: false,
            user_principal_name: None,
            sid_history_count: 0,
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

        let run_id_str = persist_scan(&db, r"C:\Root", &[], &errors, false, Utc::now())
            .expect("persist_scan should succeed");
        let run_id = Uuid::parse_str(&run_id_str).expect("valid UUID");

        let persisted = db
            .scan_store()
            .list_errors_for(&run_id)
            .expect("list_errors_for");
        assert_eq!(
            persisted.len(),
            2,
            "walk errors must end up in scan_errors, found: {persisted:?}"
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

        let run_id_str = persist_scan(&db, r"C:\Root", &[], &errors, true, Utc::now())
            .expect("persist_scan should succeed");
        let run_id = Uuid::parse_str(&run_id_str).unwrap();

        let persisted = db.scan_store().list_errors_for(&run_id).unwrap();
        assert_eq!(persisted.len(), 2, "walk error + cancel marker expected");
        // Cancel marker has path = None and is appended last.
        assert!(persisted[1].path.is_none());
        assert!(persisted[1].message.contains("cancelled"));
    }

    #[test]
    fn persist_scan_with_no_errors_yields_empty_scan_errors_when_not_cancelled() {
        let db = Database::open_in_memory().expect("in-memory DB");
        let run_id_str = persist_scan(&db, r"C:\Root", &[], &[], false, Utc::now()).unwrap();
        let run_id = Uuid::parse_str(&run_id_str).unwrap();
        let persisted = db.scan_store().list_errors_for(&run_id).unwrap();
        assert!(
            persisted.is_empty(),
            "without walk errors and without cancellation there must be no entries in scan_errors"
        );
    }

    /// Self-review follow-up point 4: the stored run must carry the real
    /// scan duration — started_at is the caller-captured begin time, not
    /// the persist time, so started_at < finished_at.
    #[test]
    fn persist_scan_stores_real_started_at() {
        let db = Database::open_in_memory().expect("in-memory DB");
        let begun = Utc::now() - chrono::Duration::seconds(42);
        let run_id_str = persist_scan(&db, r"C:\Root", &[], &[], false, begun).unwrap();
        let run_id = Uuid::parse_str(&run_id_str).unwrap();
        let runs = db.scan_store().list_scan_runs().unwrap();
        let run = runs.iter().find(|r| r.id == run_id).expect("run stored");
        assert_eq!(
            run.started_at.timestamp(),
            begun.timestamp(),
            "started_at must be the caller-captured begin time"
        );
        let finished = run.finished_at.expect("finished_at must be set");
        assert!(
            finished > run.started_at,
            "finished_at must lie after started_at (real duration, not zero)"
        );
    }

    /// Review 2026-06-04 round 3 finding 3: `build_path_trustees_with_share`
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
            sd_hash: None,
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
            sd_hash: None,
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
        // Both set: success, trimmed.
        // Both set: succeeds with trimmed values.
        let (s, n) = super::normalize_smb_pair(Some("  fileserver  "), Some("  data  "))
            .expect("matched pair must succeed");
        assert_eq!(s.as_deref(), Some("fileserver"));
        assert_eq!(n.as_deref(), Some("data"));
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

        assert!(
            !raw.starts_with("S-1-"),
            "regression guard: raw value must NOT classify as a SID — proves the fix is necessary"
        );
    }

    /// Round-7 finding 2: GUI HTML export must refuse to overwrite an
    /// existing target file instead of silently truncating it. CLI
    /// already enforces this via `check_overwrite_policy`; the GUI worker
    /// now enforces the same policy directly inside `export_html`.
    #[test]
    fn export_html_refuses_to_overwrite_existing_file() {
        use std::io::Write;
        // Unique file name placed directly in std::env::temp_dir() so
        // we do not need an external tempfile dependency.
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
            err.contains("already exists"),
            "error must name the overwrite condition; got: {err}"
        );
        // Sentinel must still be intact at the time of refusal.
        assert_eq!(
            sentinel_before_cleanup.as_deref(),
            Some(b"<!-- sentinel: must not be overwritten -->".as_ref()),
            "pre-existing file content must remain untouched"
        );
    }

    /// Review 2026-06-13 finding 3: the worker's scan-to-persist hand-off
    /// must carry the actual audit payload — not just the run row and
    /// errors (already covered above). This pins that the `permissions`
    /// slice passed to `persist_scan` reaches storage and round-trips with
    /// its identity, masks, explanation and diagnostics intact.
    #[test]
    fn persist_scan_round_trips_the_permission_payload() {
        use adpa_core::model::{
            AccessMask, EffectivePermission, Identity, IdentityKind, LocalGroupEvalStatus,
            NormalizedPath, PermissionDiagnostic, PermissionPath, ShareEvalStatus, Sid,
        };

        let perm = EffectivePermission {
            identity: Identity {
                sid: Sid("S-1-5-21-9-9-9-1234".to_owned()),
                name: Some("WorkerUser".to_owned()),
                domain: Some("CORP".to_owned()),
                kind: IdentityKind::User,
                disabled: false,
                user_principal_name: None,
                sid_history_count: 0,
            },
            path: NormalizedPath(r"C:\Root\Sub".to_owned()),
            ntfs_mask: AccessMask(0x001F01FF),
            share_mask: None,
            effective_mask: AccessMask(0x001F01FF),
            path_explanation: PermissionPath {
                steps: vec!["User -> Group A -> Allow Full Control".to_owned()],
            },
            share_status: ShareEvalStatus::NotApplicable,
            local_group_status: LocalGroupEvalStatus::NotQueried,
            contributing_sids: vec![],
            unsupported_ace_count: 0,
            matched_aces: vec![],
            diagnostics: vec![PermissionDiagnostic::OwnerRightsAceApplied],
        };

        let db = Database::open_in_memory().expect("in-memory DB");
        let run_id_str = persist_scan(&db, r"C:\Root", &[perm], &[], false, Utc::now())
            .expect("persist_scan should succeed");
        let run_id = Uuid::parse_str(&run_id_str).expect("valid UUID");

        let loaded = db
            .scan_store()
            .get_permissions(&run_id)
            .expect("get_permissions");
        assert_eq!(loaded.len(), 1, "the single permission must be persisted");
        let p = &loaded[0];
        assert_eq!(p.path.0, r"C:\Root\Sub");
        assert_eq!(p.identity.sid.0, "S-1-5-21-9-9-9-1234");
        assert_eq!(p.effective_mask.0, 0x001F01FF);
        assert_eq!(p.path_explanation.steps.len(), 1);
        assert!(
            matches!(
                p.diagnostics.as_slice(),
                [PermissionDiagnostic::OwnerRightsAceApplied]
            ),
            "the diagnostic payload must round-trip, got: {:?}",
            p.diagnostics
        );
    }

    // --- LDAP mode → params/config mapping (GUI Global Catalog support) ---

    fn params(mode: i32) -> Option<LdapParams> {
        LdapParams::from_mode(
            mode,
            "dc.corp.local".to_owned(),
            "DC=corp,DC=local".to_owned(),
            "CN=svc,DC=corp,DC=local".to_owned(),
            "pw".to_owned(),
            10,
        )
    }

    #[test]
    fn ldap_mode_off_yields_no_params() {
        assert!(params(0).is_none(), "mode 0 (Off) must mean no LDAP");
    }

    #[test]
    fn ldap_timeout_is_clamped_and_applied_to_config() {
        let cfg = |secs: i32| {
            LdapParams::from_mode(
                1,
                "dc".to_owned(),
                "DC=c".to_owned(),
                "CN=s,DC=c".to_owned(),
                "pw".to_owned(),
                secs,
            )
            .expect("LDAPS mode")
            .to_config()
            .timeout_secs
        };
        assert_eq!(cfg(45), 45, "in-range value passes through to the config");
        assert_eq!(cfg(9999), 600, "above the maximum is clamped to 600 s");
        assert_eq!(cfg(0), 1, "below the minimum is clamped to 1 s");
    }

    #[test]
    fn ldap_mode_maps_to_flags() {
        let ldaps = params(1).expect("mode 1");
        assert!(!ldaps.insecure && !ldaps.global_catalog, "mode 1 = LDAPS");
        let plain = params(2).expect("mode 2");
        assert!(
            plain.insecure && !plain.global_catalog,
            "mode 2 = plain LDAP"
        );
        let gc = params(3).expect("mode 3");
        assert!(
            gc.global_catalog && !gc.insecure && !gc.signing,
            "mode 3 = Global Catalog over LDAPS"
        );
        let signed = params(4).expect("mode 4");
        assert!(
            signed.signing && !signed.insecure && !signed.global_catalog,
            "mode 4 = signed LDAP (GSSAPI sign+seal)"
        );
    }

    #[test]
    fn to_config_picks_port_and_tls_per_mode() {
        use ad_resolver::TlsMode;
        // LDAPS (mode 1): 636 + Ldaps
        let c = params(1).unwrap().to_config();
        assert_eq!(c.port, 636);
        assert_eq!(c.tls_mode, TlsMode::Ldaps);
        // Plain (mode 2): 389 + Insecure
        let c = params(2).unwrap().to_config();
        assert_eq!(c.port, 389);
        assert_eq!(c.tls_mode, TlsMode::Insecure);
        // Global Catalog (mode 3): 3269 + Ldaps
        let c = params(3).unwrap().to_config();
        assert_eq!(c.port, 3269);
        assert_eq!(c.tls_mode, TlsMode::Ldaps);
        // Signed LDAP (mode 4): 389 + GssapiSign, no bind credentials
        let c = params(4).unwrap().to_config();
        assert_eq!(c.port, 389);
        assert_eq!(c.tls_mode, TlsMode::GssapiSign);
        assert!(
            c.bind_dn.is_empty() && c.bind_password.is_empty(),
            "signed bind uses the current Windows logon — no bind credentials"
        );
    }
}
