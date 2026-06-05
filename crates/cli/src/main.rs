// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

mod output;

#[cfg(not(windows))]
use ad_resolver::NoLsaBackend;
#[cfg(windows)]
use ad_resolver::WindowsLsaBackend;
use ad_resolver::{
    principal::PrincipalInput, DisabledStatus, GroupResolutionStatus, IdentityScopeStatus,
    LdapConfig, LdapIdentityBackend, LdapResolver, PrincipalResolution, PrincipalResolver,
};
#[cfg(not(windows))]
use adpa_core::model::{Identity, IdentityKind};
use adpa_core::{
    model::{AccessContext, EffectivePermission, NormalizedPath, RiskFinding, ScanError, ScanRun},
    traits::{
        AnalysisResult, ExportTarget, Exporter, PermissionEvaluationInput, PermissionEvaluator,
        RiskContext,
    },
};
use chrono::Utc;
use clap::{Parser, Subcommand};
use exporter::{CsvExporter, HtmlExporter, JsonExporter};
use fs_scanner::{read_fso, walk_tree, CancellationToken, WalkConfig};
use permission_engine::{
    build_token_sids_with_context, engine::DefaultPermissionEngine, NormalizedRights,
};
use persistence::Database;
use risk_engine::RuleRegistry;
use share_scanner::{effective_share_mask, get_share_dacl};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;
use validation::{
    db_path::validate_db_path,
    export_path::{validate_export_path, ExportPathStatus},
    net::{
        validate_dn, validate_identity_query, validate_ldap_endpoint, validate_share_name,
        validate_smb_server,
    },
    numbers::validate_optional_scan_depth,
    path::validate_path,
    sid::validate_sid,
};

#[derive(Parser)]
#[command(
    name = "adpa",
    version,
    about = "AD Permission Analyzer — read-only analysis of NTFS, SMB and AD permissions"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Effektive Berechtigungen für einen Benutzer auf einem einzelnen Pfad analysieren.
    /// Analyze effective permissions for a user on a single path.
    Analyze {
        #[arg(short, long)]
        path: String,
        #[arg(short, long)]
        user: String,
        #[arg(short = 's', long)]
        server: Option<String>,
        #[arg(short = 'b', long)]
        base_dn: Option<String>,
        #[arg(long)]
        bind_dn: Option<String>,
        /// **DEPRECATED — unsicher.** Sichtbar in Prozesslisten und Shell-History.
        /// Nutze stattdessen die Umgebungsvariable `ADPA_BIND_PASSWORD`.
        /// Bleibt aus Rueckwaertskompatibilitaet erhalten, wird in einer
        /// kommenden Version entfernt.
        /// **DEPRECATED — insecure.** Visible in process listings and shell
        /// history. Use the `ADPA_BIND_PASSWORD` environment variable
        /// instead. Kept for backwards compatibility; will be removed in
        /// a future release.
        #[arg(long)]
        bind_password: Option<String>,
        /// Unverschlüsseltes LDAP (Port 389) — Passwort im Klartext. Nur für Testumgebungen.
        /// Unencrypted LDAP (port 389) — password in plaintext. Test environments only.
        #[arg(long)]
        insecure_ldap: bool,
        /// Optional CSV export path
        #[arg(short = 'o', long)]
        output: Option<String>,
        /// SMB-Server für Share-Berechtigungen (auto-erkannt bei UNC-Pfad)
        /// SMB server for share permissions (auto-detected for UNC paths)
        #[arg(long)]
        smb_server: Option<String>,
        /// Share-Name für NTFS-∩-Share-Kombination (auto-erkannt bei UNC-Pfad)
        /// Share name for NTFS ∩ Share combination (auto-detected for UNC paths)
        #[arg(long)]
        share_name: Option<String>,
        /// Vorhandene Exportdatei ohne Rückfrage überschreiben.
        /// Overwrite an existing export file without confirmation.
        #[arg(long)]
        force: bool,
    },

    /// Verzeichnisbaum rekursiv scannen und Ergebnisse in der Datenbank speichern.
    /// Recursively scan a directory tree and store results in the database.
    Scan {
        /// Wurzelpfad des Scans (lokal oder UNC) / Root path (local or UNC)
        #[arg(short, long)]
        path: String,
        /// Benutzer-SID oder sAMAccountName / User SID or sAMAccountName
        #[arg(short, long)]
        user: String,
        #[arg(short = 's', long)]
        server: Option<String>,
        #[arg(short = 'b', long)]
        base_dn: Option<String>,
        #[arg(long)]
        bind_dn: Option<String>,
        /// **DEPRECATED — unsicher.** Sichtbar in Prozesslisten und Shell-History.
        /// Nutze stattdessen die Umgebungsvariable `ADPA_BIND_PASSWORD`.
        /// Bleibt aus Rueckwaertskompatibilitaet erhalten, wird in einer
        /// kommenden Version entfernt.
        /// **DEPRECATED — insecure.** Visible in process listings and shell
        /// history. Use the `ADPA_BIND_PASSWORD` environment variable
        /// instead. Kept for backwards compatibility; will be removed in
        /// a future release.
        #[arg(long)]
        bind_password: Option<String>,
        /// Unverschlüsseltes LDAP (Port 389) — Passwort im Klartext. Nur für Testumgebungen.
        /// Unencrypted LDAP (port 389) — password in plaintext. Test environments only.
        #[arg(long)]
        insecure_ldap: bool,
        /// SQLite-Datenbankdatei für Ergebnisse (wird erstellt wenn nicht vorhanden)
        /// SQLite database file for results (created if absent)
        #[arg(long)]
        db: Option<String>,
        /// Maximale Scan-Tiefe (unbegrenzt wenn nicht angegeben) / Max scan depth (unlimited if omitted)
        #[arg(long)]
        max_depth: Option<u32>,
        /// Optional CSV export path
        #[arg(short = 'o', long)]
        output: Option<String>,
        /// SMB-Server für Share-Berechtigungen (auto-erkannt bei UNC-Pfad)
        /// SMB server for share permissions (auto-detected for UNC paths)
        #[arg(long)]
        smb_server: Option<String>,
        /// Share-Name für NTFS-∩-Share-Kombination (auto-erkannt bei UNC-Pfad)
        /// Share name for NTFS ∩ Share combination (auto-detected for UNC paths)
        #[arg(long)]
        share_name: Option<String>,
        /// Vorhandene Exportdatei ohne Rückfrage überschreiben.
        /// Overwrite an existing export file without confirmation.
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze {
            path,
            user,
            server,
            base_dn,
            bind_dn,
            bind_password,
            insecure_ldap,
            output,
            smb_server,
            share_name,
            force,
        } => {
            run_analyze(
                path,
                user,
                server,
                base_dn,
                bind_dn,
                bind_password,
                AnalyzeOptions {
                    output,
                    smb_server,
                    share_name,
                    insecure_ldap,
                    force,
                },
            )
            .await?;
        }
        Commands::Scan {
            path,
            user,
            server,
            base_dn,
            bind_dn,
            bind_password,
            insecure_ldap,
            db,
            max_depth,
            output,
            smb_server,
            share_name,
            force,
        } => {
            run_scan(
                path,
                user,
                server,
                base_dn,
                bind_dn,
                bind_password,
                ScanOptions {
                    db_path: db,
                    max_depth,
                    output,
                    smb_server,
                    share_name,
                    insecure_ldap,
                    force,
                },
            )
            .await?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared identity resolution
// ---------------------------------------------------------------------------

/// CLI-lokales Bündel aus [`PrincipalResolution`] und dem Flag
/// `ad_connected` (LDAP-Pfad ja/nein). `ad_connected = false` heißt
/// SAM-only und ist beibehalten, weil einige UI-/Output-Texte davon
/// abhängen. Review 2026-06-04 Runde 3 Finding 1: die zentrale Logik
/// liegt jetzt in `PrincipalResolution`, nicht mehr in einer
/// zusammengeschusterten Tupel-Struktur.
/// CLI-local bundle: [`PrincipalResolution`] + the `ad_connected`
/// flag.
struct ResolvedIdentity {
    resolution: PrincipalResolution,
    ad_connected: bool,
}

/// Normalisierte Verbindungs-Eingaben — getrimmte und validierte
/// Werte, die direkt an LDAP- bzw. NetAPI-Aufrufe weitergegeben werden
/// dürfen. Schließt Review 2026-06-04 Runde 3 Finding 2: vorher gaben
/// CLI und GUI nach `validate_*`-Aufrufen weiterhin den (un-getrimmten)
/// Rohstring weiter — die Validierung hatte nur Konsultations-, nicht
/// Übergabe-Charakter.
/// Normalized connection inputs — trimmed and validated, ready for
/// LDAP / NetAPI consumption.
#[derive(Debug)]
struct NormalizedConnectionInputs {
    server: Option<String>,
    base_dn: Option<String>,
    bind_dn: Option<String>,
    smb_server: Option<String>,
    share_name: Option<String>,
}

/// Validiert optionale Verbindungs-Eingaben und liefert die getrimmten
/// Normalformen zurück. Aufrufer dürfen die ursprünglichen Rohstrings
/// danach nicht mehr verwenden.
/// Centrally validates optional connection inputs and returns trimmed
/// normalized values.
fn validate_connection_inputs(
    server: Option<&str>,
    base_dn: Option<&str>,
    bind_dn: Option<&str>,
    smb_server: Option<&str>,
    share_name: Option<&str>,
) -> anyhow::Result<NormalizedConnectionInputs> {
    let server = match server {
        Some(s) => Some(
            validate_ldap_endpoint(s)
                .map_err(|e| anyhow::anyhow!("Invalid LDAP server: {e}"))?
                .0,
        ),
        None => None,
    };
    let base_dn = match base_dn {
        Some(d) => Some(
            validate_dn(d)
                .map_err(|e| anyhow::anyhow!("Invalid base DN: {e}"))?
                .0,
        ),
        None => None,
    };
    let bind_dn = match bind_dn {
        Some(d) => Some(
            validate_dn(d)
                .map_err(|e| anyhow::anyhow!("Invalid bind DN: {e}"))?
                .0,
        ),
        None => None,
    };
    // Review 2026-06-04 Runde 2, Finding 2: --smb-server und --share-name
    // sind nur als Paar sinnvoll. Halb-Sets verunreinigten sonst die
    // lokale-Gruppen-Auflösung mit Token-SIDs vom Remote-Server, ohne
    // dass eine Share-Maske angewendet werden konnte.
    let smb_server_set = smb_server.is_some_and(|s| !s.trim().is_empty());
    let share_name_set = share_name.is_some_and(|s| !s.trim().is_empty());
    match (smb_server_set, share_name_set) {
        (true, false) => {
            return Err(anyhow::anyhow!(
                "SMB context incomplete: --smb-server set but --share-name missing. Provide both or neither."
            ));
        }
        (false, true) => {
            return Err(anyhow::anyhow!(
                "SMB context incomplete: --share-name set but --smb-server missing. Provide both or neither."
            ));
        }
        _ => {}
    }
    let smb_server = match smb_server {
        Some(s) if !s.trim().is_empty() => Some(
            validate_smb_server(s)
                .map_err(|e| anyhow::anyhow!("Invalid SMB server: {e}"))?
                .0,
        ),
        _ => None,
    };
    let share_name = match share_name {
        Some(s) if !s.trim().is_empty() => Some(
            validate_share_name(s)
                .map_err(|e| anyhow::anyhow!("Invalid share name: {e}"))?
                .0,
        ),
        _ => None,
    };
    Ok(NormalizedConnectionInputs {
        server,
        base_dn,
        bind_dn,
        smb_server,
        share_name,
    })
}

async fn resolve_identity(
    user: &str,
    server: Option<String>,
    base_dn: Option<String>,
    bind_dn: Option<String>,
    bind_password: Option<String>,
    insecure_ldap: bool,
) -> anyhow::Result<ResolvedIdentity> {
    if let Some(server) = server {
        let base = base_dn.ok_or_else(|| {
            anyhow::anyhow!(
                "--base-dn is required when --server is specified (e.g. DC=corp,DC=local)"
            )
        })?;
        let bind = bind_dn.ok_or_else(|| {
            anyhow::anyhow!(
                "--bind-dn is required when --server is specified \
                 (e.g. CN=Administrator,CN=Users,DC=corp,DC=local)"
            )
        })?;
        let password = if let Some(p) = bind_password {
            eprintln!(
                "[WARNING] --bind-password is DEPRECATED — credentials passed as a CLI argument \
                 are visible in process listings and shell history. \
                 Use the ADPA_BIND_PASSWORD environment variable instead. \
                 --bind-password will be removed in a future release."
            );
            p
        } else if let Ok(p) = std::env::var("ADPA_BIND_PASSWORD") {
            p
        } else {
            return Err(anyhow::anyhow!(
                "ADPA_BIND_PASSWORD environment variable is required (the --bind-password \
                 argument exists for backwards compatibility but is deprecated)"
            ));
        };

        if insecure_ldap {
            eprintln!(
                "[WARNING] --insecure-ldap: the bind password is transmitted in plaintext. \
                 Use only in isolated test environments."
            );
        }

        let config = if insecure_ldap {
            LdapConfig::new_insecure(&server, &base, &bind, &password)
        } else {
            LdapConfig::new(&server, &base, &bind, &password)
        };
        let ldap_resolver = std::sync::Arc::new(LdapResolver::new(config));
        let backend = LdapIdentityBackend::new(ldap_resolver);

        // Zentrale Pipeline statt vier separater Lookup-Pfade — schliesst
        // Review 2026-06-04 Runde 3 Finding 1.
        // Central pipeline replacing four separate lookup paths.
        #[cfg(windows)]
        let principal_resolver = PrincipalResolver::new(backend, Some(WindowsLsaBackend));
        #[cfg(not(windows))]
        let principal_resolver: PrincipalResolver<_, NoLsaBackend> =
            PrincipalResolver::new(backend, None);

        let resolution = principal_resolver
            .resolve(PrincipalInput::Auto(user.to_owned()))
            .await
            .map_err(|e| anyhow::anyhow!("Identity resolution failed: {e}"))?;

        Ok(ResolvedIdentity {
            resolution,
            ad_connected: true,
        })
    } else {
        let trimmed = user.trim();
        // SAM-only-Pfad: weiterhin der Workhorse fuer das DC-Szenario
        // ohne explizite LDAP-Bindung. Liefert jetzt aber eine
        // `PrincipalResolution` mit korrekt klassifiziertem ScopeStatus
        // und GroupResolutionStatus, statt einer Sondertupel-Struktur.
        // SAM-only path: still the workhorse for DC-without-LDAP usage.
        #[cfg(windows)]
        {
            let sid = if trimmed.starts_with("S-1-") {
                adpa_core::model::Sid(trimmed.to_owned())
            } else {
                ad_resolver::lookup_sid_for_account(None, trimmed)
                    .map_err(|e| anyhow::anyhow!("LSA name lookup failed: {e}"))?
            };
            let sam_res = ad_resolver::resolve_identity_via_sam(&sid.0)
                .map_err(|e| anyhow::anyhow!("SAM resolution failed: {e}"))?;
            let disabled_status = if sam_res.disabled_known {
                DisabledStatus::Known(sam_res.identity.disabled)
            } else {
                DisabledStatus::Unknown
            };
            let mut diagnostics: Vec<adpa_core::model::PermissionDiagnostic> = Vec::new();
            if matches!(disabled_status, DisabledStatus::Unknown) {
                diagnostics
                    .push(adpa_core::model::PermissionDiagnostic::IdentityDisabledStatusUnknown);
            } else if sam_res.identity.disabled {
                diagnostics.push(adpa_core::model::PermissionDiagnostic::IdentityDisabled);
            }
            let resolution = PrincipalResolution {
                sid: sam_res.identity.sid.clone(),
                identity: sam_res.identity,
                memberships: sam_res.memberships,
                // SAM-only auf einem DC = lokale Domain → "Inside" im
                // Sinne des konfigurierten Scopes ist nicht definiert,
                // da kein LDAP-Scope existiert. Wir verwenden Inside
                // (keine zusaetzliche Cross-Domain-Warnung), da die
                // SAM-Aufloesung domaenenkohaerent ist. Die
                // Domain-Gruppen-Rekursion ist trotzdem nur flach —
                // GroupResolutionStatus::SamFlat treibt den richtigen
                // Marker durch die Engine.
                // SAM-only on a DC = local domain → Inside; the
                // flat-recursion incompleteness is signalled separately
                // via SamFlat → DomainGroupRecursionIncomplete.
                scope_status: IdentityScopeStatus::InsideConfiguredLdapBase,
                group_resolution_status: GroupResolutionStatus::SamFlat,
                disabled_status,
                diagnostics,
            };
            Ok(ResolvedIdentity {
                resolution,
                ad_connected: false,
            })
        }
        #[cfg(not(windows))]
        {
            if !trimmed.starts_with("S-1-") {
                return Err(anyhow::anyhow!(
                    "Without --server, --user must be a SID (S-1-5-...). \
                     Use --server to resolve sAMAccountNames."
                ));
            }
            let sid = adpa_core::model::Sid(trimmed.to_owned());
            let identity = Identity {
                sid: sid.clone(),
                name: Some(trimmed.to_owned()),
                domain: None,
                kind: IdentityKind::Unknown,
                disabled: false,
                user_principal_name: None,
            };
            let resolution = PrincipalResolution {
                sid,
                identity,
                memberships: vec![],
                scope_status: IdentityScopeStatus::OrphanedSid,
                group_resolution_status: GroupResolutionStatus::NotAttempted,
                disabled_status: DisabledStatus::Unknown,
                diagnostics: vec![
                    adpa_core::model::PermissionDiagnostic::IdentityDisabledStatusUnknown,
                ],
            };
            Ok(ResolvedIdentity {
                resolution,
                ad_connected: false,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// analyze subcommand
// ---------------------------------------------------------------------------

struct AnalyzeOptions {
    output: Option<String>,
    smb_server: Option<String>,
    share_name: Option<String>,
    insecure_ldap: bool,
    /// Vorhandene Exportdatei überschreiben. / Overwrite an existing export file.
    force: bool,
}

async fn run_analyze(
    path: String,
    user: String,
    server: Option<String>,
    base_dn: Option<String>,
    bind_dn: Option<String>,
    bind_password: Option<String>,
    opts: AnalyzeOptions,
) -> anyhow::Result<()> {
    let AnalyzeOptions {
        output,
        smb_server,
        share_name,
        insecure_ldap,
        force,
    } = opts;

    // Review 2026-06-04 Runde 2, Finding 6: ab hier die validierte
    // Normalform durchreichen, nicht den rohen Eingabestring. Der Wrapper
    // hat geleerte Pfade abgelehnt, Whitespace getrimmt und Long-Path-
    // Formen kanonisiert — Downstream-Code muss genau diese Form sehen.
    // Review 2026-06-04 round 2, finding 6: from here on we forward the
    // validated canonical form, not the raw input string. The wrapper
    // rejected empty paths, trimmed whitespace and canonicalised long-
    // path forms — downstream code must see exactly that form.
    let path = validate_path(&path)
        .map_err(|e| anyhow::anyhow!("Invalid path: {e}"))?
        .0;
    // Review 2026-06-04 Runde 3 Finding 2 + Runde 4 Finding 2:
    // Klassifikation auf dem getrimmten Wert. Vorher landete
    // "  S-1-...  " im Name-Zweig — symmetrisch zum GUI-Bug.
    // Round 3 finding 2 + round 4 finding 2: classify on the trimmed value.
    let user_trimmed = user.trim();
    let user = if user_trimmed.starts_with("S-1-") {
        validate_sid(user_trimmed)
            .map_err(|e| anyhow::anyhow!("Invalid SID: {e}"))?
            .0
    } else {
        validate_identity_query(user_trimmed)
            .map_err(|e| anyhow::anyhow!("Invalid user / sAMAccountName: {e}"))?
            .0
    };
    let conn = validate_connection_inputs(
        server.as_deref(),
        base_dn.as_deref(),
        bind_dn.as_deref(),
        smb_server.as_deref(),
        share_name.as_deref(),
    )?;
    let server = conn.server;
    let base_dn = conn.base_dn;
    let bind_dn = conn.bind_dn;
    let smb_server = conn.smb_server;
    let share_name = conn.share_name;

    let fso = read_fso(&path).map_err(|e| anyhow::anyhow!("Cannot read path '{}': {}", path, e))?;

    let resolved = resolve_identity(
        &user,
        server,
        base_dn,
        bind_dn,
        bind_password,
        insecure_ldap,
    )
    .await?;

    // Lokale Server-Gruppen zuerst aufloesen — sie gehoeren zum Token-SID-Satz
    // und werden sowohl von der Share-Maskenberechnung als auch von der NTFS-
    // Auswertung benoetigt. Reihenfolge ist hier wichtig: ohne local_group_sids
    // wuerde die Share-Maske ACEs auf lokale Server-Gruppen ignorieren.
    // Resolve local server groups first — they belong to the token SID set and
    // are needed by both the share mask computation and the NTFS evaluation.
    // Order matters: without local_group_sids the share mask would ignore ACEs
    // that target local server groups.
    let (local_group_sids, local_group_memberships, local_group_status) =
        collect_local_group_sids_for_path(
            &path,
            smb_server.as_deref(),
            &resolved.resolution.identity,
            &resolved.resolution.memberships,
        );

    if let adpa_core::model::LocalGroupEvalStatus::NotAvailable(ref msg) = local_group_status {
        println!(
            "[Warning] Local server groups could not be resolved — result is incomplete (token may miss local-group SIDs). ({msg})"
        );
    }

    let access_context =
        AccessContext::for_path_with_smb(&path, smb_server.as_deref(), share_name.as_deref());
    let (share_status, unsupported_share_ace_count) = resolve_scan_share_status(
        &path,
        smb_server.as_deref(),
        share_name.as_deref(),
        &resolved,
        &local_group_sids,
        access_context,
    );

    if let adpa_core::model::ShareMaskStatus::ReadFailed(ref msg) = share_status {
        println!(
            "[Warning] Share DACL could not be read — result is incomplete (effective_mask reflects NTFS only). ({msg})"
        );
    }
    if unsupported_share_ace_count > 0 {
        println!(
            "[Warning] {unsupported_share_ace_count} share ACE(s) of unsupported type were skipped — share mask may be incomplete."
        );
    }
    // SID→Name-Tabelle für die Erklärungstexte vorbereiten: Memberships
    // (mit ggf. bereits vom Resolver gesetzten Gruppennamen) und alle in
    // der DACL referenzierten Trustee-SIDs einmalig in `DOMAIN\Name`
    // auflösen. Der Engine reicht das in den Berechtigungspfad durch.
    // Build the SID→name table for the explanation text: memberships
    // (with names possibly already set by the resolver) and all trustee
    // SIDs referenced in the DACL get a single LSA round-trip into
    // `DOMAIN\Name`. The engine threads it through the permission path.
    #[cfg(windows)]
    let sid_names = ad_resolver::build_sid_name_map(
        &resolved.resolution.memberships,
        fso.dacl.iter().map(|a| a.sid.0.clone()),
    );
    #[cfg(not(windows))]
    let sid_names = std::collections::BTreeMap::new();

    // Engine-Flags werden zentral aus dem ScopeStatus/GroupResolutionStatus
    // abgeleitet — Single Source of Truth (Review Runde 3 Finding 1).
    // Engine flags are derived centrally from the resolution status.
    // Review 2026-06-05 Runde 6 Finding 1: AD-Memberships +
    // lokale-Servergruppen-Memberships zusammen an die Engine, damit
    // der Erklaerungspfad jeden Token-Schritt sichtbar macht.
    // Round 6 finding 1: feed AD memberships + local server group
    // memberships together so the explanation path renders every
    // mediator step.
    let mut all_memberships = resolved.resolution.memberships.clone();
    all_memberships.extend(local_group_memberships.iter().cloned());

    let engine_flags = resolved.resolution.engine_flags();
    let input = PermissionEvaluationInput {
        identity: resolved.resolution.identity.clone(),
        group_memberships: all_memberships,
        file_system_object: fso.clone(),
        share_status,
        local_group_sids,
        local_group_status,
        access_context,
        unsupported_share_ace_count,
        sid_names,
        group_resolution_via_sam_fallback: engine_flags.group_resolution_via_sam_fallback,
        identity_not_in_configured_ldap_base: engine_flags.identity_not_in_configured_ldap_base,
        identity_disabled_status_unknown: engine_flags.identity_disabled_status_unknown,
        identity_lookup_failure_reason: engine_flags.identity_lookup_failure_reason.clone(),
        group_resolution_failure_reason: engine_flags.group_resolution_failure_reason.clone(),
    };
    let result = DefaultPermissionEngine
        .evaluate(input)
        .map_err(|e| anyhow::anyhow!("Permission evaluation failed: {e}"))?;

    output::print_report(
        &fso,
        &user,
        &result,
        &resolved.resolution.memberships,
        resolved.ad_connected,
    );

    // Risikoregeln auch im CLI-Pfad ausführen — sonst wirkt der Report unvollständig.
    // Run the risk rules in the CLI path too — otherwise the report looks incomplete.
    let risk_findings = compute_risk_findings(std::slice::from_ref(&result));
    output::print_risk_findings(&risk_findings);

    if let Some(out_path) = output {
        let status = validate_export_path(&out_path)
            .map_err(|e| anyhow::anyhow!("Invalid export path: {e}"))?;
        check_overwrite_policy(&status, force)?;
        let analysis = AnalysisResult {
            permissions: vec![result.clone()],
            risk_findings: risk_findings.clone(),
            ..Default::default()
        };
        export_analysis(&status.path().0, &analysis)?;
        println!("Results exported to: {out_path}");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// scan subcommand
// ---------------------------------------------------------------------------

struct ScanOptions {
    db_path: Option<String>,
    max_depth: Option<u32>,
    output: Option<String>,
    smb_server: Option<String>,
    share_name: Option<String>,
    insecure_ldap: bool,
    /// Vorhandene Exportdatei überschreiben. / Overwrite an existing export file.
    force: bool,
}

async fn run_scan(
    path: String,
    user: String,
    server: Option<String>,
    base_dn: Option<String>,
    bind_dn: Option<String>,
    bind_password: Option<String>,
    opts: ScanOptions,
) -> anyhow::Result<()> {
    let ScanOptions {
        db_path,
        max_depth,
        output,
        smb_server,
        share_name,
        insecure_ldap,
        force,
    } = opts;

    // Review 2026-06-04 Runde 2, Finding 6: Normalform durchreichen.
    // Review 2026-06-04 round 2, finding 6: propagate the normal form.
    let path = validate_path(&path)
        .map_err(|e| anyhow::anyhow!("Invalid path: {e}"))?
        .0;
    // AGENTS.md DoD 11: numerische Eingaben zentral validieren, bevor sie
    // an WalkConfig wandern — sonst kann ein --max-depth=4_000_000_000
    // den Walker bis zur RAM-Sättigung treiben.
    // AGENTS.md DoD 11: validate numeric inputs centrally before they reach
    // WalkConfig — otherwise --max-depth=4_000_000_000 would let the walker
    // run until RAM exhaustion.
    let max_depth = validate_optional_scan_depth(max_depth)
        .map_err(|e| anyhow::anyhow!("Invalid --max-depth: {e}"))?
        .map(|d| d.0);
    // Review 2026-06-04 Runde 4 Finding 2: Klassifikation auf
    // getrimmtem Wert.
    let user_trimmed = user.trim();
    let user = if user_trimmed.starts_with("S-1-") {
        validate_sid(user_trimmed)
            .map_err(|e| anyhow::anyhow!("Invalid SID: {e}"))?
            .0
    } else {
        validate_identity_query(user_trimmed)
            .map_err(|e| anyhow::anyhow!("Invalid user / sAMAccountName: {e}"))?
            .0
    };
    let conn = validate_connection_inputs(
        server.as_deref(),
        base_dn.as_deref(),
        bind_dn.as_deref(),
        smb_server.as_deref(),
        share_name.as_deref(),
    )?;
    let server = conn.server;
    let base_dn = conn.base_dn;
    let bind_dn = conn.bind_dn;
    let smb_server = conn.smb_server;
    let share_name = conn.share_name;
    if let Some(ref db) = db_path {
        validate_db_path(db).map_err(|e| anyhow::anyhow!("Invalid database path: {e}"))?;
    }

    // 1. Identität auflösen / resolve identity
    let resolved = resolve_identity(
        &user,
        server,
        base_dn,
        bind_dn,
        bind_password,
        insecure_ldap,
    )
    .await?;

    // 2. Datenbank öffnen / open database
    let db = db_path
        .as_deref()
        .map(Database::open)
        .transpose()
        .map_err(|e| anyhow::anyhow!("Cannot open database: {e}"))?;

    // 3. Scan-Lauf registrieren / register scan run
    let run_id = Uuid::new_v4();
    let started_at = Utc::now();
    if let Some(ref db) = db {
        db.scan_store()
            .insert_scan_run(&ScanRun {
                id: run_id,
                started_at,
                finished_at: None,
                target: path.clone(),
                errors: vec![],
            })
            .map_err(|e| anyhow::anyhow!("Cannot create scan run: {e}"))?;
    }

    // 4a. Lokale Server-Gruppen vor der Share-Maske auflösen — sonst fehlen die
    //     lokalen Gruppen-SIDs im Token, das gegen die Share-DACL evaluiert wird.
    //     Resolve local server groups before the share mask — otherwise the local
    //     group SIDs are missing from the token evaluated against the share DACL.
    let (scan_local_group_sids, scan_local_group_memberships, scan_local_group_status) =
        collect_local_group_sids_for_path(
            &path,
            smb_server.as_deref(),
            &resolved.resolution.identity,
            &resolved.resolution.memberships,
        );

    // Round 6 finding 1: AD + lokale Memberships zusammen an die
    // Engine (siehe Analyze-Pfad).
    // Combine AD + local memberships for the engine (see Analyze).
    let mut scan_all_memberships = resolved.resolution.memberships.clone();
    scan_all_memberships.extend(scan_local_group_memberships.iter().cloned());

    if let adpa_core::model::LocalGroupEvalStatus::NotAvailable(ref msg) = scan_local_group_status {
        println!(
            "[Warning] Local server groups could not be resolved — scan results are incomplete (token may miss local-group SIDs). ({msg})"
        );
    }

    // 4b. Share-Status auflösen (optional) / resolve share status (optional)
    let scan_access_context =
        AccessContext::for_path_with_smb(&path, smb_server.as_deref(), share_name.as_deref());
    let (scan_share_status, scan_unsupported_share_ace_count) = resolve_scan_share_status(
        &path,
        smb_server.as_deref(),
        share_name.as_deref(),
        &resolved,
        &scan_local_group_sids,
        scan_access_context,
    );

    if let adpa_core::model::ShareMaskStatus::ReadFailed(ref msg) = scan_share_status {
        println!(
            "[Warning] Share DACL could not be read — scan results are incomplete (effective masks reflect NTFS only). ({msg})"
        );
    }
    if scan_unsupported_share_ace_count > 0 {
        println!(
            "[Warning] {scan_unsupported_share_ace_count} share ACE(s) of unsupported type were skipped — share mask may be incomplete (Diagnostic propagated to each result)."
        );
    }

    // Maske für die Headeranzeige extrahieren — nur informativ.
    // Extract the mask for the header display — informational only.
    let scan_share_mask_for_header = match &scan_share_status {
        adpa_core::model::ShareMaskStatus::Applied(m) => Some(*m),
        _ => None,
    };

    // 5. Header ausgeben / print header
    print_scan_header(
        &path,
        &resolved,
        max_depth,
        &run_id,
        scan_share_mask_for_header.as_ref(),
    );

    // 6. Baum scannen / walk tree
    // Ctrl-C löst einen kooperativen Abbruch aus, statt den Prozess hart zu beenden.
    // Ctrl-C triggers a cooperative cancellation instead of killing the process.
    let cancel = CancellationToken::new();
    {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!("\n[Abort] Ctrl-C received — finishing the current path and stopping…");
                cancel.cancel();
            }
        });
    }

    let config = WalkConfig { max_depth };
    let walk = {
        let scan_path = path.clone();
        let cancel = cancel.clone();
        // Der Walk ist blockierend — auf einem Blocking-Thread ausführen, damit der
        // Ctrl-C-Handler reagieren kann.
        // The walk is blocking — run it on a blocking thread so the Ctrl-C handler
        // can still react.
        tokio::task::spawn_blocking(move || walk_tree(&scan_path, &config, &cancel))
            .await
            .map_err(|e| anyhow::anyhow!("Scan task failed: {e}"))?
    };

    let mut all_permissions = Vec::with_capacity(walk.objects.len());
    let mut unsupported_ace_paths = 0usize;
    // scan_local_group_sids wurde bereits oben (vor der Share-Maske) aufgelöst.
    // scan_local_group_sids was already resolved above (before the share mask).
    // scan_access_context wurde ebenfalls schon vor der Share-Maske abgeleitet.
    // scan_access_context was likewise derived above before the share mask.

    // SID→Name-Tabelle für den gesamten Scan einmal aufbauen. Trustee-SIDs
    // wiederholen sich quer durch viele Pfade (BUILTIN\Administrators,
    // Authenticated Users …), deshalb sammeln wir die unique SIDs aller
    // DACLs vorab und führen nur einen LSA-Lookup pro SID statt einen pro
    // Pfad. Memberships sind ohnehin scan-weit konstant.
    // Build the SID→name table once for the whole scan. Trustee SIDs
    // repeat across many paths (BUILTIN\Administrators,
    // Authenticated Users, …), so we collect the unique SIDs from every
    // DACL up front and perform one LSA lookup per SID instead of per
    // path. Memberships are scan-wide constant anyway.
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
        ad_resolver::build_sid_name_map(&resolved.resolution.memberships, trustees)
    };
    #[cfg(not(windows))]
    let scan_sid_names = std::collections::BTreeMap::new();

    let scan_engine_flags = resolved.resolution.engine_flags();
    for fso in &walk.objects {
        let input = PermissionEvaluationInput {
            identity: resolved.resolution.identity.clone(),
            group_memberships: scan_all_memberships.clone(),
            file_system_object: fso.clone(),
            share_status: scan_share_status.clone(),
            local_group_sids: scan_local_group_sids.clone(),
            local_group_status: scan_local_group_status.clone(),
            access_context: scan_access_context,
            unsupported_share_ace_count: scan_unsupported_share_ace_count,
            sid_names: scan_sid_names.clone(),
            group_resolution_via_sam_fallback: scan_engine_flags.group_resolution_via_sam_fallback,
            identity_not_in_configured_ldap_base: scan_engine_flags
                .identity_not_in_configured_ldap_base,
            identity_disabled_status_unknown: scan_engine_flags.identity_disabled_status_unknown,
            identity_lookup_failure_reason: scan_engine_flags
                .identity_lookup_failure_reason
                .clone(),
            group_resolution_failure_reason: scan_engine_flags
                .group_resolution_failure_reason
                .clone(),
        };
        let result = DefaultPermissionEngine.evaluate(input).map_err(|e| {
            anyhow::anyhow!("Permission evaluation failed for '{}': {e}", fso.path.0)
        })?;

        let rights = NormalizedRights::new(result.effective_mask.0);
        // Diagnose: Pfade mit nicht ausgewerteten ACE-Typen sichtbar markieren.
        // Diagnostic: visibly flag paths with unevaluated ACE types.
        if result.unsupported_ace_count > 0 {
            unsupported_ace_paths += 1;
            println!(
                "  {:14}  {}  [!{} unsupported ACE(s)]",
                rights.display_name(),
                fso.path.0,
                result.unsupported_ace_count
            );
        } else {
            println!("  {:14}  {}", rights.display_name(), fso.path.0);
        }

        if let Some(ref db) = db {
            db.scan_store()
                .insert_permission(&run_id, &result)
                .map_err(|e| anyhow::anyhow!("Failed to store permission: {e}"))?;
        }
        all_permissions.push(result);
    }

    for walk_err in &walk.errors {
        println!("  [Error]         {}: {}", walk_err.path, walk_err.error);
        if let Some(ref db) = db {
            db.scan_store()
                .insert_error(
                    &run_id,
                    &ScanError {
                        path: Some(NormalizedPath(walk_err.path.clone())),
                        message: walk_err.error.to_string(),
                    },
                )
                .ok();
        }
    }

    // 6b. Abbruch behandeln — partiellen Lauf als abgebrochen kennzeichnen.
    // Handle cancellation — mark the partial run as aborted.
    if walk.cancelled {
        println!();
        println!("  [Aborted] Scan cancelled by user — results are partial.");
        if let Some(ref db) = db {
            db.scan_store()
                .insert_error(
                    &run_id,
                    &ScanError {
                        path: None,
                        message: "Scan cancelled by user — results are partial".to_owned(),
                    },
                )
                .ok();
        }
    }

    // 7. Scan abschließen / finish scan run
    if let Some(ref db) = db {
        db.scan_store()
            .finish_scan_run(&run_id, Utc::now())
            .map_err(|e| anyhow::anyhow!("Failed to finish scan run: {e}"))?;
    }

    // 8. Zusammenfassung / summary
    let duration = (Utc::now() - started_at).num_milliseconds();
    print_scan_summary(
        walk.objects.len(),
        walk.errors.len(),
        unsupported_ace_paths,
        duration,
        db_path.as_deref(),
        &run_id,
    );

    // 8b. Risikoregeln auch im CLI-Scan-Pfad ausführen.
    // 8b. Run the risk rules in the CLI scan path too.
    let risk_findings = compute_risk_findings(&all_permissions);
    output::print_risk_findings(&risk_findings);

    // 9. Optionaler Export / optional export
    if let Some(out_path) = output {
        let status = validate_export_path(&out_path)
            .map_err(|e| anyhow::anyhow!("Invalid export path: {e}"))?;
        check_overwrite_policy(&status, force)?;
        let analysis = AnalysisResult {
            permissions: all_permissions,
            risk_findings,
            ..Default::default()
        };
        export_analysis(&status.path().0, &analysis)?;
        println!("  Results exported to: {out_path}");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Share-mask helpers
// ---------------------------------------------------------------------------

// UNC-Zerlegung lebt jetzt zentral in validation::path::parse_unc_components.
// Die alte CLI-lokale Variante hat lokale Pfade fälschlich als UNC akzeptiert
// (Review-Befund 1) und Long-Path-UNC falsch zerlegt (Review-Befund 4).
// UNC parsing now lives centrally in validation::path::parse_unc_components.
// The old CLI-local variant accepted local paths as UNC (review finding 1) and
// mis-split long-path UNC (review finding 4).
use validation::path::{effective_smb_target, parse_unc_components};

/// Sammelt alle SIDs des Benutzers (eigene + Gruppen-SIDs).
/// Collects all SIDs for the user (own + group SIDs).
/// Löst den Share-Status für Scan und Analyze auf.
/// Resolves the share status for scan and analyze commands.
///
/// Gibt `NotApplicable` zurück wenn kein SMB-Kontext erkennbar; `Applied(mask)`
/// nach erfolgreichem DACL-Lesen; `ReadFailed(reason)` bei NetAPI-Fehlern.
/// Returns `NotApplicable` when no SMB context is detectable; `Applied(mask)`
/// after a successful DACL read; `ReadFailed(reason)` on NetAPI errors.
fn resolve_scan_share_status(
    path: &str,
    smb_server: Option<&str>,
    share_name: Option<&str>,
    resolved: &ResolvedIdentity,
    local_group_sids: &[adpa_core::model::Sid],
    access_context: AccessContext,
) -> (adpa_core::model::ShareMaskStatus, usize) {
    use adpa_core::model::ShareMaskStatus;
    // Server-Wahl: expliziter `smb_server` schlägt UNC-Server (Finding 2).
    // Share-Wahl: expliziter `share_name` schlägt UNC-Share. Ohne UNC und ohne
    // expliziten Share landen wir bei NotApplicable — der Aufrufer wollte
    // keinen SMB-Kontext.
    // Server selection: explicit `smb_server` beats the UNC server (finding 2).
    // Share selection: explicit `share_name` beats the UNC share. Without a UNC
    // and without an explicit share we land in NotApplicable — the caller did
    // not ask for an SMB context.
    let path_components = parse_unc_components(path);
    let server = match effective_smb_target(path, smb_server) {
        Some(s) => s,
        None => return (ShareMaskStatus::NotApplicable, 0),
    };
    let share = match share_name {
        Some(s) => s.to_owned(),
        None => match path_components {
            Some((_, share_from_path)) => share_from_path,
            None => return (ShareMaskStatus::NotApplicable, 0),
        },
    };

    tracing::info!(server = %server, share = %share, "Resolving share mask");

    match get_share_dacl(&server, &share) {
        Err(e) => {
            tracing::warn!(server = %server, share = %share, error = %e, "Cannot read share DACL");
            (ShareMaskStatus::ReadFailed(e.to_string()), 0)
        }
        Ok(scan) => {
            // Token-Satz MUSS dieselben SIDs enthalten wie auf NTFS-Seite, sonst
            // werden Share-ACEs auf lokale Server-Gruppen (z. B. lokale Admins)
            // ignoriert und die Share-Maske ist falsch. Der Access-Context
            // sorgt zusätzlich dafür, dass z. B. `NETWORK` (S-1-5-2) für SMB
            // im Token landet — sonst werden `Deny NETWORK`-ACEs auf der
            // Share ignoriert (Review-Folge-Befund 1).
            // Token set MUST contain the same SIDs as on the NTFS side, otherwise
            // share ACEs on local server groups (e.g. local Administrators) are
            // ignored and the share mask is wrong. The access context further
            // ensures e.g. `NETWORK` (S-1-5-2) is in the SMB token, otherwise
            // `Deny NETWORK` ACEs on the share are ignored (follow-up
            // review finding 1).
            let user_sids = build_token_sids_with_context(
                &resolved.resolution.identity.sid.0,
                &resolved.resolution.memberships,
                local_group_sids,
                access_context,
            );
            // NULL-Share-DACL: effective_share_mask liefert None — als eigener
            // Status `Unrestricted` weitergeben, statt eine kuenstliche Maske
            // 0xFFFFFFFF zu fabrizieren (die in Reports wie eine reale
            // Special-Access-Maske wirken wuerde).
            // NULL share DACL: effective_share_mask returns None — surface as
            // dedicated `Unrestricted` status instead of fabricating a fake
            // 0xFFFFFFFF mask (which would look like a real special-access
            // mask in reports).
            let status = match effective_share_mask(&scan.dacl, &user_sids) {
                Some(mask) => {
                    tracing::info!(server = %server, share = %share, mask = format!("0x{:08X}", mask.0), "Share mask resolved");
                    ShareMaskStatus::Applied(mask)
                }
                None => {
                    tracing::info!(server = %server, share = %share, "Share has NULL DACL — unrestricted");
                    ShareMaskStatus::Unrestricted
                }
            };
            (status, scan.unsupported_count)
        }
    }
}

// ---------------------------------------------------------------------------
// Lokale Server-Gruppen / local server groups
// ---------------------------------------------------------------------------

/// Sammelt die lokalen Gruppen-SIDs des Benutzers auf dem Zielserver der Analyse.
/// Bei UNC-Pfaden wird der Server aus dem Pfad abgeleitet; bei lokalen Pfaden
/// wird der lokale Rechner abgefragt.
/// Ohne aufgeloeste Identitaet (kein AD verbunden) liefert die Funktion eine
/// leere Liste — ein fehlgeschlagener Aufruf bricht die Analyse nicht ab.
///
/// Collects the user's local group SIDs on the analysis target server. For UNC
/// paths the server is derived from the path; for local paths the local machine
/// is queried. Without a resolved identity (no AD) an empty list is returned —
/// a failed call does not abort the analysis.
fn collect_local_group_sids_for_path(
    path: &str,
    explicit_smb_server: Option<&str>,
    identity: &adpa_core::model::Identity,
    domain_memberships: &[adpa_core::model::GroupMembership],
) -> (
    Vec<adpa_core::model::Sid>,
    Vec<adpa_core::model::GroupMembership>,
    adpa_core::model::LocalGroupEvalStatus,
) {
    use adpa_core::model::LocalGroupEvalStatus;

    // Finding 2: lokale Gruppen MÜSSEN vom selben Server kommen wie die
    // Share-DACL. effective_smb_target priorisiert den expliziten
    // `--smb-server` und fällt sonst auf den UNC-Server zurück.
    let server_owned = effective_smb_target(path, explicit_smb_server);
    let server = server_owned.as_deref();
    // Review 2026-06-05 Runde 6 Finding 1: lokale Servergruppen werden
    // jetzt als `GroupMembership` mit
    // `MembershipPathSource::LocalGroup` aufgeloest, damit der
    // Erklaerungspfad jeden Token-Schritt nachvollziehbar darstellt.
    // SIDs werden aus den Memberships extrahiert; bekannte Domain-
    // Gruppen werden als Mediator-Namen mitgegeben.
    // Round 6 finding 1: resolve local server groups as
    // GroupMembership instances so the explanation path renders each
    // mediator step explicitly. SIDs come from the memberships;
    // known domain groups are passed in as mediator labels.
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
            tracing::debug!(
                ?server,
                sid = %identity.sid.0,
                count = sids.len(),
                "Resolved local group chains for target server"
            );
            (sids, memberships, LocalGroupEvalStatus::Applied)
        }
        Err(e) => {
            let msg = e.to_string();
            tracing::warn!(
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
// Risk evaluation and export helpers
// ---------------------------------------------------------------------------

/// Führt die Standard-Risikoregeln über eine Ergebnismenge aus.
/// Runs the default risk rules over a set of results.
fn compute_risk_findings(permissions: &[EffectivePermission]) -> Vec<RiskFinding> {
    RuleRegistry::with_defaults().evaluate_all(&RiskContext {
        findings: permissions.to_vec(),
    })
}

/// Setzt die Overwrite-Policy durch: ohne `--force` wird eine vorhandene
/// Exportdatei nicht überschrieben, sondern als Fehler abgelehnt.
/// Enforces the overwrite policy: without `--force` an existing export file is
/// not overwritten but rejected as an error.
fn check_overwrite_policy(status: &ExportPathStatus, force: bool) -> anyhow::Result<()> {
    if let ExportPathStatus::Exists(p) = status {
        if !force {
            return Err(anyhow::anyhow!(
                "Export file already exists: {}. Pass --force to overwrite it.",
                p.0.display()
            ));
        }
        eprintln!(
            "[Warning] --force: overwriting existing export file: {}",
            p.0.display()
        );
    }
    Ok(())
}

/// Wählt den Exporter anhand der Dateiendung und schreibt den Bericht.
/// Selects the exporter by file extension and writes the report.
///
/// `.html` und `.json` enthalten Risikobefunde; `.csv` enthält nur
/// Berechtigungen — in dem Fall wird ein Hinweis ausgegeben.
/// `.html` and `.json` include risk findings; `.csv` only includes
/// permissions — a note is printed in that case.
fn export_analysis(target_path: &std::path::Path, analysis: &AnalysisResult) -> anyhow::Result<()> {
    let ext = target_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase());
    let target = ExportTarget::File(target_path.to_path_buf());
    match ext.as_deref() {
        Some("html") => HtmlExporter
            .export(analysis, target)
            .map_err(|e| anyhow::anyhow!("HTML export failed: {e}")),
        Some("json") => JsonExporter
            .export(analysis, target)
            .map_err(|e| anyhow::anyhow!("JSON export failed: {e}")),
        _ => {
            if !analysis.risk_findings.is_empty() {
                eprintln!(
                    "[Note] CSV export does not include risk findings — \
                     use a .html target for a readable report or .json for \
                     a full structured report (risks, matched ACEs, \
                     contributing SIDs with nested detail)."
                );
            }
            CsvExporter
                .export(analysis, target)
                .map_err(|e| anyhow::anyhow!("CSV export failed: {e}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Scan output helpers
// ---------------------------------------------------------------------------

const W: usize = 65;
const HEAVY: char = '═';
const LIGHT: char = '─';

fn heavy() -> String {
    HEAVY.to_string().repeat(W)
}
fn light() -> String {
    LIGHT.to_string().repeat(W)
}

fn print_scan_header(
    root: &str,
    resolved: &ResolvedIdentity,
    max_depth: Option<u32>,
    run_id: &Uuid,
    share_mask: Option<&adpa_core::model::AccessMask>,
) {
    println!();
    println!("{}", heavy());
    println!("  AD Permission Analyzer  \u{00B7}  Tree Scan");
    println!("{}", heavy());
    let user_name = resolved
        .resolution
        .identity
        .name
        .as_deref()
        .unwrap_or(&resolved.resolution.identity.sid.0);
    let domain = resolved
        .resolution
        .identity
        .domain
        .as_ref()
        .map(|d| format!("{d}\\"))
        .unwrap_or_default();
    println!(
        "  Identity  : {domain}{user_name}  ({})",
        resolved.resolution.identity.sid.0
    );
    println!("  Root      : {root}");
    println!(
        "  Max depth : {}",
        max_depth.map_or("unlimited".to_owned(), |d| d.to_string())
    );
    if let Some(m) = share_mask {
        let rights = NormalizedRights::new(m.0);
        println!("  Share mask: {} (0x{:08X})", rights.display_name(), m.0);
    }
    println!("  Scan ID   : {run_id}");
    if !resolved.ad_connected {
        println!("  [!] No AD connection — group memberships not resolved.");
    }
    println!();
    println!("  {:14}  Path", "Rights");
    println!("  {}", light().chars().take(W - 2).collect::<String>());
}

fn print_scan_summary(
    total: usize,
    errors: usize,
    unsupported_ace_paths: usize,
    duration_ms: i64,
    db_path: Option<&str>,
    run_id: &Uuid,
) {
    println!();
    println!("  {}", light().chars().take(W - 2).collect::<String>());
    println!("  Paths scanned : {total}");
    println!("  Errors        : {errors}");
    if unsupported_ace_paths > 0 {
        println!(
            "  [!] Unsupported : {unsupported_ace_paths} path(s) had ACE types that could \
             not be evaluated — results may be incomplete."
        );
    }
    println!("  Duration      : {duration_ms} ms");
    if let Some(db) = db_path {
        println!("  Database      : {db}");
        println!("  Scan ID       : {run_id}");
    }
    println!();
    println!("{}", heavy());
    println!();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::check_overwrite_policy;
    use std::path::PathBuf;
    use validation::export_path::{ExportPathStatus, ValidatedExportPath};

    fn validated() -> ValidatedExportPath {
        ValidatedExportPath(PathBuf::from("C:\\reports\\out.csv"))
    }

    #[test]
    fn existing_export_without_force_is_rejected() {
        let status = ExportPathStatus::Exists(validated());
        assert!(
            check_overwrite_policy(&status, false).is_err(),
            "an existing file must not be overwritten without --force"
        );
    }

    #[test]
    fn existing_export_with_force_is_allowed() {
        let status = ExportPathStatus::Exists(validated());
        assert!(check_overwrite_policy(&status, true).is_ok());
    }

    #[test]
    fn new_export_is_allowed_without_force() {
        let status = ExportPathStatus::New(validated());
        assert!(check_overwrite_policy(&status, false).is_ok());
    }

    /// Review 2026-06-04 Runde 3 Finding 2: `validate_connection_inputs`
    /// muss die getrimmten Wrapperwerte zurueckgeben, nicht den Rohstring.
    /// Vorher wurde der Rueckgabewert verworfen und CLI/GUI verarbeiteten
    /// weiter die Roh-Strings — der Test deckt explizit das
    /// Whitespace-Trimming an allen fuenf Eingabefeldern ab.
    /// Review round 3 finding 2: connection-input validation must
    /// propagate the trimmed wrapper values.
    #[test]
    fn validate_connection_inputs_returns_trimmed_normalized_values() {
        let result = super::validate_connection_inputs(
            Some("  dc.example  "),
            Some("  DC=corp,DC=local  "),
            Some("  CN=admin,DC=corp,DC=local  "),
            Some("  fileserver.example  "),
            Some("  data  "),
        )
        .expect("valid whitespace-padded inputs must pass");
        assert_eq!(result.server.as_deref(), Some("dc.example"));
        assert_eq!(result.base_dn.as_deref(), Some("DC=corp,DC=local"));
        assert_eq!(result.bind_dn.as_deref(), Some("CN=admin,DC=corp,DC=local"));
        assert_eq!(result.smb_server.as_deref(), Some("fileserver.example"));
        assert_eq!(result.share_name.as_deref(), Some("data"));
    }

    /// Halbgesetzte SMB-Kombination muss fehlschlagen (Review Runde 2
    /// Finding 2 regression).
    /// Half-set SMB combination must error.
    #[test]
    fn validate_connection_inputs_rejects_half_set_smb_pair() {
        let err =
            super::validate_connection_inputs(None, None, None, Some("fileserver.example"), None)
                .expect_err("--smb-server without --share-name must error");
        assert!(err.to_string().contains("SMB context incomplete"));
    }

    /// Leere String-Eingaben fuer SMB-Felder zaehlen wie nicht gesetzt.
    /// Empty strings for SMB count as unset.
    #[test]
    fn validate_connection_inputs_treats_empty_smb_strings_as_unset() {
        let result = super::validate_connection_inputs(None, None, None, Some("   "), Some(""))
            .expect("empty strings count as unset");
        assert!(result.smb_server.is_none());
        assert!(result.share_name.is_none());
    }
}
