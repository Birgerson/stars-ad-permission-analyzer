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
        /// in an upcoming release.
        /// **DEPRECATED — insecure.** Visible in process listings and shell
        /// history. Use the `ADPA_BIND_PASSWORD` environment variable
        /// instead. Kept for backwards compatibility; will be removed in
        /// a future release.
        #[arg(long)]
        bind_password: Option<String>,
        /// Unencrypted LDAP (port 389) — password in plaintext. Test environments only.
        #[arg(long)]
        insecure_ldap: bool,
        /// Optional CSV export path
        #[arg(short = 'o', long)]
        output: Option<String>,
        /// SMB server for share permissions (auto-detected for UNC paths)
        #[arg(long)]
        smb_server: Option<String>,
        /// Share name for NTFS ∩ Share combination (auto-detected for UNC paths)
        #[arg(long)]
        share_name: Option<String>,
        /// Overwrite an existing export file without confirmation.
        #[arg(long)]
        force: bool,
    },

    /// Recursively scan a directory tree and store results in the database.
    Scan {
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
        /// in an upcoming release.
        /// **DEPRECATED — insecure.** Visible in process listings and shell
        /// history. Use the `ADPA_BIND_PASSWORD` environment variable
        /// instead. Kept for backwards compatibility; will be removed in
        /// a future release.
        #[arg(long)]
        bind_password: Option<String>,
        /// Unencrypted LDAP (port 389) — password in plaintext. Test environments only.
        #[arg(long)]
        insecure_ldap: bool,
        /// SQLite database file for results (created if absent)
        #[arg(long)]
        db: Option<String>,
        #[arg(long)]
        max_depth: Option<u32>,
        /// Optional CSV export path
        #[arg(short = 'o', long)]
        output: Option<String>,
        /// SMB server for share permissions (auto-detected for UNC paths)
        #[arg(long)]
        smb_server: Option<String>,
        /// Share name for NTFS ∩ Share combination (auto-detected for UNC paths)
        #[arg(long)]
        share_name: Option<String>,
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

/// zusammengeschusterten Tupel-Struktur.
/// CLI-local bundle: [`PrincipalResolution`] + the `ad_connected`
/// flag.
struct ResolvedIdentity {
    resolution: PrincipalResolution,
    ad_connected: bool,
}

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

        // Review 2026-06-04 round 3 finding 1.
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
        // `PrincipalResolution` with correctly classified ScopeStatus.
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
                // SAM-only on a DC = local domain → Inside; the
                // flat-recursion incompleteness is signalled separately
                // via SamFlat → DomainGroupRecursionIncomplete.
                scope_status: IdentityScopeStatus::InsideConfiguredLdapBase,
                group_resolution_status: GroupResolutionStatus::SamFlat,
                disabled_status,
                diagnostics,
                resolved_via_fsp: false,
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

    // Review 2026-06-04 round 2, finding 6: from here on we forward the
    // rejected empty paths, trimmed whitespace and canonicalised long-
    // path forms — downstream code must see exactly that form.
    let path = validate_path(&path)
        .map_err(|e| anyhow::anyhow!("Invalid path: {e}"))?
        .0;
    // Review 2026-06-04 round 3 finding 2 + round 4 Finding 2:
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

    // derived — single source of truth (Review round 3 finding 1).
    // Engine flags are derived centrally from the resolution status.
    // Review 2026-06-05 round 6 finding 1: AD memberships +
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
        identity_resolved_via_fsp: engine_flags.identity_resolved_via_fsp,
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

    // Run the risk rules in the CLI path too — otherwise the report looks incomplete.
    let risk_findings = compute_risk_findings(std::slice::from_ref(&result));
    output::print_risk_findings(&risk_findings);

    if let Some(out_path) = output {
        let status = validate_export_path(&out_path)
            .map_err(|e| anyhow::anyhow!("Invalid export path: {e}"))?;
        check_overwrite_policy(&status, force)?;
        // pfadzentrische Trustee-Liste mitliefern.
        // Round-9 finding 1: CLI exports must carry the path-centric
        // trustee list.
        // Round-10 finding 1: server/share derivation now goes through
        // `SmbAuditContext::resolve` — the same source that
        // `resolve_scan_share_status` uses. The trustee list now sees
        // the share layer even on a bare UNC call without
        // `--smb-server`/`--share-name`, instead of silently dropping
        // it.
        let smb_context = validation::path::SmbAuditContext::resolve(
            &path,
            smb_server.as_deref(),
            share_name.as_deref(),
        );
        let trustees = exporter::build_path_trustees(
            &fso,
            smb_context.as_ref().map(|c| c.server.as_str()),
            smb_context.as_ref().map(|c| c.share.as_str()),
        );
        let analysis = AnalysisResult {
            permissions: vec![result.clone()],
            risk_findings: risk_findings.clone(),
            path_trustees: vec![adpa_core::model::PathTrustees {
                path: fso.path.clone(),
                trustees,
            }],
        };
        export_analysis(&status.path().0, &analysis, force)?;
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

    // Review 2026-06-04 round 2, finding 6: propagate the normalized form.
    // Review 2026-06-04 round 2, finding 6: propagate the normal form.
    let path = validate_path(&path)
        .map_err(|e| anyhow::anyhow!("Invalid path: {e}"))?
        .0;
    // AGENTS.md DoD 11: validate numeric inputs centrally before they reach
    // WalkConfig — otherwise --max-depth=4_000_000_000 would let the walker
    // run until RAM exhaustion.
    let max_depth = validate_optional_scan_depth(max_depth)
        .map_err(|e| anyhow::anyhow!("Invalid --max-depth: {e}"))?
        .map(|d| d.0);
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

    let resolved = resolve_identity(
        &user,
        server,
        base_dn,
        bind_dn,
        bind_password,
        insecure_ldap,
    )
    .await?;

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

    //     Resolve local server groups before the share mask — otherwise the local
    //     group SIDs are missing from the token evaluated against the share DACL.
    let (scan_local_group_sids, scan_local_group_memberships, scan_local_group_status) =
        collect_local_group_sids_for_path(
            &path,
            smb_server.as_deref(),
            &resolved.resolution.identity,
            &resolved.resolution.memberships,
        );

    // Combine AD + local memberships for the engine (see Analyze).
    let mut scan_all_memberships = resolved.resolution.memberships.clone();
    scan_all_memberships.extend(scan_local_group_memberships.iter().cloned());

    if let adpa_core::model::LocalGroupEvalStatus::NotAvailable(ref msg) = scan_local_group_status {
        println!(
            "[Warning] Local server groups could not be resolved — scan results are incomplete (token may miss local-group SIDs). ({msg})"
        );
    }

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
        // The walk is blocking — run it on a blocking thread so the Ctrl-C handler
        // can still react.
        tokio::task::spawn_blocking(move || walk_tree(&scan_path, &config, &cancel))
            .await
            .map_err(|e| anyhow::anyhow!("Scan task failed: {e}"))?
    };

    let mut all_permissions = Vec::with_capacity(walk.objects.len());
    let mut all_path_trustees: Vec<adpa_core::model::PathTrustees> =
        Vec::with_capacity(walk.objects.len());
    let mut unsupported_ace_paths = 0usize;

    // build_path_trustees_with_share dieselbe Share-DACL anhaengt ohne
    // Round-9 finding 1: read the share overlay once per scan (like the
    // GUI does since ADR 0038) so every build_path_trustees_with_share
    // call appends the same share DACL without re-reading it per path.
    // Round-10 finding 1: server/share derivation now comes from
    // `SmbAuditContext::resolve` — the same source the CLI analyze
    // trustees and the `resolve_scan_share_status` helper use. A bare
    // `\\fs01\data` without explicit flags now behaves consistently:
    // all three trustee/status paths see the share layer.
    // On non-Windows `read_share_overlay` is not callable — the CI
    // build keeps the overlay None there.
    let scan_smb_context = validation::path::SmbAuditContext::resolve(
        &path,
        smb_server.as_deref(),
        share_name.as_deref(),
    );
    #[cfg(windows)]
    let scan_share_overlay = scan_smb_context
        .as_ref()
        .map(|ctx| exporter::read_share_overlay(&ctx.server, &ctx.share));
    #[cfg(not(windows))]
    let scan_share_overlay: Option<exporter::ShareTrusteeOverlay> = {
        let _ = &scan_smb_context;
        None
    };
    // scan_local_group_sids was already resolved above (before the share mask).
    // scan_access_context was likewise derived above before the share mask.

    //
    //
    // Build the SID→name table once for the whole scan. Trustee SIDs
    // repeat across many paths (BUILTIN\Administrators,
    // Authenticated Users, …), so we collect the unique SIDs from every
    // DACL up front and perform one LSA lookup per SID instead of per
    // path. Memberships are scan-wide constant anyway.
    //
    // (previously NTFS DACL only) AND is additionally handed to the
    // trustee build function so `build_path_trustees_*` no longer makes
    // per-path LSA calls.
    #[cfg(windows)]
    let scan_sid_names = {
        use std::collections::HashSet;
        let mut seen: HashSet<String> = HashSet::new();
        let mut trustees: Vec<String> = Vec::new();
        for fso in &walk.objects {
            for sid in exporter::collect_ace_sids_for_resolution(fso, scan_share_overlay.as_ref()) {
                if seen.insert(sid.clone()) {
                    trustees.push(sid);
                }
            }
        }
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
            identity_resolved_via_fsp: scan_engine_flags.identity_resolved_via_fsp,
        };
        let result = DefaultPermissionEngine.evaluate(input).map_err(|e| {
            anyhow::anyhow!("Permission evaluation failed for '{}': {e}", fso.path.0)
        })?;

        // angefragt.
        // Round-9 finding 1: collect trustees per path — identical to
        // the GUI since ADR 0038. The share overlay was read once and
        // is only referenced here.
        // Round-10 finding 2: hand the scan-wide SID→name map so the
        // trustee build function does NOT make per-path LSA calls.
        let trustees = exporter::build_path_trustees_with_share_and_names(
            fso,
            scan_share_overlay.as_ref(),
            &scan_sid_names,
        );
        all_path_trustees.push(adpa_core::model::PathTrustees {
            path: fso.path.clone(),
            trustees,
        });

        let rights = NormalizedRights::new(result.effective_mask.0);
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
            path_trustees: all_path_trustees,
        };
        export_analysis(&status.path().0, &analysis, force)?;
        println!("  Results exported to: {out_path}");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Share-mask helpers
// ---------------------------------------------------------------------------

// UNC parsing now lives centrally in validation::path::parse_unc_components.
// The old CLI-local variant accepted local paths as UNC (review finding 1) and
// mis-split long-path UNC (review finding 4).
use validation::path::effective_smb_target;

/// Collects all SIDs for the user (own + group SIDs).
/// Resolves the share status for scan and analyze commands.
///
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
    // Round-10 finding 1: server/share derivation goes through
    // `SmbAuditContext::resolve` — the same source the trustee overlay
    // build in analyze/scan and the GUI use. Effective share mask AND
    // trustee table now share the exact same server/share.
    let smb_ctx = match validation::path::SmbAuditContext::resolve(path, smb_server, share_name) {
        Some(c) => c,
        None => return (ShareMaskStatus::NotApplicable, 0),
    };
    let server = smb_ctx.server;
    let share = smb_ctx.share;

    tracing::info!(server = %server, share = %share, "Resolving share mask");

    match get_share_dacl(&server, &share) {
        Err(e) => {
            tracing::warn!(server = %server, share = %share, error = %e, "Cannot read share DACL");
            (ShareMaskStatus::ReadFailed(e.to_string()), 0)
        }
        Ok(scan) => {
            // Share ignored (review follow-up finding 1).
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
            // NULL share DACL: effective_share_mask returns None — handled as its own
            // Status `Unrestricted` weitergeben, statt eine kuenstliche Maske
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
// ---------------------------------------------------------------------------

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

    let server_owned = effective_smb_target(path, explicit_smb_server);
    let server = server_owned.as_deref();
    // Erklaerungspfad jeden Token-Schritt nachvollziehbar darstellt.
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

/// Runs the default risk rules over a set of results.
fn compute_risk_findings(permissions: &[EffectivePermission]) -> Vec<RiskFinding> {
    RuleRegistry::with_defaults().evaluate_all(&RiskContext {
        findings: permissions.to_vec(),
    })
}

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

/// Selects the exporter by file extension and writes the report.
///
/// `.html` and `.json` include risk findings; `.csv` only includes
/// permissions — a note is printed in that case.
fn export_analysis(
    target_path: &std::path::Path,
    analysis: &AnalysisResult,
    force: bool,
) -> anyhow::Result<()> {
    let ext = target_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase());
    // CLI-Vorabpruefung in check_overwrite_policy).
    // Round-8 follow-up finding 1: pick the exporter's explicit
    // overwrite branch only when --force is set. Without --force the
    // trait itself refuses an existing file (defence in depth on top of
    // the CLI's check_overwrite_policy).
    let target = if force {
        ExportTarget::FileOverwrite(target_path.to_path_buf())
    } else {
        ExportTarget::File(target_path.to_path_buf())
    };
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

    /// Review 2026-06-04 round 3 finding 2: `validate_connection_inputs`
    /// Whitespace-Trimming an allen fuenf Eingabefeldern ab.
    /// Review round 3 finding 2: connection-input validation must
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

    /// Finding 2 regression).
    /// Half-set SMB combination must error.
    #[test]
    fn validate_connection_inputs_rejects_half_set_smb_pair() {
        let err =
            super::validate_connection_inputs(None, None, None, Some("fileserver.example"), None)
                .expect_err("--smb-server without --share-name must error");
        assert!(err.to_string().contains("SMB context incomplete"));
    }

    /// Empty strings for SMB count as unset.
    #[test]
    fn validate_connection_inputs_treats_empty_smb_strings_as_unset() {
        let result = super::validate_connection_inputs(None, None, None, Some("   "), Some(""))
            .expect("empty strings count as unset");
        assert!(result.smb_server.is_none());
        assert!(result.share_name.is_none());
    }
}
