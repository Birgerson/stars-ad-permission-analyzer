// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! JSON-Berichtsexport — stabil strukturiertes, maschinenlesbares Ausgabeformat.
//! JSON report export — stable, structured, machine-readable output format.
//!
//! Der Export schreibt ein Top-Level-Objekt mit `version`, `permissions`,
//! `risk_findings` und `path_trustees`. Die Felder beider Identitaets-
//! orientierten Listen entsprechen den `Serialize`-Implementierungen von
//! `EffectivePermission` und `RiskFinding`, sodass Audit-Pipelines
//! Strukturen wie `share_status`, `local_group_status`, `incomplete` und
//! `matched_aces` direkt konsumieren koennen. Die pfad-orientierte
//! Trustee-Liste (`path_trustees`) wurde in Round-8-Folgereview Finding 2
//! ergaenzt, damit die zweite Audit-Frage „wer hat ueberhaupt Zugriff?"
//! auch im maschinenlesbaren Format vorhanden ist.
//!
//! Writes a top-level object with `version`, `permissions`,
//! `risk_findings`, and `path_trustees`. Both identity-oriented lists
//! mirror the `Serialize` implementations of `EffectivePermission` and
//! `RiskFinding`, so audit pipelines can directly consume structures
//! like `share_status`, `local_group_status`, `incomplete`, and
//! `matched_aces`. The path-oriented `path_trustees` list was added in
//! round-8 follow-up finding 2 so the second audit question "who has any
//! access?" is also available in the machine-readable format.

use adpa_core::{
    error::CoreError,
    model::{EffectivePermission, PathTrustees, RiskFinding},
    traits::{AnalysisResult, ExportTarget, Exporter},
};
use serde::Serialize;

/// Versionsnummer des JSON-Schemas — bei strukturändernden Anpassungen erhöhen.
/// Auf 2 erhoeht in Round-8-Folgereview Finding 2 (neues Feld `path_trustees`).
/// Version number of the JSON schema — bump it on structural changes.
/// Raised to 2 in round-8 follow-up finding 2 (new `path_trustees` field).
pub const JSON_SCHEMA_VERSION: u32 = 2;

#[derive(Serialize)]
struct JsonReport<'a> {
    version: u32,
    permissions: &'a [EffectivePermission],
    risk_findings: &'a [RiskFinding],
    path_trustees: &'a [PathTrustees],
}

pub struct JsonExporter;

impl Exporter for JsonExporter {
    fn export(&self, result: &AnalysisResult, target: ExportTarget) -> Result<(), CoreError> {
        let report = JsonReport {
            version: JSON_SCHEMA_VERSION,
            permissions: &result.permissions,
            risk_findings: &result.risk_findings,
            path_trustees: &result.path_trustees,
        };
        let file = crate::open_export_file(target)?;
        let mut writer = std::io::BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, &report)
            .map_err(|e| CoreError::Export(format!("JSON serialization failed: {e}")))?;
        use std::io::Write;
        writer
            .flush()
            .map_err(|e| CoreError::Export(format!("JSON flush failed: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adpa_core::{
        model::{
            AccessMask, Identity, IdentityKind, LocalGroupEvalStatus, NormalizedPath,
            PermissionPath, RiskSeverity, ShareEvalStatus, Sid,
        },
        traits::AnalysisResult,
    };

    fn sample_permission(incomplete_share: bool) -> EffectivePermission {
        EffectivePermission {
            identity: Identity {
                sid: Sid("S-1-5-21-1-2-3-1000".to_owned()),
                name: Some("max.mustermann".to_owned()),
                domain: Some("testdomain.local".to_owned()),
                kind: IdentityKind::User,
                disabled: false,
                user_principal_name: Some("max.mustermann@testdomain.local".to_owned()),
            },
            path: NormalizedPath("C:\\Data".to_owned()),
            ntfs_mask: AccessMask(0x0012_0089),
            share_mask: None,
            effective_mask: AccessMask(0x0012_0089),
            path_explanation: PermissionPath {
                steps: vec!["User -> ACL".to_owned()],
            },
            share_status: if incomplete_share {
                ShareEvalStatus::ReadFailed("access denied".to_owned())
            } else {
                ShareEvalStatus::NotApplicable
            },
            local_group_status: LocalGroupEvalStatus::Applied,
            contributing_sids: vec![],
            unsupported_ace_count: 0,
            matched_aces: vec![],
            diagnostics: vec![],
        }
    }

    fn sample_finding(incomplete: bool) -> RiskFinding {
        RiskFinding {
            rule_id: "WRITE_ACCESS".to_owned(),
            severity: RiskSeverity::High,
            description: "test finding".to_owned(),
            affected_path: Some(NormalizedPath("C:\\Data".to_owned())),
            affected_identity: Some(Sid("S-1-5-21-1-2-3-1000".to_owned())),
            incomplete,
        }
    }

    fn render(result: &AnalysisResult) -> String {
        let dir = tempdir();
        let path = dir.join("report.json");
        JsonExporter
            .export(result, ExportTarget::File(path.clone()))
            .expect("export must succeed");
        std::fs::read_to_string(&path).expect("read written file")
    }

    fn tempdir() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("adpa_json_test_{}", uuid_like()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn uuid_like() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        format!(
            "{}_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::process::id()
        )
    }

    #[test]
    fn export_contains_version_and_lists() {
        let result = AnalysisResult {
            permissions: vec![sample_permission(false)],
            risk_findings: vec![sample_finding(false)],
            ..Default::default()
        };
        let body = render(&result);
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["version"], JSON_SCHEMA_VERSION);
        assert!(parsed["permissions"].is_array());
        assert!(parsed["risk_findings"].is_array());
    }

    #[test]
    fn export_includes_share_status_and_incomplete_marker() {
        let result = AnalysisResult {
            permissions: vec![sample_permission(true)],
            risk_findings: vec![sample_finding(true)],
            ..Default::default()
        };
        let body = render(&result);
        // share_status muss als strukturiertes Feld auftauchen, nicht nur als Maske.
        // share_status must appear as a structured field, not only as a mask.
        assert!(
            body.contains("\"share_status\""),
            "share_status missing in JSON: {body}"
        );
        assert!(
            body.contains("ReadFailed"),
            "ReadFailed variant missing in JSON: {body}"
        );
        // local_group_status ebenfalls strukturiert.
        // local_group_status structured too.
        assert!(
            body.contains("\"local_group_status\""),
            "local_group_status missing in JSON: {body}"
        );
        // incomplete=true muss erscheinen, sonst sind Audit-Pipelines blind.
        // incomplete=true must appear, otherwise audit pipelines are blind.
        assert!(
            body.contains("\"incomplete\": true"),
            "incomplete=true must be present in JSON: {body}"
        );
    }

    #[test]
    fn export_to_missing_directory_returns_export_error() {
        let result = AnalysisResult {
            permissions: vec![],
            risk_findings: vec![],
            ..Default::default()
        };
        let path = std::path::PathBuf::from(r"C:\definitely\not\an\existing\dir\report.json");
        let err = JsonExporter
            .export(&result, ExportTarget::File(path))
            .expect_err("must fail when parent dir is missing");
        assert!(
            matches!(err, CoreError::Export(_)),
            "expected CoreError::Export, got {err:?}"
        );
    }

    /// Round-8-Folgereview Finding 2: das JSON-Schema enthaelt jetzt eine
    /// `path_trustees`-Liste und die Schema-Version steht auf 2.
    /// Round-8 follow-up finding 2: the JSON schema now contains a
    /// `path_trustees` list and the schema version is bumped to 2.
    #[test]
    fn export_includes_path_trustees_and_bumped_schema_version() {
        use adpa_core::model::{AceKind, PathTrustee, PathTrustees, TrusteeCategory};
        let result = AnalysisResult {
            permissions: vec![],
            risk_findings: vec![],
            path_trustees: vec![PathTrustees {
                path: NormalizedPath(r"C:\Audit".to_owned()),
                trustees: vec![PathTrustee {
                    sid: Sid("S-1-5-32-544".to_owned()),
                    display_name: Some("BUILTIN\\Administrators".to_owned()),
                    kind: AceKind::Allow,
                    mask: AccessMask(0x001F_01FF),
                    inherited: true,
                    inheritance_flags: 0,
                    propagation_flags: 0,
                    category: TrusteeCategory::Ntfs,
                }],
            }],
        };
        let body = render(&result);
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(
            parsed["version"], 2,
            "schema version must be bumped to 2 for path_trustees field"
        );
        let trustees = parsed["path_trustees"]
            .as_array()
            .expect("path_trustees must be an array");
        assert_eq!(trustees.len(), 1, "one path-trustee entry expected");
        assert_eq!(trustees[0]["path"], r"C:\Audit");
        assert_eq!(
            trustees[0]["trustees"][0]["sid"], "S-1-5-32-544",
            "trustee SID must propagate into JSON"
        );
        assert_eq!(
            trustees[0]["trustees"][0]["display_name"], "BUILTIN\\Administrators",
            "trustee display_name must propagate"
        );
    }

    /// Round-8-Folgereview Finding 1: der JSON-Exporter darf eine
    /// existierende Zieldatei NICHT mehr ueberschreiben, wenn
    /// `ExportTarget::File` genutzt wird. Mit `ExportTarget::FileOverwrite`
    /// ist Ueberschreiben explizit erlaubt.
    /// Round-8 follow-up finding 1: the JSON exporter must NOT overwrite an
    /// existing target file when called with `ExportTarget::File`. With
    /// `ExportTarget::FileOverwrite` overwriting is explicitly allowed.
    #[test]
    fn export_refuses_overwrite_unless_explicitly_allowed() {
        let dir = tempdir();
        let path = dir.join("report.json");
        let sentinel = b"sentinel\n";
        std::fs::write(&path, sentinel).expect("write sentinel");

        // Default-Branch muss ablehnen und Sentinel intakt lassen.
        let result = AnalysisResult::default();
        let refusal = JsonExporter
            .export(&result, ExportTarget::File(path.clone()))
            .expect_err("File branch must refuse to overwrite an existing file");
        assert!(
            matches!(refusal, CoreError::Export(_)),
            "expected CoreError::Export refusal, got {refusal:?}"
        );
        let after_refusal = std::fs::read(&path).expect("read sentinel after refusal");
        assert_eq!(
            after_refusal, sentinel,
            "pre-existing file content must stay intact when overwrite refused"
        );

        // Mit FileOverwrite darf die Datei truncatet werden.
        JsonExporter
            .export(&result, ExportTarget::FileOverwrite(path.clone()))
            .expect("FileOverwrite branch must succeed");
        let after_overwrite =
            std::fs::read_to_string(&path).expect("read written file after overwrite");
        assert!(
            after_overwrite.contains("\"version\""),
            "FileOverwrite must replace sentinel content with a JSON report"
        );
    }
}
