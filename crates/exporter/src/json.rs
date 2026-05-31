//! JSON-Berichtsexport — stabil strukturiertes, maschinenlesbares Ausgabeformat.
//! JSON report export — stable, structured, machine-readable output format.
//!
//! Der Export schreibt ein Top-Level-Objekt mit `version`, `permissions` und
//! `risk_findings`. Die Felder beider Listen entsprechen den `Serialize`-
//! Implementierungen von `EffectivePermission` und `RiskFinding`, sodass
//! Audit-Pipelines Strukturen wie `share_status`, `local_group_status`,
//! `incomplete` und `matched_aces` direkt konsumieren können.
//!
//! Writes a top-level object with `version`, `permissions`, and `risk_findings`.
//! Both lists mirror the `Serialize` implementations of `EffectivePermission`
//! and `RiskFinding`, so audit pipelines can directly consume structures like
//! `share_status`, `local_group_status`, `incomplete`, and `matched_aces`.

use adpa_core::{
    error::CoreError,
    model::{EffectivePermission, RiskFinding},
    traits::{AnalysisResult, ExportTarget, Exporter},
};
use serde::Serialize;

/// Versionsnummer des JSON-Schemas — bei strukturändernden Anpassungen erhöhen.
/// Version number of the JSON schema — bump it on structural changes.
const JSON_SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct JsonReport<'a> {
    version: u32,
    permissions: &'a [EffectivePermission],
    risk_findings: &'a [RiskFinding],
}

pub struct JsonExporter;

impl Exporter for JsonExporter {
    fn export(&self, result: &AnalysisResult, target: ExportTarget) -> Result<(), CoreError> {
        let report = JsonReport {
            version: JSON_SCHEMA_VERSION,
            permissions: &result.permissions,
            risk_findings: &result.risk_findings,
        };
        match target {
            ExportTarget::File(path) => {
                let file = std::fs::File::create(&path).map_err(|e| {
                    CoreError::Export(format!("Cannot create JSON file {}: {e}", path.display()))
                })?;
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
}
