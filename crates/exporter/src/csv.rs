// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! CSV export for EffectivePermission results.

use std::io::Write;

use adpa_core::{
    error::CoreError,
    model::{EffectivePermission, LocalGroupEvalStatus, ShareEvalStatus},
    traits::{AnalysisResult, ExportTarget, Exporter},
};
use permission_engine::NormalizedRights;

const HEADERS: &[&str] = &[
    "path",
    "user_sid",
    "user_name",
    "user_domain",
    "identity_kind",
    "disabled",
    "ntfs_mask_hex",
    "ntfs_rights",
    "share_mask_hex",
    "share_rights",
    "effective_mask_hex",
    "effective_rights",
    "explanation",
    // Diagnostic: count of unevaluated ACE types on this path (0 = complete).
    "unsupported_aces",
    // Share evaluation status: not_applicable / applied / unrestricted / read_failed:<reason>.
    "share_status",
    // Local group resolution status — flags the result as incomplete when
    // the target server could not be queried.
    "local_group_status",
    // Reason when local_group_status = not_available (otherwise empty).
    "local_group_error",
    // vollen JSON-Export nutzen wollen.
    // Compact JSON list of all ACEs matching the token (sid, kind, mask,
    // inherited). For structured audit pipelines that don't want the
    // full JSON export.
    "matched_aces_json",
    // Compact JSON list of ACEs that actually contributed to the NTFS
    // result (sid, contributed mask).
    "contributing_sids_json",
    // Structured diagnostic markers (follow-up finding 3) — e.g.
    // Structured diagnostic markers (follow-up finding 3) — e.g.
    // {"kind":"NonCanonicalDaclOrder","at_index":N}. Empty list: "[]".
    "diagnostics_json",
];

pub struct CsvExporter;

impl Exporter for CsvExporter {
    fn export(&self, result: &AnalysisResult, target: ExportTarget) -> Result<(), CoreError> {
        let file = crate::open_export_file(target)?;
        write_csv(file, &result.permissions)
            .map_err(|e| CoreError::Export(format!("CSV write error: {e}")))
    }
}

/// Writes permission results as CSV to any writer.
///
/// Fields are comma-separated; fields containing special characters are automatically
/// quoted (handled by the `csv` crate).
pub fn write_csv<W: Write>(writer: W, permissions: &[EffectivePermission]) -> csv::Result<()> {
    let mut wtr = csv::Writer::from_writer(writer);
    wtr.write_record(HEADERS)?;
    for perm in permissions {
        wtr.write_record(record_for(perm))?;
    }
    wtr.flush()?;
    Ok(())
}

fn record_for(p: &EffectivePermission) -> [String; 20] {
    let kind = format!("{:?}", p.identity.kind);
    let ntfs = NormalizedRights::new(p.ntfs_mask.0);
    let (share_hex, share_label) = match p.share_mask {
        Some(m) => (
            format!("0x{:08X}", m.0),
            NormalizedRights::new(m.0).display_name().to_owned(),
        ),
        None => ("(none)".to_owned(), "(none)".to_owned()),
    };
    let eff = NormalizedRights::new(p.effective_mask.0);
    let explanation = p.path_explanation.steps.join(" | ");
    let (lg_status, lg_error) = local_group_status_fields(&p.local_group_status);
    let matched_aces_json = matched_aces_to_json(&p.matched_aces);
    let contributing_sids_json = contributing_sids_to_json(&p.contributing_sids);
    let diagnostics_json =
        serde_json::to_string(&p.diagnostics).unwrap_or_else(|_| "[]".to_owned());
    [
        p.path.0.clone(),
        p.identity.sid.0.clone(),
        p.identity.name.clone().unwrap_or_default(),
        p.identity.domain.clone().unwrap_or_default(),
        kind,
        p.identity.disabled.to_string(),
        format!("0x{:08X}", p.ntfs_mask.0),
        ntfs.display_name().to_owned(),
        share_hex,
        share_label,
        format!("0x{:08X}", p.effective_mask.0),
        eff.display_name().to_owned(),
        explanation,
        p.unsupported_ace_count.to_string(),
        share_status_label(&p.share_status),
        lg_status,
        lg_error,
        matched_aces_json,
        contributing_sids_json,
        diagnostics_json,
    ]
}

/// Machine-readable label for the share_status CSV column.
fn share_status_label(status: &ShareEvalStatus) -> String {
    match status {
        ShareEvalStatus::NotApplicable => "not_applicable".to_owned(),
        ShareEvalStatus::Applied => "applied".to_owned(),
        ShareEvalStatus::Unrestricted => "unrestricted".to_owned(),
        ShareEvalStatus::ReadFailed(reason) => format!("read_failed:{reason}"),
    }
}

/// kontaminiert (wie z. B. bei `read_failed:<lange Meldung>`).
/// Splits `LocalGroupEvalStatus` into two CSV columns: status label and
/// error text (empty when no error). Keeps the status grep-/Excel-filter
/// friendly without the error text contaminating the status field.
fn local_group_status_fields(status: &LocalGroupEvalStatus) -> (String, String) {
    match status {
        LocalGroupEvalStatus::NotQueried => ("not_queried".to_owned(), String::new()),
        LocalGroupEvalStatus::Applied => ("applied".to_owned(), String::new()),
        LocalGroupEvalStatus::NotAvailable(reason) => ("not_available".to_owned(), reason.clone()),
    }
}

/// Serializes `matched_aces` as a compact JSON array. Audit pipelines
/// needing structured access to the matched ACEs can parse this field
/// directly — for the full detail tree use the JSON exporter.
fn matched_aces_to_json(aces: &[adpa_core::model::AceEntry]) -> String {
    #[derive(serde::Serialize)]
    struct Compact<'a> {
        sid: &'a str,
        kind: &'a str,
        mask: String,
        inherited: bool,
    }
    let compact: Vec<Compact<'_>> = aces
        .iter()
        .map(|a| Compact {
            sid: a.sid.0.as_str(),
            kind: match a.kind {
                adpa_core::model::AceKind::Allow => "Allow",
                adpa_core::model::AceKind::Deny => "Deny",
            },
            mask: format!("0x{:08X}", a.mask.0),
            inherited: a.inherited,
        })
        .collect();
    serde_json::to_string(&compact).unwrap_or_else(|_| "[]".to_owned())
}

/// Serializes `contributing_sids` as a compact JSON array. Per SID it
/// contains only the bits that actually contributed to the NTFS result.
fn contributing_sids_to_json(sids: &[adpa_core::model::ContributingAce]) -> String {
    #[derive(serde::Serialize)]
    struct Compact<'a> {
        sid: &'a str,
        mask: String,
    }
    let compact: Vec<Compact<'_>> = sids
        .iter()
        .map(|c| Compact {
            sid: c.sid.0.as_str(),
            mask: format!("0x{:08X}", c.mask.0),
        })
        .collect();
    serde_json::to_string(&compact).unwrap_or_else(|_| "[]".to_owned())
}

#[cfg(test)]
mod tests {
    use adpa_core::error::CoreError;
    use adpa_core::model::{
        AccessMask, EffectivePermission, Identity, IdentityKind, NormalizedPath, PermissionPath,
        Sid,
    };
    use adpa_core::traits::{AnalysisResult, ExportTarget};
    use permission_engine::mask::MASK_READ;

    use super::{write_csv, CsvExporter};
    use adpa_core::traits::Exporter;

    fn make_perm(
        path: &str,
        sid: &str,
        name: &str,
        ntfs: u32,
        share: Option<u32>,
        effective: u32,
        steps: Vec<&str>,
    ) -> EffectivePermission {
        EffectivePermission {
            identity: Identity {
                sid: Sid(sid.to_owned()),
                name: if name.is_empty() {
                    None
                } else {
                    Some(name.to_owned())
                },
                domain: Some("TESTDOMAIN".to_owned()),
                kind: IdentityKind::User,
                disabled: false,
                user_principal_name: None,
            },
            path: NormalizedPath(path.to_owned()),
            ntfs_mask: AccessMask(ntfs),
            share_mask: share.map(AccessMask),
            effective_mask: AccessMask(effective),
            path_explanation: PermissionPath {
                steps: steps.iter().map(|s| s.to_string()).collect(),
            },
            share_status: adpa_core::model::ShareEvalStatus::NotApplicable,
            local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
            contributing_sids: vec![],
            unsupported_ace_count: 0,
            matched_aces: vec![],
            diagnostics: vec![],
        }
    }

    fn parse_csv(bytes: &[u8]) -> Vec<Vec<String>> {
        let mut rdr = csv::Reader::from_reader(bytes);
        let headers: Vec<String> = rdr.headers().unwrap().iter().map(str::to_owned).collect();
        let mut rows = vec![headers];
        for record in rdr.records() {
            rows.push(record.unwrap().iter().map(str::to_owned).collect());
        }
        rows
    }

    #[test]
    fn headers_match_expected() {
        let mut buf = Vec::new();
        write_csv(&mut buf, &[]).unwrap();
        let rows = parse_csv(&buf);
        assert_eq!(rows.len(), 1, "only header row for empty input");
        assert_eq!(rows[0][0], "path");
        assert_eq!(rows[0][1], "user_sid");
        assert_eq!(rows[0].len(), 20);
        assert_eq!(rows[0][13], "unsupported_aces");
        assert_eq!(rows[0][14], "share_status");
        // Finding 9: diagnostic + audit columns.
        assert_eq!(rows[0][15], "local_group_status");
        assert_eq!(rows[0][16], "local_group_error");
        assert_eq!(rows[0][17], "matched_aces_json");
        assert_eq!(rows[0][18], "contributing_sids_json");
        // Follow-up finding 3: structured diagnostic markers.
        // Follow-up finding 3: structured diagnostic markers.
        assert_eq!(rows[0][19], "diagnostics_json");
    }

    #[test]
    fn share_status_read_failed_appears_in_csv() {
        let mut perm = make_perm(
            "C:\\Share",
            "S-1-5-21-1-2-3-1000",
            "User",
            MASK_READ,
            None,
            MASK_READ,
            vec![],
        );
        perm.share_status =
            adpa_core::model::ShareEvalStatus::ReadFailed("access denied (5)".to_owned());
        let mut buf = Vec::new();
        write_csv(&mut buf, &[perm]).unwrap();
        let rows = parse_csv(&buf);
        assert!(
            rows[1][14].starts_with("read_failed:"),
            "share_status must surface ReadFailed; got '{}'",
            rows[1][14]
        );
    }

    #[test]
    fn unsupported_ace_count_written_to_csv() {
        let mut perm = make_perm(
            "C:\\Share\\Folder",
            "S-1-5-21-1-2-3-1000",
            "User",
            MASK_READ,
            None,
            MASK_READ,
            vec![],
        );
        perm.unsupported_ace_count = 2;
        let mut buf = Vec::new();
        write_csv(&mut buf, &[perm]).unwrap();
        let rows = parse_csv(&buf);
        assert_eq!(rows[1][13], "2", "unsupported ACE count must appear in CSV");
    }

    #[test]
    fn single_permission_produces_data_row() {
        let perm = make_perm(
            "C:\\Share\\Folder",
            "S-1-5-21-1-2-3-1000",
            "MaxMustermann",
            MASK_READ,
            None,
            MASK_READ,
            vec!["User has Read via inherited Allow ACE"],
        );
        let mut buf = Vec::new();
        write_csv(&mut buf, &[perm]).unwrap();
        let rows = parse_csv(&buf);
        assert_eq!(rows.len(), 2);
        let row = &rows[1];
        assert_eq!(row[0], "C:\\Share\\Folder");
        assert_eq!(row[1], "S-1-5-21-1-2-3-1000");
        assert_eq!(row[2], "MaxMustermann");
        assert_eq!(row[3], "TESTDOMAIN");
        assert_eq!(row[4], "User");
        assert_eq!(row[5], "false");
        assert_eq!(row[7], "Read");
        assert_eq!(row[8], "(none)");
        assert_eq!(row[9], "(none)");
        assert_eq!(row[11], "Read");
        assert_eq!(row[12], "User has Read via inherited Allow ACE");
    }

    #[test]
    fn share_mask_written_when_present() {
        use permission_engine::mask::MASK_FULL_CONTROL;
        let perm = make_perm(
            "C:\\Share",
            "S-1-5-21-1-2-3-1000",
            "User",
            MASK_FULL_CONTROL,
            Some(MASK_READ),
            MASK_READ,
            vec![],
        );
        let mut buf = Vec::new();
        write_csv(&mut buf, &[perm]).unwrap();
        let rows = parse_csv(&buf);
        let row = &rows[1];
        assert_eq!(row[7], "Full Control");
        assert_eq!(row[9], "Read");
        assert_eq!(row[11], "Read");
    }

    #[test]
    fn multiple_explanation_steps_joined_with_pipe() {
        let perm = make_perm(
            "C:\\Data",
            "S-1-5-21-1-2-3-500",
            "Admin",
            MASK_READ,
            None,
            MASK_READ,
            vec!["step one", "step two", "step three"],
        );
        let mut buf = Vec::new();
        write_csv(&mut buf, &[perm]).unwrap();
        let rows = parse_csv(&buf);
        assert_eq!(rows[1][12], "step one | step two | step three");
    }

    #[test]
    fn multiple_permissions_produce_multiple_rows() {
        let perms: Vec<_> = (0..5)
            .map(|i| {
                make_perm(
                    &format!("C:\\Folder{i}"),
                    &format!("S-1-5-21-1-2-3-{}", 1000 + i),
                    "User",
                    MASK_READ,
                    None,
                    MASK_READ,
                    vec![],
                )
            })
            .collect();
        let mut buf = Vec::new();
        write_csv(&mut buf, &perms).unwrap();
        let rows = parse_csv(&buf);
        assert_eq!(rows.len(), 6); // 1 header + 5 data
    }

    #[test]
    fn empty_name_written_as_empty_field() {
        let perm = make_perm(
            "C:\\X",
            "S-1-5-21-1-2-3-999",
            "",
            MASK_READ,
            None,
            MASK_READ,
            vec![],
        );
        let mut buf = Vec::new();
        write_csv(&mut buf, &[perm]).unwrap();
        let rows = parse_csv(&buf);
        assert_eq!(rows[1][2], "");
    }

    #[test]
    fn file_export_creates_file_with_correct_content() {
        use std::fs;
        let dir = std::env::temp_dir();
        let path = dir.join("adpa_test_export.csv");
        let _ = fs::remove_file(&path);

        let perm = make_perm(
            "C:\\TestPath",
            "S-1-5-21-1-2-3-1001",
            "TestUser",
            MASK_READ,
            None,
            MASK_READ,
            vec!["Test step"],
        );
        let result = AnalysisResult {
            permissions: vec![perm],
            risk_findings: vec![],
            ..Default::default()
        };

        CsvExporter
            .export(&result, ExportTarget::File(path.clone()))
            .unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("path,user_sid"));
        assert!(content.contains("C:\\TestPath"));
        assert!(content.contains("TestUser"));
        assert!(content.contains("Test step"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn local_group_status_applied_serialized_correctly() {
        let mut perm = make_perm(
            "C:\\Share",
            "S-1-5-21-1-2-3-1000",
            "User",
            MASK_READ,
            None,
            MASK_READ,
            vec![],
        );
        perm.local_group_status = adpa_core::model::LocalGroupEvalStatus::Applied;
        let mut buf = Vec::new();
        write_csv(&mut buf, &[perm]).unwrap();
        let rows = parse_csv(&buf);
        assert_eq!(rows[1][15], "applied");
        assert_eq!(rows[1][16], "", "no error text for Applied");
    }

    #[test]
    fn local_group_status_not_available_records_reason_separately() {
        let mut perm = make_perm(
            "C:\\Share",
            "S-1-5-21-1-2-3-1000",
            "User",
            MASK_READ,
            None,
            MASK_READ,
            vec![],
        );
        perm.local_group_status = adpa_core::model::LocalGroupEvalStatus::NotAvailable(
            "RPC server unavailable".to_owned(),
        );
        let mut buf = Vec::new();
        write_csv(&mut buf, &[perm]).unwrap();
        let rows = parse_csv(&buf);
        assert_eq!(rows[1][15], "not_available");
        assert_eq!(rows[1][16], "RPC server unavailable");
    }

    #[test]
    fn matched_aces_serialized_as_compact_json_array() {
        use adpa_core::model::{AceEntry, AceKind};
        let mut perm = make_perm(
            "C:\\Share",
            "S-1-5-21-1-2-3-1000",
            "User",
            MASK_READ,
            None,
            MASK_READ,
            vec![],
        );
        perm.matched_aces = vec![
            AceEntry {
                kind: AceKind::Allow,
                sid: Sid("S-1-5-21-1-2-3-1000".to_owned()),
                mask: AccessMask(0x0012_0089),
                inherited: false,
                inheritance_flags: 0,
                propagation_flags: 0,
            },
            AceEntry {
                kind: AceKind::Deny,
                sid: Sid("S-1-1-0".to_owned()),
                mask: AccessMask(0x0002_0000),
                inherited: true,
                inheritance_flags: 0,
                propagation_flags: 0,
            },
        ];
        let mut buf = Vec::new();
        write_csv(&mut buf, &[perm]).unwrap();
        let rows = parse_csv(&buf);
        let json: serde_json::Value =
            serde_json::from_str(&rows[1][17]).expect("matched_aces_json must be valid JSON");
        assert_eq!(json.as_array().map(|a| a.len()), Some(2));
        assert_eq!(json[0]["sid"], "S-1-5-21-1-2-3-1000");
        assert_eq!(json[0]["kind"], "Allow");
        assert_eq!(json[0]["mask"], "0x00120089");
        assert_eq!(json[0]["inherited"], false);
        assert_eq!(json[1]["kind"], "Deny");
        assert_eq!(json[1]["inherited"], true);
    }

    #[test]
    fn contributing_sids_serialized_as_compact_json_array() {
        use adpa_core::model::ContributingAce;
        let mut perm = make_perm(
            "C:\\Share",
            "S-1-5-21-1-2-3-1000",
            "User",
            MASK_READ,
            None,
            MASK_READ,
            vec![],
        );
        perm.contributing_sids = vec![ContributingAce {
            sid: Sid("S-1-5-21-1-2-3-1100".to_owned()),
            mask: AccessMask(0x0012_0089),
        }];
        let mut buf = Vec::new();
        write_csv(&mut buf, &[perm]).unwrap();
        let rows = parse_csv(&buf);
        let json: serde_json::Value =
            serde_json::from_str(&rows[1][18]).expect("contributing_sids_json must be valid JSON");
        assert_eq!(json.as_array().map(|a| a.len()), Some(1));
        assert_eq!(json[0]["sid"], "S-1-5-21-1-2-3-1100");
        assert_eq!(json[0]["mask"], "0x00120089");
    }

    #[test]
    fn diagnostics_serialized_as_tagged_json() {
        // Follow-up finding 3: NonCanonicalDaclOrder must land structured in
        // the CSV column — and its tag must match the engine marker so
        // auditors can filter with jq.
        use adpa_core::model::PermissionDiagnostic;
        let mut perm = make_perm(
            "C:\\Share",
            "S-1-5-21-1-2-3-1000",
            "User",
            MASK_READ,
            None,
            MASK_READ,
            vec![],
        );
        perm.diagnostics = vec![PermissionDiagnostic::NonCanonicalDaclOrder { at_index: 2 }];
        let mut buf = Vec::new();
        write_csv(&mut buf, &[perm]).unwrap();
        let rows = parse_csv(&buf);
        let json: serde_json::Value =
            serde_json::from_str(&rows[1][19]).expect("diagnostics_json must be valid JSON");
        assert_eq!(json.as_array().map(|a| a.len()), Some(1));
        assert_eq!(json[0]["kind"], "NonCanonicalDaclOrder");
        assert_eq!(json[0]["at_index"], 2);
    }

    #[test]
    fn empty_diagnostics_yield_empty_json_array() {
        let perm = make_perm(
            "C:\\Share",
            "S-1-5-21-1-2-3-1000",
            "User",
            MASK_READ,
            None,
            MASK_READ,
            vec![],
        );
        let mut buf = Vec::new();
        write_csv(&mut buf, &[perm]).unwrap();
        let rows = parse_csv(&buf);
        assert_eq!(rows[1][19], "[]");
    }

    #[test]
    fn empty_matched_aces_and_contributing_sids_yield_empty_json_arrays() {
        // An empty value must surface as "[]", not as a blank cell — so
        // consumers can always parse the column as JSON.
        let perm = make_perm(
            "C:\\Share",
            "S-1-5-21-1-2-3-1000",
            "User",
            MASK_READ,
            None,
            MASK_READ,
            vec![],
        );
        let mut buf = Vec::new();
        write_csv(&mut buf, &[perm]).unwrap();
        let rows = parse_csv(&buf);
        assert_eq!(rows[1][17], "[]");
        assert_eq!(rows[1][18], "[]");
    }

    #[test]
    fn file_export_invalid_dir_returns_export_error() {
        let result = AnalysisResult {
            permissions: vec![],
            risk_findings: vec![],
            ..Default::default()
        };
        let bad_path = std::path::PathBuf::from("Z:\\nonexistent\\adpa_test.csv");
        let err = CsvExporter
            .export(&result, ExportTarget::File(bad_path))
            .unwrap_err();
        assert!(matches!(err, CoreError::Export(_)));
    }

    /// Round-8 follow-up finding 1: CSV exporter must not overwrite an
    /// existing target file when called with `ExportTarget::File`.
    #[test]
    fn csv_refuses_overwrite_unless_explicitly_allowed() {
        let mut tmp = std::env::temp_dir();
        tmp.push(format!(
            "adpa_csv_overwrite_{}_{}.csv",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            std::process::id()
        ));
        let sentinel = b"sentinel,row\n";
        std::fs::write(&tmp, sentinel).expect("write sentinel");

        let result = AnalysisResult::default();
        let refusal = CsvExporter
            .export(&result, ExportTarget::File(tmp.clone()))
            .expect_err("File branch must refuse to overwrite an existing file");
        assert!(matches!(refusal, CoreError::Export(_)));
        let after_refusal = std::fs::read(&tmp).expect("read sentinel after refusal");
        assert_eq!(
            after_refusal, sentinel,
            "pre-existing file content must stay intact when overwrite refused"
        );

        CsvExporter
            .export(&result, ExportTarget::FileOverwrite(tmp.clone()))
            .expect("FileOverwrite branch must succeed");
        let after_overwrite = std::fs::read_to_string(&tmp).expect("read after overwrite");
        assert!(
            after_overwrite.contains("user_sid") && after_overwrite.contains("path"),
            "FileOverwrite must replace sentinel content with CSV header (got: {after_overwrite:?})"
        );

        let _ = std::fs::remove_file(&tmp);
    }
}
