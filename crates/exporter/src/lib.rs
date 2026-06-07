// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! exporter — CSV, JSON, HTML and future report formats

pub mod csv;
pub mod html;
pub mod json;
pub mod trustees;

pub use csv::{write_csv, CsvExporter};
pub use html::{render_html, HtmlExporter};
pub use json::JsonExporter;
pub use trustees::{
    build_path_trustees, build_path_trustees_with_share, build_path_trustees_with_share_and_names,
    collect_ace_sids_for_resolution, read_share_overlay, ShareTrusteeOverlay,
};

/// Zentrale Overwrite-Policy fuer alle Datei-basierten Exporter.
/// Implementiert Round-8-Folgereview Finding 1: der Trait-Default
/// `FileOverwrite`-Pfad truncatet bewusst. Die jeweiligen Exporter
///
/// Centralised overwrite policy for every file-based exporter.
/// Implements round-8 follow-up finding 1: the trait default refuses
/// existing target files (`create_new`); the explicit `FileOverwrite`
/// branch truncates on purpose. Each exporter calls the helper and
/// writes into the returned `File`.
pub(crate) fn open_export_file(
    target: adpa_core::traits::ExportTarget,
) -> Result<std::fs::File, adpa_core::error::CoreError> {
    use adpa_core::{error::CoreError, traits::ExportTarget};
    match target {
        ExportTarget::File(path) => std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| {
                CoreError::Export(format!(
                    "Cannot create export file '{}' (already exists or other error): {e}",
                    path.display()
                ))
            }),
        ExportTarget::FileOverwrite(path) => std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| {
                CoreError::Export(format!(
                    "Cannot open export file '{}' for overwrite: {e}",
                    path.display()
                ))
            }),
    }
}
