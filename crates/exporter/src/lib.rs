// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! exporter — CSV, JSON, HTML and future report formats

pub mod csv;
pub mod html;
pub mod json;
pub mod trustees;

pub use csv::{
    neutralize_spreadsheet_formula, write_csv, CsvExporter, CsvFileWriter, CsvRowWriter,
};
pub use html::{render_html, HtmlExporter};
pub use json::JsonExporter;
pub use trustees::{
    build_path_trustees, build_path_trustees_with_share, build_path_trustees_with_share_and_names,
    collect_ace_sids_for_resolution, read_share_overlay, ShareTrusteeOverlay,
};

/// Review CR-18: moves the finished staging file `from` to `to`. Without
/// `overwrite` an existing `to` is refused **atomically** by the move itself
/// (`AlreadyExists`), so a file created meanwhile is never replaced; with it
/// the target is replaced.
pub(crate) fn publish_file(
    from: &std::path::Path,
    to: &std::path::Path,
    overwrite: bool,
) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        };
        let wide = |p: &std::path::Path| -> Vec<u16> {
            p.as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect()
        };
        let (src, dst) = (wide(from), wide(to));
        let flags = MOVEFILE_WRITE_THROUGH
            | if overwrite {
                MOVEFILE_REPLACE_EXISTING
            } else {
                0
            };
        // SAFETY: both strings are NUL-terminated UTF-16 and outlive the
        // call; MoveFileExW only reads them.
        let ok = unsafe { MoveFileExW(src.as_ptr(), dst.as_ptr(), flags) };
        if ok == 0 {
            let e = std::io::Error::last_os_error();
            // ERROR_ALREADY_EXISTS (183) / ERROR_FILE_EXISTS (80).
            return Err(match e.raw_os_error() {
                Some(80) | Some(183) => std::io::Error::new(std::io::ErrorKind::AlreadyExists, e),
                _ => e,
            });
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        if overwrite {
            std::fs::rename(from, to)
        } else {
            std::fs::hard_link(from, to)?;
            std::fs::remove_file(from)
        }
    }
}

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
