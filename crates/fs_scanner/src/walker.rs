//! Rekursiver Verzeichnis-Walker mit Fehlertoleranz.
//! Recursive directory walker with error tolerance.
//!
//! Reparse Points (Symlinks, Junctions) werden nicht rekursiert — kein Endlosschleifen-Risiko.
//! Reparse points (symlinks, junctions) are not recursed — no infinite-loop risk.

use adpa_core::{error::CoreError, model::FileSystemObject};
use tracing::{debug, info, warn};

use crate::acl::read_file_system_object;
use crate::cancel::CancellationToken;

/// Konfiguration für den Walker.
/// Configuration for the walker.
pub struct WalkConfig {
    /// Maximale Rekursionstiefe. `None` = unbegrenzt. / Maximum recursion depth. `None` = unlimited.
    /// Tiefe 0 = nur Root, 1 = Root + direkte Kinder, usw.
    /// Depth 0 = root only, 1 = root + direct children, etc.
    pub max_depth: Option<u32>,
}

/// Fehler beim Lesen eines Pfades während des Walks.
/// Error reading a path during the walk.
pub struct WalkError {
    pub path: String,
    pub error: CoreError,
}

/// Ergebnis eines Walk-Vorgangs.
/// Result of a walk operation.
pub struct WalkResult {
    pub objects: Vec<FileSystemObject>,
    pub errors: Vec<WalkError>,
    /// true wenn der Walk durch ein Abbruch-Token vorzeitig beendet wurde.
    /// true if the walk was ended early by a cancellation token.
    pub cancelled: bool,
}

/// Liest ein Verzeichnis-Teilbaum rekursiv und sammelt FSOs und Fehler getrennt.
/// Reads a directory subtree recursively, collecting FSOs and errors separately.
///
/// - Zugriff-verweigert-Fehler auf einzelne Pfade werden protokolliert; der Scan läuft weiter.
/// - Access-denied errors on individual paths are recorded; the scan continues.
/// - Reparse Points werden erkannt und nicht rekursiert.
/// - Reparse points are detected and not recursed into.
pub fn walk_tree(root: &str, config: &WalkConfig, cancel: &CancellationToken) -> WalkResult {
    info!(
        root,
        max_depth = ?config.max_depth,
        "Starting directory tree walk"
    );
    let mut objects = Vec::new();
    let mut errors = Vec::new();
    walk_dir(root, 0, config, cancel, &mut objects, &mut errors);
    let cancelled = cancel.is_cancelled();
    info!(
        root,
        paths = objects.len(),
        errors = errors.len(),
        cancelled,
        "Directory tree walk complete"
    );
    WalkResult {
        objects,
        errors,
        cancelled,
    }
}

fn walk_dir(
    path: &str,
    current_depth: u32,
    config: &WalkConfig,
    cancel: &CancellationToken,
    objects: &mut Vec<FileSystemObject>,
    errors: &mut Vec<WalkError>,
) {
    // Kooperativer Abbruchpunkt vor jedem Pfad. / Cooperative cancellation point before each path.
    if cancel.is_cancelled() {
        return;
    }
    match read_file_system_object(path) {
        Err(e) => {
            warn!(path, error = %e, "Cannot read security descriptor");
            errors.push(WalkError {
                path: path.to_owned(),
                error: e,
            });
        }
        Ok(fso) => {
            let is_dir = fso.is_directory;
            let is_reparse = fso.is_reparse_point;
            debug!(path, is_dir, is_reparse, depth = current_depth, "Read FSO");
            objects.push(fso);

            if is_reparse {
                debug!(path, "Skipping reparse point — not recursing");
            }

            let depth_ok = config.max_depth.is_none_or(|max| current_depth < max);
            if is_dir && !is_reparse && depth_ok {
                // Long-Path-Präfix vor `read_dir` ansetzen, damit
                // Verzeichnisse mit Pfaden > MAX_PATH zuverlässig enumeriert
                // werden können. Die `entry.path()`-Rückgaben tragen das
                // Präfix dann mit — `to_windows_api_path` erkennt das beim
                // nächsten Rekursionsschritt (Idempotenz) und prefixt nicht
                // doppelt.
                // Apply the long-path prefix before `read_dir` so that
                // directories with paths > MAX_PATH can be enumerated
                // reliably. The `entry.path()` results carry the prefix
                // forward — `to_windows_api_path` recognises that on the
                // next recursion step (idempotent) and does not double-prefix.
                let api_path = validation::path::to_windows_api_path(path);
                match std::fs::read_dir(&api_path) {
                    Err(e) => {
                        warn!(path, error = %e, "Cannot enumerate directory");
                        errors.push(WalkError {
                            path: path.to_owned(),
                            error: CoreError::AccessDenied(format!(
                                "Cannot enumerate directory: {e}"
                            )),
                        });
                    }
                    Ok(entries) => {
                        for entry_result in entries {
                            // Abbruch zwischen Geschwister-Einträgen prüfen.
                            // Check for cancellation between sibling entries.
                            if cancel.is_cancelled() {
                                return;
                            }
                            match entry_result {
                                Err(e) => {
                                    warn!(path, error = %e, "Directory entry error");
                                    errors.push(WalkError {
                                        path: path.to_owned(),
                                        error: CoreError::AccessDenied(format!(
                                            "Directory entry error: {e}"
                                        )),
                                    });
                                }
                                Ok(entry) => {
                                    let child = entry.path().to_string_lossy().into_owned();
                                    walk_dir(
                                        &child,
                                        current_depth + 1,
                                        config,
                                        cancel,
                                        objects,
                                        errors,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{walk_tree, WalkConfig, WalkResult};
    use crate::cancel::CancellationToken;

    fn unlimited() -> WalkConfig {
        WalkConfig { max_depth: None }
    }

    fn depth(n: u32) -> WalkConfig {
        WalkConfig { max_depth: Some(n) }
    }

    /// Walk-Helfer mit frischem, nicht abgebrochenem Token.
    /// Walk helper with a fresh, non-cancelled token.
    fn walk(root: &str, config: &WalkConfig) -> WalkResult {
        walk_tree(root, config, &CancellationToken::new())
    }

    #[test]
    fn nonexistent_root_returns_error() {
        let result = walk("C:\\__adpa_nonexistent__", &unlimited());
        assert!(result.objects.is_empty());
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn root_is_always_included() {
        let result = walk("C:\\Windows", &depth(0));
        assert_eq!(result.objects.len(), 1);
        assert_eq!(result.objects[0].path.0, "C:\\Windows");
        assert!(result.errors.is_empty());
    }

    #[test]
    fn depth_0_returns_only_root() {
        let result = walk("C:\\Windows", &depth(0));
        assert_eq!(result.objects.len(), 1);
    }

    #[test]
    fn depth_1_returns_root_and_children() {
        let result = walk("C:\\Windows", &depth(1));
        // Root + at least System32, SysWOW64, etc.
        assert!(result.objects.len() > 1, "Expected children at depth 1");
        // Root must be first
        assert_eq!(result.objects[0].path.0, "C:\\Windows");
    }

    #[test]
    fn unlimited_depth_finds_nested_entries() {
        // Limit to System32 to keep test fast
        let result = walk("C:\\Windows\\System32", &depth(1));
        assert!(
            result.objects.len() > 10,
            "System32 should have many children"
        );
    }

    #[test]
    fn all_returned_objects_have_non_empty_paths() {
        let result = walk("C:\\Windows", &depth(1));
        for obj in &result.objects {
            assert!(!obj.path.0.is_empty());
        }
    }

    #[test]
    fn directory_flag_set_on_root() {
        let result = walk("C:\\Windows", &depth(0));
        assert!(result.objects[0].is_directory);
    }

    #[test]
    fn pre_cancelled_token_stops_walk_immediately() {
        let token = CancellationToken::new();
        token.cancel();
        let result = walk_tree("C:\\Windows", &unlimited(), &token);
        assert!(result.cancelled, "result must be marked cancelled");
        assert!(
            result.objects.is_empty(),
            "a pre-cancelled walk must not read any path"
        );
    }

    #[test]
    fn non_cancelled_walk_reports_cancelled_false() {
        let result = walk("C:\\Windows", &depth(0));
        assert!(!result.cancelled);
    }

    // --- Finding 5: Long-Path-Unterstützung ---
    // --- Finding 5: long path support ---

    /// Baut unter TEMP eine Verzeichniskette, deren Gesamtpfad sicher
    /// jenseits von MAX_PATH (260) liegt, scannt sie und prüft, dass der
    /// Walker das Blattverzeichnis tatsächlich erreicht. Vor Finding 5
    /// wäre der `GetFileAttributesW`-Aufruf in `read_file_system_object`
    /// auf langen Pfaden fehlgeschlagen.
    ///
    /// Builds a directory chain under TEMP whose full path is clearly
    /// beyond MAX_PATH (260), scans it, and verifies the walker reaches
    /// the leaf directory. Before Finding 5, `GetFileAttributesW` in
    /// `read_file_system_object` would have failed on long paths.
    #[test]
    fn walk_reaches_paths_longer_than_max_path() {
        use std::path::PathBuf;

        // 12 × 30 = 360 Zeichen Segmenttiefe + TEMP-Präfix ⇒ klar > 260.
        // Wir nutzen UUID-ähnliche Namen, damit parallele Testläufe nicht
        // kollidieren.
        // 12 × 30 = 360 chars of segment depth + TEMP prefix ⇒ clearly > 260.
        let stamp = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let root: PathBuf = std::env::temp_dir().join(format!("adpa-longpath-{stamp}"));
        let segment: String = "a".repeat(30);

        // Vorhandene Reste aus früheren Läufen entfernen.
        // Clean up leftovers from prior runs.
        let _ = std::fs::remove_dir_all(&root);

        // Mit dem `\\?\`-Präfix anlegen, damit `create_dir_all` selbst nicht
        // an MAX_PATH scheitert. Der Test prüft anschließend den Scanner
        // *ohne* Präfix — der muss intern korrekt normalisieren.
        // Create via the `\\?\` prefix so that `create_dir_all` itself does
        // not hit MAX_PATH. The test then scans *without* the prefix —
        // the scanner has to normalise internally.
        let mut deep = root.clone();
        for _ in 0..12 {
            deep.push(&segment);
        }
        let deep_with_prefix: PathBuf = {
            let s = deep.to_string_lossy().to_string();
            PathBuf::from(format!(r"\\?\{s}"))
        };
        std::fs::create_dir_all(&deep_with_prefix).expect("create deep dir");

        let root_str = root.to_string_lossy().into_owned();
        assert!(
            !root_str.starts_with(r"\\?\"),
            "Test-Setup: Root muss präfix-frei sein, sonst testet er Finding 5 nicht"
        );

        let result = walk(&root_str, &unlimited());

        // Cleanup zuerst — auch wenn Asserts unten fehlschlagen. Über das
        // präfixierte Root, sonst kann remove_dir_all selbst MAX_PATH
        // reissen.
        // Cleanup first — even if asserts fail. Via the prefixed root so
        // that remove_dir_all itself does not trip over MAX_PATH.
        let _ = std::fs::remove_dir_all(PathBuf::from(format!(r"\\?\{root_str}")));

        assert!(
            result.errors.is_empty(),
            "Walker darf auf Long-Path keine Fehler haben — bekam: {:?}",
            result
                .errors
                .iter()
                .map(|e| format!("{}: {}", e.path, e.error))
                .collect::<Vec<_>>()
        );
        // 1 Root + 12 verschachtelte Verzeichnisse = 13 Objekte.
        assert_eq!(
            result.objects.len(),
            13,
            "Erwarte 13 Objekte (Root + 12 Tiefe), bekam: {}",
            result.objects.len()
        );

        // Der tiefste Pfad muss > MAX_PATH lang sein.
        let max_len = result.objects.iter().map(|o| o.path.0.len()).max().unwrap();
        assert!(
            max_len > 260,
            "Tiefster Pfad muss > 260 sein, war: {max_len}"
        );

        // Die gespeicherten Pfade dürfen das `\\?\`-Präfix NICHT tragen —
        // Reports sollen menschenlesbar bleiben (siehe acl.rs).
        for obj in &result.objects {
            assert!(
                !obj.path.0.starts_with(r"\\?\"),
                "FSO-Pfad darf kein \\\\?\\-Präfix tragen: {}",
                obj.path.0
            );
        }
    }
}
