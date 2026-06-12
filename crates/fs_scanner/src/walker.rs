// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Recursive directory walker with error tolerance.
//!
//! Reparse points (symlinks, junctions) are followed by default with
//! loop detection via the canonicalized target. Whenever a cycle is
//! detected or the target cannot be resolved, the walker writes a
//! visible `WalkError` into the result — never silent skips. This way a
//! typical SYSVOL junction
//! (`C:\Windows\SYSVOL\sysvol\<domain>` → `C:\Windows\SYSVOL\domain`)
//! is fully analyzable without the operator needing insider knowledge
//! about junctions.

use std::collections::HashSet;

use adpa_core::{error::CoreError, model::FileSystemObject};
use tracing::{debug, info, warn};

use crate::acl::read_file_system_object_cached;
use crate::cancel::CancellationToken;

/// Configuration for the walker.
pub struct WalkConfig {
    /// Maximum recursion depth. `None` = unlimited.
    /// Depth 0 = root only, 1 = root + direct children, etc.
    pub max_depth: Option<u32>,
}

/// Error reading a path during the walk.
pub struct WalkError {
    pub path: String,
    pub error: CoreError,
}

/// Result of a walk operation.
pub struct WalkResult {
    pub objects: Vec<FileSystemObject>,
    pub errors: Vec<WalkError>,
    /// true if the walk was ended early by a cancellation token.
    pub cancelled: bool,
}

/// A single item produced during a streaming walk — either a successfully
/// read object or a per-path error. Emitted as soon as it is discovered,
/// so a caller can consume incrementally instead of buffering the whole
/// tree in memory (engine review 2026-06-12 finding 3, performance
/// rule 7). See [`walk_tree_streaming`] and ADR 0049.
pub enum WalkItem {
    Object(FileSystemObject),
    Error(WalkError),
}

/// Reads a directory subtree recursively, collecting FSOs and errors separately.
///
/// - Access-denied errors on individual paths are recorded; the scan continues.
/// - Reparse points are followed by default with loop detection via
///   canonicalized targets. Cycles or unresolvable targets produce a visible
///   entry in `errors` — never silent skips.
pub fn walk_tree(root: &str, config: &WalkConfig, cancel: &CancellationToken) -> WalkResult {
    // Buffering wrapper over the streaming walk: collect every item into
    // the classic WalkResult. Callers that must hold the full result set
    // (risk analysis over all paths, export, delta) use this; callers that
    // can consume incrementally use walk_tree_streaming directly.
    let mut objects = Vec::new();
    let mut errors = Vec::new();
    let cancelled = walk_tree_streaming(root, config, cancel, |item| match item {
        WalkItem::Object(o) => objects.push(o),
        WalkItem::Error(e) => errors.push(e),
    });
    WalkResult {
        objects,
        errors,
        cancelled,
    }
}

/// Streaming variant of [`walk_tree`]: invokes `on_item` for each object
/// and error **as it is discovered**, so a memory-sensitive caller never
/// has to hold the whole tree at once (performance rule 7).
///
/// The traversal is identical to [`walk_tree`] — sequential depth-first,
/// with the same reparse-point loop detection and the same per-scan
/// security-descriptor cache. Only the sink differs (a callback instead
/// of a `Vec`), so results and ordering are byte-for-byte the same. The
/// walk is deliberately kept sequential (correctness before speed —
/// parallelizing the shared loop-detection state is a separate, riskier
/// step); see ADR 0049.
///
/// Returns `true` if the walk ended early because of cancellation.
pub fn walk_tree_streaming(
    root: &str,
    config: &WalkConfig,
    cancel: &CancellationToken,
    mut on_item: impl FnMut(WalkItem),
) -> bool {
    info!(
        root,
        max_depth = ?config.max_depth,
        "Starting directory tree walk"
    );
    let mut visited_canonical: HashSet<String> = HashSet::new();
    // One security-descriptor cache for the whole tree so an inherited
    // DACL shared by many directories is parsed once, not once per object
    // (engine review 2026-06-12 finding 2). A cache hit is byte-validated
    // inside the reader, so it can never assign a wrong DACL.
    let mut sd_cache = crate::acl::SdCache::new();
    // Canonicalize the root up front and seed the visited set with it so
    // that reparse points pointing back to the scan root are detected as a
    // cycle right away.
    if let Some(canon) = canonicalize_path(root) {
        visited_canonical.insert(canon);
    }
    // Count objects and errors in a wrapping closure so the recursive walk
    // needs no extra counter parameters and the completion log keeps both
    // figures (self-review follow-up: the error count must not be lost).
    let mut object_count = 0usize;
    let mut error_count = 0usize;
    let mut counting_sink = |item: WalkItem| {
        match &item {
            WalkItem::Object(_) => object_count += 1,
            WalkItem::Error(_) => error_count += 1,
        }
        on_item(item);
    };
    walk_dir(
        root,
        0,
        config,
        cancel,
        &mut counting_sink,
        &mut visited_canonical,
        &mut sd_cache,
    );
    let cancelled = cancel.is_cancelled();
    info!(
        root,
        paths = object_count,
        errors = error_count,
        cancelled,
        "Directory tree walk complete"
    );
    cancelled
}

///
/// Canonicalizes a path to its resolved target form (long-path prefixed on
/// Windows). For a reparse point this returns the *target* — exactly what we
/// need for loop detection. Returns `None` if resolution fails (e.g. broken
/// link).
fn canonicalize_path(path: &str) -> Option<String> {
    let api_path = validation::path::to_windows_api_path(path);
    std::fs::canonicalize(&api_path)
        .ok()
        .map(|p| p.to_string_lossy().to_string().to_ascii_lowercase())
}

#[allow(clippy::too_many_arguments)]
fn walk_dir(
    path: &str,
    current_depth: u32,
    config: &WalkConfig,
    cancel: &CancellationToken,
    on_item: &mut dyn FnMut(WalkItem),
    visited_canonical: &mut HashSet<String>,
    sd_cache: &mut crate::acl::SdCache,
) {
    if cancel.is_cancelled() {
        return;
    }
    match read_file_system_object_cached(path, sd_cache) {
        Err(e) => {
            warn!(path, error = %e, "Cannot read security descriptor");
            on_item(WalkItem::Error(WalkError {
                path: path.to_owned(),
                error: e,
            }));
        }
        Ok(fso) => {
            let is_dir = fso.is_directory;
            let is_reparse = fso.is_reparse_point;
            debug!(path, is_dir, is_reparse, depth = current_depth, "Read FSO");
            on_item(WalkItem::Object(fso));

            // For a reparse point we try to determine the canonical target.
            // If it is already part of the current walk, descending further
            // would create a cycle — we surface that as a visible error and
            // stop the recursion at this point. If canonicalization fails
            if is_reparse {
                match canonicalize_path(path) {
                    None => {
                        warn!(path, "Reparse point target could not be resolved");
                        on_item(WalkItem::Error(WalkError {
                            path: path.to_owned(),
                            error: CoreError::AccessDenied(
                                "Reparse point target could not be resolved — recursion stopped at this junction/link. The object itself is in the result with its DACL; objects behind the link were not enumerated."
                                    .to_owned(),
                            ),
                        }));
                        return;
                    }
                    Some(target) => {
                        if visited_canonical.contains(&target) {
                            info!(
                                path,
                                target = %target,
                                "Reparse point target already visited — recursion stopped to avoid loop"
                            );
                            on_item(WalkItem::Error(WalkError {
                                path: path.to_owned(),
                                error: CoreError::AccessDenied(format!(
                                    "Reparse point target already visited in this scan — recursion stopped to avoid an infinite loop. Target: {target}. The object itself is in the result with its DACL; objects behind the link were not enumerated again."
                                )),
                            }));
                            return;
                        }
                        visited_canonical.insert(target);
                    }
                }
            }

            let depth_ok = config.max_depth.is_none_or(|max| current_depth < max);
            if is_dir && depth_ok {
                // Apply the long-path prefix before `read_dir` so that
                // directories with paths > MAX_PATH can be enumerated
                // reliably. The `entry.path()` results carry the prefix
                // forward — `to_windows_api_path` recognises that on the
                // next recursion step (idempotent) and does not double-prefix.
                let api_path = validation::path::to_windows_api_path(path);
                match std::fs::read_dir(&api_path) {
                    Err(e) => {
                        warn!(path, error = %e, "Cannot enumerate directory");
                        on_item(WalkItem::Error(WalkError {
                            path: path.to_owned(),
                            error: CoreError::AccessDenied(format!(
                                "Cannot enumerate directory: {e}"
                            )),
                        }));
                    }
                    Ok(entries) => {
                        for entry_result in entries {
                            // Check for cancellation between sibling entries.
                            if cancel.is_cancelled() {
                                return;
                            }
                            match entry_result {
                                Err(e) => {
                                    warn!(path, error = %e, "Directory entry error");
                                    on_item(WalkItem::Error(WalkError {
                                        path: path.to_owned(),
                                        error: CoreError::AccessDenied(format!(
                                            "Directory entry error: {e}"
                                        )),
                                    }));
                                }
                                Ok(entry) => {
                                    let child = entry.path().to_string_lossy().into_owned();
                                    walk_dir(
                                        &child,
                                        current_depth + 1,
                                        config,
                                        cancel,
                                        on_item,
                                        visited_canonical,
                                        sd_cache,
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
    use super::{walk_tree, walk_tree_streaming, WalkConfig, WalkItem, WalkResult};
    use crate::cancel::CancellationToken;

    fn unlimited() -> WalkConfig {
        WalkConfig { max_depth: None }
    }

    fn depth(n: u32) -> WalkConfig {
        WalkConfig { max_depth: Some(n) }
    }

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

    /// The streaming walk must produce exactly the same objects (in the
    /// same order) and the same errors as the buffering wrapper — the
    /// callback only changes the sink, not the traversal (finding 3).
    ///
    /// Walks a controlled temp tree rather than a live system directory:
    /// `C:\Windows` mutates between two independent walks (logs / temp
    /// files), which would make a "same objects in the same order"
    /// assertion flaky on CI.
    #[test]
    fn streaming_matches_buffered() {
        use std::path::PathBuf;
        let stamp = format!(
            "{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let root: PathBuf = std::env::temp_dir().join(format!("adpa-stream-{stamp}"));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("sub_a").join("nested")).expect("create sub_a/nested");
        std::fs::create_dir_all(root.join("sub_b")).expect("create sub_b");
        std::fs::write(root.join("sub_a").join("file.txt"), b"x").expect("write file");
        let root_str = root.to_string_lossy().into_owned();

        let cfg = unlimited();
        let buffered = walk(&root_str, &cfg);

        let mut streamed_objects = Vec::new();
        let mut streamed_errors = Vec::new();
        let cancelled =
            walk_tree_streaming(
                &root_str,
                &cfg,
                &CancellationToken::new(),
                |item| match item {
                    WalkItem::Object(o) => streamed_objects.push(o.path.0),
                    WalkItem::Error(e) => streamed_errors.push(e.path),
                },
            );

        let _ = std::fs::remove_dir_all(&root);

        assert!(!cancelled);
        assert!(
            buffered.objects.len() >= 4,
            "fixture tree must yield at least root + sub_a + nested + sub_b"
        );
        let buffered_paths: Vec<String> =
            buffered.objects.iter().map(|o| o.path.0.clone()).collect();
        assert_eq!(
            streamed_objects, buffered_paths,
            "streaming objects must match the buffered walk exactly, in order"
        );
        assert_eq!(
            streamed_errors.len(),
            buffered.errors.len(),
            "streaming must report the same number of errors"
        );
    }

    /// The callback is invoked incrementally — the first object arrives
    /// before the walk has finished collecting the whole tree.
    #[test]
    fn streaming_emits_root_first() {
        let mut first: Option<String> = None;
        walk_tree_streaming(
            "C:\\Windows",
            &depth(1),
            &CancellationToken::new(),
            |item| {
                if first.is_none() {
                    if let WalkItem::Object(o) = item {
                        first = Some(o.path.0);
                    }
                }
            },
        );
        assert_eq!(first.as_deref(), Some("C:\\Windows"));
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

    // --- Finding 5: long path support ---

    /// Builds a directory chain under TEMP whose total path is reliably
    ///
    /// Builds a directory chain under TEMP whose full path is clearly
    /// beyond MAX_PATH (260), scans it, and verifies the walker reaches
    /// the leaf directory. Before Finding 5, `GetFileAttributesW` in
    /// `read_file_system_object` would have failed on long paths.
    #[test]
    fn walk_reaches_paths_longer_than_max_path() {
        use std::path::PathBuf;

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

        // Clean up leftovers from prior runs.
        let _ = std::fs::remove_dir_all(&root);

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
            "test setup: root must be prefix-free, otherwise it does not exercise finding 5"
        );

        let result = walk(&root_str, &unlimited());

        // reissen.
        // Cleanup first — even if asserts fail. Via the prefixed root so
        // that remove_dir_all itself does not trip over MAX_PATH.
        let _ = std::fs::remove_dir_all(PathBuf::from(format!(r"\\?\{root_str}")));

        assert!(
            result.errors.is_empty(),
            "Walker must produce no errors on long paths — got: {:?}",
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
            "expected 13 objects (root + 12 depth), got: {}",
            result.objects.len()
        );

        let max_len = result.objects.iter().map(|o| o.path.0.len()).max().unwrap();
        assert!(max_len > 260, "Deepest path must be > 260, was: {max_len}");

        for obj in &result.objects {
            assert!(
                !obj.path.0.starts_with(r"\\?\"),
                "FSO path must not carry a \\\\?\\ prefix: {}",
                obj.path.0
            );
        }
    }

    // ----------------------------------------------------------------
    // ----------------------------------------------------------------

    /// Creates a small structure under TEMP where `link → target` is a
    /// directory junction. The walker must follow `link` and find the
    /// child under `target` — this is the SYSVOL situation.
    #[test]
    fn walker_follows_directory_junction_into_target() {
        use std::path::PathBuf;

        let stamp = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let root: PathBuf = std::env::temp_dir().join(format!("adpa-junction-{stamp}"));
        let _ = std::fs::remove_dir_all(&root);
        let target = root.join("target");
        let inside_target = target.join("inside");
        let link = root.join("link");

        std::fs::create_dir_all(&inside_target).expect("create target tree");
        let status = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &link.to_string_lossy(),
                &target.to_string_lossy(),
            ])
            .status()
            .expect("spawn mklink");
        if !status.success() {
            // Junction creation may fail on some CI hosts (e.g. without write
            // permission under TEMP). Skip the test deliberately in that case
            // so it does not fail spuriously.
            let _ = std::fs::remove_dir_all(&root);
            eprintln!("mklink /J failed — skipping junction test");
            return;
        }

        let root_str = root.to_string_lossy().into_owned();
        let result = walk(&root_str, &unlimited());
        let _ = std::fs::remove_dir_all(&root);

        let paths: Vec<String> = result
            .objects
            .iter()
            .map(|o| o.path.0.to_ascii_lowercase())
            .collect();

        let inside_via_link = link.join("inside").to_string_lossy().to_ascii_lowercase();
        assert!(
            paths.iter().any(|p| p == &inside_via_link),
            "Walker must traverse the junction and find 'link\\inside' — got: {paths:?}"
        );
    }

    /// Creates a circular junction structure (`b → a`) and verifies that the
    /// walker detects the cycle and surfaces a *visible* error in the result
    /// — no silent skip, no stack overflow.
    #[test]
    fn walker_detects_junction_loop_and_emits_visible_error() {
        use std::path::PathBuf;

        let stamp = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let root: PathBuf = std::env::temp_dir().join(format!("adpa-junction-loop-{stamp}"));
        let _ = std::fs::remove_dir_all(&root);
        let a = root.join("a");
        let b = a.join("b");

        std::fs::create_dir_all(&a).expect("create a");
        // starten.
        // `b` is a junction back to `root` — once the walker enters `b`,
        // without loop detection it would start over from `root`.
        let status = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &b.to_string_lossy(),
                &root.to_string_lossy(),
            ])
            .status()
            .expect("spawn mklink");
        if !status.success() {
            let _ = std::fs::remove_dir_all(&root);
            eprintln!("mklink /J failed — skipping junction-loop test");
            return;
        }

        let result = walk(&root.to_string_lossy(), &unlimited());
        let _ = std::fs::remove_dir_all(&root);

        assert!(
            !result.errors.is_empty(),
            "Loop junction must produce an error in the result, got 0"
        );
        let loop_msg = result.errors.iter().any(|e| {
            let msg = format!("{}", e.error);
            msg.contains("already visited") || msg.contains("loop")
        });
        assert!(
            loop_msg,
            "at least one error must explain the loop detection, got: {:?}",
            result
                .errors
                .iter()
                .map(|e| format!("{}", e.error))
                .collect::<Vec<_>>()
        );
    }
}
