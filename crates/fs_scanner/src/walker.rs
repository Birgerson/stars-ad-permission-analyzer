// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Recursive directory walker with error tolerance.
//!
//! Reparse points (symlinks, junctions) are followed by default. Loop
//! handling distinguishes two cases via canonicalized identities
//! (deep review 2026-07-04, F2 — ADR 0058):
//!
//! - **Cycle** — the target is an ancestor of the *active* recursion
//!   chain; descending would recurse forever. Recursion stops with a
//!   typed [`CoreError::ReparseCycle`] error.
//! - **Duplicate target** — the target was already enumerated anywhere
//!   in this scan under another namespace path (e.g. two junctions to
//!   the same directory, or a junction plus the directory's real path).
//!   Each distinct directory is enumerated exactly once; every further
//!   route is recorded as a typed [`CoreError::ReparseDuplicateTarget`]
//!   error naming the first path, so the report stays deduplicated
//!   without hiding the alternate route.
//!
//! Whenever recursion stops or a target cannot be resolved, the walker
//! writes a visible `WalkError` into the result — never silent skips.
//! This way a typical SYSVOL junction
//! (`C:\Windows\SYSVOL\sysvol\<domain>` → `C:\Windows\SYSVOL\domain`)
//! is fully analyzable without the operator needing insider knowledge
//! about junctions.

use std::collections::HashMap;

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
    // Cycle vs duplicate-target bookkeeping — the root's canonical identity
    // enters the active chain in its own `walk_dir` step, so a reparse
    // point back to the scan root is detected as a cycle right away.
    let mut detector = LoopDetector::new();
    // One security-descriptor cache for the whole tree so an inherited
    // DACL shared by many directories is parsed once, not once per object
    // (engine review 2026-06-12 finding 2). A cache hit is byte-validated
    // inside the reader, so it can never assign a wrong DACL.
    let mut sd_cache = crate::acl::SdCache::new();
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
        None,
        0,
        config,
        cancel,
        &mut counting_sink,
        &mut detector,
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

/// The walk's decision for a directory about to be descended into —
/// produced by [`LoopDetector::enter`].
#[derive(Debug, PartialEq, Eq)]
enum DescendDecision {
    /// Not seen before — descend. The detector recorded the entry; the
    /// caller must pair it with [`LoopDetector::leave`] when the subtree
    /// (or the depth-limited stop) is done.
    Fresh,
    /// The canonical identity is an **ancestor on the active recursion
    /// chain** — descending would recurse forever. A real cycle.
    Cycle,
    /// The canonical identity was **already enumerated in this scan**
    /// under `first_path` — a second namespace route (junction/symlink)
    /// to the same directory, not a cycle.
    DuplicateTarget { first_path: String },
}

/// Cycle vs duplicate-target bookkeeping for one tree walk, factored out
/// so the semantics are unit-testable without any filesystem setup
/// (deep review 2026-07-04, F2 + F5; ADR 0058).
///
/// Two structures with distinct jobs — conflating them was exactly the
/// F2 defect (a scan-wide set reported duplicate routes as "loops"):
///
/// - `chain`: canonical identities of the directories on the **active**
///   recursion path. Membership means a descent would re-enter an
///   ancestor — the only true cycle condition.
/// - `seen_first_path`: canonical identity → first namespace path that
///   enumerated it, scan-wide. A later hit is a duplicate route; the
///   stored path makes the diagnostic explainable ("already enumerated
///   under …").
struct LoopDetector {
    chain: Vec<String>,
    seen_first_path: HashMap<String, String>,
}

impl LoopDetector {
    fn new() -> Self {
        Self {
            chain: Vec::new(),
            seen_first_path: HashMap::new(),
        }
    }

    /// Decides whether the walk may descend into the directory with the
    /// given canonical identity, reached via `namespace_path`. Records the
    /// entry when `Fresh` — the caller must call [`Self::leave`] after the
    /// subtree completes (and only then).
    fn enter(&mut self, canonical: &str, namespace_path: &str) -> DescendDecision {
        if self.chain.iter().any(|c| c == canonical) {
            return DescendDecision::Cycle;
        }
        if let Some(first) = self.seen_first_path.get(canonical) {
            return DescendDecision::DuplicateTarget {
                first_path: first.clone(),
            };
        }
        self.seen_first_path
            .insert(canonical.to_owned(), namespace_path.to_owned());
        self.chain.push(canonical.to_owned());
        DescendDecision::Fresh
    }

    /// Pops the innermost chain entry — pairs with a `Fresh` result of
    /// [`Self::enter`].
    fn leave(&mut self) {
        self.chain.pop();
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_dir(
    path: &str,
    // Canonical identity of the parent directory — `None` for the scan
    // root. Lets plain (non-reparse) children derive their canonical form
    // without a filesystem round trip: parent canonical + component name.
    parent_canonical: Option<&str>,
    current_depth: u32,
    config: &WalkConfig,
    cancel: &CancellationToken,
    on_item: &mut dyn FnMut(WalkItem),
    detector: &mut LoopDetector,
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

            // An unresolvable reparse target (broken link, no access) stops
            // here for files and directories alike — visible, not silent.
            if is_reparse && canonicalize_path(path).is_none() {
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

            // Only directories recurse, so only directories need the cycle /
            // duplicate-target bookkeeping (a file symlink cannot loop).
            if !is_dir {
                return;
            }

            // Canonical identity of this directory. Reparse points and the
            // root resolve via the filesystem (the reparse *target* is the
            // identity); plain children derive from the parent — same
            // lowercased, prefix-consistent form without a syscall per
            // directory.
            let canonical = if is_reparse || parent_canonical.is_none() {
                match canonicalize_path(path) {
                    Some(c) => c,
                    // Root that cannot be canonicalized (rare: virtual FS):
                    // best-effort identity so the walk still runs.
                    None => path.to_ascii_lowercase(),
                }
            } else {
                let component = std::path::Path::new(path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_ascii_lowercase());
                match (parent_canonical, component) {
                    (Some(parent), Some(name)) => {
                        format!("{parent}{}{name}", std::path::MAIN_SEPARATOR)
                    }
                    // No derivable component — fall back to the filesystem.
                    _ => canonicalize_path(path).unwrap_or_else(|| path.to_ascii_lowercase()),
                }
            };

            match detector.enter(&canonical, path) {
                DescendDecision::Cycle => {
                    info!(
                        path,
                        target = %canonical,
                        "Reparse point target is an ancestor of the active chain — cycle, recursion stopped"
                    );
                    on_item(WalkItem::Error(WalkError {
                        path: path.to_owned(),
                        error: CoreError::ReparseCycle(format!(
                            "Reparse point target is an ancestor of the current traversal chain — descending would loop forever; recursion stopped at this junction/link. Target: {canonical}. The object itself is in the result with its DACL."
                        )),
                    }));
                    return;
                }
                DescendDecision::DuplicateTarget { first_path } => {
                    info!(
                        path,
                        target = %canonical,
                        first_path = %first_path,
                        "Reparse point target already enumerated under another namespace path — duplicate route, not enumerated again"
                    );
                    on_item(WalkItem::Error(WalkError {
                        path: path.to_owned(),
                        error: CoreError::ReparseDuplicateTarget(format!(
                            "Reparse point target already enumerated in this scan under '{first_path}' — subtree not enumerated again under this namespace path (duplicate target, not a cycle). Target: {canonical}. The link object itself is in the result with its DACL."
                        )),
                    }));
                    return;
                }
                DescendDecision::Fresh => {}
            }

            let depth_ok = config.max_depth.is_none_or(|max| current_depth < max);
            if depth_ok {
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
                            // (Aborting mid-chain without `leave()` is fine —
                            // the whole walk ends here.)
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
                                        Some(&canonical),
                                        current_depth + 1,
                                        config,
                                        cancel,
                                        on_item,
                                        detector,
                                        sd_cache,
                                    );
                                }
                            }
                        }
                    }
                }
            }
            // Pairs with the `Fresh` entry above — the directory leaves the
            // active recursion chain (it stays in the scan-wide seen map).
            detector.leave();
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
        // 1 root + 12 nested directories = 13 objects.
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
        mklink_junction(&link, &target);

        let root_str = root.to_string_lossy().into_owned();
        let result = walk(&root_str, &unlimited());
        let _ = std::fs::remove_dir_all(&root);

        let paths: Vec<String> = result
            .objects
            .iter()
            .map(|o| o.path.0.to_ascii_lowercase())
            .collect();

        // NTFS enumerates alphabetically: `link` before `target`, so the
        // junction route enumerates the content first (the SYSVOL case).
        let inside_via_link = link.join("inside").to_string_lossy().to_ascii_lowercase();
        assert!(
            paths.iter().any(|p| p == &inside_via_link),
            "Walker must traverse the junction and find 'link\\inside' — got: {paths:?}"
        );
        // ADR 0058: the real `target` directory is then a duplicate route to
        // the already-enumerated content — its subtree is not enumerated
        // again, and the walk says so with a typed diagnostic naming the
        // first path instead of silently duplicating (or mislabelling it a
        // "loop", the F2 defect).
        let inside_via_target = target.join("inside").to_string_lossy().to_ascii_lowercase();
        assert!(
            !paths.iter().any(|p| p == &inside_via_target),
            "duplicate route must not re-enumerate the subtree — got: {paths:?}"
        );
        let dup = result
            .errors
            .iter()
            .find(|e| {
                matches!(
                    e.error,
                    adpa_core::error::CoreError::ReparseDuplicateTarget(_)
                )
            })
            .expect("the duplicate route must surface as a typed diagnostic");
        let msg = format!("{}", dup.error).to_ascii_lowercase();
        assert!(
            msg.contains(&link.to_string_lossy().to_ascii_lowercase()),
            "duplicate diagnostic must name the first namespace path: {msg}"
        );
        assert!(
            msg.contains("not a cycle"),
            "duplicate diagnostic must distinguish itself from a cycle: {msg}"
        );
    }

    /// Creates an NTFS junction `link → target` and fails LOUDLY when that
    /// is not possible. The old silent `return` made audit-critical reparse
    /// coverage look green on runners that never exercised it (deep review
    /// 2026-07-04, F5). `mklink /J` needs no admin rights — a failure here
    /// means the environment genuinely cannot run this test, and that must
    /// be visible, not swallowed.
    fn mklink_junction(link: &std::path::Path, target: &std::path::Path) {
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
        assert!(
            status.success(),
            "mklink /J '{}' '{}' failed ({status}) — junction tests REQUIRE the \
             ability to create NTFS junctions (no admin rights needed); a silent \
             skip would fake coverage of audit-critical reparse handling (F5)",
            link.display(),
            target.display()
        );
    }

    /// Review 2026-07-04 F2 acceptance case: TWO junctions to the same
    /// (out-of-tree) target are not cyclic. The first route enumerates the
    /// content; the second must surface as a typed duplicate-target
    /// diagnostic naming the first route — not as a bogus "loop", and not
    /// as a second silent enumeration.
    #[test]
    fn walker_reports_second_junction_to_same_target_as_duplicate_not_cycle() {
        use std::path::PathBuf;

        let stamp = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let base: PathBuf = std::env::temp_dir().join(format!("adpa-dup-{stamp}"));
        let _ = std::fs::remove_dir_all(&base);
        // `shared` lives OUTSIDE the walk root, so the two junctions are the
        // only routes to it.
        let shared = base.join("shared");
        let root = base.join("root");
        let link_a = root.join("link_a");
        let link_b = root.join("link_b");
        std::fs::create_dir_all(shared.join("inside")).expect("create shared tree");
        std::fs::create_dir_all(&root).expect("create walk root");
        mklink_junction(&link_a, &shared);
        mklink_junction(&link_b, &shared);

        let result = walk(&root.to_string_lossy(), &unlimited());
        let _ = std::fs::remove_dir_all(&base);

        let paths: Vec<String> = result
            .objects
            .iter()
            .map(|o| o.path.0.to_ascii_lowercase())
            .collect();
        let inside_a = link_a.join("inside").to_string_lossy().to_ascii_lowercase();
        let inside_b = link_b.join("inside").to_string_lossy().to_ascii_lowercase();
        assert!(
            paths.iter().any(|p| p == &inside_a),
            "first junction route must enumerate the content — got: {paths:?}"
        );
        assert!(
            !paths.iter().any(|p| p == &inside_b),
            "second route must not re-enumerate — got: {paths:?}"
        );
        // Both link objects themselves are in the result with their DACLs.
        assert!(paths
            .iter()
            .any(|p| p == &link_b.to_string_lossy().to_ascii_lowercase()));

        assert!(
            !result
                .errors
                .iter()
                .any(|e| matches!(e.error, adpa_core::error::CoreError::ReparseCycle(_))),
            "two independent junctions to one target are NOT a cycle"
        );
        let dup = result
            .errors
            .iter()
            .find(|e| {
                matches!(
                    e.error,
                    adpa_core::error::CoreError::ReparseDuplicateTarget(_)
                )
            })
            .expect("second route must surface as a typed duplicate diagnostic");
        // WalkError paths of child entries carry the `\\?\` long-path prefix
        // (pre-existing behavior for all child error paths) — strip it for
        // the comparison.
        let dup_path = dup
            .path
            .to_ascii_lowercase()
            .trim_start_matches(r"\\?\")
            .to_owned();
        assert_eq!(
            dup_path,
            link_b.to_string_lossy().to_ascii_lowercase(),
            "the diagnostic must sit on the second route"
        );
        assert!(
            format!("{}", dup.error)
                .to_ascii_lowercase()
                .contains(&link_a.to_string_lossy().to_ascii_lowercase()),
            "the diagnostic must name the first route"
        );
    }

    // ----------------------------------------------------------------
    // LoopDetector — OS-free unit tests (review 2026-07-04, F5: the
    // cycle/duplicate decision must be validatable without mklink).
    // ----------------------------------------------------------------

    #[test]
    fn loop_detector_duplicate_after_leave_names_first_path() {
        let mut d = super::LoopDetector::new();
        assert_eq!(
            d.enter("c:\\shared", "C:\\root\\link_a"),
            super::DescendDecision::Fresh
        );
        d.leave();
        match d.enter("c:\\shared", "C:\\root\\link_b") {
            super::DescendDecision::DuplicateTarget { first_path } => {
                assert_eq!(first_path, "C:\\root\\link_a");
            }
            other => panic!("expected DuplicateTarget, got {other:?}"),
        }
    }

    #[test]
    fn loop_detector_ancestor_on_active_chain_is_cycle() {
        let mut d = super::LoopDetector::new();
        assert_eq!(d.enter("c:\\a", "C:\\a"), super::DescendDecision::Fresh);
        assert_eq!(
            d.enter("c:\\a\\b", "C:\\a\\b"),
            super::DescendDecision::Fresh
        );
        assert_eq!(
            d.enter("c:\\a", "C:\\a\\b\\link"),
            super::DescendDecision::Cycle,
            "re-entering an ancestor of the ACTIVE chain is a real cycle"
        );
    }

    #[test]
    fn loop_detector_left_sibling_is_duplicate_not_cycle() {
        let mut d = super::LoopDetector::new();
        assert_eq!(d.enter("c:\\a", "C:\\a"), super::DescendDecision::Fresh);
        assert_eq!(
            d.enter("c:\\a\\b", "C:\\a\\b"),
            super::DescendDecision::Fresh
        );
        d.leave(); // done with c:\a\b — no longer on the active chain
        match d.enter("c:\\a\\b", "C:\\a\\c_link") {
            super::DescendDecision::DuplicateTarget { first_path } => {
                assert_eq!(first_path, "C:\\a\\b");
            }
            other => panic!(
                "a completed sibling reached again is a duplicate, not a cycle — got {other:?}"
            ),
        }
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
        // `b` is a junction back to `root` — once the walker enters `b`,
        // without loop detection it would start over from `root`.
        mklink_junction(&b, &root);

        let result = walk(&root.to_string_lossy(), &unlimited());
        let _ = std::fs::remove_dir_all(&root);

        // The cycle must surface as the TYPED cycle error (not as a
        // duplicate route, and not silently) with an explanatory message.
        let cycle = result
            .errors
            .iter()
            .find(|e| matches!(e.error, adpa_core::error::CoreError::ReparseCycle(_)))
            .unwrap_or_else(|| {
                panic!(
                    "loop junction must produce a typed ReparseCycle error, got: {:?}",
                    result
                        .errors
                        .iter()
                        .map(|e| format!("{}", e.error))
                        .collect::<Vec<_>>()
                )
            });
        let msg = format!("{}", cycle.error);
        assert!(
            msg.contains("loop"),
            "the cycle error must explain the loop: {msg}"
        );
    }
}
