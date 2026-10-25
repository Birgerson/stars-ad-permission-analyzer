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

use adpa_core::{
    error::CoreError,
    model::{FileSystemObject, LinkInfo, LinkKind},
};
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

/// `true` when `path` is reached over SMB (a UNC path, with or without the
/// `\\?\UNC\` long-path prefix).
fn is_remote_path(path: &str) -> bool {
    validation::path::to_windows_api_path(path)
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\UNC\"))
}

/// Chooses the key the loop detector compares (ADR 0062). Remote scans use
/// the volume-serial + file-ID identity when the server provides one;
/// otherwise — and always for local scans — the canonical path, exactly as
/// before. Pure, so the selection rule is unit-testable.
fn select_loop_key(remote: bool, file_identity: Option<String>, canonical: &str) -> String {
    match (remote, file_identity) {
        (true, Some(id)) => id,
        _ => canonical.to_owned(),
    }
}

/// How a second route to an already enumerated directory was recognized —
/// which decides what its diagnostic may claim (ADR 0058, ADR 0062).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DuplicateRoute<'a> {
    /// Local scan: this path is a reparse point resolving to `target`.
    LocalLink { target: &'a str },
    /// Local scan: a plain directory that a reparse point led to first.
    LocalDirectory,
    /// Scan over SMB. The server reports neither reliably whether a
    /// directory is a reparse point nor the resolved path of a junction —
    /// the lab saw the flag of one junction missing in 25 of 37 runs and
    /// the resolved path then being the link's own (ADR 0062). So the
    /// diagnostic claims neither, only the identity that matched: volume
    /// serial + file ID, or — when the server gives none — the path.
    Remote { by_file_id: bool },
}

impl<'a> DuplicateRoute<'a> {
    /// The route kind of a directory the detector found again.
    fn classify(remote: bool, by_file_id: bool, is_reparse: bool, canonical: &'a str) -> Self {
        match (remote, is_reparse) {
            (true, _) => DuplicateRoute::Remote { by_file_id },
            (false, true) => DuplicateRoute::LocalLink { target: canonical },
            (false, false) => DuplicateRoute::LocalDirectory,
        }
    }
}

/// What an unresolvable junction or symbolic link means, from the Windows
/// error of resolving it and — when it could be read — what the link
/// stores. Pure.
fn unresolved_reparse_error(
    os_error: Option<i32>,
    link: Option<&LinkInfo>,
    remote: bool,
) -> CoreError {
    const TAIL: &str = "Recursion stopped at this junction/link. The object itself is in the \
                        result with its DACL; objects behind the link were not enumerated.";
    // Lab 2026-10-25: over SMB, Windows follows a symbolic link on the
    // client. An absolute target — a path of the server's own disk — is
    // resolved on this machine: error 1463 where this machine has the drive
    // (remote-to-local evaluation is disabled by default), error 3 where it
    // has not. Neither says anything about the server's folder.
    if let Some(l) = link.filter(|l| {
        remote && l.kind == LinkKind::SymbolicLink && !l.relative && is_drive_path(&l.target)
    }) {
        let why = match os_error {
            Some(1463) => "its symbolic link evaluation policy does not allow that (Windows \
                           error 1463: \"remote to local\", disabled by default; see `fsutil \
                           behavior query SymlinkEvaluation`)"
                .to_owned(),
            Some(code @ (2 | 3)) => format!("that path does not exist here (Windows error {code})"),
            Some(code) => format!("that failed (Windows error {code})"),
            None => "that failed".to_owned(),
        };
        return CoreError::ReparseNotFollowed(format!(
            "this symbolic link points to {target}, a path on the server's own disk. Over SMB, \
             Windows follows a symbolic link on the client, so this machine resolved {target} on \
             itself: {why}. No SMB client reaches the server's folder through this link, and \
             whether that folder exists on the server cannot be seen over SMB. {TAIL}",
            target = l.target
        ));
    }
    // "this junction (→ X)" where the target is known.
    let what = match link {
        Some(l) if l.kind == LinkKind::Junction => format!("this junction (→ {})", l.target),
        Some(l) => format!("this symbolic link (→ {})", l.target),
        None => "this junction/link".to_owned(),
    };
    if let Some(l) = link {
        match os_error {
            Some(1463) => {
                return CoreError::ReparseNotFollowed(format!(
                    "this machine's symbolic link evaluation policy does not allow following \
                     {what} (Windows error 1463; see `fsutil behavior query SymlinkEvaluation`). \
                     A client with the same policy cannot follow it either. {TAIL}"
                ))
            }
            Some(code @ (2 | 3)) => {
                // A junction is resolved by the computer that holds it, a
                // relative symbolic link on the share itself: the target is
                // missing there.
                let place = if l.kind == LinkKind::Junction && remote {
                    " on the server"
                } else {
                    ""
                };
                return CoreError::PathNotFound(format!(
                    "the target of {what} does not exist{place} (Windows error {code}) — a broken \
                     link. {TAIL}"
                ));
            }
            _ => {}
        }
    }
    match os_error {
        // ERROR_SYMLINK_CLASS_DISABLED — lab 2026-10-24, a symbolic link
        // over SMB with Windows' default policy.
        Some(1463) => CoreError::ReparseNotFollowed(format!(
            "this machine's symbolic link evaluation policy does not allow following this link \
             type (Windows error 1463 — e.g. a link on a share that points to a local path of the \
             server, \"remote to local\", which Windows disables by default; see `fsutil \
             behavior query SymlinkEvaluation`). A client with the same policy cannot follow it \
             either. {TAIL}"
        )),
        Some(5) => CoreError::AccessDenied(format!(
            "the target of {what} could not be opened (Windows error 5, access denied). {TAIL}"
        )),
        // The link itself could not be read: over SMB, "not found" does not
        // tell a broken link from a symbolic link to the server's own disk.
        Some(code @ (2 | 3)) if remote => CoreError::PathNotFound(format!(
            "the target of this junction/link was not found (Windows error {code}): the link is \
             broken, or it is a symbolic link to a path on the server's own disk, which Windows \
             resolves on this machine over SMB. The link could not be read to tell which. {TAIL}"
        )),
        Some(code @ (2 | 3)) => CoreError::PathNotFound(format!(
            "the target of this junction/link does not exist (Windows error {code}) — a broken \
             link. {TAIL}"
        )),
        // ERROR_CANT_RESOLVE_FILENAME — more reparse traversals than Windows
        // allows (a loop, known limitation L14).
        Some(1921) => CoreError::ReparseNotFollowed(format!(
            "Windows stopped resolving this link after too many reparse points (Windows error \
             1921 — a loop of links). {TAIL}"
        )),
        Some(code) => CoreError::ReparseNotFollowed(format!(
            "the target of {what} could not be resolved (Windows error {code}). {TAIL}"
        )),
        None => CoreError::ReparseNotFollowed(format!(
            "the target of {what} could not be resolved. {TAIL}"
        )),
    }
}

/// A link of a share that Windows resolved to a path of this machine (lab
/// 2026-10-25). Over SMB, a symbolic link is followed by the client; with
/// remote-to-local evaluation enabled here, an absolute target such as
/// `C:\Data` reaches this computer's own folder. Its content is not on the
/// server, so it is not enumerated. Pure.
fn local_resolution_error(resolved: &str, link: Option<&LinkInfo>) -> CoreError {
    let stored = link.map_or(String::new(), |l| format!(" (it stores {})", l.target));
    CoreError::ReparseNotFollowed(format!(
        "this link{stored} resolves to {resolved} on this machine, not on the server: over SMB, \
         Windows follows a symbolic link on the client, and this machine's symbolic link \
         evaluation policy allows \"remote to local\" (see `fsutil behavior query \
         SymlinkEvaluation`). What it reaches is this computer's own folder, so it was not \
         enumerated as part of the share. The link object itself is in the result with its \
         DACL. Which folder the link reaches on the server cannot be seen over SMB."
    ))
}

/// `C:\…` — a path on a drive of the computer that resolves it. Pure.
fn is_drive_path(path: &str) -> bool {
    let mut chars = path.chars();
    matches!(
        (chars.next(), chars.next(), chars.next()),
        (Some(d), Some(':'), Some('\\')) if d.is_ascii_alphabetic()
    )
}

/// ADR 0085: the reader-facing reason when a directory is served from
/// another share than the scan root, `None` when it is the same share (or
/// either side is unknown — no claim without evidence). Pure.
fn other_share_message(
    root_share: Option<&(String, String)>,
    final_path: Option<&str>,
) -> Option<String> {
    let (root_server, root_name) = root_share?;
    let final_path = final_path?;
    let (server, share) = validation::path::parse_unc_components(final_path)?;
    if server.eq_ignore_ascii_case(root_server) && share.eq_ignore_ascii_case(root_name) {
        return None;
    }
    Some(format!(
        "this directory is served from \\\\{server}\\{share}, not from the share of the scan root \
         (\\\\{root_server}\\{root_name}) — a folder of a DFS namespace or a link to another \
         share. Its share permissions and local groups are those of that share's server, so it \
         was not evaluated in this scan and its content was not enumerated; scan this path on \
         its own."
    ))
}

/// The diagnostic for a second route to a directory already enumerated in
/// this scan under `first_path` (ADR 0058). Pure, so every wording is
/// unit-testable.
fn duplicate_route_message(first_path: &str, route: DuplicateRoute<'_>) -> String {
    let first = validation::path::strip_long_path_prefix(first_path);
    match route {
        DuplicateRoute::LocalLink { target } => format!(
            "Reparse point target already enumerated in this scan under '{first}' — subtree not enumerated again under this namespace path (duplicate target, not a cycle). Target: {}. The link object itself is in the result with its DACL.",
            validation::path::strip_long_path_prefix(target)
        ),
        DuplicateRoute::LocalDirectory => format!(
            "Directory already enumerated in this scan under '{first}', reached there through a reparse point — subtree not enumerated again under this path (duplicate route, not a cycle). The directory itself is in the result with its DACL."
        ),
        DuplicateRoute::Remote { by_file_id } => {
            let identity = if by_file_id {
                "same volume serial and file ID"
            } else {
                "same resolved path"
            };
            format!(
                "Directory already enumerated in this scan under '{first}' — this path leads to the same directory ({identity}); its subtree is not enumerated again (duplicate route, not a cycle). The object at this path is in the result with its DACL."
            )
        }
    }
}

/// The walk's decision for a directory about to be descended into —
/// produced by [`LoopDetector::enter`].
#[derive(Debug, PartialEq, Eq)]
enum DescendDecision {
    /// Not seen before — descend. The detector recorded the entry; the
    /// caller must pair it with [`LoopDetector::leave`] when the subtree
    /// (or the depth-limited stop) is done.
    Fresh,
    /// The identity is an **ancestor on the active recursion chain** —
    /// descending would recurse forever. A real cycle. `ancestor_path` is
    /// the namespace path of that ancestor, so the diagnostic can name the
    /// real target even when the link's own resolved path is unreliable
    /// (over SMB — ADR 0062).
    Cycle { ancestor_path: String },
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
    /// `(identity, namespace path)` of each directory on the active chain.
    chain: Vec<(String, String)>,
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
    fn enter(&mut self, identity: &str, namespace_path: &str) -> DescendDecision {
        if let Some((_, ancestor)) = self.chain.iter().find(|(id, _)| id == identity) {
            return DescendDecision::Cycle {
                ancestor_path: ancestor.clone(),
            };
        }
        if let Some(first) = self.seen_first_path.get(identity) {
            return DescendDecision::DuplicateTarget {
                first_path: first.clone(),
            };
        }
        self.seen_first_path
            .insert(identity.to_owned(), namespace_path.to_owned());
        self.chain
            .push((identity.to_owned(), namespace_path.to_owned()));
        DescendDecision::Fresh
    }

    /// Pops the innermost chain entry — pairs with a `Fresh` result of
    /// [`Self::enter`].
    fn leave(&mut self) {
        self.chain.pop();
    }
}

/// One pending unit of work in the iterative walk (see [`walk_dir`]).
///
/// `Leave` pairs with a `Visit` that got a `Fresh` decision from the loop
/// detector: it is pushed onto the stack immediately *before* that
/// `Visit`'s children, so — because the stack is LIFO — it is only popped
/// (and `detector.leave()` only runs) once every item below it (the whole
/// subtree) has been fully processed. This is the same position the old
/// recursive version reached by falling through to `detector.leave()`
/// after its children loop returned.
///
/// `DirEntryError` exists so a single `std::fs::read_dir` pass can be
/// turned into stack entries *in order* without emitting anything early:
/// pushing every entry (error or child) in the same relative sequence they
/// came from `read_dir`, then reversing before pushing, reproduces the
/// exact depth-first interleaving the old recursive version produced
/// (error for entry N emitted, then entry N+1's whole subtree, …).
enum WalkWork {
    Visit {
        path: String,
        parent_canonical: Option<String>,
        depth: u32,
        /// ADR 0088: the parent's directory listing marks this entry as a
        /// junction or symbolic link. Over SMB the listing is reliable where
        /// the attributes of an open are not (the open follows the link).
        listed_as_link: bool,
    },
    Leave,
    DirEntryError(WalkError),
}

/// Walks one directory subtree, starting at `path`.
///
/// FS2-1 (2026-10-06): this used to recurse by plain function call, one
/// stack frame per directory level, with no depth ceiling — `WalkConfig`'s
/// default `max_depth: None` is also the common case for a full audit, so
/// a real (if unusual) sufficiently deep tree — nested build caches,
/// backup trees, or just a lot of them — could overflow the thread stack
/// instead of producing a bounded, reportable result. This version uses
/// an explicit `Vec` as the DFS stack so traversal depth is bounded only
/// by available heap memory, not by stack frames. Traversal order, error
/// reporting, cancellation behavior and loop/duplicate-target detection
/// are unchanged — see [`WalkWork`] for how the `Leave`/`detector.leave()`
/// pairing is preserved without recursion.
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
    // Decided once per walk from the root: everything below a UNC root is
    // reached over SMB too.
    let remote = is_remote_path(path);
    // ADR 0085: the share the root is really served from. A directory below
    // it that the redirector opens on another share (a DFS folder of a
    // namespace root) is outside this scan's share context.
    let root_share = if remote {
        crate::file_id::final_unc_path(path)
            .as_deref()
            .and_then(validation::path::parse_unc_components)
            .or_else(|| validation::path::parse_unc_components(path))
    } else {
        None
    };
    let mut stack = vec![WalkWork::Visit {
        path: path.to_owned(),
        parent_canonical: parent_canonical.map(str::to_owned),
        depth: current_depth,
        listed_as_link: false,
    }];

    while let Some(work) = stack.pop() {
        // Checked before processing every unit of work — a Visit, a
        // Leave, or a deferred directory-entry error — exactly the same
        // granularity as the old per-recursive-call check. On
        // cancellation the whole walk ends here: any `Leave` entries
        // still on the stack are abandoned along with it, which is fine
        // because `detector` is dropped by the caller right after this
        // function returns and its partially-unwound `chain` is never
        // consulted again (same reasoning the old version documented at
        // its own early-return).
        if cancel.is_cancelled() {
            return;
        }

        let (path, parent_canonical, current_depth, listed_as_link) = match work {
            WalkWork::Leave => {
                detector.leave();
                continue;
            }
            WalkWork::DirEntryError(err) => {
                warn!(path = %err.path, error = %err.error, "Directory entry error");
                on_item(WalkItem::Error(err));
                continue;
            }
            WalkWork::Visit {
                path,
                parent_canonical,
                depth,
                listed_as_link,
            } => (path, parent_canonical, depth, listed_as_link),
        };

        match read_file_system_object_cached(&path, sd_cache) {
            Err(e) => {
                warn!(path, error = %e, "Cannot read security descriptor");
                on_item(WalkItem::Error(WalkError {
                    path: path.clone(),
                    error: e,
                }));
            }
            Ok(mut fso) => {
                let is_dir = fso.is_directory;
                let is_reparse = fso.is_reparse_point;
                debug!(path, is_dir, is_reparse, depth = current_depth, "Read FSO");
                // ADR 0088: a link the attributes did not show (over SMB the
                // open follows it) but the directory listing did.
                if fso.link.is_none() && listed_as_link {
                    fso.link = crate::file_id::link_target(&path);
                }
                // One open per remote directory: its identity for the loop
                // detection (ADR 0062) and the share it is served from.
                let probe = (remote && is_dir).then(|| crate::file_id::probe_directory(&path));
                // ADR 0088: without an identity a second route here is not
                // recognized. The row says so only where the walk descends —
                // a folder it cannot enter cannot be listed twice.
                let identity_reason = probe
                    .as_ref()
                    .filter(|p| p.identity.is_none())
                    .and_then(|p| p.identity_error.clone());
                if let Some(reason) = &identity_reason {
                    warn!(path, reason, "Directory identity could not be read");
                }
                let link = fso.link.clone();
                // The row is emitted once it is known whether the walk
                // descends — always before its errors and its children.
                let mut pending = Some(fso);
                macro_rules! emit_object {
                    ($descends:expr) => {
                        if let Some(mut object) = pending.take() {
                            if $descends {
                                object.identity_unknown = identity_reason.clone();
                            }
                            on_item(WalkItem::Object(object));
                        }
                    };
                }
                if parent_canonical.is_some() {
                    if let Some(message) = other_share_message(
                        root_share.as_ref(),
                        probe.as_ref().and_then(|p| p.final_path.as_deref()),
                    ) {
                        info!(
                            path,
                            "Directory is served from another share — not enumerated"
                        );
                        on_item(WalkItem::Error(WalkError {
                            path: path.clone(),
                            error: CoreError::OtherShare(message),
                        }));
                        continue;
                    }
                }

                // An unresolvable reparse target stops here for files and
                // directories alike — visible, not silent, with the reason
                // Windows gives (not every failure is missing access).
                if is_reparse {
                    let api_path = validation::path::to_windows_api_path(&path);
                    match std::fs::canonicalize(&api_path) {
                        Err(e) => {
                            warn!(path, error = %e, "Reparse point target could not be resolved");
                            emit_object!(false);
                            // What the link stores tells who resolves it (lab
                            // 2026-10-25: "broken" for a symbolic link the
                            // client resolved on itself).
                            on_item(WalkItem::Error(WalkError {
                                path: path.clone(),
                                error: unresolved_reparse_error(
                                    e.raw_os_error(),
                                    link.as_ref(),
                                    remote,
                                ),
                            }));
                            continue;
                        }
                        // A link of the share that reaches a folder of this
                        // machine: not part of the share.
                        Ok(resolved) if remote => {
                            let resolved = validation::path::strip_long_path_prefix(
                                &resolved.to_string_lossy(),
                            );
                            if validation::path::parse_unc_components(&resolved).is_none() {
                                warn!(path, resolved, "Link of the share resolves to this machine");
                                emit_object!(false);
                                on_item(WalkItem::Error(WalkError {
                                    path: path.clone(),
                                    error: local_resolution_error(&resolved, link.as_ref()),
                                }));
                                continue;
                            }
                        }
                        Ok(_) => {}
                    }
                }

                // Only directories recurse, so only directories need the cycle /
                // duplicate-target bookkeeping (a file symlink cannot loop).
                if !is_dir {
                    emit_object!(false);
                    continue;
                }

                // Canonical identity of this directory. Reparse points and the
                // root resolve via the filesystem (the reparse *target* is the
                // identity); plain children derive from the parent — same
                // lowercased, prefix-consistent form without a syscall per
                // directory.
                let canonical = if is_reparse || parent_canonical.is_none() {
                    match canonicalize_path(&path) {
                        Some(c) => c,
                        // Root that cannot be canonicalized (rare: virtual FS):
                        // best-effort identity so the walk still runs.
                        None => path.to_ascii_lowercase(),
                    }
                } else {
                    let component = std::path::Path::new(&path)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_ascii_lowercase());
                    match (parent_canonical.as_deref(), component) {
                        (Some(parent), Some(name)) => {
                            format!("{parent}{}{name}", std::path::MAIN_SEPARATOR)
                        }
                        // No derivable component — fall back to the filesystem.
                        _ => canonicalize_path(&path).unwrap_or_else(|| path.to_ascii_lowercase()),
                    }
                };

                // Over SMB the canonical path of a junction is unreliable
                // (ADR 0062), so remote scans key directories by volume
                // serial + file ID; `canonical` stays the display form.
                let file_identity = probe.and_then(|p| p.identity);
                let keyed_by_file_id = remote && file_identity.is_some();
                let loop_key = select_loop_key(remote, file_identity, &canonical);
                debug!(path, canonical = %canonical, key = %loop_key, "Directory loop identity");

                match detector.enter(&loop_key, &path) {
                    DescendDecision::Cycle { ancestor_path } => {
                        let ancestor = validation::path::strip_long_path_prefix(&ancestor_path);
                        info!(
                            path,
                            target = %ancestor,
                            "Reparse point target is an ancestor of the active chain — cycle, recursion stopped"
                        );
                        emit_object!(false);
                        on_item(WalkItem::Error(WalkError {
                            path: path.clone(),
                            error: CoreError::ReparseCycle(format!(
                                "Reparse point target is an ancestor of the current traversal chain — descending would loop forever; recursion stopped at this junction/link. Target: {ancestor}. The object itself is in the result with its DACL."
                            )),
                        }));
                        continue;
                    }
                    DescendDecision::DuplicateTarget { first_path } => {
                        info!(
                            path,
                            first_path = %first_path,
                            key = %loop_key,
                            "Directory already enumerated under another namespace path — duplicate route, not enumerated again"
                        );
                        // Over SMB neither the reparse flag nor the resolved
                        // path is reliable (ADR 0062): the message claims only
                        // what the match proves.
                        let route = DuplicateRoute::classify(
                            remote,
                            keyed_by_file_id,
                            is_reparse,
                            &canonical,
                        );
                        emit_object!(false);
                        on_item(WalkItem::Error(WalkError {
                            path: path.clone(),
                            error: CoreError::ReparseDuplicateTarget(duplicate_route_message(
                                &first_path,
                                route,
                            )),
                        }));
                        continue;
                    }
                    DescendDecision::Fresh => {}
                }

                // Pairs with the `Fresh` entry above — pushed *before* any
                // children so it is only popped (and `detector.leave()`
                // called) once this directory's whole subtree — pushed
                // next, on top of it — has been fully processed.
                stack.push(WalkWork::Leave);

                let depth_ok = config.max_depth.is_none_or(|max| current_depth < max);
                if depth_ok {
                    // Apply the long-path prefix before `read_dir` so that
                    // directories with paths > MAX_PATH can be enumerated
                    // reliably. The `entry.path()` results carry the prefix
                    // forward — `to_windows_api_path` recognises that on the
                    // next step (idempotent) and does not double-prefix.
                    let api_path = validation::path::to_windows_api_path(&path);
                    match std::fs::read_dir(&api_path) {
                        Err(e) => {
                            warn!(path, error = %e, "Cannot enumerate directory");
                            emit_object!(false);
                            on_item(WalkItem::Error(WalkError {
                                path: path.clone(),
                                error: CoreError::AccessDenied(format!(
                                    "Cannot enumerate directory: {e}"
                                )),
                            }));
                        }
                        Ok(entries) => {
                            // The walk descends: only here can a second
                            // route go unrecognized.
                            emit_object!(true);
                            // Collect in read_dir's own order, then push in
                            // reverse — the LIFO stack then pops them back
                            // in original order, so the next directory
                            // listing's entries and this directory's own
                            // `Leave` interleave exactly like the old
                            // recursive call sequence did.
                            let mut children: Vec<WalkWork> = Vec::new();
                            for entry_result in entries {
                                match entry_result {
                                    Err(e) => {
                                        children.push(WalkWork::DirEntryError(WalkError {
                                            path: path.clone(),
                                            error: CoreError::AccessDenied(format!(
                                                "Directory entry error: {e}"
                                            )),
                                        }));
                                    }
                                    Ok(entry) => {
                                        let child = entry.path().to_string_lossy().into_owned();
                                        // On Windows a junction counts as a
                                        // symbolic link here (a name-surrogate
                                        // reparse point), from the listing's
                                        // own data — no extra call.
                                        let listed_as_link =
                                            entry.file_type().is_ok_and(|t| t.is_symlink());
                                        children.push(WalkWork::Visit {
                                            path: child,
                                            parent_canonical: Some(canonical.clone()),
                                            depth: current_depth + 1,
                                            listed_as_link,
                                        });
                                    }
                                }
                            }
                            for child in children.into_iter().rev() {
                                stack.push(child);
                            }
                        }
                    }
                }
                // Not entered (the depth limit): the row without the marker.
                emit_object!(false);
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

    // --- FS2-1: no recursion-depth ceiling ---

    /// FS2-1 (2026-10-06): the walker used to recurse by plain function
    /// call, one stack frame per directory level, with no depth ceiling —
    /// `WalkConfig::max_depth: None` (unlimited) is also the common case
    /// for a full audit. 2,000 nested one-character directories stay well
    /// inside the `\\?\` long-path budget (~4,000 chars) and are already
    /// far deeper than any real directory tree — but are a real, if
    /// unusual, tree shape (deeply nested build caches, backup trees).
    /// The explicit-stack walk must complete it correctly regardless —
    /// depth is now bounded by heap, not by call-stack frames.
    #[test]
    fn walk_handles_pathologically_deep_tree_without_stack_overflow() {
        use std::path::PathBuf;

        const DEPTH: usize = 2_000;
        let stamp = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let root: PathBuf = std::env::temp_dir().join(format!("adpa-deep-{stamp}"));
        let _ = std::fs::remove_dir_all(&root);

        // Create via the `\\?\` prefix so the creation calls themselves
        // don't trip over MAX_PATH; the test then scans *without* the
        // prefix, same as the long-path test above.
        let mut deep = root.clone();
        for _ in 0..DEPTH {
            deep.push("d");
        }
        let deep_with_prefix = PathBuf::from(format!(r"\\?\{}", deep.to_string_lossy()));
        std::fs::create_dir_all(&deep_with_prefix).expect("create deep dir");

        let root_str = root.to_string_lossy().into_owned();
        let result = walk(&root_str, &unlimited());

        let _ = std::fs::remove_dir_all(PathBuf::from(format!(r"\\?\{root_str}")));

        assert!(
            result.errors.is_empty(),
            "walk of a {DEPTH}-level tree must produce no errors — got: {:?}",
            result
                .errors
                .iter()
                .map(|e| format!("{}: {}", e.path, e.error))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            result.objects.len(),
            DEPTH + 1,
            "expected root + {DEPTH} nested directories, got {}",
            result.objects.len()
        );
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

        // ADR 0088: the junction's own row names what it stores; the real
        // directory is no link, and a local scan probes no identity.
        let row = |p: &std::path::Path| {
            result
                .objects
                .iter()
                .find(|o| o.path.0.eq_ignore_ascii_case(&p.to_string_lossy()))
                .expect("a row for the path")
        };
        let stored = row(&link)
            .link
            .as_ref()
            .expect("the junction's stored target");
        assert_eq!(stored.kind, adpa_core::model::LinkKind::Junction);
        assert!(
            stored
                .target
                .eq_ignore_ascii_case(&target.to_string_lossy()),
            "{stored:?}"
        );
        assert!(row(&target).link.is_none());
        assert!(result.objects.iter().all(|o| o.identity_unknown.is_none()));

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
        // `target` is a plain directory, not a link (review 2026-10-18).
        assert!(
            msg.contains("directory already enumerated") && !msg.contains("link object"),
            "a plain directory must not be called a link: {msg}"
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

    /// Locally a second link to an enumerated target names the first route
    /// and the resolved target; a plain directory a link led to first is not
    /// called a link.
    #[test]
    fn duplicate_route_message_on_a_local_scan() {
        use super::{duplicate_route_message, DuplicateRoute};
        let link = DuplicateRoute::classify(false, false, true, r"\\?\c:\shared");
        assert_eq!(
            link,
            DuplicateRoute::LocalLink {
                target: r"\\?\c:\shared"
            }
        );
        let msg = duplicate_route_message(r"\\?\C:\root\link_a", link);
        assert!(msg.contains(r"under 'C:\root\link_a'"), "{msg}");
        assert!(msg.contains(r"Target: c:\shared."), "{msg}");
        assert!(
            msg.contains("not a cycle") && msg.contains("link object"),
            "{msg}"
        );

        let dir = DuplicateRoute::classify(false, false, false, r"c:\root\target");
        assert_eq!(dir, DuplicateRoute::LocalDirectory);
        let msg = duplicate_route_message(r"\\?\C:\root\link", dir);
        assert!(msg.starts_with(r"Directory already enumerated in this scan under 'C:\root\link'"));
        assert!(
            msg.contains("reached there through a reparse point"),
            "{msg}"
        );
        assert!(msg.contains("not a cycle") && msg.contains("The directory itself"));
        assert!(
            !msg.contains("link object") && !msg.contains("Target:"),
            "{msg}"
        );
    }

    /// ADR 0062: over SMB neither the reparse flag nor a junction's resolved
    /// path is reliable — the lab saw "Target: …\spezial\link_zu_finance"
    /// (the link's own path) in 25 of 37 runs. The message claims only the
    /// identity that matched, whatever the flag says.
    #[test]
    fn duplicate_route_message_over_smb_claims_only_the_matched_identity() {
        use super::{duplicate_route_message, DuplicateRoute};
        let unreliable = r"\\?\unc\srv\data$\special\link_to_finance";
        for flag in [true, false] {
            let route = DuplicateRoute::classify(true, true, flag, unreliable);
            assert_eq!(route, DuplicateRoute::Remote { by_file_id: true });
            let msg = duplicate_route_message(r"\\?\UNC\srv\data$\Departments\Finance", route);
            assert!(
                msg.contains(r"under '\\srv\data$\Departments\Finance'"),
                "{msg}"
            );
            assert!(msg.contains("same volume serial and file ID"), "{msg}");
            assert!(
                !msg.contains("Target:") && !msg.contains("link_to_finance"),
                "{msg}"
            );
            assert!(
                !msg.contains("reached there through"),
                "no claim about the route: {msg}"
            );
        }
        // A server without file IDs: the path matched.
        let route = DuplicateRoute::classify(true, false, true, unreliable);
        assert_eq!(route, DuplicateRoute::Remote { by_file_id: false });
        assert!(
            duplicate_route_message(r"\\?\UNC\srv\data$\a", route).contains("same resolved path")
        );
    }

    // --- ADR 0062 / FS3-1: loop identity for scans over SMB ---

    /// ADR 0085, lab 2026-10-24: in the namespace root `\\corp.test\dfs`
    /// (served from DC-01's share `dfs`) the folder `Projects` is opened on
    /// `\\FS-01.corp.test\DfsProj`.
    #[test]
    fn a_directory_on_another_share_is_named_with_both_shares() {
        use super::other_share_message;
        let root = ("WIN-MONCCCT07FT.corp.test".to_owned(), "dfs".to_owned());
        let m = other_share_message(Some(&root), Some(r"\\FS-01.corp.test\DfsProj"))
            .expect("another share");
        assert!(m.contains(r"\\FS-01.corp.test\DfsProj"), "{m}");
        assert!(m.contains(r"\\WIN-MONCCCT07FT.corp.test\dfs"), "{m}");
        assert!(m.contains("scan this path on its own"), "{m}");
        // Same share, other case and a sub-path: no claim.
        assert_eq!(
            other_share_message(Some(&root), Some(r"\\win-moncccT07ft.CORP.test\DFS\Sub")),
            None
        );
        // Unknown on either side: no claim.
        assert_eq!(other_share_message(None, Some(r"\\FS-01\DfsProj")), None);
        assert_eq!(other_share_message(Some(&root), None), None);
    }

    /// Lab 2026-10-24: a symbolic link over SMB failed with error 1463 and
    /// was reported as "Access denied". Each Windows reason keeps its kind.
    #[test]
    fn an_unresolved_link_names_the_windows_reason() {
        use super::unresolved_reparse_error;
        use adpa_core::error::CoreError;
        let e = unresolved_reparse_error(Some(1463), None, true);
        assert!(
            matches!(&e, CoreError::ReparseNotFollowed(m) if m.contains("1463") && m.contains("SymlinkEvaluation")),
            "{e}"
        );
        assert!(matches!(
            unresolved_reparse_error(Some(5), None, true),
            CoreError::AccessDenied(_)
        ));
        for remote in [true, false] {
            assert!(matches!(
                unresolved_reparse_error(Some(2), None, remote),
                CoreError::PathNotFound(_)
            ));
            assert!(matches!(
                unresolved_reparse_error(Some(3), None, remote),
                CoreError::PathNotFound(_)
            ));
        }
        assert!(
            matches!(&unresolved_reparse_error(Some(1921), None, true), CoreError::ReparseNotFollowed(m) if m.contains("loop"))
        );
        assert!(
            matches!(&unresolved_reparse_error(Some(87), None, true), CoreError::ReparseNotFollowed(m) if m.contains("error 87"))
        );
        assert!(matches!(
            unresolved_reparse_error(None, None, true),
            CoreError::ReparseNotFollowed(_)
        ));
        for code in [Some(1463), Some(5), Some(2), None] {
            assert!(unresolved_reparse_error(code, None, true)
                .to_string()
                .contains("not enumerated"));
        }
    }

    /// Lab 2026-10-25: a symbolic link to `T:\…` on a share gave Windows
    /// error 3 on a client without a drive T: — reported as "a broken
    /// link", although the client had resolved the target on itself. What
    /// the link stores now decides the wording.
    #[test]
    fn an_unresolved_link_is_explained_by_what_it_stores() {
        use super::unresolved_reparse_error;
        use adpa_core::error::CoreError;
        use adpa_core::model::{LinkInfo, LinkKind};
        let link = |kind, target: &str, relative| LinkInfo {
            kind,
            target: target.to_owned(),
            relative,
        };
        let absolute = link(
            LinkKind::SymbolicLink,
            r"T:\Enterprise\Finance\P02_2021",
            false,
        );
        // Over SMB: resolved on this machine, not "broken".
        for code in [3, 2] {
            let e = unresolved_reparse_error(Some(code), Some(&absolute), true);
            let m = match &e {
                CoreError::ReparseNotFollowed(m) => m.clone(),
                other => panic!("{other}"),
            };
            assert!(
                m.contains(r"points to T:\Enterprise\Finance\P02_2021"),
                "{m}"
            );
            assert!(
                m.contains("server's own disk") && m.contains("on itself"),
                "{m}"
            );
            assert!(
                m.contains("does not exist here") && !m.contains("broken"),
                "{m}"
            );
            assert!(m.contains("cannot be seen over SMB"), "{m}");
        }
        let policy = unresolved_reparse_error(Some(1463), Some(&absolute), true).to_string();
        assert!(
            policy.contains("1463") && policy.contains("SymlinkEvaluation"),
            "{policy}"
        );
        assert!(
            policy.contains(r"T:\Enterprise\Finance\P02_2021"),
            "{policy}"
        );
        // Scanned locally, the same link with a missing target is broken.
        assert!(matches!(
            unresolved_reparse_error(Some(3), Some(&absolute), false),
            CoreError::PathNotFound(m) if m.contains("broken") && m.contains(r"→ T:\Enterprise")
        ));
        // A junction is resolved by the server: missing there means broken.
        let junction = link(LinkKind::Junction, r"T:\gone", false);
        assert!(matches!(
            unresolved_reparse_error(Some(3), Some(&junction), true),
            CoreError::PathNotFound(m) if m.contains("does not exist on the server") && m.contains(r"→ T:\gone")
        ));
        // A relative symbolic link is resolved on the share: broken.
        let relative = link(LinkKind::SymbolicLink, r"..\P02", true);
        assert!(matches!(
            unresolved_reparse_error(Some(3), Some(&relative), true),
            CoreError::PathNotFound(m) if m.contains("broken") && m.contains(r"→ ..\P02")
        ));
        // A link that could not be read, over SMB: both readings are named.
        let unknown = unresolved_reparse_error(Some(3), None, true).to_string();
        assert!(
            unknown.contains("broken") && unknown.contains("server's own disk"),
            "{unknown}"
        );
        // Access denied names the target where it is known.
        assert!(matches!(
            unresolved_reparse_error(Some(5), Some(&junction), true),
            CoreError::AccessDenied(m) if m.contains(r"→ T:\gone")
        ));
    }

    /// A symbolic link of the share that this machine resolves on itself
    /// (remote-to-local enabled) reaches a local folder: named, not walked.
    #[test]
    fn a_link_that_reaches_this_machine_is_named_not_walked() {
        use super::local_resolution_error;
        use adpa_core::error::CoreError;
        use adpa_core::model::{LinkInfo, LinkKind};
        let link = LinkInfo {
            kind: LinkKind::SymbolicLink,
            target: r"C:\Data".into(),
            relative: false,
        };
        let e = local_resolution_error(r"C:\Data", Some(&link));
        let m = match &e {
            CoreError::ReparseNotFollowed(m) => m.clone(),
            other => panic!("{other}"),
        };
        assert!(
            m.contains(r"(it stores C:\Data) resolves to C:\Data on this machine"),
            "{m}"
        );
        assert!(
            m.contains("remote to local") && m.contains("not enumerated"),
            "{m}"
        );
        assert!(m.contains("link object itself is in the result"), "{m}");
        // Without the stored target, the resolved path alone.
        let e = local_resolution_error(r"D:\x", None).to_string();
        assert!(
            e.contains(r"this link resolves to D:\x") && !e.contains("it stores"),
            "{e}"
        );
    }

    #[test]
    fn drive_paths_are_recognised() {
        use super::is_drive_path;
        assert!(is_drive_path(r"T:\Enterprise") && is_drive_path(r"c:\"));
        for p in [
            r"\\server\share",
            r"..\P02",
            "T:",
            "TT:\\x",
            r"\??\T:\x",
            "",
        ] {
            assert!(!is_drive_path(p), "{p}");
        }
    }

    #[test]
    fn remote_path_detection() {
        assert!(super::is_remote_path(r"\\server\share\dir"));
        assert!(super::is_remote_path(r"\\?\UNC\server\share\dir"));
        assert!(super::is_remote_path(r"\\?\unc\server\share"));
        assert!(!super::is_remote_path(r"C:\Data"));
        assert!(!super::is_remote_path(r"\\?\C:\Data"));
    }

    /// Remote scans key by file identity when the server provides one; in
    /// every other case the canonical path is used, exactly as before.
    #[test]
    fn loop_key_selection() {
        let fid = Some("fid:9c6e99436e9916dc:000000000000000200000000000071c3".to_owned());
        assert_eq!(
            super::select_loop_key(true, fid.clone(), r"\\?\unc\srv\s\loop\back"),
            "fid:9c6e99436e9916dc:000000000000000200000000000071c3"
        );
        assert_eq!(
            super::select_loop_key(true, None, r"\\?\unc\srv\s\loop"),
            r"\\?\unc\srv\s\loop",
            "no file identity from the server → path fallback"
        );
        assert_eq!(
            super::select_loop_key(false, fid, r"c:\loop"),
            r"c:\loop",
            "local scans keep the proven path identity"
        );
    }

    /// The lab failure mode (FS3-1): over SMB the junction's canonical path
    /// is the path it was opened through, so every level looks new — but
    /// the file identity repeats. Keyed by file identity the detector stops
    /// at the first repetition, and names the real ancestor.
    #[test]
    fn file_identity_catches_a_cycle_the_paths_hide() {
        let id = "fid:9c6e99436e9916dc:000000000000000200000000000071c3";
        let mut d = super::LoopDetector::new();
        assert_eq!(
            d.enter(id, r"\\?\UNC\srv\share\loop"),
            super::DescendDecision::Fresh
        );
        assert_eq!(
            d.enter(id, r"\\?\UNC\srv\share\loop\back"),
            super::DescendDecision::Cycle {
                ancestor_path: r"\\?\UNC\srv\share\loop".to_owned()
            }
        );
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
            super::DescendDecision::Cycle {
                ancestor_path: "C:\\a".to_owned()
            },
            "re-entering an ancestor of the ACTIVE chain is a real cycle, \
             and the decision names that ancestor's namespace path"
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
