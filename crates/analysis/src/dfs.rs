// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Paths through a DFS namespace (ADR 0085).
//!
//! Lab 2026-10-24: for `\\corp.test\dfs\Projects\Sub` the NTFS permissions
//! came from the folder target (FS-01) — the redirector follows the
//! referral — but the share permissions were read from the namespace's root
//! share on DC-01 (Everyone Read), and the local groups and policies from
//! the namespace server. A user with Modify through the target's share
//! (Change) was reported with Read & Execute.
//!
//! So a path is evaluated where Windows serves it: the path the redirector
//! really opens (`GetFinalPathNameByHandle`) is the evaluated path, and the
//! DFS client names the folder and its targets. A folder with more than one
//! target, or with unknown targets, leaves the result open — a client
//! referred to another target has that target's permissions.

use adpa_core::model::{DfsEvaluation, PermissionPath};
use share_scanner::dfs::DfsLookup;
use validation::path::parse_unc_components;

/// Where a path is evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationTarget {
    /// The path the analysis reads — the target path for a DFS path,
    /// otherwise the path as given.
    pub evaluated_path: String,
    /// Set for a path of a DFS namespace.
    pub dfs: Option<DfsEvaluation>,
}

impl EvaluationTarget {
    fn unchanged(path: &str) -> Self {
        Self {
            evaluated_path: path.to_owned(),
            dfs: None,
        }
    }
}

/// Resolves where `path` is evaluated. Opens the path once (read
/// attributes only) and asks this machine's DFS client — read-only.
pub fn resolve_evaluation_target(path: &str) -> EvaluationTarget {
    if parse_unc_components(path).is_none() {
        return EvaluationTarget::unchanged(path);
    }
    // The open comes first: for some name forms the DFS client knows the
    // folder only after the path was opened once (lab 2026-10-24).
    // Validated like any input: a value the OS returns is not trusted blindly.
    let final_path =
        fs_scanner::final_unc_path(path).filter(|p| validation::path::validate_path(p).is_ok());
    let lookup = share_scanner::dfs::dfs_client_link(path);
    decide(path, final_path.as_deref(), &lookup)
}

fn same_share(a: &str, b: &str) -> bool {
    match (parse_unc_components(a), parse_unc_components(b)) {
        (Some((sa, ha)), Some((sb, hb))) => {
            sa.eq_ignore_ascii_case(&sb) && ha.eq_ignore_ascii_case(&hb)
        }
        _ => false,
    }
}

/// The decision from the two answers. Pure.
///
/// - The redirector opened the path on its own share: not redirected —
///   evaluated as given (a plain UNC path, or a target path given directly).
/// - On another share: a DFS path, evaluated on that path. The DFS client's
///   folder names the other targets; without a consistent answer from it
///   they are unknown.
/// - The path could not be opened, but the DFS client names the folder and
///   its active target: evaluated on the active target (the remainder of the
///   path appended); without an active target, or when the path does not
///   start with the folder, the targets are unknown and the path is
///   evaluated as given.
/// - Otherwise: no evidence of DFS, evaluated as given.
pub fn decide(requested: &str, final_path: Option<&str>, lookup: &DfsLookup) -> EvaluationTarget {
    let link = match lookup {
        DfsLookup::Link(l) => Some(l),
        DfsLookup::NotDfs | DfsLookup::Failed(_) => None,
    };
    if let Some(fp) = final_path {
        if same_share(fp, requested) {
            return EvaluationTarget::unchanged(requested);
        }
        let (folder, other_targets, known) = match link {
            Some(l) => {
                let active: Vec<_> = l.targets.iter().filter(|t| t.active).collect();
                let consistent = active.len() == 1 && same_share(&active[0].unc(), fp);
                let others: Vec<String> = l
                    .targets
                    .iter()
                    .filter(|t| !same_share(&t.unc(), fp))
                    .map(|t| t.unc())
                    .collect();
                (Some(l.entry_path.clone()), others, consistent)
            }
            None => (None, Vec::new(), false),
        };
        return EvaluationTarget {
            evaluated_path: fp.to_owned(),
            dfs: Some(DfsEvaluation {
                requested: requested.to_owned(),
                target: fp.to_owned(),
                folder,
                other_targets,
                other_targets_known: known,
            }),
        };
    }
    let Some(l) = link else {
        return EvaluationTarget::unchanged(requested);
    };
    let active: Vec<_> = l.targets.iter().filter(|t| t.active).collect();
    let rest = strip_prefix_ignore_case(requested, &l.entry_path);
    match (active.as_slice(), rest) {
        ([a], Some(rest)) => {
            let target = format!("{}{rest}", a.unc());
            let others = l
                .targets
                .iter()
                .filter(|t| !t.active)
                .map(|t| t.unc())
                .collect();
            EvaluationTarget {
                evaluated_path: target.clone(),
                dfs: Some(DfsEvaluation {
                    requested: requested.to_owned(),
                    target,
                    folder: Some(l.entry_path.clone()),
                    other_targets: others,
                    other_targets_known: true,
                }),
            }
        }
        _ => EvaluationTarget {
            evaluated_path: requested.to_owned(),
            dfs: Some(DfsEvaluation {
                requested: requested.to_owned(),
                target: requested.to_owned(),
                folder: Some(l.entry_path.clone()),
                other_targets: l.targets.iter().map(|t| t.unc()).collect(),
                other_targets_known: false,
            }),
        },
    }
}

/// Puts the DFS step right after the user step of the explanation path —
/// every surface shows where the path was evaluated.
pub fn attach_step(path: &mut PermissionPath, d: &DfsEvaluation) {
    let folder = d
        .folder
        .as_deref()
        .map(|f| format!("the {}", DfsEvaluation::entry_label(f)))
        .unwrap_or_else(|| "a DFS namespace".to_owned());
    let step = format!(
        "DFS: {} lies in {folder}; evaluated on {}, the target this machine is referred to \
         (its share permissions, local groups and policies)",
        d.requested, d.target
    );
    let at = usize::from(!path.steps.is_empty());
    path.steps.insert(at, step);
}

/// `path` without the leading `prefix` (ASCII case ignored), only at a
/// path-component boundary; `None` when `path` does not start with it.
fn strip_prefix_ignore_case<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let head = path.get(..prefix.len())?;
    if !head.eq_ignore_ascii_case(prefix) {
        return None;
    }
    let rest = &path[prefix.len()..];
    (rest.is_empty() || rest.starts_with('\\')).then_some(rest)
}

/// For one object of a scan whose root was redirected: the path the reader
/// asked for (`requested_root` + the part below `evaluated_root`) and the
/// object's own DFS evaluation. `None` when `path` is not below the
/// evaluated root (not expected from the walker; such a path stays as it is).
pub fn for_scanned_object(path: &str, root: &DfsEvaluation) -> Option<(String, DfsEvaluation)> {
    // The walker reports some paths in the long-path form (`\\?\UNC\â€¦`).
    let path = validation::path::strip_long_path_prefix(path);
    let rest = strip_prefix_ignore_case(&path, root.target.trim_end_matches('\\'))?;
    let requested = format!("{}{rest}", root.requested.trim_end_matches('\\'));
    Some((
        requested.clone(),
        DfsEvaluation {
            requested,
            target: path.clone(),
            ..root.clone()
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use share_scanner::dfs::{DfsLink, DfsTarget};

    fn target(server: &str, share: &str, active: bool) -> DfsTarget {
        DfsTarget {
            server: server.to_owned(),
            share: share.to_owned(),
            active,
            online: true,
        }
    }

    /// The lab answer for `\\corp.test\dfs\Projects\Sub` (2026-10-24).
    fn projects() -> DfsLookup {
        DfsLookup::Link(DfsLink {
            entry_path: r"\\corp.test\dfs\Projects".to_owned(),
            targets: vec![
                target("FS-01.corp.test", "DfsProj", true),
                target("FS-02.corp.test", "DfsProj", false),
            ],
        })
    }

    #[test]
    fn a_plain_unc_path_is_evaluated_as_given() {
        let t = decide(
            r"\\fs-01.CORP.test\dfsproj\Sub",
            Some(r"\\FS-01.corp.test\DfsProj\Sub"),
            &DfsLookup::NotDfs,
        );
        assert_eq!(t.evaluated_path, r"\\fs-01.CORP.test\dfsproj\Sub");
        assert_eq!(t.dfs, None);
    }

    #[test]
    fn a_dfs_path_is_evaluated_on_its_target_and_names_the_others() {
        let t = decide(
            r"\\corp.test\dfs\Projects\Sub",
            Some(r"\\FS-01.corp.test\DfsProj\Sub"),
            &projects(),
        );
        assert_eq!(t.evaluated_path, r"\\FS-01.corp.test\DfsProj\Sub");
        let d = t.dfs.unwrap();
        assert_eq!(d.folder.as_deref(), Some(r"\\corp.test\dfs\Projects"));
        assert_eq!(d.other_targets, [r"\\FS-02.corp.test\DfsProj"]);
        assert!(d.other_targets_known);
        assert!(d.marker().is_incompleteness_trigger(), "two targets: open");
    }

    #[test]
    fn a_single_target_folder_is_exact() {
        let team = DfsLookup::Link(DfsLink {
            entry_path: r"\\corp.test\dfs\Team".to_owned(),
            targets: vec![target("FS-02.corp.test", "DfsTeam", true)],
        });
        let t = decide(
            r"\\corp.test\dfs\Team\Sub",
            Some(r"\\FS-02.corp.test\DfsTeam\Sub"),
            &team,
        );
        let d = t.dfs.unwrap();
        assert!(d.other_targets.is_empty() && d.other_targets_known);
        assert!(!d.marker().is_incompleteness_trigger());
    }

    /// Redirected, but the DFS client gives no (or an inconsistent) answer:
    /// whether other targets exist is unknown — never assumed "none".
    #[test]
    fn a_redirect_without_a_consistent_client_answer_leaves_the_targets_unknown() {
        for lookup in [DfsLookup::NotDfs, DfsLookup::Failed("x".to_owned())] {
            let t = decide(
                r"\\corp.test\dfs\Projects\Sub",
                Some(r"\\FS-01.corp.test\DfsProj\Sub"),
                &lookup,
            );
            let d = t.dfs.unwrap();
            assert!(!d.other_targets_known);
            assert!(d.marker().is_incompleteness_trigger());
        }
        // The client names FS-02 as active while the handle went to FS-01.
        let wrong = DfsLookup::Link(DfsLink {
            entry_path: r"\\corp.test\dfs\Projects".to_owned(),
            targets: vec![
                target("FS-01.corp.test", "DfsProj", false),
                target("FS-02.corp.test", "DfsProj", true),
            ],
        });
        let d = decide(
            r"\\corp.test\dfs\Projects\Sub",
            Some(r"\\FS-01.corp.test\DfsProj\Sub"),
            &wrong,
        )
        .dfs
        .unwrap();
        assert!(!d.other_targets_known);
    }

    #[test]
    fn without_an_open_the_active_target_of_the_client_is_used() {
        let t = decide(r"\\corp.test\dfs\Projects\Sub\a.txt", None, &projects());
        assert_eq!(t.evaluated_path, r"\\FS-01.corp.test\DfsProj\Sub\a.txt");
        assert!(t.dfs.unwrap().other_targets_known);
        // No active target: evaluated as given, targets unknown.
        let none_active = DfsLookup::Link(DfsLink {
            entry_path: r"\\corp.test\dfs\Projects".to_owned(),
            targets: vec![target("FS-01.corp.test", "DfsProj", false)],
        });
        let t = decide(r"\\corp.test\dfs\Projects\Sub", None, &none_active);
        assert_eq!(t.evaluated_path, r"\\corp.test\dfs\Projects\Sub");
        assert!(!t.dfs.unwrap().other_targets_known);
        // Nothing known at all: evaluated as given, no claim.
        assert_eq!(decide(r"\\srv\share", None, &DfsLookup::NotDfs).dfs, None);
    }

    #[test]
    fn the_dfs_step_follows_the_user_step() {
        let d = DfsEvaluation {
            requested: r"\\corp.test\dfs\Team\Sub".to_owned(),
            target: r"\\FS-02.corp.test\DfsTeam\Sub".to_owned(),
            folder: Some(r"\\corp.test\dfs\Team".to_owned()),
            other_targets: Vec::new(),
            other_targets_known: true,
        };
        let mut p = PermissionPath {
            steps: vec!["User: x".to_owned(), "Effective: y".to_owned()],
        };
        attach_step(&mut p, &d);
        assert_eq!(p.steps.len(), 3);
        assert!(p.steps[1].starts_with(r"DFS: \\corp.test\dfs\Team\Sub lies in the DFS folder"));
        assert_eq!(
            DfsEvaluation::entry_label(r"\\corp.test\dfs"),
            r"DFS namespace root \\corp.test\dfs"
        );
        assert!(p.steps[1].contains(r"evaluated on \\FS-02.corp.test\DfsTeam\Sub"));
    }

    #[test]
    fn the_prefix_matches_only_whole_components() {
        assert_eq!(
            strip_prefix_ignore_case(r"\\corp.test\dfs\Projects\Sub", r"\\CORP.test\dfs\projects"),
            Some(r"\Sub")
        );
        assert_eq!(
            strip_prefix_ignore_case(r"\\corp.test\dfs\Projects", r"\\corp.test\dfs\Projects"),
            Some("")
        );
        assert_eq!(
            strip_prefix_ignore_case(r"\\corp.test\dfs\ProjectsX", r"\\corp.test\dfs\Projects"),
            None
        );
    }

    #[test]
    fn a_scanned_object_keeps_the_requested_form_and_its_own_target() {
        let root = DfsEvaluation {
            requested: r"\\corp.test\dfs\Projects".to_owned(),
            target: r"\\FS-01.corp.test\DfsProj".to_owned(),
            folder: Some(r"\\corp.test\dfs\Projects".to_owned()),
            other_targets: vec![r"\\FS-02.corp.test\DfsProj".to_owned()],
            other_targets_known: true,
        };
        let (requested, d) =
            for_scanned_object(r"\\FS-01.corp.test\DfsProj\Sub\a.txt", &root).unwrap();
        assert_eq!(requested, r"\\corp.test\dfs\Projects\Sub\a.txt");
        assert_eq!(d.requested, requested);
        assert_eq!(d.target, r"\\FS-01.corp.test\DfsProj\Sub\a.txt");
        assert_eq!(d.other_targets, root.other_targets);
        let (long, _) = for_scanned_object(r"\\?\UNC\FS-01.corp.test\DfsProj\Sub", &root).unwrap();
        assert_eq!(
            long, r"\\corp.test\dfs\Projects\Sub",
            "long-path form of the walker"
        );
        let (root_again, _) = for_scanned_object(r"\\FS-01.corp.test\DfsProj", &root).unwrap();
        assert_eq!(root_again, r"\\corp.test\dfs\Projects");
        assert!(for_scanned_object(r"\\other\share\x", &root).is_none());
    }
}
