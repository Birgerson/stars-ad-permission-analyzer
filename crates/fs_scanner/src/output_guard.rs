// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Output destinations outside the audited tree (review CR-17).
//!
//! Stars is read-only towards the systems it audits. A report, a CSV
//! staging file or the scan database written into the tree being scanned
//! changes that tree — on a file server it creates a file on the target —
//! and can become part of the walk itself. An overwrite could even replace
//! a file of the audited tree.
//!
//! [`check_outside_tree`] refuses a destination whose folder is the tree
//! root or lies below it. Paths alone are not enough: the same folder can
//! be reached through a link, a mapped drive, another server name or an
//! administrative share. So every folder from the destination up to its
//! root is compared with the tree root twice — by its resolved path, and by
//! its directory identity (volume serial + file ID, ADR 0062), which is the
//! same whatever route led to it. Read-only: the folders are opened for
//! their attributes only.

use std::path::{Path, PathBuf};

/// `Err(reason)` when `output_file` would be written into the tree rooted at
/// `tree_root`; `Ok(())` otherwise — also when the tree root is a file (an
/// analysis of one file has no tree) or does not exist.
pub fn check_outside_tree(output_file: &Path, tree_root: &str) -> Result<(), String> {
    let root_api = validation::path::to_windows_api_path(tree_root);
    let root_is_dir = std::fs::metadata(&root_api)
        .map(|m| m.is_dir())
        .unwrap_or(false);
    if !root_is_dir {
        return Ok(());
    }
    let parent = match output_file.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let parent_canonical = std::fs::canonicalize(&parent).map_err(|e| {
        format!(
            "the destination folder {} cannot be resolved ({e})",
            parent.display()
        )
    })?;
    let root_canonical = std::fs::canonicalize(&root_api).ok();
    let root_identity = crate::file_id::directory_identity_once(&root_api);
    for folder in parent_canonical.ancestors() {
        let same_path = root_canonical
            .as_deref()
            .is_some_and(|r| same_path_text(folder, r));
        let same_identity = !same_path
            && root_identity.is_some()
            && crate::file_id::directory_identity_once(&folder.to_string_lossy()) == root_identity;
        if same_path || same_identity {
            tracing::warn!(
                destination = %output_file.display(),
                tree_root,
                "Output destination lies inside the audited tree"
            );
            return Err(format!(
                "{} lies inside the audited tree {tree_root}{}. Stars must not write into the \
                 tree it audits — the file would change the target and could become part of the \
                 scan. Choose a folder outside it.",
                output_file.display(),
                if same_path {
                    ""
                } else {
                    " (the same folder, reached through another path, link, drive or server name)"
                }
            ));
        }
    }
    Ok(())
}

/// Case-insensitive comparison of two resolved paths (refusing more is the
/// safe side). Pure.
fn same_path_text(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| p.to_string_lossy().trim_end_matches('\\').to_lowercase();
    norm(a) == norm(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "adpa-cr17-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_destination_inside_the_tree_is_refused_outside_accepted() {
        let root = fresh_dir("tree");
        std::fs::create_dir_all(root.join(r"sub\deeper")).unwrap();
        let outside = fresh_dir("out");
        let r = root.to_string_lossy().into_owned();
        for inside in [
            root.join("report.csv"),
            root.join(r"sub\deeper\report.html"),
        ] {
            let err = check_outside_tree(&inside, &r).unwrap_err();
            assert!(err.contains("inside the audited tree"), "{err}");
        }
        // Another case of the same path is the same folder on Windows.
        let upper = PathBuf::from(r.to_uppercase()).join("x.json");
        assert!(check_outside_tree(&upper, &r).is_err());
        assert!(check_outside_tree(&outside.join("report.csv"), &r).is_ok());
        // A sibling whose name starts like the root is outside.
        let twin = PathBuf::from(format!("{r}twin"));
        std::fs::create_dir_all(&twin).unwrap();
        assert!(check_outside_tree(&twin.join("r.csv"), &r).is_ok());
        // A file as the root has no tree.
        let file = outside.join("one.txt");
        std::fs::write(&file, b"x").unwrap();
        assert!(check_outside_tree(&outside.join("r.csv"), &file.to_string_lossy()).is_ok());
        for d in [root, outside, twin] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    /// A junction into the tree is the same folder: refused by identity.
    #[test]
    fn a_destination_reached_through_a_junction_is_refused() {
        let root = fresh_dir("jroot");
        let outside = fresh_dir("jout");
        let link = outside.join("into_tree");
        let made = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&root)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if made {
            let err =
                check_outside_tree(&link.join("report.csv"), &root.to_string_lossy()).unwrap_err();
            assert!(err.contains("inside the audited tree"), "{err}");
            let _ = std::process::Command::new("cmd")
                .args(["/c", "rmdir"])
                .arg(&link)
                .output();
        } else {
            eprintln!("mklink /J unavailable — test skipped");
        }
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }
}
