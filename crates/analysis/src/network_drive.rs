// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Local-looking paths that are reached over SMB (review CR-21, CR-22).
//!
//! - **A mapped network drive.** `Z:\Data` on a drive mapped to
//!   `\\FS-02\Data` is evaluated as the UNC path it maps to, so the share
//!   permission and the file server's local groups and policies apply.
//!   Without that, the drive-letter form passed as a local path: the NTFS
//!   DACL came from the server through the mapping, and the result was
//!   reported as exact local rights, without the share (lab 2026-11-21:
//!   exact Modify through `Z:`, Read & Execute through UNC).
//! - **A link on the way.** `C:\Links\Data\Sub`, where `C:\Links\Data` is a
//!   directory symbolic link to `\\FS-02\Data` (Windows follows a
//!   local-to-remote link by default), is the same case: what the path
//!   reaches is the server's object. The redirector reports the UNC path it
//!   opened, and that path is evaluated.
//!
//! The UNC path is the one both frontends continue with — also into the DFS
//! resolution, because a drive or link can lead to a DFS namespace. Results
//! name the UNC path; a step of each explanation says where it came from. A
//! network drive whose UNC path cannot be read is an error, never a local
//! evaluation. Links below a local scan root are not followed into a share
//! at all: the walker reports them (`fs_scanner::walker`).

use adpa_core::{error::CoreError, model::PermissionPath};
use validation::path::{parse_unc_components, validate_path};

/// How a local-looking path reaches a share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkVia {
    /// The path lies on a mapped network drive.
    MappedDrive,
    /// A junction or symbolic link on the path leads to a share.
    Link,
}

/// A path given in local form and the UNC path it reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkTarget {
    /// The path as given (`Z:\Data`, `C:\Links\Data`).
    pub requested: String,
    /// The validated UNC path (`\\FS-02\Data`).
    pub unc: String,
    pub via: NetworkVia,
}

impl NetworkTarget {
    fn how(&self) -> &'static str {
        match self.via {
            NetworkVia::MappedDrive => "lies on a mapped network drive",
            NetworkVia::Link => "is reached through a link that leads to a network share",
        }
    }

    /// The note both frontends show once for the analysis or scan.
    pub fn note(&self) -> String {
        format!(
            "{} {}; evaluated as {} over SMB — the share permissions, local groups and \
             policies of that server apply, not those of this machine.",
            self.requested,
            self.how(),
            self.unc
        )
    }
}

/// Resolves `path` when its local form reaches a share — a mapped network
/// drive or a link on the way. `Ok(None)` for every other path, also for a
/// UNC path (it is evaluated as given).
pub fn resolve_network_target(path: &str) -> Result<Option<NetworkTarget>, CoreError> {
    if parse_unc_components(path).is_some() {
        return Ok(None);
    }
    match fs_scanner::drive::network_drive_target(path) {
        Ok(Some(unc)) => return check_unc(path, &unc, NetworkVia::MappedDrive).map(Some),
        Err(reason) => {
            return Err(CoreError::Validation(format!(
                "{reason}. Enter the UNC path (\\\\server\\share\\…) instead."
            )))
        }
        Ok(None) => {}
    }
    // Review CR-21: the open follows every link on the path; a local path
    // the redirector opened on a share was reached over SMB.
    match fs_scanner::final_unc_path(path) {
        Some(unc) => {
            tracing::info!(path, unc, "Local path reaches a share through a link");
            check_unc(path, &unc, NetworkVia::Link).map(Some)
        }
        None => Ok(None),
    }
}

/// Validates the UNC path Windows returned for `requested` — a value the OS
/// returns is not trusted blindly. Pure.
fn check_unc(requested: &str, unc: &str, via: NetworkVia) -> Result<NetworkTarget, CoreError> {
    let refuse = |why: String| {
        CoreError::Validation(format!(
            "{requested} is reached over SMB, but its UNC path {unc:?} {why}. Enter the UNC \
             path (\\\\server\\share\\…) instead."
        ))
    };
    let valid = validate_path(unc)
        .map_err(|e| refuse(format!("is not a valid path ({e})")))?
        .0;
    if parse_unc_components(&valid).is_none() {
        return Err(refuse("is not of the form \\\\server\\share".to_owned()));
    }
    Ok(NetworkTarget {
        requested: requested.to_owned(),
        unc: valid,
        via,
    })
}

/// Puts the step right after the user step of the explanation path, before
/// a DFS step (attach this one after the DFS step).
pub fn attach_step(path: &mut PermissionPath, t: &NetworkTarget) {
    let label = match t.via {
        NetworkVia::MappedDrive => "Network drive",
        NetworkVia::Link => "Link to a share",
    };
    let step = format!(
        "{label}: {} {} and was evaluated as {} (that server's share permissions, local \
         groups and policies)",
        t.requested,
        t.how(),
        t.unc
    );
    let at = usize::from(!path.steps.is_empty());
    path.steps.insert(at, step);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_valid_unc_answer_is_taken() {
        let m = check_unc(
            r"Z:\Sub",
            r"\\FS-02.corp.test\DfsProj\Sub",
            NetworkVia::MappedDrive,
        )
        .unwrap();
        assert_eq!(m.unc, r"\\FS-02.corp.test\DfsProj\Sub");
        assert!(m.note().contains("mapped network drive"));
        assert!(m.note().contains("over SMB"));
        let l = check_unc(r"C:\L\Sub", r"\\FS-02\Data\Sub", NetworkVia::Link).unwrap();
        assert!(l.note().contains("through a link"), "{}", l.note());
    }

    /// Whatever Windows returns must be a UNC path with server and share.
    #[test]
    fn an_implausible_answer_is_refused() {
        for bad in ["", r"C:\local", r"\\onlyserver", "\\\\srv\\sh\0are"] {
            let err = check_unc(r"Z:\x", bad, NetworkVia::MappedDrive)
                .unwrap_err()
                .to_string();
            assert!(err.contains("Enter the UNC path"), "{bad:?}: {err}");
        }
    }

    #[test]
    fn the_step_comes_right_after_the_user_step() {
        let mut p = PermissionPath {
            steps: vec!["User: alice".into(), "DFS: …".into(), "NTFS".into()],
        };
        let m = check_unc(r"Z:\Sub", r"\\FS-02\Data\Sub", NetworkVia::MappedDrive).unwrap();
        attach_step(&mut p, &m);
        assert!(
            p.steps[1].starts_with("Network drive: Z:\\Sub"),
            "{:?}",
            p.steps
        );
        assert_eq!(p.steps[2], "DFS: …");
    }

    /// A plain local path and a UNC path are left alone.
    #[test]
    fn local_and_unc_paths_are_left_alone() {
        let system = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        assert_eq!(
            resolve_network_target(&format!(r"{system}\Windows")).unwrap(),
            None
        );
        assert_eq!(resolve_network_target(r"\\srv\share\x").unwrap(), None);
    }
}
