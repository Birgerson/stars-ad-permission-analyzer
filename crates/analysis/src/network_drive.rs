// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Paths on a mapped network drive (review CR-22).
//!
//! `Z:\Data` on a drive mapped to `\\FS-02\Data` is evaluated as the UNC
//! path it maps to, so the share permission and the file server's local
//! groups and policies apply. Without that, the drive-letter form passed as
//! a local path: the NTFS DACL came from the server through the mapping,
//! and the result was reported as exact local rights, without the share
//! (lab 2026-11-21: exact Modify through `Z:`, Read & Execute through UNC).
//!
//! The UNC path is the one both frontends continue with — also into the DFS
//! resolution, because a drive can be mapped to a DFS namespace. Results
//! name the UNC path; a step of each explanation says it came from the
//! drive. A network drive whose UNC path cannot be read is an error, never a
//! local evaluation.

use adpa_core::{error::CoreError, model::PermissionPath};
use validation::path::{parse_unc_components, validate_path};

/// A path given on a network drive and the UNC path it maps to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedDrive {
    /// The path as given (`Z:\Data`).
    pub requested: String,
    /// The validated UNC path (`\\FS-02\Data`).
    pub unc: String,
}

impl MappedDrive {
    /// The note both frontends show once for the analysis or scan.
    pub fn note(&self) -> String {
        format!(
            "{} lies on a network drive; evaluated as {} over SMB — the share permissions, \
             local groups and policies of that server apply, not those of this machine.",
            self.requested, self.unc
        )
    }
}

/// Resolves `path` when it lies on a network drive. `Ok(None)` for every
/// other path.
pub fn resolve_mapped_drive(path: &str) -> Result<Option<MappedDrive>, CoreError> {
    match fs_scanner::drive::network_drive_target(path) {
        Ok(None) => Ok(None),
        Ok(Some(unc)) => check_unc(path, &unc).map(Some),
        Err(reason) => Err(CoreError::Validation(format!(
            "{reason}. Enter the UNC path (\\\\server\\share\\…) instead."
        ))),
    }
}

/// Validates the UNC path Windows returned for `requested` — a value the OS
/// returns is not trusted blindly. Pure.
fn check_unc(requested: &str, unc: &str) -> Result<MappedDrive, CoreError> {
    let refuse = |why: String| {
        CoreError::Validation(format!(
            "{requested} lies on a network drive, but its UNC path {unc:?} {why}. Enter the UNC \
             path (\\\\server\\share\\…) instead."
        ))
    };
    let valid = validate_path(unc)
        .map_err(|e| refuse(format!("is not a valid path ({e})")))?
        .0;
    if parse_unc_components(&valid).is_none() {
        return Err(refuse("is not of the form \\\\server\\share".to_owned()));
    }
    Ok(MappedDrive {
        requested: requested.to_owned(),
        unc: valid,
    })
}

/// Puts the drive step right after the user step of the explanation path,
/// before a DFS step (attach this one after the DFS step).
pub fn attach_step(path: &mut PermissionPath, m: &MappedDrive) {
    let step = format!(
        "Network drive: {} is on a mapped network drive and was evaluated as {} (that \
         server's share permissions, local groups and policies)",
        m.requested, m.unc
    );
    let at = usize::from(!path.steps.is_empty());
    path.steps.insert(at, step);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_valid_unc_answer_is_taken() {
        let m = check_unc(r"Z:\Sub", r"\\FS-02.corp.test\DfsProj\Sub").unwrap();
        assert_eq!(m.unc, r"\\FS-02.corp.test\DfsProj\Sub");
        assert!(m.note().contains("over SMB"));
    }

    /// Whatever Windows returns must be a UNC path with server and share.
    #[test]
    fn an_implausible_answer_is_refused() {
        for bad in ["", r"C:\local", r"\\onlyserver", "\\\\srv\\sh\0are"] {
            let err = check_unc(r"Z:\x", bad).unwrap_err().to_string();
            assert!(err.contains("Enter the UNC path"), "{bad:?}: {err}");
        }
    }

    #[test]
    fn the_drive_step_comes_right_after_the_user_step() {
        let mut p = PermissionPath {
            steps: vec!["User: alice".into(), "DFS: …".into(), "NTFS".into()],
        };
        let m = check_unc(r"Z:\Sub", r"\\FS-02\Data\Sub").unwrap();
        attach_step(&mut p, &m);
        assert!(
            p.steps[1].starts_with("Network drive: Z:\\Sub"),
            "{:?}",
            p.steps
        );
        assert_eq!(p.steps[2], "DFS: …");
    }

    #[test]
    fn a_local_path_is_no_network_drive() {
        let system = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        assert_eq!(
            resolve_mapped_drive(&format!(r"{system}\Windows")).unwrap(),
            None
        );
    }
}
