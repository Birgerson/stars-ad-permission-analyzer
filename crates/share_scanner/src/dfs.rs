// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! DFS folder targets as this machine's DFS client sees them (ADR 0085).
//!
//! `NetDfsGetClientInfo` (level 3) answers for any path inside a DFS
//! namespace with the folder (or root) the path lies in, every target of
//! that folder, and which target the client uses (`DFS_STORAGE_STATE_ACTIVE`).
//! Measured on MS-01 (2026-10-24): the answer matches the folder by prefix
//! (`\\corp.test\dfs\Projects\Sub\x.txt` → folder `Projects`), a path outside
//! DFS yields `NERR_DfsNoSuchVolume` (2662), and for some name forms the
//! client knows the folder only after the path was opened once — callers
//! open the path first.
//!
//! Read-only: the client's referral cache is queried, nothing is changed.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use win_safe::netapi::NetApiBuffer;
use windows_sys::Win32::Storage::DistributedFileSystem::{
    NetDfsGetClientInfo, DFS_INFO_3, DFS_STORAGE_INFO, DFS_STORAGE_STATE_ACTIVE,
    DFS_STORAGE_STATE_ONLINE,
};

/// `NERR_DfsNoSuchVolume` — the path is not in a DFS namespace.
const NERR_DFS_NO_SUCH_VOLUME: u32 = 2662;
/// More targets than any real folder has; a larger count is treated as a
/// damaged answer.
const MAX_TARGETS: u32 = 1024;

/// One target of a DFS folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DfsTarget {
    pub server: String,
    pub share: String,
    /// The target this client uses.
    pub active: bool,
    pub online: bool,
}

impl DfsTarget {
    /// `\\server\share`.
    pub fn unc(&self) -> String {
        format!(r"\\{}\{}", self.server, self.share)
    }
}

/// The DFS folder (or root) a path lies in, with its targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DfsLink {
    /// The folder's path in the namespace, `\\domain\namespace\folder`.
    pub entry_path: String,
    pub targets: Vec<DfsTarget>,
}

/// Answer of the DFS client for one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DfsLookup {
    /// The path is not in a DFS namespace.
    NotDfs,
    Link(DfsLink),
    /// The client could not answer or answered with damaged data.
    Failed(String),
}

/// The folder `path` lies in, as this machine's DFS client knows it.
pub fn dfs_client_link(path: &str) -> DfsLookup {
    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut buf: NetApiBuffer<DFS_INFO_3> = NetApiBuffer::null();
    // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the
    // call; server and share are null (allowed: the path names the entry).
    // The OS allocates the buffer; NetApiBuffer frees it on drop.
    let status = unsafe {
        NetDfsGetClientInfo(
            wide.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            3,
            buf.out_ptr().cast(),
        )
    };
    if status == NERR_DFS_NO_SUCH_VOLUME {
        return DfsLookup::NotDfs;
    }
    if status != 0 {
        return DfsLookup::Failed(format!("NetDfsGetClientInfo failed with status {status}"));
    }
    if buf.is_null() {
        return DfsLookup::Failed("NetDfsGetClientInfo returned no data".to_owned());
    }
    // SAFETY: on success the buffer holds one DFS_INFO_3 whose `Storage`
    // array has `NumberOfStorages` entries, all valid until the buffer is
    // freed (after this block).
    let (entry, raw_targets) = unsafe {
        let info = &*buf.as_ptr();
        if info.NumberOfStorages > MAX_TARGETS {
            return DfsLookup::Failed(format!(
                "NetDfsGetClientInfo reported {} targets",
                info.NumberOfStorages
            ));
        }
        let storages: &[DFS_STORAGE_INFO] = if info.NumberOfStorages == 0 {
            &[]
        } else if info.Storage.is_null() {
            return DfsLookup::Failed(
                "NetDfsGetClientInfo reported targets but no list".to_owned(),
            );
        } else {
            std::slice::from_raw_parts(info.Storage, info.NumberOfStorages as usize)
        };
        let targets: Vec<(String, String, u32)> = storages
            .iter()
            .map(|s| {
                (
                    wide_to_string(s.ServerName),
                    wide_to_string(s.ShareName),
                    s.State,
                )
            })
            .collect();
        (wide_to_string(info.EntryPath), targets)
    };
    match build_link(&entry, raw_targets) {
        Ok(link) => DfsLookup::Link(link),
        Err(e) => DfsLookup::Failed(e),
    }
}

/// Validates the raw answer and builds the link. Pure.
///
/// The client reports the entry path with one leading backslash
/// (`\corp.test\dfs\Projects`, lab 2026-10-24); it is returned in UNC form.
fn build_link(entry: &str, raw_targets: Vec<(String, String, u32)>) -> Result<DfsLink, String> {
    let entry_path = format!(r"\\{}", entry.trim_start_matches('\\'));
    if validation::path::parse_unc_components(&entry_path).is_none() {
        return Err(format!("the DFS client reported the folder path '{entry}'"));
    }
    if raw_targets.is_empty() {
        return Err(format!(
            "the DFS client reported no target for {entry_path}"
        ));
    }
    let mut targets = Vec::with_capacity(raw_targets.len());
    for (server, share, state) in raw_targets {
        let ok = |s: &str| !s.is_empty() && !s.chars().any(|c| c.is_control() || c == '\\');
        if !ok(&server) || !ok(&share) {
            return Err(format!(
                "the DFS client reported the target '{server}\\{share}' for {entry_path}"
            ));
        }
        targets.push(DfsTarget {
            server,
            share,
            active: state & DFS_STORAGE_STATE_ACTIVE != 0,
            online: state & DFS_STORAGE_STATE_ONLINE != 0,
        });
    }
    Ok(DfsLink {
        entry_path,
        targets,
    })
}

/// # Safety
/// `ptr` is null or a valid NUL-terminated UTF-16 string.
unsafe fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY (caller contract): NUL-terminated.
    let len = (0usize..).take_while(|&i| *ptr.add(i) != 0).count();
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(server: &str, share: &str, state: u32) -> (String, String, u32) {
        (server.to_owned(), share.to_owned(), state)
    }

    /// The lab answer for `\\corp.test\dfs\Projects\Sub` (2026-10-24).
    #[test]
    fn the_lab_answer_builds_the_folder_with_its_active_target() {
        let link = build_link(
            r"\corp.test\dfs\Projects",
            vec![
                raw("FS-01.corp.test", "DfsProj", 0x6),
                raw("FS-02.corp.test", "DfsProj", 0x2),
            ],
        )
        .unwrap();
        assert_eq!(link.entry_path, r"\\corp.test\dfs\Projects");
        assert_eq!(link.targets.len(), 2);
        assert!(link.targets[0].active && link.targets[0].online);
        assert!(!link.targets[1].active && link.targets[1].online);
        assert_eq!(link.targets[0].unc(), r"\\FS-01.corp.test\DfsProj");
    }

    #[test]
    fn damaged_answers_are_errors() {
        assert!(build_link(r"\corp.test\dfs\Projects", vec![]).is_err());
        assert!(build_link("", vec![raw("FS-01", "DfsProj", 0x6)]).is_err());
        assert!(build_link(r"\corp.test\dfs", vec![raw("", "DfsProj", 0x6)]).is_err());
        assert!(build_link(r"\corp.test\dfs", vec![raw("FS-01", r"a\b", 0x6)]).is_err());
    }

    #[test]
    fn a_local_path_is_not_dfs() {
        let dir = std::env::temp_dir();
        assert_eq!(dfs_client_link(&dir.to_string_lossy()), DfsLookup::NotDfs);
    }
}
