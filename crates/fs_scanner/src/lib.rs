// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! fs_scanner — Dateisystem-Enumeration und NTFS-ACL-Auswertung
//! fs_scanner — file system enumeration and NTFS ACL evaluation

pub mod acl;
pub mod cancel;
pub mod scanner;
pub mod walker;

pub use cancel::CancellationToken;
pub use scanner::{read_fso, NtfsScanner};
pub use walker::{walk_tree, WalkConfig, WalkResult};
