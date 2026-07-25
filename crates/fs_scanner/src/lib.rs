// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! fs_scanner — file system enumeration and NTFS ACL evaluation

pub mod acl;
pub mod cancel;
pub mod scanner;
pub mod walker;

pub use cancel::CancellationToken;
// `read_fso` is production API (CLI analyze + GUI worker); `NtfsScanner` is
// the architectural `Scanner` seam and has no callers — see the `scanner`
// module docs (fs_scanner review 2026-07-25, FS-4).
pub use scanner::{read_fso, NtfsScanner};
pub use walker::{walk_tree, walk_tree_streaming, WalkConfig, WalkItem, WalkResult};
