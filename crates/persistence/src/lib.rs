// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! persistence — SQLite, Caching und Scan-Historie
//! persistence — SQLite, caching, and scan history

pub mod db;
pub mod delta;
pub mod identity_cache;
pub mod migrations;
pub mod scan_store;

pub use db::Database;
pub use delta::{
    compare_scans, diff_permission_lists, DeltaEntry, DeltaKind, DeltaReason, LocalGroupStatusTag,
    PermissionSignature, ShareStatusTag,
};
pub use identity_cache::IdentityCache;
pub use scan_store::ScanStore;
