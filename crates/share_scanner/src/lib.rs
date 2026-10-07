// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! share_scanner — SMB share enumeration and permission reading

pub mod scanner;

pub use scanner::{
    classify_share, effective_share_mask, enumerate_shares, get_share_dacl,
    resolve_share_mask_status, scan_shares, ShareDacl, ShareDaclScan, ShareScanError,
    ShareScanResult,
};
