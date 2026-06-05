// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! share_scanner — SMB-Freigaben-Enumeration und Berechtigungsauswertung
//! share_scanner — SMB share enumeration and permission reading

pub mod scanner;

pub use scanner::{
    effective_share_mask, enumerate_shares, get_share_dacl, get_share_permissions, scan_shares,
    ShareDacl, ShareDaclScan, ShareScanError, ShareScanResult,
};
