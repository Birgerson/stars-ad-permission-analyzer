// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! share_scanner — SMB share enumeration and permission reading

pub mod scanner;

pub use scanner::{
    classify_share, effective_share_mask, enumerate_shares, get_share_dacl,
    resolve_share_mask_status, resolve_share_mask_status_explained, scan_shares,
    share_ace_decisions, share_decision_steps, ShareAceDecision, ShareAceOutcome, ShareDacl,
    ShareDaclScan, ShareResolution, ShareScanError, ShareScanResult,
};
