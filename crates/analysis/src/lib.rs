// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! analysis — the analysis pipeline shared by the CLI and the GUI (ADR 0082,
//! step 5).
//!
//! Both frontends run the same steps for one path and one account: resolve
//! the account, read its local groups on the target server, read the share
//! DACL, evaluate. Each step that both frontends need lives here exactly
//! once, so a fix cannot reach one frontend and miss the other. The crate
//! holds orchestration only — the permission logic stays in
//! `permission_engine`, the directory and server reads in `ad_resolver` and
//! `share_scanner`.
//!
//! - [`local_groups`] — the account's local groups on the analysis target
//!   (ADR 0068, UAC ADR 0070/0071/0076, Everyone for anonymous L17).
//! - [`share`] — the share mask of an SMB path for the account's token.

pub mod local_groups;
pub mod share;
