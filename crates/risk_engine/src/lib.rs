// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! risk_engine — risk rules and audit assessments

pub mod rules;

// Review 2026-07-25 finding RK-7: AdminRightsRule was the only registered
// rule missing from the re-export list — external callers building a custom
// registry could not name it without the `rules::` path.
pub use rules::{
    AdminRightsRule, BroadGroupWriteRule, DirectUserAceRule, FullControlRule, RuleRegistry,
    SensitivePathRule, WriteAccessRule,
};
