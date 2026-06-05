// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! risk_engine — Risikoregeln und Audit-Bewertungen
//! risk_engine — risk rules and audit assessments

pub mod rules;

pub use rules::{
    BroadGroupWriteRule, DirectUserAceRule, FullControlRule, RuleRegistry, SensitivePathRule,
    WriteAccessRule,
};
