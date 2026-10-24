// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! The Rust side of each tab (ADR 0082), one module per `ui/tabs/<tab>.slint`.
//! A module wires its tab's callbacks (`wire`) and applies the worker's
//! answers to its tab's global (`handle_*`); UI bookkeeping that is not a
//! Slint property stays inside the module.

pub mod analyze;
pub mod delta;
pub mod graph;
pub mod groups;
pub mod info;
pub mod scan;
pub mod shares;
pub mod trusts;
