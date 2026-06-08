// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! permission_engine — Berechnung effektiver Rechte
//! permission_engine — calculation of effective permissions

pub mod engine;
pub mod mask;

pub use engine::{build_token_sids, build_token_sids_with_context};
// `build_token_sids_with_local` has been deprecated since ADR 0019 but is kept
// as a convenience re-export. External callers will see the deprecation
// warning in the normal build output.
#[allow(deprecated)]
pub use engine::build_token_sids_with_local;
pub use mask::NormalizedRights;
