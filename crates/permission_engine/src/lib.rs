// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! permission_engine — calculation of effective permissions

pub mod engine;
pub mod mask;

pub use engine::{build_token_sids, build_token_sids_with_context, DefaultPermissionEngine};
pub use mask::{rights_label_compact, rights_statement, NormalizedRights, NOT_DETERMINABLE};
