//! permission_engine — Berechnung effektiver Rechte
//! permission_engine — calculation of effective permissions

pub mod engine;
pub mod mask;

pub use engine::{build_token_sids, build_token_sids_with_context};
// `build_token_sids_with_local` ist seit ADR 0019 deprecated, bleibt aber als
// Bequemlichkeits-Re-Export erhalten. Externe Aufrufer sehen die Deprecation-
// Warnung im normalen Build-Output.
// `build_token_sids_with_local` has been deprecated since ADR 0019 but is kept
// as a convenience re-export. External callers will see the deprecation
// warning in the normal build output.
#[allow(deprecated)]
pub use engine::build_token_sids_with_local;
pub use mask::NormalizedRights;
