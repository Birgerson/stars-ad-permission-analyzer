# ADR 0022 — Validate `max_depth` centrally at the CLI/GUI boundary

**Status:** Accepted  
**Date:** 2026-05-25

## Context

`validation::numbers::validate_scan_depth` (min 0, max 512) has existed
since the initial validation setup, but was not called by the CLI or the
GUI worker. Both passed `max_depth: Option<u32>` directly from the
`clap::Parser` or the GUI state into `WalkConfig`. The GUI DragValue only
limited the value visually to 0..=50 — a programmatic call or a UI
refactor would have bypassed that.

AGENTS.md Definition of Done, point 11 explicitly requires that **all
affected inputs be validated** before they are further processed. Numeric
scan-control values are expressly named under "input types to validate".

Follow-up review (2026-05-25), finding 3 (Low).

## Decision

1. **New helper `validate_optional_scan_depth(Option<u32>)`** in
   `validation::numbers`, which passes `None` through (= unlimited depth,
   the desired behavior) and sends `Some(d)` through the existing
   `validate_scan_depth`. This gives the `Option` API a single call site.

2. **CLI** (`crates/cli/src/main.rs`) calls the validator directly after
   `validate_path` and before the walk setup. On error, `anyhow::anyhow!`
   with a clear reason — analogous to the existing path/SID/LDAP
   validation.

3. **GUI worker** (`crates/gui/src/worker.rs`) validates directly after
   `validate_path` via the existing `make_early_summary` closure — so the
   validation error lands both in the UI event and in the persisted
   `scan_errors` list, consistent with the other setup errors
   (cf. ADR 0016).

4. **`WalkConfig` stays unchanged** (`max_depth: Option<u32>`). An API
   change to `Option<ScanDepth>` would be more type-safe, but a larger
   refactor in `fs_scanner` with no immediate correctness gain.
   "Validate at the boundary, then unwrap" is a common Rust pattern and
   fits here.

## Rationale

- **Single source of truth for limits** — `MAX_SCAN_DEPTH = 512` lives in
  a constant that the validator enforces. Later adjustments take effect
  everywhere at once.
- **Defense in depth**: GUI widget limit (visual), validator
  (programmatic), walker (operational). If one layer is bypassed, the next
  catches it.
- **Consistency with path/SID/LDAP**: all other user inputs in the CLI and
  GUI run through the same validation pattern; scan depth now closes this
  gap.

## Consequences

- 4 new unit tests in `validation::numbers::tests`:
  - `optional_scan_depth_none_passes_through`
  - `optional_scan_depth_some_within_limit_accepted`
  - `optional_scan_depth_some_at_boundary_accepted`
  - `optional_scan_depth_some_above_limit_rejected`
- No API breaks, no schema migration.
- DoD point 11 for the scan depth is satisfied; point 12 ("validation
  errors tested") along with it.
