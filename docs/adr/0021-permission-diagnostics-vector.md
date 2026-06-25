# ADR 0021 — Structured diagnostic markers per permission

**Status:** Accepted  
**Date:** 2026-05-24

## Context

ADR 0012 (stored-order DACL evaluation) deliberately decides to evaluate
non-canonically sorted DACLs in stored order following Windows
AccessCheck semantics. The engine detected the case via
`first_non_canonical_position` and emitted a `tracing::warn!`.

ADR 0012 itself noted the trade-off explicitly: *"A later structured
diagnostic (e.g. a `non_canonical_dacl: bool` field) is possible once a
concrete audit use case demands it."*

The follow-up review (2026-05-24) makes the use case concrete: a log-only
marker survives neither the CLI run, the GUI run, the DB history, nor the
export. An auditor who sees a surprising effective-rights result has no
trace of **why** it deviates from the canonicalized expectation.

Follow-up finding 3.

## Decision

1. **New variant-tagged enum `PermissionDiagnostic`** in
   `adpa_core::model`. First marker:
   `NonCanonicalDaclOrder { at_index: usize }`.

   The tag format (`#[serde(tag = "kind")]`) lets future markers — e.g.
   "inheritance disabled", "SACL not readable" — be added without breaking
   existing JSON/DB data.

2. **`EffectivePermission.diagnostics: Vec<PermissionDiagnostic>`** as a
   new mandatory field with `#[serde(default)]`. Empty by default; the
   engine populates it via the new helper `collect_diagnostics(dacl, path)`,
   which at the same time emits the existing `warn!` log.

3. **Persistence: new TEXT column `diagnostics`** on
   `effective_permissions` (migration v6) with `DEFAULT '[]'`. Old rows
   read as "no markers"; new rows carry the JSON array. INSERT/SELECT
   extended; a round-trip test covers it.

4. **Exports and GUI:**
   - **JSON export:** automatic via `Serialize` — no extra work.
   - **CSV export:** new column `diagnostics_json` (always filled, empty
     list as `"[]"` — consistent with `matched_aces_json`).
   - **GUI scan view:** per row, the warn badge now shows jointly
     `N unsupported ACE(s), M diagnostic(s)`; an aggregated message at the
     bottom of the table summarizes the paths with diagnostic markers.

5. **`evaluate_dacl_ordered` no longer warns itself.** The diagnostic
   detection is centralized in `collect_diagnostics` — a single source of
   truth between log and structured marker.

## Rationale

- **Audit effectiveness:** a marker that does not enter the persistent
  artifact is worthless to an auditor.
- **Forward compatibility:** tagged enum + JSON column + `serde(default)`
  allow new markers without schema jumps.
- **GUI symmetry:** the existing `unsupported_aces` badge logic is simply
  extended by the second diagnostic column — same view, same color, one
  less source of surprise.
- **HTML export stays unchanged for now:** JSON is the canonical audit
  path, CSV carries the markers, the GUI makes them visible. HTML can
  visualize the same data later — deliberately not packed into this
  iteration, to keep the change focused.

## Consequences

- 4 new tests in `permission_engine::engine::tests`:
  - `non_canonical_dacl_yields_diagnostic_marker`
  - `canonical_dacl_yields_no_diagnostic_marker`
  - `null_dacl_yields_no_diagnostic_marker`
  - (existing ACE-order tests stay valid)
- 1 new test in `persistence::scan_store::tests`: `diagnostics_round_trip`
- 2 new tests in `exporter::csv::tests`:
  `diagnostics_serialized_as_tagged_json`,
  `empty_diagnostics_yield_empty_json_array`
- CSV header test extended (19 → 20 columns).
- Migration v6 added — `fresh_database_gets_latest_version` bumps to 6.
- ScanRow carries `diagnostic_count`; the GUI scan view aggregates it.
- No breakage for existing callers of `EffectivePermission` —
  `diagnostics` is `#[serde(default)]` and old construction sites were
  extended with `diagnostics: vec![]`.
- A later HTML extension with a "Diagnostics" section is a natural
  follow-up.
