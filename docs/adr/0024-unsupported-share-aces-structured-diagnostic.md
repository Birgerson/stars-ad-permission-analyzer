# ADR 0024 — Unsupported share ACEs as a structured diagnostic

**Status:** Accepted  
**Date:** 2026-05-25

## Context

`FileSystemObject.unsupported_aces` and
`EffectivePermission.unsupported_ace_count` have recorded, since ADR 0004,
when the NTFS DACL parser skipped ACE types (object, callback, conditional,
or vendor-specific ACEs). The risk engine uses this for the
`incomplete = true` marking.

On the share side there was no counterpart: `parse_share_dacl` logged
unsupported share ACE types only at `debug!` level and let the parse
continue silently. The caller got back a `ShareDacl::Acl(perms)` that no
longer contained the error part. Consequence: the share mask could be
incomplete (e.g. if a hidden Deny-object ACE was in the DACL), risk
findings were reported as `confirmed`, and CSV/JSON/HTML reports showed no
warning.

Follow-up review (2026-05-25), finding 2 (Medium).

## Decision

1. **New variant `PermissionDiagnostic::UnsupportedShareAces { count }`**
   in `adpa_core::model`. Uses the tagged-enum format established in
   ADR 0021 (`#[serde(tag = "kind")]`) — **no schema migration needed**:
   the variant flows automatically through persistence (JSON column
   `diagnostics`), JSON export, CSV (`diagnostics_json`), and HTML (new
   badge).

2. **New wrapper type `ShareDaclScan { dacl, unsupported_count }`** as the
   return of `get_share_dacl`. Carries the unchanged structured `ShareDacl`
   plus the audit count. This keeps the 30+ existing pattern matches on
   `ShareDacl::Acl(...)` unchanged; only the `get_share_dacl` callers
   unpack the wrapper.

3. **`parse_share_dacl`** counts unsupported ACE types and returns the
   tuple `(perms, unsupported_count)`. The log level switches from `debug!`
   to `warn!`, because this is now a real audit diagnostic (analogous to
   the NTFS parser).

4. **New mandatory field
   `PermissionEvaluationInput.unsupported_share_ace_count: usize`.**
   CLI (`resolve_scan_share_status`) and GUI (`resolve_share_status`) now
   return `(ShareMaskStatus, usize)` tuples; the callers pass the value
   through to `evaluate()`.

5. **The engine** pushes, when `unsupported_share_ace_count > 0`, a
   `PermissionDiagnostic::UnsupportedShareAces { count }` into
   `EffectivePermission.diagnostics`. The logic is centralized in the
   `evaluate` path — no caller has to do the diagnostic push manually.

6. **Risk engine `is_incomplete`** recognizes the new marker and flags
   every risk finding of the affected permission as `incomplete = true`.
   This makes the share side symmetric to the `unsupported_ace_count` logic
   of the NTFS side.

7. **HTML exporter** renders a dedicated badge
   `⚠ {count} unsupported share ACE(s)` with a tooltip explanation in the
   diagnostics column. CSV (`diagnostics_json`) and JSON carry the variant
   automatically via Serialize.

8. **Deliberate trade-off:** `NonCanonicalDaclOrder` (ADR 0021) does NOT
   mark as incomplete — it is audit info, not a correctness problem.
   `UnsupportedShareAces` does mark as incomplete, because a hidden Deny in
   the unsupported part would have changed the mask directly. The
   risk-engine test
   `non_canonical_dacl_diagnostic_alone_does_not_mark_incomplete`
   documents the distinction explicitly.

## Rationale

- **Symmetry with the NTFS side:** both DACL worlds now have the same
  "I could not evaluate an ACE" signal in model, persistence, export, and
  risk assessment.
- **No schema migration:** the tagged-enum format from ADR 0021 pays off —
  schema v6 carries on.
- **Wrapper type instead of enum extension:** laying a new `ShareDaclScan`
  struct over `ShareDacl` is more invasive than necessary, but saves 30+
  test adjustments for the minimally invasive path.
- **Engine as single source of truth for the push:** callers do not have
  to remember to set the diagnostic themselves — they only supply the
  count, the engine decides.
- **The CLI prints a warning** when `unsupported_share_ace_count > 0` — so
  the diagnostic is already visible in the console output, not just in the
  exports. The GUI worker propagates it into `scan_errors` (persisted).

## Consequences

- 1 new test in `share_scanner::scanner::tests`
  (`share_dacl_scan_carries_dacl_and_unsupported_count`).
- 2 new tests in `permission_engine::engine::tests`
  (`unsupported_share_aces_count_emits_diagnostic`,
  `zero_unsupported_share_aces_no_diagnostic`).
- 2 new tests in `risk_engine::rules::tests`
  (`unsupported_share_aces_diagnostic_marks_finding_incomplete`,
  `non_canonical_dacl_diagnostic_alone_does_not_mark_incomplete` — the
  latter documents the deliberate trade-off).
- 1 new test in `exporter::html::tests`
  (`permissions_table_renders_unsupported_share_aces_badge`);
  `permissions_table_renders_combined_diagnostics` extended by the new
  badge.
- CLI/GUI tests stay green — no adjustments needed, since the tests do not
  construct `PermissionEvaluationInput` themselves.
- `PermissionEvaluationInput` constructions in engine tests got
  `unsupported_share_ace_count: 0` added (8 sites via `replace_all`).
- No schema migration, no DB break.
- The NTFS/share symmetry is thereby closed on the diagnostic level too —
  the last recognizable asymmetry in the audit pipeline.
