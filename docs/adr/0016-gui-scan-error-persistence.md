# ADR 0016 — GUI scans persist walk/eval errors in `scan_errors`

**Status:** Accepted  
**Date:** 2026-05-24

## Context

The GUI worker sent walk, permission-eval, and setup errors to the
UI (`WorkerEvent::ScanError`), but `persist_scan` wrote only the
successful `EffectivePermission` entries and (on `cancelled`) a single
cancellation marker into the SQLite history. Access-denied,
path-not-found, security-descriptor, and eval errors disappeared once
the scan window was closed.

Consequences:

- Historical GUI scans appeared more complete than they were.
- Delta comparisons and later audits could not tell which paths were
  not read at all.
- The CLI path already stored such errors correctly — GUI and CLI thus
  had diverging audit paths.

See review finding 6.

## Decision

1. **`ScanSummary` now carries a structured error list.**
   `errors: usize` → `errors: Vec<ScanError>`. The UI display still uses
   `errors.len()` (in the `ScanDone` event).

2. **Collect all error sources, not just walk errors.** The worker
   fills `summary_errors` from three sources:

   - Early setup errors (path/SID validation, connection inputs,
     identity resolution) — collected via a `make_early_summary` closure
     that both sends the entry to the UI and adds it to the summary.
   - Local-group resolution with `NotAvailable` status — previously only
     a UI event, now additionally in the summary.
   - Walk errors from `walk.errors` (access-denied, path-not-found, etc.).
   - Permission-eval errors from the engine call.

3. **`persist_scan` writes every entry.** Signature extended with
   `errors: &[ScanError]`; one `store.insert_error(&run_id, …)` per entry.
   The existing cancellation marker (`path: None`,
   `"Scan cancelled by user — results are partial"`) is inserted after
   the structured errors as before.

4. **New `ScanStore::list_errors_for`** reads persisted errors back in
   insertion order (by rowid). Used by the GUI worker test and is a
   useful diagnostic API for future history views.

## Rationale

- **CLI ↔ GUI parity:** the audit expectation that "the scan run in the
  history is complete" must hold equally in both paths.
- **Closure instead of fourfold duplication:** the previous four
  early-return sites each built an identical
  `ScanSummary { ..., errors: 1, ... }`. `make_early_summary` replaces
  all four and guarantees that no path lets the UI event and the
  persistence drift out of sync.
- **`Vec<ScanError>` instead of `usize`** as the single source of truth:
  a count can be derived from a list, but not the other way around.

## Consequences

- 3 new tests in `gui::worker::tests` (persists walk errors, appends the
  cancellation marker, empty run stays empty).
- 2 new tests in `persistence::scan_store::tests` for the new
  `list_errors_for` API (order + run isolation).
- No schema migration needed — `scan_errors` already exists and supports
  `path` as a nullable column. Existing GUI scan histories remain
  readable; only new runs benefit from the full error persistence.
- The count display in the `ScanDone` event and in the UI stays
  unchanged (semantically and visually).
