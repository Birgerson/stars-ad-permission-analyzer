# ADR 0018 — CSV export: completeness diagnostics and structured audit data

**Status:** Accepted  
**Date:** 2026-05-24

## Context

The CSV export previously carried 15 columns — all top-level fields of an
`EffectivePermission` plus `share_status` and `unsupported_aces` as
diagnostics. Three important audit aspects were missing:

1. **`local_group_status`** — the `LocalGroupEvalStatus` marks the result
   as incomplete when local server groups could not be resolved (access
   denied, RPC error, …). The JSON export carries this in structured form;
   CSV left the audit user blind to it.
2. **`matched_aces`** — structured list of the ACEs whose trustee was in
   the token. Used by the risk engine; not accessible to external audit
   pipelines in the CSV.
3. **`contributing_sids`** — per SID, which bits effectively contributed
   (for broad-group risk analysis). Likewise only available in JSON.

Risk findings themselves were already, by documented decision, not in the
CSV (the CLI prints a `[Note]` hint); HTML or JSON is the appropriate
format for them.

See review finding 9.

## Decision

1. **Four new columns at the end of the CSV** — the order is deliberate so
   that existing importers with fixed column positions for the first 15
   columns keep running unchanged:

   | # | Column | Content |
   |---|---|---|
   | 16 | `local_group_status` | `not_queried` / `applied` / `not_available` |
   | 17 | `local_group_error` | error text on `not_available`, otherwise empty |
   | 18 | `matched_aces_json` | compact JSON array, always filled (`[]` when empty) |
   | 19 | `contributing_sids_json` | compact JSON array, always filled (`[]` when empty) |

2. **Status and reason in separate columns** (not `not_available:<reason>`
   as a single field) — so that Excel/grep filters can still match plain
   status values. This is a deliberate deviation from the format of the
   `share_status` column (`read_failed:<reason>`), where nothing was
   changed for backward compatibility.

3. **JSON-in-CSV cells** for `matched_aces` and `contributing_sids`:
   - Per `matched_aces` entry: `{sid, kind, mask: "0xHHHHHHHH", inherited}`
   - Per `contributing_sids` entry: `{sid, mask: "0xHHHHHHHH"}`

   Empty lists appear as `"[]"` (not as an empty cell) so consumers can
   always parse the column as JSON.

4. **Risk findings stay outside the CSV.** The CLI `[Note]` hint has become
   more precise: it explicitly names JSON as the structured format for
   risks, matched ACEs, and contributing SIDs in their full depth. CSV is
   the top-level table; JSON is the canonical machine-readable form for the
   whole tree.

## Rationale

- **Close the diagnostic gap without overturning structural decisions:**
  audit users whose primary format is CSV (Excel, Power BI, simple
  pipelines) now see the incomplete computation instead of overlooking it.
- **JSON strings in CSV cells are a deliberate trade-off:** the detail
  lists are variable-length and fit poorly into a flat table schema. A
  second detail CSV per detail list would be cleaner but forces consumers
  into joins and multiplies file operations. JSON cells are widely
  supported (Snowflake, BigQuery, jq) and avoid that.
- **Append-only** new columns preserve backward-compatible column
  positions 1–15.
- **Risk findings explicitly JSON-only** cleanly separates two levels:
  CSV = per-(path, identity) row; JSON = complete report.

## Consequences

- 5 new tests in `exporter::csv::tests`:
  - `local_group_status_applied_serialized_correctly`
  - `local_group_status_not_available_records_reason_separately`
  - `matched_aces_serialized_as_compact_json_array`
  - `contributing_sids_serialized_as_compact_json_array`
  - `empty_matched_aces_and_contributing_sids_yield_empty_json_arrays`
- `headers_match_expected` was extended (15 → 19 columns).
- CLI hint on CSV export extended: now points to JSON for structured
  details and risks.
- No schema change in `EffectivePermission` — the data is already there;
  only the CSV exporter now pulls it in.
- `exporter` already had `serde_json` as a workspace dependency — no new
  dependency.
