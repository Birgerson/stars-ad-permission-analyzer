# ADR 0020 — `matched_aces` filters out INHERIT_ONLY entries

**Status:** Accepted  
**Date:** 2026-05-24

## Context

Since ADR 0012 the engine correctly filters out `INHERIT_ONLY_ACE`
(flag 0x08) during the effective-rights computation — such ACEs apply
only to children, not to the current object. `collect_matched_aces`,
however, did not perform this filtering and returned all ACEs whose
trustee SID was in the token.

Consequence: `DirectUserAceRule` in the `risk_engine` (the best-practice
rule "permissions via groups, not directly on the user") consumes
`matched_aces` and looks for explicit user ACEs. An explicit-but-
inherit-only user ACE would show up there as a `DIRECT_USER_ACE` finding
even though it does not touch the current object at all — a false
positive.

Follow-up review (2026-05-24), finding 2.

## Decision

`collect_matched_aces` now additionally filters via
`ace_applies_to_current_object(ace)` — the same helper the engine
evaluation and `collect_contributing_sids` already use. This reduces
`EffectivePermission.matched_aces` to the ACEs that are actually
applicable to the current object.

The explanatory information about IO ACEs is not lost: `build_explanation`
still marks IO entries in the `PermissionPath` with
`[inherit-only — not applied to this object]` (introduced in ADR 0012).
Risk rules work with `matched_aces`, reports with the explanation — the
separation fits.

## Rationale

- **Minimal invasiveness:** one line of filter logic, no model change, no
  persistence migration. The alternative — an
  `applies_to_current_object: bool` flag on `AceEntry` — would be more
  correct in the sense of "preserve information", but would have touched
  schema fields, serialization, DB persistence, and exports. The
  explanation already carries the info; the filter fixes the false
  positive.
- **Symmetry with the engine:** `evaluate_dacl_ordered` and
  `collect_contributing_sids` already filter via
  `ace_applies_to_current_object`. `collect_matched_aces` follows this
  pattern.

## Consequences

- 1 new engine test (`inherit_only_ace_not_in_matched_aces`).
- 1 new risk-engine test
  (`inherit_only_explicit_user_ace_does_not_trigger_direct_user_finding`)
  — documents the downstream effect in the concrete audit use case.
- No schema or API change.
- Note for consumers: anyone who, in future use cases, wants to see the IO
  ACEs explicitly (e.g. "what inheritance expectations does the object
  have for its children?") can still derive them from the raw
  `FileSystemObject.dacl` — `matched_aces` is deliberately the "what
  applies now" view.
