# ADR 0039 — Diagnostics for failed identity and group resolution

**Status:** Accepted
**Date:** 2026-06-04

## Context

Review 2026-06-04 round 4 finding 1 (High) revealed a follow-up deficiency
of the central principal pipeline introduced in ADR 0036: the new status
values `IdentityScopeStatus::LookupFailed { reason }`,
`GroupResolutionStatus::Failed { reason }`, and in certain constellations
also `GroupResolutionStatus::NotAttempted` produced **no visible diagnostic
markers**.

Concrete consequence:

- An LDAP bind error, timeout, or query crash in `resolve_by_sid` was
  converted into `LookupFailed { reason }` — the analysis continued with a
  placeholder identity and empty memberships.
- `resolve_groups` converted errors into `Failed { reason }` and returned
  empty memberships; the engine saw this as a "no multi-domain" standard
  case.
- `engine_flags()` set only three booleans (`Outside`, `Unknown`,
  `SamFlat`); `LookupFailed` and `Failed` flowed nowhere.
- The permission engine pushed no corresponding marker; the risk engine
  could not set `incomplete = true`.

In practice, a finding could thereby **look "clean"** even though it was
computed with an empty token. Exactly the anti-pattern that the entire
marker architecture has been meant to avoid since ADR 0021.

(Self-criticism: I had already identified this problem myself in the honest
status answer at the end of the v1.4.1 discussion, but left it open in
v1.5.0 as "LookupFailed is an edge case". That was a mistake — edge cases
are exactly where markers must be visible.)

## Decision

Two new structured diagnostic markers in
`adpa_core::model::PermissionDiagnostic`:

```rust
PermissionDiagnostic::IdentityLookupFailed { reason: String }
PermissionDiagnostic::GroupResolutionFailed { reason: String }
```

Both carry the original error text along, so auditors see the real problem
(bind error, timeout, wrong DC address …) in the report. Both are
**incompleteness triggers** — the risk engine matches them in
`is_incomplete()`.

Data flow:

```text
PrincipalResolution.scope_status / group_resolution_status
   ↓ PrincipalResolution::engine_flags()
EngineFlags {
   …,
   identity_lookup_failure_reason: Option<String>,
   group_resolution_failure_reason: Option<String>,
}
   ↓ into PermissionEvaluationInput
PermissionEvaluationInput {
   …,
   identity_lookup_failure_reason: Option<String>,
   group_resolution_failure_reason: Option<String>,
}
   ↓ the engine pushes the matching marker per Some value
EffectivePermission.diagnostics +=
   IdentityLookupFailed { reason }
   GroupResolutionFailed { reason }
   ↓ the risk engine is_incomplete() matches both
RiskFinding.incomplete = true
   ↓ CLI and HTML renderers describe both markers
   ↓ JSON export carries them variant-tagged
```

**Three derivation rules** in `engine_flags()`:

1. `IdentityScopeStatus::LookupFailed { reason }` →
   `identity_lookup_failure_reason = Some(reason)`.
2. `GroupResolutionStatus::Failed { reason }` →
   `group_resolution_failure_reason = Some(reason)`.
3. `IdentityScopeStatus::OutsideConfiguredLdapBase` +
   `GroupResolutionStatus::NotAttempted` →
   `group_resolution_failure_reason = Some("group resolution skipped:
   identity is outside the configured LDAP base")`. Previously the outside
   path could silently compute without groups.

**Renderers:**

- CLI (`output::print_report`) prints a `[!]` hint for both markers with
  reason text.
- HTML exporter (`exporter::html`) renders both as `badge-high` with the
  reason in the `title` attribute (HTML-escaped).

## Consequences

**Positive:**

- Technical LDAP/NetAPI errors now appear explicitly in CLI, HTML, and
  JSON — auditors know why a finding is incomplete.
- Risk findings are automatically marked as `incomplete = true` —
  symmetric to all other incompleteness sources.
- The `OutsideConfiguredLdapBase + NotAttempted` path is no longer a silent
  skip; the gap becomes visible to the auditor.

**Negative:**

- `EngineFlags` is no longer `Copy` (now contains `Option<String>`).
  Callers must use `.clone()` if they consume it multiple times. Current
  callers were adapted accordingly.
- `PermissionEvaluationInput` grows by two optional fields; the migration
  is additive.

**Test requirements:**

- 3 principal tests:
  - `ldap_error_yields_lookup_failed_not_orphaned` (extended with an
    `engine_flags()` assertion)
  - `group_resolution_error_after_identity_hit_carries_reason`
  - `outside_base_with_skipped_groups_yields_group_failure_reason`
- 2 engine tests:
  - `engine_pushes_identity_lookup_failed_diagnostic_with_reason`
  - `engine_pushes_group_resolution_failed_diagnostic_with_reason`
- 2 risk-engine tests (positive `incomplete = true` assertion):
  - `full_control_marks_finding_incomplete_on_identity_lookup_failed`
  - `full_control_marks_finding_incomplete_on_group_resolution_failed`

## Closes

Review 2026-06-04 round 4, finding 1.

## References

- ADR 0021 — permission diagnostics as a variant-tagged enum.
- ADR 0033 — visible diagnostics for SAM fallback and disabled identities
  (marker-schema template).
- ADR 0034 — multi-domain LSA fallback.
- ADR 0035 — the SAM path `disabled` via `NetUserGetInfo`.
- ADR 0036 — unified principal-resolution pipeline (introduces the status
  enums whose reasons are passed through here).
- ADR 0037 — propagate validated wrappers consistently.
- ADR 0038 — share trustees in the scan output.
