# ADR 0033 — Visible diagnostics for SAM fallback and disabled identities

**Status:** Accepted
**Date:** 2026-06-04

## Context

Two findings from the ChatGPT code review 2026-06-04 hit the same
mechanism — structured diagnostic markers on the `EffectivePermission`:

- **Finding 6 (Medium):** the SAM/LSA fallback without LDAP uses
  `NetUserGetGroups`, which yields only direct global groups. Nested domain
  groups are not resolved recursively; on a domain controller the result is
  better than a bare SID fallback, but not complete for deeply nested AD
  groups. This limitation was previously mentioned only in a code comment —
  an audit reader could not tell that the computation might be incomplete.

- **Finding 7 (Low):** the LDAP resolver correctly detects disabled users
  via `userAccountControl`. The permission engine nevertheless computes the
  theoretical rights from SID and groups unchanged. That is sensible for
  "ACL-derived rights", but for the actual remote SMB access of a disabled
  account it is not the same as an authenticatable access. CLI/HTML/JSON
  did not clearly separate the two views.

## Decision

Both gaps are closed via the already-existing `PermissionDiagnostic` vector
infrastructure (ADR 0021), which is serialized as variant-tagged JSON
anyway and can thus be extended with further markers in a future-proof way.

1. **Two new variants in `adpa_core::model::PermissionDiagnostic`:**

   - `DomainGroupRecursionIncomplete` — set as soon as group resolution
     runs via the SAM/LSA fallback instead of LDAP. Risk findings for this
     permission must carry `incomplete = true`.
   - `IdentityDisabled` — set as soon as the analyzed identity is marked
     disabled in AD (`userAccountControl` `ACCOUNTDISABLE`, bit `0x0002`).

2. **New input field
   `PermissionEvaluationInput.group_resolution_via_sam_fallback: bool`**
   (default `false`). The caller sets the flag when it uses the SAM path.
   The engine then automatically pushes `DomainGroupRecursionIncomplete`
   into the result.

3. **Engine logic for `IdentityDisabled`**: pushes the marker automatically
   when `input.identity.disabled == true`. No additional input field
   needed — the `Identity` carries the bit anyway.

4. **Caller plumbing:**

   - **GUI**: `resolve_identity_sids` now returns a `used_sam_fallback`
     flag (3-tuple `(Identity, Memberships, bool)`). The worker passes it
     into `PermissionEvaluationInput`.
   - **CLI**: uses the already-existing `ResolvedIdentity::ad_connected`
     with negation (`group_resolution_via_sam_fallback = !ad_connected`).

5. **Visible presentation:**

   - **HTML report** (`exporter::html`) shows, for
     `DomainGroupRecursionIncomplete`, a yellow
     `⚠ SAM fallback — nested groups not resolved` badge with a tooltip
     explanation; for `IdentityDisabled` a blue `ℹ disabled account` hint.
   - **CLI output** (`output::print_report`) prints two additional
     diagnostic blocks: `[!] Group resolution ran through the SAM/LSA
     fallback…` and `[i] Identity is flagged as disabled in AD…`.

## Rationale

- **Reuse of the existing diagnostic layer.** ADR 0021 established the
  `PermissionDiagnostic` vector for exactly this use case: structured,
  variant-tagged serialized, consistently rendered by CLI/HTML/JSON.
  Hooking in new audit markers is a one-liner in `model.rs` plus the
  respective renderer path.
- **Non-blocking style — the audit reader may keep reading.** A disabled
  account produces no engine error; it is a hint, not a blocker. That is
  exactly what the diagnostic layer is for.
- **Keep risk findings consistent.** Several risk rules use
  `is_incomplete(p)`. Both new markers fit this scheme — risk findings for
  affected permissions are automatically rendered as `incomplete = true`,
  without the rules needing adjustment.

## Consequences

- Existing construction sites of `PermissionEvaluationInput` must set the
  new field `group_resolution_via_sam_fallback` — a default of `false`
  would be possible, but is deliberately omitted so callers set the value
  explicitly.
- The two new variants need match arms in CLI / HTML; this is enforced by
  the compiler — no silent forgetting possible.
- Future further diagnostic markers (e.g. "Kerberos ticket expired",
  "account locked", "password expired") can follow the same pattern.

## Tests

Workspace tests stay green. The two new markers are rendered via the
already-existing diagnostic-display pipeline, which is covered by the
existing engine and exporter tests. Real-AD verification runs via the
`#[ignore]` integration tests against the test domain.

## Closes

ChatGPT code review 2026-06-04, findings 6 (Medium) and 7 (Low).
