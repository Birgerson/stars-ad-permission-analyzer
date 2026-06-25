# ADR 0035 — The SAM path confirms `disabled` via `NetUserGetInfo`

**Status:** Accepted
**Date:** 2026-06-04

## Context

In the second ChatGPT code review pass on 2026-06-04, a silent correctness
problem surfaced in the SAM fallback path
(`ad_resolver::sam::resolve_identity_via_sam`):

- The SAM path previously built `Identity` from `LookupAccountSidW` and
  `NetUserGetGroups`. Both APIs return the display name, the domain, and
  the direct groups — but **not** the `userAccountControl` bit
  `UF_ACCOUNTDISABLE`.
- Consequence: `Identity.disabled` was uniformly `false` in the SAM path.
  An account that was in truth disabled appeared as active in the report
  and got no corresponding UI diagnostic. In the LDAP path this worked
  correctly, because there `userAccountControl` came directly from AD.
- The `IdentityDisabled` marker (ADR 0033) therefore ran silently as soon
  as the scan went through SAM resolution — typically on a domain
  controller without explicit LDAP configuration.

Without a fix, an audit consumer could not tell that the `disabled` status
for a SAM-resolved identity is even questionable. This violates the
"no silent skips" rule.

## Decision

1. **New helper function `user_account_disabled`** in `ad_resolver::sam`:
   - Calls `NetUserGetInfo(server, user, level=1, &mut buf)`, reads
     `USER_INFO_1::usri1_flags`, and checks whether
     `UF_ACCOUNTDISABLE (= 0x2)` is set.
   - Return `Result<Option<bool>, CoreError>`:
     - `Ok(Some(true))`  → account disabled.
     - `Ok(Some(false))` → account active.
     - `Ok(None)`        → status not reliably determinable
       (`NERR_USER_NOT_FOUND`, `ERROR_ACCESS_DENIED`, other NetAPI errors).
       Callers then mark the diagnostic status as unknown.
     - `Err(_)`         → unexpected library error.

2. **`resolve_identity_via_sam` now returns a `SamResolution` struct**
   instead of a tuple. The struct carries `identity`, `memberships`, and
   additionally `disabled_known: bool`. The worker decides, based on this
   flag, whether it must set
   `PermissionEvaluationInput::identity_disabled_status_unknown`.

3. **`Identity.disabled` is now reliable in the SAM path:**
   - For `IdentityKind::User` the value is set via `user_account_disabled`;
     on failure `disabled = false` remains, but `disabled_known = false`
     informs the caller.
   - For groups, computers, and well-known SIDs there is no `disabled`
     status — `disabled_known = true` with `disabled = false` is
     definitively correct.

4. **Engine integration:**
   - `PermissionEvaluationInput::identity_disabled_status_unknown` pushes
     the diagnostic marker `PermissionDiagnostic::IdentityDisabledStatusUnknown`.
   - `risk_engine::is_incomplete()` does **not** match this marker — it is
     informational, not a completeness deficiency of the ACL model.
   - CLI and HTML render the marker with their own description (`[i]` hint
     and `badge-info` respectively).

## Consequences

**Positive:**

- The SAM path now delivers the same degree of correctness regarding
  `disabled` as the LDAP path.
- Auditors see explicitly when the `disabled` status could not be
  determined (e.g. because of access denied on the NetAPI call) —
  previously that was a default `false`.
- Breaks no existing API: the `SamResolution` struct is additive; the only
  internal caller (`gui::worker::sam_resolve_fallback`) was adapted.

**Negative:**

- An additional NetAPI call per identity in the SAM resolution.
  `NetUserGetInfo` is cheap on a DC — on a workstation that does not know a
  remote user, it fails with `NERR_USER_NOT_FOUND`; that is translated into
  `Ok(None)` and the marker appears.

**Test requirements:**

- The DC integration test (`resolve_local_administrator_yields_memberships`,
  `#[ignore]`) now additionally checks that `disabled_known = true`, because
  `NetUserGetInfo` must be answerable for the built-in administrator.
- Engine tests set `identity_disabled_status_unknown` and see the marker in
  `result.diagnostics`.
- Risk-engine test: a finding over a permission with only
  `IdentityDisabledStatusUnknown` must **not** carry `incomplete = true`
  (a negative assertion to secure the separation from
  `IdentityNotInConfiguredLdapBase`).

## Closes

Review 2026-06-04 round 2, finding 5 (SAM disabled status).

## References

- ADR 0021 — permission diagnostics as a variant-tagged enum.
- ADR 0033 — `IdentityDisabled` for the LDAP path and the original marker
  idea.
- ADR 0034 — multi-domain LSA fallback (introduces
  `IdentityDisabledStatusUnknown`; this ADR uses the same marker).
- Windows API docs on `USER_INFO_1::usri1_flags` and `UF_ACCOUNTDISABLE`.
