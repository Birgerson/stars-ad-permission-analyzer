# ADR 0040 — Candidate list for local group resolution

**Status:** Accepted
**Date:** 2026-06-04

## Context

Review 2026-06-04 round 5 finding 1 (High) revealed a **silent rights
under-estimation** in the local group path:

`format_account_for_local_groups()` built the account name for
`NetUserGetLocalGroups` blindly as `name@domain`. For identities that come
from the LSA/trust path (ADR 0034 / 0036), `domain` is, however, very often
a **NetBIOS name** like `TRUSTED`, not a DNS suffix. `alice@TRUSTED` is not
a valid UPN form — `NetUserGetLocalGroups` returns `NERR_USER_NOT_FOUND`.

`resolve_local_group_sids()` had treated the `NERR_USER_NOT_FOUND` case
explicitly as `Ok(Vec::new())` — justified on the merits with "not an error
in the strict sense". The callers (`collect_local_group_sids_for_path` in
CLI and GUI) saw an `Ok(v)` and set `LocalGroupEvalStatus::Applied`. The
finding:

1. Trust user correctly resolved via LSA.
2. Domain groups already marked as incomplete
   (`IdentityNotInConfiguredLdapBase`).
3. Local group search with `alice@TRUSTED` → `NERR_USER_NOT_FOUND`.
4. Stars sees `LocalGroupEvalStatus::Applied(0)` — "local groups
   successfully evaluated, none in them".
5. **ACEs on local server groups (e.g. `BUILTIN\Administrators`, of which
   the trust-domain group is a member) stay invisible.**
6. Effective rights can be computed too low, without an `incomplete` signal
   from this path.

For an AD/DC analysis tool, exactly this kind of silent under-estimation is
the most dangerous bug class: Stars *shows* rights that the auditor
considers correct, even though the computational basis was incomplete.

## Decision

**Three changes** in `crates/ad_resolver/src/local_groups.rs`:

### 1. Candidate list instead of a single account name

The new function `format_account_candidates_for_local_groups(identity)`
returns a `Vec<String>` in preference order:

1. `userPrincipalName` (the real UPN, if AD has set it).
2. `DOMAIN\name` — works for both NetBIOS and DNS domains, the most robust
   classic NetAPI form.
3. `name@domain` — **only** if `domain` looks like a DNS suffix (contains
   at least one dot). Heuristic: `looks_like_dns_domain()`.
4. `name` (plain) — local accounts without a domain.

The old `format_account_for_local_groups()` stays as a convenience wrapper
(returns the first candidate), so external consumers do not break — but is
no longer in internal use.

### 2. Strict variant with an explicit outcome

New type `LocalGroupLookupOutcome`:

```rust
pub enum LocalGroupLookupOutcome {
    WithGroups(Vec<Sid>),
    UserNotFoundOnServer,
}
```

The new function `resolve_local_group_sids_strict()` returns this type —
explicitly separating "user found, here are the (possibly empty) groups"
from "user not known on the server".

The old `resolve_local_group_sids()` stays as a backward-compat wrapper: on
`UserNotFoundOnServer` it still returns `Ok(Vec::new())`. So the public API
does not break.

### 3. Identity wrapper with a candidate loop

The new function `resolve_local_group_sids_for_identity(server, identity)`
is the **new, correct** path for the CLI/GUI consumers:

1. Builds the candidate list via
   `format_account_candidates_for_local_groups`.
2. Tries them one after another with `resolve_local_group_sids_strict`.
3. The first `WithGroups` match wins — even if the list is empty (that then
   honestly means: "the account is known but has no local groups", which is
   the correct answer).
4. If **all** candidates return `UserNotFoundOnServer`: returns a
   `CoreError::Validation(reason)` — the caller sets
   `LocalGroupEvalStatus::NotAvailable(reason)`, and that drives the
   `incomplete = true` logic in the risk engine.
5. On any other technical error (access denied, NetAPI error): propagate
   immediately, no further tries.

**CLI** (`crates/cli/src/main.rs::collect_local_group_sids_for_path`) and
**GUI** (`crates/gui/src/worker.rs::collect_local_group_sids_for_path`) now
call `resolve_local_group_sids_for_identity` directly with the `&Identity`,
no longer `format_account_for_local_groups` + `resolve_local_group_sids`.

## Consequences

**Positive:**

- Trust/multi-domain identities with a NetBIOS domain are now regularly
  detected via `DOMAIN\name` — the typical production case works.
- When the account is in fact not known on the target server, that now
  surfaces as `LocalGroupEvalStatus::NotAvailable(...)` with a concrete
  `tried` reason — no more silent skip.
- The risk engine automatically marks such findings as `incomplete = true`
  (`LocalGroupEvalStatus::NotAvailable` has been an incomplete trigger
  since v1.0).
- Backward compat: the old public APIs stay.

**Negative:**

- Up to four NetAPI calls per identity in the worst case (UPN,
  DOMAIN\name, name@dns, name). In practice the first or second candidate
  hits — the overhead is small.
- `LocalGroupEvalStatus::NotAvailable` appears more often than before,
  because the path is now honest. That is intended — the auditor previously
  saw silent `Applied(0)` findings that were in truth gaps.

**Test requirements:**

- 5 new unit tests in `local_groups::tests`:
  - `format_falls_back_to_domain_backslash_name_for_dns_domain`
  - `format_netbios_domain_only_emits_domain_backslash_form`
  - `format_returns_plain_name_without_domain` (extended)
  - `looks_like_dns_domain_distinguishes_netbios_and_dns`
  - `format_upn_wins_over_domain_form`
- The existing `format_ignores_empty_upn` adapted to the new
  `DOMAIN\name`-first order.
- The existing `format_returns_none_without_name` renamed to
  `format_returns_empty_without_name` (candidate list instead of an
  Option).

**What was deliberately NOT changed:**

- `resolve_local_groups` (with group names, internal to
  `resolve_local_group_chains` in `sam.rs` — that is a different API layer
  and not the ChatGPT path). There `account.name` from LSA is used
  directly; the fix can be ported in a later ADR if needed.
- `resolve_local_group_sids` itself (the public API) stays
  backward-compatible with `Ok(Vec::new())` on NERR — but new callers
  should use `_for_identity` or `_strict`.

## Closes

Review 2026-06-04 round 5, finding 1 (local server groups can silently be
missing for LSA/trust identities).

## References

- ADR 0033 — visible diagnostics for SAM fallback and disabled identities.
- ADR 0034 — multi-domain LSA fallback for identity resolution.
- ADR 0036 — unified principal-resolution pipeline.
- ADR 0039 — diagnostics for failed identity and group resolution
  (parallel: incomplete marker at the `EffectivePermission` level; this ADR
  adds it at the `LocalGroupEvalStatus` level).
- [known-limitations.md L5](../known-limitations.md) — empty memberships in
  the outside path.
