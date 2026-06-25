# ADR 0032 — Identity-input dispatcher and enforced LDAP timeouts

**Status:** Accepted
**Date:** 2026-06-04

## Context

Two findings from the ChatGPT code review 2026-06-04 showed weaknesses in
LDAP resolution that directly affected functional correctness:

- **Finding 3 (High):** `LdapResolver::lookup_by_samaccount` accepted
  `DOMAIN\username`, but silently cut off the domain part and searched only
  `(sAMAccountName=username)` under `base_dn`. In multi-domain forests or
  with a duplicate `sAMAccountName` this could return the SID of the
  **wrong** user; even in a single domain the input was formally qualified
  but semantically discarded.

- **Finding 5 (Medium):** `LdapConfig::timeout_secs` was configurable, but
  was not enforced anywhere with `tokio::time::timeout`. An unreachable DC,
  a firewall drop, DNS problems, or a slow global catalog could block the
  analysis indefinitely.

## Decision

### Finding 3 — three explicit input forms, three dedicated paths

`LdapResolver::lookup_by_samaccount` is a dispatcher with a clear routing
table:

| Input | Path | Rationale |
|---|---|---|
| `DOMAIN\user` | Windows LSA (`LookupAccountNameW`) | LSA is **domain-aware**; returns a unique SID. Afterwards identity details via `resolve_identity_internal` (LDAP SID search). |
| `user@domain.tld` (UPN) | LDAP `(userPrincipalName=…)` | UPN is **forest-wide unique**. |
| `username` (plain) | LDAP `(sAMAccountName=…)` with a uniqueness check | On `len() > 1` the helper returns `Err(CoreError::Validation("Ambiguous sAMAccountName …"))` instead of blindly `next()`. |

Empty input → `Err(CoreError::Validation(…))` instead of a silent no-op.

New helpers in `ldap_client`:

- `search_all_by_samaccount` (returns **all** matches for the uniqueness
  check — `search_by_samaccount` is now a thin wrapper that returns
  `Ok(into_iter().next())`).
- `search_by_upn` for the UPN variant.

### Finding 5 — timeout wrapper as a central layer

New `pub async fn ldap_client::with_timeout(operation, duration, fut)` plus
`pub fn ldap_timeout(&config) -> Duration`. A timeout hit returns
`CoreError::LdapQuery("LDAP operation '<op>' timed out after Ns")`.

`LdapResolver::lookup_by_samaccount`, `resolve_identity_internal`, and
`resolve_memberships_internal` (via a new `inner` helper) wrap their entire
LDAP logic once with the configured timeout. `connect` itself additionally
wraps TCP/TLS setup and bind separately — a hanging connection is thus
caught directly during setup, not only on the first search.

## Rationale

- **A dedicated path per form** is more robust than a heuristic. Whoever
  writes `DOMAIN\user` should hit exactly that domain — not a randomly
  chosen identity of the same name.
- **The LSA path for `DOMAIN\user`** saves an LDAP round-trip and uses the
  domain-aware resolution that Windows performs anyway — no
  re-implementing the domain DN logic in the client.
- **Uniqueness check instead of `next()`** makes responsibility clear:
  whoever has multiple matches must disambiguate deliberately.
- **Timeout wrapper at the method level** is the right granularity. A
  logical operation is a unit; the caller sets `timeout_secs` for the whole
  operation, not per sub-call.

## Consequences

- Callers who write `lookup_by_samaccount("admin")` now get a clear error
  in multi-match scenarios instead of a wrong SID. Migration: write
  `DOMAIN\admin` or `admin@domain.tld` explicitly.
- `LdapConfig::timeout_secs` now actually takes effect. Whoever expects a
  very large transitive group result should set the value accordingly
  (default 10s).
- The LSA path is `#[cfg(windows)]`-specific; on non-Windows the function
  returns a `Validation` error — Stars targets Windows anyway.

## Tests

Unit tests for the dispatcher itself can only be written to a limited
extent without a real LDAP/LSA environment. Build verification covers the
signature consistency; the already-existing `#[ignore]` integration tests
(`resolve_administrator_identity`, `resolve_group_memberships_max_mustermann`,
…) are run against a real TESTDOMAIN and cover dispatch and the timeout
wrapper.

## Closes

ChatGPT code review 2026-06-04, findings 3 (High) and 5 (Medium).
