# ADR 0014 — LDAP paging and server-side transitivity

**Status:** Accepted
**Date:** 2026-05-24

## Context

The original `LdapResolver` implementation had two classic AD problems:

1. **No paging.** `search_by_query` called `Ldap::search()` directly — without the paged-results control. If the result hits the AD default limit `MaxPageSize` (1000), it is truncated server-side without the client noticing. In large domains searches are silently incomplete.

2. **`memberOf` walking with range-retrieval risk.** Transitive group resolution ran client-side: first read `memberOf` on the user, then for each group read `memberOf` again, and so on. AD truncates `memberOf` at around 1500 values — users in many groups lose part of their membership. Additionally this caused N+1 LDAP round-trips per hierarchy level.

Visible live effect in the test server scan (before finding 8): even for `max.mustermann` (direct in two groups, transitive in two more), the resolver only returned `Domain Users` (the primary group).

See review finding 8.

## Decision

1. **Paged search as the default.** A new private helper `search_paged_with_limit` in `ldap_client` builds a `streaming_search_with` pipeline using the ldap3 adapters `EntriesOnly` + `PagedResults`. Default page size: 1000 (AD `MaxPageSize` default). Optional `client_limit` for use cases like "name suggestions" (max 50 hits for the picker list). `search_by_query` uses this function.

2. **Server-side transitive group resolution.** New function `search_transitive_groups_for_member(member_dn)` sends a single filter

   ```text
   (&(objectClass=group)(member:1.2.840.113556.1.4.1941:=<dn>))
   ```

   to the domain controller. The OID `1.2.840.113556.1.4.1941` (`LDAP_MATCHING_RULE_IN_CHAIN`) lets AD resolve transitivity in one round-trip. The search itself is paged.

3. **Resolver simplified.** `resolve_memberships_internal` now does:

   1. Load the entry (for DN + `primaryGroupID` + `memberOf` as a "direct" marker).
   2. Resolve `primaryGroupID` separately (it is not modelled via `member`).
   3. One transitive search for the user DN — returns every group the user is in via `member` chains.
   4. Transitively resolve the primary group as well (for its parent groups).
   5. Mark results as `direct=true/false` using the user's `memberOf` list.

   The old `resolve_groups_recursive` with `MAX_GROUP_DEPTH=64` is gone without replacement — cycles can no longer occur in this shape (the server returns sets of groups, not traversal paths).

4. **`memberOf` is now only a hint.** The authoritative membership list comes from the transitive search; `memberOf` is only used to classify "direct vs. transitive". If AD truncates `memberOf`, the impact is at most on the `direct` marker of individual groups (an inherited one could be wrongly tagged as transitive) — the membership itself is complete.

## Rationale

- **Correctness:** "Large AD environments are the default case" (AGENTS.md rule 9). The previous path failed silently in exactly those environments.
- **Fewer round-trips:** one LDAP operation per user instead of N per hierarchy level. Scales noticeably better with deep group nesting.
- **No more own cycle detection** — the server returns a set, not a traversal path.
- **Backwards-compatible public API:** `search_by_query` keeps its signature and the 50-hit cap; only the implementation underneath got more robust.
- **Deliberately not implemented: explicit range retrieval on `memberOf`.** With the transitive-search path it is redundant. If a future use case needs `memberOf` as truth, range retrieval can be added as an extra `ldap_client` function.

## Consequences

- `LDAP_MATCHING_RULE_IN_CHAIN` is AD-specific (Windows Server 2003 R2 and newer). OpenLDAP and others do not support the OID — but the project explicitly targets Active Directory.
- The existing integration test `resolve_group_memberships_max_mustermann` has been tightened: previously optional transitivity asserts are now unconditional. Additionally checked: the `direct` marker on the returned memberships.
- The constant `MAX_GROUP_DEPTH` is removed; `MAX_GROUP_DEPTH` warnings in the log are gone.
