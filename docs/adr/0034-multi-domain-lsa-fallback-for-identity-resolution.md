# ADR 0034 — Multi-domain LSA fallback for identity resolution

**Status:** Accepted
**Date:** 2026-06-04

## Context

In the second ChatGPT code review pass on 2026-06-04, the `DOMAIN\user`
path in `ad_resolver::resolver::LdapResolver` was in focus. Previous
behavior:

1. `LookupAccountNameW` (LSA) resolves `DOMAIN\user` correctly to the SID —
   also for trusted domains outside the forest root.
2. Afterwards `resolve_identity_internal(sid)` tries to find the
   corresponding identity via LDAP over `objectSid`.
3. If the LDAP search returns `None` (the standard case in multi-domain
   forests, because `base_dn` points to a single domain), an
   `IdentityKind::Orphaned` identity was previously produced. This
   particularly affected accounts from trusted domains and cross-forest
   trusts.

Consequences of the previous classification:

- Real domain users were rendered as "orphaned SID".
- The explanation paths had no name.
- Audit consumers could not distinguish whether the SID is really unknown
  or whether the `base_dn` simply indexes the wrong domain.
- Group resolution ran onto a bare list — a true recursive domain-group
  resolution was not possible in this constellation.

## Decision

When LSA returns a valid SID but LDAP does not index the SID, the resolver
falls back to an **LSA-only identity** and marks the result via two
structured diagnostic markers on the `EffectivePermission`:

1. **New diagnostic variant `IdentityNotInConfiguredLdapBase`**
   - Set as soon as `lookup_via_lsa` could resolve a SID, but the
     configured LDAP `base_dn` does not cover the SID.
   - The engine pushes the marker; `risk_engine::is_incomplete()` matches
     it (like `DomainGroupRecursionIncomplete`) — derived risk findings are
     reported as `incomplete = true`.

2. **New diagnostic variant `IdentityDisabledStatusUnknown`**
   - Additionally set, because in the LSA-only path neither `disabled` nor
     `userPrincipalName` is reliably known.
   - `risk_engine::is_incomplete()` deliberately does **not** match the
     variant — it is purely informational. The ACL evaluation itself is
     correct; only the question "can the account authenticate at all?"
     remains open.

3. **Data flow through the whole pipeline:**
   - `LookupResult` (new in `ad_resolver`) carries both flags.
   - `ResolvedIdentity` (CLI) and `IdentityResolution` (GUI worker) pass
     them through.
   - Both fields in `PermissionEvaluationInput`
     (`identity_not_in_configured_ldap_base`,
     `identity_disabled_status_unknown`).
   - The engine checks both flags and pushes the matching marker for each.

4. **LSA-only identity construction:**
   - The helper `build_identity_from_lsa(sid)` in `resolver.rs` calls
     `lookup_account_for_sid` and builds an identity with `kind` from
     `sid_use_to_kind`, `disabled = false` (conservative default), and
     `user_principal_name = None`. On an LSA error, the `Orphaned` path
     remains as the last stage.

5. **Renderers:**
   - CLI (`output::print_report`) prints a `[!]` hint for
     `IdentityNotInConfiguredLdapBase` and an `[i]` hint for
     `IdentityDisabledStatusUnknown`.
   - HTML exporter (`exporter::html`) renders a `badge-medium` and
     `badge-info` respectively.

## Consequences

**Positive:**

- Audit consumers see explicitly why a finding is incomplete — no more
  silent false-`Orphaned` classifications.
- `IdentityNotInConfiguredLdapBase` makes the configuration visible:
  whoever wants to evaluate the forest completely knows immediately that a
  second (or global-catalog) `base_dn` is needed.
- Engine, CLI, GUI, HTML/CSV/JSON all go uniformly through the
  `PermissionDiagnostic` pipeline — no special path, no re-render.
- Breaks no existing consumers: variant-tagged JSON is forward-compatible.

**Negative:**

- In the LSA-only path, nested domain groups *of the trust partner* are
  still not resolved. The marker makes this visible, but does not solve it.
- `disabled` is not reliable in the LSA path. ADR 0035 covers the analogous
  SAM path with `NetUserGetInfo` — for pure LSA resolutions, an additional
  `NetUserGetInfo` query against the trust-partner server would be needed
  (outside this ADR).

**Test requirements:**

- Permission-engine tests that set `identity_not_in_configured_ldap_base =
  true` must see the corresponding marker in `result.diagnostics`.
- Risk-engine tests: a finding over a permission with
  `IdentityNotInConfiguredLdapBase` must carry `incomplete = true`.
- Renderer snapshots (HTML/CSV): the two new markers must not invent the
  variant's string, but render the UI description.

## Closes

Review 2026-06-04 round 2, finding 1 (multi-domain LSA fallback).

## References

- ADR 0021 — permission diagnostics as a variant-tagged enum.
- ADR 0032 — identity-input dispatcher and LDAP timeouts (introduces the
  `DOMAIN\user` path).
- ADR 0033 — visible diagnostics for SAM fallback and disabled identities
  (variant schema and flag propagation as a template).
- ADR 0035 — the SAM path confirms `disabled` via `NetUserGetInfo`
  (complementary to this ADR).
