# ADR 0036 — Unified principal-resolution pipeline

**Status:** Accepted
**Date:** 2026-06-04

## Context

ChatGPT code review 2026-06-04 round 3 (finding 1, High) revealed that the
multi-domain/trust fallback introduced in v1.4.1 took effect **only for
`DOMAIN\user`**. Three other input paths bypassed the central logic:

- **GUI name → SID workflow**: `resolve_name_to_sid` resolved the name via
  LSA but wrote **only the SID** into the UI field. The later analysis
  called `resolve_identity_sids(sid, ldap)` with a bare SID string — the
  LSA information disappeared, the LDAP miss ended in a wrongly-`Orphaned`
  classification.
- **CLI direct SID input**: the same direct `resolver.resolve_identity(&sid)`
  path, with hard-coded diagnostic flags `(false, false)`.
- **UPN path**: `lookup_via_upn` searched only under the configured
  `base_dn` and returned `None` on a miss, even though the docs promised a
  multi-domain fallback.

Additionally, the identity cache behaved toxically: a
`resolve_identity_internal` call cached an `Orphaned` identity on an LDAP
miss **before** `lookup_via_lsa` built the LSA-only identity — a follow-up
call for the same SID could return stale `Orphaned` data.

Thus the same real trust principal could appear, depending on the UI/CLI
input form, sometimes correctly with diagnostic markers, sometimes silently
as an orphaned SID. For AD/DC audits this is not acceptable — the entire
point of the markers from ADR 0033 (severity visibility) was undermined by
it.

## Decision

A new pipeline `ad_resolver::principal` with **a single public entry-point
method** that handles all input forms uniformly and consolidates the
diagnostic source in **one** model:

```text
PrincipalInput::Auto(...)
   ↓ classify() — trims + classifies
PrincipalResolver::resolve()
   ├─ DomainQualified / DisplayName → LSA-first path
   │       ↓ LSA: name → SID
   │       ↓ then same path as SID
   ├─ Sid                             → LDAP lookup
   │       ↓ LDAP miss + LSA hit      → LSA-only identity
   │                                     scope = OutsideConfiguredLdapBase
   │       ↓ LDAP miss + LSA miss     → OrphanedSid
   │       ↓ LDAP error               → LookupFailed { reason }
   ├─ Upn                             → LDAP lookup, miss = explicit error
   │                                      with GC hint (no silent fallback)
   └─ SamAccount                      → LDAP lookup with uniqueness check
                                     ↓
              PrincipalResolution {
                  sid, identity, memberships,
                  scope_status:           IdentityScopeStatus,
                  group_resolution_status: GroupResolutionStatus,
                  disabled_status:        DisabledStatus (tri-state),
                  diagnostics:            Vec<PermissionDiagnostic>,
              }
                                     ↓
              EngineFlags { 3 bool flags for PermissionEvaluationInput }
```

**Four tri-state/enum models** replace the previous
bool-flag-special-tuple constructions:

- `IdentityScopeStatus` — `InsideConfiguredLdapBase` /
  `OutsideConfiguredLdapBase` (trust/multi-domain) / `OrphanedSid` /
  `LookupFailed { reason }`. **Separates** real orphaned SIDs from real
  cross-domain principals.
- `GroupResolutionStatus` — `LdapRecursive` / `SamFlat` /
  `Failed { reason }` / `NotAttempted`. **Separates** "resolution happened
  with a gap" from "resolution did not happen at all".
- `DisabledStatus` — tri-state `Known(bool)` / `Unknown`. **Separates**
  "account active" from "account status not known".
- `EngineFlags` — the three booleans that flow into
  `PermissionEvaluationInput`. **Single source of truth**: all callers
  derive them via `PrincipalResolution::engine_flags()`.

**Backend traits** (`IdentityBackend`, `LsaBackend`) make the resolver
fakable — phase 2 built an 11-case test matrix with in-memory LDAP and LSA
fakes that covers exactly the input/result combinations where the old
architecture silently failed.

**Cache bug**: `resolve_identity_internal` no longer caches `Orphaned`
identities — the next call gets fresh data, LSA reclassification can always
step in.

## Consequences

**Positive:**

- The same principal yields bit-exactly the same resolution result in CLI
  and GUI for every input form. No more silent classification drifts.
- Four sharply delimited states replace three bool flags — new diagnostic
  markers can be added without API drift.
- The UPN docs now match the implementation: a UPN miss is an explicit
  validation error with a hint about GC bind, not a silent orphan.
- The `_via_*` helpers and the old `LookupResult` struct are gone — less
  public API surface, fewer special paths.
- The test matrix with fakes runs in the normal `cargo test --workspace`,
  not only as `#[ignore]` integration tests.

**Negative:**

- Internal API break: all callers had to be migrated (CLI 2 sites, GUI 2
  sites). Breaks no public consumers, because Stars has no external
  embedders.
- The `principal` module is non-trivially large (~700 lines incl. tests).
  Accepted as necessary complexity for a correct pipeline.

**Test requirements:**

- 11 tests in `principal::tests`:
  - `domain_user_ldap_hit_is_inside_base`
  - `domain_user_ldap_miss_with_lsa_hit_is_outside_base`
  - `direct_sid_ldap_miss_with_lsa_hit_is_outside_base` (core regression)
  - `display_name_workflow_uses_lsa_then_cross_checks`
  - `upn_outside_configured_base_returns_explicit_error`
  - `unknown_sid_with_no_lsa_match_is_orphaned`
  - `ldap_disabled_account_pushes_identity_disabled_marker`
  - `ldap_miss_without_lsa_backend_is_orphaned`
  - `ldap_error_yields_lookup_failed_not_orphaned`
  - `ambiguous_sam_returns_uniqueness_error`
  - `auto_dispatcher_classifies_by_syntax_and_trims`

## Closes

Review 2026-06-04 round 3, finding 1 (multi-domain fallback only for
`DOMAIN\user`) incl. the cache poisoning as an implicit sub-finding.

## References

- ADR 0021 — permission diagnostics as a variant-tagged enum.
- ADR 0032 — identity-input dispatcher and LDAP timeouts.
- ADR 0033 — visible diagnostics for SAM fallback and disabled identities.
- ADR 0034 — multi-domain LSA fallback (v1.4.1, **only `DOMAIN\user`**;
  this ADR generalizes).
- ADR 0035 — the SAM path `disabled` via `NetUserGetInfo`.
- ADR 0037 — propagate validated wrappers consistently (parallel).
- ADR 0038 — share-DACL trustees in the scan path (parallel).
