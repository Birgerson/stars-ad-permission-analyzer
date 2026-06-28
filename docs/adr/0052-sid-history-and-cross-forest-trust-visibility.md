# ADR 0052 — Make the SID-history (L3) and cross-forest-trust (L4) gaps visible

**Status:** Accepted (2026-06-28)
**References:** known-limitations L1–L4, ADR 0021 (diagnostic markers),
ADR 0034 / 0039 (marker plumbing), ADR 0051 (signed LDAP)

## Context

Stars computes effective rights from the SID set it can resolve for an
identity and matches that set against the DACL. Two real-world cases make
that computation **silently wrong** — the dangerous "looks safe, isn't
safe" class — because, unlike most incompleteness sources, they produced
**no runtime marker** at all:

- **L3 — SID history (under-report).** A migrated account carries earlier
  SIDs in `sIDHistory`. The real Windows logon token includes them, so an
  ACE on an old SID grants access. Stars did not fetch `sIDHistory`, so it
  saw the old SID as "another user", matched nothing, and reported **less**
  access than exists.
- **L4 — cross-forest trust effects (over-report).** A forest trust may
  apply **SID filtering / quarantine** (dropping SIDs) and **Selective
  Authentication** (blocking the logon before the ACL is evaluated). Stars
  reads the raw DACL and assumes every SID passes and authentication is
  allowed, so it can report **more** access than exists.

Both were demonstrated live against the test lab (cross-forest `sIDHistory`
injection; a Selective-Authentication block; a SID-filtering trust flip).
In each case Stars produced a confident, wrong number with no warning.

## Decision

Implement the **visibility step** (option A of the three scoped options):
surface the gaps through the existing `PermissionDiagnostic` marker
mechanism, **without** changing the effective-rights computation.

Two new variants in `adpa_core::model::PermissionDiagnostic`:

1. `SidHistoryPresent { count }` — **incompleteness trigger.** Emitted when
   the resolved identity carries one or more `sIDHistory` values. Drives
   `risk_engine::is_incomplete`, so derived risk findings carry
   `incomplete = true`. Message: the account carries N historical SID(s);
   ACEs referencing them are not evaluated, so rights may be understated.
2. `CrossForestTrustEffectsNotModeled` — **informational.** Emitted when the
   identity crosses a forest trust (resolved via a Foreign Security
   Principal **or** found outside the configured LDAP base — both signals
   already computed). It deliberately does **not** raise a second
   incompleteness trigger, because the FSP / outside-base markers beside it
   already set `incomplete`. Message: SID filtering / quarantine and
   Selective Authentication may reduce the shown access.

Data flow (mirrors the existing `disabled` attribute):

- `sIDHistory` is added to `IDENTITY_ATTRS` and counted via a new
  `RawEntry::value_count` helper (it is a multi-valued **binary** SID
  attribute, so values land in `bin_attrs`).
- `parse_identity_from_entry` sets the new `Identity::sid_history_count`
  (`#[serde(default)]` for persisted back-compat). The SAM/LSA path cannot
  read it → count `0` → marker stays silent (no false positive).
- The engine reads `input.identity.sid_history_count` (exactly as it reads
  `input.identity.disabled`) and derives the cross-forest marker from the
  existing `identity_resolved_via_fsp` / `identity_not_in_configured_ldap_base`
  inputs. Rendered by `cli::output` and the HTML exporter.

## Why on `Identity` (not a new `PermissionEvaluationInput` flag)

`sIDHistory` is an attribute of the principal, exactly like `disabled` —
which already lives on `Identity` and is read by the engine as
`input.identity.disabled`. Putting the count there keeps the data flow
trivial (resolver sets it → engine reads it) with no extra plumbing through
`PrincipalResolution` / `EngineFlags` / the input struct.

## Scope boundary (deliberate)

This step makes the gaps **visible** (silently-wrong → honestly-uncertain).
It explicitly does **not**:

- evaluate the historical SIDs into the token (would change the
  effective-rights core — and would itself be wrong without trust modeling,
  since whether a historical SID is honored depends on the trust's
  SID-filtering state, which Stars does not read);
- read `trustAttributes` / model SID filtering or Selective Authentication.

That fuller evaluation (option B) is a larger, higher-risk follow-up because
it touches the safety-critical effective-rights computation and cannot be
correct without modeling per-trust filtering. For a read-only audit tool,
**honest incompleteness beats confident incorrectness**, so the visibility
step is the correct first building block and is valuable on its own.

## Alternatives considered

- **B — evaluate history into the token.** Rejected for now: blindly adding
  `sIDHistory` SIDs would trade the L3 under-report for an L4 over-report in
  the common (SID-filtering-on) case. Correct only together with trust
  modeling; tracked as the deeper follow-up.
- **C — documentation only.** Rejected: the gaps stay silent in the tool;
  the whole point is that the report itself must flag them.

## Consequences

- Migrated-account and cross-forest findings are now flagged instead of
  silently wrong; `SidHistoryPresent` additionally marks them incomplete.
- A least-privilege bind that cannot read `sIDHistory` simply sees count `0`
  — the marker stays silent rather than producing a false positive.
- known-limitations L3/L4 updated from "no marker" to "visible (ADR 0052)";
  the evaluation work remains open there.

## Tests

- Engine: `SidHistoryPresent` fires when `sid_history_count > 0` and not when
  `0`; `CrossForestTrustEffectsNotModeled` fires for FSP and for
  outside-base, and not for a plain in-domain identity.
- Risk engine: `SidHistoryPresent` marks a finding incomplete;
  `CrossForestTrustEffectsNotModeled` alone does not.
