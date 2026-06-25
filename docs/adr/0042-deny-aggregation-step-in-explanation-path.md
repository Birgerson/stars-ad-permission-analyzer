# ADR 0042 — Deny aggregation as a dedicated explanation-path step

**Status:** Accepted
**Date:** 2026-06-05

## Context

The Stars engine aggregates NTFS Allow and Deny ACEs into a single final
`ntfs_raw` mask (function `evaluate_dacl_ordered`). This mask flows into the
explanation path as a single step:

```text
NTFS effective: Special (0x00100000)
```

As long as only Allow ACEs are involved, this is self-explanatory — the ACE
steps above show where the bits come from. But as soon as a Deny ACE is in
play and blocks bits of an Allow ACE, **the path lacks a hint about what
happened**. Block A of the 2026-06-05 lab verification showed the symptom
concretely (scenario E1, `C:\TestShare\DenyZone`):

```text
DACL:
  Deny  explicit  T0LAB\alice → Special (0x000301BF)
  Allow inherited T0LAB\GroupB → Modify (0x001301BF)
  …

Effective Rights:
  NTFS    : Special (0x00100000)
  Result  : Special (0x00100000)

Explanation Path (excerpt):
  6. Deny ACE [explicit] for T0LAB\alice → Special (0x000301BF)
  7. Allow ACE [inherited] for GroupB → Modify (0x001301BF)
  …
  11. NTFS effective: Special (0x00100000)
```

A skilled admin reads this correctly (Deny removed the Modify bits, leaving
the SYNCHRONIZE bit). But `Special (0x00100000)` is a cryptic answer for the
main target group — the everyday admin. At this point, however, the engine
very much knows which bits were removed by Deny: in `evaluate_dacl_ordered`
a second mask `denied` runs along, collecting all "first decision = Deny"
bits. This information was previously not surfaced out of the function.

## Decision

`evaluate_dacl_ordered` now returns `(granted, denied)`. The engine passes
`denied_raw` through to `build_explanation`, and `build_explanation` —
provided `denied_raw != 0` — inserts an explicit step directly before the
"NTFS effective" step:

```text
Deny aggregation: Special (0x000301BF) blocked by Deny ACEs — those bits
were removed from the effective NTFS mask
NTFS effective: Special (0x00100000)
```

This makes the bridge between "I see a Deny ACE" and "I see an unexpectedly
small effective" visible in the path itself, instead of only in the
difference of the hex values.

If there is no Deny ACE in the DACL of the relevant SIDs, the path stays
unchanged — the new step does not appear, so that perfectly normal reports
(the overwhelming majority of all audits) stay cleanly readable.

## Consequences

### Positive

- **The everyday admin reads directly** that Deny crushed the Allow bits.
  No hex-difference detective game.
- **Consistent with the share step**: Stars has always rendered
  `NTFS ∩ Share` aggregation as a dedicated step; now also `Allow ⊖ Deny`.
- **Honest by default**: whoever reads an audit report sees all three
  aggregation stages explicitly, without having to compute between the
  lines.
- **No API breaks**: `evaluate_dacl_ordered` is engine-internal; the only
  call path was updated with it. Public models stay the same.

### Negative / trade-offs

- The path gets one more step when Deny is in play. Since Deny is more the
  exception than the rule in production, the noise load is low.
- `NormalizedRights::display_name()` still shows "Special" for a Deny mask
  like `0x000301BF` (not "Modify"), because the sync bit is missing. This
  is consistent with the previous presentation, but could trigger a future
  follow-up refactor if the readability of the bit names is to be improved
  further.

### Tests

Two new engine tests in `crates/permission_engine/src/engine.rs::tests`:

- `deny_aggregation_step_surfaces_blocked_bits` — verifies that the new
  step appears when Deny Modify overrides Allow Modify, and that it names
  the correct blocked mask.
- `deny_aggregation_step_absent_when_no_deny` — verifies that the step does
  **not** appear when no Deny ACE is in play.

Live verification against the 3-forest lab in
[`docs/lab/verification.md`](../lab/verification.md), Block A scenario E1:
the step appears as step 11 in the path with the exact hex value
`0x000301BF`.

## Relationship to other ADRs

- **ADR 0039** (diagnostic markers): the same approach — make previously
  implicit information explicit so auditors do not have to guess
  themselves.
- **ADR 0041** (LocalGroup memberships in the explanation path): introduced
  the same mechanism for the group source, now for the ACE aggregation.
