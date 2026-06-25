# ADR 0027 — `SensitivePathRule` requires actual access

**Status:** Accepted  
**Date:** 2026-05-25

## Context

`SensitivePathRule` flags paths whose name hints at sensitive data
(`password`, `secret`, `token`, …). The finding description reads
literally:

> Path contains keyword '<kw>' — may contain credentials or secrets;
> '<name>' has access

Previously the rule checked only the path name. A permission with
`effective_mask == 0` (e.g. because NTFS denies or `NTFS ∩ Share = 0`) was
still reported as "has access". That is a false positive: the auditor reads
a risk that does not actually exist. Especially critical with audit reports
as an evidentiary artifact (cf. AGENTS.md "exports must be treated as
sensitive").

Review 2026-05-25, finding 3 (Medium).

## Decision

**`SensitivePathRule.evaluate` pre-filters `p.effective_mask.0 > 0`**
before the keyword check. Paths to which the user has **no** access right
no longer produce a finding.

Rationale text in the code:

> the rule claims "has access" — so only emit a finding when the identity
> actually has access. Otherwise a deny-all result would be misreported as
> a positive risk.

## Rationale

- **The finding must match the statement.** "Has access" without effective
  access is semantically incorrect.
- **False positives are expensive in the audit context.** They undermine
  trust in the report and cost operator time for verification.
- **The effective mask, not the NTFS mask, is authoritative.** When the
  share side blocks (`NTFS Full Control ∩ Share Read = Read & Execute` as
  an example from the live scans), but the share yields `0`, the result
  must be consistent — the regression test
  `sensitive_path_uses_effective_not_ntfs_mask` pins this down.
- **Deliberately no split into two rules** (e.g. "sensitive path observed"
  vs. "access to sensitive path"). The reviewer suggested this optionally,
  but: the existing rule is named `SENSITIVE_PATH`, describes "has access"
  textually, and is established as one concept. If a dedicated
  "pure-naming" finding is wanted later, it will be a separate rule with
  its own ID.

## Consequences

- 2 new tests in `risk_engine::rules::tests`:
  - `sensitive_path_with_zero_effective_mask_not_flagged`
    (core regression from the reviewer example)
  - `sensitive_path_uses_effective_not_ntfs_mask`
    (edge case: NTFS Full, but effective_mask = 0)
- `sensitive_path_flagged` stays green unchanged — the standard case with
  `MASK_READ` as effective_mask.
- No API change, no schema migration.
- The risk-engine output for reports is quieter on paths without actual
  access — the other rules (`WRITE_ACCESS`, `DELETE_RIGHT`, etc.) already
  check explicitly against the effective mask or concrete bits, so they are
  unchanged and correct.
