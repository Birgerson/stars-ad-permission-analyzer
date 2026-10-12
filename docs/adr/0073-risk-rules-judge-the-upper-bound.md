# ADR 0073 — Risk rules judge the upper bound

## Status
Accepted (2026-10-12). Closes review finding CR-2.

## Context

The risk rules read `effective_mask`. For a result with a logon-dependent
range (ADR 0065) that is the value the known data gives — typically the
**lower** bound. Since ADR 0070/0071 a local administrator (on a local path
or over SMB) shows the UAC-filtered value, e.g. "between Read & Execute and
Full Control". The elevated session really has Full Control, yet no
`FULL_CONTROL`, `WRITE_ACCESS` or `PERMISSION_CHANGE` finding appeared, and
`SENSITIVE_PATH` was skipped when the shown value was 0. The finding was
not marked incomplete — it was absent. For an audit an absent finding is
the unsafe direction.

The descriptions also stated every right as a fact ("has", "can"), even
for a result that is not determinable.

## Decision

1. `EffectivePermission::effective_upper_bound()` (core model, single source
   of truth): `effective_mask` for an exact result; otherwise the NTFS upper
   bound of a `LogonDependentTrustees` range (else the NTFS mask),
   intersected with the share mask **only** when the share side has no
   uncertainty of its own — an undeterminable share may grant more, and a
   share can only restrict, never extend, the NTFS right. Never below the
   shown value. With a token gap or un-evaluated NTFS ACEs no upper bound is
   known; the known data is used.
2. Every rule that judges rights (`FULL_CONTROL`, `WRITE_ACCESS`,
   `PARTIAL_WRITE`, `PERMISSION_CHANGE`, `OWNER_CHANGE`, `DELETE_RIGHT`,
   `DELETE_CHILD_RIGHT`, `BROAD_GROUP_WRITE`, `SENSITIVE_PATH`) judges this
   upper bound. `DIRECT_USER_ACE` judges the ACE itself and is unchanged.
3. Wording: a fact ("has", "can") only for an exact result; otherwise
   "may have" / "may be able to" plus `(NOT DETERMINABLE: the known data
   gives …; up to … is possible)` for a range, or `(NOT DETERMINABLE:
   stated from the known data only)`. Such findings carry
   `incomplete = true` as before.
4. Severities stay fixed per rule-ID: a possible Full Control is still
   Critical — the reader decides with the range in front of them.

## Consequences

- Exact results produce exactly the findings and descriptions they did
  before.
- A local administrator whose session may be elevated now gets the
  findings for the elevated rights, marked incomplete and worded "may".
- `BROAD_GROUP_WRITE` still requires a broad SID that contributed in the
  evaluated walk; a broad SID the token only *may* contain (Guest /
  anonymous, ADR 0072) shows up through the other rules' "may" findings.
- Tests: upper bound (exact, range ∩ share, undeterminable share, failed
  share read, token gap), each rule with a range, a token gap, an
  undeterminable share and the unchanged exact wording; mutation-checked.
