# ADR 0075 — A share without security descriptor is not determinable

## Status
Accepted (2026-10-12). Finding CR-15, found during the smoke test of CR-7.

## Context

`NetShareGetInfo` (level 502) reports **no security descriptor** for the
administrative shares — on the analysing Windows 11 machine for `C$`,
`ADMIN$` and `IPC$` (log: "Share has no security descriptor"). Stars treated
that as a NULL DACL: `adpa shares` and the Shares tab said "no share-level
restriction — every principal passes the share layer", and an analysis over
`\\server\C$\…` combined NTFS with an unrestricted share. That is wrong: with
no security descriptor the server service applies its own built-in default,
and an administrative share admits only administrators and backup
operators. A non-administrator analysed over `C$` was shown passing the
share layer. The user guide even called the NULL DACL "typical for the
administrative shares".

A NULL DACL (a security descriptor whose DACL is NULL) remains what it is:
no share-level restriction.

## Decision

1. New `ShareDacl::NoSecurityDescriptor`, distinct from `NullDacl`; set when
   the descriptor pointer is null (and when no share information is
   returned at all).
2. The share permission of such a share is **not determinable**:
   `resolve_share_mask_status` returns `ShareMaskStatus::ReadFailed` with the
   reason `NO_SECURITY_DESCRIPTOR_REASON` — the existing status that means
   "the share permission is not determinable": the result is NTFS-only,
   marked NOT DETERMINABLE, and the explanation states that the share can
   only restrict the NTFS right. `evaluate_share_dacl` and
   `effective_share_mask` return "nothing known to be granted" (never
   `None` = unrestricted) and count the share as not evaluable.
3. Every surface says so: `adpa shares`, the Shares tab and the trustee view
   read "NOT DETERMINABLE — no security descriptor reported; the server
   applies a built-in default (an administrative share admits only
   administrators and backup operators)". The exhaustive matches made the
   compiler point to every place.

## Consequences

- No share is ever reported as "unrestricted" without a NULL DACL actually
  being present.
- The status is carried as `ReadFailed` so persisted data and JSON need no
  schema change; its CLI warning says "could not be read", the reason text
  says why. A dedicated status is a later, schema-versioned change.
- Lab follow-up: confirm the server's default for a non-administrator, a
  backup operator and a filtered local administrator over `C$`.
