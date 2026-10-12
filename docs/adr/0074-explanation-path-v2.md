# ADR 0074 — Explanation path v2: every right traceable

## Status
Accepted (2026-10-12). Review priority 3 (code review of 2026-10-12):
invariant test, CR-6, CR-10, CR-3, CR-13, CR-12, CR-14 — this ADR grows with
each step; the "Steps" section records what has shipped.

## Context

The core goal of Stars: an administrator must understand, honestly and
traceably, how each right comes about. The review found that the
explanation path — exported verbatim to CSV, HTML and the GUI — leaves
gaps exactly where the result is most surprising: the evaluated logon and
its implicit SIDs are never named (CR-6), a NULL or empty DACL is not
explained (CR-10), ACEs that only bound a result are not listed and the
bound has a generic, partly wrong reason (CR-3), the Deny wording overstates
(CR-13), the decisive memberships are not marked (CR-12), and deleting
through the parent folder is not mentioned (CR-14).

The explanation stays a list of text steps (no DB / JSON schema change);
a typed, structured explanation is a later feature.

## Decision

1. **Invariant first.** A generated test (3000 DACLs: allow / deny,
   explicit / inherited, inherit-only, generic rights, group and non-member
   trustees, OWNER RIGHTS, owner or not) asserts that the path accounts for
   every bit: the `[granted …]` bits of the ACE steps are pairwise disjoint,
   with the owner rule they are exactly the NTFS mask, and the Deny
   aggregation step states exactly the `[denied …]` bits the owner rule does
   not restore. Every later step must keep it green.
2. **CR-6 — the evaluated logon.** Step 2 of every path:
   `Evaluated as: <logon> — the token receives <implicit SIDs>; …`, built by
   `access_context_step` from the same rules as the token
   (`build_token_sids_with_context`, `identity_uncertain_well_knowns`):
   network logon over SMB (NETWORK; UAC filters local accounts only),
   interactive logon at the target, not elevated (INTERACTIVE; LOCAL and
   UAC-filtered groups bounded), or no specific logon type. Guest and
   anonymous wording follows ADR 0072. The step says that logon rights
   ("Access this computer from the network", "Allow log on locally") are
   not checked. A test asserts that the step and the token agree for every
   context and identity class. The CLI header shows the short form
   (`Evaluated : …`).

## Steps

| Step | Finding | Status |
| --- | --- | --- |
| Invariant test | — | shipped |
| Evaluated logon | CR-6 | shipped |
