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

3. **CR-10 — DACL states.** A NULL DACL ("the object has no access control
   list: Windows grants every access to everyone"), an empty DACL ("nobody is
   granted anything through it; only the owner rule can apply") and a DACL
   in which no ACE applies to the token each get their own step — the
   result is never left without a reason.
4. **CR-3 — bounded results are traceable.** Every applicable ACE that only
   bounds the result (`uncertain_ace_reason`, the same predicate as
   `logon_dependent_bounds`) is listed like the others, as
   `… [UNCERTAIN — <reason>; counted in the upper / lower bound only, not
   in the shown value]` or `…; cannot change this result]`. The reason is
   per trustee: User Account Control (elevation on a local access; remote
   filtering of local accounts over SMB, `LocalAccountTokenFilterPolicy`),
   Cryptographic Operators, Guest / anonymous (ADR 0072), a local group
   reached only through a logon-dependent SID, the specific logon-dependent
   well-known (LOCAL, organisation, authentication package, logon type),
   OWNER RIGHTS of a filtered owner group. A filtered membership is marked
   `[deny-only in a filtered token: …]`, an uncertain implicit owner grant
   has its own step, "no ACE applies" becomes "no ACE certainly applies —
   only the UNCERTAIN ACEs" where that is the case, and the range step
   points to the per-ACE reasons instead of one generic (for UAC wrong)
   text. The invariant test now also requires every SID of a range to have
   its own UNCERTAIN step.

5. **CR-13 — what a Deny takes away.** The Deny aggregation step keeps the
   total of the bits Deny ACEs decided and separates them: bits an
   applicable Allow ACE of this token would otherwise have granted ("the
   Deny takes them away") and bits no Allow ACE grants ("denied in advance
   only") — the old text called every denied bit "removed".
6. **CR-12 — which membership mattered.** A membership whose group has an
   ACE that decided bits of this result is marked `[decisive — …]`; a group
   whose ACE matched but decided nothing is not. (Collapsing the full list
   is a frontend matter and stays open.)
7. **CR-14 — deleting a file through its folder.** For a file whose result
   lacks DELETE, a note says that "Delete subfolders and files"
   (`FILE_DELETE_CHILD`) on the parent folder still allows deleting it —
   evaluated on the folder (`DELETE_CHILD_RIGHT`), as in the Windows
   Effective Access tab, not in this result.

## Consequences

- An exact result keeps its wording; new steps only add what was missing.
- The explanation remains text steps; consumers that parse step prefixes
  ("NTFS effective:", "Share permission:", "Effective (NTFS ∩ Share):",
  "Deny aggregation:") keep working. The value steps keep the
  `(0x…)` mask as the first hex value of their line.
- Live review against real lab output (UAC / INTERACTIVE texts on MS-01)
  follows in the next lab run (review P5).

## Steps

| Step | Finding | Status |
| --- | --- | --- |
| Invariant test | — | shipped |
| Evaluated logon | CR-6 | shipped |
| DACL states | CR-10 | shipped |
| Bounded results traceable | CR-3 | shipped |
| Deny wording | CR-13 | shipped |
| Decisive memberships | CR-12 | shipped (list collapsing open) |
| Deletion through the folder | CR-14 | shipped |
