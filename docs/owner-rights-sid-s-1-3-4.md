# OWNER RIGHTS (SID S-1-3-4) in Windows ACLs — and how Stars analyzes it

This page explains the well-known SID **`S-1-3-4` ("OWNER RIGHTS")**, why
it is one of the easiest ways to get an NTFS effective-permission analysis
wrong, and how **Stars — AD Permission Analyzer** handles it exactly
(neither over- nor under-reporting the owner's access).

## The implicit owner grant (the default)

On Windows, the **owner** of a securable object is *implicitly* granted
two rights, regardless of what the DACL says:

- **`READ_CONTROL`** — read the security descriptor (view the permissions).
- **`WRITE_DAC`** — change the DACL (re-permission the object).

This grant **bypasses the DACL**: even if no ACE mentions the owner, the
owner can always read and rewrite the object's permissions. It exists so a
user can never lock themselves out of something they own. For an auditor it
means the owner effectively has at least `READ_CONTROL + WRITE_DAC` — even
when the visible ACL suggests otherwise.

## What OWNER RIGHTS (S-1-3-4) changes

Since Windows Server 2008, a DACL may contain an ACE for the special SID
**`S-1-3-4` (OWNER RIGHTS)**. When such an ACE is present, it **replaces**
the implicit owner grant: the owner's rights are then governed **only** by
the `S-1-3-4` ACE(s), not by the automatic `READ_CONTROL + WRITE_DAC`
bonus.

This is deliberately used to **cap owners**. Typical cases:

- Redirected folders / home directories where users own their files but
  administrators do **not** want owners to be able to change permissions.
- Shared data areas where "creator owner" inheritance would otherwise let
  the creator re-grant themselves anything.

With an OWNER RIGHTS ACE the owner can have **less** than the implicit
grant (e.g. read-only, with no `WRITE_DAC`), or exactly the specific rights
the ACE spells out — nothing is added automatically on top.

## Why this is an audit trap

Two common mistakes:

1. **Always adding the implicit owner grant** → **over-reports**: a tool
   reports `WRITE_DAC` for the owner even though an OWNER RIGHTS ACE has
   taken it away. The auditor wrongly believes the owner can re-permission
   the object.
2. **Ignoring `S-1-3-4` as "just another SID"** → **mis-reports**: the
   owner's true, capped rights are missed, or the special SID is shown as
   an unresolved/unknown trustee.

Either way the owner's *effective* access is stated incorrectly — and the
owner is exactly the principal who can quietly change everything else, so
getting this wrong matters.

## How Stars handles it (exactly, not approximately)

When Stars evaluates a path for an identity, it checks whether that
identity is the object's **owner**:

- **No `S-1-3-4` ACE present, user is the owner:** Stars applies the
  implicit grant — it adds `READ_CONTROL + WRITE_DAC` to the effective NTFS
  mask and records an explanation step
  *"Owner special rule: READ_CONTROL + WRITE_DAC granted implicitly"*.
- **An `S-1-3-4` ACE is present, user is the owner:** Stars **suppresses**
  the implicit grant and instead includes the `S-1-3-4` ACEs in the
  match set, evaluating them in stored DACL order like any other ACE
  ([Windows AccessCheck semantics](audit-criteria.md)). The owner's rights
  therefore come solely from the OWNER RIGHTS ACE(s). Stars marks the
  result with the diagnostic **`OwnerRightsAceApplied`** and the
  explanation step *"OWNER RIGHTS (S-1-3-4) ACE present — owner rights are
  governed by that DACL entry; the implicit owner grant is suppressed"*.

`OwnerRightsAceApplied` is **informational, not an incompleteness marker**:
the evaluation is exact. The marker exists only so an auditor understands
*why* the owner did not receive the usual implicit `WRITE_DAC` — the
unusual owner-rights mechanism was in play.

### Example

```text
Object owner : CORP\mmuster
DACL:
  Allow  S-1-3-4 (OWNER RIGHTS)  → Read & Execute
  Allow  CORP\Editors            → Modify

Analysis for CORP\mmuster (the owner):
  Effective NTFS : Read & Execute        (NOT Full Control, NOT WRITE_DAC)
  Diagnostic     : OwnerRightsAceApplied
  Explanation    : … OWNER RIGHTS (S-1-3-4) ACE present — owner rights are
                   governed by that DACL entry; the implicit owner grant is
                   suppressed.
```

Without OWNER-RIGHTS handling, a naive tool would add `WRITE_DAC` here and
report that the owner can re-permission the object. Stars reports what
Windows actually enforces: `Read & Execute`, no `WRITE_DAC`.

## See also

- [Audit Criteria and Evaluation Principles](audit-criteria.md) — the full
  effective-rights model, including stored-order DACL evaluation.
- [User Guide → Reading findings — diagnostic markers](user-guide.md#reading-findings--diagnostic-markers)
  — how `OwnerRightsAceApplied` and the other markers appear in the GUI,
  CLI, and reports.
