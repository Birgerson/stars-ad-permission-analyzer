# ADR 0025 — NULL-DACL classification: `bDaclPresent=TRUE, pDacl=NULL` is a NULL DACL

**Status:** Accepted  
**Date:** 2026-05-25

## Context

Per the Win32 docs (`GetSecurityDescriptorDacl`):

| `bDaclPresent` | `pDacl`     | Meaning                                             |
|----------------|-------------|-----------------------------------------------------|
| `FALSE`        | irrelevant  | DACL not in the SD → **NULL DACL** → unrestricted   |
| `TRUE`         | `NULL`      | explicitly set **NULL DACL** → unrestricted         |
| `TRUE`         | non-NULL, `AceCount=0` | empty DACL → **deny all**                |
| `TRUE`         | non-NULL, `AceCount>0` | normal DACL                              |

The previous `parse_share_dacl` wrongly turned the second case —
`present=TRUE, pDacl=NULL` — into an **empty DACL**
(`Ok(Some((Vec::new(), 0)))` → `ShareDacl::Acl(vec![])`). The engine
evaluated that as `Some(AccessMask(0))` → **no access**.

Consequence: an unrestricted share NULL DACL appeared in reports as "no SMB
access". With `effective = NTFS ∩ Share` this blocked every NTFS access in
the effective result — a direct false-negative source for share audits.

Review 2026-05-25, finding 1 (High).

## Decision

1. **New pure classification function
   `classify_dacl(present, ptr_is_null, ace_count) → DaclClassification`**
   in `share_scanner::scanner`. Three results:

   - `Null` — unrestricted (cases 1 and 2 above)
   - `Empty` — deny-all (case 3)
   - `Normal` — evaluable DACL (case 4)

   The function contains no Win32 calls and is therefore isolated and
   unit-testable — which the Win32 pointer path in `parse_share_dacl`
   previously blocked.

2. **`parse_share_dacl` calls `GetAclInformation` only when
   `pDacl != NULL`.** On a null pointer, `ace_count = 0` is set;
   `classify_dacl` short-circuits before this value (`ptr_is_null`
   short-circuit). This rules out `GetAclInformation(NULL, …)` as potential
   UB.

3. **Afterwards `parse_share_dacl` matches on the classification:**
   - `Null` → `Ok(None)` (leads to `ShareDacl::NullDacl`)
   - `Empty` → `Ok(Some((vec![], 0)))` (leads to `ShareDacl::Acl(vec![])`)
   - `Normal` → ACE loop as before

## Rationale

- **Correctness is non-negotiable** (AGENTS.md base rule 1). An
  unrestricted share reported as "no access" undermines the fundamental
  audit function.
- **Pure classification = directly testable**: without the helper, every
  test would have needed a real Win32 security descriptor — practically
  impossible without integration against a real share. The helper
  encapsulates the error-prone logic in a fully isolated function.
- **Table-driven tests**: the four rows of the MSDN table are each checked
  by a dedicated test. The previous bug is documented as an explicit
  assertion with "**MUST** classify as Null" and a comment.

## Consequences

- 4 new tests in `share_scanner::scanner::tests`:
  - `classify_dacl_not_present_is_null`
  - `classify_dacl_present_but_pointer_null_is_null` (the **core bugfix**)
  - `classify_dacl_present_non_null_zero_aces_is_empty`
  - `classify_dacl_present_non_null_with_aces_is_normal`
- `parse_share_dacl` internal structure clearer: first Win32 calls, then
  pure classification, then optionally the ACE loop. Separation of side
  effects / logic.
- No API change — `ShareDacl::NullDacl` / `Acl(...)` and `ShareDaclScan`
  stay the same. External callers see only the corrected behavior.
- No schema migration.
