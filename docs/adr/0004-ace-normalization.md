# ADR 0004 — ACE normalization: `NormalizedRights`

**Status:** Accepted
**Date:** 2026-05-20

## Context

Raw Windows AccessMask values (u32) from DACL entries are not directly human-readable. The permission logic and later exporters need a named, comparable representation.

## Decision

`NormalizedRights` in `permission_engine::mask` as a dedicated wrapper around the raw u32 with:

- Single-bit getters (e.g. `read_data()`, `delete()`).
- Composite checks (`is_full_control()`, `is_modify()`, ...).
- `label()` / `display_name()` for an icacls-compatible short / long form.
- `intersect()` for the more restrictive NTFS ∩ share combination.
- `From<AccessMask>` / `Into<AccessMask>` for type-safe conversion.

## Rationale

- No data loss: the raw value is preserved and every bit is queryable.
- Composite masks match the Windows icacls semantics exactly.
- `intersect()` implements the core rule: effective permission = the more restrictive combination of NTFS and share (cf. AGENTS.md).
- Hierarchy tests confirm: Full Control ⊃ Modify ⊃ RX ⊃ Read.

## Composite mask values

| Name         | Hex          | Bits |
|--------------|--------------|------|
| Full Control | 0x001F_01FF  | STANDARD_RIGHTS_ALL \| SYNCHRONIZE \| 0x1FF |
| Modify       | 0x0013_01BF  | FC without WRITE_DAC, WRITE_OWNER, DELETE_CHILD |
| Read+Execute | 0x0012_00A9  | FILE_GENERIC_READ \| FILE_EXECUTE |
| Read         | 0x0012_0089  | FILE_GENERIC_READ |
| Write        | 0x0012_0116  | FILE_GENERIC_WRITE |

## Consequences

- Unit tests cover every composite check, bit check, the hierarchy, and the share ∩ NTFS combination logic.
- `NormalizedRights` itself is passive: it takes a u32 and interprets it. Expanding the generic bits (GENERIC_READ/WRITE/EXECUTE/ALL) happens explicitly via `expand_generic_rights()` and must be called before any Allow/Deny evaluation (see ADR 0012).
- `permission_engine::engine` (DefaultPermissionEvaluator) uses `NormalizedRights` for display and composite checks plus `expand_generic_rights()` for the analytical evaluation.
