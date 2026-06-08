# ADR 0015 — Long-path normalization for Win32 calls

**Status:** Accepted
**Date:** 2026-05-24

## Context

Path validation in `validation::path` accepts paths up to 32 767 characters (Windows extended-length limit). The NTFS scanner however passed such paths through unchanged to `GetFileAttributesW` and `GetNamedSecurityInfoW` — these Win32 wide APIs are capped at `MAX_PATH` (260 characters) without the `\\?\` prefix. A path the tool formally accepted could therefore fail at runtime on the Win32 call, with no way to predict that from the validation — a broken promise.

`std::fs::read_dir` in the walker hit the same problem for directory enumeration.

See review finding 5.

## Decision

1. **New path type `WindowsApiPath`** in `validation::path` plus two free helpers:

   ```rust
   pub fn to_windows_api_path(path: &str) -> String;
   pub fn strip_long_path_prefix(path: &str) -> String;
   ```

   - `to_windows_api_path` converts:
     - `C:\…` → `\\?\C:\…`
     - `\\server\share\…` → `\\?\UNC\server\share\…`
     - already-prefixed paths stay unchanged (idempotent)
     - anything else (relative etc.) stays unchanged
   - `strip_long_path_prefix` is the inverse — used during FSO construction so the path that appears in the report stays human-readable.

2. **Applied in the NTFS scanner:** `read_file_system_object` normalizes the input path **once** before the Win32 calls. The path stored in the resulting `FileSystemObject` is cleaned via `strip_long_path_prefix` first, so reports and persistence see the original, readable form.

3. **Applied in the walker:** `walk_dir` calls `std::fs::read_dir` with the normalized path. The `DirEntry::path()` returns inherit the `\\?\` prefix on children — `to_windows_api_path` is idempotent, so there is no double prefixing. The FSO build in `read_file_system_object` strips the prefix again for display.

4. **No loosening of validation.** Paths in the `\\?\…` form remain forbidden in `validate_local_path` / `validate_unc_path` (`?` and `:` are illegal characters in segments). The prefix is an internal scanner optimization, not a user-facing input format.

## Rationale

- **Consistency with validation:** what validation permits (up to 32 767 characters) the scanner should be able to read.
- **Minimally invasive:** the external API (CLI/GUI/trait signatures) stays unchanged; the prefix only lives between validation and the Win32 call.
- **Reports stay readable:** users continue to see `C:\Users\…` rather than `\\?\C:\Users\…`.
- **Idempotency** of the converter allows it to be applied any number of times without special-case handling — walker and ACL reader can both run their own conversions.

## Consequences

- 11 new tests in `validation::path::tests`: four round-trip / strip / idempotency tests, seven case tests (`to_windows_api_path` for UNC / local / long / prefixed, plus `WindowsApiPath::from(&Validated…)`).
- 1 new integration test in `fs_scanner::walker::tests` builds a 12-level directory chain (~412 characters) under `TEMP`, scans it without the `\\?\` prefix, and verifies: no errors, 13 objects (root + depth), the deepest path is > 260, FSO paths carry no prefix.
- `fs_scanner` now depends on `validation` — the long-path mechanism is validation/path semantics, not a scanner detail.
- A later deliberate extension of validation to also accept the `\\?\…` form is possible if external callers want to pass it in directly — but it is not mandatory.
