# ADR 0003 — NTFS DACL reading with `GetNamedSecurityInfoW`

**Status:** Accepted
**Date:** 2026-05-20

## Context

To read NTFS permissions the security descriptor of a path must be read. Windows offers several APIs:

- `GetFileSecurity` — requires separate memory management for the descriptor.
- `GetNamedSecurityInfoW` — allocates the security descriptor internally, returns `PSECURITY_DESCRIPTOR` which must be freed with `LocalFree`.
- `NtQuerySecurityObject` — low-level, requires a HANDLE.

## Decision

Use `GetNamedSecurityInfoW` from `windows-sys 0.59`.

## Rationale

- Highest abstraction: returns the owner SID and the DACL pointer directly.
- Supports UNC paths natively.
- No separate memory management for the security descriptor.
- `SE_FILE_OBJECT` as the object type covers both files and directories.

## Technical details

- `ACCESS_ALLOWED_ACE_TYPE` (0) and `ACCESS_DENIED_ACE_TYPE` (1) are not exported as constants in windows-sys 0.59; raw values from WinNT.h are defined as local `const`.
- `INHERITED_ACE` is exported as `u32` in windows-sys; applied via `as u8` to the `AceFlags` byte (u8) of the ACE header.
- `HLOCAL` = `*mut c_void` in windows-sys 0.59; `LocalFree` accordingly takes `*mut c_void`, not `isize`.
- `SidStart` in `ACCESS_ALLOWED_ACE` is a placeholder (u32); `addr_of!` returns the start pointer of the SID byte block.
- `SE_DACL_PROTECTED` (0x1000) in the security-descriptor control field indicates whether inheritance is broken on this path.

## Consequences

- All Windows API calls are encapsulated in `crates/fs_scanner/src/acl.rs`.
- `scanner.rs` and callers receive typed `FileSystemObject` models.
- 7 unit tests with `C:\Windows` and `C:\Windows\System32` as known test paths; no mocking required.
- Unsupported ACE types (object ACEs etc.) are skipped and may be added in a later step.
