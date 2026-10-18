# ADR 0080 — SYNCHRONIZE missing from the effective right

## Status
Accepted (2026-10-18).

## Context

In the L4 lab comparison (ADR 0079) one folder differed: `TrustTest\TG_deny_ext`
(Allow Modify for a group, Deny "Write" for another group of the account).
Stars and the Windows Authz oracle gave `0x000300A9` (read, list, read
attributes, delete, read permissions), while the SMB probe, which opens
through `CreateFileW`, got "access denied" for every right.

The basic permission "Write" (Explorer, `icacls (W)`) is `0x00100116`. It
contains **SYNCHRONIZE**. `CreateFileW` adds SYNCHRONIZE to every request,
and so do the Windows APIs built on it.

### Measurements (lab, 2026-10-18)

Folders under `C:\SyncTest` on DC-01, account `CORP\rt_gt01`, network logon
(LogonUser, impersonation) and real SMB from a client, each right opened
singly through `NtOpenFile` with and without SYNCHRONIZE:

| Object | Without SYNCHRONIZE | With SYNCHRONIZE |
| --- | --- | --- |
| S0: Allow Modify | `0x000301AF` | `0x000301AF` |
| S1: Allow Modify + Deny "Write" | `0x000300A9` | `0` |
| S2: Allow Modify + Deny only SYNCHRONIZE | `0x000301AF` | `0` |
| S3: Allow special rights without SYNCHRONIZE, no inheritance | `0x000300A9` | `0` |
| S4: owner only, no ACE for the account | `READ_CONTROL`, `WRITE_DAC` | `0` |

(`0x10`, Write extended attributes, was not in the probe's list of rights.)

What the account can really do in S1, locally and over SMB (identical):

| Action | Result |
| --- | --- |
| `CreateFileW` read (requests SYNCHRONIZE) | access denied |
| read the file content through `NtOpenFile` / `NtReadFile`, no SYNCHRONIZE | **succeeds** |
| list the folder through `NtQueryDirectoryFile`, no SYNCHRONIZE | **succeeds** |
| open for write data | access denied (Write is denied, correct) |
| read the DACL (`GetNamedSecurityInfoW`) | **succeeds** |
| delete a file (`DeleteFileW`) | **succeeds** |
| delete a folder (`RemoveDirectoryW`) | access denied |
| delete a folder (`NtOpenFile` DELETE + disposition), no SYNCHRONIZE | **succeeds** |
| S4: change the DACL as owner (`SetNamedSecurityInfoW`) | **succeeds** |

The AccessCheck result Stars computes is therefore exactly the set of rights
the account holds and can exercise. Only programs that request SYNCHRONIZE
fail, and that covers Explorer and most applications.

## Decision

1. **The value stays.** The effective right is the AccessCheck result. Setting
   it to "No access" was considered and rejected. It would hide rights the
   account can exercise: reading the data with a tool that opens without
   SYNCHRONIZE, deleting, reading and (as owner) changing permissions. An
   understated right is the dangerous direction for an audit.
2. **New marker `SynchronizeNotGranted { cause, certain }`** (Notice,
   informational, no incompleteness trigger). It fires when the effective
   right holds rights besides SYNCHRONIZE but not SYNCHRONIZE itself, and
   neither does its upper bound. Possible causes:
   - `DeniedByNtfsAce`: an applicable Deny ACE takes SYNCHRONIZE away, e.g.
     a denied "Write".
   - `NotGrantedByNtfs`: no applicable NTFS ACE grants it, e.g. special
     rights without it, or owner rights only.
   - `NotGrantedByShare`: the share permission does not grant it.

   `certain` is false when the result itself is not determinable; the text
   then says "from the known data". The marker is not set when the logon is
   refused (ADR 0079), because the effective right is then No access.
3. **Surfaces.** A closing explanation step "Note — SYNCHRONIZE is not
   granted …", a second line under the CLI result, the same addition in the
   GUI headline (one wording, `EffectivePermission::synchronize_suffix`), an
   HTML badge, and the graph result tooltip. The user guide explains the
   effect and how to verify it by hand.

## Consequences

- Lab: `C:\SyncTest` scan matches every measurement above; `TG_deny_ext`
  carries the marker.
- Regression against v1.16.0 (built from the tag), every column: 25,841 rows,
  25,833 identical. The other 8 differ only by the appended marker and
  explanation step, never in a right: Deny "Write" through a universal
  group, Delete-only objects, and owner-only objects.
- The SMB probe used in the lab (`CreateFileW`) measures what ordinary Windows
  programs get, not the rights; earlier comparisons that used it are read
  with that in mind.
