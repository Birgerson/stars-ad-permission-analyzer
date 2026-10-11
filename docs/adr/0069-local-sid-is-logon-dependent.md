# ADR 0069 — `LOCAL` is logon-dependent for a local access

## Status
Accepted (2026-10-11). Refines ADR 0013 (access context) and ADR 0065
(logon-dependent trustees); closes lab finding MS-2.

## Context

ADR 0013 put `INTERACTIVE` (S-1-5-4) **and** `LOCAL` (S-1-2-0) into the token
for every local path (`AccessContext::LocalInteractive`). Real tokens on the
member server MS-01 (lab, 2026-10-11) show that only the first holds for
every interactive logon:

| Token | `INTERACTIVE` | `LOCAL` |
|---|---|---|
| console session (explorer.exe of the logged-on user) | yes | yes |
| `LogonUser`, interactive (type 2) | yes | **no** |
| `LogonUser`, batch (type 4) | no | yes |
| `LogonUser`, network (type 3) | no | no |

An ACE for `LOCAL` therefore applies to some local logons and not to
others. Stars treated it as applying — a fact that is wrong for part of
the logons the stated context covers.

## Decision

- `LocalInteractive` adds only `INTERACTIVE` to the token.
- `LOCAL` is a logon-dependent SID for `LocalInteractive` (as it already was
  for an unspecified context): an ACE for it — NTFS or share — and a local
  group reachable only through it (ADR 0068) bound the result
  (`LogonDependentTrustees`) instead of being assumed.
- Over SMB (`RemoteSmb`) nothing changes: a network logon never carries
  `LOCAL`, so its ACEs do not apply.

## Consequences

- A local analysis of a DACL with a deciding `LOCAL` ACE now reads "not
  determinable — between … and …" instead of a single value.
- Tests: the classification of `LOCAL` per context, the bounded result for
  a `LOCAL` ACE on a local path, the token without `LOCAL`.
