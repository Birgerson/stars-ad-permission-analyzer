# ADR 0076 — Remote UAC decided from the target's policies

## Status
Accepted (2026-10-13). Narrows known limitation L16 for the network case.

## Context

Over SMB, User Account Control filters the network token of a **local
account** of the target (remote UAC, ADR 0070): the administrative groups
become deny-only. Whether it does depends on two policy values under
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` of the
target. Stars could not see them, so every Allow ACE for such a group
bounded the result — a local administrator over SMB always read "between
No access and Full Control".

Lab matrix (2026-10-13, MS-01, Windows Server 2025, real SMB access with
`smb-probe.ps1`, sessions closed after each change, values restored):

| `LocalAccountTokenFilterPolicy` | `FilterAdministratorToken` | local administrator (`msadmin2`) | built-in Administrator (RID 500) |
| --- | --- | --- | --- |
| 0 (not set) | 0 (not set) | filtered | **not** filtered |
| 1 | 0 | not filtered | not filtered |
| 0 | 1 | filtered | **filtered** |
| 1 | 1 | not filtered | not filtered |

## Decision

1. `ad_resolver::read_target_uac_policy(server)` reads `EnableLUA`,
   `LocalAccountTokenFilterPolicy` and `FilterAdministratorToken` through
   the remote registry with `KEY_QUERY_VALUE` only (read-only). Each value
   is `PolicyDword::Value` (validated REG_DWORD, 4 bytes), `Absent` (the
   Windows default) or `Unreadable` (with the reason). An invalid server
   name is never passed to the API.
2. `permission_engine::engine::remote_uac_filtering(rid500, …)` implements
   the matrix: a local account other than RID 500 is filtered exactly when
   `LocalAccountTokenFilterPolicy` = 0; RID 500 exactly when
   `FilterAdministratorToken` = 1 and `LocalAccountTokenFilterPolicy` = 0.
   `EnableLUA` = 0 (UAC off — not measured), a value other than 0 / 1 or an
   unreadable value give `Unknown`: never guessed.
3. The frontends ask only for a local account over SMB with UAC groups.
   `NotFiltered` → no UAC-filtered groups (they are enabled, exact).
   `Filtered` → `PermissionEvaluationInput::remote_uac` makes the groups
   **certainly** deny-only: their Allow ACEs do not apply (NTFS and share
   side, `ShareToken::deny_only_certain`), their Deny ACEs do. `Unknown`
   keeps the bounded behaviour of ADR 0070.
4. Every surface states it: the informational marker
   `RemoteUacPolicy { filtered, reason }` names the values read; the
   explanation marks the membership "deny-only in this token — read from
   the target: …" and lists the Allow ACE "[not applied — the group is
   deny-only in this token: …]".

5. **Local interactive (amended 2026-10-13).** Real `LogonUser` tokens on
   MS-01: the built-in Administrator (RID 500) with
   `FilterAdministratorToken` = 0 gets an **unsplit, full** token
   (elevation type 1, Administrators enabled); with 1, and every other
   account always, the token is limited (elevation type 3, Administrators
   deny-only) — and a limited session can be elevated, which no policy
   reveals. `local_uac_filtering` therefore decides only the first case
   (`NotFiltered`); everything else stays bounded. Live: a local scan of
   `C:\MSData` on MS-01 for `MS-01\Administrator` — 27 of 27 rows exact and
   identical to the Windows authorization oracle (before: ranges).

## Consequences

- A local administrator over SMB gets an exact result whenever the target's
  policies are readable — the common case for an administrator running
  Stars. A local session's elevation stays unknown (L16, bounded).
- Lab acceptance: the MS-01 campaign — 81 formerly bounded rows are now
  decided by the policies, 45 of them checked against real SMB access, 0
  violations (comparison verified with a falsified row); 108 oracle-exact
  rows unchanged. Live: `msadmin2` exact "No access", RID 500 exact full
  rights at the default policies; with `LocalAccountTokenFilterPolicy` = 1
  `msadmin2` exact full rights.
- Tests: the full matrix, UAC off / unexpected / unreadable values, the
  engine result and path for a certainly filtered group, the share token.
