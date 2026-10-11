# ADR 0070 — Local accounts of the target server

## Status
Accepted (2026-10-11). Closes lab findings MS-3 and OBS-1. Extended to
domain accounts on a local access by [ADR 0071](0071-uac-split-token-for-local-access.md). Builds on
ADR 0068 (local groups by SID) and ADR 0065 (bounds instead of guesses).

## Context

A local account exists only in the SAM of one machine. Without LDAP, Stars
resolved every account on the machine it runs on:

- A local account of a remote file server (`MS-01\msuser1`) could not be
  analysed at all ("has no SID on this system").
- A name that exists on both machines (`Administrator`) silently resolved to
  the **analysing** machine's account — a different SID evaluated against
  the server's ACLs.
- A local account of the local machine went through the SAM fallback and
  every result was "not determinable" (OBS-1), although its groups cannot
  nest.

Real tokens on the lab member server MS-01 (Windows Server 2025) showed what
a local account's token holds and where User Account Control (UAC) changes
it:

- every local account: its SAM primary group (`MS-01\None`, RID 513) and
  `Local account` (S-1-5-113) — interactive, network and batch logons;
- a local account in Administrators: `Local account and member of
  Administrators` (S-1-5-114);
- **UAC filtering** turns Administrators, Power Users, Print Operators,
  Backup Operators and Network Configuration Operators, and S-1-5-114, into
  deny-only groups:
  - in the non-elevated interactive token (any account in such a group,
    domain accounts included — handled separately, MS-4);
  - **over the network for local accounts** (remote UAC): real SMB access
    as a local administrator other than the built-in one got no
    administrator rights; with `LocalAccountTokenFilterPolicy` = 1 it did;
    the built-in Administrator (RID 500) got them, unless
    `FilterAdministratorToken` = 1 — all four cases tested;
  - domain accounts with local administrator rights are **not** filtered
    over the network;
- Cryptographic Operators (S-1-5-32-569) is deny-only in a filtered token
  and **absent** from the token when the account is also in Administrators,
  Backup Operators or Power Users.

## Decision

1. **Resolution on the target server.** Without LDAP, the identity is
   looked up on the server of the analysed path (`effective_smb_target`;
   this machine for a local path): `NetUserModalsGet` (account domain name
   and SID, validated `S-1-5-21-a-b-c`), `NetServerGetInfo` (a domain
   controller has no local accounts), `LookupAccountNameW` /
   `LookupAccountSidW` on the server. A user whose SID belongs to the
   server's account domain is a local account; anything else continues on
   the existing path **with the server's SID**, never with a name resolved
   on the analysing machine.
2. **Complete group set of a local account.** `NetUserGetInfo` level 4 on
   the server (state, primary group, and the account's own SID —
   cross-checked against the lookup), `NetUserGetGroups` (SAM groups, each
   validated as a group of the server's domain), the primary group added by
   RID if missing, `Local account` (source `AccountType`), and the server's
   local groups by SID (ADR 0068). Status `GroupResolutionStatus::LocalAccount`
   — not the SAM fallback; anything unreadable is a gap.
3. **UAC.** For a local account the UAC-filtered groups (and S-1-5-114 when
   in Administrators) go into `uac_filtered_group_sids`. The engine removes
   them from the enabled token: they match Deny ACEs only; their Allow ACEs
   bound the result (`LogonDependentTrustees`), and an object owned by such
   a group bounds the implicit owner grant. Share ACEs for them count as
   uncertain. `UacFilteredGroups` names them and the two policies. The
   shown value is the filtered token — the default for every local account
   but the built-in Administrator; the bounds cover both cases.
4. **Cryptographic Operators** is never a certain membership — bounded.
5. The "no LDAP — nested domain groups unknown" warnings appear only where
   true (SAM fallback of a domain account); a local account says it was
   resolved on its machine. The membership view of a local account lists its
   local groups by SID; groups entered only through a logon-dependent SID are
   named as gaps.

## Verification (lab, 2026-10-11)

Seven local accounts of MS-01 (built-in Administrator, two local admins,
an account in every builtin group, an account in Cryptographic Operators, two
plain accounts, a disabled one), Stars without LDAP:

- **From a workstation outside the domain over SMB:** 108 rows exact (equal
  to the Authz oracle), 81 rows bounded — the oracle value (token without UAC)
  inside the bounds every time; 75 folder rows compared with real SMB access
  as the account — shown value (filtered) or, for the built-in
  Administrator, the upper bound equal to what Windows granted. 0 violations.
  The comparison script found all three deliberately falsified rows.
- **On MS-01 over the local path:** every row matches, except a local group
  containing INTERACTIVE, which Stars counts for a local (interactive)
  access and the oracle (no logon) does not. An access check with the real
  interactive token gives Modify, as Stars says; with the network token no
  access, as the SMB run says.
- The bare name `Administrator` now resolves to `MS-01\Administrator`.

## Consequences

- Local accounts of a file server can be audited from any machine, and no
  account is ever confused with a same-named one of the analysing machine.
- Results of local administrators read "between … and …" wherever an Allow
  ACE for a filtered group decides them — Stars cannot see the UAC policies.
- Over SMB, Windows reported `Traverse` and the attribute bits as granted
  where the same real token was denied locally; the comparison leaves those
  bits out. Privilege-based access stays out of scope (features §10).
