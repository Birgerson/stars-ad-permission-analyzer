# ADR 0071 — User Account Control for every account on a local access

## Status
Accepted (2026-10-11). Extends ADR 0070 (local accounts, remote UAC) to
domain accounts; closes lab finding MS-4.

## Context

ADR 0070 modelled User Account Control (UAC) for local accounts. On a local
path (`AccessContext::LocalInteractive`) Stars still counted every group of a
**domain** account as enabled. Real interactive tokens (lab, 2026-10-11):

- **Member server MS-01:** a domain account in the local Administrators
  (`rt_uac01`) and a Domain Admin (`rt_uac02`) get a split token
  (elevation type "limited"). Deny-only in the filtered token: Domain Admins
  (512), Cert Publishers (517), Schema Admins (518), Enterprise Admins (519),
  Group Policy Creator Owners (520), Administrators (544). **Not** filtered:
  Key Admins (526), Enterprise Key Admins (527), DnsAdmins, Denied RODC
  Password Replication Group (572). The domain's built-in Administrator
  (RID 500) gets no split token. Over the network none of them is filtered.
- **Domain controller DC-01:** a Domain Admin as above plus Pre-Windows 2000
  Compatible Access (554); an account in the DC's operator groups: Account
  (548), Server (549), Print (550), Backup (551) and Network Configuration
  Operators (556), and 554, deny-only. 554 alone does not cause a split
  (an account with only 554 kept it enabled).
- Cryptographic Operators (569) was absent from **both** the interactive and
  the network token of an account that is also in other filtered groups —
  so an LDAP membership in 569 (on a DC the builtin groups come from LDAP)
  is not a certain token group either.

So a local access gives an administrator, as long as the session is not
elevated, fewer rights than Stars showed — "Full Control" as a fact where
the non-elevated session gets "Read & Execute".

## Decision

1. `permission_engine::engine::uac_filtered_groups(token_groups,
   local_account, context)` is the single rule:
   - **RemoteSmb:** only a local account's groups are filtered (ADR 0070);
     a domain account keeps them;
   - **LocalInteractive / Unspecified:** for every account, every token group
     UAC may filter — `UAC_FILTERED_BUILTIN_GROUPS` (544, 547, 548, 549, 550,
     551, 554, 556) and domain groups with `UAC_FILTERED_DOMAIN_RIDS` (512,
     517, 518, 519, 520 lab-confirmed; the domain controller groups 498, 516,
     521 treated the same without a lab test — a bound is the safe statement)
     — plus `S-1-5-114` for a local account in Administrators.
   The token groups are all of them: domain groups with their SID history and
   the local groups. Stars cannot see whether a session is elevated, whether
   the account is exempt (built-in Administrator) or the UAC policies, so the
   groups are deny-only with a bounded Allow side (ADR 0070 mechanism): the
   shown value is the non-elevated token, the upper bound the elevated one.
   554 is always included, because a split caused by something Stars cannot
   see (e.g. a privilege) would filter it too.
2. **Cryptographic Operators** is handled in the engine, whatever source the
   membership came from: never an enabled token group, its ACEs bounded. The
   membership itself stays visible in the explanation and membership views.
3. `UacFilteredGroups` now describes both cases: the non-elevated local
   session and remote UAC for local accounts.

## Verification (lab, 2026-10-11)

Stars on MS-01 over `C:\MSData` with LDAP for `rt_uac01`, `rt_uac02`, the
domain Administrator and a non-admin account (`rt_uac03`), compared with an
access check on the **real** interactive token of each account and, for the
split tokens, on its elevated linked token (108 objects): 26 rows exact,
82 bounded; both real values inside the bounds every time, and the shown
value equal to the non-elevated token. 0 violations; the comparison found all
three deliberately falsified rows. The domain campaigns (UNC/LDAP and SAM on
the DC) and the ADR 0070 local-account run were repeated.

## Consequences

- On a local path every administrator's result reads "between … and …"
  wherever an Allow ACE for a filtered group decides it — which is what a
  non-elevated and an elevated session actually differ in.
- Over SMB nothing changes for domain accounts.
