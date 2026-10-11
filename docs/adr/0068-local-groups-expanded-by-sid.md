# ADR 0068 — Local groups of the target server expanded by SID

## Status
Accepted (2026-10-11). Supersedes ADR 0040 (candidate name list for
`NetUserGetLocalGroups`); closes lab finding MS-1 and observation OBS-3.

## Context

Windows puts a local group (alias) of a server into a logon token when one
of its **direct members is a SID already in the token**: the account, its
SID history, every domain group it is in (nested ones included, domain local
groups included) and the well-knowns of the logon (`Everyone`,
`Authenticated Users`, `INTERACTIVE` or `NETWORK`, …). Local groups cannot
contain local groups, so one level is exact.

Stars took the local groups from `NetUserGetLocalGroups(LG_INCLUDE_INDIRECT)`.
A member server added to the lab (MS-01, Windows Server 2025, member of
corp.test) showed that this is not that set:

- **From a machine outside the domain** the call fails for every domain
  account with status 1355 (no such domain), whichever name form is used.
  Stars reported this honestly — every result "not determinable" — but the
  analysis was useless.
- **On a domain member** the call succeeds and returns only groups entered
  through the account itself or a group it is directly in. In the lab it
  missed groups entered through a nested domain group, a domain local group,
  `Everyone` and `Authenticated Users`. Stars then printed, **as a fact**,
  for example "No access" where Windows grants Modify (u00001 on a folder of
  a local group containing a nested domain group) — rights too low, no
  marker.

## Decision

1. `read_local_group_table(server)` reads every local group of the target
   server and its direct members **by SID**: `NetLocalGroupEnum` (all pages)
   → `LookupAccountNameW` on the server, whose answer must be an alias →
   `NetLocalGroupGetMembers`. No account name of the analysed identity is
   involved. Every value is validated (SID syntax, SID type, one account
   domain for all non-builtin groups); a group that cannot be read
   completely is a gap (`LocalGroupEvalStatus::NotAvailable`), never a
   shorter table.
2. `permission_engine::engine::expand_local_groups` is the token rule
   above, as a pure function over the same token SID set the evaluation
   uses (`build_token_sids_with_context`), in the evaluated access context.
3. A group reachable **only** through a logon-dependent SID
   (`is_logon_dependent_sid`, ADR 0065 — e.g. `INTERACTIVE` when the context
   is unspecified, `This Organization` always) is not a membership. It is
   passed as `logon_dependent_group_sids`; ACEs and share ACEs for it bound
   the result exactly like ACEs for logon-dependent SIDs
   (`LogonDependentTrustees`).
4. Explanation: `account → local group` when the account itself is a
   member, otherwise `account → token SID → local group`; further entries
   are listed as "also via". Order is deterministic (account first, then by
   SID; groups by name, then SID).
5. The name-based functions remain only for the SAM fallback without LDAP,
   whose results are always marked not determinable.

## Verification (lab, 2026-10-11)

- Windows Authz oracle on MS-01: 11 identities × 27 objects.
- Stars from a workstation outside the domain over SMB: 182 rows, all
  determinable, **0 differences** (before: all not determinable).
- Stars on MS-01 itself over the local path: every row matches the oracle
  except the folder granted to a local group containing `INTERACTIVE` — for
  a local path Stars models an interactive logon, the oracle builds its
  context from the SID without any logon. A real interactive logon token on
  MS-01 does contain that group, a network or batch logon token does not
  (`LogonUser` types 2/3/4), so Stars is right for the context it states.

## Consequences

- Local-group results no longer depend on where Stars runs.
- One `NetLocalGroupGetMembers` call per local group of the target server
  per analysis (a few dozen on a typical server).
- Tests: every entry route (account, nested domain group, `Authenticated
  Users`, `Everyone`, SID history), the access-context dependence of
  `INTERACTIVE`, certain route winning over a logon-dependent one,
  independence from server order, bounded ACE for a logon-dependent group,
  share ACE counted, the explanation paths, a live read of this machine's
  local groups.
