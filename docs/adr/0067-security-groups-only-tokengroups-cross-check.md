# ADR 0067 — Only security groups count; cross-check against tokenGroups

## Status
Accepted (2026-10-10). Refines the LDAP group resolution (ADR 0063/0066);
closes lab finding AD4-4.

## Context

The transitive LDAP search (`LDAP_MATCHING_RULE_IN_CHAIN`) returns every
group an account is nested in — security **and distribution** groups — and
Stars put all of them into the evaluated token. Windows does not:

- Lab fixture: `rt_user02` ∈ `rt_dist` (distribution) ∈ `rt_sec_over_dist`
  (security); a test folder grants `rt_dist` Read & Execute
  and `rt_sec_over_dist` Modify.
- The DC's constructed `tokenGroups` of `rt_user02` contain only BUILTIN\Users
  and Domain Users — **neither** group.
- Windows Authz (`AuthzAccessCheck`, MAXIMUM_ALLOWED): `0x00000000` on the
  folder. Stars printed **"Result : Modify"** as a fact.

So a distribution group is never in the token, and nesting through one does
not make anybody a member of the groups above it. An over-report of exactly
the kind an audit tool must not produce.

## Decision

1. `groupType` is read for every group of the transitive result. A group is
   counted only if it is reachable from the account through **security
   groups only** (the primary group is always one). Distribution groups and
   groups reached only through a distribution group are left out of the token
   and of the membership routes.
2. The exclusion is never silent: the informational marker
   `NonSecurityGroupsExcluded { groups }` names every left-out group and why
   (CLI, GUI, HTML, JSON, membership view).
3. A group whose `groupType` is not readable is counted (as before) but
   reported as a gap (`GroupResolutionIncomplete`) — whether it is in the
   token is unknown, so the result is not determinable.
4. **Cross-check with the DC's own answer.** On a domain bind the account's
   `tokenGroups` (constructed attribute, base search) is read and compared
   with the resolved set (historical SIDs of counted groups count as
   counted). A group Stars counts that the DC does not list ("rights may be
   too high") and a group the DC lists that Stars did not find ("rights may
   be too low") are gaps. A `tokenGroups` read failure is a gap as well. A
   Global Catalog bind sees only part of the token, so it is not compared.
5. **Token size limit.** A Windows logon token holds at most 1,024 SIDs; an
   account in more than 1,015 groups (SID history included) cannot log on
   ("too many security IDs", Microsoft KB 328889). When the resolved set
   exceeds 1,015 SIDs this is reported as a gap of its own — found in the lab
   with `rt_user01`: 3,201 security groups in the transitive closure, while
   the DC's `tokenGroups` listed only 2,049, so the cross-check alone would
   have named the wrong cause.

## Consequences

- The token Stars evaluates now follows the DC's rules for group types, and
  any remaining divergence from the DC's own token list is reported instead
  of trusted.
- One extra base search per resolved account.
- A least-privilege bind that may not read `tokenGroups` makes results "not
  determinable" with that reason — a correct statement, since the
  cross-check could not be done.
- Tests: exclusion of distribution groups and of groups reached only through
  them (a group also reachable through a security group stays, with the
  security route), unreadable `groupType`, the cross-check in both
  directions, the token size limit (1,016 groups → gap, 1,015 → none).
