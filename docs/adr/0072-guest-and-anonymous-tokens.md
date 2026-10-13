# ADR 0072 — Guest and anonymous tokens

## Status
Accepted (2026-10-12). Closes review finding CR-8. **Amended 2026-10-13:**
the lab measurement replaced the bound by the exact rule (see "Lab
measurement").

## Context

Stars added `Everyone` (S-1-1-0) and `Authenticated Users` (S-1-5-11) to every
evaluated token. Microsoft documents two exceptions:

- the built-in **Guest** account is not a member of `Authenticated Users`;
- an **anonymous** logon (S-1-5-7) is in neither `Authenticated Users` nor —
  unless the policy `EveryoneIncludesAnonymous` is set — `Everyone`.

Guest and anonymous access to shares is exactly what an audit looks for, and
Stars stated such rights as a fact through ACEs for `Authenticated Users`
(and `Everyone`). The lab that could measure real Guest and anonymous tokens
was deleted on 2026-10-11, so the documented behaviour could not be
confirmed yet.

## Decision

1. `permission_engine::engine::identity_uncertain_well_knowns(user_sid)`:
   Guest (RID 501 of a machine or domain, `is_guest_account`) →
   `Authenticated Users`; ANONYMOUS LOGON → `Authenticated Users` and
   `Everyone`; every other account → none.
2. `build_token_sids_with_context` leaves these SIDs out of the token; the
   engine treats them like logon-dependent SIDs (ADR 0065): their ACEs bound
   the result. The shown value follows the documentation, the upper bound
   covers the opposite.
3. The same holds for local groups reached only through such a SID
   (`expand_local_groups`) and for the share token (`share_token`).
4. The informational marker `GuestOrAnonymousToken { sids }` names the SIDs
   and the reason.

## Verification

Unit tests: Guest recognition (RID 501 only, account-domain SIDs only), the
token without the documented well-knowns, bounded results for Guest
(`Authenticated Users`) and anonymous (`Everyone`), unchanged exact results
for every other account, a local group through `Authenticated Users`, the
share token.

**Next lab:** measure a real Guest network token and an anonymous session
(with and without `EveryoneIncludesAnonymous`); if they confirm the
documentation, replace the bound by the exact rule.

## Lab measurement (2026-10-13)

`guest-token.ps1` on MS-01 (Windows Server 2025, member server): the Guest
account enabled with a random password only for the measurement and
restored afterwards; real tokens from `LogonUser` and the anonymous token
from `ImpersonateAnonymousToken`.

| Token | Everyone | Authenticated Users |
| --- | --- | --- |
| Guest, network logon | present | **absent** |
| Guest, interactive logon | present | **absent** |
| Anonymous (`EveryoneIncludesAnonymous` = 0, the default) | **absent** | **absent** |

The documented behaviour is confirmed. Decision, replacing points 1–2:

- `identity_absent_well_knowns`: Guest and ANONYMOUS LOGON → Authenticated
  Users is **certainly absent** — not in the token, its ACEs do not apply,
  no range; a local group reached only through it is no membership.
- `identity_uncertain_well_knowns`: ANONYMOUS LOGON → Everyone stays
  **uncertain**, because it depends on `EveryoneIncludesAnonymous`, which
  Stars does not read. A Guest token always has Everyone.
- The marker `GuestOrAnonymousToken` names both; the "Evaluated as" step
  and the UNCERTAIN reason say the same.

## Consequences

- No Guest or anonymous right is stated as a fact through a well-known the
  token may not carry.
- Until the lab measurement, results for these identities read "between …
  and …" wherever such an ACE decides them.
