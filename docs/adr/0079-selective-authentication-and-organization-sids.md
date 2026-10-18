# ADR 0079 — Selective Authentication and the organization SIDs of trusted-domain accounts

## Status
Accepted (2026-10-17). Closes the Selective Authentication part of known
limitation L4 and makes `This Organization` / `Other Organization` exact for
accounts of a trusted domain (the open point of L15 after ADR 0078).

## Context

ADR 0078 resolves an account of a trusted domain on a domain controller of
that domain. Two runtime effects of the trust were still not modelled:

1. **Selective Authentication** ("authentication firewall"). Windows lets an
   account of the trusted domain log on to a computer of the configured
   domain only when the computer's AD object grants it the control access
   right **"Allowed to authenticate"**
   (`68b1d179-0d15-4d4f-ab71-46152e79a7bc`). Otherwise the logon fails with
   error **1935** — no access at all, whatever NTFS and share grant. Stars
   marked such results with the informational
   `TrustBoundaryEffectsNotModeled` only.
2. **`This Organization` (S-1-5-15) / `Other Organization` (S-1-5-1000)**.
   Both were logon-dependent for every account (ADR 0065), so an ACE for
   either gave a range.

### Measurements (lab, 2026-10-17, real SMB logons)

External quarantined trust corp.test ⇄ ext.test; target DC-01 (corp.test);
accounts `EXT\ext_partner01` / `EXT\ext_partner04`. Selective Authentication
was switched with `Domain.SetSelectiveAuthenticationStatus` (LSA). `netdom`
and a raw LDAP write of `trustAttributes` had no effect. With it on,
`trustAttributes` reads `0x14`, normally `0x4`.

**Token of a trusted-domain account** (Authz oracle and real SMB access, all
13 TrustTest folders):

| Trust | Organization SID in the token |
| --- | --- |
| without Selective Authentication | `This Organization` (S-1-5-15), not `Other Organization` |
| with Selective Authentication | `Other Organization` (S-1-5-1000), not `This Organization` |

**What the Selective Authentication check counts.** Method: "Allowed to
authenticate" on DC-01's computer object for exactly one principal, then a
fresh `net use \\DC-01\IPC$` as the account. Every row starts from a
confirmed refusal (1935) on the same client:

| Principal with the right | Logon |
| --- | --- |
| a global group of the trusted domain (`EXT\GG_ExtPartners`) | accepted |
| a domain-local group of this domain reached through an FSP chain | accepted |
| Everyone (S-1-1-0) | accepted |
| Authenticated Users (S-1-5-11) | accepted |
| Other Organization (S-1-5-1000) | accepted |
| This Organization (S-1-5-15) | refused |
| NETWORK (S-1-5-2) | refused |
| BUILTIN\Remote Desktop Users, account a member through an FSP | refused |
| BUILTIN\Administrators, account a member through an FSP (default ACE with all extended rights) | refused |

So the check uses the account's token from the trusted domain plus the
domain-local groups of this domain, Everyone, Authenticated Users and the
organization SID. It does **not** use the builtin groups of this domain,
although the resource token for file access does contain them (ADR 0078,
e.g. `BUILTIN\Users`). The check runs before the alias expansion.

**Timing (Microsoft behavior, measured).** A new or changed right takes
effect at the next logon. After the right is **removed**, a client that was
accepted shortly before can keep connecting for a while: for minutes on one
client, longer on another, even after `net session /delete` on the server,
`klist purge` and `nltest /sc_reset`. A second client was refused at once.
So the server's decision is immediate, and the delay belongs to the client
that was already connected. Every measurement above was therefore made from
a client whose refusal had just been confirmed.

**FSP objects.** An account of the trusted domain that was ever added to a
group of the configured domain has an FSP object there, and it stays after
the membership is removed. Its SID then resolves to that FSP, which is the
normal case in production.

## Decision

1. **Organization SID in the token.** `LdapTrustedDomainBackend` adds
   `Other Organization` to the account's token when the trust has
   Selective Authentication, otherwise `This Organization`, with the new
   membership source `TrustedDomainLogon`. It is labeled "added by
   Windows for an account of a trusted domain", not as a local account.
   `permission_engine::is_logon_dependent_for` treats the other
   organization SID as certainly absent when one is in the token. For every
   other account both stay logon-dependent, as before.
2. **Selective Authentication check** (`ad_resolver::selective_auth`), only
   for an account resolved through the trusted-domain connection whose trust
   has Selective Authentication:
   - The NetBIOS name of the target server comes from `NetWkstaGetInfo`
     level 100. `NetServerGetInfo` echoes an IP address passed to it. The
     name is validated: 1–15 characters, no dot, no reserved character.
   - The DACL of its computer object comes from the configured domain:
     an LDAP search with the SD-flags control, DACL only, so no SACL
     privilege is needed.
   - A pure, length-checked parser evaluates "Allowed to authenticate" in
     stored order. It reads object ACEs (`0x05` / `0x06`) with and without
     an object type, `GenericAll` and all-extended-rights grants, and skips
     inherit-only ACEs. Audit and label ACEs are ignored. A callback or
     conditional ACE makes the answer *unknown*.
   - **Certain in the check token:** the account, its `sIDHistory`, its
     groups (home and domain-local, with their history), Everyone,
     Authenticated Users and the organization SID.
     **Certainly absent:** the builtin groups of this domain (`S-1-5-32-…`)
     and NETWORK (both measured), every other domain SID, and the SIDs no
     user logon holds (SYSTEM, LOCAL SERVICE, NETWORK SERVICE, Enterprise
     Domain Controllers, PRINCIPAL_SELF, CREATOR OWNER / GROUP, ANONYMOUS
     LOGON). **Uncertain:** every other well-known SID (e.g. INTERACTIVE,
     authentication-assertion SIDs).
   - The answer is decided only when it is the same with and without the
     uncertain SIDs; otherwise it is unknown.
3. **Result.** New input `PermissionEvaluationInput::selective_authentication`
   and three markers:
   - `SelectiveAuthenticationAllowed { server, via }`: neutral, names the
     principal that grants it. The result is unchanged.
   - `SelectiveAuthenticationDenied { server }`: notice. Effective right
     **No access (0x00000000)**, with a closing explanation step "Logon
     refused". NTFS and share views keep their values, so an admin sees
     what the permissions would grant once the right is given.
   - `SelectiveAuthenticationUnknown { server, reason }`: concern, new
     uncertainty layer `Logon`. The effective right is NOT DETERMINABLE
     (between No access and what the permissions grant); NTFS and share
     stay determinable.
   `TrustBoundaryEffectsNotModeled` now fires for a Selective
   Authentication trust only when no check could be made.
4. **FSP hit of a served trusted domain.** When the configured LDAP returns
   an FSP object for the SID and the trusted-domain connection serves the
   SID's domain, the account is resolved there (ADR 0078 path, including the
   check) instead of through the FSP. Without such a connection, or for
   another domain, the FSP path is unchanged.
5. **Surfaces.** CLI (`analyze`, `scan`: one check per run), GUI (Analyze,
   Scan Tree), HTML badges, graph result node ("logon refused" / "logon not
   determinable").

Strictly read-only: two LDAP searches and one `NetWkstaGetInfo`; Stars
never logs on as the account and never changes a right.

## Consequences

- Lab, Selective Authentication on, no right: both accounts Denied on all
  13 folders = real 1935. Right for `EXT\GG_ExtPartners`: ext_partner01
  Allowed, and its rights match real SMB access on every folder; ext_partner04
  Denied = 1935. Right for INTERACTIVE only: not determinable, with the SID
  named.
- Selective Authentication off: This Organization and Other Organization
  are exact; both accounts match real SMB access on all 26 folder rows.
  The one exception is `TG_deny_ext`: the probe opens through `CreateFileW`,
  which requests SYNCHRONIZE, and a Deny "Write" takes it away. Stars' value
  is the account's real rights (ADR 0080).
- Regression without the trust options: v1.15.0 vs. new, every column
  identical: DC data share 37 identities × 689 rows, MS-01 with and without
  LDAP 270 rows, group-type fixture 78 rows.
- Still open (L4): SID filtering of a forest trust for SIDs of third
  domains, and the M.5 edge (an in-base account's foreign-forest
  `sIDHistory`).
- The check needs the target's computer object to be readable by the bind
  account. Domain defaults allow it; otherwise the result is not
  determinable, with the reason.

## Addendum (2026-10-18): an undeterminable logon with nothing granted

`SelectiveAuthenticationUnknown` made every result of the account NOT
DETERMINABLE — also where the permissions grant nothing. There the range
"between No access and what the permissions grant" is No access to No
access: refused, the account has no access; allowed, the DACLs grant
nothing. A scan of an account in that state reported "NOT DETERMINABLE
(known data: No access)" for every path it cannot reach, which buried the
paths where the logon really decides.

- The marker carries `affects_result`. The engine sets it to false when the
  DACL result is exactly No access — effective mask 0 and no other
  uncertainty (token, NTFS, share). Then `uncertain_layer()` is `None`: the
  result is exact, the marker is informational (severity Neutral), its
  text ends "the permissions grant nothing here, so the effective right is
  No access either way", and the closing explanation step reads "Logon not
  determinable — … Effective: No access (0x00000000)." With anything else
  uncertain the range stays open, because an unknown group could grant.
- Records stored before the field existed read as `true` (serde default):
  they keep the meaning they were written with.
- CLI `[i]` instead of `[!]`, HTML neutral badge "logon not determinable —
  no access either way", GUI share line and graph ("whatever the logon
  decides", the line from the logon box grey dashed) say the same.

Lab (Selective Authentication on, "Allowed to authenticate" only for
INTERACTIVE, which the check cannot decide): `TrustTest` for
`ext_partner01` and `ext_partner04`, 26 rows, before and after — 14 rows
with nothing granted now exact No access, 12 rows with rights still NOT
DETERMINABLE with the same range; in every row masks, matches and every
other column identical, the marker only gaining the field, the explanation
changing only in the three steps that follow from the exact result. Real
SMB logon of both accounts in that state: refused (1935) — No access, inside
both statements. Regression without the trust options, every column: DC
data share 37 identities (25,493 rows), group-type fixture (78), MS-01 with
and without LDAP (270) — 0 differing rows.
