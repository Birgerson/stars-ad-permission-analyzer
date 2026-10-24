# ADR 0078 — Accounts of a trusted domain, resolved on its domain controller

## Status
Accepted (2026-10-17). Closes the remaining part of known limitation L15
(ADR 0064 had closed the classification).

## Context

Since ADR 0064 an account of a **trusted** domain, given by SID, is no
longer called orphaned: Stars names the trust partner and reports the
result as not determinable, because the account's groups in its own domain
are unknown. In the corp.test lab every such result (the project tree for
`ext.test` partner accounts) was NOT DETERMINABLE, although Windows grants
those accounts exact rights.

Measured on DC-01 (Authz context from the SID, S4U across the external,
quarantined trust corp.test ⇄ ext.test, 2026-10-17), the token Windows
builds for an ext.test account accessing a corp.test resource contains:

| From | SIDs |
| --- | --- |
| the account's own domain (ext.test) | the account, its primary group, its **global and universal** groups — exactly the domain controller's `tokenGroupsGlobalAndUniversal` |
| the resource domain (corp.test) | the **domain-local** groups that contain one of those SIDs as a Foreign Security Principal (transitively), marked as resource groups |
| the resource domain's builtin groups | e.g. `BUILTIN\Users` through Authenticated Users |
| well-known | Everyone, Authenticated Users, This Organization (no Selective Authentication) |

Not in the token: the builtin and domain-local groups of ext.test
(`tokenGroups` of the account lists them; `tokenGroupsGlobalAndUniversal`
does not), and distribution groups.

A simple LDAP bind with an account of corp.test against the ext.test DC is
refused across the trust (`52e`, invalid credentials). Reading the trusted
domain needs credentials of that domain, or a Kerberos signed bind.

## Decision

1. **Optional second connection.** CLI `--trust-server`, `--trust-base-dn`,
   `--trust-bind-dn` (password only via `ADPA_TRUST_BIND_PASSWORD`); GUI
   section "Also resolve accounts of a trusted domain" in Analyze, Scan Tree
   and Groups (one shared Slint component). Same encryption mode and timeout
   as the main connection; every input validated like the main one.
2. **Used only for an account of that trusted domain.** The principal
   pipeline consults it only when the configured domain classifies the SID
   as belonging to a trusted domain (`SidDomainRelation::TrustedDomain`,
   now with the trust's domain SID and attributes), and only when the
   connection's own domain SID equals the trust's. Any other identity — and
   every identity without the flags — takes exactly the path it took before.
3. **Token as Windows builds it** (`ad_resolver::trusted`):
   - the account and its groups are resolved on the trusted DC with the
     existing resolver (security groups only, chains, tokenGroups
     cross-check); only groups in `tokenGroupsGlobalAndUniversal` are kept,
     the others are named as "apply only inside" the trusted domain; a
     crossing group without a found chain is kept without a chain;
   - **SID filtering:** on a quarantined trust (`trustAttributes` 0x4)
     every SID not of the trusted domain is removed — group SIDs and
     `sIDHistory` values of the account and of its groups, list and count;
     on any other trust such a SID is left out and reported as a gap
     (`GroupResolutionIncomplete`), because Stars does not model what that
     trust lets through;
   - for each remaining SID that has a Foreign Security Principal in the
     configured domain, its domain-local groups there are resolved with the
     existing resolver, and the chain continues the home-domain path
     (account → GG_A → GG_B → DL_X → DL_Y). A SID without FSP has no group
     there — no gap.
   - Builtin and local groups of the target server come, as for any
     account, from the frontends' local-group expansion by SID.
4. **Markers.** `TrustedDomainAccountResolved { domain, home_only_groups,
   sid_filtered }` — informational (Neutral), the result stays exact.
   `TrustBoundaryEffectsNotModeled` only when the trust uses Selective
   Authentication, which Stars does not model. Scope status
   `ResolvedInTrustedDomain`.
5. **Failure is never a guess.** A connection to the wrong domain, an
   unreadable domain SID or an error on the trusted DC keeps the result
   "not resolvable", with the reason.

## Consequences

- An account of a trusted domain gets exact, explainable rights when the
  connection is given; without it the result is unchanged (not
  determinable). The reason text now names the option.
- **This Organization** (S-1-5-15) stays logon-dependent for every
  account, as before: for an account across a trust without Selective
  Authentication Windows includes it (measured), but deciding it would
  change results for all accounts. Such a result keeps the range, which
  contains the Windows value. Possible follow-up.
- Windows evaluates the groups in the account's Kerberos ticket; a cached
  ticket can carry an older group set after a change (measured: the Authz
  context showed the new ext.test groups only after `klist purge` on the
  DC). Stars reads the current directory — for every domain, not only
  across trusts.
- Selective Authentication ("allowed to authenticate" on the target) and a
  forest trust's SID filtering of third-domain SIDs are not modelled; both
  are reported, never assumed.
- Input forms: a SID, or a name the LSA of the machine Stars runs on can
  resolve (a domain member resolves `PARTNER\user` across the trust). On a
  machine outside the domain use the SID.

## Lab evidence (2026-10-17)

- New fixtures: ext.test `UG_ExtUniversal` (universal), `DL_ExtLocal`
  (domain local), `GG_ExtNested` (global ∋ GG_ExtAuditors), `GG_ExtDist`
  (distribution); corp.test `gt_DL_trust` (∋ FSP of GG_ExtNested) ⊂
  `gt_DL_trust_outer`; folder tree `C:\TrustTest` (share `TrustTest`,
  outside the lab's existing data tree, so earlier baselines keep their
  rows) with one rule
  per folder.
- Stars with the trusted connection vs. the Windows Authz oracle (every
  folder, including no-access ones), five ext.test accounts:
  `TrustTest` 55 / 55 determinable rows identical, 5 This-Organization rows
  bounded with the Windows value inside the range; project tree 205 / 205
  identical (incl. the original L15 cases: ext_partner04 → RX on P025,
  ext_partner05 → Modify on P030 — before: NOT DETERMINABLE).
- Regression, v1.13.0 vs. this change, without the trust flags, every
  column: DC-01 data share, 32 corp identities × 689 paths = 22,048 rows
  identical; MS-01 with LDAP 135 and without LDAP 135 rows identical;
  group-kind fixture 78 rows identical. The five ext.test SIDs without the
  connection: identical except the one reworded reason sentence (0
  differences after replacing it, 3,445 rows).
- GUI: Analyze tab with the trusted section on `TrustTest\TE_fsp_chain` →
  Modify with the full chain; Graph tab shows it.

## Addendum (2026-10-24) — the connection is used on a domain-joined machine too

The lab evidence above was taken from a workstation outside the domain.
There, Windows LSA cannot name an account of a trusted domain, so the
resolver falls through to the classification and from there to the
trusted-domain connection.

On a **domain-joined** machine LSA names every such account
(`EXT\ext_partner02`). The resolver then took its LSA path ("outside the
configured LDAP base", groups not attempted) and **never used the
configured connection**. The only exception was an account with a Foreign
Security Principal object here (ADR 0079).

Measured on MS-01 (member of corp.test, as SYSTEM, the same five ext.test
accounts and the `TrustTest` fixture, with the connection to DC-02):

- **v1.18.0 / main 7ad1dc7:** 65 of 65 rows NOT DETERMINABLE.
- **With the fix:** 65 of 65 rows determinable and identical, column by
  column in rights and mask, to the workstation run.

The accounts of partner.test and child.partner.test (ADR 0084) ran on MS-01
as `CORP\Administrator` with Signed LDAP. All 56 rows were determinable and
match the real SMB logons, including `CHILD\ch_user02` reaching a folder
through the forest root's universal group `PARTNER\UG_PT_Forest`.

**Decision.** An LSA hit now asks the configured connection first, under the
same rule as the FSP hit: only when the SID's domain is a trusted domain
and the connection serves exactly that domain. Otherwise the LSA path stays
unchanged.
