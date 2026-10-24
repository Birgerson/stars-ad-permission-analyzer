# ADR 0084 — Domains of a trusted forest and forest-trust SID filtering

## Status
Accepted (2026-10-24). Closes the forest-trust part of known limitation L4
for SIDs of the trusted forest's own domains. SIDs of third domains on a
forest trust (and the M.5 edge) stay open.

## Context

The lab got a second forest on 2026-10-24: `partner.test` (forest root,
DC-03, Server 2022 en-us) with the child domain `child.partner.test` (DC-04,
Server 2025 en-us), and a bidirectional forest trust corp.test ⇄
partner.test (`trustAttributes` 0x8). corp.test's only trust objects are
`ext.test` (external, quarantined) and `partner.test`; there is **no** trust
object for `child.partner.test`. Windows reaches the child domain through
the forest trust: the trust object's `msDS-TrustForestTrustInfo` lists every
domain of the trusted forest.

Measured with Stars v1.18.0 (main a6c26e1):

1. **Misinformation:** an account of `child.partner.test` was reported as
   *"belongs to domain S-1-5-21-…, which is neither the configured domain
   nor one of its trusts"*. It is trusted.
2. **Gap:** `PARTNER\pt_user02`, a member of the universal group
   `CHILD\UG_CH_Forest`, was not determinable on every folder: the child
   domain's SID was "not modelled" on the forest trust, and the walk on DC-03
   reported the group as "outside the resolved set" and as missing from
   `tokenGroups`.
3. **Misinformation with a Global Catalog bind:** every SID that is no SID
   of the forest — even one of the directly trusted `ext.test` — was
   "neither the configured domain nor one of its trusts". The classification
   never looked at the trust objects in that mode.
4. **Hidden reason:** a trusted-domain connection to DC-04 failed because
   Server 2025 refuses a simple bind without signing (`strongerAuthRequired`).
   Stars said only "the domain SID … could not be read"; the reason was in the
   debug log alone.

### Measurements (lab, 2026-10-24)

Fixture `C:\ForestTest` on DC-01 (share `ForestTest`): 13 folders, each with
one ACE for a principal of partner.test or child.partner.test (user, global,
universal, home domain-local group, a corp.test domain-local group with
both global groups as FSPs, This Organization, Domain Users of both
domains, Authenticated Users). Ground truth from the Authz oracle on DC-01
**and** real SMB logons from MS-01 (`net use` as the account, then opening
each folder with single access rights):

| Account | Token at the corp.test resource (forest-trust part) |
| --- | --- |
| `PARTNER\pt_user01` | its global and universal groups of partner.test, not its domain-local group; the FSP chain; This Organization |
| `PARTNER\pt_user02` | `CHILD\UG_CH_Forest` (a universal group of the **child** domain) — Modify on its folder |
| `CHILD\ch_user01` | `CHILD\Domain Users`, `GG_CH_Staff`, `UG_CH_Forest`, the FSP chain; not `DL_CH_Local` |
| `CHILD\ch_user02` | `CHILD\Domain Users`, This Organization |

Real SMB access matched the Authz result for the first three accounts.
For `ch_user02` the Authz context lacked This Organization. That was an
oracle artefact (the S4U fallback). The real logon read the folder that
grants This Organization.

So a forest trust lets the SIDs of every domain of the trusted forest pass,
not only the SIDs of the forest root it names.

`msDS-TrustForestTrustInfo` on both sides (Server 2022 de and en-us): the
format of MS-ADTS 6.1.6.9.3, with one difference. The **last** record
carries `RecordLen` 0, while every other record carries its true length. The
Global Catalog replicates the trust objects of every domain of the forest
with `trustPartner`, `trustDirection`, `trustAttributes`,
`securityIdentifier` and `msDS-TrustForestTrustInfo` (not `flatName`).

## Decision

1. **Read the forest trust information.** For a forest trust, Stars reads
   `msDS-TrustForestTrustInfo` (one more attribute of the trust search,
   readable by Authenticated Users) and parses its domain records into
   `DomainTrust::forest_domains` (DNS name, NetBIOS name, SID, raw flags).
   The parser reads each known record by its structure. A non-zero
   `RecordLen` must match. The value must be consumed exactly. An unknown
   record type can be skipped only by its stated length. Anything else is
   an error, kept as `forest_info_error`, never shown as an empty forest.
2. **Classify forest domains as trusted.** A SID whose domain is an enabled
   domain of a trusted forest is a SID of a trusted domain (`partner` is
   that domain, `forest` names the forest trust). A domain record whose SID
   is disabled (flags 0x1 / 0x2) gets its own reason: not modelled. When a
   forest trust's information is unknown, a SID of no listed domain is
   *unknown*, not "another domain".
3. **Forest-trust SID filtering.** For an account of a trusted domain on a
   forest trust, SIDs of every enabled domain of the trusted forest pass.
   This was measured. Every other SID (third domains, the trusting forest's
   own domains, disabled domains) stays not modelled and is reported as a
   gap, as before. Quarantine on a forest trust was not measured. There the
   other SIDs are not modelled either; until now they were removed.
4. **The DC's own list settles the token-set gaps.** For a trusted-domain
   account, the set that crosses the trust is the DC's
   `tokenGroupsGlobalAndUniversal`, which must be read or the resolution
   fails. The gaps of the home-domain walk that only concern which groups
   the token holds can therefore be dropped: groups outside the resolved
   set, and differences to `tokenGroups`
   (`GroupMembershipResolution::token_set_gaps`). Every other gap stays.
5. **Global Catalog bind.** The classification reads the trust objects of
   the whole forest. A forest trust applies to every domain of the forest.
   Any other trust applies only to the domain that holds it, so its partner
   gets its own reason: trusted by that domain, but whether the resource's
   domain trusts it is not known.
6. **Domain bind on a domain that is not the forest root.** It does not hold
   the forest's forest trusts, which still apply to it. A miss there is
   *unknown* (RootDSE `rootDomainNamingContext` decides; unreadable counts as
   unknown). This case is not measured; the rule only refuses to claim
   "another domain".
7. **The reason reaches the reader.** When the trusted-domain connection
   cannot read its domain SID, the error (for example the refused bind) is
   part of the "not resolvable" reason.
8. **Trust inventory.** `adpa trusts` and the GUI Trusts tab list the
   domains of a forest trust, or why they are not known. The closing note
   now says what is modelled and what is not. Before, it claimed Stars
   models no runtime effect at all, which has been wrong since ADR 0078.

## Consequences

- `PARTNER\pt_user01` and `PARTNER\pt_user02` are exact on all 14 rows of
  the fixture and match the real SMB logons.
- An account of `child.partner.test` is named as trusted, with its forest.
  Its exact evaluation needs a trusted-domain connection to a DC of the
  child domain. On the lab's Server 2025 DC that connection needs signed
  LDAP (or LDAPS), and the refusal is now shown.
- Still open (L4): what a forest trust does with SIDs of third domains and
  of the trusting forest (sIDHistory from a migration), the effect of
  `TREAT_AS_EXTERNAL` (0x40), and disabled domain records. Stars reports all
  of these as not modelled.
- Read-only: one more attribute on the trust search, one RootDSE read.
