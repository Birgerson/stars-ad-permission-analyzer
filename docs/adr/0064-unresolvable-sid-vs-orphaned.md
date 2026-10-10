# ADR 0064 — Orphaned only with evidence; unresolvable SIDs are incomplete

## Status
Accepted (2026-10-10). Refines the principal pipeline (ADR 0032/0033);
closes lab findings AD3-1 and AD3-2; narrows known limitation L15.

## Context

When the identity to analyze is given as a SID that neither the configured
LDAP base nor the local LSA can resolve, the principal pipeline classified
it as `Orphaned` ("the account no longer exists") and evaluated the bare
SID with a confident result.

The corp.test lab run (2026-10-07) showed why that is wrong:
`EXT\ext_partner04`, a valid account of the trusted domain `ext.test`, was
reported as `Kind: Orphaned` with effective rights 0, although the DACL
grants Read & Execute to its group `EXT\GG_ExtAuditors` (case P4; S21 the
same for a direct ACE). The local LSA of a host that is not joined to a
domain cannot resolve any domain SID, so on such a host every foreign SID
looked orphaned. Only a generic "local groups could not be resolved"
warning appeared. In addition, the header said `Status: Active` for every
unresolvable or orphaned SID although the state was unknown (AD3-2).

A miss is proof that an account is gone only when the directory that was
searched is authoritative for the SID: the SID belongs to the configured
domain, and the configured base covers that whole domain.

## Decision

1. On an LDAP miss plus an LSA miss the pipeline asks the identity backend
   to classify the SID (`SidDomainRelation`). The LDAP backend reads the
   domain SID of the base's domain root (base search) and, if the SID is
   foreign, the domain's trust objects; on a Global Catalog bind it reads
   the SIDs of all forest domains.
   - SID of the configured domain **and** base = domain root (or GC):
     **orphaned** — `Kind: Orphaned`, informational marker
     `IdentityOrphaned` ("nobody can log on with it; an ACE naming it is a
     dead entry").
   - SID of the configured domain, base covers only part of it; SID of a
     trusted domain (named); SID of another domain; or any read problem:
     **not resolvable** — `Kind: Unknown`, scope
     `IdentityScopeStatus::Unresolvable`, marker `IdentityNotResolvable {
     reason }`, an incompleteness trigger (Concern). The reason states
     which case applies.
   - The trait default answers "unknown": a backend that cannot read the
     directory context never turns a miss into proof.
2. Account status lines and the CSV `disabled` column come from one helper
   (`AccountStatus`): `Active`/`DISABLED` only when known, otherwise
   `unknown`, `n/a (not an account)` for groups and well-known principals,
   `does not exist (orphaned SID)` for orphans. The CSV column carries
   `true`/`false`/`unknown`/`n/a`.
3. An orphaned SID no longer gets the misleading "disabled status unknown"
   marker; the orphan marker says what there is to say.

## Consequences

- A trusted-domain account given by SID is never called orphaned, and its
  result is marked incomplete with the named trust partner. Its group
  memberships in the trusted domain are still not resolved — that needs a
  second directory connection (L15, remaining part).
- Two extra LDAP reads only on the miss path (domain SID, trust objects),
  inside the configured timeout. A read failure degrades to "not
  resolvable", never to "orphaned".
- A SID of a domain that does not exist anywhere is reported as "another
  domain, unknown" — Stars cannot prove that a domain does not exist.
- Lab acceptance (2026-10-10, against DC-01): P4/S21 → "belongs to the
  trusted domain ext.test", status unknown; S20 → "neither the configured
  domain nor one of its trusts"; S32 (deleted corp accounts) → orphaned,
  status "does not exist"; regular user u00030 → Active.
- Tests: classification per relation (trusted, other, partial base,
  unknown, whole base) with the fake backend, the SID/DN helpers, the
  account status, the engine markers and the CSV column.
