# ADR 0066 — No silent drops in group resolution

## Status
Accepted (2026-10-10). Extends the principal pipeline and the local-group
resolution; complements ADR 0064 (unresolvable identities) and ADR 0065
(not-determinable results).

## Context

A successful group resolution could still lose groups without any trace —
the token was then smaller than the real one and every result built on it
looked exact:

- a user's or computer's **primary group** that was not found under the
  configured base or whose lookup failed (only a log line);
- a group of the transitive result without a readable `objectSid`
  (skipped);
- memberships in groups **outside the resolved set** — e.g. groups outside
  a base that is only an OU — whose DNs appear in `memberOf` but which the
  transitive search could not return (ignored);
- a `memberOf` larger than the server's `MaxValRange` (1500 on the lab DC):
  AD returns `memberOf;range=0-1499`, which the resolver read as an empty
  list — direct memberships counted as nested, further routes went unseen;
- a principal entry the group search no longer found (empty list);
- a local group of the target server whose SID could not be looked up
  (dropped), a failing `NetUserGetGroups` / local-group lookup on the
  SAM/LSA path (log line only), and in the GUI a failed SAM resolution that
  fell back to a bare SID.

The first live test of the new gap report also exposed a long-standing
defect: ldap3 stores attribute values whose bytes happen to be valid UTF-8
as text, and every builtin SID (`S-1-5-32-*`, e.g. BUILTIN\Users) is valid
UTF-8. Stars read `objectSid` only from the binary map, so all builtin
groups — and any SID whose bytes form valid UTF-8 by chance — vanished from
LDAP results. On a domain controller the local-group lookup happened to
add them back, which is why the lab comparison had not shown it.

## Decision

1. The group-resolution contract carries its gaps:
   `IdentityResolver::resolve_group_memberships` returns
   `GroupMembershipResolution { memberships, gaps }`; the principal pipeline
   keeps them in `PrincipalResolution::group_resolution_gaps`, the engine
   flags carry them (`ResolutionProvenance::group_resolution_gaps`), and the
   engine and the membership view attach one `GroupResolutionIncomplete {
   reason }` marker per gap (incompleteness trigger, token layer, Concern) —
   so the result is "not determinable" (ADR 0065).
2. Gaps detected: the primary-group cases (attribute missing for an
   account, not numeric, domain not derivable, not found, lookup error),
   groups without a readable SID, DNs referenced by `memberOf` that are
   neither in the resolved set nor the principal itself, a principal entry
   the group search did not find.
3. `memberOf` is completed through **range retrieval** (`memberOf;range=
   N-*` until the final `*` chunk) for the principal and every group of the
   closure. Each server answer is validated (the next chunk must start
   right after the previous one, bounded rounds); an inconsistency fails
   the group resolution visibly instead of shortening the list.
4. Local groups whose SID cannot be looked up are reported; the CLI and
   GUI keep the resolved local groups in the token but mark the local-group
   evaluation as not complete. The SAM/LSA path reports unresolvable domain
   groups, failed group reads and a failed SAM resolution as gaps.
5. `RawEntry::first_bin_attr` falls back to the text map, so binary
   attributes are read regardless of how the LDAP layer classified them —
   `objectSid`, `securityIdentifier` (trusts), the new domain-SID reads.

## Consequences

- No group-resolution shortfall is silent any more; a result whose token
  may lack groups always says so and why, naming concrete DNs (first three,
  then a count).
- Builtin groups now come from LDAP on a domain controller as well; they
  also come from the local-group lookup there, so the same group can arrive
  twice — the explanation shows it once (lab finding CLI3-1).
- Range retrieval costs one extra base search per 1500 values, only for
  entries that need it.
- Lab acceptance (2026-10-10, DC-01): `rt_user01`, a direct member of 1601
  groups, and `rt_bigparent`, a member of 1600 groups: `memberOf` arrived
  ranged and was completed to 1601 / 1600 values; 1602 direct memberships
  (before: 0 direct); further routes through `rt_bigparent` named. With the
  base `OU=LabUsers,DC=corp,DC=test` the result for `u00030` is "not
  determinable" with the missing primary group and 18 groups outside the
  base named — before, the token simply lacked them.
- Tests: range-suffix parsing and key detection, binary attributes stored
  as text, gaps for groups without SID and outside the resolved set, no
  false gap for a complete closure or a cyclic nesting, propagation to
  flags, markers and the engine.
