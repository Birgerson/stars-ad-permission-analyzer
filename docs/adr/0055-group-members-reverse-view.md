# ADR 0055 — Group → Members (reverse / downward view), v1 direct members

**Status:** Accepted (2026-07-02)
**References:** ADR 0053 (standalone group-membership view — the upward
direction), ADR 0054 (GUI LDAP timeout control), ADR 0052 (sIDHistory / trust
visibility)

## Context

Stars answers *"which groups is this identity in?"* — the **upward** direction
(ADR 0053: CLI `groups`, GUI Groups tab). The natural complement, repeatedly
requested, is the **downward** direction: *"who is in this group, and how?"* —
the members of a group (users and nested subgroups).

Enumerating a group's members correctly on Active Directory has two well-known
sharp edges, both of the *silently-wrong* class Stars exists to avoid:

1. **`primaryGroupID` members are invisible in `member`.** A user (or computer)
   whose **primary** group is the target does **not** appear in the group's
   `member` attribute. Classic case: nearly every user's primary group is
   *Domain Users*, so a naive `member`-only read reports **zero** members for
   it. These members must be found by a separate search on `primaryGroupID`.
2. **Large-group truncation.** The multi-valued `member` attribute is returned
   by AD in ~1500-value ranges (`member;range=0-1499`). Reading it naively and
   mishandling the range boundary silently drops the rest of a large group.

## Decision

Add a **direct-members** view (v1) as the reverse of ADR 0053, sharing the same
scope discipline: read-only, no path / ACL / effective rights, one shared data
model rendered by both CLI and GUI.

### Enumeration — back-link instead of range retrieval

For the direct members we search the **`memberOf` back-link** rather than
reading the group's `member` attribute:

```
(memberOf=<escaped group DN>)      → MemberVia::Direct
```

`memberOf` is AD's referential back-link of `member`, so this returns exactly
the group's direct members — but as a **normal paged search** (`PagedResults`),
which sidesteps the `member;range=` boundary entirely and reuses the existing,
tested paging. This is deliberately **not** the literal `member` range-retrieval
the first plan sketched: the back-link achieves the same result (no silent
truncation) with less that can go wrong.

The `primaryGroupID` members are fetched separately and merged:

```
(primaryGroupID=<RID>)             → MemberVia::PrimaryGroup
```

where `<RID>` is the last component of the group SID. The attribute exists only
on security principals, so this returns exactly the primary-group members.

### Graceful degradation, no silent skip

The two searches run independently. If **one** fails, the other's results are
still returned with a `GroupMemberEnumerationIncomplete { reason }` marker (the
count is then a lower bound). If **both** fail, that is a hard error rather than
a misleading empty "0 members". Members are deduplicated by SID.

### Data model (core)

- `GroupMembersReport { group, members, diagnostics }`
- `MemberNode { identity, via, children }` — `children` is reserved for v2
  (recursive nesting) and stays empty in v1, so the serialized shape is stable
  across versions.
- `MemberVia { Direct, PrimaryGroup }`
- Two diagnostics: `MembersViaPrimaryGroupIncluded { count }` (neutral — the
  members were *included*, so it is **not** an incompleteness trigger) and
  `GroupMemberEnumerationIncomplete { reason }` (incompleteness trigger,
  Concern). The privileged-group flag is reused so a **nested privileged group**
  member is surfaced just like a privileged parent is in the upward view.

### Surfaces

- **CLI:** new `adpa members --group <name|DOMAIN\group|SID>` with the same
  LDAP / bind / timeout / `--output` flags as `groups`. **LDAP is required** —
  the SAM/LSA path cannot enumerate domain-group members, so without `--server`
  the command errors clearly rather than returning an empty list. Non-group
  input is rejected (a user has no members).
- **GUI:** a **direction toggle** in the existing Groups tab ("Member of" ↔
  "Members"), reusing the identity field, the LDAP controls, and the result
  widgets. The downward result flows through the same `GroupsViewData` /
  `WorkerEvent::GroupsDone` path; a `is_members` flag relabels the counts.
- **Export:** `.json` / `.csv`, under the same conservative `create_new`
  overwrite policy as the `groups` export (deep review 2026-07-01 finding 2).

### Timeout budget

The whole enumeration (group DN lookup + both member searches) runs under
**one** `--ldap-timeout` budget — unlike most resolver calls, which are
per-operation. On very large groups, size the timeout for the *sum* of the
searches; on expiry the operation fails as a whole (a clear error, never a
silently short list).

### Follow-up review fixes (2026-07-03)

Two independent reviews of the initial implementation led to hardening within
the same release: the `primaryGroupID` hits are filtered to the group's
**domain-SID prefix** (a bare RID is not forest-unique — on a GC bind the
unfiltered query would return users of *other* domains whose group shares the
RID: false positives), and a **universal group** queried over a plain domain
bind now carries a `UniversalGroupCrossDomainMembersNotVisible` marker
(members from other domains live in other partitions and are not visible from
that bind — Neutral, but an incompleteness trigger).

### Live proof in a multi-domain forest (2026-07-04)

Both follow-up fixes were verified live against a purpose-built **redundant
multi-domain forest** (`res.lab` root + `emea.res.lab` child + `leg.lab` tree,
five DCs). The single-domain lab could not exercise them; the multi-domain
build does:

- **F1 (RID collision):** RID 513 (`Domain Users`) collides across three
  domains — res.lab 2012, leg.lab 704, emea.res.lab 6. A raw forest-wide GC
  query `(primaryGroupID=513)` returns **2722**; `members "Domain Users"
  [res.lab] --global-catalog` returns **exactly 2012** — the domain-SID filter
  drops the 710 cross-domain collisions a naive tool would misattribute.
- **F2 (universal cross-domain):** a universal group with a real cross-domain
  member is enumerated as 1 member **plus the marker** over a domain bind (the
  cross-domain member is flagged missing, never silently dropped), and as both
  members over a GC bind.

## Consequences

- The most-requested reverse question is answerable, correctly, including the
  Domain-Users / primaryGroupID case that a naive tool gets wrong.
- Config construction was factored into a shared `build_ldap_config` so the
  `members` command binds identically to `analyze` / `scan` / `groups`.
- **Deferred to v2:** recursive nesting (the member tree) with cycle detection
  and `--recursive` / `--max-depth`. `MemberNode.children` already exists for
  it. A hard cap / streaming for pathologically large groups is also v2; v1
  enumerates fully via paging.

## Alternatives considered

- **Read `member` with explicit range retrieval.** Correct but fiddlier (range
  parsing, re-query per range) than the back-link search, with no benefit for
  direct members. Rejected for v1.
- **`LDAP_MATCHING_RULE_IN_CHAIN` on `member`.** Returns the flat *transitive*
  closure, not the direct members, and omits primaryGroupID members — wrong
  shape for "who is directly in this group, and how". Reserved consideration for
  a future "all effective members" mode, not v1.
- **A separate GUI tab** instead of a toggle. More discoverable but duplicates
  the LDAP controls and adds a sixth tab; the toggle keeps one mental model.
