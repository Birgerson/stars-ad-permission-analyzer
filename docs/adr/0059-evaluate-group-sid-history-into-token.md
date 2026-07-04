# ADR 0059 — Evaluate the groups' `sIDHistory` SIDs into the access token

**Status:** Accepted (2026-07-04)
**References:** ADR 0056 (user `sIDHistory`), ADR 0052 (visibility step),
known-limitations L3 (group-history remainder), ADR 0019 (share token =
NTFS token)

## Context

ADR 0056 evaluated the **user's** historical SIDs into the token and
explicitly scoped out the groups': the Windows PAC carries the
`sIDHistory` values of the token **groups** as well, so an ACE on a
migrated *group's* old SID grants access at runtime while Stars still saw
"another SID" and understated the right. Unlike the pre-ADR-0052 user
case this gap produced **no marker at all** — group entries' `sIDHistory`
was not even counted. L3 tracked it as the open remainder; this ADR
closes it.

The same forest-scope reasoning as in ADR 0056 applies: history SIDs
owned by a domain of the connected forest are honored unconditionally;
foreign-forest-sourced values depend on the trust's `/EnableSIDHistory`
state, which Stars does not read (L4, verification.md M.5). Group history
is read exactly where the group entries already come from — the
server-side transitive membership search — so no new query is needed.

## Decision

1. **`GroupMembership` gains the same count/values pair as `Identity`**
   (both `#[serde(default)]` for cache/persist back-compat):
   - `group_sid_history_count: usize` — authoritative total from LDAP;
   - `group_sid_history: Vec<Sid>` — parsed values
     (`len <= count`; malformed values are logged and stay visible as
     the difference).
2. **Resolver**: `sIDHistory` joins `MEMBERSHIP_ATTRS`; a shared
   `parse_sid_history(entry)` helper (also used by
   `parse_identity_from_entry`) fills the fields at all three
   construction sites — primary group (8a), transitive groups (8b),
   primary-group parents (8c). The SAM/LSA fallback cannot read the
   attribute (fields stay 0/empty — that path already carries
   `DomainGroupRecursionIncomplete`); local server groups have no
   `sIDHistory` (0 is exact, not unknown); the SQLite membership cache
   does not store the fields (it does not feed evaluation).
3. **Token**: `build_token_sids_with_context` inserts every membership's
   `group_sid_history` values. No signature change — the history rides
   inside `GroupMembership`, so the engine, the CLI share path and the
   GUI share path stay consistent automatically (ADR 0019 invariant).
4. **Explanation path**: the membership step is suffixed with the
   group's evaluated historical SIDs
   (`… [carries historical SID(s) (sIDHistory) in the evaluated token:
   S-…]`), so an ACE matching a group's old SID is explainable from the
   step list alone.
5. **Marker split**, mirroring ADR 0056, via a shared helper in the core
   model (`group_sid_history_diagnostics(&[GroupMembership])`) consumed
   by the engine and the membership view:
   - **`GroupSidHistoryEvaluated { groups, count }`** (new) —
     informational, `Neutral`, not an incompleteness trigger: `count`
     historical SIDs of `groups` token groups were evaluated.
   - **`GroupSidHistoryPresent { count }`** (new) — `Concern`,
     incompleteness trigger: `count` group history values could **not**
     be parsed and stay un-evaluated (rights may be understated).

## Consequences

- An ACE on a migrated group's old SID now matches (Allow **and** Deny)
  for every member of that group, with an explainable path.
- The user-level markers (`SidHistoryEvaluated`/`SidHistoryPresent`)
  keep their ADR 0056 meaning untouched; group history is reported
  separately, so old persisted rows stay unambiguous.
- Cross-forest caveat unchanged (L4 / M.5): foreign-forest-sourced
  group history is evaluated like the user case and is exact while the
  trust honors history.
- Known-limitations **L3 closes fully** (user half: ADR 0056; group
  half: this ADR).

## Tests

- Engine: ACE on a group's old SID grants Modify for a member
  (acceptance); Deny via a group's old SID is honored; partial parse →
  `GroupSidHistoryEvaluated` + `GroupSidHistoryPresent` + incomplete;
  token builder includes group history; membership step names the old
  SID.
- Resolver: group entry with two binary `sIDHistory` values → count 2 +
  both parsed; malformed value keeps the count.
- Principal view: `membership_diagnostics` applies the same group split.
- Risk engine: `GroupSidHistoryEvaluated` alone does not mark a finding
  incomplete; `GroupSidHistoryPresent` does.
