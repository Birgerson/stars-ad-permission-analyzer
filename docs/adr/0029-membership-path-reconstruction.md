# ADR 0029 — Concrete membership path in the explanation

**Status:** Accepted
**Date:** 2026-06-01

## Context

ADR 0014 implemented transitive group resolution server-side via
`LDAP_MATCHING_RULE_IN_CHAIN`. That yields a complete set of all groups a
principal is transitively a member of — but no path. The explanation text
of an `EffectivePermission` result therefore showed, per group, only
`Member of GRP_B [transitive]`.

For an audit this is not sufficient: a reviewer must be able to trace the
permission path, i.e. "through which intermediate group does the ACE act on
the user?". Reviewer finding 2026-05-31 #1 rates this as High, because the
effective computation is correct but the proof path remains incomplete.

## Decision

1. **New data model `MembershipPath` in `adpa_core::model`.** Carries:
   - `nodes: Vec<Sid>` — chain `Member → … → target group`, starting with
     the identity SID.
   - `names: Vec<Option<String>>` — index-aligned with `nodes`, readable
     display name per node (where known).
   - `source: MembershipPathSource` —
     `PrimaryGroup | DomainGroup | LocalGroup | LdapMatchingRule`.
   - `complete: bool` — `true` only if the chain was reconstructed from
     concrete `member` edges.

2. **`GroupMembership.path: Option<MembershipPath>`** — new field with
   `#[serde(default)]`, so that older cache entries without this field
   remain readable.

3. **LDAP resolver: BFS reconstruction over `memberOf` edges.**
   - After the existing transitive search, a forward graph
     `group_dn → [memberOf-DNs]` is built from the already-loaded group
     entries.
   - The BFS start nodes are the user's direct `memberOf` DNs and (if
     present) the primary group.
   - The BFS marks a predecessor (`came_from`) per reached group DN. The
     shortest chain to the target group is reconstructed by reading
     backward and translated into SIDs.
   - If a transitively confirmed target is not reached (e.g. because the
     `memberOf` of an intermediate group was truncated by the server), the
     path stays two SIDs long and is marked `complete = false` with
     `source = LdapMatchingRule`.

4. **SAM resolver: analogous paths.** `NetUserGetGroups` yields direct
   edges — path `[user_sid, group_sid]`, `source = DomainGroup`,
   `complete = true`. `NetUserGetLocalGroups` yields the end set, without
   concrete intermediate chains — path `[user_sid, group_sid]`,
   `source = LocalGroup`, `complete = false`.

5. **Engine rendering.** Per membership with a concrete path, the engine
   emits exactly one step:

   ```text
   Member of GRP_B (S-1-5-21-…) [via max.mustermann → GRP_A → GRP_B, source: DomainGroup]
   ```

   Direct edges get `[direct, source: …]`. Incomplete transitive chains are
   marked with
   `[transitive, exact chain unknown — source: LdapMatchingRule, possibly truncated memberOf]`.
   `path = None` (cache reads) falls back to the old format
   `Member of X [direct/transitive]`.

6. **Persistence still stores only topology.** `identity_cache`
   deliberately does not write `MembershipPath` back — the reconstruction
   is a live evaluation and costs nothing per run that would justify
   persisting it.

## Rationale

- **Audit correctness.** AGENTS.md requires a traceable chain per result,
  not just the final statement. Without this path the effective
  computation stays true but unprovable.
- **No additional LDAP round-trips.** The reconstruction runs on entries
  that are loaded anyway (the transitive search brings the group entries
  back with the `memberOf` attribute; see `MEMBERSHIP_ATTRS` in
  `ldap_client`).
- **Backwards-compatible.** The new field is an `Option`. Cache reads and
  external consumers without a path still get sensible output.
- **The `complete` flag makes the difference visible.** When the chain is
  not reconstructable (e.g. because of `memberOf` truncation), this is
  stated explicitly in the report instead of a plausible-looking but
  misleading direct statement.

## Consequences

- Explanation texts have become longer. For GUI list views this may require
  a visual adjustment (wrap/truncation behavior).
- The BFS works exclusively on the known entries — if the server truncates
  the `memberOf` of a transitive intermediate link, the path contains only
  the endpoints (`complete = false`). That is the more honest answer than a
  guessed path.
- Risk rules in `risk_engine` still evaluate `matched_aces` and
  `contributing_sids` — they do not depend on the explanation text. This
  separation is reinforced by ADR 0029: the path is audit information, not
  a computation input.

## Tests

Four new engine tests in `crates/permission_engine/src/engine.rs`:

- `explanation_contains_nested_chain_in_order` — the review's core
  requirement: for `User → GRP_A → GRP_B → ACE on GRP_B` the explanation
  step must contain the order `max.mustermann → GRP_A → GRP_B` inside the
  `via …` block.
- `explanation_direct_membership_with_source_label` — a direct edge shows
  `[direct, source: PrimaryGroup]`.
- `explanation_incomplete_transitive_marks_unknown_chain` —
  `complete = false` writes `exact chain unknown` into the result.
- `explanation_falls_back_to_legacy_format_when_path_missing` — backward
  compatibility with `path = None`.

## Closes

ChatGPT code review 2026-05-31, finding 1 (High).
