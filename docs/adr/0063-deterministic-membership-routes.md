# ADR 0063 — Deterministic membership routes and disclosure of further routes

## Status
Accepted (2026-10-10). Refines the chain reconstruction of the LDAP group
resolution and the local-group chains; closes lab finding DET-1 (explanation
path varies between runs).

## Context

Every group membership in Stars carries a `MembershipPath`: one concrete
chain `user → group → … → target` that the explanation path and the
membership views show. The lab campaign of 2026-10-10 ran the same scan
(32 identities over the lab's hidden data share on DC-01) twice and
compared every CSV column. The effective masks were identical; the
explanation text was not:
for `u00030` all 663 explanations differed, e.g. `g00100` reached once via
`g00229` and once via `g00211`, both chains real and equally short.

Root cause, confirmed by code reading and by re-running the old algorithm
in isolation (40 process starts, identical input: 20 × one chain, 20 × the
other):

- The resolver seeded its breadth-first search from the principal's
  `memberOf` values collected in a `HashSet`. Rust's `HashSet` uses a
  randomly keyed hasher **per process**, so the seed order — and with it the
  queue order — changed on every program start.
- The first time the search discovered a group, its predecessor was fixed.
  With several equally short chains, the chain that happened to be expanded
  first won.
- Secondary order dependencies: the `memberOf` value order and the entry
  order returned by the server (stable in practice, not guaranteed), and the
  member order of `NetLocalGroupGetMembers` for local groups, where the first
  known member became the shown mediator.

A varying explanation is a reproducibility defect for an audit tool. It also
hides a correctness problem in what was shown: the explanation presented
**one** chain as if it were the only one. An administrator who removes the
user from the shown intermediate group expects the access to disappear; if
another route exists, it does not.

## Decision

1. **Distances from a plain BFS, predecessor by an explicit rule.** The hop
   distance of each group from the principal is computed by BFS (order does
   not affect distances). The chosen predecessor of a group is, among its
   member groups exactly one hop closer to the principal, the one with the
   alphabetically first lower-cased distinguished name. Every collection that
   influences the output is ordered (`BTreeMap`/`BTreeSet`, sorted vectors);
   `memberOf` values are sorted before use. The same directory state now
   yields identical memberships regardless of server answer order.
2. **Further routes are disclosed.** `MembershipPath` gains `also_via`: every
   group the principal is in that is a direct member of the target, except
   the last hop of the shown chain — including groups on longer routes. The
   explanation step says `[also a member through B (SID), C (SID) — the
   shown chain is not the only route]`; the membership views
   (`origin_label`, CLI `groups`, GUI Groups tab, membership CSV column
   `origin`) say `…; also a member through …`. At most five entries are
   spelled out, the rest are counted (`+N more`); the full list stays in the
   JSON model.
3. **Local groups the same way.** All members of a local group that are the
   user or one of the user's known token groups are entries. Shown chain: the
   user itself, otherwise the entry with the alphabetically first name, then
   SID; all others go into `also_via`.
4. **Stable output order.** Memberships are listed primary group first, then
   by hop distance, name (case-insensitive) and DN; groups whose chain could
   not be reconstructed come last.
5. An unreconstructable chain no longer claims "transitive": it reads
   `membership confirmed, exact chain unknown`, because with unreadable
   local-group members or a truncated `memberOf` whether the membership is
   direct is unknown too.

## Consequences

- Repeated runs produce identical explanation paths; the campaign comparison
  can treat any text difference as a real change again.
- The explanation of a multiply reachable group is longer by one bracket.
  The shown chain is still one shortest route; Stars does not claim which
  single removal would cut access (that would need a cut-set analysis), it
  only states every entry into the group.
- `also_via` lists entries into the **target**, not every alternative path
  through the whole graph: two routes that diverge earlier but enter the
  target through the same group appear as one entry. The intermediate
  group's own membership step lists its own entries, so the full picture
  stays readable step by step.
- Serialized results gain an optional field (`#[serde(default)]`); older
  rows and exports stay readable.
- Tests: route choice independent of entry and value order (fixed cases and
  40 shuffled permutations of a dense 24-group graph), longer routes listed,
  direct-plus-nested membership, primary group handling, unreconstructable
  chains, cyclic nesting, local-group mediator choice, rendering and the
  five-entry limit.
