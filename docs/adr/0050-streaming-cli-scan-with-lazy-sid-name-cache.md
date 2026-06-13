# ADR 0050 — Streaming CLI scan with a lazy SID-name cache

**Status:** Accepted
**Date:** 2026-06-13

## Context

ADR 0049 added a streaming walk API (`walk_tree_streaming`) but kept
`walk_tree` (buffering) as the only consumer; the CLI and GUI scan
workflows still materialized the whole `Vec<FileSystemObject>` before
evaluation. The 2026-06-13 full-repository review flagged this as the main
remaining large-environment data-flow gap (review finding 1): on a big
file server the heaviest structure — every object with its full DACL —
was held at once, first results were delayed until enumeration finished,
and cancellation only took effect after a large set had already been
built.

A naive "just call `walk_tree_streaming`" did not actually fix this,
because the CLI scan was **two-pass over the buffered objects**:

1. **Pass 1** iterated every object to collect all ACE trustee SIDs and
   build the `SID → name` map once (one LSA lookup per *unique* SID via
   `build_sid_name_map`).
2. **Pass 2** iterated again, evaluating each object with that complete
   map.

Pass 1 is what forced the full buffer. Removing the buffer therefore
required removing the up-front SID-collection pass.

## Decision

Convert the CLI scan (`cli::run_scan`) to a streaming pipeline and replace
the up-front SID collection with a **lazy, incremental SID-name cache**.

- **New `ad_resolver::SidNameResolver`** (engine review 2026-06-13
  finding 1). It holds the growing `SID → name` map plus a `tried` set,
  seeded from the user's group memberships. `resolve(sids)` resolves only
  not-yet-seen SIDs via LSA, so each distinct SID is still resolved
  **exactly once** across the whole scan — the per-unique-SID
  optimization is preserved without an up-front pass. `build_sid_name_map`
  is now a thin wrapper over `new()` + `resolve()` + `into_map()`, so the
  batched and streamed paths share one implementation.

- **Streaming pipeline.** The blocking walk runs in `spawn_blocking` and
  pushes each `WalkItem` through a **bounded** `tokio::sync::mpsc`
  channel (`blocking_send`, capacity 256). The async task consumes items
  one at a time: for each object it resolves that object's trustee SIDs
  into the lazy cache, builds its trustee table, evaluates the permission,
  prints, accumulates the result, and then **drops the
  `FileSystemObject`**. The bounded channel applies backpressure so the
  walk paces itself to consumption rather than racing ahead and buffering.

- The object is **moved** into the engine input (no `fso.clone()` as
  before), a small extra saving.

### Correctness — the streamed result is identical to the buffered one

A path's outputs (its trustee table and its explanation) reference only
**that path's own** trustee SIDs plus the user's memberships. The lazy
resolver resolves a path's SIDs *before* that path is rendered, so the
map handed to evaluation/trustee-building for path *i* always contains
everything path *i* needs. The reused result is therefore byte-for-byte
what the previous two-pass code produced. Verified live (a temp tree
scans and persists identically) and by the existing scan tests plus a new
`build_sid_name_map_matches_resolver` equality test.

## Consequences

- **Memory:** peak no longer includes the full `Vec<FileSystemObject>`.
  The permission set and trustee set are still accumulated (risk analysis,
  optional export and the summary need the whole run), but those are far
  lighter than the FSOs with their DACLs. First on-screen results now
  appear as enumeration proceeds.
- **Cancellation** is more responsive: the walk checks the token between
  entries and the consumer stops as soon as the channel closes.
- **Persistence** stays atomic: results are still collected and written in
  one `persist_scan_atomic` transaction at the end (the all-or-nothing
  history from the v1.6.2 work is unchanged).

## Scope and what is deliberately not done

- **The GUI scan still uses the buffering `walk_tree`.** It is an
  interactive, bounded workflow (a human watching a single scan) and its
  worker interleaves per-object progress events with the UI; converting it
  to streaming is a separate, UI-aware change and is not required to close
  the large-environment concern, which is the headless/automation CLI
  path. Tracked as a follow-up.
- **Risk analysis and export remain whole-set.** They inherently need the
  full permission set; the win here is dropping the FSO buffer, not
  eliminating all accumulation. A future "scan to CSV without risk
  analysis" mode could stream end to end with zero accumulation.

## Tests

- `ad_resolver`: `resolver_seeds_membership_names_verbatim`,
  `resolver_resolves_each_sid_once`, `build_sid_name_map_matches_resolver`.
- Live: a temp-tree scan (with and without `--db`) produces the same
  paths/rights and persists correctly through the streaming path.
