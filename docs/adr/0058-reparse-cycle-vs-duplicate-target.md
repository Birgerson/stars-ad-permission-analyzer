# ADR 0058 — Reparse handling: real cycles vs duplicate targets

**Status:** Accepted (2026-07-04)
**References:** ADR 0049 (streaming walk), deep review 2026-07-04
findings F2 + F5, feedback rule "no silent skips"

## Context

The walker kept a single scan-wide `visited_canonical` set. Any reparse
point whose canonical target was already in that set was reported as
"already visited — recursion stopped to avoid an infinite loop". Review F2:
that conflates two different situations —

- a **real cycle** (junction to an ancestor of the current traversal
  chain), where stopping is the only correct move; and
- a **duplicate target** (two independent namespace routes to the same
  directory — two junctions to one share folder, or a junction plus the
  directory's real path), which is not a cycle at all.

Worse, the behavior was **inconsistent**: only reparse targets (and the
root) were registered, so a junction pointing at an already-walked *plain*
directory silently enumerated the whole subtree a second time, while a
junction pointing at another junction's target was suppressed with a
misleading "loop" message. Review F5 added that the junction tests
silently `return`ed when `mklink` failed, so this audit-critical behavior
could appear covered without ever being exercised.

## Decision

1. **Two structures with distinct jobs** in a new, OS-free-testable
   `LoopDetector` (`fs_scanner::walker`):
   - `chain` — canonical identities of the **active** recursion path.
     Membership ⇒ descending would re-enter an ancestor ⇒ **cycle**.
   - `seen_first_path` — scan-wide map canonical identity → **first
     namespace path** that enumerated it. A later hit ⇒ **duplicate
     target**.
2. **Duplicate semantics: enumerate once, report every further route.**
   Each distinct directory's subtree is enumerated exactly once — under
   whichever namespace route reaches it first (NTFS enumerates
   alphabetically, so this is deterministic). Every further route emits a
   typed diagnostic naming the first path and does not descend. Rationale:
   unbounded duplicate traversal is an amplification hazard (N junctions
   to a large tree multiply the scan and the report N-fold — against
   performance rules 1/7 and the large-environment default), while a
   suppressed route without evidence would be a silent skip. The link
   object itself is always in the result with its own DACL.
3. **Typed errors instead of message prose** (review asked for a typed
   diagnostic): `CoreError::ReparseCycle` and
   `CoreError::ReparseDuplicateTarget`. Both surface as visible
   `WalkError`s in CLI/GUI/persisted scan errors like before — but audit
   consumers can now tell the cases apart mechanically.
4. **Consistency fix**: every directory's canonical identity is now
   registered — plain children derive theirs from the parent's canonical
   plus the component name (no extra syscall per directory; `canonicalize`
   is only called for the root and for reparse points). A junction to an
   already-walked plain directory is therefore a duplicate route too,
   instead of a silent second enumeration.
5. **Tests fail loudly (F5).** `mklink /J` needs no admin rights; the
   junction tests now `assert!` on its success instead of silently
   returning. The cycle/duplicate decision logic additionally has pure
   unit tests (`LoopDetector`) that need no filesystem at all, and a new
   integration test pins the two-junctions-one-target case end to end.

## Consequences

- A SYSVOL-style pair (junction + real directory in one tree) now yields
  the content **once** plus one duplicate-route diagnostic, instead of
  (pre-F2, silently) twice. Object counts on trees with such pairs drop
  accordingly — the diagnostic explains why, naming the first route.
- The misleading "infinite loop" wording no longer appears for
  non-cyclic duplicates; real cycles keep a loop explanation.
- `LoopDetector::enter/leave` is the single decision point; the walk
  cannot drift from the tested semantics.

## Alternatives considered

- **Fully enumerating duplicate routes** (namespace-complete output).
  Rejected: junction fan-in makes the output size a function of the
  route count, not the data — an amplification hazard on exactly the
  large file servers Stars targets. The evidence need ("which routes
  exist?") is served by the link objects plus the typed diagnostics.
- **A traversal cap per duplicate target.** Rejected: a cap is a policy
  knob nobody can set correctly; partial duplicate enumeration is harder
  to explain in an audit than "once + named routes".
