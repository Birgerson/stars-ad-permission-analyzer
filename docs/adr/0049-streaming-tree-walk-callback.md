# ADR 0049 — Streaming tree-walk callback; parallelization deferred

**Status:** Accepted
**Date:** 2026-06-12

## Context

Large file servers are the design default for Stars, not the exception. A full repository review (`review.md`, 2026-06-12, finding 3) flagged two performance-rule gaps in the directory scanner (`crates/fs_scanner/src/walker.rs`):

- **Performance rule 7** ("results should be streamed or stored incrementally"): `walk_tree` accumulated every `FileSystemObject` into one `Vec` (`WalkResult.objects`) before anything downstream ran, so peak memory grew unbounded with the tree size.
- **Performance rule 3** ("enumeration should be parallelizable"): the walk was strictly sequential; on a large server most of the wall-clock time is per-directory `GetNamedSecurityInfoW` latency, which would parallelize well.

Both are "should" requirements and are explicitly subordinate to correctness in the project's priority order (Security → Correctness → Traceability → Testability → Stability → Performance → …).

Two options were on the table:

1. **Streaming via callback only** — replace the internal `Vec` sink with a callback so a caller can consume each item as it is produced, while keeping the proven sequential traversal untouched.
2. **Streaming plus parallelization** — additionally run the directory enumeration on a bounded worker pool.

## Decision

We implement **option 1: a streaming callback**, and **defer parallelization** (option 2) as a separate, later step.

Concretely:

- A new `WalkItem` enum (`Object(FileSystemObject)` / `Error(WalkError)`).
- A new `walk_tree_streaming(root, config, cancel, on_item)` that invokes `on_item` for each object and error as it is discovered and returns whether the walk was cancelled.
- `walk_tree` is now a thin **buffering wrapper** over `walk_tree_streaming` that collects items back into the classic `WalkResult`. Every existing caller keeps working unchanged.
- The internal recursive `walk_dir` writes to a `&mut dyn FnMut(WalkItem)` sink instead of two `Vec`s. The traversal, the reparse-point loop detection (`visited_canonical`), the per-scan security-descriptor cache (ADR-less, engine review finding 2), the cancellation checks, and the result ordering are **byte-for-byte identical** to before.

## Rationale — why correctness-first, why not parallelize now

This is a deliberate correctness-over-speed choice, and it is recorded here precisely because the conservative option was taken on purpose.

1. **The scanner's shared state is order-sensitive.** Reparse-point loop detection mutates a `visited_canonical` set during the depth-first walk. The semantics are "stop recursing into a canonical target already claimed in *this* scan." Parallelizing makes that set shared mutable state and makes it **non-deterministic which path** is flagged as the loop-stopper across runs. For a security-audit tool, every new piece of concurrency is a new source of hard-to-reproduce defects: deadlocks, work-queue termination races, and data races. Correctness ranks above performance.

2. **Streaming alone is almost mechanical and near-zero-risk.** It swaps "push into a `Vec`" for "call a callback." The sequential walk — already covered by tests against real directory trees, long paths, junctions, and junction loops — is untouched. High value (rule 7) at negligible risk.

3. **Diminishing returns at the stated target scale.** Lab Block H measured 0.22–0.29 ms per path. A 5000-path scan is therefore in the low-seconds range sequentially; the dominant cost is per-directory I/O latency. Parallelization is a real win but not a bottleneck at ~5000 paths — the design target.

4. **AGENTS.md forbids uncontrolled threads.** A correct bounded thread pool (controlled lifetime, deadlock-free termination, thread-safe loop detection, per-thread or lock-granular SD caches) is meaningful design and test work. It deserves its own focused change with its own conformance test (the parallel result must provably equal the sequential one), not a rushed addition.

## Consequences

- **Achieved now:** the streaming mechanism (rule 7) exists at the scanner boundary. A memory-sensitive consumer can process the tree incrementally instead of buffering it. Results, ordering, and error reporting are unchanged.
- **Current callers** (`cli::run_scan`, `gui::handle_scan`) still use the buffering `walk_tree` because their downstream logic — risk analysis over the whole result set, optional export, delta comparison — needs the full set. They get a clean, non-breaking path and can adopt streaming later (e.g. a "scan to CSV without risk analysis" mode that never holds the tree).
- **Deferred:** parallel enumeration (rule 3). When implemented it must: keep the loop-detection state thread-safe, terminate without busy-waiting, bound the thread count, and ship a test asserting the parallel object set equals the sequential one. Until then the walk stays sequential and correct.

## Tests

- `streaming_matches_buffered`: the streaming walk yields exactly the same objects (same order) and the same error count as `walk_tree`.
- `streaming_emits_root_first`: the callback fires incrementally — the root object is delivered before the walk has finished collecting the tree.

## Alternatives considered

- **Streaming plus parallelization in one step** — rejected for now per the rationale above (correctness risk vs. modest benefit at the target scale; deserves its own tested change).
- **Leave the walk fully buffered and only document the limitation** — rejected: the streaming sink is cheap and removes the unbounded-memory property at the scanner boundary with no downside.
