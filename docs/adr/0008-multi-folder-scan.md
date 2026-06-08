# ADR 0008 — Multi-folder scan

## Status
Accepted

## Context

Step 12 adds the ability to analyze an entire directory tree in a single run. A single `analyze` call covers one path; a `scan` run covers the whole subtree from a root and stores every result in the database for later review.

## Decision

### Walker (`fs_scanner::walker`)

`walk_tree(root, config) -> WalkResult`

- Reads the root FSO via `read_file_system_object`, then recurses into children using `std::fs::read_dir`.
- **Reparse-point guard**: if `fso.is_reparse_point` is true, the node is included in results but not recursed into. This prevents infinite loops caused by symlinks and junctions.
- **Error tolerance**: access-denied on a single path (either `read_file_system_object` or `read_dir`) is recorded in `WalkResult.errors` and the walk continues. No single failure aborts the entire scan.
- **Depth limit**: `WalkConfig.max_depth` limits recursion. `None` = unlimited; `0` = root only; `1` = root + direct children, etc.

### CLI `scan` subcommand

```
adpa scan --path <ROOT> --user <SID|sAMAccountName>
          [--server ... --base-dn ... --bind-dn ... --bind-password ...]
          [--db <FILE>]          # SQLite database for results
          [--max-depth <N>]      # depth limit
          [--output <CSV>]       # optional CSV export
```

Flow:

1. Resolve identity + groups (shared `resolve_identity` helper, also used by `analyze`).
2. Open optional SQLite database via `persistence::Database::open`.
3. Register a `ScanRun` with UUID, start timestamp, target path.
4. `walk_tree` — reads DACL for each path in the subtree.
5. For each `FileSystemObject`: evaluate effective permissions; store in DB; print `  <Rights>  <Path>`.
6. For each walk error: print `  [Error]  <path>: <msg>`; store in DB as `ScanError`.
7. Finish the `ScanRun` (sets `finished_at`).
8. Print summary: path count, error count, duration, DB path and Scan ID.
9. Optional CSV export of all collected `EffectivePermission` results.

### Identity resolution refactor

`resolve_identity(user, server?, ...)` is now a shared `async fn` used by both `analyze` and `scan`, eliminating duplicated AD-connect logic. It returns `ResolvedIdentity { identity, memberships, ad_connected }`.

### Scan-specific options struct

`ScanOptions { db_path, max_depth, output }` groups the scan-specific arguments to keep `run_scan`'s parameter count within clippy's `too_many_arguments` limit.

## Alternatives considered

- **Stream-based walker** (channel / iterator): avoids accumulating all FSOs in memory for huge trees. Deferred — current `Vec<FileSystemObject>` approach is correct for moderate trees and simpler to reason about. Step 12 is not required to handle millions of paths.
- **Parallel walk** (rayon / tokio tasks): meaningful for file servers with slow NTFS paths. Deferred — correctness first, parallelism in a later step when performance is measured.
- **Cancellation**: the walk runs to completion. A cancellation signal (`CancellationToken`) will be added when the GUI progress bar is implemented.

## Consequences

- `adpa scan` provides end-to-end coverage: walk → evaluate → store → optionally export.
- Every scan run is uniquely identified by a UUID and queryable from the database.
- Walk errors are non-fatal and recorded alongside results.
- The `analyze` command is unchanged; `scan` builds on the same core components.
