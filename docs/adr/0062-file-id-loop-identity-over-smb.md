# ADR 0062 — Directory identity by volume serial + file ID for scans over SMB

## Status
Accepted (2026-10-10). Refines ADR 0058 (cycle vs. duplicate target);
closes known limitation L14 (lab finding FS3-1).

## Context

ADR 0058 detects reparse-point cycles and duplicate targets by comparing a
directory's **canonical path**. Reparse points (and the scan root) get it
from `std::fs::canonicalize`, i.e. `GetFinalPathNameByHandleW`; plain
directories derive it from their parent.

The corp.test lab run (2026-10-07) found a junction loop on an SMB share
followed about 64 levels deep. The investigation (2026-10-10, against a
Windows Server 2022 DC) established the cause precisely:

- Opening `\\server\share\Loop\back` (a junction to `Loop`) and asking for
  its final path returns `\\?\UNC\server\share\Loop` — **resolved** — as long
  as the client has not enumerated `Loop`.
- **After the client has listed the parent directory** (which the walker
  always does before it looks at a child), the same call returns
  `\\?\UNC\server\share\Loop\back` — the path the junction was **opened
  through**. The SMB client answers from its directory cache. Every level
  then looks new, and the walk only stops at Windows' limit of 63 reparse
  traversals, with a misleading "target could not be resolved" error.
- Whether the cache is warm is a matter of timing, which is why the lab
  result was non-deterministic: it failed after the DC booted or its SMB
  service restarted and passed on later runs. Restarting `LanmanServer`
  reproduces the failure reliably.
- The **file ID** (`GetFileInformationByHandleEx(FileIdInfo)`) of the opened
  directory was identical in every state, before and after the listing, for
  all of `Loop`, `Loop\back` and `Loop\back\back`. The same holds for a
  junction whose target is outside the share: the path cannot be resolved
  in the share's namespace, the file ID still matches the target.
- `GetFileInformationByHandle` (the older call) reports a volume serial of
  **0** over SMB; `FILE_ID_INFO` reports the real 64-bit serial.
- Over loopback (`\\localhost\C$`) the final path stayed resolved, so the
  defect cannot be reproduced on a single machine.

## Decision

1. When the scan root is a UNC path, the walker keys the loop detector by
   **`fid:<volume serial>:<128-bit file ID>`** from `FILE_ID_INFO`, obtained
   by opening each directory (reparse points followed, `FILE_READ_ATTRIBUTES`,
   backup semantics). New module `fs_scanner::file_id`.
2. If the server provides no usable identity (open or query fails, or a
   zero serial / zero ID as some non-Windows servers report), the walker
   falls back to the canonical path for that directory — the previous
   behaviour.
3. Local scans are unchanged: they keep the path identity, which is correct
   locally and needs no extra system call per directory.
4. The cycle diagnostic now names the **ancestor's namespace path** (the
   chain stores it next to the identity) instead of the link's canonical
   path, which over SMB can be the link's own path.

## Consequences

- Over SMB, cycles and duplicate targets are now detected deterministically.
  Lab acceptance in the reproduced failure state: the loop is stopped after
  3 paths in 3 of 3 runs (before: 129); the share holding it scans 90 paths
  instead of 216; scanning the parent share additionally reports a junction
  into another subtree as a duplicate target, which previously depended on
  the cache state too.
- Cost: one extra open + query + close per **directory** on UNC scans (files
  are not affected). In the lab, 663 objects over SMB took about 2 s.
- Mixed identities are possible within one UNC scan when a server returns a
  usable ID for some directories and not for others; a cycle that crosses
  such a boundary falls back to path comparison and to the old limitation.
- A share that exposes several file systems with independent file IDs but a
  shared, non-zero volume serial could produce a false match; not observed,
  and Windows servers report distinct serials per volume.
- Tests: `file_id` unit tests (identity of a directory and of a junction to
  it, distinct directories, missing path, zero-value rejection) and walker
  tests for the key selection and for a cycle that only the file identity
  reveals. The SMB failure itself needs a remote server and is covered by
  the lab acceptance run recorded above.

## Addendum (2026-10-18): the duplicate-target diagnostic over SMB

Decision 4 fixed the cycle diagnostic, not the duplicate-target one. That
message still ended with "Target: <canonical path>". Regression runs (37
identities, each a scan of the same share on DC-01, which holds a junction
to a folder scanned before it) showed it naming the link itself in 24 to 26
of 37 runs and the real target in the others — in every version since
v1.15.0. The cause goes one step further than the resolved path: over SMB
**the reparse attribute of the junction itself is not reliable**. A first
version of this fix worded the message by that attribute and showed it
missing (`GetFileAttributesW` without `FILE_ATTRIBUTE_REPARSE_POINT`) in 25
of 37 runs; which runs varies from one series to the next. Without the
attribute the walker derives the junction's canonical path from its
parent — the link's own path; with it, the resolved path can still be the
link's own (the cache effect above).

The detection was right every time: the file identity matched, the subtree
was enumerated once, the CSV of all 37 runs identical. Only the message
claimed a target it did not know. Now:

- **Over SMB** the message claims only what the match proves: "Directory
  already enumerated in this scan under '<first route>' — this path leads to
  the same directory (same volume serial and file ID) …" (or "same resolved
  path" for a server without file IDs). It names no target and does not say
  which route is the reparse point.
- **Locally**, where the attribute and the resolved path are reliable, a
  link keeps "Target: <resolved path>"; a plain directory that a link led to
  first is no longer called a link object.
- Every route is shown in its display form (no `\\?\` prefix).
  `validation::path::strip_long_path_prefix` now matches `\\?\UNC\` in any
  case, as Windows does — hardening only: no caller passes the lowercase
  canonical form (`\\?\unc\…`, which it would have cut to `unc\…`).

The reparse attribute is used nowhere else in a result: `FileSystemObject`
is neither exported nor stored, and the loop identity over SMB does not
depend on it. Lab after the fix: 37 of 37 runs with one and the same
message, CSV identical to v1.16.1 (25,493 rows).
