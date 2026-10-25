# ADR 0086 — CLI scan results are streamed to the database and the CSV export

## Status
Accepted (2026-10-25). New known limitation L19 for the GUI's Scan Tree.

## Context

The lab got a mass-test tree on 2026-10-24 on FS-01 (Server 2025, data disk `T:`):

- **Size:** `MassData` holds 1,500,560 files in 11,139 folders: 20 departments × 50 projects × 10 folders × 150 files.
- **ACLs:** inheritance breaks with group ACEs, explicit Modify ACEs, Deny Write ACEs.
- **Edge cases:** long paths, Unicode names, credential-like file names.

A CLI scan of one department (75,586 paths, account `u00030` with about 70 groups) over SMB measured:

- **Throughput:** 160 s, about 470 paths per second, 0 errors.
- **Memory:** peak commit **1,922 MB**, peak working set 2,001 MB, read from the OS peak counters of the process. That is about 26 KB per result.
- **Output size:** CSV 908 MB, database 923 MB. Most of a row is the explanation path, about 11 KB, mostly the account's membership steps.

The cause: `run_scan` kept every result (`Vec<EffectivePermission>`) and every path's trustee table until the end. Only then did it write the database in one transaction, run the risk rules and write the export. Memory grows linearly with the tree, about 40 GB for the 1.5 million files. A 16 GB machine fails at about half a million objects. The project rules say otherwise: large environments are the standard case, results are streamed or stored incrementally, and an export must not hold the whole result set in memory. The export target was also checked only after the scan, so a scan could run for 45 minutes and then fail on an existing export file.

## Decision

1. **Database: one transaction, written while scanning.** `ScanStore::begin_scan` opens the transaction and inserts the run row. `ScanWriter::add_permission` and `add_error` insert row by row, and `commit` sets the finish time and commits.
   - A writer dropped without `commit` (an error, an early return) rolls back. The history is never silently partial, exactly as with `persist_scan_atomic`.
   - `persist_scan_atomic` is now this writer over a slice.
2. **CSV: row by row into `<target>.partial`, renamed at the end.** The format is unchanged, because the same header and record function are used (`CsvRowWriter`).
   - `CsvFileWriter` checks the overwrite policy at the start.
   - If the scan fails, the partial file is removed, so a half-written export can never be taken for a complete one.
   - A cancelled scan (Ctrl-C) finishes normally: its rows are in the file, and the run carries "Scan cancelled by user — results are partial", as before.
3. **Risk rules: result by result.** `RuleRegistry::accumulator` evaluates every rule for each result. The result is moved through the rule context, not copied. The findings come out in exactly the order of `evaluate_all` (rule by rule, results in walk order). Every rule evaluates each result on its own; none looks across results.
4. **The export target is checked before the scan,** both the path validation and the overwrite policy.
5. **JSON and HTML** still need every result and the trustee tables at the end. Only those formats keep them. The handbook recommends CSV or the database for large trees.

## Consequences

Measured, old (main 1ca851b) against this change, release builds, the same department, over SMB:

| | old | streaming |
| --- | --- | --- |
| peak commit / working set | 1,922 MB / 2,001 MB | **14 MB / 29 MB** |
| scan time | 160 s | 125 s |
| CSV | 907.9 MB | byte-identical |
| database (every column but the run id) | 75,586 rows | identical (digest) |
| console output | — | identical except the export path |
| risk findings | 11,634 | 11,634 |

- **Real Ctrl-C** after 40 s: 15,795 rows, in the database and in the CSV alike. The run carries the cancel error; no `.partial` file remains.
- **The whole tree** (1,500,560 files): see verification Block U.
- **Not covered (L19):** the GUI's Scan Tree still keeps the walk (`walk_tree`) and every result for its list, its Delta and its history. Its list is not virtualized.
