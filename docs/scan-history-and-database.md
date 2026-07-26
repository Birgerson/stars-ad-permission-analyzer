# Stars — Scan History and Database

Stars persists its scan history in a **SQLite database** so the Delta tab can compare two runs and every run's evidence — including its error list — stays reviewable later.

### Location

```
%APPDATA%\Stars\stars_data.db
```

On a typical Windows Server DC this is:

```
C:\Users\<account>\AppData\Roaming\Stars\stars_data.db
```

If `%APPDATA%` is not set, the application falls back to the directory next to the EXE (only relevant for `cargo run` during development).

### What is stored

| Table | Content |
|---|---|
| `scan_runs` | One row per completed scan: UUID, start time, end time, target path |
| `effective_permissions` | Every evaluated path per run with an identity snapshot, NTFS mask, share mask, effective mask, explanation path, diagnostic markers |
| `scan_errors` | Walk and eval errors per scan (e.g. "Access denied", "Path not found"). Reviewable per run via `adpa runs` / `adpa errors --run-id <ID>` and the Delta tab's ⚠ button (since the persistence review 2026-07-26 — before that this evidence was write-only). |
| `identities` | SID → name/domain/kind/disabled, written by every stored permission. **Note:** since v1.5.16 the identity snapshot is stored per permission row in `effective_permissions` itself — this table is **no longer the source for historical reports** (audit integrity). |
| `group_memberships` | **Legacy, empty in practice.** Its writer (a persistent membership cache) was removed in the persistence review 2026-07-26 (PS-2) because it had no production reader. The table stays — migrations are append-only and existing databases must keep opening cleanly. |

### Properties

- **Created automatically on first start;** migration scripts (schema v1 → current) run idempotently. Since schema v8 both child tables carry an index on `scan_run_id`, so loading or deleting one run no longer scans the whole history.
- **Separate per user profile** — every Windows user has their own history.
- **Survives uninstallation** — by default the uninstaller removes only its install directory; the audit history stays. To get rid of it, delete `%APPDATA%\Stars\` manually, or use the uninstaller's optional component (see [Installation and uninstallation](installation-and-uninstallation.md)).
- **Snapshot-stable:** Historical scan data has been immutable against later identity updates since v1.5.16. If a user gets disabled between two scans, the older scan still shows their state at scan time when reloaded (see schema migration v7).
- **No password, no encryption.** Anyone with access to the user profile can read the data. Protect the profile path itself (NTFS permissions, BitLocker) for sensitive audit data.
- **Inspectable with any SQLite tool** (DB Browser for SQLite, DBeaver, `sqlite3.exe`) — read-only, without Stars running.

### When the database is unreachable

If opening or writing fails (no write permissions, disk full), the scan still runs — Stars does not suppress that. The persistence message appears as an error in the status bar so the finding does not silently disappear.

### Delta comparison

The Delta tab compares two scan runs and reports paths as `Added`, `Removed`, or `Changed`. Since v1.5.16 the `Changed` comparison covers not only the effective mask but also:

- NTFS and share mask composition (same final mask with a different cause)
- `share_status` (e.g. flip from `Applied` to `ReadFailed`)
- `local_group_status` (e.g. flip to `NotAvailable`)
- `unsupported_ace_count`
- Diagnostic markers

The UI names the concrete reasons — e.g. "Changed (NTFS mask + share status)".

Since the persistence review 2026-07-26 the comparison also refuses semantically meaningless pairings instead of producing a plausible-looking nonsense report: two runs with **different targets** are rejected with an error naming both targets, and an unknown run id is an error rather than silently reading as "everything was removed". Rows are keyed by **(identity, path)**, so two identities on the same path are diffed independently.

### Per-run error evidence

Every run's stored error list answers the question "**what could this scan not read?**" — those paths are missing from the run's results, so the list is part of the audit evidence:

- **GUI:** the Delta tab's run list shows the true error count per run and a **⚠ button** that opens the run's error list (path + reason per entry).
- **CLI:** `adpa runs --db <DB>` lists the stored runs with their path/error counts; `adpa errors --db <DB> --run-id <ID>` prints one run's error list. Both are strictly read-only and refuse to *create* a database file that does not exist.
