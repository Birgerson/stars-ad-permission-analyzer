# Stars — Scan History and Database

Stars persists its scan history in a **SQLite database** so the Delta tab can compare two runs and identity resolutions are cached across sessions.

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
| `scan_errors` | Walk and eval errors per scan (e.g. "Access denied", "Path not found") |
| `identities` | Cache for identity resolutions (SID → name, domain, kind, disabled status). **Note:** since v1.5.16 the identity snapshot is stored per permission row in `effective_permissions` itself — this table is now only a cache for live lookups, **no longer the source for historical reports** (audit integrity). |
| `group_memberships` | Resolution cache for recursive group memberships |

### Properties

- **Created automatically on first start;** migration scripts (schema v1 → current) run idempotently.
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
