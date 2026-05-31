# ADR 0007 — SQLite-Cache und Scan-Historie

## Status
Accepted

## Kontext / Context

Step 11 adds a local SQLite database with two purposes:
1. **Identity cache** — avoids repeated AD queries for the same SID across scans.
2. **Scan history** — stores every analysis run with its results so they can be reviewed later
   without re-running the analysis.

## Entscheidung / Decision

### Schema (migration v1)

Five tables, versioned via `PRAGMA user_version`:

| Table | Purpose |
|---|---|
| `scan_runs` | One row per analysis run; UUID PK, RFC3339 timestamps, target path |
| `scan_errors` | Errors encountered during a scan run |
| `identities` | SID → name / domain / kind / disabled (cache) |
| `group_memberships` | Member-SID + group-SID + direct flag (cache) |
| `effective_permissions` | Result rows per scan run; explanation stored as JSON array |

### Migration system

`migrations::run_migrations(conn)` reads `PRAGMA user_version`, then applies any migration whose
version number is higher. Each migration is wrapped in a `BEGIN … COMMIT` and updates
`user_version` atomically within the same transaction.

Currently one migration exists (`v1`). Future columns or tables are added as `v2`, `v3`, etc.
without touching previous migration SQL.

### Public API (`Database` struct)

```rust
Database::open(path)          // production use — opens/creates file
Database::open_in_memory()    // tests only

db.scan_store()       -> ScanStore<'_>
db.identity_cache()   -> IdentityCache<'_>
```

`ScanStore` and `IdentityCache` hold a `&Connection` (lifetime-bound to the `Database`).
`rusqlite::Connection` uses interior mutability so all methods take `&self`.

### IdentityCache

- `upsert(identity)` — INSERT OR UPDATE by SID
- `lookup(sid)` → `Option<Identity>`
- `upsert_memberships(memberships)` — batch INSERT OR UPDATE
- `lookup_memberships(sid)` → `Vec<GroupMembership>`

### ScanStore

- `insert_scan_run(run)` — records a new run
- `finish_scan_run(id, timestamp)` — updates finished_at
- `insert_permission(scan_run_id, perm)` — stores permission + upserts identity
- `insert_error(scan_run_id, error)` — records a scan error
- `list_scan_runs()` → `Vec<ScanRun>` (newest first)
- `get_permissions(scan_run_id)` → `Vec<EffectivePermission>` (JOIN with identities)

### Explanation path storage

`path_explanation.steps: Vec<String>` is serialized to a JSON array (`serde_json`) and stored in a
single TEXT column. This keeps the schema simple and avoids a many-to-one join for a field that is
always read as a unit.

## Alternativen erwogen / Alternatives considered

- **Separate explanation table**: normalized but requires a join for every permission read.
  The JSON column approach is simpler and the explanation is always read with the permission.
- **`Arc<Mutex<Connection>>`**: deferred. The current synchronous single-connection design is
  correct for CLI use. Multi-threaded scanning will wrap in `Mutex` when needed.
- **Diesel / SeaORM**: ORM overhead not justified for a small fixed schema. Raw `rusqlite` keeps
  the crate dependency minimal and the SQL explicit.

## Konsequenzen / Consequences

- AD queries for previously seen SIDs can be skipped if the cache is warm.
- Past analysis results are queryable without re-scanning.
- Schema evolution is handled by appending migrations — no destructive changes to existing tables.
- All tests use `Database::open_in_memory()` — no file system side-effects.
