# ADR 0006 — CSV export

## Status
Accepted

## Context

Step 10 of the development roadmap adds a CSV export so analysis results can be consumed by spreadsheet tools, scripts, and future pipeline stages without depending on the formatted console output.

## Decision

### Dependency

The standard Rust `csv` crate (v1) is used for serialization. It handles quoting, escaping of special characters (commas, quotes, newlines), and BOM-free UTF-8 output. Manual CSV generation would be error-prone for paths and explanation text that may contain commas.

### Columns (13 fixed columns)

| Column | Source |
|---|---|
| `path` | `EffectivePermission.path` |
| `user_sid` | `identity.sid` |
| `user_name` | `identity.name` (empty string if None) |
| `user_domain` | `identity.domain` (empty string if None) |
| `identity_kind` | `identity.kind` (Debug representation) |
| `disabled` | `identity.disabled` |
| `ntfs_mask_hex` | `ntfs_mask` as `0xXXXXXXXX` |
| `ntfs_rights` | `NormalizedRights::display_name()` |
| `share_mask_hex` | `share_mask` as `0xXXXXXXXX` or `(none)` |
| `share_rights` | `NormalizedRights::display_name()` or `(none)` |
| `effective_mask_hex` | `effective_mask` as `0xXXXXXXXX` |
| `effective_rights` | `NormalizedRights::display_name()` |
| `explanation` | `path_explanation.steps` joined with ` | ` |

Both the raw hex mask and the human-readable label are exported so downstream tools can filter by exact bit mask or by readable label without recomputing.

### Public API

```rust
// Writes directly to any writer — suitable for tests.
pub fn write_csv<W: Write>(writer: W, permissions: &[EffectivePermission]) -> csv::Result<()>

// Implements the Exporter trait from adpa_core.
pub struct CsvExporter;
impl Exporter for CsvExporter { ... }
```

`write_csv` takes any `Write` implementation, enabling in-memory testing without temporary files. `CsvExporter` wraps it and maps `ExportTarget::File` to a `std::fs::File`.

### CLI integration

The `analyze` subcommand gains an optional `--output <PATH>` (`-o`) flag. When given, the single `EffectivePermission` is wrapped in an `AnalysisResult` and passed to `CsvExporter`. The console report is always printed first; the CSV is written afterwards.

## Alternatives considered

- **serde + csv feature**: Deriving `Serialize` on the model structs would let `csv::Writer` serialize automatically. Rejected because the desired CSV shape (hex + label columns, flattened identity fields, joined explanation) differs from the model structure and would require custom serializers more complex than the explicit `record_for()` function.
- **JSON-only export**: Deferred; `JsonExporter` stub is in place for step 17 (HTML report).

## Consequences

- Results can be imported into Excel, Power BI, or custom scripts without parsing the terminal output.
- The `write_csv` function makes the exporter unit-testable without touching the file system.
- The `exporter` crate now depends on `permission_engine` for `NormalizedRights`; this dependency is deliberate — the exporter must translate raw masks to labels.
- Future exporters (JSON, HTML) follow the same `Exporter` trait pattern.
