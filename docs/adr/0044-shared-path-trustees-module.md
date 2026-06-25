# ADR 0044 — Path-centric trustees as a shared module for GUI and CLI

**Status:** Accepted
**Date:** 2026-06-06

## Context

Stars answers two audit questions per path:

1. **Identity-related:** "What effective permission does this user have on
   this path?" — answered by `EffectivePermission` from the permission
   engine.
2. **Path-related:** "Who is even on the ACL of this path — and on the
   share DACL of the surrounding share?" — answered by `PathTrustees` with
   `Vec<PathTrustee>`.

The second question is *identity-free*: it is the raw enumeration of all
trustees per path, not the computational aggregation for a specific
identity. It is just as important as the first, because otherwise an audit
tool cannot answer the question "who can actually do anything here at all?"
— and that is the question auditors most often ask first.

Until v1.5.13, this list was built **only in the GUI**. The helper functions
`read_share_overlay`, `build_path_trustees`, and
`build_path_trustees_with_share` lay private in `crates/gui/src/worker.rs`.
The CLI had no access to them and always sent the exporters (HTML, JSON) an
`AnalysisResult` with empty `path_trustees`. Consequence for CLI audits:

- `adpa analyze --output report.json --path X --user alice` → JSON without
  `path_trustees`.
- `adpa scan --output report.json --path X --user alice` → JSON without
  `path_trustees`.
- HTML reports from the CLI: the technical render logic for the trustee
  table was present in the `HtmlExporter`, but because of the empty input
  field it was never triggered.

The second audit question was thus effectively *not answered* for CLI
audits — a silently-wrong state, because the report *looked* as if it were
complete.

Round-9 review finding 1 classified this as Medium. The GUI was correct, but
the data was in the wrong layer. Recommendation: extract into a non-UI
layer, CLI and GUI share it.

## Decision

The trustee-build logic moves into a new module
**`crates/exporter/src/trustees.rs`**. The choice of crate follows three
criteria:

1. **`exporter` is the natural semantic home.** Trustees are report data,
   not engine logic. They are serialized into a report format — and that is
   exactly what `exporter` does. A separate `reporting` crate would be
   redundant.
2. **`exporter` has no UI dependency.** Thus GUI and CLI are equal
   consumers. Neither does the GUI have to load CLI code nor vice versa.
3. **`exporter` has no upward engine dependency.** `exporter` may reach into
   `permission_engine` and `share_scanner`, but not into `cli` or `gui`.
   That fits the layering direction of the workspace (ADR 0023 — crate
   layering).

### Interface

```rust
pub struct ShareTrusteeOverlay {
    pub trustees: Vec<PathTrustee>,
}

pub fn read_share_overlay(server: &str, share_name: &str) -> ShareTrusteeOverlay;

pub fn build_path_trustees(
    fso: &FileSystemObject,
    smb_server: Option<&str>,
    share_name: Option<&str>,
) -> Vec<PathTrustee>;

pub fn build_path_trustees_with_share(
    fso: &FileSystemObject,
    share_overlay: Option<&ShareTrusteeOverlay>,
) -> Vec<PathTrustee>;
```

The two build functions differ only in whether the caller has read the
share overlay beforehand or whether the function should read it fresh per
call. The pre-read path is the performance variant for scans (one DACL read
per share instead of per path).

### Cargo impact

`crates/exporter/Cargo.toml` gets two new dependencies:

```toml
share_scanner = { path = "../share_scanner" }

[target.'cfg(windows)'.dependencies]
ad_resolver = { path = "../ad_resolver" }
```

`ad_resolver` is `cfg(windows)`-only, because LSA exists only on Windows. On
non-Windows platforms `display_name` simply stays `None` — the build
function still works, only the readability column is missing.

### GUI adaptation

The GUI-private implementation is removed without replacement.
`crates/gui/src/worker.rs` re-exports the symbols:

```rust
pub use exporter::{
    build_path_trustees,
    build_path_trustees_with_share,
    read_share_overlay,
    ShareTrusteeOverlay,
};
```

This keeps all existing GUI call sites and 11 GUI tests runnable unchanged.
The GUI-specific display formatting (`trustee_row_for_display`) stays in the
GUI, because it fills Slint render types.

### CLI adaptation

`crates/cli/src/main.rs::run_analyze` calls the simple form:

```rust
let trustees = exporter::build_path_trustees(
    &fso,
    smb_server.as_deref(),
    share_name.as_deref(),
);
```

and stores the entry in `AnalysisResult.path_trustees`.

`crates/cli/src/main.rs::run_scan` reads **once** before the path loop:

```rust
#[cfg(windows)]
let scan_share_overlay = match (smb_server, share_name) {
    (Some(server), Some(name)) if !server.is_empty() && !name.is_empty() =>
        Some(exporter::read_share_overlay(server, name)),
    _ => None,
};
```

and passes the overlay to every path call. This makes the share-DACL read
load constant per scan instead of linear per path — identical behavior to
the GUI scan path since ADR 0038.

## Consequences

### Positive

- **Format symmetry achieved:** HTML and JSON reports from CLI and GUI now
  have the same data basis. The CHANGELOG claim of v1.5.13 ("HTML and JSON
  have the same audit information") now also holds for the CLI as of
  v1.5.14.
- **One data source, two consumers:** a future bugfix in the build
  functions automatically takes effect in GUI and CLI. Previously, every fix
  would have had to be done twice — and that is exactly what does not happen
  in practice.
- **Architecture consistency:** the layering direction of the workspace
  stays intact (`exporter` → `share_scanner`, `core`, no jump into
  `cli`/`gui`).
- **Tests are platform-independent:** the three new unit tests in the module
  (`ntfs_only_yields_all_ntfs_trustees`, `null_dacl_yields_explicit_pseudo_row`,
  `share_overlay_is_appended_to_ntfs_trustees`) also pass on CI Linux,
  because they touch no Windows API.

### Negative / trade-offs

- `crates/exporter` now has a dependency on `share_scanner` — previously it
  was a pure "data → format" crate. The extension is conceptually justified
  (trustees are part of the report), but it slightly broadens the crate's
  responsibility.
- Callers who want *only* the render part of `exporter` now pull
  `share_scanner` in as a transitive dependency. In practice this affects
  only the workspace itself — no external consumers.
- `cfg(windows)` in two places: once for `ad_resolver` in Cargo.toml, once
  in `trustees.rs` for LSA resolution. That is the norm in this workspace.

### Relationship to other ADRs

- **ADR 0036** (unified principal resolution pipeline): shares the principle
  "one data source, consumed by both consumers".
- **ADR 0038** (share trustees in the scan path): introduced the
  share-overlay mechanism — ADR 0044 now implements it identically on the
  CLI side.
- **ADR 0023** (workspace layering): justifies the choice of `exporter` as
  the home.

### Tests

Three new tests in `crates/exporter/src/trustees.rs`:

| Test | What it guarantees |
|---|---|
| `ntfs_only_yields_all_ntfs_trustees` | Without a share overlay, all NTFS ACEs appear in the `Ntfs` category, no `Share` entry is constructed. |
| `null_dacl_yields_explicit_pseudo_row` | A NULL DACL yields a visible "Everyone (NULL DACL)" pseudo-row instead of a silent skip. |
| `share_overlay_is_appended_to_ntfs_trustees` | With a share overlay, NTFS and share entries appear separately visible, in the order NTFS → Share. |

Plus 11 existing GUI tests keep running unchanged (verifying that the
re-export works), plus the Round-8 follow-up review tests for
`JsonExporter`, `CsvExporter`, `HtmlExporter` from v1.5.13.
