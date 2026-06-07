# ADR 0046 — `PathTrusteeEntry` enum: separate ACE and diagnostic in the type system

**Status:** Accepted
**Date:** 2026-06-06

## Context

Stars answers "who is even on the DACL?" for every path through a list `PathTrustees.trustees`. Before this ADR the list only contained `PathTrustee` records — i.e. flat ACE descriptions with `sid`, `kind` (Allow/Deny), `mask`, `inherited`, `inheritance_flags`, `propagation_flags`, `category` (NTFS/Share).

Three special states were "smuggled along" in this structure:

1. **NTFS NULL DACL** — the path technically has no DACL, which in the Windows model means "full access for everyone". Previously a pseudo-`PathTrustee` with `sid: "S-1-1-0"`, `display_name: "Everyone (NULL DACL — no access restriction)"`, `kind: Allow`, `mask: 0x001F01FF`.
2. **Share NULL DACL** — the analogous case on the SMB layer. Previously a pseudo-`PathTrustee` with `sid: "S-1-1-0"`, `display_name: "Everyone (Share NULL DACL — no SMB restriction)"`, `kind: Allow`, `mask: 0x001F01FF`.
3. **Share DACL read failure** — the share DACL could not be read (access denied, timeout, parsing failed). Previously a pseudo-`PathTrustee` with `sid: ""`, `display_name: "Share DACL not readable: <error text>"`, `kind: Allow`, `mask: 0`.

Review round 10 finding 4 classified the modelling as **semantically blurry**. Three concrete problems:

- **JSON consumers could not tell diagnostics from ACEs.** An audit tool counting `path_trustees[].kind == "Allow"` on all entries would interpret read errors and NULL-DACL hints as real Allow ACEs. That could distort risk analyses.
- **An empty SID (`""`) is not a valid identity identifier.** Strict-validating pipelines might drop the entry — and with it the diagnostic hint, silently.
- **A mask of `0`** in the error case looks like "Allow with no rights at all". That too is model abuse: the entry is not an ACE but a meta hint.

The GUI rendered this correctly visually (using `display_name` as an explanation text), but that was a convention, not the type system. A second render code path or a different JSON consumer could have misinterpreted the model.

## Decision

We replace `PathTrustees.trustees: Vec<PathTrustee>` with `PathTrustees.trustees: Vec<PathTrusteeEntry>`, where `PathTrusteeEntry` is a **typed enum**:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "entry_kind", rename_all = "snake_case")]
pub enum PathTrusteeEntry {
    Ace(PathTrustee),
    Diagnostic {
        category: TrusteeCategory,
        message: String,
    },
}
```

Consequence:

- **Real ACEs** are carried as `PathTrusteeEntry::Ace(PathTrustee)` — the `PathTrustee` struct itself stays unchanged, all its fields (`sid`, `kind`, `mask`, ...) semantically carry their real meaning.
- **Diagnostic hints** are carried as `PathTrusteeEntry::Diagnostic { category, message }` — no SID, no mask, no Allow/Deny label. Only the technically relevant fields: which layer (NTFS or share) the hint occurs on, and its human-readable explanation.

### Why `entry_kind` and not `kind` as the tag?

Internally-tagged serde enums use one JSON field as the discriminator. The natural word would be `"kind"`. **But:** `PathTrustee` already carries a field `pub kind: AceKind` (Allow/Deny). A tag named `"kind"` would silently overwrite this field in the JSON output — serde does not prevent that at compile time, it just produces misleading JSON.

We therefore deliberately choose `tag = "entry_kind"`. The JSON now clearly carries:

- `entry_kind: "ace"` or `entry_kind: "diagnostic"` — the *variant* of the list.
- `kind: "Allow"` or `kind: "Deny"` — the *ACE type* (only present in the Ace variant).

### Concrete JSON example (schema v3)

```json
{
  "version": 3,
  "path_trustees": [
    {
      "path": "C:\\Audit",
      "trustees": [
        {
          "entry_kind": "ace",
          "sid": "S-1-5-32-544",
          "display_name": "BUILTIN\\Administrators",
          "kind": "Allow",
          "mask": 2032127,
          "inherited": true,
          "inheritance_flags": 0,
          "propagation_flags": 0,
          "category": "Ntfs"
        },
        {
          "entry_kind": "diagnostic",
          "category": "Share",
          "message": "share DACL not readable: timeout"
        }
      ]
    }
  ]
}
```

Before v3 the diagnostic entry would have looked like a normal ACE: `"kind": "Allow", "sid": "", "mask": 0`. Now it is structurally a different object with a different field set — not confusable formally.

### Schema version bump

`JSON_SCHEMA_VERSION` is raised from 2 to 3. That is a **breaking change** for JSON consumers — old parsers that read `path_trustees[].kind == "Allow"` directly need to update to:

```pseudocode
if entry.entry_kind == "ace":
    use entry.kind, entry.sid, entry.mask, ...
elif entry.entry_kind == "diagnostic":
    use entry.message, entry.category   # NOT an ACE
```

We accept the break because:

- JSON schema versioning exists precisely for cases like this.
- The alternative (an optional `synthetic_reason` field next to the pseudo ACE) would be more compatible but semantically unclean — the "flat" entry would *still* look like an ACE, just with an extra marker. That is a variant of the original bug, not its resolution.
- Stars is at v1.5.x, not 1.0 — we are still in a phase where schema breaks are legitimate as long as they are documented and versioned.

### Render adjustments

- **HTML** (`exporter::html::write_trustees_table`): diagnostic rows get a yellowish background (`#fff7d6`), a warning symbol (⚠), italic typography, and no Allow/Deny label. ACEs are unchanged.
- **GUI Slint renderer** (`gui::worker::trustee_row_for_display`): diagnostic entries render as a row with `kind: "Diagnostic"` and em-dash placeholders in the ACE-specific columns (rights/mask/source/application); the `display_name` carries the explanation text with the warning glyph.
- **JSON** (`exporter::json`): as shown above — the `entry_kind` tag makes the variant unambiguous.
- **CSV** (`exporter::csv`): unchanged because CSV only exports the identity-bound `EffectivePermission` block, not `path_trustees`.

### Tests

Four new / updated tests verify the invariants:

| Test | What it guarantees |
|---|---|
| `null_dacl_yields_typed_diagnostic_not_synthetic_ace` | NULL DACL is `Diagnostic`, **not** `Ace`. Guards against regression to the original model. |
| `diagnostic_and_ace_have_distinct_json_tags` | `entry_kind` is distinguishable in the JSON output: `"ace"` vs `"diagnostic"`. |
| `export_includes_path_trustees_with_typed_diagnostic` | End-to-end: `JsonExporter` writes schema v3 with a mixed Ace+Diagnostic list. Plus: the diagnostic entry has **no** `sid` field. |
| `ntfs_only_yields_all_ntfs_trustees`, `share_overlay_is_appended_to_ntfs_trustees` | Existing tests adapted to the enum — verify that the GUI and CLI paths populate the categories correctly. |

## Consequences

### Positive

- **JSON consumers can no longer accidentally interpret diagnostics as ACEs.** The audit-pipeline use case is robust against the old model abuse.
- **Type system instead of convention.** Whoever holds a `PathTrusteeEntry` in code *must* match — the compiler enforces that both variants are handled. Previously you could read a `PathTrustee` and forget that `sid == ""` and `mask == 0` might be a diagnostic hint.
- **Clean render separation.** HTML and GUI renderers derive their rendering from the variant, not from string conventions in `display_name`.
- **Extensible.** When future diagnostic categories appear (for example "canonical ordering violated" or "ACE type unsupported"), they can be added as an extension of the `Diagnostic` variant or as a new enum variant without repurposing old fields.

### Negative / trade-offs

- **JSON schema break from 2 to 3.** An external consumer has to update its parsing. We document the break in the `JSON_SCHEMA_VERSION` docstring and in the CHANGELOG.
- **More match arms in render code.** HTML and GUI now have explicit `match` blocks instead of a linear iteration. That is more code, but the additional code is precisely the type-safety win.
- **The tag name `entry_kind`** is not a sweet word — but it is the only correct way to avoid the collision with the ACE `kind` field. The rationale lives in the model comment and in this ADR.

### Relationship to other ADRs

- **ADR 0044** (path-centric trustees as a shared module) — introduced the shared `exporter::trustees` module in which the current migration lives.
- **ADR 0038** (share trustees in the scan path) — describes how the share overlay is read once per share. Diagnostic hints for read failures are now carried in a typed form.
