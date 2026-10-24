# ADR 0082 — Modular GUI: design tokens, components, one module per tab

## Status
Accepted (2026-10-24). Carried out in steps; the table under
"Implementation" says which are done.

## Context

The GUI grew tab by tab inside one Rust file. At v1.17.0:

- `crates/gui/src/main.rs` had 5,431 lines; 3,015 of them were the whole
  UI inside one `slint::slint! { … }` macro: a single `MainWindow`
  component with **201 properties and 32 callbacks** for all eight tabs.
  The "Identity resolution" block was written out three times (Analyze,
  Groups, Scan Tree).
- `crates/gui/src/worker.rs` (4,280 lines) carried the analysis pipeline,
  and part of it was a **copy of the CLI**: `collect_local_groups_on` (155
  lines), `uac_filtered_token_groups`, `collect_local_group_sids_for_path`
  and `add_local_groups_for_membership_view` were the same code in both;
  share status, input validation and identity resolution the same logic
  behind different signatures. A fix had to be made twice, or CLI and GUI
  would answer differently.

AGENTS.md asks for small modules with clear boundaries, no permission
logic in the GUI and no duplicated group logic — and the design itself
should be changeable in one place.

## Decision

1. **Layers of the UI**, each in its own `.slint` files under
   `crates/gui/ui/`:
   - `theme/` — design tokens only: colours (light and dark), type sizes,
     spacing, radii. A colour or a spacing changes in one place.
   - `components/` — reusable building blocks (buttons, section, form row,
     help tip, connection fields, status line, result lists). They take
     every colour and size from the tokens.
   - `tabs/` — one file per tab, composed of components; no colour or size
     of its own.
   - `app.slint` — the window only: header, tab bar, the tabs.
2. **State per tab** in a Slint `global` instead of properties on the
   window; the Rust side of each tab is its own module under
   `crates/gui/src/tabs/`, and `main.rs` only starts and wires.
3. **One analysis pipeline** for CLI and GUI in a library crate, so the
   duplicated code above exists once.
4. **The macro, not `slint-build`.** `slint::slint! { export * from
   "../ui/app.slint"; }` compiles the files and rebuilds when one of them
   changes (checked). `slint-build` would do the same but force-enables
   compiler features this UI does not use (software-renderer resource
   embedding, translation bundling) and pulls about 60 extra build-time
   crates (image codecs, rayon, rspolib).
5. **Nothing visible changes while the structure changes.** Every step is
   checked against screenshots of all eight tabs taken with v1.17.0
   (light, dark, empty and with an analysis result), compared pixel by
   pixel; two runs of the same build are pixel-identical, so any
   difference is real. Design changes come after the structure, as their
   own steps.
6. The language gate (`scripts/check-language.py`) covers `.slint` (and
   the website's `.html`): the UI texts left the `.rs` files and would
   otherwise have dropped out of the check unnoticed. A German probe line
   in `app.slint` fails the gate (checked).

## Implementation

| Step | Content | State |
| --- | --- | --- |
| 1 | UI moved unchanged from the macro into `ui/app.slint`; gate covers `.slint` | done — 18 of 18 screenshots identical |
| 2 | `theme/theme.slint` (tokens), `components/` (buttons, header, help tip, trusted-domain fields), `models.slint` (view models) split out of `app.slint`; `app.slint` re-exports what Rust uses | done — 18 of 18 identical |
| 3 | Each tab in `tabs/<tab>.slint`: its state as a global (`AnalyzeState`, `GraphState`, `GroupsState`, `ScanState`, `DeltaState`, `TrustsState`, `SharesState`, `InfoState`; prefixes dropped, `a-status` → `AnalyzeState.status`) and its layout as a component; `AppState` holds the version that header and Info tab show. `MainWindow` keeps no property; `app.slint` shrinks from 3,011 to 212 lines | done — 18 of 18 identical; one real action per tab identical as well |

Step 3 also introduced a functional check: with a fresh, empty scan history
(APPDATA redirected), one action per tab — analysis, a click into the graph,
saving it, zoom, "Show all groups", group resolution, a tree scan, loading
the history, reading trusts without LDAP (explicit error), listing the
shares of this machine, the update check — run with v1.17.0 and with the
new build. Results identical apart from what differs by nature (the time of
a scan run, the blinking text cursor, the scratch folder's name in a
status line); the saved SVG is byte-identical. One mapping error was caught
on the way: the Analyze tab's old name `resolve-name-clicked` equalled the
Scan Tree tab's new one, and the Scan handler was routed twice — the build
failed on it, the rename now skips accessors already routed to a global.

Screenshot comparison notes: the Windows title bar (top 31 rows) is drawn
by Windows, not Stars — its text colour follows whether the window is in
the foreground — and is left out of the comparison. A widget under the
physical mouse pointer shows its hover state; such a difference moves
between runs and is repeated, a real change is the same in every run.

## Consequences

- Editing the UI no longer means editing a 5,000-line Rust file; a tab, a
  component or a token has its own file.
- The Rust API of the UI (`MainWindow`, the view-model structs, `Theme`)
  stays the same until step 2 moves tab state into globals.
