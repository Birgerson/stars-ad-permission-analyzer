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
| 4 | Rust side per tab: `src/tabs/<tab>.rs` wires its tab's callbacks (`wire`) and applies the worker's answers (`handle_*`), with the tab's own bookkeeping (scan rows, delta selection, the Analyze path, the graph's result); `identity_input.rs` holds what Analyze, Groups and Scan Tree share (identity cache, suggestion models, LSA lookup); `view_models.rs` the one trustee-row builder that Analyze and Scan Tree had twice. `main.rs` (2,517 → 246 lines) creates the window, starts the worker, lets each tab wire itself and routes each worker event to its tab | done — see below |
| 5a | New library crate `analysis`: the account's local groups on the target (`LocalGroupResolution`, `collect_local_group_sids_for_path`, `collect_local_groups_on`, `uac_filtered_token_groups`, `add_local_groups_for_membership_view`) and the share-mask adapter (`resolve_share_status`) — CLI and GUI each had a copy, now both call the one: CLI and GUI lose 601 lines, the one copy with its tests has 423 | done — see below |
| 5b | The rest of decision 3: connection-input validation (`validate_connection_inputs` — the GUI's covers Global Catalog, signed LDAP and the trusted-domain connection, the CLI's does not, so the two are not interchangeable yet) and identity resolution (`resolve_identity` / `resolve_identity_sids`) | open |
| 6 | `worker.rs` split by task | open |

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

Step 4 was checked at three levels. The code: a script compared every
function and every callback closure of the old `main.rs` with its new place,
comments and whitespace ignored — all 30 callbacks and all functions are the
same code, apart from the shared trustee-row builder (field for field the
two former copies) and the event routing to the new module paths. The
screen: 18 of 18 screenshots identical, and the functional check gives the
same results with a byte-identical saved SVG. And the one path whose wiring
moved — deleting a scan run, after which the Delta tab reloads the history
through its own worker sender — deleted the run and reloaded the list
exactly like v1.17.0 (four screenshots identical). One screenshot first
differed: the dark Analyze tab drew the "Include share mask" checkbox in its
hover shade. v1.17.0 itself, run again at the same time, drew it the same
way, and step 4 is identical to that run — the shade comes from the desktop
session, not from the code.

Step 5a was checked by comparison: before the move, a script compared the four local-group functions of CLI and GUI with comments and whitespace ignored — three identical apart from type paths and one `use`, the fourth identical; the moved code is the CLI's copy. After the move, the same CLI scans as for the v1.18.0 release (DC-01's data share for 37 identities, the group-types fixture, MS-01 with LDAP and with local accounts — 25,841 rows) agree with v1.18.0 in every column, and the GUI's functional check per tab gives the same results as the v1.18.0 build (Analyze, Groups for a local account, Scan Tree pixel-identical; saved SVG byte-identical).

Screenshot comparison notes: the Windows title bar (top 31 rows) is drawn
by Windows, not Stars — its text colour follows whether the window is in
the foreground — and is left out of the comparison. A widget under the
physical mouse pointer shows its hover state; such a difference moves
between runs and is repeated, a real change is the same in every run.

## Consequences

- Editing the UI no longer means editing a 5,000-line Rust file; a tab, a
  component or a token has its own file.
- The Rust API of the UI changed once, in step 3: tab state moved from
  `MainWindow` properties into one global per tab (`ui.global::<ScanState>()`).
- A tab's behaviour is in two files that carry its name —
  `ui/tabs/<tab>.slint` and `src/tabs/<tab>.rs`.
