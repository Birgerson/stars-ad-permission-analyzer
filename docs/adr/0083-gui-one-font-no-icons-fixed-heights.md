# ADR 0083 — GUI design: one font, no symbol icons, fields at their natural height

## Status
Accepted (2026-10-24). The first design step after the structural steps of
ADR 0082.

## Context

Three requests from the user: Arial as the one font of the application; no
emoji or "messaging icons"; input fields that no longer change their height
between an empty and a filled state. Looking into them showed:

- **Fonts.** The window already set `default-font-family: "Arial"`, and the
  Slint widgets take it over. But 17 kinds of characters in the UI texts have
  no glyph in Arial — 🔍 🌐 📂 🗑 💾 👥 🔗 ⟳ ▶ ■ ☀ ☾ ★ ⓘ ⚠ ℹ ✓ ✗ — and Windows
  draws them from its emoji or symbol font. The graph saved as SVG (and the
  one in the HTML report) named `Segoe UI` first.
- **Heights.** When no element of a Slint box layout has a vertical stretch
  above 0, the layout shares its free height out equally over all of them
  (`i-slint-core` `layout.rs`), and a `GroupBox` gives its content a stretch
  of 1. So while a tab had room, every field, button and section grew; as
  soon as the suggestion list, a status line or a result took the room, they
  shrank back to their natural height. The same effect let the Delta tab's
  run list sink to the bottom of the tab and opened a gap above *Mode* in the
  Scan Tree. Groups, Trusts and Shares had been fixed by hand before
  (`alignment: start`), the other tabs not.
- **A real bug on the way.** Once a ScrollView's content is taller than the
  window, Slint sizes it to the content's *minimum* height (the compiler's
  `flickable.rs` binds `viewport-height` to `min-height`), and every element
  is pressed down to its own minimum. `PrimaryButton` and `DangerButton` had
  `preferred-height` and `max-height` 30 px but a minimum of 0. In the Scan
  Tree tab, *Start scan* and *Cancel* sit in a row of their own, so the row
  collapsed to nothing as soon as the results overflowed the window: during a
  long scan *Cancel* could not be seen or clicked, and afterwards a second
  scan could not be started. v1.17.0 shows the same. Rows where such a
  button sits next to a Slint `Button` or a `LineEdit` keep the neighbour's
  minimum (Analyze, Graph, Export); the Delta tab's *Load scan history* and
  *Compare* stand alone and are subject to the same mechanism (not
  reproduced separately — it needs a run list taller than the window).

## Decision

1. **One font token.** `Theme.font-family` is `"Arial"`; the window's
   `default-font-family` takes it, every text and widget inherits it. The
   graph SVG names `Arial, sans-serif` — the GUI drew the graph's texts in
   Arial before already.
2. **Only characters Arial can draw.** No emoji, no symbol icons. Severity
   markers are text, the same as the CLI: `[!]` where the GUI showed ⚠, `[i]`
   where it showed ℹ; the colours stay. Buttons carry words only; the Delta
   tab's run buttons read *Errors (n)* and *Delete*. The disclosure triangles
   ▲ ▼ ► are Arial glyphs and stay. The brand star is a vector shape (`Path`,
   a regular five-pointed star with computed points), the help icon a `?` in
   a drawn circle — a small `i` read like a power symbol.
   `ui_text_tests::gui_texts_use_only_characters_arial_can_draw` checks every
   non-comment line of `crates/gui/ui/**/*.slint` and `crates/gui/src/**/*.rs`
   against a set of characters checked against Arial regular and bold
   (ASCII, Latin-1, dashes, quotes, bullet, ellipsis, arrows, − ∩ ≠ ≤ ≥,
   ▲ ► ▼); an emoji put into a UI text for the check failed it.
3. **Natural height from the top.** The top layout of every scrolling tab
   has `alignment: start`: each element gets its natural height and the free
   height stays below the content.
4. **Buttons have a fixed height**: `min-height`, `preferred-height` and
   `max-height` of `PrimaryButton` and `DangerButton` are 30 px.
5. **The HTML report follows** (its own commit): its badges read `[!]` and
   `[i]` instead of ⚠ and ℹ, "No risk findings." loses its ✓. The report's
   body was Arial already; paths and SIDs stay in a monospace font, so that
   every character of them can be read. `html::tests::report_markers_are_text_not_symbol_icons`
   fails on a symbol icon in the exporter's code (checked with a ✓ put back).

## Verification (2026-10-24)

- Screenshots of all eight tabs, light and dark, empty and with a result:
  the changes are the intended ones. The Analyze form sits at the same
  positions with the same heights empty and with a result taller than the
  window (Path 187–217, Identity 225–255, … *Analyze* 598–628).
- The functional check of ADR 0082 (one real action per tab) gives the same
  results; the saved SVG is identical apart from the font name; deleting a
  scan run and the automatic reload work as before.
- Scan Tree: before the fix the buttons vanished at the first scan whose
  results overflowed; with the fix they stay, during the scan (*Running…*,
  *Cancel* red) and after it.
- Lab (`corp.test`, MS-01, ext.test trust), see
  [lab/verification.md, Block Q](../lab/verification.md): every tab driven
  against the lab with the results of the earlier runs; the graph of
  `u00030` on `F06` is pixel-identical to the v1.17.0 documentation image.
- Report: a lab scan exported as HTML (the data share's special-case
  folder for `u00030`) carries `[!]` / `[i]` badges, no symbol icon, and all
  90 embedded graphs name Arial.
- Gates: fmt, clippy, 993 tests with the GUI step, 994 with the report
  step, language and secret gate.

## Consequences

- The GUI looks calmer: no fields that grow and shrink, no sections spread
  over the tab, no icons from a second font.
- Known, not changed here:
  - The graph fits its texts by an average character width (6.7 px); a long
    capitals-only rights label can overrun a box edge (ADR 0081 correction).
  - The Scan Tree list is not virtualized, and every streamed row rebuilds
    the shown model; with several hundred rows the GUI lags for seconds
    while the rows arrive (689 rows in the lab). AGENTS.md asks for
    virtualized or paged tables — an open item.
  - A *Cancel* during the group resolution of a scan takes effect when the
    directory walk starts; until then the status still reads *Scan
    running…*.
