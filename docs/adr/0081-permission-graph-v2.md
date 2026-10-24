# ADR 0081 — Permission graph v2: two bands, layer results, routes on click

## Status
Accepted (2026-10-18).

## Context

The first graph (ADR 0077) drew six lanes in one row: Account → Token
groups → NTFS ACEs → NTFS → Share ACEs → Result. In the lab it showed four
weaknesses:

- **Detours.** Every edge that skipped a lane (group → share ACE, NTFS →
  result past the share lane) ran on its own track below all boxes. On
  `u00030` / `F06` two long lines crossed the picture, and
  `effective = NTFS ∩ share` was not visible as two inputs of one result.
- **Cut texts.** Box lines were cut at a fixed length: "Deny Special:
  Create files / writ…", "grants Special: Create files / wr…", a SID as
  "S-1-5-21-1025961329-1437379190-25…". The bits that decide a result were
  not visible in the box.
- **No place for the newer markers.** A refused or undeterminable logon
  (Selective Authentication, ADR 0079) and a missing SYNCHRONIZE (ADR 0080)
  change what an administrator must know about the result, but the graph
  did not show them.
- **GUI.** The canvas was light in both themes, there was no zoom, no
  detail on click and no way to save a single graph.

## Decision

1. **Columns and bands.** Account → Token groups → ACEs → result per layer
   → (Logon) → Result. The ACE column and the layer column carry two
   bands: NTFS on top, the share below (band headers "Share ACEs" and
   "Share"). Every edge connects neighbouring columns — a test checks it —
   so no edge needs a track and none runs through a box it does not
   connect.

2. **Layer results.** NTFS and Share each get a result box. Both flow into
   the effective result (slate, "result of a layer"), which sits between
   them. The effective box names the limiting side by the engine's own
   rule, `permission_engine::limiting_side(ntfs, share)`: *Share* when NTFS
   grants a bit the share removes, *Ntfs* when the share allows a bit NTFS
   does not grant, *Neither* when both allow the same bits — the rule of
   the explanation step "Limited by the share / Limited by NTFS / NTFS and
   share allow the same". An engine test checks the function against that
   step for 64 mask pairs, so graph and path cannot disagree. The limiting
   side's edge is thick. Without a share the box says "no SMB share — NTFS
   decides"; a NULL share DACL "share unrestricted — NTFS decides"; an
   unreadable share DACL "share not determinable".

3. **Logon column** (only when a Selective Authentication marker exists):
   - "Logon allowed — via …" (green);
   - "Logon refused — not "Allowed to authenticate" on SERVER" (red, double
     line); the result then says **No access — logon refused before any
     ACE**;
   - "Logon not determinable" with the reason (amber); the result adds
     "logon not determinable" — or, when the permissions grant nothing
     (ADR 0079 addendum), "whatever the logon decides", and the line from
     the logon box is grey dashed: it has no effect on the exact No access.

4. **SYNCHRONIZE.** With the marker of ADR 0080 the result box adds
   "no SYNCHRONIZE: Explorer and most programs get "access denied"" (amber,
   two lines). The rights shown stay the AccessCheck value.

5. **Decisive route thick.** Account → group when the group is decisive;
   group → ACE when the ACE decided bits and the group is decisive; ACE →
   layer when the ACE decided bits; layer → result on the limiting side.

6. **A Deny is a double line** (the red stroke with a bright core), so it
   reads apart from an Allow without colour. The legend has six entries.

7. **No bit is hidden in a box.** Rights appear in the long form when it
   fits the line, else in the `icacls` short form (`(WD,AD,WA,WEA,S)`) —
   after the prefix when it fits there, on a line of its own when it fits
   that, else broken after a comma; rights are never cut. Names lose the
   domain first (`…\name`), then the middle; a domain SID keeps its
   authority and its RID (`S-1-5-21-…-1132`), also inside a logon line
   ("via GG_ExtPartners (S-1-5-21-…-1110)"). Routes and ACE reasons take
   up to two lines, the reason why a logon or a share is not determinable
   up to four; only a last line that is still too long is cut — the full
   text stays in the tooltip (report) and in the click detail (GUI).

8. **Two palettes.** Light and dark, one meaning per colour in both. The
   HTML report (dark) embeds the dark graph and scales it with the row,
   down to 80 % of its size; below that it scrolls.

9. **GUI.**
   - The graph follows the theme (both palettes are rendered; the texts
     carry both colours).
   - A click on a box shows its full text below the graph and keeps every
     route through it bright — the box, every box it is reached from and
     every box it leads to (`GraphLayout::route_nodes`); boxes, edges and
     texts off those routes fade. A second click shows everything again.
     Because edges connect neighbouring columns only, an edge between two
     bright boxes always lies on such a route.
   - Zoom: −, +, *Actual size*, *Fit width* (40–200 %).
   - **Save graph (SVG)** writes the graph as shown (the "Show all groups"
     setting included), light, with a caption line (account and path),
     without the selection. The path is validated like a report export
     (`validation::export_path::validate_svg_export_path`: not empty, no
     NUL, extension `.svg` only, existing directory). An existing file is
     never overwritten: the GUI refuses it, and `create_new` also covers a
     file created between the check and the write.

10. **Presentation only.** The graph still comes from
    `EffectivePermission::trace`, its values and its markers. The only
    addition outside `viz` is `limiting_side` in `permission_engine::mask`;
    the engine's own evaluation is unchanged.

## Consequences

- The report's graphs change their look (dark, two bands, scaling); the
  report's other content, CSV and JSON are unchanged.
- ADR 0077's v1 limits "no export of a single graph from the GUI" and "no
  tooltips in the GUI" are lifted (save as SVG; the click detail). Still
  open: no graph in the Scan Tree tab; results loaded from the scan history
  have no graph (the trace is not stored).
- Text widths are estimated (6.7 px per character at 12 px Segoe UI), not
  measured. The estimate is conservative; a font much wider than Segoe UI
  could still overrun a box edge.
  *Correction (2026-10-24, ADR 0083):* measured, the estimate is
  conservative for mixed text only. A capitals-only rights label such as
  `RX+WA,WEA,DC,DE,WDAC,WO` needs about 7.2 px per character in Segoe UI and
  7.8 px in Arial, the font the graph uses since ADR 0083 (the GUI drew it in
  Arial before already), so a long label of that kind can overrun a box
  edge.

## Verification (2026-10-18)

- `viz`: 27 tests — among them: every edge between neighbouring columns,
  the share band below the NTFS band, the limiting side named and thick,
  the logon node, the SYNCHRONIZE line, no box line longer than the box,
  rights never cut, the full logon reason, SIDs in logon lines, routes on
  click, the dark palette. `permission_engine`: `limiting_side` against
  the explanation step (64 mask pairs). `validation`: `.svg` only. GUI: a
  saved graph never overwrites a file.
- Lab results rendered in both palettes and checked: MS-01 `MSData` for
  `u00030` (15), `SyncTest` for `rt_gt01` (11: Deny of SYNCHRONIZE, rights
  without a named level), and `TrustTest` for two accounts of the trusted
  domain in every Selective Authentication state of the L4 measurements
  (105: logon allowed 13, refused 39, not determinable 27, trust without
  Selective Authentication — no logon column — 26). No box line is cut
  except names and SIDs as described above.
- GUI live: `u00030` on `\\MS-01\MSData\F06_LocalGroupDomUsersDeny` over
  SMB with the share (screenshot in the user guide), and a local folder
  with a Deny for the own account: themes, click and second click, the
  route through *Share*, zoom, Fit width, Show all groups; Save with an
  empty path (refused), a new file (written: light, caption, no selection)
  and the same file again (refused).
- Regression: the same CLI scans with v1.16.1 (main `06064bc`, built
  fresh) and with this change, compared column by column — the data share
  of DC-01 for 37 identities (25,493 rows), its group-types fixture (78
  rows), MS-01 `MSData` with LDAP (135 rows) and with local accounts (135
  rows): 0 differing rows.
