# ADR 0077 — Permission graph: the explanation path as a lane diagram

## Status
Accepted (2026-10-17). The layout of decision 2 (lanes, routing tracks),
the light-only canvas of decision 4 and the v1 limits are superseded by
ADR 0081 (2026-10-18); the trace (decision 1) and the colours of
decision 3 stand.

## Context

The explanation path (ADR 0074) accounts for every bit of a result, but it
is a numbered list. In a token with dozens of groups and a DACL with many
ACEs an administrator has to assemble the picture in their head: which
group brings which ACE, which ACE decided which bits, where the share
limits the result. A diagram shows that at a glance — provided it says
nothing the list does not say.

The risk is a second, drifting copy of the permission logic: a graph built
by re-reading the DACL or re-matching SIDs could disagree with the engine.

## Decision

1. **One source.** The engine fills `EffectivePermission::trace`
   (`PermissionTrace`) while it builds the explanation path, from the same
   decisions:
   - `aces`: one `AceOutcome` per ACE step, with layer (NTFS / share),
     kind, trustee, mask, inherited flag and `AceEffect` — `Decided{bits}`,
     `NoEffect`, `InheritOnly`, `Uncertain{reason}` or
     `NotApplied{reason}` (deny-only).
   - `groups`: the token groups an ACE names, each with its membership
     route (`direct`, `via A → B`, `implicit`, …), its state (member,
     deny-only, uncertain, implicit) and whether it was decisive.
   - `other_groups`: the number of further memberships no ACE names.

   Share ACE outcomes come from `share_scanner::share_ace_outcomes` (the
   same decisions as the share steps) through
   `PermissionEvaluationInput::share_trace`. The engine invariant test over
   3000 random DACLs checks that the trace has one entry per ACE step and
   that its decided Allow bits are exactly the granted bits of the path.

2. **Pure presentation.** The new crate `viz` lays the trace out; it
   contains no permission logic. Lanes, left to right: Account → Token
   groups → NTFS ACEs → NTFS → Share ACEs (only when a share was applied)
   → Result.
   - An ACE on the account itself runs through its own node "the account
     itself" in the group lane, never through a group.
   - Only groups an ACE names get a node; the rest is one node
     "+N further groups".
   - An ACE lane without any ACE for the account carries a node "no ACE
     reaches the account" instead of staying empty.
   - An edge that skips a lane (group → share ACE, NTFS → result past the
     share lane) runs on its own track below all nodes, so no line crosses
     a node it does not connect.
   - NTFS and result show `NOT DETERMINABLE` exactly where the result
     does, through `rights_label_compact`.

3. **One meaning per colour.** Green: an Allow decided bits. Red: a Deny
   decided bits. Amber dashed: uncertain (the trustee is in the token only
   for certain logons or session states). Grey dashed: matched without
   effect, inherit-only or not applied (deny-only). "Decided" is per layer:
   a share ACE that decided share bits is green even when NTFS grants
   nothing; the result node shows the combination.

4. **One layout, two renderings.** `GraphLayout::to_svg` is the complete
   SVG with `<title>` tooltips; every text is XML-escaped. The HTML report
   embeds it per row (collapsed `<details>`). The GUI tab **Graph** shows
   the last Analyze result: Slint's SVG renderer has no fonts, so the GUI
   draws `to_svg_shapes` (boxes and edges only) and puts the layout's
   texts on top as native text at the same coordinates. The canvas is
   light in both themes.

5. **Bounded size.** The HTML report embeds graphs for the first 500 rows
   (about 4–8 KB each). Further rows say "Permission graph not embedded"
   in their explanation — never silently.

## Consequences

- **Addendum (2026-10-17, after user feedback):** "+N further groups" did
  not say which groups those are. The trace now also carries them
  (`PermissionTrace::other`, name and route; omitted from JSON when empty,
  so older results stay valid and keep the plain count). The box's tooltip
  names them (first 40), the GUI lists them under the graph, and the GUI
  option "Show all groups" (`viz::GraphOptions::all_groups`) draws each as
  a grey dashed box. In that view the columns are top-aligned and a
  lane-skipping edge runs just below the lanes it crosses, not below the
  whole group column. The default layout is unchanged — v1.14.0 vs. this
  change: 15 of 15 report graphs identical apart from the named tooltip.
- JSON export gains the additive field `trace` (omitted when empty); old
  readers ignore it.
- The trace is **not** stored in the SQLite scan history. Results loaded
  from the history have no graph; the explanation path is stored as
  before.
- The graph is a picture of the explanation path, not a replacement: long
  names are shortened (full text in the report's tooltips), and the
  numbered path stays the complete account.
- Share ACEs whose trustee is not in the token are left out of the graph,
  as they are left out of the share steps; on the share layer this
  includes the Allow ACE of a deny-only group. NTFS shows such an ACE as
  "not applied (deny-only)".
- v1 limits: no export of a single graph as a file from the GUI, no
  tooltips in the GUI, no graph in the Scan Tree tab.

## Lab evidence (2026-10-17)

MS-01 over SMB, CLI HTML reports rendered and checked by eye:
`u00030` on `\\MS-01\MSData` (15 rows, 15 graphs): F06 shows the Deny of
`msg_deny` in red removing "Create files / write" from the Allow Modify
of `msg_domusers`, and the share ACEs of Everyone and `msg_direct`. F04
shows "no ACE reaches the account" (the INTERACTIVE ACE does not apply
over the network), NTFS No access. `MS-01\msadmin2` on `MSCR1`:
Administrators deny-only (remote UAC from the target's policy, ADR 0076),
its Full Control ACE "not applied (deny-only)", result Read & Execute —
the same as the earlier real SMB access. GUI tab checked locally by
screenshot.
