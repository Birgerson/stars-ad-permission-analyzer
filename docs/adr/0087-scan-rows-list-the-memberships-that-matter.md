# ADR 0087 — A scan row lists the memberships that can change its result

## Status
Accepted (2026-10-25).

## Context

The enterprise campaign (FS-01, `T:\Enterprise`, see `docs/testing/enterprise-test-campaign.md`) uses accounts with the token sizes of real AGDLP environments: global role groups nested in domain-local resource groups. `ent_std` has 78 groups in its token, `ent_heavy` 874.

Every row of a scan listed every membership of the account, each with its route. A CLI scan of `Finance\P00_Archive` (11,579 paths) over SMB measured, with main 9ab4edd:

| account | membership steps | explanation per row | CSV | database | time (wall / scan) |
| --- | --- | --- | --- | --- | --- |
| `ent_std` | 79 | 13,022 characters | 154.0 MB | 159.0 MB | 45 s / 20.5 s |
| `ent_heavy` | 875 | 131,597 characters | 1,505.2 MB | 1,508.5 MB | 135 s / 116.7 s |

The membership list is the same on every row of a scan; only the markers on it differ. For the whole 1.65-million-object tree, `ent_heavy` would need about 210 GB of CSV and as much again in the database. Most of the time went into building these texts. An instrumented build (not committed) put 90.8 seconds of the scan in the engine. Two spots in it were quadratic in the number of groups:

- `merged_memberships_per_group` looked through every membership for each kept group. With 874 groups that is about 760,000 comparisons per row.
- `trace_groups` searched the memberships linearly for each ACE.

## Decision

1. **`MembershipDetail` in the evaluation input.** It has two values:
   - `All`, the default: a single analysis (Analyze tab, `adpa analyze`) and the first row of a scan.
   - `NamedOnly { full_list_at }`: every other row of a scan. `full_list_at` is the path of the first row.
2. **A compact row lists the memberships that can change its result.** A membership is listed when:
   - an ACE of the object's DACL or of the share's DACL names its group, by the group's SID or by one of its historical SIDs (ADR 0059);
   - its group owns the object (the implicit READ_CONTROL + WRITE_DAC needs no ACE);
   - its step carries a warning: deny-only, uncertain, or chain unknown.

   The others become one step:

   > Not listed: N further group membership(s) of this account — no ACE on this object or its share names these groups and none of them owns the object, so they cannot change this result; the full list is in the result for `<first path>`

3. **Some rows list every membership anyway.** Stars cannot know which groups can change these rows:
   - The object or its share has an ACE Stars cannot evaluate (object, callback, conditional). Such an ACE can name any group, or test any group in its condition.
   - The share DACL could not be read.
   - A Selective Authentication check applies (ADR 0079). It decides the logon through the groups on the target computer's object.
4. **Only the explanation changes.** These values stay the same:
   - masks, statuses, diagnostics, the reasons a value is not determinable;
   - matched ACEs, contributing SIDs, risk findings;
   - the delta comparison, which compares masks, statuses and diagnostics.

   The trace keeps the count of the other memberships, but not their names (`trace.other` is empty). The permission graph in the HTML report therefore shows them as one summary box.
5. **The reference row must exist.** `full_list_at` is set only once a row with the full list has been written. In the GUI, if that evaluation fails, the next row lists the memberships in full.
6. **Faster code paths.**
   - `merged_memberships_per_group` builds a by-group index once.
   - `trace_groups` looks each ACE's trustee up in a map.
   - The engine decides whether to leave a membership out before it builds the step text.

## Consequences

Measured over SMB from the workstation, with release builds: main 9ab4edd against this change, on the same trees and the same day.

| run | paths | explanation per row | CSV | database | time (wall / scan) |
| --- | --- | --- | --- | --- | --- |
| `ent_std`, `P00_Archive` | 11,579 | 13,022 → **1,285** characters | 154.0 → **18.2 MB** | 159.0 → **23.3 MB** | 45 s / 20.5 s → 50 s / 21.2 s |
| `ent_heavy`, `P00_Archive` | 11,579 | 131,597 → **1,303** characters | 1,505.2 → **18.4 MB** | 1,508.5 → **23.7 MB** | 135 s / 116.7 s → **50 s / 27.5 s** |
| `u00030` (107 steps), `MassData\Finance` | 75,586 | 19,442 → **1,553** characters | 1,521.2 → **145.7 MB** | 1,529.2 → **168.0 MB** | 165 s / 139.1 s → 160 s / 130.4 s |

- **The values are unchanged.** Every column but the explanation is identical in the CSV and in the database (digest). So are the console output, every risk finding and the scan errors.
- **The explanation changes as decided.** A strict comparison (verification Block V) checks every row: the first row in full, every other row as the full explanation minus the plain membership steps of unnamed groups plus one count step. No removed group appears anywhere else in the full result.
- **Reading a row alone,** an administrator sees which memberships matter on that object. The full list with every route is in the first row: in the CSV, in the database, and in the GUI's Scan Tree.
- **A single analysis is unchanged.**
- **Rows stored by older versions** keep their full lists, and the delta comparison does not change.
- **The share's DACL is read once per scan.** Its ACEs therefore name the same groups on every row, and the groups they name are listed on every row.

Measurement and regression proof: verification Block V.
