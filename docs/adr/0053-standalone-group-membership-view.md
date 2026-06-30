# ADR 0053 — Standalone group-membership view (identity → groups)

**Status:** Accepted (2026-06-30)
**References:** ADR 0021 (diagnostic markers), ADR 0052 (SID-history / trust
visibility), known-limitations L1–L4

## Context

Stars answers *"what can identity Y do on path X?"* (Analyze) and *"who has
access to the tree under X?"* (Scan / trustee view). A recurring, simpler
operator question had **no** first-class answer: *"which groups is this user
actually in?"* — including the recursive, nested memberships and whether any of
them are privileged. Operators worked around it by analysing an arbitrary path
just to read the resolved-groups side panel, which couples an unrelated path/ACL
read to a pure identity question and hides the answer behind rights output.

The resolver already produces everything needed: `PrincipalResolution` carries
the identity plus its recursively resolved `GroupMembership` list (primary
group, domain groups via `LDAP_MATCHING_RULE_IN_CHAIN`, local groups) and the
identity-level status (disabled, SAM fallback, FSP, GC, outside-base,
`sIDHistory`).

## Decision

Add a **dedicated, read-only membership view** — one direction only
(**user → groups**, upward) — exposed identically by the CLI (`adpa groups`)
and the GUI (a new **Groups** tab). It shows the recursive group memberships
**without** a path, ACL, or effective-rights computation. Those stay in
Analyze/Scan; the view ends with a pointer back to them.

Shared building block — `adpa_core::model::MembershipReport`:

- `identity`, `ad_connected`, `memberships` (deduplicated by group SID),
  `diagnostics`.
- Built once by `PrincipalResolution::into_membership_report(ad_connected)`;
  the CLI renderer and the GUI worker consume the **same** structure, so both
  surfaces word and classify everything identically.

Reused, not duplicated:

- **Diagnostics.** `PrincipalResolution::membership_diagnostics()` derives the
  identity-/resolution-level markers from `engine_flags()` + the identity
  (disabled, SAM fallback, FSP, GC, outside-base, lookup/group failure,
  `sIDHistory`, trust boundary) — the same set the engine surfaces for an
  identity, minus the path-specific ones. It cannot drift from the engine's
  classification because it reuses the same `EngineFlags` source.
- **Origin label.** `GroupMembership::origin_label()` ("direct", "primary
  group", "local group", or the chain "via A → B") lives in core and is shared
  by both renderers.
- **Diagnostic rendering.** The CLI factors its marker block into a shared
  `print_diagnostics`, reused by both the analyze report and the membership
  report.

### Privileged-membership flag (included now)

`adpa_core::model::privileged_group_role(&Sid) -> Option<&'static str>` flags a
membership in a well-known privileged group: built-in aliases by their constant
SID (`S-1-5-32-544` Administrators, `-548/-549/-550/-551` Operators) and domain
groups by their well-known **RID** suffix (`-512` Domain Admins, `-519`
Enterprise Admins, `-518` Schema Admins, `-520` Group Policy Creator Owners,
`-526/-527` Key Admins). This is pure SID matching against the already-resolved
membership list — **no extra LDAP fetch** — and is the high-value audit signal
("⚠ member of Domain Admins via …").

## Scope boundary (deliberate)

- **One direction only.** Group → members (downward) is a separate, later stage.
  Its gotcha (`primaryGroupID` members such as Domain Users are not returned by
  the `member` attribute and need a second query) is out of scope here.
- **No rights.** The view never reads a path or DACL; "who else has access?"
  remains the existing trustee view. Effective rights stay in Analyze/Scan.
- **Security/Distribution + group scope (`groupType`)** are deferred — they need
  an extra resolver fetch; the privileged flag does not.

## Why a separate report type (not reuse `EffectivePermission`)

`EffectivePermission` is path-bound (mask, matched ACEs, share status). The
membership question has no path, so a path-bound type would carry meaningless
empty fields and tempt callers to render rights that were never computed.
`MembershipReport` keeps the view honestly scope-free.

## Consequences

- A pure identity question gets a first-class, read-only answer in both the CLI
  and the GUI, reusing the resolver, the diagnostics, and the origin label —
  no new permission logic, fully within the read-only principle.
- Incompleteness stays visible: a SAM/LSA fallback or a resolution timeout shows
  its marker, so a short list never looks like a complete one.
- Exports: `--output .json` (serde) / `.csv` for the CLI; the GUI renders the
  list with the shared attention-based severity colours.

## Tests

- Core: `privileged_group_role` matches built-in aliases and domain RIDs
  (domain-independent) and rejects Domain Users / plain user RIDs;
  `MembershipReport::privileged` collects only privileged groups.
- Resolver: `membership_diagnostics` surfaces `sIDHistory` + SAM fallback;
  `into_membership_report` deduplicates by group SID.
- CLI: CSV field escaping (quotes/commas/newlines).
- Live (lab, res.lab): `Administrator` flags Schema/Enterprise/Domain Admins +
  GPO Creator Owners and renders the nested chain "via Administrator → Domain
  Admins → …"; `mig01` surfaces the `sIDHistory` marker.
