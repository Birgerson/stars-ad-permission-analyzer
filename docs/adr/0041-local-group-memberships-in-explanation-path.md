# ADR 0041 — Local-group memberships in the explanation path

**Status:** Accepted
**Date:** 2026-06-05

## Context

ADR 0040 closed the *evaluation* of local server groups for trust
identities: a candidate list (`format_account_candidates_for_local_groups`)
ensures that `NetUserGetLocalGroups` returns the correct local group SIDs
for NetBIOS trust identities. These SIDs flow into the token set with which
the engine matches ACEs against the identity.

What ADR 0040 **did not** solve: the **explanation**. The local group SIDs
ended up exclusively in the engine's `local_group_sids` token.
`group_memberships` — the data stream from which `format_membership_step()`
renders the path steps — did **not** see them.

The visible effect in the report:

```text
Effective Rights: Modify (0x001301BF)
Explanation Path
  1. User: alice
  2. Member of Domain Users [direct, source: PrimaryGroup]
  3. Allow ACE [explicit] for BUILTIN\Administrators → Modify
  4. NTFS effective: Modify
```

Step 3 names the ACE but leaves open **why** alice is in
`BUILTIN\Administrators`. The auditor sees "Modify applies to a local
group" without seeing the mediator step that justifies this membership
(e.g. `alice → Domain Admins → BUILTIN\Administrators`).

Review 2026-06-05 round 6 finding 1 classified this as **High**: Stars
reports the correct effective right but gives no traceable justification in
the explanation path — which directly violates the read-only auditing
promise to make every rights finding traceable.

## Decision

The `ad_resolver` no longer produces only a SID vec for local groups per
identity, but a **`Vec<GroupMembership>` with
`MembershipPathSource::LocalGroup`**.

### 1. New resolver function

`crates/ad_resolver/src/local_groups.rs::resolve_local_group_chains_for_identity`:

```rust
pub fn resolve_local_group_chains_for_identity(
    server: Option<&str>,
    identity: &Identity,
    known_member_sids_to_names: &HashMap<String, String>,
) -> Result<Vec<GroupMembership>, CoreError>
```

The function:

1. Builds account candidates via
   `format_account_candidates_for_local_groups` (ADR 0040 — reused).
2. Calls `resolve_local_group_chains` per candidate, which, in addition to
   the SIDs, also returns the **member chain** (path nodes and `complete`
   flag).
3. Converts each found chain into `GroupMembership { source = LocalGroup }`.
   Direct membership (`path.nodes.len() == 2 && complete`) is marked with
   `direct: true`; multi-level chains or incomplete lookups with
   `direct: false`.
4. As soon as a candidate succeeded (`WithGroups`), the loop breaks — the
   same ordering semantics as in ADR 0040.

### 2. CLI and GUI merge the memberships

`crates/cli/src/main.rs` and `crates/gui/src/worker.rs`:
`collect_local_group_sids_for_path` returns a 3-tuple:

```rust
(Vec<Sid>, Vec<GroupMembership>, LocalGroupEvalStatus)
```

The SIDs are filled into `PermissionEvaluationInput::local_group_sids` as
before. The memberships are **merged** with the AD memberships and passed
into `PermissionEvaluationInput::group_memberships`:

```rust
let all_memberships =
    resolved.resolution.memberships.clone()
        .into_iter()
        .chain(local_group_memberships)
        .collect();
```

### 3. The engine renders a LocalGroup step

`permission_engine::engine::format_membership_step` and `source_label` were
already prepared for `MembershipPathSource::LocalGroup` (see ADR 0036). The
output for the new constellation:

```text
Member of BUILTIN\Administrators (S-1-5-32-544)
    [via alice → Domain Admins → BUILTIN\Administrators, source: LocalGroup]
```

For an incomplete member chain (`complete: false`):

```text
Member of BUILTIN\Administrators (S-1-5-32-544)
    [exact chain unknown, source: LocalGroup]
```

## Consequences

### Positive

- **Fully traceable paths** — even when local server groups are part of the
  effective permission, the auditor can see exactly which mediator group(s)
  convey the access.
- **`exact chain unknown` as an honest diagnostic signal** — when the
  member list of the local group is not readable, that is named in the path
  instead of silently leaving a gap.
- **ADR 0036's promise (unified pipeline) is kept** — the explanation is
  consistent, whether the membership comes from AD or from a local lookup.
- **Token and explanation are consistent**: previously the engine could
  match via a SID without leaving a trace in the explanation.

### Negative / trade-offs

- `resolve_local_group_chains_for_identity` is slower than the pure SID
  variant, because it additionally performs member lookups per group. That
  is acceptable — the call is on-demand and caches the SID-to-name lookup
  via `known_member_sids_to_names`.
- Doubly referenced memberships (both AD and LocalGroup find "alice →
  Domain Admins") are possible. The engine does not actively detect this
  via `MembershipPath` comparison — the path then shows two steps with a
  different source. For the explanation this is tolerable, because both
  sources actually exist.

### Test coverage

Two new tests in `crates/permission_engine/src/engine.rs::tests`:

- `local_group_membership_renders_in_explanation_path` — a complete chain,
  `source: LocalGroup` must appear in the path step, the mediator
  (`Domain Admins`) must show up in the step line.
- `local_group_membership_with_incomplete_path_renders_unknown_chain` —
  `complete: false` must be rendered as `exact chain unknown`, the source
  must still be marked as `LocalGroup`.

Live verification against a real 3-forest lab in
[`docs/lab/verification.md`](../lab/verification.md) (test T1,
alice@tier0.lab): the `BUILTIN\Users` membership step appears there with
`[via alice → Domain Users → BUILTIN\Users, source: LocalGroup]`.

## Relationship to other ADRs

- **ADR 0034** (LSA fallback): brings the trust identity to local group
  resolution in the first place.
- **ADR 0036** (unified principal resolution pipeline): defines the uniform
  mediator-step semantics, extended here to local groups.
- **ADR 0040** (candidate list): is reused, both for the token-SID variant
  (`resolve_local_group_sids_for_identity`) and for the now-added chain
  variant.
