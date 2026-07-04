# ADR 0057 — SemVer pre-release precedence in the update version policy

**Status:** Accepted (2026-07-04)
**References:** ADR 0028 (update-manager skeleton), ADR 0030 (policy split),
deep review 2026-07-04 finding F4, known-limitations L12

## Context

The update policy compared versions by stripping everything after `-`, and
a test cemented `1.1.0-rc1 == 1.1.0`. Consequences (review F4):

- a system running `1.1.0-rc1` **rejected the final `1.1.0`** as "not
  newer" unless downgrades were explicitly allowed — a release-management
  trap, and an acute one: this repository itself currently ships
  `v1.7.7-rc1`, so rc-to-final is the very next transition;
- the manifest schema accepted any non-empty `app_version` (e.g.
  `latest`), which then failed only later, at policy time.

## Decision

1. New module `update_manager::version` with `AppVersion`: dotted-numeric
   core (zero-padded, `1.2 == 1.2.0`), optional pre-release identifier
   list, optional build metadata. Precedence per SemVer §11:
   - **a pre-release orders before its final release** (`1.1.0-rc1 <
     1.1.0`) — the F4 fix;
   - pre-release identifiers compare dot-wise (numeric numerically,
     numeric < alphanumeric, alphanumeric in ASCII order, shorter list
     first on equal prefix);
   - build metadata (`+…`) carries no precedence (SemVer §10).
2. `verify_update_policy` compares through this parser; behavior for
   plain versions is unchanged (equality still rejected without
   `allow_downgrade`, downgrade still rejected).
3. `UpdateManifest::validate_schema` requires `app_version` to parse —
   `latest` and friends fail at schema time with a clear message.

Deliberate practical note (documented in the module): `rc1`/`rc2` are
single *alphanumeric* identifiers and compare lexically — correct up to
`rc9`. A two-digit release candidate must be written `rc.10` (numeric
identifier) to order numerically. The project's release history
(`v1.7.7-rc1`-style) stays within that boundary.

## Alternatives considered

- **Reject pre-releases in the schema** (the review's fallback option).
  Rejected: the project actively ships `-rcN` builds; refusing them in
  manifests would block the very transition that exposed the bug.
- **Pull in the `semver` crate.** Rejected for now: the needed subset is
  ~150 lines with exhaustive tests, and the update manager deliberately
  keeps its dependency surface minimal (fail-closed seam, L12).

## Consequences

- rc-to-final is an upgrade; final-to-rc of the same core is a downgrade
  and stays rejected by default; same-version re-install stays rejected.
- Manifests with unparseable versions are refused before any policy or
  signature context is even considered.
- Tests: parser (valid/invalid/pre-release/build), precedence matrix,
  and policy-level cases `current=1.1.0-rc1 + manifest=1.1.0` (accepted),
  same-rc re-install (rejected), `final → rc` (rejected),
  schema `latest` (rejected), schema `1.7.7-rc1` (accepted).
