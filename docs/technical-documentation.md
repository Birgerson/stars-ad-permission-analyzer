# Stars — Technical Documentation

**Version:** v1.5.10 (2026-06-05)
**Audience:** Developers, code reviewers, and security engineers who
want to understand *how* Stars works internally — not *how to use* it
(that's the [User Guide](user-guide.md)).

This document covers architecture, data flows, and the core
algorithms. It does not replace the source code (the truth lives
there) nor the [ADRs](adr/) (the decision rationales live there) — it
bridges them.

---

## Table of Contents

1. [Architectural principles](#1-architectural-principles)
2. [Workspace and crate layering](#2-workspace-and-crate-layering)
3. [The domain data model](#3-the-domain-data-model)
4. [The overall data flow](#4-the-overall-data-flow)
5. [Identity resolution — the Principal pipeline](#5-identity-resolution--the-principal-pipeline)
6. [Permission engine — the AccessCheck reproduction](#6-permission-engine--the-accesscheck-reproduction)
7. [Share DACL ∩ NTFS DACL](#7-share-dacl--ntfs-dacl)
8. [Local server groups and the candidate list](#8-local-server-groups-and-the-candidate-list)
9. [The diagnostic marker system](#9-the-diagnostic-marker-system)
10. [Risk engine — from permission to audit finding](#10-risk-engine--from-permission-to-audit-finding)
11. [Threading model — GUI / CLI / engine](#11-threading-model--gui--cli--engine)
12. [Persistence and export](#12-persistence-and-export)
13. [Validation at system boundaries](#13-validation-at-system-boundaries)
14. [Test architecture](#14-test-architecture)
15. [Update manager](#15-update-manager)
16. [Further reading](#16-further-reading)

---

## 1. Architectural principles

Four rules that shaped every design decision in Stars:

### 1.1 Read-only

Stars reads from AD, NTFS, SMB. Stars writes **nothing** back to those
systems. There is **no code path** that modifies an ACL, sets an AD
group membership, moves a file, or changes an owner — not as a
"repair suggestion", not in a GUI convenience mode. This rule is
encoded as the [`AGENTS.md`](../AGENTS.md) project boundary and
guaranteed by the *absence* of corresponding API calls in every
crate.

Writes only to Stars-owned data:
- The SQLite scan history (`%APPDATA%\Stars\stars_data.db`).
- Application logs.
- Export files chosen by the user.

### 1.2 Visibility of uncertainty

Stars does not just show the answer — it also shows what it *did not
know*. This is realised through structured
[`PermissionDiagnostic`](#9-the-diagnostic-marker-system) markers
threaded through the entire pipeline (engine → risk → renderer →
export) as variant-tagged data. Risk findings carry
`incomplete = true` as soon as the underlying computation had a
structural gap. **No silent skips.**

### 1.3 Modular separation

The domain engine runs **independently of the GUI and CLI**. This
principle is encoded in the crate layering: `permission_engine` and
`risk_engine` know about neither `gui` nor `cli`. Adapter traits
(`IdentityResolver`, `IdentityBackend`, `LsaBackend`,
`PermissionEvaluator`, `RiskRule`, `Exporter`) form the interfaces —
no implementation dependencies.

### 1.4 Explainability

Every permission finding carries a `PermissionPath` with the
intermediate steps:

```text
User → Group A → Group B (over LDAP_MATCHING_RULE_IN_CHAIN)
     → ACE (Allow, Modify, inherited from C:\)
     → normalized right: Modify
```

Meaning: not "Stars computed", but "Stars computed and **why**".
That makes findings auditable and falsifiable.

---

## 2. Workspace and crate layering

Stars is a Rust workspace with 12 crates. Layering is strictly
directed — higher layers depend on lower ones, never the reverse:

```text
┌──────────────────────────────────────────────────────────┐
│                                                          │
│  cli (adpa.exe)        gui (adpa-gui.exe, Slint)         │
│                                                          │
└──────────────┬───────────────────────┬───────────────────┘
               │                       │
               ▼                       ▼
┌──────────────────────────────────────────────────────────┐
│  exporter (CSV/JSON/HTML)   persistence (SQLite)         │
│  update_manager                                          │
└──────────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────┐
│  risk_engine (6 rules + is_incomplete)                   │
└──────────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────┐
│  permission_engine (AccessCheck reproduction)            │
└──────────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────┐
│  fs_scanner       share_scanner     ad_resolver          │
│  (NTFS walk +     (Share DACL,      (LDAP, LSA, SAM,     │
│   DACL read)       NetShareEnum)     Principal pipeline) │
└──────────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────┐
│  core (data model, traits, CoreError)                    │
│  validation (wrapper types for all user inputs)          │
└──────────────────────────────────────────────────────────┘
```

### Per-crate responsibilities

| Crate | Role | Key modules |
| --- | --- | --- |
| `core` | Domain types (`Identity`, `Sid`, `FileSystemObject`, `EffectivePermission`, `PermissionDiagnostic`) + traits + `CoreError` | `model.rs`, `traits.rs`, `error.rs` |
| `validation` | Typed wrappers for every user input (`ValidatedSid`, `ValidatedDn`, `ValidatedServerName`, …) plus validation functions | `sid.rs`, `net.rs`, `path.rs`, `numbers.rs`, `export_path.rs`, `db_path.rs` |
| `ad_resolver` | AD / LSA / SAM access; **central Principal pipeline** lives here | `principal.rs`, `resolver.rs`, `sam.rs`, `local_groups.rs`, `ldap_client.rs` |
| `fs_scanner` | NTFS DACL read + walker with reparse-point loop detection | `walker.rs`, `dacl.rs` |
| `share_scanner` | SMB enumeration + share DACL read via Windows API | `scanner.rs`, `dacl.rs` |
| `permission_engine` | AccessCheck reproduction, token SID assembly, permission path generation | `engine.rs`, `token.rs`, `mask.rs`, `normalized.rs` |
| `risk_engine` | Six risk rules + `is_incomplete()` | `rules.rs` |
| `persistence` | SQLite schema + migrations + `ScanStore` | `scan_store.rs`, `migrations.rs` |
| `exporter` | CSV / JSON / HTML renderers | `csv.rs`, `json.rs`, `html.rs` |
| `update_manager` | Skeleton for signature-checked updates | `lib.rs` |
| `cli` | Command-line front-end (`adpa.exe`) | `main.rs`, `output.rs` |
| `gui` | Slint-based GUI (`adpa-gui.exe`) | `main.rs`, `worker.rs`, `ui.slint` |

### Workspace configuration

Versions are centralised in [`Cargo.toml`](../Cargo.toml)
(`workspace.package.version`); each crate inherits with
`version.workspace = true`. Dependencies come from
`workspace.dependencies` so version drift between crates is
impossible.

---

## 3. The domain data model

`adpa_core::model` defines the central types every crate works with.
Highlights:

### Identity

```rust
struct Sid(String);              // canonical "S-1-5-..."

enum IdentityKind { User, Group, Computer, WellKnown, Orphaned, Unknown }

struct Identity {
    sid: Sid,
    name: Option<String>,             // sAMAccountName / LSA name
    domain: Option<String>,           // NetBIOS or DNS, depending on source
    kind: IdentityKind,
    disabled: bool,                   // userAccountControl/UF_ACCOUNTDISABLE
    user_principal_name: Option<String>,
}
```

`Sid` is a typed string wrapper that travels between modules without
a validation guarantee. **Validating raw SIDs at system boundaries**
happens in `validation::sid::validate_sid`, which produces a
`ValidatedSid`.

### File system object

```rust
struct FileSystemObject {
    path: NormalizedPath,
    is_directory: bool,
    owner_sid: Option<Sid>,
    dacl: Vec<AceEntry>,
    inheritance_disabled: bool,
    is_reparse_point: bool,
    unsupported_aces: Vec<UnsupportedAce>,
    null_dacl: bool,                   // NULL DACL ≠ empty DACL!
}

struct AceEntry {
    kind: AceKind,                     // Allow | Deny
    sid: Sid,
    mask: AccessMask,
    inherited: bool,
    inheritance_flags: u32,            // OBJECT_INHERIT_ACE, CONTAINER_INHERIT_ACE, …
    propagation_flags: u32,            // INHERIT_ONLY_ACE, NO_PROPAGATE_INHERIT_ACE
}
```

Important:

- `null_dacl: bool` distinguishes a **NULL DACL** (no access
  restriction = full access for everyone) from an **empty DACL** (no
  access for anyone). The two cases mean the opposite and must be
  handled separately throughout the computation.
- `unsupported_aces` collects object / callback / conditional /
  vendor-specific ACEs the parser does not understand — counted for
  the `UnsupportedShareAces` marker.

### Permission result

```rust
struct EffectivePermission {
    identity: Identity,
    path: NormalizedPath,
    ntfs_mask: AccessMask,
    share_mask: Option<AccessMask>,
    effective_mask: AccessMask,         // = ntfs ∩ share (more restrictive)
    path_explanation: PermissionPath,
    share_status: ShareEvalStatus,
    local_group_status: LocalGroupEvalStatus,
    contributing_sids: Vec<Sid>,        // which token SIDs hit ACEs?
    unsupported_ace_count: usize,
    diagnostics: Vec<PermissionDiagnostic>,
}
```

`PermissionPath::steps` is a `Vec<String>` of explanation lines —
the human-readable proof of *why* the effective right came out the
way it did.

### Diagnostic markers

```rust
enum PermissionDiagnostic {
    NonCanonicalDaclOrder { at_index: usize },
    UnsupportedShareAces { count: usize },
    DomainGroupRecursionIncomplete,
    IdentityDisabled,
    IdentityNotInConfiguredLdapBase,
    IdentityDisabledStatusUnknown,
    IdentityLookupFailed { reason: String },
    GroupResolutionFailed { reason: String },
}
```

Variant-tagged — JSON serialisation produces
`{ "kind": "IdentityLookupFailed", "reason": "..." }`. This keeps the
export forward-compatible: new variants can be added without breaking
existing JSON consumers.

### Status enums vs. optional bools

Wherever a boolean decision has more than two states, Stars uses
enum status values. Examples:

```rust
enum ShareMaskStatus {
    NotApplicable,         // no SMB context (local path)
    Applied(AccessMask),   // share DACL read, mask computed
    Unrestricted,          // NULL DACL — share grants full access
    ReadFailed(String),    // read failed — incomplete trigger
}

enum LocalGroupEvalStatus {
    NotQueried,                // deliberately not queried
    Applied,                   // resolved successfully (0 or more groups)
    NotAvailable(String),      // resolution failed → incomplete
}
```

This separation is what enables the risk engine to distinguish "we
**did not** check" from "we checked and **found nothing**" — without
it, silent skips would be inevitable.

---

## 4. The overall data flow

```text
                      ┌─────────────────────────┐
   User inputs ────►  │  Validation             │
   (CLI args, GUI,    │  validation::*          │
    Slint events)     │  (trimming, typing)     │
                      └────────────┬────────────┘
                                   ▼
                      ┌─────────────────────────┐
   AD / LDAP, LSA, ─► │  Principal Pipeline     │
   SAM / NetAPI       │  ad_resolver::principal │  ───► PrincipalResolution
                      │  (backend traits)       │
                      └────────────┬────────────┘
                                   ▼
                      ┌─────────────────────────┐
   NTFS walker ────►  │  FileSystemObjects      │
   fs_scanner         │  (path + DACL + owner)  │
                      └────────────┬────────────┘
                                   ▼
                      ┌─────────────────────────┐
   Share DACL ────►   │  ShareMaskStatus        │
   share_scanner      │  + ShareTrusteeOverlay  │
                      └────────────┬────────────┘
                                   ▼
                      ┌─────────────────────────┐
                      │  Permission Engine      │
                      │  permission_engine      │  ───► EffectivePermission
                      │  (token + ACE walk)     │       (+ diagnostics)
                      └────────────┬────────────┘
                                   ▼
                      ┌─────────────────────────┐
                      │  Risk Engine            │
                      │  risk_engine            │  ───► RiskFinding
                      │  (6 rules + incomplete) │       (+ severity)
                      └────────────┬────────────┘
                                   ▼
                      ┌─────────────────────────┐
                      │  Persistence + Export   │
                      │  (SQLite, CSV, JSON,    │
                      │   HTML; CLI/GUI display)│
                      └─────────────────────────┘
```

Each stage consumes the previous stage's output — no stage reaches
"backward" into a later one. That makes the pipeline testable (each
stage in isolation) and parallelisable (one `EffectivePermission` per
path is independent of the next).

---

## 5. Identity resolution — the Principal pipeline

**Source:** [`crates/ad_resolver/src/principal.rs`](../crates/ad_resolver/src/principal.rs).
**Architecture rationale:** [ADR 0036](adr/0036-unified-principal-resolution-pipeline.md).

The Principal pipeline is the **single entry point** for every
identity resolution in Stars. It replaces five earlier side paths
with one shared logic.

### 5.1 Inputs

```rust
enum PrincipalInput {
    Auto(String),             // classify by syntax
    DomainQualified(String),  // "DOMAIN\\user"
    Upn(String),              // "user@domain.tld"
    SamAccount(String),       // "user"
    Sid(Sid),
    DisplayName(String),      // GUI identity picker
}
```

`PrincipalInput::Auto(...).classify()` trims and dispatches by
syntax — `\` → DomainQualified, `@` → Upn, `S-1-…` → Sid, otherwise
SAM.

### 5.2 Backend traits

The resolver consumes two abstract backends:

```rust
#[async_trait]
trait IdentityBackend: Send + Sync {
    async fn lookup_identity_by_sid(&self, sid: &Sid)
        -> Result<Option<Identity>, CoreError>;
    async fn lookup_identity_by_upn(&self, upn: &str)
        -> Result<Option<(Sid, Identity)>, CoreError>;
    async fn lookup_identities_by_sam(&self, sam: &str)
        -> Result<Vec<(Sid, Identity)>, CoreError>;
    async fn resolve_memberships(&self, sid: &Sid)
        -> Result<Vec<GroupMembership>, CoreError>;
}

trait LsaBackend: Send + Sync {
    fn lookup_sid_for_name(&self, name: &str) -> Result<Sid, CoreError>;
    fn lookup_account_for_sid(&self, sid: &Sid) -> Result<LsaAccountInfo, CoreError>;
}
```

**Production:** `LdapIdentityBackend` (delegates to `LdapResolver`) +
`WindowsLsaBackend` (Windows) or `NoLsaBackend` (non-Windows).

**Tests:** `FakeLdapBackend` + `FakeLsaBackend` with HashMap backing
— enable structural tests of every input/output combination without
a real DC.

### 5.3 Resolution status

```rust
enum IdentityScopeStatus {
    InsideConfiguredLdapBase,           // LDAP hit
    OutsideConfiguredLdapBase,          // LDAP miss + LSA hit (trust)
    OrphanedSid,                        // LDAP miss + LSA miss
    LookupFailed { reason: String },    // LDAP connection error
}

enum GroupResolutionStatus {
    LdapRecursive,                      // LDAP_MATCHING_RULE_IN_CHAIN
    SamFlat,                            // NetUserGetGroups (DC mode)
    Failed { reason: String },
    NotAttempted,
}

enum DisabledStatus {
    Known(bool),                        // userAccountControl read
    Unknown,                            // SAM path without NetUserGetInfo
}
```

### 5.4 The routing table

| Input | Path |
| --- | --- |
| `DomainQualified` / `DisplayName` | LSA → SID → `resolve_by_sid(sid)` |
| `Sid` | LDAP by SID → on miss + LSA available: LSA cross-check → build Outside identity |
| `Upn` | LDAP by UPN → on miss: **explicit error with GC hint** (no silent fallback!) |
| `SamAccount` | LDAP by SAM → uniqueness check (> 1 hit = error) |

The `Sid` route is the central knot — all input forms ultimately
funnel there and share the same LDAP / LSA cross-check.

### 5.5 Engine-flag derivation

```rust
impl PrincipalResolution {
    fn engine_flags(&self) -> EngineFlags {
        EngineFlags {
            identity_not_in_configured_ldap_base:
                matches!(self.scope_status, OutsideConfiguredLdapBase),
            identity_disabled_status_unknown:
                matches!(self.disabled_status, DisabledStatus::Unknown),
            group_resolution_via_sam_fallback:
                matches!(self.group_resolution_status, SamFlat),
            identity_lookup_failure_reason:
                match &self.scope_status {
                    LookupFailed { reason } => Some(reason.clone()),
                    _ => None,
                },
            group_resolution_failure_reason:
                match &self.group_resolution_status {
                    Failed { reason } => Some(reason.clone()),
                    NotAttempted if outside path => Some("group resolution skipped..."),
                    _ => None,
                },
        }
    }
}
```

`engine_flags()` is the **only official source** for the five flags
that flow into `PermissionEvaluationInput`. Callers (CLI + GUI)
derive their `PermissionEvaluationInput` directly from this method —
they do not reconstruct the flags from the status fields themselves.

### 5.6 Cache behavior

`LdapResolver::resolve_identity_internal` caches LDAP hits, but
**explicitly does not cache `Orphaned` identities**
(`crates/ad_resolver/src/resolver.rs` — fix from
[ADR 0036](adr/0036-unified-principal-resolution-pipeline.md)).
Otherwise a first LDAP miss would have prevented a later LSA
re-classification.

---

## 6. Permission engine — the AccessCheck reproduction

**Source:** [`crates/permission_engine/src/engine.rs`](../crates/permission_engine/src/engine.rs).

The permission engine reproduces Windows `AccessCheck` semantics,
extended with Stars-specific structured diagnostic markers.

### 6.1 Input

```rust
struct PermissionEvaluationInput {
    identity: Identity,
    group_memberships: Vec<GroupMembership>,
    file_system_object: FileSystemObject,
    share_status: ShareMaskStatus,
    local_group_sids: Vec<Sid>,
    local_group_status: LocalGroupEvalStatus,
    access_context: AccessContext,        // RemoteSmb / LocalInteractive / Unspecified
    unsupported_share_ace_count: usize,
    sid_names: BTreeMap<String, String>,  // SID → display name for the explanation path
    group_resolution_via_sam_fallback: bool,
    identity_not_in_configured_ldap_base: bool,
    identity_disabled_status_unknown: bool,
    identity_lookup_failure_reason: Option<String>,
    group_resolution_failure_reason: Option<String>,
}
```

Note: the input **consumes** the FSO — the engine does not need it
after evaluation; the report hangs off the result.

### 6.2 Step 1 — build the token SID set

`build_token_sids_with_context(sid, memberships, local_group_sids, access_context)`
builds the SID list Windows would write into the access token on
login:

1. The user SID itself.
2. All domain group SIDs from `memberships`.
3. All local server group SIDs from `local_group_sids`.
4. Universal well-knowns: `Everyone` (S-1-1-0),
   `Authenticated Users` (S-1-5-11).
5. **Context-specific well-knowns** from `access_context`:
   - `RemoteSmb` → `NETWORK` (S-1-5-2).
   - `LocalInteractive` → `INTERACTIVE` (S-1-5-4), `LOCAL` (S-1-2-0).
   - `Unspecified` → none.

This distinction is critical: an ACE on `NETWORK` only matches in
SMB evaluation, not in a local one. Stars must know the context to
be correct.

### 6.3 Step 2 — walk the DACL (allow before deny)

Windows evaluates DACLs in **stored order**, not in a canonicalised
one. Stars does the same:

```rust
let mut allow_mask = 0u32;
let mut deny_mask = 0u32;

for ace in dacl_iter {
    if !token_sids.contains(&ace.sid) { continue; }
    if !ace_applies_to_this_object(ace, is_dir) { continue; }
    match ace.kind {
        Allow => allow_mask |= ace.mask & !deny_mask,  // already denied stays denied
        Deny  => deny_mask  |= ace.mask & !allow_mask, // already allowed stays allowed
    }
}
let effective = allow_mask & !deny_mask;
```

Important: `Allow & !deny_mask` and `Deny & !allow_mask` implement
the Windows rule **"first match wins per bit"**. If a DACL contains
an explicit Allow before an inherited Deny, the Allow wins for those
specific bits — Stars produces the same result as AccessCheck.

`ace_applies_to_this_object()` checks the inheritance and propagation
flags:
- `OBJECT_INHERIT_ACE` (0x1) on files, `CONTAINER_INHERIT_ACE` (0x2)
  on dirs.
- `INHERIT_ONLY_ACE` (0x8) — does not apply to the current object,
  only to children.
- `NO_PROPAGATE_INHERIT_ACE` (0x4) — halts further inheritance
  (Stars notes this in the explanation, not in the current mask).

### 6.4 Step 3 — non-canonical DACL detection

`first_non_canonical_position(dacl)` checks whether the ACE order
matches the Windows canonical form (Deny-explicit, Allow-explicit,
Deny-inherited, Allow-inherited). On deviation
`PermissionDiagnostic::NonCanonicalDaclOrder { at_index }` is pushed.

This is not `incomplete = true` — the computation agrees with Windows,
but the auditor should know the ACL is "unusually" sorted (often a
sign of manual intervention).

### 6.5 Step 4 — owner rights

If `identity.sid == owner_sid`, the engine implicitly adds
`READ_CONTROL` and `WRITE_DAC` to the effective right — owners
always have the right to see and change the DACL in Windows,
regardless of the DACL itself.

### 6.6 Step 5 — intersect with the share mask

If `share_status = Applied(share_mask)`, the effective right is **the
more restrictive** of the two (`effective & share_mask`). For
`Unrestricted` (NULL share DACL) the share side is ignored (= full
access via the share). For `ReadFailed` the NTFS mask stays as-is
and the `incomplete` marker fires.

### 6.7 Step 6 — push markers

```rust
if input.unsupported_share_ace_count > 0 {
    diagnostics.push(UnsupportedShareAces { count: ... });
}
if input.group_resolution_via_sam_fallback {
    diagnostics.push(DomainGroupRecursionIncomplete);
}
if input.identity.disabled {
    diagnostics.push(IdentityDisabled);
}
if input.identity_not_in_configured_ldap_base {
    diagnostics.push(IdentityNotInConfiguredLdapBase);
}
if input.identity_disabled_status_unknown {
    diagnostics.push(IdentityDisabledStatusUnknown);
}
if let Some(reason) = input.identity_lookup_failure_reason {
    diagnostics.push(IdentityLookupFailed { reason });
}
if let Some(reason) = input.group_resolution_failure_reason {
    diagnostics.push(GroupResolutionFailed { reason });
}
```

Plus the non-canonical marker from step 4. Each marker that is an
incomplete trigger is later matched by the risk engine (see
chapter 10).

### 6.8 Step 7 — build the explanation path

`PermissionPath::steps` is populated in parallel with mask computation:

```text
- User S-1-5-21-...-1001 (CORP\alice)
- Member of S-1-5-21-...-1100 (CORP\Domain Users) [direct, source: LDAP_MATCHING_RULE_IN_CHAIN]
- Member of S-1-5-32-545 (BUILTIN\Users) [via local server group chain]
- Allow ACE for S-1-5-32-545 → Read,Execute (inherited from C:\)
- Effective: Read,Execute (0x001200A9)
```

`sid_names` is built up front from the membership names and the
DACL trustee SIDs — one LSA call per unique SID, deduplicated across
the whole scan.

---

## 7. Share DACL ∩ NTFS DACL

**Source:** [`crates/share_scanner/src/scanner.rs`](../crates/share_scanner/src/scanner.rs)
and [`crates/permission_engine/src/engine.rs`](../crates/permission_engine/src/engine.rs).

SMB access is **restrictive**: a user may only do what **both** share
and NTFS DACL allow at the same time. Stars builds this intersection
in three steps:

### 7.1 Read the share DACL

`share_scanner::get_share_dacl(server, share_name)`:

1. Connects to the `server` (`NetShareGetInfo` level 502).
2. Reads the share's security descriptor.
3. Parses the DACL into `ShareDacl::Acl(Vec<SharePermission>)` or
   `ShareDacl::NullDacl`.
4. Counts unsupported ACE types (`unsupported_count`).

Returns: `ShareDaclScan { dacl, unsupported_count }`.

### 7.2 Compute the share mask

`effective_share_mask(share_dacl, token_sids)`:

- For `NullDacl`: `None` (= full access via the share, signalled via
  `ShareMaskStatus::Unrestricted`).
- For `Acl`: same allow/deny logic as for NTFS, using the user's
  token SIDs.

### 7.3 Forward the ShareMaskStatus

The mask is passed to the engine as a `ShareMaskStatus`:

```rust
enum ShareMaskStatus {
    NotApplicable,         // local path, no UNC, no --smb-server
    Applied(AccessMask),   // read + computed successfully
    Unrestricted,          // NULL DACL — share grants everything
    ReadFailed(String),    // get_share_dacl failed → incomplete trigger
}
```

The engine sets the effective right accordingly:
- `NotApplicable` → `share_mask = None`, no intersect.
- `Applied(m)` → `effective = ntfs & m`.
- `Unrestricted` → `effective = ntfs` (share is wider than NTFS).
- `ReadFailed` → `effective = ntfs` plus the incomplete marker; the
  real value could be more restrictive, but Stars cannot know.

### 7.4 Share trustees in the report

For the "who can access?" trustee view the GUI worker builds the
`ShareTrusteeOverlay` **once per share** before the scan
([ADR 0038](adr/0038-share-trustees-in-scan-output.md)):

```rust
struct ShareTrusteeOverlay {
    trustees: Vec<PathTrustee>,  // all TrusteeCategory::Share
}

// per path:
let raw_trustees = build_path_trustees_with_share(&fso, share_overlay.as_ref());
```

Every path then carries the NTFS trustees from its DACL **plus** the
share trustees from the share DACL, separated via the
`TrusteeCategory::{Ntfs, Share}` column.

---

## 8. Local server groups and the candidate list

**Source:** [`crates/ad_resolver/src/local_groups.rs`](../crates/ad_resolver/src/local_groups.rs).
**Architecture rationale:** [ADR 0040](adr/0040-local-group-candidate-name-list.md).

Local server groups (`BUILTIN\Administrators`, locally defined
groups) are essential for correct token construction — and
historically one of the most common silent gaps in permission tools.

### 8.1 The problem

`NetUserGetLocalGroups` expects an account name. Which form is
correct?

- For domain-joined users with a UPN: `user@dns.suffix` works.
- For NetBIOS-domain trust identities: `user@TRUSTED` fails (not a
  valid UPN suffix). `TRUSTED\user` works.
- For local accounts: `user` alone.

Up to v1.5.2 Stars blindly built `name@domain` — for NetBIOS-domain
identities from the LSA / trust path that regularly produced
`NERR_USER_NOT_FOUND`, which was **silently** interpreted as
`Ok(Vec::new())`. Result: ACEs on local server groups invisible, no
`incomplete` marker.

### 8.2 The candidate list

`format_account_candidates_for_local_groups(identity)` returns a
list in preference order:

```rust
1. identity.user_principal_name              // real UPN (when AD has it)
2. format!("{domain}\\{name}")                // works for all domain types
3. format!("{name}@{domain}")                 // ONLY when looks_like_dns_domain(domain)
4. name                                       // local accounts
```

`looks_like_dns_domain(domain)` is the heuristic:

```rust
fn looks_like_dns_domain(domain: &str) -> bool {
    domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}
```

A NetBIOS name like `TRUSTED` contains no dot → the UPN form is
**not** added to the list → no misleading `alice@TRUSTED` attempt.

### 8.3 Strict variant + outcome type

```rust
enum LocalGroupLookupOutcome {
    WithGroups(Vec<Sid>),     // account found, here are the groups
    UserNotFoundOnServer,     // NERR_USER_NOT_FOUND
}

fn resolve_local_group_sids_strict(server, account)
    -> Result<LocalGroupLookupOutcome, CoreError>
```

This separation is what the candidate loop needs: only with it can
the caller distinguish "account found, 0 groups" (= a valid result)
from "account not recognised" (= try the next candidate).

### 8.4 The identity wrapper

`resolve_local_group_sids_for_identity(server, identity)` is the
**honest** function the CLI and GUI call:

```rust
for candidate in candidates {
    match resolve_local_group_sids_strict(server, &candidate)? {
        WithGroups(sids) => return Ok(sids),       // first hit
        UserNotFoundOnServer => continue,          // next
    }
}
// when ALL NotFound:
Err(CoreError::Validation(format!(
    "NetUserGetLocalGroups: account for identity {} not known on {server:?} \
     (tried forms: {:?}). Local server group memberships are not available; \
     the result is marked incomplete.",
    identity.sid.0, tried
)))
```

Callers set the `Err` as
`LocalGroupEvalStatus::NotAvailable(reason)` → the risk engine
flags `incomplete = true`. **No silent skips.**

### 8.5 Backward compatibility

The old API `resolve_local_group_sids()` is preserved — it still
treats `NERR_USER_NOT_FOUND` as `Ok(Vec::new())`, but is only used by
external consumers. Internally all callers go through the identity
wrapper.

---

## 9. The diagnostic marker system

**Source:** [`crates/core/src/model.rs`](../crates/core/src/model.rs)
(enum) +
[`crates/permission_engine/src/engine.rs`](../crates/permission_engine/src/engine.rs)
(push) +
[`crates/risk_engine/src/rules.rs`](../crates/risk_engine/src/rules.rs)
(matching).

The marker system is the central architecture that makes Stars
auditable at all. It works in three layers:

### 9.1 Data layer — variant-tagged enum

```rust
#[serde(tag = "kind")]
enum PermissionDiagnostic {
    NonCanonicalDaclOrder { at_index: usize },
    UnsupportedShareAces { count: usize },
    DomainGroupRecursionIncomplete,
    IdentityDisabled,
    IdentityNotInConfiguredLdapBase,
    IdentityDisabledStatusUnknown,
    IdentityLookupFailed { reason: String },
    GroupResolutionFailed { reason: String },
}
```

The `tag = "kind"` attribute serialises as:

```json
{ "kind": "IdentityLookupFailed", "reason": "LDAP bind failed: connection refused" }
```

New variants can be added without breaking JSON consumers — they
just see a new `kind` and can ignore or handle it.

### 9.2 Engine layer — push from flags

`PermissionEvaluationInput` carries **the flags** that `engine_flags()`
derived from the `PrincipalResolution` status. The engine pushes the
matching marker per flag (see chapter 6.7).

The strict rule here: **no marker arises in the engine without a
corresponding input.** When a marker is missing, you don't debug the
engine — you debug the caller (CLI / GUI) that failed to forward the
flags correctly from `engine_flags()`.

### 9.3 Risk layer — incomplete classification

`risk_engine::is_incomplete(p: &EffectivePermission)` is the
**authoritative source** for whether a finding is marked
`incomplete = true`:

```rust
fn is_incomplete(p: &EffectivePermission) -> bool {
    matches!(p.share_status, ShareEvalStatus::ReadFailed(_))
        || p.unsupported_ace_count > 0
        || matches!(p.local_group_status, LocalGroupEvalStatus::NotAvailable(_))
        || p.diagnostics.iter().any(|d| matches!(d,
            PermissionDiagnostic::UnsupportedShareAces { .. }
            | PermissionDiagnostic::DomainGroupRecursionIncomplete
            | PermissionDiagnostic::IdentityNotInConfiguredLdapBase
            | PermissionDiagnostic::IdentityLookupFailed { .. }
            | PermissionDiagnostic::GroupResolutionFailed { .. }
        ))
}
```

Deliberately **not** matched:

- `IdentityDisabled` — the ACL evaluation is complete; only the
  authentication ability is restricted. That is an **informational**
  statement, not a completeness gap.
- `IdentityDisabledStatusUnknown` — orthogonal to permission
  computation.
- `NonCanonicalDaclOrder` — Windows AccessCheck works correctly on
  the stored order; Stars reproduces that exactly.

This separation is the productive substance of the marker system —
an auditor distinguishes what Stars *did not know* (= please
investigate) from what Stars *knew and reported* (= the Stars finding
is final).

### 9.4 Renderer layer

CLI (`crates/cli/src/output.rs`), HTML
(`crates/exporter/src/html.rs`), and JSON
(`crates/exporter/src/json.rs`) render each marker with its own
description. Markers with a `reason` field have the text rendered
along (HTML-escaped in the HTML path).

### 9.5 Consistency obligation

When `PermissionDiagnostic` is extended with a variant, the following
must be updated **at the same time**:

- `risk_engine::is_incomplete()` (if it's an incomplete trigger).
- Renderers in `cli::output`, `exporter::html`, `exporter::json`.
- Marker table in `docs/features-and-limitations.md`.
- Marker tables in `docs/anwender-handbuch.md` and
  `docs/user-guide.md`.
- `docs/audit-kriterien.md` (DE + EN incomplete sections).

This list is the contribution policy recorded in
`docs/audit-kriterien.md` and in every ADR introducing a new marker.

---

## 10. Risk engine — from permission to audit finding

**Source:** [`crates/risk_engine/src/rules.rs`](../crates/risk_engine/src/rules.rs).
**Domain rationale:** [`docs/audit-kriterien.md`](audit-kriterien.md).

The risk engine consumes `Vec<EffectivePermission>` and produces
`Vec<RiskFinding>`.

### 10.1 Architecture

```rust
trait RiskRule {
    fn evaluate(&self, context: &RiskContext) -> Vec<RiskFinding>;
}

struct RuleRegistry {
    rules: Vec<Box<dyn RiskRule>>,
}

impl RuleRegistry {
    fn with_defaults() -> Self {
        let mut r = Self::new();
        r.register(Box::new(FullControlRule));
        r.register(Box::new(WriteAccessRule));
        r.register(Box::new(AdminRightsRule));
        r.register(Box::new(BroadGroupWriteRule));
        r.register(Box::new(DirectUserAceRule));
        r.register(Box::new(SensitivePathRule));
        r
    }
}
```

A rule reads `context.findings`, filters by its criterion, and
produces one `RiskFinding` per hit:

```rust
struct RiskFinding {
    severity: RiskSeverity,    // Critical | High | Medium | Low | Info
    rule_id: String,           // "FULL_CONTROL", "BROAD_GROUP_WRITE", …
    identity: Identity,
    path: NormalizedPath,
    rights: AccessMask,
    explanation: String,
    incomplete: bool,          // from is_incomplete(p)
}
```

### 10.2 The six rules

| Rule | Severity | Trigger |
| --- | --- | --- |
| `FullControlRule` | Critical | Effective mask contains `MASK_FULL_CONTROL` bits |
| `WriteAccessRule` | High | Effective mask has write-specific bits (`MASK_WRITE & !MASK_READ`) |
| `AdminRightsRule` | High | `FILE_WRITE_DAC`, `FILE_WRITE_OWNER` individually present |
| `BroadGroupWriteRule` | Critical | Write right via `Everyone`, `Authenticated Users`, `Anonymous Logon` |
| `DirectUserAceRule` | Low | ACE directly on the user SID (not via a group) |
| `SensitivePathRule` | Critical/High/Medium | Path contains sensitive keywords (`password`, `credentials`, …) |

`SensitivePathRule` is the only one whose severity is *dynamically*
derived from the effective right — Full Control on a
`passwords.txt` is Critical, Read on the same file is Medium.

### 10.3 `incomplete = true`

Every rule calls `is_incomplete(&p)` and writes the result into the
`RiskFinding`. CLI, HTML, and JSON sort and render findings
differently when `incomplete` is set — typically with an additional
hint at the finding.

### 10.4 Audit criteria

The document [`docs/audit-kriterien.md`](audit-kriterien.md) holds
the domain logic:
- Who may have which rights on which path class.
- Who should *not* have which rights on which path class.
- How severities are derived.

The risk rules implement what that document specifies — when the
document and code disagree, the document wins (it is the domain
specification).

---

## 11. Threading model — GUI / CLI / engine

### 11.1 CLI

The CLI uses `tokio` as its runtime:

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> { ... }
```

The **walker** (`fs_scanner::walk_tree`) is blocking (Windows APIs
are sync), so it runs on a `tokio::task::spawn_blocking` thread. A
`tokio::spawn` catches `Ctrl-C` and sets a `CancellationToken` that
the walker checks periodically.

LDAP calls (`ldap3`) are genuinely async — they run directly on the
main tokio pool.

### 11.2 GUI

The GUI uses **Slint** for the surface and **`std::sync::mpsc`
channels** for worker communication:

```rust
// GUI thread (Slint event loop):
let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<WorkerCommand>();
let (evt_tx, evt_rx) = std::sync::mpsc::channel::<WorkerEvent>();

// Worker thread:
std::thread::spawn(move || {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        loop {
            match cmd_rx.recv() {
                Ok(WorkerCommand::Analyze { ... }) => { ... }
                Ok(WorkerCommand::Scan { ... }) => { ... }
                ...
            }
        }
    });
});
```

The GUI **never blocks** on a running scan — it receives
`WorkerEvent::ScanItem` events from the worker and updates the Slint
models.

A `CancellationToken` from `fs_scanner` is shared with the worker
and triggered via a `WorkerCommand::Cancel`.

### 11.3 Engine

The engine itself is **sync and single-threaded per call** — one
`EffectivePermission` per path. Parallelism happens at the caller
level: each path is independent and the walker could in theory feed
them to the engine in parallel (it currently doesn't, because the
LSA lookup for `sid_names` is cached globally).

---

## 12. Persistence and export

### 12.1 SQLite scan history

**Source:** [`crates/persistence/src/scan_store.rs`](../crates/persistence/src/scan_store.rs)
and [`crates/persistence/src/migrations.rs`](../crates/persistence/src/migrations.rs).

Schema (simplified):

```sql
CREATE TABLE scan_runs (
    run_id TEXT PRIMARY KEY,         -- UUID
    timestamp TEXT NOT NULL,
    root_path TEXT NOT NULL,
    cancelled INTEGER NOT NULL
);

CREATE TABLE scan_permissions (
    run_id TEXT NOT NULL,
    path TEXT NOT NULL,
    identity_sid TEXT NOT NULL,
    effective_mask INTEGER NOT NULL,
    ntfs_mask INTEGER NOT NULL,
    share_mask INTEGER,
    diagnostics_json TEXT NOT NULL,  -- variant-tagged JSON
    FOREIGN KEY (run_id) REFERENCES scan_runs(run_id)
);

CREATE TABLE scan_errors (
    run_id TEXT NOT NULL,
    path TEXT,
    message TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES scan_runs(run_id)
);
```

Migrations are versioned and transactional. At every start
`Database::open` checks the schema version and runs the necessary
migration steps.

### 12.2 Delta comparison

`ScanStore::compute_delta(run_a, run_b)` joins two runs per path and
returns the before/after effective masks per path. The GUI filters
out paths without change client-side.

### 12.3 Export formats

**CSV** (`crates/exporter/src/csv.rs`):
- Path per row.
- Diagnostic markers as comma-separated variant names
  (`"IdentityDisabled,IdentityLookupFailed"`).
- Designed for Excel / pivot.

**JSON** (`crates/exporter/src/json.rs`):
- Full variant-tagged output.
- `reason` texts preserved.
- Designed for SIEM, scripts, custom tooling.

**HTML** (`crates/exporter/src/html.rs`):
- Fully formatted report with tabs:
  - Risk findings (sorted by severity).
  - Trustee table per path (NTFS + Share separated).
  - Scan errors in their own section.
- Diagnostic markers as coloured badges (`badge-high`,
  `badge-medium`, `badge-info`) with tooltip text.

---

## 13. Validation at system boundaries

**Source:** [`crates/validation/`](../crates/validation/).

Every user input — CLI argument, GUI field, config file value — is
converted into a typed wrapper at the system boundary:

```rust
struct ValidatedSid(pub String);              // matches S-1-...
struct ValidatedServerName(pub String);       // hostname check
struct ValidatedShareName(pub String);        // SMB share name check
struct ValidatedDn(pub String);               // LDAP DN check
struct ValidatedIdentityQuery(pub String);    // GUI search input
struct ValidatedExportPath(pub PathBuf);      // path safety
struct ValidatedDbPath(pub PathBuf);
struct ScanDepth(pub u32);
```

All `validate_*` functions **trim whitespace** and check format.
The wrapper types are then passed to LDAP / NetAPI / SQLite / file
APIs — **never the raw strings**.

### 13.1 The pair obligation

`gui::worker::normalize_smb_pair(smb_server, share_name)` and its
CLI counterpart enforce that the two SMB fields are set **as a pair**.
Single values produce a validation error — not a silent "use only
one" ([ADR background: ChatGPT review round 2 finding 2 and round 4
finding 3](../review.md)).

### 13.2 Path normalisation

`validate_path(path)` returns a `NormalizedPath` with:
- whitespace trimmed,
- canonicalised long-path form (`\\?\C:\…`, `\\?\UNC\…`),
- invalid characters rejected.

The `NormalizedPath` flows through the entire pipeline — the walker,
the engine, and persistence all see the same value. Stars long
suffered from the "validate, then forward the raw value" anti-pattern
— see ADR 0037 for the consolidation.

---

## 14. Test architecture

### 14.1 Three test layers

1. **Unit tests** in every module (`#[cfg(test)] mod tests`).
   Cover engine logic, validations, marker system. Run in
   `cargo test --workspace` — currently ~485 tests, all green.

2. **Fake-based integration** in
   [`crates/ad_resolver/src/principal.rs`](../crates/ad_resolver/src/principal.rs).
   `FakeLdapBackend` + `FakeLsaBackend` with HashMap backing enable
   structural tests of the Principal pipeline:
   - DOMAIN\user → LDAP hit
   - DOMAIN\user → LDAP miss + LSA hit (multi-domain)
   - Direct SID → LDAP miss + LSA hit
   - GUI name → SID → LDAP miss + LSA hit
   - UPN → outside configured base
   - Unknown SID → LDAP miss + LSA miss
   - LDAP bind error → LookupFailed
   - Group resolution error after identity hit
   - Outside path + skipped groups
   - Ambiguous SAM → uniqueness error

3. **Live integration** as `#[ignore]` tests.
   Run with `cargo test -- --ignored` against a real Windows / AD
   environment. Cover `NetUserGetLocalGroups`,
   `NetLocalGroupGetMembers`, and real LDAP binds.

### 14.2 Engine test pattern

Engine tests construct synthetic `FileSystemObject`s and
`PermissionEvaluationInput`s directly:

```rust
#[test]
fn deny_before_allow_wins() {
    let fso = fso(None, vec![
        deny_ace(USER, MASK_WRITE, false),
        allow_ace(USER, MASK_READ | MASK_WRITE, false),
    ]);
    let result = DefaultPermissionEngine
        .evaluate(input_for(user(USER), fso))
        .unwrap();
    assert_eq!(result.effective_mask.0, MASK_READ);  // Write denied
}
```

These tests cover the AccessCheck reproduction — also non-canonical
DACLs, NULL DACLs, inherit-only ACEs, owner-rights implication.

### 14.3 Marker consistency tests

For every engine marker there is a test that sets the
`Some(reason)` / `true` input directly and verifies the marker
lands in the diagnostics vector. For every risk-engine marker there
is a test that asserts the `incomplete = true` behavior. Negative
tests (informational markers must **not** count as incomplete) are
explicit:

```rust
#[test]
fn full_control_does_not_mark_incomplete_on_disabled_status_unknown_alone() {
    let mut p = perm(USER_SID, MASK_FULL_CONTROL, r"C:\data", vec![]);
    p.diagnostics.push(PermissionDiagnostic::IdentityDisabledStatusUnknown);
    let r = FullControlRule.evaluate(&ctx(vec![p]));
    assert!(!r[0].incomplete);
}
```

---

## 15. Update manager

**Source:** [`crates/update_manager/`](../crates/update_manager/).
**Architecture rationale:** ADR 0028, ADR 0030.

The update manager is in place as a **skeleton** — path validation,
signature schema, and migration hooks are implemented; automatic
update logic itself is not.

Currently:
- Installer updates are manual through the user.
- SQLite schema migrations run automatically at `Database::open` —
  versioned, transactional, with rollback on error.
- Update paths are validated (`validation::path::*`) so an attacker
  cannot do UNC-path substitution.

Planned for future versions:
- Signature verification on signed update packages.
- Configurable update source (local file, internal HTTPS URL).
- Rollback mechanism on failed installation.

---

## 16. Further reading

- **[User Guide](user-guide.md)** — GUI / CLI walkthrough.
- **[Features and limits](features-and-limitations.md)** — full list
  (German) of what Stars reliably handles.
- **[Known limitations and roadmap](known-limitations.md)** —
  structural gaps Stars flags but does not resolve.
- **[Audit criteria](audit-kriterien.md)** — domain evaluation rules,
  severities, optimal rights per role.
- **[ADRs](adr/)** — Architecture Decision Records with rationale
  and consequences.
- **[review.md](../review.md)** (gitignored) — record of ChatGPT
  review rounds 1–5 with status tables.

## Deutsche Version

Eine deutsche Fassung dieser technischen Dokumentation liegt unter
**[technische-dokumentation.md](technische-dokumentation.md)**.
