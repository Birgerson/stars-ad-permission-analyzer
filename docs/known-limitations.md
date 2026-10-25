# Stars — Known Limitations and Roadmap (v1.6+)

**Status:** v1.18.0
**Purpose:** Honest enumeration of the places where Stars **structurally
cannot guarantee** to deliver a complete picture.

Stars is and remains a read-only analysis tool. This file describes
areas where the current implementation **detects** that something is
missing (`incomplete = true`) but **cannot productively resolve** the
missing knowledge. Each limitation is its own entry so future
contributions can address them individually.

> **Relationship to the marker table in
> [features-and-limitations.md](features-and-limitations.md):** The
> markers documented there (`IdentityNotInConfiguredLdapBase`,
> `IdentityLookupFailed`, `GroupResolutionFailed`, …) make the gaps
> described here **visible**. This file describes *what* structural
> gaps Stars has; the marker table describes *how* they appear in a
> finding.

---

## L1 — Foreign Security Principals (FSP) are not explicitly recognized

**Priority:** High
**Tracking:** **closed 2026-06-11 — shipped (v1.6+)**
**References:** ADR 0036 (extension point), ADR 0034

> **Status update (2026-06-11):** implemented. The LDAP SID search finds
> the FSP object (its `objectSid` is the trust SID and the
> `CN=ForeignSecurityPrincipals` container lives inside `base_dn`); the
> principal resolver now recognizes `objectClass=foreignSecurityPrincipal`
> (`IdentityKind::ForeignSecurityPrincipal`), enriches the identity via
> LSA reverse lookup (real name / domain / kind from the trust), resolves
> home-domain groups through the FSP DN, reports the disabled state
> honestly as Unknown (the FSP carries no `userAccountControl`), and
> pushes the structured marker
> `IdentityResolvedViaForeignSecurityPrincipal`. The marker is an
> incompleteness trigger — the principal's memberships in its **own
> forest** remain unknown (that part needs a trust-side query, see L2).
> Worse than documented below: pre-fix, an existing FSP was an LDAP *hit*
> classified `Unknown` with the raw SID as display name, scope
> `InsideConfiguredLdapBase`, and **no marker at all** — silently
> incomplete. Covered by fake-backend, engine, and risk-rule tests.

### Problem

In multi-domain forests or inter-forest trusts, trust principals are
represented in the home domain as a **Foreign Security Principal (FSP)**
in the container `CN=ForeignSecurityPrincipals,DC=…`. The FSP object
carries the trust SID as `objectSid`, but the membership schema runs
through the FSP object, not through the user object in the trust domain.

Current Stars path for a trust SID:

1. LDAP search by `objectSid` in the configured `base_dn` → miss (the
   FSP lives in a different LDAP subtree).
2. LSA reverse lookup → hit.
3. → `IdentityScopeStatus::OutsideConfiguredLdapBase` + marker.

Stars therefore does **not** see that a local home-domain group (e.g.
`Domain Admins` of the home domain) holds the FSP as a member. Such
group ACEs effectively apply to the trust user but are not evaluated.

### Effect

Findings understate the rights of the trust user in the home domain.
Markers (`IdentityNotInConfiguredLdapBase`, `GroupResolutionFailed`)
are set — the auditor knows something is missing — but Stars does not
show *which* home-domain groups grant the user access via FSP.

### Solution sketch

- On `OutsideConfiguredLdapBase`, additionally search the
  `CN=ForeignSecurityPrincipals` container of the configured home
  domain by `objectSid`.
- On hit: recursively resolve the FSP object's memberships (LDAP
  `memberOf` on the FSP object → home-domain groups).
- New diagnostic marker `IdentityResolvedViaForeignSecurityPrincipal`
  or `IdentityScopeStatus::OutsideConfiguredLdapBaseViaFsp`.
- Add memberships (do not replace) — Stars still does not know
  trust-domain groups.

### Test plan

Extend the LDAP fake by an FSP container and a home-domain group that
contains the FSP as member. Expectation: `engine_flags` contain the
home-domain group, new marker appears.

---

## L2 — Global Catalog (GC) bind is not supported

**Priority:** High
**Tracking:** **closed 2026-06-11 — shipped (v1.6+)**
**References:** ADR 0034, features-and-limitations.md section 2

> **Status update (2026-06-11):** implemented. `LdapConfig` gains
> `new_global_catalog` (port 3269 LDAPS) and
> `new_global_catalog_insecure` (port 3268); an empty `base_dn` is
> permitted in GC mode (searches all forest partitions). The CLI
> exposes `--global-catalog`; `--base-dn` becomes optional with it.
> Identity lookups (SID, UPN) are forest-wide — the UPN miss error in
> GC mode now says "the search was forest-wide" instead of
> recommending the flag that is already active. **Honest caveat:**
> only universal group memberships replicate fully to the GC; global
> and domain-local memberships of foreign domains can be missing.
> Stars therefore pushes the structured marker
> `GroupResolutionViaGlobalCatalog` on every GC-resolved finding and
> the risk engine flags them `incomplete = true`. Covered by config,
> fake-backend, engine, and risk-rule tests. The GUI exposes GC as a
> fourth LDAP mode ("Global Catalog — forest-wide, port 3269") since
> v1.6.4.

### Problem

UPN lookups and SID searches are only forest-wide unique in Active
Directory when binding against the **Global Catalog (port 3268)**.
Stars currently uses only the regular LDAP port (389/636) and thus
searches only inside the configured domain.

Stars *documents* the GC workaround:
- ADR 0034 mentions it.
- The UPN error text explicitly says "bind against a Global Catalog
  (port 3268)".
- features-and-limitations.md references `gc://…:3268/…`.

But Stars does *not implement* it — the user has to manually run a
second Stars analysis with the `base_dn` of the partner domain.

### Effect

Multi-domain audits currently need either multiple Stars runs or yield
incomplete results. Both are marked (incomplete), but both are
uncomfortable.

### Solution sketch

- New config mode "GC" in `LdapConfig` (port 3268, empty `base_dn`
  permitted).
- `PrincipalResolver` recognizes GC mode and skips the
  `OutsideConfiguredLdapBase` classification because the GC indexes
  forest-wide.
- Adjust documentation in features-and-limitations.md.

### Test plan

Live test against a DC with the GC role (no fake backend needed
because the LDAP protocol is the same — only port and scope change).

---

## L3 — SID History evaluation

**Priority:** Medium
**Tracking:** **closed 2026-07-04 — user history (ADR 0056) and group
history (ADR 0059) both shipped**

> **Status update (2026-07-04, ADR 0059 — closes the remainder):** the
> **groups'** `sIDHistory` values are now read from the same transitive
> membership search that already returns every group entry
> (`MEMBERSHIP_ATTRS` + shared `parse_sid_history`), carried on
> `GroupMembership` (count/values pair like on `Identity`), and evaluated
> into the token — an ACE on a migrated group's old SID matches (Allow and
> Deny) for every member. The membership step in the explanation names
> each group historical SID; `GroupSidHistoryEvaluated { groups, count }`
> (informational) and `GroupSidHistoryPresent { count }` (incompleteness,
> unparseable remainder) mirror the user-level split. SAM/LSA fallback
> cannot read the attribute (0 — that path already carries the
> recursion-incomplete marker); local server groups have no `sIDHistory`
> (0 is exact). The foreign-forest trust caveat (M.5) applies to group
> history exactly as to user history and remains L4 work.

> **Status update (2026-07-04, ADR 0056):** the **user's** `sIDHistory`
> values are now parsed on the direct in-base LDAP path and **evaluated
> into the token**: an ACE on the old SID matches (Allow and Deny), the
> explanation path names each historical SID, and the finding carries the
> informational `SidHistoryEvaluated { count }` marker instead of being
> flagged incomplete. `SidHistoryPresent { count }` narrows to the
> un-evaluated remainder (a malformed value, or reports persisted before
> ADR 0056) and stays an incompleteness trigger. The share-side token uses
> the same history SIDs, so NTFS and share evaluation cannot diverge.
> Identities resolved via SAM/LSA or as an FSP still cannot read the
> attribute (count 0 — no false positives; their own boundary markers
> apply). This closed exactly the deep-review 2026-07-04 finding F1
> acceptance case: `S-new` + `sIDHistory = [S-old]` + ACL `S-old: Modify`
> → Modify, explained, complete. **Live-proven the same day** against the
> lab (`mig01`/`_OldSid`, verification.md Block M): Modify via the injected
> historical SID, matching the Windows runtime truth in the current
> (history-honoring) trust state. Block M.5 records the honest caveat: a
> *foreign-forest-sourced* history SID on an in-base account is honored by
> Windows only while the trust's `/EnableSIDHistory` allows it — if the
> trust filters, Stars overstates and no trust marker fires (the identity
> is in-base). That edge belongs to the L4 trust-modeling gap below.

### Problem

In domain migration scenarios, users **and groups** carry the
`sIDHistory` attribute, which contains earlier SIDs from migrated
domains. NTFS DACLs that were not migrated along still reference these
old SIDs — the Windows logon token includes them, so they grant access
at runtime.

### Resolution (both halves shipped)

- **User history (ADR 0056):** parsed on the direct in-base LDAP path,
  evaluated into the token, explanation step per SID, live-proven
  (verification.md Block M).
- **Group history (ADR 0059):** parsed from the transitive membership
  entries, carried on `GroupMembership`, evaluated into the token,
  membership step names the group's old SIDs; covered by engine /
  model / principal / risk tests mirroring the user-history suite.
- The membership **cache** deliberately does not store history (like
  names and paths, it is a live-resolution concern; the cache only
  carries topology and does not feed evaluation).

---

## L4 — Cross-forest trust effects are not modelled

**Priority:** Medium
**Tracking:** v1.7+ candidate
**References:** L1, L2

### Problem

Forest trusts have configuration options that take effect at runtime
at the DC:

- **Selective Authentication** (also "Authentication Firewall"): the
  trust user may only authenticate against specific servers — even if
  the DACL grants rights, the user cannot log on.
- **SID Filtering / Quarantine**: certain SIDs from the trust are
  ignored (protection against SID spoofing).

Stars sees the raw DACL and computes what it *theoretically* grants.
What the real DC actually filters at runtime is invisible to Stars.

### Effect

Stars findings for trust users can be **too high** — the DACL would
grant, but Selective Auth or SID Filtering block at runtime.

**Status (ADR 0052 — visibility step):** the gap is now **visible**. When
the identity is resolved across a domain/trust boundary (via an FSP, or
found outside the configured LDAP base), Stars emits the informational
`TrustBoundaryEffectsNotModeled` marker, warning that *if* the boundary is a
forest trust, SID filtering / quarantine and Selective Authentication may
reduce the shown access. (For a purely intra-forest cross-domain identity
those filters usually do not apply, so the marker is then only a
precautionary note.)

**Status (ADR 0060 — read-only trust inventory):** Stars now **reads** the
domain's `trustedDomain` objects and displays each trust's `trustDirection`
and decoded `trustAttributes` — including whether **SID filtering /
quarantine** or **Selective Authentication** is configured — via the new
read-only `adpa trusts` command. This gives an auditor the exact facts needed
to apply the L4 caveat by hand. **Live-verified 2026-07-23** (verification.md
Block O.2): against a real external trust with SID filtering enabled
(`trustAttributes = 0x4`), `adpa trusts` read the trust and fired the
SID-filtering over-report warning. Stars still does **not** *model* the runtime
filter effect on a specific finding (that needs a synthetic logon — out of
scope, see below), nor does it yet auto-cross-reference a token's
foreign-forest history SIDs against a filtering trust (the M.5 per-finding
edge). Those remain the deeper follow-ups.

**Status (ADR 0079 — Selective Authentication modelled, 2026-10-17):** for
an account of a trusted domain resolved through the trusted-domain
connection (ADR 0078), Stars reads the DACL of the target server's computer
object and evaluates "Allowed to authenticate" for the token Windows uses in
that check (measured with real SMB logons: the account's groups from its
domain, the domain-local groups of this domain, Everyone, Authenticated
Users and `Other Organization` count; the builtin groups of this domain,
`NETWORK` and `This Organization` do not). Result: allowed (normal result),
denied (**No access**, error 1935) or not determinable (named reason, range
from No access). `This Organization` / `Other Organization` are exact for
such accounts. Still not modelled: the SID filtering of a forest trust for
SIDs of third domains, and the M.5 edge below.

**Status (ADR 0084 — domains of a trusted forest, 2026-10-24):** for a forest
trust Stars reads the trust object's forest trust information
(`msDS-TrustForestTrustInfo`). Its effects:

- A SID of **any** domain of the trusted forest counts as a SID of a trusted
  domain. Until v1.18.0 an account of a child domain of the trusted forest
  was reported as "neither the configured domain nor one of its trusts".
- For an account of a trusted domain resolved through the trusted-domain
  connection, SIDs of every enabled domain of the trusted forest pass the
  forest trust. This was measured with real SMB logons: `PARTNER\pt_user02`
  reached a corp.test folder through the universal group
  `CHILD\UG_CH_Forest`.
- With a Global Catalog bind the trust objects of the whole forest are read.
  Until v1.18.0 that mode reported even a directly trusted domain as "not
  one of its trusts".
- `adpa trusts` and the GUI Trusts tab list the domains of each forest trust.

Still not modelled, and reported as such:

- SIDs of third domains and of the trusting forest on a forest trust
  (sIDHistory from a migration)
- `TREAT_AS_EXTERNAL` (0x40)
- domain records whose SID is disabled
- quarantine on a forest trust
- the M.5 edge below

**Additional L4 edge since ADR 0056 (verification.md Block M.5):** an
**in-base** identity whose evaluated `sIDHistory` SID is owned by a
*foreign forest's* domain. Windows honors that SID only while the trust's
`/EnableSIDHistory` state allows it; Stars evaluates it unconditionally
and — because the identity is in-base — no `TrustBoundaryEffectsNotModeled`
marker fires. Exact while the trust honors history (the lab's current
state), a potential over-report when it filters. Fixing this requires the
trust-topology work described here.

### Solution sketch

- Stars documentation: features-and-limitations.md should clearly
  document that Stars shows the DACL view, not the filtered runtime
  result.
- ✅ **Done (ADR 0060):** Read `trustAttributes` and `trustDirection` from AD
  and display them as read-only info — the `adpa trusts` command lists every
  trust with its direction and decoded attributes (SID filtering / quarantine,
  selective authentication, forest-transitive).
- ✅ **Done (ADR 0079):** Selective Authentication for accounts of a
  trusted domain, from the computer object's DACL — no logon attempt.
- ✅ **Done (ADR 0084):** the domains of a trusted forest — classification,
  forest-trust SID filtering for their SIDs, the Global Catalog view of the
  forest's trusts.
- A synthetic logon attempt would violate the read-only principle →
  deliberately **not** implemented.
- Follow-up (open): cross-reference a token's foreign-forest history SIDs
  against a filtering trust to flag the M.5 per-finding over-report.

### Test plan

No automated detection possible; documentation only.

---

## L5 — `OutsideConfiguredLdapBase` identities have empty memberships

**Priority:** Medium
**Tracking:** v1.7+ candidate
**References:** L1, L2, ADR 0039

### Problem

When Stars resolves a SID via LSA but the configured LDAP `base_dn`
does not index it, the pipeline ends up in
`scope_status = OutsideConfiguredLdapBase`,
`group_resolution_status = NotAttempted`. Since v1.5.2 this is marked
with a `group_resolution_failure_reason` (the finding is `incomplete`),
but the actual memberships remain **empty**.

### Effect

Cross-domain memberships of the trust user are not evaluated. The
finding is marked incomplete, but the right gets computed too low in
case of doubt.

### Solution sketch

Two independent tracks (can be implemented separately):

a) **L1 (FSP path):** add memberships of the FSP object in the home
   domain.
b) **L2 (GC path):** if a GC is configured, query memberships
   forest-wide via the GC.

Without L1 or L2 L5 stays structurally open.

### Test plan

See L1 and L2.

---

## L6 — Multi-domain live integration tests are missing

**Priority:** High (validation of the existing architecture)
**Tracking:** as soon as a test forest is available

### Problem

The central principal pipeline (ADR 0036) is covered by **in-memory
fakes**:

- `FakeLdapBackend` simulates LDAP hit/miss/error.
- `FakeLsaBackend` simulates LSA hit/miss.

This covers *structural* correctness — the pipeline does what the
code logic says. **Until 2026-06-14 no one had run it against a real
multi-domain forest with a trust** (see the progress note below).

The `#[ignore]`-marked integration tests in the code (`sam.rs`,
`local_groups.rs`, …) only run when you explicitly execute
`cargo test -- --ignored` on a DC.

### Effect

Unknown real-world pitfalls (LDAP server idiosyncrasies, referrals,
specific trust configurations) are not covered. Structurally correct
≠ confirmed in the wild.

### Solution sketch

- Set up a test forest in Proxmox (matches the deployment target):
  two domains, one trust.
- Stars smoke-test script that manually plays through the pipeline
  cases (L1, L2, L5) and checks the result against expectations.
- Results as a Markdown table in the repo.

### Test plan

Its own task; probably initially manual, later as `#[ignore]` test
with documented prerequisites.

> **Progress (2026-06-12 / -13):** a Windows authorization **conformance
> harness** exists at
> `crates/permission_engine/tests/windows_conformance.rs` (engine review
> 2026-06-12 finding 2) and now covers both levels of ground truth. The
> tests are `#[ignore]` (require a Windows session) — run with
> `cargo test -p permission_engine --test windows_conformance -- --ignored`.
>
> - **Single-trustee** (`GetEffectiveRightsFromAclW`): builds a real
>   in-memory ACL for the current user and asserts the engine's effective
>   mask matches the OS bit-for-bit. Fixtures: Allow Read & Execute,
>   Allow Full Control, Deny Write over Allow Full (canonical order), two
>   accumulating Allows.
> - **Token-based, multi-group** (`AccessCheck`, added 2026-06-13): builds
>   an absolute security descriptor and a duplicated impersonation token,
>   then asks the OS for the `MAXIMUM_ALLOWED` access across a DACL whose
>   ACEs target **different principals** in the token (the user plus the
>   implicit `Everyone` / `Authenticated Users`). Fixtures: two groups
>   accumulating, **Deny on one group beating Allow on another** (the
>   critical interaction), and a direct user ACE plus a group ACE. All
>   pass — the engine's multi-principal token evaluation matches the OS
>   authorization call.
>
> All seven conformance tests pass against a live Windows session, and a
> dedicated `conformance` CI job on `windows-latest` runs
> `cargo test -p permission_engine --test windows_conformance -- --ignored`
> on **every push** (engine review 2026-06-13 finding 5) — so conformance
> is verified per commit, not only locally. A further extension to
> `AuthzAccessCheck` with a fully **synthetic** token (arbitrary forged
> group memberships, beyond the principals the current process actually
> holds) would need `SeCreateTokenPrivilege` and is left as optional
> future work; the current `AccessCheck`-based harness already exercises
> real multi-group token evaluation.

> **Progress (2026-06-14):** Stars was run live against a purpose-built
> **three-domain Proxmox forest** (tier0 / tier1 / tier2, bidirectional
> trusts) on Windows Server 2025 DCs. A deeply nested cross-domain group
> structure, a deny-precedence case, an inheritance break and the
> NTFS ∩ Share combination were created with known ground truth; the CLI
> results matched it on every evaluable case. Notably the signed-LDAP bind
> (ADR 0051) resolved a user's **full five-level nested group chain** over
> LDAP against a hardened, certificate-less DC — previously impossible.
> The full ground-truth-vs-Stars results are now committed as a repository
> artifact — [`docs/lab/verification.md`](lab/verification.md), **Block L**
> (NTFS ground truth, the deny-precedence `0x300A9` case, the inheritance
> break, the NTFS ∩ Share UNC case, and the signed-LDAP five-level chain).
> **Honest caveat:** this run was *manual* — it is not yet an automated
> `#[ignore]` integration test in CI, and the lab is powered down, so the
> figures are the recorded session output. Turning it into a repeatable
> automated lab suite remains future work, so L6 stays **partially** open.

---

## L7 — Token privileges (`SeBackupPrivilege`, …) are not modelled

**Priority:** Low
**Tracking:** likely never — out of scope

### Problem

Windows grants accounts with token privileges (`SeBackupPrivilege`,
`SeRestorePrivilege`, `SeTakeOwnershipPrivilege`) effective access
independent of the DACL. A backup operator can productively read what
the DACL does not grant.

### Effect

Stars findings show only the DACL view. Whoever wants to know
*can this user effectively reach the data*, has to add token
privileges manually.

### Solution sketch

- features-and-limitations.md already documents this (limit 10).
- Stars could render membership in `Domain Admins`, `Backup Operators`
  etc. as a hint — currently does not.

### Test plan

Out of scope. Documentation is enough.

---

## L8 — Dynamic Access Control (DAC) / Conditional ACEs are not evaluated

**Priority:** Low
**Tracking:** likely never — out of scope

### Problem

Windows DAC (claims-based ACEs) is not understood by the Stars
parser. Conditional ACEs are counted as `UnsupportedShareAces` /
`unsupported_ace_count` and skipped.

### Effect

Stars marks this as `incomplete`. The DAC logic, however, is not
evaluated.

### Solution sketch

- features-and-limitations.md documents this (limit 11).
- A DAC parser would be its own large piece of work
  (SDDL conditional expressions).
- Remains a deliberate out-of-scope decision.

### Test plan

Out of scope.

---

## L9 — Canonical order across inheritance levels cannot be decided

**Priority:** Low
**Tracking:** narrowed 2026-10-17 — the ambiguous case has its own marker; exact detection is impossible with the available data

### Problem

The `NonCanonicalDaclOrder` diagnostic uses a single-level 4-phase model:
explicit-deny → explicit-allow → inherited-deny → inherited-allow.
Windows canonical order, however, sorts inherited ACEs **per ancestor
level**: first all ACEs inherited from the parent (deny before allow),
then from the grandparent, and so on. A DACL like
`[inherited-Allow from parent, inherited-Deny from grandparent]` is
fully canonical in Windows but is flagged by Stars.

### Effect

The diagnostic marker can appear on perfectly healthy ACLs in deep
directory trees where an ancestor carries Deny ACEs. **Evaluation is
not affected** — the engine always walks the stored order, which is
exactly what Windows `AccessCheck` does. Only the informational marker
can be a false positive.

### What Stars does since 2026-10-17

`AceEntry` carries no ancestry information (Windows does not expose
which ancestor an inherited ACE came from through
`GetNamedSecurityInfoW`), so an exact canonical check per inheritance
level is impossible. Stars therefore separates the two cases:

- `NonCanonicalDaclOrder` only for orders that are **never** canonical:
  an explicit ACE after an inherited one, or an explicit Allow before an
  explicit Deny.
- `InheritedDenyAfterInheritedAllow` when the only irregularity is an
  inherited Deny after an inherited Allow: canonical across levels, not
  within one — the marker says that Stars cannot tell, instead of calling
  a healthy DACL non-canonical.

Found in the lab (2026-10-17, DC-01 fixture covering every AD group kind
and inheritance breaks): two child folders inherit an Allow from their
parent and a Deny from their grandparent — canonical in Windows,
previously reported as non-canonical. Results were identical to the
Windows Authz oracle before and after (104 / 104 rows).

### Test plan

`inherited_deny_after_inherited_allow_is_not_called_non_canonical` and
`definite_order_violations_stay_non_canonical` (permission engine); the
lab fixture above.

---

## L10 — Security-descriptor deduplication is scan-local, not storage-level

**Priority:** Low
**Tracking:** possible future optimization

### Problem

Within a single scan the scanner parses each distinct security
descriptor only once (a per-run cache keyed by an FNV-1a hash of the raw
descriptor bytes, validated by a full byte comparison before reuse). The
hash is kept on the in-memory `FileSystemObject` as `sd_hash`, but it is
**not persisted**: the SQLite schema has no `sd_hash` column and no
descriptor table.

### Effect

Performance during a scan benefits (no repeated parsing of identical
inherited DACLs), but **storage does not deduplicate**: on a tree where
thousands of objects share one inherited descriptor, the database still
stores the explanation, matched-ACE and diagnostic JSON once per row.
For very large histories this is extra disk usage, not a correctness
problem.

### Solution sketch

Add a descriptor table keyed by the validated raw-descriptor hash (plus
collision-safe bytes/metadata) and reference it from permission or object
rows, behind a schema migration. The hash is already computed and carried
on the scanned object, so the scanner side is ready; only the persistence
schema and read/write paths would need the addition.

### Test plan

A persistence test asserting that two objects with an identical
descriptor reference one stored descriptor row, once the table exists.

---

## L11 — The permission engine lives in a single large module

**Priority:** Low — code maintainability, not a defect and not a correctness issue.

`permission_engine/src/engine.rs` is large (~3.6k lines), but the bulk of
that is the in-file test suite. The production logic is a handful of
cohesive functions (stored-order DACL walk, token-SID assembly, explanation
builder) behind a small public surface. The engine evaluates correctly and
is covered by unit tests plus the Windows `AccessCheck` conformance harness
that runs in CI — so this is a readability concern, **not** a "god module"
with tangled responsibilities.

### Resolution

Optionally split the file into submodules (e.g. `dacl`, `token`,
`explanation`) behind the unchanged public API. The change would be purely
mechanical, with no behavioural change and no effect on results. It is
deferred because the current structure is correct and well-tested — the
value is reader ergonomics only.

---

## L12 — Application updates are manual; `update_manager` is a deliberate extension point

**Priority:** Low — by design; not a defect, and not an unfinished feature.

Stars is distributed as a versioned installer on the GitHub release page and
verified via the published SHA256 hash. There is **no in-app auto-update**,
and none is promised.

Since the update_manager review 2026-07-26 (ADR 0061) Stars can at least
**tell you** when a newer version is published: a **manual, read-only
check** — the "Check for updates" button in the GUI Info tab, or
`adpa check-update` in the CLI — fetches the release info from a
configurable, validated HTTPS source (default: the official GitHub feed),
compares versions with SemVer precedence, and reports. It never runs
automatically (Stars runs on DCs, often offline or hardened — no
phone-home), downloads nothing, and installs nothing. Installation stays
manual as described below.

The `update_manager` crate is an **intentional architectural seam**, not a
half-finished feature. The project's architecture requires that update/patch
installation be *architecturally provided for* — so the crate establishes the shape of that
capability (the `SignatureVerifier` trait, a validated manifest schema, update
channels, and the rollback/migration surface) **without** committing to a
specific implementation now. The default `SignatureVerifier` is the
**fail-closed `RejectAllVerifier`**: an unconfigured system refuses every
update rather than trusting one. So the seam is safe by default, and its
public APIs are honest, reject-by-default stubs that must not be mistaken for
a working updater.

Why keep it if Stars itself does not auto-update? Because the seam is the kind
of thing that is **far worse to be missing when someone needs it than to be
present and unused**. A downstream user, an enterprise rollout, or a future
phase of the project can implement a real verifier behind the existing trait
without reshaping the architecture. Manual, operator-controlled installation
is also a perfectly valid (often mandated) model for an audit tool — so for
the base product the seam staying dormant is the expected state, not a gap.

### Resolution

Nothing is required for the base product. If in-app updates are ever needed,
implement a real `SignatureVerifier` (e.g. Ed25519 with a pinned public key)
and the install/rollback flow behind the existing trait and manifest schema,
against the project's update requirements (signed, checksummed,
channel-aware, rollback-capable, offline source supported). Until then the crate stays a
documented, fail-closed extension point and updates remain a manual
download-and-verify step.

---

## L13 — IPv6 literals are not accepted as server addresses

**Priority:** Low — DNS names and IPv4 addresses work; IPv6-only
environments are rare for AD DCs today.

### Problem

The hostname validator (`validation::net::check_hostname`) accepts only
letters, digits, `.`, `-`, and `_`. An IPv6 literal (`::1`, `fe80::…`,
`2001:db8::…`) contains `:` and is rejected — for **both** the LDAP
endpoint (`--server`, GUI Server field) and the SMB server
(`--smb-server`). The error message names the limitation explicitly.

### Effect

In an IPv6-only (or IPv6-preferred, no-DNS) environment, Stars cannot be
pointed at a DC or file server by address. With a resolvable DNS name or
an IPv4 address there is no restriction.

### Resolution

Deliberately documented instead of implemented (validation review
2026-07-25, VA-4): real support needs bracket handling for LDAP URLs
(`ldaps://[fe80::1]:636`) and the Windows `ipv6-literal.net`
transformation for UNC/NetAPI paths — neither is implemented or
lab-verified (the lab is IPv4). If IPv6 support is added, both paths must
be built and live-tested together, plus user-guide examples.

---

## L14 — Junction cycles are not detected when scanning over UNC

**Status: closed 2026-10-10** (ADR 0062) — kept here for the record.

**Priority:** Medium — found by the corp.test lab run 2026-10-07
(finding FS3-1). Bounded, but it inflated results.

### Problem

The walker detects a reparse-point cycle by comparing the canonical
identity of each directory with the active traversal chain (ADR 0058).
On a local path that identity is the resolved target, so a junction that
points to its own ancestor is stopped at once (unit test
`walker_detects_junction_loop_and_emits_visible_error`). Over SMB,
`GetFinalPathNameByHandleW` returns the junction's resolved target only
while the client has not enumerated the junction's parent; afterwards —
and the walker always lists the parent first — it returns the path the
junction was opened through. Every level of `\\server\share\Loop\back\…`
then looked new. Whether the client cache was warm depended on timing, so
the failure was intermittent (reliably reproducible right after the
server's SMB service restarts).

### Effect

The walker follows the loop until Windows' own limit of 63 reparse
traversals per path (about 64 levels in the lab), re-enumerating the
looped subtree on every level, and then reports the deepest level as
"Reparse point target could not be resolved". The scan terminates and
the error is visible, but the result contains duplicate paths (in the
lab: 216 paths scanned, more than 100 of them loop duplicates) and the
message names the wrong cause.
Scanning the same tree via its local path on the server is not affected.

### Resolution

Closed by ADR 0062: for scans with a UNC root the walker identifies each
directory by volume serial + 128-bit file ID from
`GetFileInformationByHandleEx(FileIdInfo)`, which the server reports
identically for a directory no matter which route led to it. (The older
`GetFileInformationByHandle` was ruled out: it reports a volume serial of
0 over SMB.) Lab acceptance in the reproduced failure state: the loop is
stopped after 3 paths in 3 of 3 runs, the share scans 90 paths instead of
216, and a junction into another subtree of the same scan is now reported
as a duplicate target. Directories for which a server returns no usable
identity fall back to the previous path comparison. Over SMB the reparse
attribute of a junction is not reliable either (lab 2026-10-18: missing in
25 of 37 runs); the loop identity does not depend on it, and since the
ADR 0062 addendum the duplicate-target message claims only the identity
that matched.

---

## L15 — Accounts of a trusted domain, given by SID, are reported as orphaned

**Priority:** Medium — found by the corp.test lab run 2026-10-07
(finding AD3-1).

### Problem

When the identity to analyze is a SID of a **trusted** domain (e.g. an
`ext.test` account analyzed against `corp.test`), the resolver only asks
the configured domain. It finds no account object and classifies the SID
as `Kind: Orphaned`, although the account is valid in its own domain.
Its group memberships in that domain are not resolved.

### Effect

The effective right **under-reports**: in the lab an `ext.test` user whose
group is granted Read & Execute in the DACL was reported with no access.
A generic "local groups could not be resolved — result is incomplete"
warning appears, but no marker names the foreign domain, and the L4
SID-filtering caveat is not shown. Analyzing such an identity through its
FSP-backed group membership in the resource domain (L1) is not affected.

### Resolution

**Partly closed 2026-10-10 (ADR 0064).** Stars now reads the domain SID of
the configured base and the domain's trust objects when a SID cannot be
resolved. A SID of a trusted domain is reported as **not resolvable** with
the trust partner named (marker `IdentityNotResolvable`, incompleteness
trigger) — never as orphaned; the result is marked incomplete. Only a SID
of the configured domain, searched with a base that covers the whole
domain, is still called orphaned.

**Closed 2026-10-17 (ADR 0078).** With an optional connection to a domain
controller of the trusted domain (CLI `--trust-server` / `--trust-base-dn` /
`--trust-bind-dn`, GUI section "Also resolve accounts of a trusted domain")
Stars resolves such an account there and builds its token the way Windows
builds it for a resource in the configured domain: its global and universal
groups (`tokenGroupsGlobalAndUniversal` of the trusted DC), the trust's SID
filtering (quarantine), and the domain-local groups of the configured domain
it reaches through Foreign Security Principals. Lab: identical to the
Windows Authz oracle on every determinable row. Without the connection the
result stays "not resolvable", and the reason names the option.

**Closed 2026-10-17 (ADR 0079):** Selective Authentication is checked for
such an account, and `This Organization` / `Other Organization` are exact
for it (`This Organization` without Selective Authentication, `Other
Organization` with it — measured with real SMB logons). An account with a
Foreign Security Principal object in the configured domain is resolved on
the trusted DC too.

**Fixed 2026-10-24 (ADR 0078 addendum):** on a domain-joined machine,
Windows LSA names an account of a trusted domain, and until then Stars
never used the configured connection for it (except through an FSP
object). It now does. Lab, MS-01: 65 of 65 rows went from NOT
DETERMINABLE to exact.

**Extended 2026-10-24 (ADR 0084):** an account of any domain of a trusted
forest (for example a child domain of the forest the trust names) is
recognised as an account of a trusted domain and resolved through a
connection to a DC of its own domain. SIDs of the trusted forest's other
domains in its token pass the forest trust (measured). When that connection
cannot read its domain SID, the reason is shown — a Server 2025 DC, for
example, refuses a simple bind without signing (use `--ldap-signing` or
LDAPS there).

**What stays open:** the SID filtering of a forest trust for SIDs of third
domains is not modelled (reported, never assumed); for every other account
`This Organization` stays logon-dependent.

---

## L16 — User Account Control policies and session elevation are not visible

**Priority:** Medium — found in the member-server lab run 2026-10-11
(ADR 0070, ADR 0071)

### Problem

User Account Control turns Administrators, the operator groups and the
privileged domain groups deny-only in a filtered token: on a local access
for every account until the session is elevated, and over the network for
local accounts unless the server sets `LocalAccountTokenFilterPolicy` = 1
(the built-in Administrator only with `FilterAdministratorToken` = 1).
Stars sees neither the session's elevation nor these registry policies.

### Effect

Wherever an Allow ACE for such a group decides the result, it reads
**NOT DETERMINABLE — between … and …** (marker `UacFilteredGroups` +
`LogonDependentTrustees`): the lower bound is the filtered token, the upper
bound the unfiltered one. Deny ACEs for the groups always apply. The result
is never wrong, but for administrators it is often a range.

### Status (2026-10-13)

**The network case is closed** (ADR 0076): Stars reads
`LocalAccountTokenFilterPolicy` / `FilterAdministratorToken` read-only from
the target and decides remote UAC exactly (lab matrix of all four
combinations). It stays a range only when the policies cannot be read
(remote registry unreachable or denied, `EnableLUA` = 0, unexpected
values) — and for a **local session**, whose elevation is a property of the
logon that no policy reveals. Exception: the built-in Administrator with
`FilterAdministratorToken` = 0 has an unsplit full token, also decided
exactly (measured).

---

## L17 — Guest and anonymous tokens (closed 2026-10-14)

**Priority:** Low — review finding CR-8 (ADR 0072).

Real Guest and anonymous tokens were measured (2026-10-13): Authenticated
Users is never in them. `EveryoneIncludesAnonymous` is now read read-only
from the target (2026-10-14): Everyone in an anonymous token is exact (0 →
absent, 1 → present). Only when the value cannot be read does an Everyone
ACE bound an anonymous result. Not measured: `NETWORK` in a real SMB null
session (Stars assumes it, as for every SMB logon).

---

## L18 — DFS folders with more than one target

**Priority:** Medium — found by the lab run 2026-10-24 (ADR 0085).

A path through a DFS namespace (`\\domain\namespace\folder\…`) is evaluated
on the folder target this machine's DFS client is referred to: its NTFS
DACL, its share permission, its server's local groups and policies. Until
v1.18.0 the share permission and the server context came from the
namespace server, which under-reported rights (lab: Modify shown as Read &
Execute).

What stays open: a folder with **more than one target** (for example two
file servers kept in sync by DFS-R) can grant different rights on each
target. DFS-R replicates the NTFS permissions, but share permissions and
local groups are per server. A client may be referred to any of them. Stars
evaluates one target, names the others in the marker
`DfsTargetEvaluated`, and marks the result **not determinable**. To get
exact values, scan each target's share directly (`\\FS-01\DfsProj`,
`\\FS-02\DfsProj`).

A scan of a namespace root reports each folder below it as "served from
another share" and does not enumerate it. Scan the folder path itself.

---

## L19 — The GUI's Scan Tree keeps the whole tree in memory

**Priority:** Medium — found by the mass test 2026-10-25 (ADR 0086).

The CLI `scan` streams its results into the database and the CSV export:
about 30 MB of memory whatever the size of the tree. The GUI's Scan Tree
does not:

- It reads the whole walk first.
- It keeps every result for the list, the Delta tab and the history:
  about 26 KB per result for an account in about 70 groups, measured
  before ADR 0087 made the rows of a scan shorter. The memory still grows
  with the tree.
- Its list is not virtualized, so streamed rows make the GUI catch up for
  seconds even with hundreds of rows.

For trees with more than a few tens of thousands of paths, use the CLI
with `--db` and a `.csv` export.

---

## Status overview

| Limit | Priority | Marker present? | Resolvable? |
| --- | --- | --- | --- |
| L1 — FSP | High | **yes** (IdentityResolvedViaForeignSecurityPrincipal) | **closed 2026-06-11** (trust-side groups still need L2) |
| L2 — GC bind | High | **yes** (GroupResolutionViaGlobalCatalog) | **closed 2026-06-11** (GUI toggle shipped v1.6.4) |
| L3 — SID History | Medium | **yes** (SidHistoryEvaluated/Present + GroupSidHistoryEvaluated/Present) | **closed 2026-07-04** (user: ADR 0056; groups: ADR 0059) |
| L4 — Cross-forest filter | Medium | yes (Selective Authentication markers) | partial: trust inventory (ADR 0060); Selective Authentication modelled for trusted-domain accounts (ADR 0079); domains of a trusted forest and their SIDs on a forest trust (ADR 0084); forest-trust SID filtering of third-domain SIDs open |
| L5 — Empty memberships | Medium | yes (incomplete) | only via L1/L2 |
| L6 — Live tests | High | n/a | **partially** — live 3-domain run 2026-06-14 committed (verification.md Block L); automated CI suite still open |
| L7 — Token privileges | Low | no | deliberately out of scope |
| L8 — DAC | Low | yes (incomplete) | deliberately out of scope |
| L9 — Canonical order across inheritance levels | Low | yes (informational: `InheritedDenyAfterInheritedAllow`) | narrowed 2026-10-17; exact check impossible (missing ancestry data) |
| L10 — SD dedup scan-local only | Low | n/a | yes, with a descriptor table + migration |
| L11 — Engine module size | Low | n/a | optional refactor (readability only, not a defect) |
| L12 — Manual updates / `update_manager` extension point | Low | n/a | by design; fail-closed seam, implement a real verifier only if in-app updates are required |
| L13 — IPv6 literals rejected as server addresses | Low | n/a (explicit validation error) | yes — bracket handling (LDAP) + `ipv6-literal.net` (UNC/NetAPI), must be built and lab-verified together |
| L14 — Junction cycles over UNC | Medium | **yes** (ReparseCycle / ReparseDuplicateTarget, as locally) | **closed 2026-10-10** (ADR 0062: volume serial + file ID on UNC scans) |
| L15 — Accounts of a trusted domain | Medium | **yes** (IdentityNotResolvable without, TrustedDomainAccountResolved with the trusted-domain connection) | **closed 2026-10-17** (classification ADR 0064, resolution on the trusted DC ADR 0078) |
| L16 — UAC policies / session elevation not visible | Low | **yes** (UacFilteredGroups, RemoteUacPolicy) | **network case closed 2026-10-13** (ADR 0076); local session elevation stays bounded |
| L17 — Guest / anonymous tokens | Low | **yes** (GuestOrAnonymousToken) | **closed 2026-10-14** — Guest, Authenticated Users and anonymous Everyone exact (policy read); bounded only when the policy is unreadable |
| L18 — DFS folders with several targets | Medium | **yes** (DfsTargetEvaluated; OtherShare scan error) | partial (ADR 0085): evaluated on the referred target, exact with one target; several targets → not determinable, scan each target |
| L19 — GUI Scan Tree keeps the whole tree | Medium | n/a (documented) | the CLI streams (ADR 0086); the GUI's walk, result list and history still to be streamed / virtualized |

## Contribution policy

Whoever wants to address one of these limits:

1. Write an ADR (format `docs/adr/00NN-...md`) documenting the
   architecture decision.
2. Tests with fakes (for L1, L3, L5) or against a live setup (L2, L6).
3. Update features-and-limitations.md (status, possibly new markers).
4. CHANGELOG entry.
5. Set the matching entry in this file to "closed in vX.Y.Z".

The read-only principle is preserved with every extension: Stars
**shows** gaps, **explains** them, **closes** them structurally — but
never modifies target systems.
