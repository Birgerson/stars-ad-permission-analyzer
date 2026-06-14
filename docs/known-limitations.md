# Stars — Known Limitations and Roadmap (v1.6+)

**Status:** v1.7.0 — 2026-06-14
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

## L3 — SID History is not evaluated

**Priority:** Medium
**Tracking:** v1.7+ candidate

### Problem

In domain migration scenarios, users carry the `sIDHistory` attribute,
which contains earlier SIDs from migrated domains. NTFS DACLs that
were not migrated along still reference these old SIDs.

Stars currently does not evaluate `sIDHistory`. If a DACL contains a
SID-history SID, no match against the user can occur.

### Effect

Findings understate the rights of migrated users on non-migrated
filesystem structures. Unlike L1, this case produces **no marker** —
Stars simply sees the old SID as "another user" and finds no match.

### Solution sketch

- Have `parse_identity_from_entry` additionally evaluate the
  `sIDHistory` multi-value attribute.
- Extend `PrincipalResolution` by `historical_sids: Vec<Sid>`.
- Token construction in `build_token_sids_with_context` adds the
  history SIDs.
- New marker `MembershipResolvedViaSidHistory` with the historical SID
  in the reason so the auditor can see that a right applies via the
  old SID.

### Test plan

Extend the LDAP fake by the `sIDHistory` attribute. ACE on the old
SID, expectation: right is granted and marker appears.

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

### Solution sketch

- Stars documentation: features-and-limitations.md should clearly
  document that Stars shows the DACL view, not the filtered runtime
  result.
- (Optional) Read `trustAttributes` and `trustDirection` from AD and
  display them as read-only info in the report.
- Real detection of the filter effect would require Stars to perform
  a synthetic logon attempt — that violates the read-only principle →
  deliberately **not** implemented.

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

## L9 — Canonical-order detector can flag legitimate multi-level inheritance

**Priority:** Low
**Tracking:** documentation only — exact detection is impossible with the available data

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

### Why not fixed

`AceEntry` carries no ancestry information (Windows does not expose
which ancestor an inherited ACE came from through
`GetNamedSecurityInfoW`). An exact canonical check per inheritance
level is therefore impossible. The diagnostic text and the engine log
message state this limitation explicitly.

### Test plan

Not testable beyond the wording — the marker semantics are documented
here and in the diagnostic tooltip texts.

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

## Status overview

| Limit | Priority | Marker present? | Resolvable? |
| --- | --- | --- | --- |
| L1 — FSP | High | **yes** (IdentityResolvedViaForeignSecurityPrincipal) | **closed 2026-06-11** (trust-side groups still need L2) |
| L2 — GC bind | High | **yes** (GroupResolutionViaGlobalCatalog) | **closed 2026-06-11** (GUI toggle shipped v1.6.4) |
| L3 — SID History | Medium | **no** | yes, with implementation |
| L4 — Cross-forest filter | Medium | no | no (documentation only) |
| L5 — Empty memberships | Medium | yes (incomplete) | only via L1/L2 |
| L6 — Live tests | High | n/a | **partially** — live 3-domain run 2026-06-14 committed (verification.md Block L); automated CI suite still open |
| L7 — Token privileges | Low | no | deliberately out of scope |
| L8 — DAC | Low | yes (incomplete) | deliberately out of scope |
| L9 — Canonical-order false positives | Low | yes (informational) | no (missing ancestry data) |
| L10 — SD dedup scan-local only | Low | n/a | yes, with a descriptor table + migration |

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
