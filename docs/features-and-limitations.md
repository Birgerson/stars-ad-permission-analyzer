# Stars — Features, Limits and How to Read the Results

**Audience:** Windows/AD administrators with mixed environments
(domain controllers, file servers, NTFS volumes, SMB shares).
**Convention:** This file is the central user-facing document for the
question "What does Stars show me correctly, what doesn't it?". If a
feature is not listed here or is explicitly marked as a limitation,
that applies.

> **Core principle:** Stars is and remains a read-only analysis tool.
> Stars **writes nothing** to NTFS, SMB shares, or AD. Findings are
> hints — the admin handles productive remediation themselves.

---

## What Stars reliably covers

### Identity and groups

- **SID ↔ name resolution** via LDAP (`objectSid` search) and via the
  Windows LSA (`LookupAccountSidW`, `LookupAccountNameW`).
- **Input formats:** `DOMAIN\user`, `user@domain.tld` (UPN), bare
  `sAMAccountName`, and SIDs (`S-1-5-…`). Ambiguous `sAMAccountName`
  hits are reported as an uniqueness error (no silent selection) —
  see ADR 0032.
- **Recursive group resolution via LDAP**: through `memberOf` with
  `LDAP_MATCHING_RULE_IN_CHAIN`. This avoids N+1 recursion and
  range-retrieval problems on large groups — and cycles.
- **Primary group** is evaluated separately via `primaryGroupID`.
- **`disabled` status** is read in the LDAP path via
  `userAccountControl` and in the SAM path via `NetUserGetInfo`
  level 1 — see ADR 0033 and ADR 0035.

### NTFS DACL evaluation

- **Allow and Deny ACEs**, **explicit and inherited** entries,
  **inheritance flags** and **propagation flags** are read and shown
  separately in the path report.
- **Owner** SID and the named owner are shown separately.
- **Access mask normalization:** Windows access mask bits are
  translated into normalized rights (Read, Write, Modify, Full
  Control, …); raw data is preserved.
- **Identical security descriptors** are deduplicated by hash — the
  GUI shows a hint when the same DACL propagates across large path
  trees.
- **Long paths** (`\\?\…`, UNC long-path form `\\?\UNC\server\…`) are
  supported — see ADR 0031.
- **Reparse points / junctions / symlinks** no longer cause infinite
  loops; loops are detected and surfaced.

### SMB share evaluation

- **Share DACL and NTFS DACL stay separate** in the data model and
  the report. The effective SMB permission is the restrictive
  combination of both (mask ∩ NTFS).
- **Administrative shares** (`C$`, `ADMIN$`, …) are marked as such
  by default.
- **UNC paths and local target paths** are consistently normalized
  (`validation::path::effective_smb_target`, ADR 0031).
- **`--smb-server` without `--share-name`** (and vice versa) is
  rejected as a configuration error — otherwise an incomplete SMB
  context silently contaminates local-group resolution. Closes
  review 2026-06-04 round 2, finding 2.

### Permission-path explanation

- Every finding carries an **explainable path** of the form
  `User → Group A → Group B → ACL entry → normalized right`.
- **Local group chains** on the target server are reconstructed via
  `NetLocalGroupGetMembers` (ADR 0029) — the mediator layer (e.g.
  `Domain Admins → BUILTIN\Administrators`) is visible in the path.
- **SID → name table** is built once per scan; every explanation
  path renders `DOMAIN\Name` instead of raw SIDs.

### Scan, persistence, and export

- **Cancellable scans** through a cancel token; the GUI stays
  responsive during a scan.
- **Large-environment efficient:** a whole scan run is persisted in a
  single transaction (no per-path commit), and identical security
  descriptors — the common case on a tree that inherits one DACL — are
  parsed once per scan via a content-hash cache (scan-local, not yet
  storage-level). The dedup is validated by a full byte comparison before
  reuse, so it can never change a computed result, only the parsing speed
  of a large scan.
- **Scan history** in SQLite (local, `persistence` crate) — see
  ADR 0026.
- **Delta comparison** between two scans (what changed per path in
  effective rights?).
- **Trustee view** per path (who has access?), complementing the
  classic per-user report.
- **Exporter:** CSV, JSON (variant-tagged diagnostics — ADR 0021),
  HTML with diagnostic badges.
- **Update-manager skeleton:** versioning, signature verification,
  update-path validation are designated as their own component
  (ADR 0028, ADR 0030).

### Structured diagnostic markers per finding

Every `EffectivePermission` carries a `diagnostics` vector with
variant-tagged JSON. CLI, HTML, and JSON render every marker with
its own description — a list of markers and their meaning:

| Marker | Severity | Risk `incomplete`? | Meaning |
| --- | --- | --- | --- |
| `NonCanonicalDaclOrder { at_index }` | medium | no | DACL is not in Windows canonical order. AccessCheck still runs in stored order — the result may diverge from a canonical expectation. |
| `UnsupportedShareAces { count }` | medium | **yes** | The share DACL contained ACE types the parser could not evaluate (object / callback / conditional / vendor-specific). The share mask is potentially incomplete. |
| `DomainGroupRecursionIncomplete` | medium | **yes** | Group resolution ran via SAM/LSA instead of LDAP. `NetUserGetGroups` only returns direct global groups — nested domain groups are not recursive. |
| `IdentityDisabled` | info | no | The account is disabled in AD via `userAccountControl/UF_ACCOUNTDISABLE`. ACL-theoretical rights are correct, but the account cannot normally authenticate. |
| `IdentityNotInConfiguredLdapBase` | medium | **yes** | LSA resolved the SID, but the configured LDAP `base_dn` does not index it. Typical in multi-domain forests / trusts — cross-domain memberships may be missing. |
| `IdentityDisabledStatusUnknown` | info | no | The `disabled` flag could not be determined (e.g. SAM path without successful `NetUserGetInfo`, or LDAP without a user object). |
| `IdentityLookupFailed { reason }` | high | **yes** | LDAP identity lookup failed with a technical error (bind, timeout, DC unreachable, query error). Analysis continues with a placeholder identity and empty token — ACEs targeting domain groups may be missing. The `reason` text carries the original error message. |
| `GroupResolutionFailed { reason }` | high | **yes** | Recursive group resolution failed or was skipped (e.g. cross-domain path without GC crawl). ACEs targeting domain groups may be missing. The `reason` text carries the original error message. |

The "Risk `incomplete`?" column shows whether
`risk_engine::is_incomplete()` matches this marker —
`incomplete = true` means: the risk finding is structurally
incomplete and should be presented as such in the audit.

---

## What Stars does **not** do (by design)

Stars never modifies target systems. The following functions are
permanently not part of the product:

- Modifying, cleaning up, or repairing NTFS permissions.
- Changing owners, enabling/disabling inheritance.
- Modifying SMB share permissions.
- Modifying AD users, AD groups, AD computers.
- Modifying group memberships.
- Creating, modifying, moving, or deleting files or folders on
  target systems.
- ACL auto-repair, remediation workflows, repair recipes.
- Automatic permission recommendations with implementation.
- Credential harvesting; filename hits on
  `password|secret|credentials|…` are marked, **but not opened or
  processed for content**.
- Agent rollout to foreign systems.
- Active SIEM response.

> This list follows directly from the CLAUDE.md/AGENTS.md project
> boundary. Any contribution that introduces a writing operation
> into the code is considered a breach of this boundary.

---

## Known limitations and how to read them

### 1. SAM fallback without LDAP (domain controller / local)

- **When:** Stars is run without `--server`/LDAP bind (e.g. on a DC
  or a workstation as a quick pre-analysis).
- **What happens:** Groups come via `NetUserGetGroups` +
  `NetLocalGroupGetMembers`. These only return **direct** domain
  and local groups.
- **Effect:** Nested domain groups beyond the direct membership are
  not in the token. ACEs targeting such deeply nested groups are
  not recognized in the finding.
- **How visible:** Marker `DomainGroupRecursionIncomplete` on every
  finding; risk findings are `incomplete = true`. The CLI prints the
  hint in the diagnostics block; HTML shows a `badge-medium`.
- **Solution:** Set `--server`, `--base-dn`, `--bind-dn` and a
  password — then recursive resolution runs server-side via
  `LDAP_MATCHING_RULE_IN_CHAIN`. See ADR 0033.

### 2. Multi-domain forest / trusted domains

- **When:** The identity belongs to a domain not covered by the
  configured LDAP `base_dn` (typical case: forest-wide trust, or the
  GUI identity picker searched in a trust domain).
- **What happens (since v1.5.0):** **All** input forms — `DOMAIN\user`,
  UPN (except see below), direct SID, and GUI name → SID — run
  through the same central principal pipeline
  (`ad_resolver::principal`). On an LDAP miss + LSA hit, Stars
  constructs an LSA-only identity with name + domain and marks the
  result as `IdentityScopeStatus::OutsideConfiguredLdapBase`.
- **Effect:** Group recursion only runs inside the configured
  domain — cross-domain memberships of the trust partner may be
  missing. `disabled` is not known.
- **How visible:** Marker `IdentityNotInConfiguredLdapBase` (medium,
  `incomplete = true`) **and** `IdentityDisabledStatusUnknown`
  (info) on every finding — regardless of which UI/CLI input form
  the user used.
- **UPN is a special case:** UPN search has no LSA cross-check
  (LSA cannot reverse-lookup UPNs). If the UPN search in the
  configured `base_dn` finds no hit, Stars returns an **explicit
  error** with the hint to bind against the Global Catalog
  (`port 3268`) or to use the `DOMAIN\user` / direct-SID input
  form. No silent fallback. See ADR 0036.
- **Solution (built-in since 2026-06-11):** pass `--global-catalog`
  (CLI). Stars then binds against the Global Catalog (port 3269
  LDAPS / 3268 with `--insecure-ldap`); `--base-dn` becomes optional
  (empty = all forest partitions) and identity lookups (SID, UPN)
  are forest-wide. **Caveat:** only universal group memberships
  replicate fully to the GC — Stars marks GC-resolved findings with
  `GroupResolutionViaGlobalCatalog` (incomplete trigger). See
  ADR 0034 (initial fix, only `DOMAIN\user`), ADR 0036
  (generalization to all input forms), and known-limitations L2
  (closed).
- **Solution (manual, still valid):** run a second Stars analysis
  with the `base_dn` of the partner domain.

### 3. Access denied during scan

- **When:** Stars has no read rights on a path or its DACL (Access
  Denied).
- **What happens:** The single path is recorded in the scan-error
  log (with path and reason); the scan continues.
- **How visible:** In the CLI as a `[scan error]` line, in the GUI
  as an entry in the scan-error list, in the HTML report as its own
  "Scan errors" section.
- **Solution:** Run Stars as an account that has at least
  `SeBackupPrivilege` or read-DACL rights on the target path.

### 4. Unsupported share ACEs

- **When:** The share DACL contains object ACEs, callback ACEs,
  conditional ACEs, or vendor-specific entries.
- **What happens:** These ACEs are counted and skipped — the share
  mask is potentially incomplete.
- **How visible:** Marker `UnsupportedShareAces { count }` (medium,
  `incomplete = true`). Risk findings are marked incomplete.

### 5. Non-canonical DACL order

- **When:** The DACL of an object is not in Windows canonical order
  (e.g. Allow before Deny). Windows still evaluates the list in
  stored order.
- **What happens:** Stars likewise evaluates in stored order and
  reports the divergence.
- **How visible:** Marker `NonCanonicalDaclOrder { at_index }`
  (medium, not `incomplete`).
- **How to read:** An auditor should have the DACL reordered —
  Stars does not do that.

### 6. Disabled accounts

- **When:** The account carries `UF_ACCOUNTDISABLE` (LDAP) or
  `NetUserGetInfo` delivers the flag set (SAM).
- **What happens:** ACL-theoretical rights are still computed and
  reported.
- **How visible:** Marker `IdentityDisabled` (info). Audit consumers
  thereby separate "the ACL would grant Modify" from "the account
  can authenticate". See ADR 0033.
- **Note:** In the SAM path with a failed `NetUserGetInfo`,
  `IdentityDisabledStatusUnknown` appears instead — see limitation 2.

### 7. Reparse points, junctions, symbolic links

- **When:** The scan hits reparse points (NTFS links to other
  directories or volumes).
- **What happens:** The walker follows reparse points and detects
  loops via path identity — infinite loops are ruled out.
- **How visible:** Reparse-point hits and detected loops are
  visibly marked in the GUI hit list; the HTML report has its own
  note.
- **How to read:** Following is built in because a switch to
  another volume would otherwise "disappear". Whoever does not want
  that excludes the path at the scan root.

### 8. Orphaned SIDs (real orphans)

- **When:** An ACE references a SID for which neither LDAP nor LSA
  finds an account (typical after AD object deletion).
- **What happens:** Identity is `IdentityKind::Orphaned`, the name
  is unset; the SID is preserved and displayed.
- **How visible:** The path display contains the raw SID; audit
  consumers see "SID exists in the DACL but no longer has a bearer".
- **Important:** A SID that exists in **another domain** (which the
  configured LDAP simply does not index) is **not** an orphan — it
  now appears with name + the marker
  `IdentityNotInConfiguredLdapBase`. See limitation 2.

### 9. Local groups on the target server

- **When:** The NTFS DACL references a local group on the file/SMB
  server (e.g. `BUILTIN\Administrators` or a custom local group).
- **What happens:** Stars resolves local server groups on the same
  server as the share DACL (`effective_smb_target`, ADR 0031). On
  explicit specification, `--smb-server` wins.
- **When resolution fails:** `LocalGroupEvalStatus::NotAvailable`
  → entry in the diagnostics block; the result is marked incomplete.
- **How to read:** Without successful local-group resolution, ACEs
  targeting local groups may stay invisible to the user — the
  "local groups unavailable" marker points exactly at that.

### 10. Permissions via token privileges

- **What we do not model:** Privilege-based access
  (`SeBackupPrivilege`, `SeRestorePrivilege`,
  `SeTakeOwnershipPrivilege`). These grant effective access but are
  **not** part of the DACL.
- **Effect:** A backup operator can productively read what the DACL
  does not grant. Stars shows only the ACL finding.
- **How to read:** If the auditor wants to know "can this user
  actually reach the data?", token privileges must be added
  manually — Stars answers the question "what does the ACL say?".

### 11. Dynamic Access Control (DAC) / Conditional ACEs

- **What we do not model:** Claims-based ACEs (Windows DAC). These
  are counted as "unsupported" — see limitation 4.
- **How to read:** Stars is a DACL auditor, not a claims evaluator.

### 12. SMB session layer

- **What we do not model:** SMB encryption policy, signing
  requirements, SMB version requirements, IP restrictions via
  firewall.
- **How to read:** Stars compares share DACL ∩ NTFS DACL. To
  answer "is the user even allowed to use SMB?", you also need the
  SMB server configuration.

---

## How to read a finding — step by step

A typical EffectivePermission entry contains:

1. **Path** (normalized).
2. **Identity** (SID + name + domain + kind).
3. **Effective rights** (Read / Write / Modify / Full Control, …).
4. **NTFS rights** and **share rights** separated (or "—" if not
   relevant).
5. **Diagnostics**: variant-tagged marker list — see the table above.
6. **PermissionPath**: one line per step
   `User → Group → … → ACE → normalized right`.

> **Golden rule:** When a finding carries markers, prepend the word
> "possibly". Markers indicate that the evaluation was deliberately
> not 100 % complete — not that Stars guessed.

---

## When a finding is unexpected

1. **Check markers.** If `DomainGroupRecursionIncomplete` or
   `IdentityNotInConfiguredLdapBase` is set, resolution is
   structurally incomplete. → Re-run with LDAP bind or against the
   Global Catalog.
2. **Read the PermissionPath.** Every step is visible — where does
   the explanation break off? Which group is missing?
3. **Check scan errors.** Access Denied on a single directory leads
   to gaps that are visible in the error tab / CLI block.
4. **CLI as cross-check.** The GUI is only the display layer. The
   CLI builds on the same engine — if a finding is identical in GUI
   and CLI, the cause is not rendering.
5. **Writing changes stay with the admin.** Stars does not suggest
   how to rebuild ACLs — that would be out of scope.

---

## References

- [ADR index](adr/) — full list of architecture decisions.
- ADR 0021 — Permission diagnostics as variant-tagged enum.
- ADR 0026 — Persistent scan history.
- ADR 0029 — Membership-path reconstruction.
- ADR 0031 — Shared UNC components and `effective_smb_target`.
- ADR 0032 — Identity input dispatcher and LDAP timeouts.
- ADR 0033 — Visible diagnostics for SAM fallback and disabled
  identities.
- ADR 0034 — Multi-domain LSA fallback for identity resolution
  (initial fix, only `DOMAIN\user`).
- ADR 0035 — SAM path confirms `disabled` via `NetUserGetInfo`.
- ADR 0036 — Unified principal-resolution pipeline (all input
  forms — `DOMAIN\user`, UPN, plain SAM, direct SID, GUI name →
  SID — have gone through the same pipeline since v1.5.0).
- ADR 0037 — Propagate validated wrappers consistently.
- ADR 0038 — Share DACL trustees in scan output (NTFS + share in
  the path-centric trustee table).
- ADR 0039 — Diagnostics for failed identity and group resolution
  (`IdentityLookupFailed`, `GroupResolutionFailed`).
- [Audit Criteria](audit-criteria.md) — what Stars covers from an
  audit-content perspective.
