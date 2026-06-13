# Audit Criteria and Evaluation Principles

### Table of Contents

1. [Core principles](#1-core-principles)
2. [What Stars analyzes](#2-what-stars-analyzes)
3. [How effective permissions are computed](#3-how-effective-permissions-are-computed)
4. [The six risk rules in detail](#4-the-six-risk-rules)
5. [The severity model](#5-the-severity-model)
6. [The `incomplete` marker](#6-the-incomplete-marker)
7. [Optimal rights per role and path class](#7-optimal-rights)
8. [Sensitive paths — what Stars takes as a hint](#8-sensitive-paths)
9. [What Stars deliberately does not do](#9-what-stars-does-not-do)
10. [Known limits of the evaluation](#10-known-limits)
11. [Persisted data and scan history](#11-persisted-data)

#### <a name="1-core-principles"></a>1. Core principles

Stars evaluates permissions **strictly read-only**. The tool makes **no changes** to AD objects, NTFS DACLs, or SMB shares — neither automatically nor on a button click. It shows, explains, and exports; nothing more.

The evaluation stands on four pillars:

| Pillar | Meaning |
|---|---|
| **Correctness** | The permission calculation must do what Windows does on a real access — otherwise every other statement is worthless. |
| **Traceability** | Every result carries a complete explanation path: through which groups, which ACEs, and which inheritance rules the right came about. |
| **Risk evaluation by fixed rules** | Six rules implemented in `risk_engine`, each with a clearly defined trigger and severity. No "heuristic". |
| **Honesty about uncertainty** | When the evaluation had gaps (e.g. share DACL not readable), the result is marked `incomplete`. Stars does not hide its own limits. |

These pillars match the priorities of the internal specification exactly:
> Security > Correctness > Traceability > Testability > Stability > Performance > Usability > Aesthetics.

#### <a name="2-what-stars-analyzes"></a>2. What Stars analyzes

For every examined path, Stars pulls **five input data sets**:

##### 2.1 Identity resolution

From the supplied user SID, Stars determines the full identity and group data — **directly through the Windows LSA/SAM API**, with no LDAP bind required:

* `LookupAccountSidW` → plain-text name (e.g. `BUILTIN\Administrator`) and account type
* `NetUserGetGroups` → **global (domain) groups** like `Domain Admins`, `Schema Admins`
* `NetUserGetLocalGroups` → **local groups** of the target server (e.g. `BUILTIN\Administrators`)

LDAP can optionally be added — relevant when Stars does **not** run on a domain controller and the data must be fetched from outside.

##### 2.2 Token construction

Stars reconstructs the **access token** the way Windows would build it on a real access. It includes:

* the user SID itself
* every direct group SID
* every transitive group SID (e.g. Administrator → Domain Admins → `BUILTIN\Administrators`)
* local server group SIDs
* context-dependent well-known SIDs:
  * `Everyone` (S-1-1-0) — always
  * `Authenticated Users` (S-1-5-11) — always (for non-anonymous logons)
  * `INTERACTIVE` (S-1-5-4) and `LOCAL` (S-1-2-0) — only on local access
  * `NETWORK` (S-1-5-2) — only on SMB access

Which of the last group is present depends on the **AccessContext**. Stars derives it from the path type: local paths → `LocalInteractive`, UNC paths → `RemoteSmb`. This matters because ACEs on `NETWORK` apply on SMB but are ignored on local access — and vice versa.

##### 2.3 NTFS DACL

The raw Discretionary Access Control List of the path is read directly via Win32 API. For each ACE, Stars remembers:

* trustee SID
* Allow or Deny
* access mask (raw value)
* explicit or inherited
* inheritance and propagation flags

The raw access mask is summarized into a readable label (`F`, `M`, `RX`,
`RW`, `R`, `W`, or `(special)`) that matches the Windows `icacls`
notation; the raw mask is always kept alongside it. The full legend is in
the [user guide](user-guide.md#rights-labels--what-f-rx-rw-mean).

##### 2.4 SMB share DACL (optional)

For UNC paths (`\\server\share\…`) Stars additionally reads the **share permissions**. The effective permission over SMB is then the **more restrictive** of the two sets:

```
effective_smb = NTFS ∩ Share
```

Examples:

| NTFS | Share | Effective |
|---|---|---|
| Modify | Read | **Read** |
| Read & Execute | Full Control | **Read & Execute** |
| Full Control | Change | **Change** |

A NULL DACL on the share is interpreted as "no restriction over SMB" — not as "Full Control" — and marked with the dedicated status `Unrestricted`, instead of fabricating an artificial `0xFFFFFFFF` mask. This matters because otherwise an auditor could think someone deliberately granted Full Control.

##### 2.5 Diagnostic markers

During evaluation Stars collects structured **diagnostic markers**:

* `NonCanonicalDaclOrder` — the order of ACEs does not match Windows' canonical pattern (`explicit deny → explicit allow → inherited deny → inherited allow`). Windows still evaluates the DACL in **stored order**; the tool surfaces this as an audit hint, since a non-canonical DACL usually arose from manual editing.
* `UnsupportedShareAces { count }` — the share DACL contained ACE types the parser could not evaluate (object, callback, or vendor-specific ACEs). The effective mask is then a **lower bound**; a hidden Deny could flip the result.
* `unsupported_ace_count > 0` (NTFS side) — the same thing on the NTFS DACL.

These markers feed into the `incomplete` flag of risk findings (see section 6).

#### <a name="3-how-effective-permissions-are-computed"></a>3. How effective permissions are computed

The calculation runs in four phases:

##### Phase 1 — Token building

From user SID + memberships + local groups + well-knowns, a **HashSet** of all effective token SIDs is built.

##### Phase 2 — DACL application (stored order)

For every ACE in **stored order**:

* Check the trustee SID against the token → no match? Skip.
* Deny ACE → add bits to the **Deny mask**.
* Allow ACE → add bits to the **Allow mask**, **but only bits that are not already in the Deny mask** (this is Windows semantics: a Deny seen earlier overrides a later Allow).

Generic bits (`GENERIC_ALL`, `GENERIC_READ`, etc.) are expanded into their concrete bits. INHERIT_ONLY ACEs are filtered out — they do not apply to the current object, only to children.

##### Phase 3 — Owner special rule

If the user is the owner of the object, Stars adds `READ_CONTROL` and `WRITE_DAC` to the Allow mask — Windows always grants the owner the right to read and modify the ACL, regardless of DACL content.

##### Phase 4 — Share combination

When a share context is present:
* `share_status == Applied(mask)` → Effective = NTFS AND Share-Mask
* `share_status == Unrestricted` (NULL DACL) → Effective = NTFS (no additional filter)
* `share_status == ReadFailed` → Effective = NTFS, **incomplete** flag is set
* `share_status == NotApplicable` → Effective = NTFS (no share context)

The end result is the **Effective Access Mask**, plus the full explanation path with every effective membership and ACE.

#### <a name="4-the-six-risk-rules"></a>4. The six risk rules in detail

All rules live in `crates/risk_engine/src/rules.rs` and are registered via `RuleRegistry::with_defaults()`. Each rule is an independent implementation of the `RiskRule` trait and can be tested in isolation.

##### 4.1 Rule: `FULL_CONTROL` — severity **Critical**

**Source:** `FullControlRule` (rules.rs:135ff)

**Trigger:** The effective mask contains **all** bits of `MASK_FULL_CONTROL` (`0x001F01FF` plus `WRITE_DAC`, `WRITE_OWNER`).

**Logic:** `effective_mask & MASK_FULL_CONTROL == MASK_FULL_CONTROL`

**Severity justification:**
Full Control gives the principal the right to change the ACL itself (`WRITE_DAC`) and to take ownership (`WRITE_OWNER`). Anyone with Full Control on an object can grant themselves practically any permission — and audit-relevant changes become indistinguishable from a normal write. This is the most severe finding the engine knows.

**When this is *normal*:**
* `BUILTIN\Administrators` on system paths (`C:\Windows`, `C:\Program Files`)
* `SYSTEM` on practically every system path
* `TrustedInstaller` on components that only Windows Update should touch
* The owner on their own user profile

**When this is *critical*:**
* `Everyone`, `Authenticated Users`, `Domain Users` have Full Control on a share → immediate action required
* A normal user has Full Control on a *foreign* share or on a shared data directory
* A service account has Full Control beyond its own data directory

##### 4.2 Rule: `WRITE_ACCESS` — severity **High**

**Source:** `WriteAccessRule` (rules.rs:166ff)

**Trigger:** The effective mask contains Modify or Write, but **not** Full Control.

**Logic:** `(MASK_MODIFY or MASK_WRITE) set, MASK_FULL_CONTROL not set`

**Severity justification:**
Write access allows creating, modifying, or deleting files. On data that others use for reading (configs, scripts, reports), this is a **tampering risk**: an attacker (or an accidentally compromised account) can swap content. Write access on user profiles is normal; on system files it is not.

**Relation to Full Control:**
The rule deliberately does **not** fire when Full Control is present — that is already covered by `FullControlRule`. Otherwise there would be duplicate findings for the same situation.

**When this is *normal*:**
* User on their own `%USERPROFILE%`
* Service account on its data directory
* Editors on a share (domain local group `<Share>_Modify`)

**When this is *critical*:**
* `Everyone` or `Authenticated Users` have Modify on system or program files
* Normal users have Modify on configuration files (configurations can no longer be trusted)

##### 4.3 Rule: `PERMISSION_CHANGE` / `OWNER_CHANGE` / `DELETE_RIGHT` / `DELETE_CHILD_RIGHT`

**Source:** `AdminRightsRule` (rules.rs:217ff)

This rule closes a gap left by `WriteAccessRule` and `FullControlRule`: **destructive or administrative individual rights** that are not included in Modify/Write but already represent a privilege escalation opportunity.

**Bits reported individually:**

| Rule-ID | Bit | Severity | Meaning |
|---|---|---|---|
| `PERMISSION_CHANGE` | `FILE_WRITE_DAC` | **High** | Can change the ACL → can grant themselves further rights |
| `OWNER_CHANGE` | `FILE_WRITE_OWNER` | **High** | Can take ownership → the owner special rule then works in favor of the attacker |
| `DELETE_RIGHT` | `FILE_DELETE` | **Medium** | Can delete the object itself |
| `DELETE_CHILD_RIGHT` | `FILE_DELETE_CHILD` | **Medium** | Can delete children of a folder without write access on the children themselves |

**Important property:** The rule **stays silent** when the principal already has Full Control — that is already `FULL_CONTROL` Critical, and additional break-down would only produce noise.

**Justification for the severity differences:**
* `WRITE_DAC` and `WRITE_OWNER` are **High** because they enable privilege escalation — the principal can grant themselves further rights without the audit tool noticing.
* `DELETE` and `DELETE_CHILD` are **Medium** — no privilege gain, but tampering and data loss are possible.

##### 4.4 Rule: `BROAD_GROUP_WRITE` — severity **Critical**

**Source:** `BroadGroupWriteRule` (rules.rs:290ff)

**Trigger:** Write access arose from an ACE on a **broad well-known group**, **and** that ACE actually contributed write bits.

**Broad SIDs:**

| SID | Meaning |
|---|---|
| `S-1-1-0` | `Everyone` — literally anyone, including anonymous accesses depending on configuration |
| `S-1-5-11` | `Authenticated Users` — anyone with a valid domain/local login |
| `S-1-5-7` | `Anonymous Logon` — accesses without authentication |
| `S-1-5-2` | `NETWORK` — anyone accessing via SMB |

**Important (anti-false-positive):** The rule fires **only** when the broad principal actually contributed **write bits** to the effective mask (via the `contributing_sids` field). If `Everyone` only has Read and the Modify rights come through a specific group, it is **not** reported. Otherwise it would be a classic false alarm that makes the entire audit unusable.

**Severity justification:**
Write access via a broad SID is the worst configuration that practically occurs — it makes every user on the network (or with `Anonymous Logon`, every unauthenticated client) a potential attacker on that path. It is essentially an "open door" that often arose historically from quick fixes and was never rolled back.

##### 4.5 Rule: `DIRECT_USER_ACE` — severity **Low**

**Source:** `DirectUserAceRule` (rules.rs:356ff)

**Trigger:** The user has a **direct explicit ACE** on the path — not via a group but on their own user SID, **not inherited** but explicitly assigned on the object.

**Data source:** The `matched_aces` field of `EffectivePermission`. The rule is therefore **localization-safe** and independent of the explanation text — it also works on German systems with translated names.

**Treatment of Allow and Deny:** Both are reported — a direct explicit Deny violates the best practice just as much as a direct explicit Allow.

**INHERIT_ONLY:** ACEs with `INHERIT_ONLY_ACE` flag are deliberately filtered out of `matched_aces` (the engine removes them earlier). A direct user ACE that would only affect children has no effect on the current object and does not trigger a finding here.

**Severity justification:**
This is **Low** because it is rarely a concrete security risk — rather a **management problem**. Best practice in AD environments is `AGDLP` (Account → Global Group → Domain Local Group → Permission): permissions go through groups, never directly on users. Direct user ACEs are:
* hard to audit (they become invisible once the user is removed from the directory → orphaned SID)
* hard to maintain (every path must be touched individually instead of swapping a group)
* historically often a sign of "just rubber-stamped" actions

`incomplete` flag: always `false`. The structured ACE source is an NTFS property, independent of share status.

##### 4.6 Rule: `SENSITIVE_PATH` — severity **Medium**

**Source:** `SensitivePathRule` (rules.rs:394ff)

**Trigger:** The path name contains one of the following keywords (case-insensitive), **and** the principal actually has access (`effective_mask > 0`):

```
password, passwort, pwd, login, credential, credentials, secret, secrets,
token, api-key, apikey, keyfile, private-key, ssh-key, private_key, ssh_key
```

**Important (anti-false-positive):** The rule reports **only** when `effective_mask > 0`. A path named `passwords.txt` on which the identity is explicitly denied is **not** a finding — otherwise Stars would falsely report a non-access as a risk.

**What the rule does *not* do:** It does not open the file, does not read content, does not search for actual secrets in cleartext. That would itself be a privacy problem. It looks **only at the path name** as a heuristic.

**Severity justification:**
Medium, because the **path name alone** is a weak indicator. `password-policies.pdf` matches the keyword but is harmless. `c:\dev\password-resets\logs\` is highly sensitive. Stars does not distinguish that — the auditor must. The hint still matters because:
* sensitive paths often carry overly broad permissions (convenience over security)
* sensitive paths are typical targets in pentests and real attacks

`incomplete` flag: always `false`. The path name is an NTFS property, independent of share status.

#### <a name="5-the-severity-model"></a>5. The severity model

Stars classifies every finding into one of five levels (`adpa_core::model::RiskSeverity`):

| Severity | Meaning | Examples from the rules |
|---|---|---|
| **Critical** | Immediate attention. Privilege escalation, tampering by broad user groups, or direct data loss are imminent. | `FULL_CONTROL`, `BROAD_GROUP_WRITE` |
| **High** | Elevated risk. Write rights on valuable objects, individual privilege escalation bits. | `WRITE_ACCESS`, `PERMISSION_CHANGE`, `OWNER_CHANGE` |
| **Medium** | Worth attention. Destructive individual rights, sensitive path names. | `DELETE_RIGHT`, `DELETE_CHILD_RIGHT`, `SENSITIVE_PATH` |
| **Low** | More of a best-practice or management finding than an acute risk. | `DIRECT_USER_ACE` |
| **Info** | Hints without risk character (not currently used by any default rule; reserved for extensions). | — |

**Important:** Severity is **not** an absolute value. A `FULL_CONTROL` Critical from `SYSTEM` on `C:\Windows` is trivial and correct; the same Critical from `Authenticated Users` on `\\server\Accounting` is an emergency. Severity sorts by **technical seriousness**; context must be added by the auditor.

#### <a name="6-the-incomplete-marker"></a>6. The `incomplete` marker

Every `RiskFinding` carries a boolean `incomplete` field. It marks findings whose underlying **permission evaluation** had gaps and which should therefore be read **cautiously**.

`incomplete = true` is set when the underlying evaluation has at least one of the gaps listed below. **Authoritative source:** `crates/risk_engine/src/rules.rs::is_incomplete()` — the list here must stay in sync with the code (last verified for v1.5.3).

**Direct evaluation gaps:**

1. **Share DACL was not readable** (`ShareEvalStatus::ReadFailed(...)`).
   `effective_mask` is then only an **NTFS lower bound** — actual SMB access could be more restrictive.

2. **DACL contained unsupported NTFS ACEs** (`unsupported_ace_count > 0`).
   Object, callback, or conditional ACEs are skipped by the parser; a hidden Deny could flip the result.

3. **Local server groups could not be resolved** (`LocalGroupEvalStatus::NotAvailable(...)`).
   ACEs targeting e.g. a local `Administrators` group are then invisible; effective rights may be **too low**. Since v1.5.3 this also covers the case where `NetUserGetLocalGroups` returns `NERR_USER_NOT_FOUND` for **all** tried account name forms (typical with trust / LSA identities backed by a NetBIOS domain) — see ADR 0040.

**Structural identity / group gaps** (variant-tagged `PermissionDiagnostic` markers in `EffectivePermission.diagnostics`):

4. **Share DACL contained unsupported ACEs** (`PermissionDiagnostic::UnsupportedShareAces`).
   Analogous to point 2 but on the share side.

5. **Domain group recursion was flat** (`PermissionDiagnostic::DomainGroupRecursionIncomplete`).
   Group resolution via the SAM/LSA fallback (`NetUserGetGroups`) returns only direct global groups — nested domain groups are not recursively resolved. See ADR 0033.

6. **Identity lives outside the configured LDAP base** (`PermissionDiagnostic::IdentityNotInConfiguredLdapBase`).
   LSA resolved the SID, but the configured `base_dn` does not index it — typical in multi-domain forests / trusts. Cross-domain memberships may be missing. See ADR 0034 / 0036.

7. **LDAP identity lookup failed with a technical error** (`PermissionDiagnostic::IdentityLookupFailed { reason }`).
   Bind, timeout, DC unreachable. The analysis runs with a placeholder identity and an empty token — `reason` carries the underlying error. See ADR 0039.

8. **Recursive group resolution failed or was skipped** (`PermissionDiagnostic::GroupResolutionFailed { reason }`).
   Also fires when the `OutsideConfiguredLdapBase` path has no GC crawl logic and memberships remain structurally empty. See ADR 0039.

Markers that do **not** contribute to incomplete — informational:

- `PermissionDiagnostic::IdentityDisabled` (account flagged disabled in AD via `userAccountControl`; ACL-theoretical rights are correct).
- `PermissionDiagnostic::IdentityDisabledStatusUnknown` (`disabled` flag not reliably determinable; orthogonal to permission computation).
- `PermissionDiagnostic::NonCanonicalDaclOrder { at_index }` (DACL not in Windows canonical order; AccessCheck still works correctly on the stored order).

A finding with `incomplete = true` does **not** mean it is wrong — it means the underlying result might not be 100 % complete. For an audit that is the honest statement; for an automated escalation you should not blindly trust it.

> **Doc consistency check (contribution policy):** When `PermissionDiagnostic` is extended with a variant that should count as an incomplete trigger, the following must be updated **at the same time**:
> - `crates/risk_engine/src/rules.rs::is_incomplete()` (the matching list),
> - this section (audit-kriterien.md),
> - the marker table in `docs/features-and-limitations.md`,
> - the marker tables in `docs/anwender-handbuch.md` and `docs/user-guide.md`.
>
> This consistency check addresses review 2026-06-04 round 5 finding 2.

#### <a name="7-optimal-rights"></a>7. Optimal rights per role and path class

This section shows **what counts as well configured**. Stars flags deviations through the risk rules — the following sections give the auditor the yardsticks against which to judge findings.

The recommendations follow long-established Microsoft best practices, notably the **AGDLP model**:

```
Account  →  Global Group  →  Domain Local Group  →  Permission
```

Concretely: users go into global groups, global groups into domain local groups, **NTFS rights are assigned exclusively to domain local groups** — never directly to users, never to global groups, never to broad well-known identities.

##### 7.1 System paths — `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`

**Optimal ACL:**

| Identity | NTFS right | Justification |
|---|---|---|
| `NT AUTHORITY\SYSTEM` (S-1-5-18) | **Full Control** | Windows services run as SYSTEM and must be able to modify system files at any time |
| `BUILTIN\Administrators` (S-1-5-32-544) | **Full Control** | Administrative maintenance, manual updates |
| `TrustedInstaller` | **Full Control** on system components | Only Windows Update should touch core files |
| `BUILTIN\Users` (S-1-5-32-545) | **Read & Execute** | Programs must be readable and runnable |
| `Authenticated Users` | **Read & Execute** | Like above, also covers domain-joined users |
| `Everyone` | Nothing (or at most Read) | Anonymous accesses have no business here |

**What Stars reports (and why it is *normal* here):**
* `FULL_CONTROL` for Administrators → expected on system paths, no real finding
* `FULL_CONTROL` for SYSTEM → expected
* `WRITE_ACCESS` for Modify holders (e.g. `TrustedInstaller`) → expected

**What Stars reports that is *critical*:**
* `BROAD_GROUP_WRITE` for `Everyone` or `Authenticated Users` on system files → real finding, act immediately
* `WRITE_ACCESS` for normal users on system files → system integrity at risk

##### 7.2 User profiles — `C:\Users\<user>`

**Optimal ACL:**

| Identity | NTFS right | Justification |
|---|---|---|
| The user themselves | **Full Control** on their own profile | Own data, own responsibility |
| `NT AUTHORITY\SYSTEM` | **Full Control** | Backup, profile loading |
| `BUILTIN\Administrators` | **Full Control** (or deliberately removed for privacy) | Administrative maintenance |
| **Other users** | Nothing | Strict — foreign profiles are off-limits |

**What Stars reports:**
* `FULL_CONTROL` for the profile owner → expected
* `FULL_CONTROL` for SYSTEM/Administrators → expected
* `FULL_CONTROL` for **other** users → real finding (privacy violation)
* `BROAD_GROUP_WRITE` on a profile, ever → real finding

##### 7.3 Shared data directories — `\\server\Data\…`

The AGDLP model becomes especially visible here. An example ACL for `\\server\Accounting`:

| Identity | NTFS right | Share right | Justification |
|---|---|---|---|
| `NT AUTHORITY\SYSTEM` | Full Control | — | Backup agent |
| `BUILTIN\Administrators` | Full Control | Full Control | Emergency access |
| Domain Local Group `FS_Accounting_RW` | **Modify** | **Change** | Editor role |
| Domain Local Group `FS_Accounting_RO` | **Read & Execute** | **Read** | Reader role |
| `CREATOR OWNER` | Modify (inherit-only) | — | Edit one's own documents |
| **No one else** | Nothing | Nothing | Strict |

The members of the domain local groups are **global groups** (e.g. `GG_Accounting_Staff`) into which individual users go as account members.

**What Stars reports:**
* `FULL_CONTROL` for `SYSTEM` and Administrators → expected
* `WRITE_ACCESS` for members of `FS_Accounting_RW` → expected
* `DIRECT_USER_ACE` for any user → best-practice violation (Low)
* `BROAD_GROUP_WRITE` ever → real Critical finding

##### 7.4 Service accounts and service data directories

**Optimal ACL:** A service account may write **only** in its own data directory. Read access only on configuration files the service actually needs.

| Identity | NTFS right on service data dir | Justification |
|---|---|---|
| `NT AUTHORITY\SYSTEM` | Full Control | Backup |
| Administrators | Full Control | Maintenance |
| The service account itself | **Modify** | Write to data directory |
| **No one else** | Nothing | Strict |

**What Stars reports:**
* `WRITE_ACCESS` for the service account on *its* directory → expected
* `WRITE_ACCESS` for the service account on *other* directories → real finding
* `FULL_CONTROL` for the service account → almost always excessive; Modify would have sufficed

##### 7.5 Administrators on data (not system)

A particular question: should `BUILTIN\Administrators` have Full Control on **data** directories?

* **System paths:** yes, always (emergency maintenance, recovery).
* **Data paths:** technically yes, but **deliberately set and documented**. Whoever is "Admin" has practically unrestricted access to the server — the audit log should make this traceable.
* **Sensitive data paths (payroll, HR, executive):** worth considering replacing administrator access with a separate permission structure (e.g. a dedicated domain local group `FS_HR_FullControl` with *explicit* membership) instead of relying on global administrator membership. This protects against accidental data leakage through general admin tasks.

Stars reports `FULL_CONTROL` as Critical here — how seriously to take that in each case is up to the auditor based on the path's sensitivity.

#### <a name="8-sensitive-paths"></a>8. Sensitive paths — what Stars takes as a hint

The `SensitivePathRule` (see 4.6) searches for keywords in the path name. It does not report the **content**, only the **suspicion**.

**Practical reading hints:**

| Path name contains | Typical meaning | Audit attention |
|---|---|---|
| `password`, `passwort`, `pwd` | Password lists, reset workflows, configurations | Very high — even if the path is "password-policy.docx", access should be strictly controlled |
| `credential`, `credentials` | Credential stores, script configs with cleartext logins | Very high |
| `secret`, `secrets` | Application secrets, tokens | Very high |
| `token`, `api-key`, `apikey` | OAuth tokens, API keys | Very high |
| `private-key`, `private_key`, `ssh-key`, `ssh_key`, `keyfile` | Private crypto keys | **Highest priority** — a compromised key is not revocable like a password |
| `login` | Login scripts, profiles, sometimes configs | High |

**What Stars *does not* cover** (and the auditor should additionally check):
* Encrypted containers whose file name sounds neutral
* Configuration files with cleartext credentials but innocuous names (`config.ini`, `web.config`, `appsettings.json`)
* Database backups (`.bak`, `.dmp`) that may contain personal data

#### <a name="9-what-stars-does-not-do"></a>9. What Stars deliberately does not do

The tool is **permanently designed as a read-only analysis and display utility**. The following is not planned and will not be implemented in the future:

* **Change permissions** — neither automatically nor on a button click
* **Clean up** or "repair" ACLs
* **Change AD group memberships**
* **Change AD users**
* **Create, change, or delete shares**
* **Modify files or folders on target systems**
* **Automatically apply repair suggestions**
* **Deploy agents to file servers**
* **SIEM integration with active response**
* **Open file contents for the purpose of secret hunting** (`SensitivePathRule` only looks at the path name)

This self-restriction is not coincidental but essential: an audit tool that can do more is an attack tool. Stars must not become a risk itself.

#### <a name="10-known-limits"></a>10. Known limits of the evaluation

Even a technically correct audit has limits — Stars does not evaluate facts it cannot see:

##### 10.1 What Stars *sees*

* NTFS DACLs in the order in which they are stored
* SMB share DACLs (if readable)
* Group memberships (via SAM/LSA, optionally LDAP)
* Local server groups (via NetUserGetLocalGroups)
* AccessContext (local vs. SMB) — derived from the path

##### 10.2 What Stars *does not* see

* **File contents** — what is in `Payroll_2025.xlsx` is irrelevant to the permission calculation
* **Audit logs** — *who actually did what when* belongs in the event log, not the DACL
* **Central Access Rules (CAR)** — Dynamic Access Control with central policies is not yet evaluated by the parser
* **SACLs** (System Access Control Lists) — only DACLs are read; SACLs for audit logging are a different topic
* **Mandatory Integrity Control (Integrity Levels)** — Low/Medium/High integrity labels are not taken into account
* **Conditional ACEs** — reported as `unsupported`, not evaluated
* **Object and callback ACEs** — also marked as `unsupported`

##### 10.3 Limits of the heuristics

* `SENSITIVE_PATH` is keyword-based — `password-policy.pdf` matches, `creds.cfg` does not
* `BROAD_GROUP_WRITE` covers the four practically most important well-knowns. Your own large distribution groups (`All Employees`) are not on the list as domain groups — the auditor must recognize such own groups as "broad" manually
* Severity is **technically classified**, not **business-classified** — a Critical can be normal (SYSTEM), a Low can be dangerous (Direct ACE on an executive's folder)

##### 10.4 Platform verification

Stars is verified or deliberately not verified against the following Windows versions:

| Platform | Status |
|---|---|
| **Windows Server 2022 Standard** | ✅ **tested** — audit paths (identity resolution, NTFS DACL, SMB share DACL, risk rules, GUI) were exercised on a real domain controller of this version. |
| **Windows Server 2025** | ⚠ **not yet verified** — no systematic verification. |
| **Other Windows versions** (10/11, older servers) | Implementation target but not systematically verified. The LSA/NetAPI layer is expected to work identically on Windows 10/11 and Server 2016+, but that expectation is no substitute for testing. |

This list is updated with every documented test run. A missing entry does **not** mean "does not work" — it means **"not verified"**.

> **Important — liability and personal responsibility:** "Tested" only means the audit functions were manually exercised on the named platform. It is **not a guarantee of correctness, completeness, or suitability for any particular use**. Use of Stars on **all** platforms — including the tested ones — is **at the sole risk of the user**. Birger Labinsch assumes **no liability** for damages, data loss, faulty audit results, or decisions derived from them. The full disclaimer is in the repository's README and is part of every use of this tool.

##### 10.5 Audit workflow recommendation

1. **Choose the target identity carefully** — as which user should the check be done? A domain admin sees Full Control everywhere; that produces noise. Useful targets:
   * Deputy accounts (test accounts with a normal profile)
   * Service accounts (check their specific scope of effect)
   * `Authenticated Users` and `Everyone` (deliberately: what can "anyone on the domain" actually do?)
2. **Limit scan depth** — the whole root path of a server takes hours and produces thousands of findings. Better to scan per department/share
3. **Treat `incomplete = true` findings separately** — they are not hard statements but investigation requests
4. **HTML report for documentation, CSV for postprocessing** — both export formats are available and reportable
5. **Use the Delta tab for recurring audits** — for regular checks of the same share, the Delta tab brings out the changes (added paths, changed rights). Prerequisite: the scans are stored in the local SQLite history (see chapter 11)
6. **Enter names instead of SIDs** — the "User/group" field has a live search with up to 15 suggestions per keystroke. Four type markers narrow the class:
   * `[U]` = domain/local user
   * `[G]` = global (domain) group
   * `[L]` = local group (`BUILTIN\…`)
   * `[W]` = well-known identity (`Everyone`, `Authenticated Users`, `SYSTEM`, `NETWORK`, `ANONYMOUS LOGON`, …)

   Clicking takes the name; the `LookupAccountNameW` call delivers the SID automatically. The "🔍 Resolve SID" button performs the same resolution without search, if the name is already in mind.

#### <a name="11-persisted-data"></a>11. Persisted data and scan history

Stars stores every completed scan in a **local SQLite database** so the Delta tab can compare two runs and identity resolutions are cached across sessions.

**Location:** `%APPDATA%\Stars\stars_data.db` (typically `C:\Users\<account>\AppData\Roaming\Stars\stars_data.db`).
If `%APPDATA%` is not set, Stars falls back to the directory next to the EXE — relevant only for development runs.

**Tables:**

| Table | Content |
|---|---|
| `scan_runs` | One row per completed scan: UUID, start time, end time, target path |
| `permissions` | Every evaluated path per run with identity, NTFS mask, share mask, effective mask, full explanation path |
| `scan_errors` | Walk/eval errors per scan (e.g. "Access denied", "Path not found", "Cancelled by user") |
| `identity_cache` | SAM/LDAP resolution cache (SID → name, domain, group memberships) — speeds up repeated scans for the same identity |

**Auditor-relevant properties:**

* **Separate per user profile.** If multiple admins maintain the same server, each has their own audit history. Clean separation of activity traces, but not a "team audit pool".
* **Survives a Stars uninstall** — by default the uninstaller removes only its install directory (`%LOCALAPPDATA%\Stars\` without `logs\`). The audit history at `%APPDATA%\Stars\stars_data.db` is kept. This is by design: audit history is evidence and should not vanish accidentally with the tool. To remove it deliberately, check the optional component **"Remove audit history and logs"** in the uninstaller — it is off by default.
* **No password, no encryption of the file itself.** Anyone with access to the user profile can read the audit results. For sensitive audit data the profile path itself must be secured accordingly (NTFS permissions on the directory, BitLocker on the disk). Stars deliberately does **not** encrypt — so the auditor can open the DB with standard SQLite tools.
* **Inspectable in read-only mode** — any SQLite tool (DB Browser for SQLite, DBeaver, `sqlite3.exe`) can open it, even when Stars is not running. Enables external evaluation or archiving.
* **Schema migrations are idempotent** — on start the schema is migrated up if needed (`run_migrations`). Old DBs continue to work.
* **Persistence errors are visibly reported, not swallowed.** If creating the DB fails (permissions, disk space), the scan still runs but every scan carries a visible persistence error in the status bar. So the auditor cannot accidentally believe the history is intact when it is not.

**What Stars *does not* do with the database:**
* No automatic size limit or retention — old scans stay until they are removed manually.
* No replication, no cloud sync, no multi-user synchronization.
* No "in-transit" encryption — the DB is a local file, nothing goes over the network.
* No backups — the auditor is responsible for adding the file to their backup routine if the audit history must be retained long-term.

#### Appendix A — Glossary

| Term | Meaning |
|---|---|
| **SID** | Security Identifier — the technical identity in Windows, e.g. `S-1-5-21-1234-1234-1234-500` for the domain admin |
| **DACL** | Discretionary Access Control List — list of ACEs that decide who may do what |
| **ACE** | Access Control Entry — a single entry in the DACL |
| **SACL** | System Access Control List — list for audit logging (not evaluated by Stars) |
| **Effective Mask** | Computed actual permission after applying all relevant ACEs |
| **Access Mask** | Raw permission value as a 32-bit mask, e.g. `0x001F01FF` for Full Control |
| **AGDLP** | Account → Global → Domain Local → Permission, Microsoft best practice for permission assignment |
| **AccessContext** | Stars concept: simulates local vs. remote SMB access for correct token building |
| **incomplete** | Marker on risk findings: the evaluation had gaps, the result is an approximation |
| **WARP** | Software D3D12 renderer, irrelevant for audit logic, relevant for the GUI on a DC |
| **`[U]` / `[G]` / `[L]` / `[W]`** | Type markers in the GUI's live search: user / global (domain) group / local group (`BUILTIN\…`) / well-known SID. Precede the plain-text name so the auditor immediately sees the membership class |
| **Live search** | Autocomplete helper in the name field of the Analyze and Scan masks. From a cache list (`NetUserEnum` + `NetGroupEnum` + `NetLocalGroupEnum` + well-known table) up to 15 matches are shown per query. Click takes the name; the SID is resolved automatically via `LookupAccountNameW` |

#### Appendix B — Code cross-references

| Concept | Implemented in |
|---|---|
| Effective-rights calculation | `crates/permission_engine/src/engine.rs::evaluate` |
| Token building with AccessContext | `crates/permission_engine/src/lib.rs::build_token_sids_with_context` |
| SAM-based identity resolution | `crates/ad_resolver/src/sam.rs` |
| LDAP-based identity resolution | `crates/ad_resolver/src/resolver.rs` |
| Local server group resolution | `crates/ad_resolver/src/local_groups.rs` |
| All risk rules | `crates/risk_engine/src/rules.rs` |
| Structured diagnostic markers | `adpa_core::model::PermissionDiagnostic` |
| Explanation path | `adpa_core::model::PermissionPath` |
| HTML export | `crates/exporter/src/html.rs` |
| Persistence (SQLite, schema, migrations) | `crates/persistence/src/` |
| Delta comparison of two scan runs | `crates/persistence/src/delta.rs::compare_scans` |
| Database default path | `crates/gui/src/worker.rs::default_db_path` |
| Identity enumeration for the GUI live search | `crates/ad_resolver/src/enumerate.rs::enumerate_all` |
| Name → SID (LSA, GUI button and live search) | `crates/ad_resolver/src/sam.rs::lookup_sid_for_account` |

---

*This document is part of the Stars documentation and is versioned with the repository. Changes to rules, severities, or thresholds must be reflected here, otherwise the documentation drifts out of sync.*

---

### Authorship

**Concept, specification, direction, and review:** Birger Labinsch — IT Specialist for Application Development / Prompt Engineer.

**Authored by:** Claude Opus 4.7 (Anthropic) as an AI model, under direct guidance and review by Birger Labinsch. Content derived from the code actually implemented in the repository (`crates/risk_engine/src/rules.rs`, `crates/permission_engine/`, `crates/ad_resolver/`) — no invented rules, no wishful thinking.

Birger Labinsch did **not** write the code documented here himself; as a prompt engineer he commissioned, directed, and approved it.
