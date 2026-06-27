# Stars — User Guide

**Version:** v1.5.16 (2026-06-06)
**Audience:** Windows / AD administrators who want to audit NTFS and
SMB permissions **without changing anything**.

> **Read-only principle:** Stars never writes to NTFS, SMB shares, or
> Active Directory. It is a pure analysis, display, and export tool.
> Producing the actual fix for any issue surfaced by Stars remains
> your responsibility.

---

## Contents

1. [What can Stars do?](#what-can-stars-do)
2. [Installation and prerequisites](#installation-and-prerequisites)
3. [First run — the GUI](#first-run--the-gui)
4. [The four GUI tabs](#the-four-gui-tabs)
5. [Identity input forms](#identity-input-forms)
6. [Active Directory binding (optional)](#active-directory-binding-optional)
7. [Local paths vs. SMB shares](#local-paths-vs-smb-shares)
8. [Rights labels — what F, RX, RW mean](#rights-labels--what-f-rx-rw-mean)
9. [Reading findings — diagnostic markers](#reading-findings--diagnostic-markers)
10. [Exporting — CSV, JSON, HTML](#exporting--csv-json-html)
11. [The CLI](#the-cli)
12. [Where is data stored?](#where-is-data-stored)
13. [Updates](#updates)
14. [FAQ](#faq)
15. [Further reading](#further-reading)

---

## What can Stars do?

Stars answers two core audit questions for any given NTFS path or SMB
share:

1. **"What can this user effectively do here?"** — per path one
   explainable finding (Read / Write / Modify / Full Control) plus a
   traceable permission path.
2. **"Who can access this path at all?"** — per path a trustee list
   (users / groups), separated by NTFS and Share DACL.

To answer them, Stars reads:

- **Active Directory** (via LDAP bind): identities, recursive group
  memberships (incl. cross-domain trust detection), primary groups,
  `userAccountControl` (account disabled).
- **Local server groups** on the share's target server
  (`BUILTIN\Administrators`, locally defined groups).
- **NTFS DACL** of every path — allow / deny ACEs, explicit and
  inherited entries, inheritance flags, owner.
- **SMB share DACL** and combines it restrictively with the NTFS mask
  (Share ∩ NTFS).
- **Reparse points / junctions / symlinks** — followed; loops are
  detected and surfaced.
- **Long paths** (`\\?\…`, UNC long-path form `\\?\UNC\…`).

For each finding Stars builds **structured diagnostic markers** when
assumptions are uncertain — the report never shows just a right, but
also what Stars knew and *did not know* while computing it.

### What Stars deliberately does **not** do

- Modify permissions (neither NTFS, nor share, nor AD).
- Modify AD accounts or group memberships.
- Create, move, or delete files or folders.
- ACL repair, permission cleanup, remediation workflows.
- Automatically apply recommendations.
- Open file contents (not even to scan for passwords; files with
  suspicious names are only **flagged**, never read).

The full list lives in
[features-and-limitations.md](features-and-limitations.md).

---

## Installation and prerequisites

### Prerequisites

- **Windows 10 / 11** or **Windows Server 2019 / 2022 / 2025**.
- For full functionality: **domain membership** or at least an AD
  read account.
- At least **read-DACL permission** on the analyzed paths (or
  `SeBackupPrivilege`).
- Recommended: run Stars as an account with read privileges, **not**
  as Administrator.

### Download

Get the installer from the GitHub release page:
[releases](https://github.com/Birgerson/stars-ad-permission-analyzer/releases).
Currently recommended: `Stars-v1.7.1-Setup.exe`.

### Installation

1. Double-click the installer.
2. Default install path: `C:\Program Files\Stars\`.
3. A "Stars" start menu entry is created.
4. **No** drivers, **no** services, **no** auto-start components —
   Stars only runs while you have it open.

### First start

On first start Stars creates the scan history at
`%APPDATA%\Stars\stars_data.db` (SQLite file, only you have read
access).

---

## First run — the GUI

After starting Stars the main window shows **four tabs:** `Analyze`,
`Scan Tree`, `Delta`, `Info`. **Recommended first workflow:**

1. Open the **`Analyze`** tab — type an identity (user/group + SID)
   and a path. Hit "Analyze".
2. Read the result: effective right, full explanation chain,
   diagnostic markers.
3. Optional: "Who has access?" for the path-centric trustee table.

If you only want to see what Stars can do at all, start with any local
folder and your own user SID — that works without LDAP configuration
and shows the engine in action.

> **Important on terminology:** "Identity", "Trustees", and "Risk
> findings" are **not separate tabs**. They are sections inside the
> four real tabs. Earlier versions of this guide accidentally listed
> them as five tabs — this is the corrected wording.

---

## The four GUI tabs

### `Analyze` tab — single-path analysis

**Purpose:** You have a specific path and want to know what a given
user can effectively do there.

**Fields (sections inside the tab):**

- **Target** — path, local (`C:\data\…`) or UNC (`\\server\share\…`).
- **Identity resolution** — user/group via live search or direct
  SID, plus mode (Off = SAM/LSA, LDAPS, plaintext LDAP). See
  [Identity input forms](#identity-input-forms).
- **SMB share (optional)** — SMB server and share name. Auto-detected
  for UNC paths; on local paths on a share, set manually if you also
  want the share mask evaluated.
- **Analyze** — runs the identity-bound evaluation.
- **Who has access?** — runs the **path-centric trustee table**
  instead: all trustees with their ACEs, NTFS and share separated.
  A share-DACL read failure appears as a typed diagnostic entry
  (`entry_kind: "diagnostic"`), never silently dropped.

**Result of "Analyze":**

- effective right (Read / Write / Modify / Full Control),
- NTFS and share rights separately,
- explainable permission path
  (`User → Group → … → ACE → normalized right`),
- all diagnostic markers.

### `Scan Tree` tab — recursive directory scan

**Purpose:** Audit a whole directory tree — typical for the periodic
"how does Q3 look right now?" question.

**Fields:**

- **Root path**, **identity**, **SMB server** / **share name** as in
  `Analyze`.
- **Maximum scan depth** — protects against runaway walks; empty =
  unbounded.
- **Start scan** — cancellable any time via the cancel button; the
  GUI stays responsive during the scan.

**Result:** a table of all paths, their effective rights, a per-path
trustee table, and a **risk findings section** with the rules that
fired per path. Auto-persisted to the SQLite scan history.

A path whose evaluation is uncertain or informational is shown in the
**error color** in the list. **Expand the row** (click it) to read the
exact reason: a **Diagnostics** block lists one line per marker — the
same wording the CLI and reports use — so you see *why* the row is
flagged, not just *that* it is. See
[Reading findings — diagnostic markers](#reading-findings--diagnostic-markers)
for what each marker means.

**Risk findings:** Stars applies six built-in risk rules to every
finding:

- **FullControlRule** (Critical) — user has Full Control.
- **WriteAccessRule** (High) — user has write rights.
- **AdminRightsRule** (High) — user carries admin-relevant rights
  (TakeOwnership, WriteDAC).
- **BroadGroupWriteRule** (Medium) — write rights via a wide group
  (`Everyone`, `Authenticated Users`).
- **DirectUserAceRule** (Low) — direct ACE on the user (not via a
  group).
- **SensitivePathRule** (variable) — path contains sensitive
  keywords (`password`, `credentials`, …).

Findings carry `incomplete = true` when the underlying finding is
incomplete — see the diagnostic markers.

### `Delta` tab — what changed?

**Purpose:** Compare two scan runs. Stars shows per path what changed
in the audit picture — not just the effective right, but also
composition (NTFS/share), status (e.g. flip to `ReadFailed`), and
diagnostic markers.

**Fields:**

- **Left run** and **right run** selected from the scan history.
- **Compare** — table with `Before → After` per path, including a
  "Changed (...)" column with concrete change reasons (e.g. "NTFS
  mask + share status").

Unchanged paths are hidden so only the relevant entries remain.

### `Info` tab — about Stars

Shows version, platform status (e.g. "verified against Server 2022
and 2025"), license, AI authorship (Co-Author Claude Opus), and
links to the online documentation. No interactive content.

---

## Identity input forms

Stars accepts **five input forms** and routes all of them through the
*same* central pipeline:

| Form | Example | When useful? |
| --- | --- | --- |
| `DOMAIN\user` | `CORP\alice` | Domain explicit, unambiguous, also in multi-domain. |
| UPN | `alice@corp.local` | Standard for modern AD environments. |
| `sAMAccountName` | `alice` | Quick; errors on ambiguity (two `alice` in different domains). |
| SID | `S-1-5-21-…-1001` | Direct path, works offline too. |
| Display name (GUI only) | "Alice Beispiel" | The GUI identity picker suggests; Stars resolves to the SID. |

**Whitespace is auto-trimmed** (since v1.5.2 for all input paths).

**Ambiguous `sAMAccountName` input** returns a clear error — Stars
asks you to use `DOMAIN\user` or UPN instead of silently picking the
first match.

**UPN outside the configured LDAP base** returns a clear error
pointing at the Global Catalog binding workaround (port 3268) or
`DOMAIN\user`.

### GUI identity picker — what the suggestion list contains, what it does not

When you type into the GUI "User / Group" field, a suggestion list
appears. **This list contains local identities only** (the `[L]` tag
on the left stands for *Local*):

- local users (`Administrator`, `Guest`, …) and local groups
  (`BUILTIN\Administrators`, `BUILTIN\Users`, `BUILTIN\Remote Desktop
  Users`, …)
- well-knowns from the local LSA

**Domain accounts and domain groups are intentionally not looked up live
from LDAP** while you type. For example, typing `m` for
`max.mustermann001` will not surface any AD suggestions — this is **not
a bug**, it is by design (rationale below and in the technical
documentation).

**How to enter a domain user that does not appear in the suggestion
list:**

| Action | Example |
|---|---|
| Type the full `DOMAIN\user` directly | `CORP\mustermann001` |
| Or the UPN | `mustermann001@corp.local` |
| Or the raw SID if known | `S-1-5-21-…-1128` |
| Then click **"Resolve SID"** | Stars performs a one-shot LDAP lookup and fills the SID field |

**Why no live lookup on every keystroke?** Issuing an LDAP search to the
DC for every typed character would turn each keystroke delay into a
perceptible wait in directories with thousands of accounts (e. g.
10 000 users), and would flood the DC with throwaway queries. The
deliberate split — suggestion list local only, LDAP lookup on click —
keeps the GUI responsive even in forests with hundreds of thousands of
identities.

---

## Active Directory binding (optional)

**When do you need it?**

- You want **recursive group resolution** via
  `LDAP_MATCHING_RULE_IN_CHAIN` — the only correct way for nested
  AD groups.
- You want the GUI **identity search** by display name.
- You want to see the `userAccountControl` status (account disabled).

**When not?**

- Quick smoke test on a domain controller — the local SAM/LSA
  fallback there yields the direct domain groups plus local group
  chains. **Caveat:** nested domain groups are missing then; Stars
  flags those findings with `DomainGroupRecursionIncomplete`.

### LDAP configuration

In the **"Identity resolution"** section (inside the `Analyze` and
`Scan Tree` tabs) under **"LDAP mode"**:

- **0 — Off (SAM/LSA)**: no LDAP, only local APIs.
- **1 — LDAPS (encrypted, port 636)** — standard for production
  environments.
- **2 — Plain LDAP (port 389)** — **test only**. Password flows in
  plain text.
- **3 — Global Catalog (LDAPS, port 3269)** — forest-wide identity and
  group lookups; the base DN may be left empty. Same certificate
  requirements as LDAPS (see below). Memberships are flagged potentially
  incomplete because only universal groups replicate fully to the GC.
- **4 — Signed LDAP (Kerberos sign & seal, port 389)** — the **cert-free**
  way to query a hardened DC that enforces LDAP signing. The bind is
  encrypted and integrity-protected by Kerberos, so **no LDAPS certificate
  is needed**. It uses the **current Windows logon** (single sign-on): no
  bind DN or password. **Server** must be the DC's FQDN, and the process
  needs a real Kerberos ticket — run Stars from an interactive or service
  (scheduled-task) logon as the domain account whose context you want; a
  bare remote-shell session without delegation will not have a ticket.

Fields (all auto-trimmed before use):

- **Server** — DC hostname (e.g. `dc01.corp.local`).
- **Base DN** — domain root DN (e.g. `DC=corp,DC=local`).
- **Bind DN** — account for the LDAP bind
  (`CN=stars-svc,CN=Users,DC=corp,DC=local`).
- **Password** — bind password. **Never stored**, only valid for the
  current session.

### LDAPS certificate requirements (read this before using LDAPS)

LDAPS mode (port 636) only connects if the domain controller presents a
certificate that the **machine running Stars actually trusts**. This trips
up many first-time setups, so concretely:

- **The certificate must be issued by a trusted CA** — it must chain to a
  Certification Authority in the Stars host's trust store, in practice a
  certificate auto-enrolled from your **AD Certificate Services (AD CS)**
  enterprise CA. A **self-signed certificate is rejected**: Stars validates
  the full chain and has **no "ignore/skip certificate" option**. "Some
  certificate" is not enough — it has to be a real, trusted one.
- **Connect by FQDN, not by IP.** Put the DC's fully-qualified name
  (`dc01.corp.local`) in the **Server** field, not its IP address — the
  name you connect to must match the certificate's host name, or validation
  fails.
- **Cross-domain / cross-forest:** when you bind to a DC in another domain,
  the Stars host must also trust *that* domain's CA.

If LDAPS is not available (no certificate on the DC) the TLS handshake
fails. Falling back to **Plain LDAP** (Mode 2 / CLI `--insecure-ldap`) does
not help against a hardened DC: **Windows Server 2022 and 2025 enforce LDAP
signing by default** and refuse the unencrypted bind with
`strongerAuthRequired`. In both cases the bind **fails with a clear error
and the analysis aborts** — Stars does *not* hand back a result that looks
complete.

**No certificate? Use Signed LDAP (Mode 4 / CLI `--ldap-signing`).** It
binds on port 389 with Kerberos sign & seal — encrypted and accepted by a
hardened DC, **without any certificate**. It uses your current Windows
logon (no password), so run Stars as a domain account from an interactive
or service logon (a bare remote shell without a Kerberos ticket will not
work). This is the recommended way to get full LDAP group resolution
against a stock-hardened DC.

If you cannot use LDAP at all, leave **LDAP mode Off** and rely on
the SAM/LSA fallback; nested domain groups are then flagged
`DomainGroupRecursionIncomplete` (see
[Reading findings — diagnostic markers](#reading-findings--diagnostic-markers)).

### Multi-domain / trust relationships

When the configured `base_dn` only indexes **a single domain**
(standard in multi-domain forests), Stars detects cross-domain
identities via LSA and flags them as
`IdentityNotInConfiguredLdapBase`.

For **full** forest coverage:

- Run a second Stars analysis with the partner domain's `base_dn`, or
- Bind against the **Global Catalog** — in the **GUI** select LDAP mode
  *"Global Catalog — forest-wide, port 3269"*, or in the **CLI** pass
  `--global-catalog`. Stars then binds the GC (LDAPS port 3269; the CLI
  also offers plain 3268 with `--insecure-ldap`), identity lookups become
  forest-wide, and the base DN may be left empty. GC-resolved memberships
  are flagged potentially incomplete, because only **universal** groups
  replicate fully to the Global Catalog. The same LDAPS certificate-trust
  rules as above apply (port 3269 is TLS).

### Large or deeply nested domains — `--ldap-timeout`

Stars caps each LDAP operation at **10 seconds** by default. In large
forests with deep or densely cross-linked group nesting, the transitive
membership query (`LDAP_MATCHING_RULE_IN_CHAIN`) can take longer; Stars
then aborts that step and **marks the result incomplete** rather than
hanging or silently under-reporting. Raise the cap with the CLI flag
`--ldap-timeout <SECONDS>` (range 1–600 seconds; it only takes effect
together with `--server`):

```powershell
adpa analyze --path "C:\data" --user "CORP\alice" `
    --server "dc01.corp.local" --base-dn "DC=corp,DC=local" `
    --bind-dn "CN=stars-svc,CN=Users,DC=corp,DC=local" `
    --ldap-timeout 60
```

---

## Local paths vs. SMB shares

**Local paths** (`C:\data\…`, also long-path form `\\?\C:\data\…`):

- **Only** the NTFS DACL is evaluated.
- Local server groups are read from the *local* system.

**UNC paths** (`\\server\share\…`, also long-path form
`\\?\UNC\server\share\…`):

- Stars auto-detects server and share from the path.
- **Share DACL ∩ NTFS DACL** is evaluated — the effective SMB right
  is the *more restrictive* of the two.
- Local server groups are read from the share's server.

**Manual SMB context** (CLI flags `--smb-server` / `--share-name` or
GUI "SMB context" checkbox):

These fields are only valid **as a pair**. Setting only one returns
a clear error — otherwise it would silently affect token SID
resolution.

---

## Rights labels — what F, RX, RW mean

Stars shows every effective right as a **long form plus a short label**,
for example `Read & Execute (RX)` or `Full Control (F)`. The short labels
are **identical to the Windows `icacls` notation**, so they read exactly
the same as in the tools you already use on the file server.

| Short | Long form | Meaning |
| --- | --- | --- |
| `F` | Full Control | Everything, **including** changing the ACL itself (`WRITE_DAC`) and taking ownership (`WRITE_OWNER`). The most powerful — and most audit-relevant — right. |
| `M` | Modify | Read + write + delete the object, but **not** ACL or owner changes. |
| `RX` | Read & Execute | Read and list contents, and run executables. |
| `RW` | Read & Write | Read + write, but **without** the execute right. |
| `R` | Read | Read only. |
| `W` | Write | Write only. |
| `(special)` | Special | A partial or custom access mask that matches none of the levels above. Inspect the raw mask (`0x…`) shown next to the label for the exact bits. |

Two things to keep in mind when reading these:

- **Highest level wins.** Stars reports the highest matching level with
  the precedence `F > M > RX > RW > R > W > (special)`. A higher level
  implies the lower ones: Full Control implies Modify, which implies
  Read & Execute, which implies Read. So a row showing `Modify (M)` also
  has read and write — it just is not Full Control.
- **Nothing is lost.** The label is a readable summary; the exact
  per-bit access mask is always preserved in the raw hex value
  (`0x001F01FF` etc.) next to it and in the CSV/JSON export, so special
  permissions stay visible.

This mapping comes from a single place in the engine
(`NormalizedRights` in `crates/permission_engine/src/mask.rs`) and is the
same across the GUI, the CLI, and every export format.

---

## Reading findings — diagnostic markers

Every `EffectivePermission` entry in CLI, HTML, or JSON carries a
`diagnostics` list. A marker means Stars **warned** you that
something about the computation is uncertain.

| Marker | Severity | Risk `incomplete`? | What it tells you |
| --- | --- | --- | --- |
| `NonCanonicalDaclOrder` | medium | no | DACL is not in Windows canonical order. AccessCheck still walks in stored order — result may differ from a canonicalized expectation. |
| `UnsupportedShareAces` | medium | **yes** | Share DACL contained ACE types the parser could not interpret (object / callback / conditional / vendor-specific). Share mask is potentially incomplete. |
| `DomainGroupRecursionIncomplete` | medium | **yes** | Group resolution ran through SAM/LSA instead of LDAP. `NetUserGetGroups` returns only direct global groups — nested domain groups are not recursively resolved. |
| `IdentityDisabled` | info | no | Account is flagged disabled in AD via `userAccountControl/UF_ACCOUNTDISABLE`. ACL-theoretical rights are correct, but the account normally cannot authenticate. |
| `IdentityNotInConfiguredLdapBase` | medium | **yes** | LSA resolved the SID, but the configured LDAP `base_dn` does not index it. Typical in multi-domain forests / trusts — cross-domain memberships may be missing. |
| `IdentityDisabledStatusUnknown` | info | no | The `disabled` flag could not be determined (e.g. SAM path without `NetUserGetInfo`, or LDAP did not return the user object). |
| `IdentityLookupFailed { reason }` | high | **yes** | LDAP identity lookup failed with a technical error (bind, timeout, DC unreachable). The analysis ran with a placeholder identity and an empty token — ACEs targeting domain groups may be missing. `reason` carries the underlying error. |
| `GroupResolutionFailed { reason }` | high | **yes** | Recursive group resolution failed or was skipped (e.g. cross-domain path with no GC crawl). ACEs on domain groups may be missing. `reason` carries the underlying error. |

**Risk `incomplete = true`** means: the risk finding is structurally
incomplete — the auditor should additionally inspect manually.

**Golden rule:** finding + marker = honest finding. Finding without a
marker = Stars trusts its computation.

---

## Exporting — CSV, JSON, HTML

Via the **Export** menu (or `--output` flag in the CLI):

- **CSV** — flat path-per-row view for Excel/pivot. Diagnostic
  markers as a comma-separated variant list.
- **JSON** — variant-tagged diagnostic markers (`{ "kind":
  "IdentityNotInConfiguredLdapBase" }`), including `reason` texts for
  the Failed markers. Suitable for scripts and SIEM ingest.
- **HTML** — fully formatted audit report with:
  - risk findings sorted by severity,
  - trustee table per path (NTFS + share separated),
  - diagnostic markers as colored badges,
  - scan errors in their own section.

Existing export files are **not overwritten** without `--force` (CLI)
or explicit confirmation (GUI).

### Two audit questions, two report blocks

Stars answers two distinct audit questions per path, and the export
carries both answers:

| Question | Report field | Block |
|---|---|---|
| "What effective rights does **this specific user** have on the path?" | `permissions` with `EffectivePermission` and a full explanation path | identity-bound block |
| "Who is **on the NTFS/Share DACL at all** for this path?" | `path_trustees` with `PathTrustee` entries, split into NTFS and share | path-centric block |

Since v1.5.14 **both blocks are also populated in CLI exports**.
Before that only the GUI produced the path-centric trustee list; the
CLI export had the field defined but passed it empty. JSON consumers
find the field under the `path_trustees` key (**schema version 3**
since v1.5.14); HTML auto-renders the "Trustees per path" table
whenever the list is not empty.

#### JSON schema v3 — tagged trustee entries

Each item in `path_trustees[].trustees[]` carries a discriminator
`entry_kind` and one of two shapes:

```json
{ "entry_kind": "ace",
  "sid": "S-1-5-32-544",
  "display_name": "BUILTIN\\Administrators",
  "kind": "Allow",
  "mask": 2032127,
  "inherited": false,
  "inheritance_flags": 0,
  "propagation_flags": 0,
  "category": "Ntfs" }

{ "entry_kind": "diagnostic",
  "category": "Share",
  "code": "share_read_failed",
  "detail": "Access denied reading share DACL" }
```

`"ace"` is the regular trustee row backed by an ACE. `"diagnostic"`
appears when Stars could not read a layer for a structured reason
(typically a share-DACL read failure) — it replaces what would
otherwise be a missing row that SIEM consumers might misread as
"no permission". The discriminator was introduced with schema v3 in
Round 10; consumers reading schema v2 should be updated to dispatch
on `entry_kind`.

In practice: `adpa analyze --output report.json --path X --user alice`
and `adpa scan --output report.json --path X --user alice` now both
contain the answer for `alice` *and* the full ACE listing for `X`
(and for every sub-path under `X` in the scan case).

---

## The CLI

`adpa.exe` ships alongside `adpa-gui.exe`.

### Analyze a single path

```powershell
adpa analyze --path "C:\data\projects" --user "CORP\alice" `
    --server "dc01.corp.local" --base-dn "DC=corp,DC=local" `
    --bind-dn "CN=stars-svc,CN=Users,DC=corp,DC=local" `
    --output "audit.csv"
```

Set the environment variable `ADPA_BIND_PASSWORD` for the bind
password — that is safer than the `--bind-password` option, which
remains visible in the process listing.

### Recursive scan

```powershell
adpa scan --path "\\fileserver\projects" --user "CORP\alice" `
    --server "dc01.corp.local" --base-dn "DC=corp,DC=local" `
    --bind-dn "CN=stars-svc,CN=Users,DC=corp,DC=local" `
    --max-depth 8 --db "C:\audit\stars.db" --output "audit.json"
```

`Ctrl-C` triggers a cooperative shutdown — the current path is
finished, then Stars terminates cleanly.

### More options

`adpa --help` lists everything.

---

## Where is data stored?

| Data | Path | Notes |
| --- | --- | --- |
| Scan history (SQLite) | `%APPDATA%\Stars\stars_data.db` | Local file, only you have access. |
| Configuration | (none — Stars does not persist LDAP credentials) | The bind password is session-only. |
| Logs | `%APPDATA%\Stars\logs\` | Application logs only, not target-system logs. |
| Exports | wherever you save them | Stars only writes where you tell it to. |

**Sensitive data:** Stars logs **no** passwords, tokens, or bind
credentials. Paths and identities can be confidential — treat the
scan history and exports as sensitive material.

---

## Updates

Stars carries an **update manager skeleton** that signature-checks
update packages (see ADR 0028 / 0030). Currently update installation
happens manually:

1. Download the new installer from the release page.
2. Install (overwrites the previous version).
3. On larger version bumps Stars checks at startup whether the SQLite
   scan history needs migration — and performs it transactionally.

An automatic update function is planned for a later version
(signature-verified updates from a configured source).

---

## FAQ

### "Stars says `Orphaned` but the user exists!"

Up to v1.4.1 trust users could appear as `Orphaned` depending on the
input form. Since v1.5.0 the pipeline is uniform across input forms;
a trust user is now flagged `OutsideConfiguredLdapBase`.

If you still see `Orphaned`, check:

- Is the SID typed correctly? Whitespace is trimmed since v1.5.2, but
  a typo remains a typo.
- Does the account actually exist on this system? `whoami /user` or
  `Get-ADUser -Identity ...` for cross-check.
- If the account lives in a trust domain: does your configured LDAP
  bind index the trust domain at all? (see
  `IdentityNotInConfiguredLdapBase`).

### "Why do CLI and GUI show different rights?"

That **must not happen** — both use the same Principal pipeline and
the same engine since v1.5.0. If you observe differences, one of
these is almost always the cause:

- Different SMB context (UNC vs. local, or differently set
  `--smb-server` / `--share-name`).
- Different LDAP configuration.
- Whitespace in the identity field (no longer relevant — fixed in
  v1.5.2).

If reproducible, please file a
[GitHub issue](https://github.com/Birgerson/stars-ad-permission-analyzer/issues)
with both findings side by side.

### "Stars takes forever — what can I do?"

Common causes:

- **Very deep directory trees**: set `--max-depth`.
- **Slow DC**: the LDAP timeout kicks in; on each hanging call Stars
  yields a `LookupFailed` marker instead of blocking.
- **Huge DACLs**: identical security descriptors are deduplicated by
  hash, but very wide trees with many unique ACLs take time.

Stars has **no** background scans, **no** auto-refresh, **no**
writes — when it takes long, it really is reading.

### "A file is named `passwords.txt` — what does Stars do?"

Stars **does not open the file**. It is only flagged "potentially
sensitive" by `SensitivePathRule` so the auditor handles it
deliberately. Stars never reads contents.

### "Stars shows a gap, I need the full picture — what now?"

When a marker shows `incomplete = true`:

1. **Read the `reason` text.** For `IdentityLookupFailed { reason }`
   or `GroupResolutionFailed { reason }` the underlying error is
   right there.
2. **Check configuration.** Is the LDAP server reachable? Is the
   bind account still valid? Does the `base_dn` actually cover the
   user?
3. **If multi-domain is involved:** run a second Stars analysis with
   the partner domain's `base_dn`, or apply the
   [known-limitations.md L2](known-limitations.md) workaround
   (Global Catalog) manually.

Stars tells you honestly *what* is missing — but **it does not fix
the configuration for you**. That's your call.

---

## Further reading

- **[features-and-limitations.md](features-and-limitations.md)** —
  Full list of what Stars reliably handles and what is out
  of scope by design.
- **[known-limitations.md](known-limitations.md)** — Known
  structural gaps (FSP, GC bind, SID history, cross-forest) with
  roadmap tracking.
- **[audit-criteria.md](audit-criteria.md)** — Domain evaluation
  rules and severity per risk rule.
- **[adr/](adr/)** — Architecture Decision Records — historical
  justifications for individual model, pipeline, and API decisions.
- **[../README.md](../README.md)** — Project overview, build
  instructions, license.
- **[../SECURITY.md](../SECURITY.md)** — Reporting security
  vulnerabilities.
