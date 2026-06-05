# Stars — User Guide

**Version:** v1.5.7 (2026-06-05)
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
4. [The five GUI tabs](#the-five-gui-tabs)
5. [Identity input forms](#identity-input-forms)
6. [Active Directory binding (optional)](#active-directory-binding-optional)
7. [Local paths vs. SMB shares](#local-paths-vs-smb-shares)
8. [Reading findings — diagnostic markers](#reading-findings--diagnostic-markers)
9. [Exporting — CSV, JSON, HTML](#exporting--csv-json-html)
10. [The CLI](#the-cli)
11. [Where is data stored?](#where-is-data-stored)
12. [Updates](#updates)
13. [FAQ](#faq)
14. [Further reading](#further-reading)

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
[features-and-limitations.md](features-and-limitations.md) (German
only — content overlaps with this English guide).

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
Currently recommended: `Stars-v1.5.7-Setup.exe`.

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

After starting Stars the main window shows five tabs. **Recommended
first workflow:**

1. **Identity tab** — pick or type *who* should be analyzed.
2. **Analyze tab** — type a single path, hit "Analyze".
3. Read the result: effective right, explanation, diagnostic markers.

If you only want to see what Stars can do at all, start with any local
folder and your own user SID — that works without LDAP configuration
and shows the engine in action.

---

## The five GUI tabs

### Analyze — single-path analysis

**Purpose:** You have a specific path and want to know what a given
user can effectively do there.

**Fields:**

- **Path** — local (`C:\data\…`) or UNC (`\\server\share\…`).
- **User** — see [Identity input forms](#identity-input-forms).
- **SMB server** and **share name** (optional) — auto-detected for
  UNC paths. Set manually on local paths if you also want the share
  mask evaluated.
- **Analyze** — runs the evaluation.

**Result:** one report per path with:

- effective right (Read / Write / Modify / Full Control),
- NTFS and share rights separately,
- explainable permission path
  (`User → Group → … → ACE → normalized right`),
- all diagnostic markers.

### Scan — recursive directory scan

**Purpose:** Audit a whole directory tree — typical for the periodic
"how does Q3 look right now?" question.

**Fields:**

- **Root path**, **User**, **SMB server** / **share name** as in
  Analyze.
- **Maximum scan depth** — protects against runaway walks; empty =
  unbounded.
- **Start scan** — cancellable any time via the cancel button; the
  GUI stays responsive during the scan.

**Result:** a table of all paths, their effective rights, and a
per-path trustee list. The result is automatically persisted into the
SQLite scan history.

### Trustees — who-has-access view

**Purpose:** Unlike Analyze (which shows one user per path), Trustees
lists **all** trustees of a path with their ACEs — NTFS and Share
separated through the `TrusteeCategory::Ntfs` / `Share` column.

**For SMB paths:** Stars reads the share DACL once and shows it on
top of the NTFS entries. Read errors appear as a visible pseudo-row
— never silently dropped.

### Delta — what changed?

**Purpose:** Compare two scan runs. Stars shows per path what changed
about the effective right.

**Fields:**

- **Left run** and **right run** selected from the scan history.
- **Compare** — table with `Before → After` per path.

Unchanged paths are hidden so only the relevant entries remain.

### Risk — risk rules and findings

**Purpose:** Stars applies six built-in risk rules to every finding:

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

In the identity tab under **"LDAP mode"**:

- **0 — Off (SAM/LSA)**: no LDAP, only local APIs.
- **1 — LDAPS (encrypted, port 636)** — standard for production
  environments.
- **2 — Plain LDAP (port 389)** — **test only**. Password flows in
  plain text.

Fields (all auto-trimmed before use):

- **Server** — DC hostname (e.g. `dc01.corp.local`).
- **Base DN** — domain root DN (e.g. `DC=corp,DC=local`).
- **Bind DN** — account for the LDAP bind
  (`CN=stars-svc,CN=Users,DC=corp,DC=local`).
- **Password** — bind password. **Never stored**, only valid for the
  current session.

### Multi-domain / trust relationships

When the configured `base_dn` only indexes **a single domain**
(standard in multi-domain forests), Stars detects cross-domain
identities via LSA and flags them as
`IdentityNotInConfiguredLdapBase`.

For **full** forest coverage:

- Run a second Stars analysis with the partner domain's `base_dn`,
  or
- Bind against the **Global Catalog** (`gc://dc.corp.local:3268`) —
  **not yet implemented in Stars**, see
  [known-limitations.md L2](known-limitations.md).

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
  Full list (German) of what Stars reliably handles and what is out
  of scope by design.
- **[known-limitations.md](known-limitations.md)** — Known
  structural gaps (FSP, GC bind, SID history, cross-forest) with
  roadmap tracking.
- **[audit-kriterien.md](audit-kriterien.md)** — Domain evaluation
  rules and severity per risk rule (German).
- **[adr/](adr/)** — Architecture Decision Records — historical
  justifications for individual model, pipeline, and API decisions.
- **[../README.md](../README.md)** — Project overview, build
  instructions, license.
- **[../SECURITY.md](../SECURITY.md)** — Reporting security
  vulnerabilities.

---

## Deutsche Version

Eine deutsche Fassung dieses Handbuchs liegt unter
**[anwender-handbuch.md](anwender-handbuch.md)**.
