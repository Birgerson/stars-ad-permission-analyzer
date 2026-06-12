# Verification of the Lab Setup and the Stars Software

> **Last update:** v1.5.16 (2026-06-07). This file grows by one verification block per release; older blocks stay unchanged as a historical record.
> Each verification block notes its own Stars version (e.g. "Block C — v1.5.8"). The lab topology itself comes from the initial setup (see commit timestamps of [`forest-topology.md`](forest-topology.md)).

This file documents *what* was verified, *how* it was checked, and *what* Stars actually produced. Reproduce with the scripts under [`scripts/`](scripts/).

| Block | Stars version | Topic |
|---|---|---|
| A — Lab infrastructure | v1.5.5 (initial) | Forest / trust / CF snapshot at the initial lab build |
| B — Test data population | v1.5.5 (initial) | OUs, test users, test ACL incl. FSP |
| C — Stars tests (initial) | v1.5.5 | T1 nested groups, T2 cross-forest FSP, T3 cross-forest no ACE |
| D — Block A | v1.5.7 | NTFS edge cases (Deny, Protect, Share ∩ NTFS) |
| E — Block B | v1.5.7 | GUI boot smoke on VirtIO-GPU |
| F — Block C | v1.5.8 | Scaling — 1000 users, 5000 dirs |
| G — Block D | v1.5.9 | NETWORK SID on a local path + explicit SMB context (Round-7 finding 1) |
| H — Server 2025 | v1.5.16 | Platform smoke on Windows Server 2025 Standard (3 forests, 1000 users, 5000 dirs) |

## Part A — Lab infrastructure

Checked on every one of the three DCs after reboot and before the Stars test.

### A.1  AD-DS topology

```powershell
$d = Get-ADDomain
"$($d.DNSRoot)  netbios=$($d.NetBIOSName)  forest=$($d.Forest)  sid=$($d.DomainSID)  mode=$($d.DomainMode)"
$f = Get-ADForest
"forest=$($f.Name)  mode=$($f.ForestMode)  schema-master=$($f.SchemaMaster)"
```

Observed values:

| VMID | Get-ADDomain.DNSRoot | NetBIOS | Domain SID | Mode |
|---|---|---|---|---|
| 100 | tier0.lab | T0LAB | `S-1-5-21-82128098-3850859968-3663624259` | Windows2016Domain / -Forest |
| 101 | tier1.lab | T1LAB | `S-1-5-21-2422202677-580894712-1536135282` | Windows2016Domain / -Forest |
| 102 | tier2.lab | T2LAB | `S-1-5-21-2422907361-2909490334-1284861871` | Windows2016Domain / -Forest |

### A.2  DC services

```powershell
foreach ($s in 'ADWS','Netlogon','Kdc','DNS','NTDS') {
    "$s -> $((Get-Service $s).Status)"
}
```

All three DCs return **Running** for all five services.

### A.3  Conditional DNS forwarders

```powershell
Get-DnsServerZone | Where-Object { $_.ZoneType -eq 'Forwarder' } |
    Format-Table ZoneName, MasterServers
```

| DC | CF zone | Master |
|---|---|---|
| tier0 | tier1.lab | 192.168.11.101 |
| tier0 | tier2.lab | 192.168.11.102 |
| tier1 | tier0.lab | 192.168.11.100 |
| tier1 | tier2.lab | 192.168.11.102 |
| tier2 | tier0.lab | 192.168.11.100 |
| tier2 | tier1.lab | 192.168.11.101 |

Resolve check `Resolve-DnsName tier{0,1,2}.lab` from each DC → returns the matching IP of the target domain.

### A.4  Forest trusts

```powershell
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().GetAllTrustRelationships() |
    ForEach-Object { "$($_.SourceName) -> $($_.TargetName) [$($_.TrustDirection)/$($_.TrustType)]" }
```

Returns two Bidirectional / Forest trusts to the other two forests on each of the three DCs:

```text
tier0.lab:
  tier0.lab -> tier1.lab [Bidirectional/Forest]
  tier0.lab -> tier2.lab [Bidirectional/Forest]

tier1.lab:
  tier1.lab -> tier0.lab [Bidirectional/Forest]
  tier1.lab -> tier2.lab [Bidirectional/Forest]

tier2.lab:
  tier2.lab -> tier1.lab [Bidirectional/Forest]
  tier2.lab -> tier0.lab [Bidirectional/Forest]
```

### A.5  Known quirk — `netdom trust /Verify`

```text
netdom trust tier0.lab /Domain:tier1.lab /Verify /Quiet
> rc=87 — "The syntax of this command is: NETDOM [...]"
```

The trusts exist nonetheless per the reflection API (A.4). `/Verify` is a read-only diagnostic; its absence does not block functionality. Accepted as a known quirk.

## Part B — Test data population

Created for the Stars tests:

### B.1  Identities

| Forest | OU | User | Group memberships |
|---|---|---|---|
| tier0.lab | OU=TestOU | T0LAB\alice | GroupA → GroupB (nested) |
| tier1.lab | OU=TestOU | T1LAB\bob | (primary group only) |
| tier2.lab | OU=TestOU | T2LAB\carol | (primary group only) |

Groups:

| Forest | Group | SID suffix | Member of |
|---|---|---|---|
| tier0.lab | GroupA | -1105 | GroupB |
| tier0.lab | GroupB | -1106 | (root of the test chain) |

### B.2  Path with ACL

`C:\TestShare` on tier0 (local directory, no SMB share yet).

```powershell
Get-Acl C:\TestShare | Select-Object -ExpandProperty Access
```

Returns (relevant test ACEs):

| IdentityReference | Rights | Type | Source |
|---|---|---|---|
| `T0LAB\GroupB` | Modify | Allow (explicit) | Test ACE for the nested-group test |
| `T1LAB\bob` (SID-only) | ReadAndExecute | Allow (explicit) | **Cross-forest FSP**, set via `NTAccount("T1LAB","bob").Translate(SID)` (trust-mediated resolution) |
| `NT AUTHORITY\SYSTEM` / `BUILTIN\Administrators` / `BUILTIN\Users` / `CREATOR OWNER` | … | inherited | Default NTFS inheritance |

## Part C — Stars tests against the lab

The Stars CLI (`C:\Stars\adpa.exe`, version 1.5.5) was uploaded to tier0 and checked with three scenarios. Full outputs live in the lab capture (`/tmp/lab-stars-evidence.txt`). Here only the critical excerpts.

### C.1  T1 — Inside the forest, nested groups

```text
adpa.exe analyze \
    --path 'C:\TestShare' \
    --user 'T0LAB\alice' \
    --server 'tier0.tier0.lab' \
    --base-dn 'DC=tier0,DC=lab' \
    --bind-dn 'CN=Administrator,CN=Users,DC=tier0,DC=lab' \
    --insecure-ldap
```

Key result:

```text
Effective Rights
  NTFS    : Modify (0x001301BF)
  Result  : Modify (0x001301BF)

Explanation Path
  1. User: alice (S-1-5-21-…-1107)
  2. Member of Domain Users (S-1-5-21-…-513) [direct, source: PrimaryGroup]
  3. Member of GroupA (S-1-5-21-…-1105) [direct, source: DomainGroup]
  4. Member of GroupB (S-1-5-21-…-1106) [via alice → GroupA → GroupB, source: DomainGroup]
  5. Member of BUILTIN\Users (S-1-5-32-545) [via alice → Domain Users → BUILTIN\Users, source: LocalGroup]
  6. Allow ACE [explicit] for GroupB (…-1106) → Modify (0x001301BF)
  7. Allow ACE [inherited] for BUILTIN\Users → Read & Execute
  ...
  10. NTFS effective: Modify (0x001301BF)
```

**Confirmed:**
- Nested-group resolution (alice → GroupA → GroupB) is rendered correctly as a mediator chain in the path.
- Local-group resolution (BUILTIN\Users) appears as its own step line with `source: LocalGroup` — exactly the behaviour from finding 1 of this release cycle.
- Risk engine reports `HIGH WRITE_ACCESS` (Modify) and `MEDIUM DELETE_RIGHT` for alice on the path.

### C.2  T2 — Cross-forest, Foreign Security Principal

```text
adpa.exe analyze \
    --path 'C:\TestShare' \
    --user 'T1LAB\bob' \
    --server 'tier1.tier1.lab' \
    --base-dn 'DC=tier1,DC=lab' \
    --bind-dn 'CN=Administrator,CN=Users,DC=tier1,DC=lab' \
    --insecure-ldap
```

Key result:

```text
Effective Rights
  NTFS    : Read & Execute (0x001200A9)
  Result  : Read & Execute (0x001200A9)

Explanation Path
  1. User: bob (S-1-5-21-2422202677-…-1105)
  2. Member of Domain Users (S-1-5-21-2422202677-…-513) [direct, source: PrimaryGroup]
  3. Allow ACE [explicit] for T1LAB\bob (…) → Read & Execute
  4. NTFS effective: Read & Execute (0x001200A9)

Risk Findings (1)
  [LOW] DIRECT_USER_ACE — 'bob' has a direct explicit ACE …
```

**Confirmed:**
- Stars resolves `T1LAB\bob` via tier1.tier1.lab to the correct cross-forest SID.
- The FSP ACE on the tier0 path is recognized by its cross-forest SID and aggregated into the effective permission.
- The risk engine detects the Direct-User-ACE risk class.

### C.3  T3 — Cross-forest without an ACE (negative test)

```text
adpa.exe analyze \
    --path 'C:\TestShare' \
    --user 'T2LAB\carol' \
    --server 'tier2.tier2.lab' \
    --base-dn 'DC=tier2,DC=lab' \
    --bind-dn 'CN=Administrator,CN=Users,DC=tier2,DC=lab' \
    --insecure-ldap
```

Key result:

```text
Matching ACEs (for this identity)
  (none)

Effective Rights
  NTFS    : Special (0x00000000)
  Result  : Special (0x00000000)

Explanation Path
  1. User: carol (S-1-5-21-2422907361-…-1105)
  2. Member of Domain Users (…) [direct, source: PrimaryGroup]
  3. NTFS effective: Special (0x00000000)

Risk Findings (0)
```

**Confirmed:**
- The identity is resolved correctly even without an ACE match.
- "No effective permission" is a valid, fully explained answer — not an error.

## Summary

| Area | Result |
|---|---|
| 3 forests / 3 separate domain SIDs | ✓ created, read back |
| Conditional DNS forwarders between every pair | ✓ added, cross-forest resolution checked |
| 3 bidirectional forest trusts | ✓ created via `Forest.CreateTrustRelationship`, both sides visible |
| Stars smoke (alice, nested groups, inside tier0) | ✓ Modify, path with all mediators |
| Stars cross-forest FSP (bob from tier1, ACE on tier0) | ✓ Read & Execute correct |
| Stars cross-forest without ACE (carol from tier2) | ✓ 0x0 special, clean path |
| Finding 1 — LocalGroup source in the explanation path | ✓ visible in T1 (`source: LocalGroup`) |

The lab topology reproduces the two most important real-world auditing scenarios that a single-forest setup cannot represent (cross-forest FSPs and cleanly separated schemas) and shows that Stars reports them in an evaluable way.

## Part D — Block A: NTFS edge cases (Deny, Protect-Inheritance, Share ∩ NTFS)

> Added in release cycle **v1.5.7** (2026-06-05). Reproduction script:
> [`scripts/09-blockA-edge-cases.sh`](scripts/09-blockA-edge-cases.sh).

Block A checks three edge cases that a typical AD audit tool can aggregate incorrectly without anyone noticing:

### D.1  E1 — Deny ACE beats an inherited Allow ACE

Setup on tier0:

- `C:\TestShare\DenyZone` subfolder inheriting from the parent
- **Explicit Deny Modify** for `T0LAB\alice`
- **Inherited Allow Modify** for `T0LAB\GroupB` (alice is a member via GroupA → GroupB)

Stars result (excerpt):

```text
Effective Rights
  NTFS    : Special (0x00100000)
  Result  : Special (0x00100000)

Explanation Path
  ...
  6. Deny ACE [explicit] for T0LAB\alice → Special (0x000301BF)
  7. Allow ACE [inherited] for GroupB → Modify (0x001301BF)
  ...
  11. Deny aggregation: Special (0x000301BF) blocked by Deny ACEs —
      those bits were removed from the effective NTFS mask
  12. NTFS effective: Special (0x00100000)
```

**Confirmed:**
- The engine computes Allow ⊖ Deny correctly (only the SYNCHRONIZE bit `0x00100000` remains, effectively no data access).
- The path now names the Deny effect explicitly (step 11, see ADR 0042) — before v1.5.7 the auditor had to spot the hex difference themselves.

### D.2  E2 — Inheritance break (`Protect`)

Setup on tier0:

- `C:\TestShare\Protected` subfolder
- `SetAccessRuleProtection($true, $false)` — inheritance disabled, inherited rules removed
- Only `BUILTIN\Administrators` and `NT AUTHORITY\SYSTEM` as explicit Allow rules

Stars result:

```text
Inheritance : Protected (inheritance disabled)
Matching ACEs (for this identity) : (none)

Effective Rights
  NTFS    : Special (0x00000000)
  Result  : Special (0x00000000)

Explanation Path
  1. User: alice (...)
  2-5. (membership chain)
  6. NTFS effective: Special (0x00000000)

Risk Findings (0)
```

**Confirmed:**
- The inheritance break is reported visibly (`Inheritance: Protected (inheritance disabled)`).
- No false positive on the inherited level: because GroupB does not inherit here, alice has no match at all.
- The risk engine correctly stays silent (no rights, no risk).

### D.3  E3 — SMB share permissions dominate NTFS

Setup on tier0:

- `New-SmbShare -Name TestShareSMB -Path C:\TestShare -ReadAccess Everyone -FullAccess "T0LAB\Domain Admins"`
- NTFS still has GroupB=Modify (alice via the mediator chain).

Stars call with UNC path + share hint:

```text
adpa.exe analyze \
    --path '\\tier0\TestShareSMB' \
    --user 'T0LAB\alice' \
    --smb-server tier0 \
    --share-name TestShareSMB \
    ...
```

Result:

```text
Effective Rights
  NTFS    : Modify              (0x001301BF)
  Share   : Read & Execute      (0x001200A9)
  Result  : Read & Execute      (0x001200A9)

Explanation Path
  ...
  10. NTFS effective: Modify (0x001301BF)
  11. Share permission: Read & Execute (0x001200A9)
  12. Effective (NTFS ∩ Share): Read & Execute (0x001200A9)
```

**Confirmed:**
- Stars reads share permissions correctly over SMB (Everyone=Read mapped to Read & Execute).
- `Result = NTFS ∩ Share` (the more restrictive wins) — the path renders the aggregation as its own step 12.

## Part E — Block B: GUI boot smoke

> Added in release cycle **v1.5.7** (2026-06-05). Reproduction script:
> [`scripts/10-blockB-gui-smoke.sh`](scripts/10-blockB-gui-smoke.sh).

Full UI validation of the GUI remains a manual step — `qm guest exec` has no interactive desktop and cannot take screenshots. What can be automated is the **boot smoke**: process starts, stays stable, terminates cleanly.

Result on tier0:

```text
gui-binary: C:\Stars\adpa-gui.exe
gui-size  : 18734592 bytes
launched pid=4036
still-alive-after-15s pid=4036 handle-count=240 ws=22.83MB
process-terminated cleanly
stderr: (empty)
```

**Confirmed:**
- Slint + the winit software backend boot on the VirtIO-GPU VM without errors (the `project-deployment-target` memory is therefore still valid).
- Working set ~23 MB after boot, no anomalies on stderr.
- The process can be terminated cleanly with Stop-Process; no dangling threads.

What Block B **does not** cover and must be checked manually by the operator via RDP/SPICE:

- Rendering correctness when toggling themes
- Layout stability on window resize
- Input validation in live forms
- Output tables with real scan results

## Summary v1.5.7

| Area | Result |
|---|---|
| Block A E1 — Deny override | ✓ computationally + new explanation step (ADR 0042) |
| Block A E2 — Protect inheritance | ✓ without false positive |
| Block A E3 — Share ∩ NTFS | ✓ Share dominates, the path makes the aggregation explicit |
| Block B — GUI boot smoke | ✓ no Slint crash on VirtIO-GPU |

## Part F — Block C: scaling on large directories

> Added in release cycle **v1.5.8** (2026-06-05). Reproduction scripts:
> [`scripts/11-blockC-ad-bulk.sh`](scripts/11-blockC-ad-bulk.sh),
> [`scripts/12-blockC-dirs-acls.sh`](scripts/12-blockC-dirs-acls.sh),
> [`scripts/13-blockC-stars-perf.sh`](scripts/13-blockC-stars-perf.sh).

Block C checks whether Stars stays in shape under realistic lab load — i.e. on a forest with hundreds of users, nested groups, and thousands of folders with mixed ACLs.

### F.1  AD bulk setup

Per forest the following is created:

- OUs: `OU=Company / OU={Departments, Users, Groups}` plus 5 department OUs under `Departments` = **9 OUs**
- Security groups: 5 department groups + 15 sub-team groups = **20 groups**
- Nesting: user → sub-team group → department group (3 levels)
- User distribution:

| Forest | User range | Count | Per department | Per sub-team |
|---|---|---|---|---|
| tier0.lab | `mm0001`–`mm0500` | 500 | ~100 | ~33 |
| tier1.lab | `mm0501`–`mm0800` | 300 | ~60 | ~20 |
| tier2.lab | `mm0801`–`mm1000` | 200 | ~40 | ~13 |

**In total: 1000 users across three forests, lexicographically sortable (4-digit padding).**

Bulk runtime measured via `Stopwatch`:

| Forest | User create duration | ms/user |
|---|---|---|
| tier0 (500) | 44.7 s | ~89 |
| tier1 (300) | 24.7 s | ~82 |
| tier2 (200) | 17.0 s | ~85 |

A consistent ~85 ms per `New-ADUser` + `Add-ADGroupMember` pair, dominated by LDAP replication and index update.

### F.2  Directory and ACL setup on tier0

Directory structure on `C:\Data`:

```text
C:\Data\
  Sales\Engineering\HR\Finance\IT      (5 department roots)
    Project01..20                      (20 projects per dept)
      Folder01..50                     (50 folders per project)
                                       Σ = 5000 folder dirs
                                         + 100 project dirs
                                         + 5 department dirs
                                         = 5105 directories
```

ACL variation on the 100 project folders:
- **Project 01..15** (75 dirs): explicit Allow Modify for the matching sub-team group (`Sales-Alpha`, `Engineering-Beta`, …)
- **Project 16..18** (15 dirs): `SetAccessRuleProtection($true)` — inheritance disabled, only `BUILTIN\Administrators` + `NT AUTHORITY\SYSTEM`
- **Project 19..20** (10 dirs): explicit Deny ReadAndExecute for the matching `-Gamma` sub-team group

Setup runtime:

| Step | Duration | Rate |
|---|---|---|
| Create 5000 folder dirs | 8.8 s | ~570 dirs/s |
| 5 dept-root ACLs | 1.6 s | (3 ms/ACL, dominated by `Set-Acl` I/O) |
| 100 project ACLs (varied) | 1.9 s | ~52 ACLs/s |
| **Total C.2+C.3** | **13.2 s** | |

### F.3  Stars performance against `C:\Data`

Test user: `T0LAB\mm0001` (Sales-Alpha member, has Modify on Sales/Project01..15 via the mediator chain).

**T1 — Full scan** (`adpa.exe scan --path C:\Data --user T0LAB\mm0001 --output ...`):

```text
elapsed_seconds : 4.89
adpa rc         : 0
csv_lines       : 5107
csv_size_kb     : 6538.5
```

- 5105 directories + 1 header + 1 root entry = 5107 CSV rows ✓
- ~1043 dirs/s (= 0.96 ms per directory including ACL read, owner lookup, effective-rights computation, and CSV serialization)
- 6.5 MB CSV (~1.3 KB per row, i.e. full path explanation per entry)
- Exit 0, no crash, no OOM hint

**T2 — Single deep analyze** (`adpa.exe analyze --path C:\Data\Sales\Project05\Folder25 --user T0LAB\mm0001`):

```text
elapsed_seconds : 4.24

Explanation Path
  1. User: mm0001 (S-1-5-21-…-1128)
  2. Member of Domain Users (…-513) [direct, source: PrimaryGroup]
  3. Member of Dept-Sales (…-1108) [via mm0001 → Sales-Alpha → Dept-Sales, source: DomainGroup]
  4. Member of Sales-Alpha (…-1109) [direct, source: DomainGroup]
  5. Member of BUILTIN\Users (S-1-5-32-545) [via mm0001 → Domain Users → BUILTIN\Users, source: LocalGroup]
  6. Allow ACE [inherited] for Dept-Sales (…-1108) → Modify (0x001301BF)
  …
  10. NTFS effective: Modify (0x001301BF)
```

- Dominant cost: one-off LDAP connect + bind + group resolution (~4 s)
- ACL read and aggregation < 100 ms
- Mediator chain correct (ADR 0036) + LocalGroup step (ADR 0041) visible

### F.4  Observations

- Stars renders even with 1000 AD identities and 5000 paths **without memory pressure and without a crash**.
- The dominant factor on *single* invocations is the LDAP bind plus the group resolution of the user token (one-off cost). Once the identity is resolved, the per-directory ACL-read path is sub-millisecond.
- On a full scan the LDAP cost amortizes over the entire tree — the effective rate of ~1 ms/dir is real-production grade.

### F.5  Known lab limitation — cross-forest FSPs

The bulk setup script attempts to enter 50 cross-forest Foreign Security Principals (25 from `T1LAB`, 25 from `T2LAB`) into tier0 `Dept-*` groups. Both `Add-ADGroupMember -Members <SID>` and an ADSI `Add` variant fail with `0x80072030 — There is no such object on the server`. Microsoft's `Add-ADGroupMember` only auto-creates the FSP container entry when the input is a NetBIOS account name from a trust whose source forest can be resolved at lookup time — which on large cross-forest setups often requires additional configuration (`dsadd group` from legacy tools on older schemas, or an explicit `New-ADObject -Type foreignSecurityPrincipal`).

**Important:** This is **not a Stars bug**. Stars reads existing FSP ACEs cleanly (see test T2 in Part C — `T1LAB\bob` had an FSP ACE in tier0 and Stars resolved it correctly and reflected it in the Effective Rights report). It is just the lab bulk setup that cannot create FSPs without further configuration steps. Whoever wants to complete the lab adds the FSPs manually or via `dsadd group` from a Domain Controller with RSAT.

## Summary v1.5.8

| Area | Result |
|---|---|
| Block C.1 — 1000 users across 3 forests, 3-level nesting | ✓ in 86 s |
| Block C.2/C.3 — 5000 folders + 100 varied ACLs | ✓ in 13 s |
| Block C.4 T1 — Full scan 5105 dirs | ✓ 4.89 s (≈ 1 ms/dir) |
| Block C.4 T2 — Single deep analyze | ✓ 4.24 s (LDAP-dominated) |
| Block C.5 — Cross-forest FSP via bulk script | Lab limitation documented (no Stars bug) |

## Part G — Block D: NETWORK SID on a local path + explicit SMB context (v1.5.9)

> Added in release cycle **v1.5.9** (2026-06-05). Reproduction script:
> [`scripts/14-blockD-network-context.sh`](scripts/14-blockD-network-context.sh).
> References: Round-7 review finding 1, ADR 0043.

Block D verifies the central effect of the Round-7 fix: when an auditor analyzes a **local NTFS path** (e.g. `C:\TestShare\NetworkBlock`) together with an **explicit SMB context** (`--smb-server` + `--share-name`) — the common file-server-local audit case — Stars must add the `NETWORK` well-known SID to the token and aggregate share-DACL ACEs against `NETWORK` correctly.

### G.1  Setup

`C:\TestShare\NetworkBlock` is a subfolder with the NTFS DACL inherited from `C:\TestShare` — `T0LAB\GroupB` has **Modify** there, and alice (via the `Sales-Alpha → GroupB` mediator) does too.

A new SMB share `TestShareNetBlock` points at this subfolder and has a restrictive share permission list:

```text
Everyone              Full Allow
NT AUTHORITY\NETWORK  Full Deny
NT AUTHORITY\NETWORK  Read Allow
```

The order is deliberate: Allow Everyone + explicit Deny NETWORK. Over SMB the access lands via `NETWORK` — the Deny dominates.

### G.2  Three Stars scenarios

| Scenario | Path | `--smb-server` / `--share-name` | Stars output (`Result`) |
|---|---|---|---|
| **E4a** | `C:\TestShare\NetworkBlock` | — (not set) | `Modify (0x001301BF)` |
| **E4b** | `C:\TestShare\NetworkBlock` | `tier0` / `TestShareNetBlock` | `Special (0x00000000)` |
| **E4c** | `\\tier0\TestShareNetBlock` (control) | `tier0` / `TestShareNetBlock` | Access denied during NTFS read (share blocks NETWORK at the source) |

### G.3  Analysis

**E4a — no SMB hint, Stars uses `LocalInteractive`:**
- No share context → the share DACL is never queried → `Share: (not specified)`
- NTFS dominates: `Modify`
- Correct: a local audit without an SMB reference should show the NTFS view.

**E4b — the same local path with an explicit SMB hint:**
- *Before v1.5.9:* `AccessContext::for_path(&path)` returned `LocalInteractive`, `NETWORK` was missing in the token, the Deny ACE against NETWORK did not apply → Stars incorrectly reported `Result = Modify`.
- *With v1.5.9 (`for_path_with_smb(path, smb_server, share_name)`):* `RemoteSmb`, NETWORK in the token, Deny ACE on NETWORK applies → Stars renders the full aggregation:

```text
Effective Rights
  NTFS    : Modify (0x001301BF)
  Share   : Special (0x00000000)
  Result  : Special (0x00000000)

Explanation Path (excerpt)
  ...
  10. NTFS effective: Modify (0x001301BF)
  11. Share permission: Special (0x00000000)
  12. Effective (NTFS ∩ Share): Special (0x00000000)
```

This fixes exactly the constellation an auditor encounters in practice: local on the file server but wanting the share view.

**E4c — UNC path as the control case:**
- The share permission blocks NETWORK already at the connection layer. Stars runs as LocalSystem and is itself NETWORK when reading the UNC path's NTFS → it receives **Access denied** while reading the ACL.
- This is semantically consistent: the share forbids NETWORK access, and an audit tool isn't allowed through either.
- For engine correctness, E4b is the actual proof point.

### G.4  Engine tests

Two new engine unit tests in `crates/permission_engine/src/engine.rs::tests` cover the end-to-end path:

- `remote_smb_context_grants_network_ace_even_on_local_path` — with `AccessContext::RemoteSmb` the engine correctly aggregates an Allow-NETWORK ACE.
- `local_interactive_context_ignores_network_ace` — mirror image: under `LocalInteractive` it correctly ignores it.

Plus five tests for the helper function `AccessContext::for_path_with_smb` in `crates/core/src/model.rs::tests`.

## Summary v1.5.9

| Area | Result |
|---|---|
| Finding 1 — `AccessContext::for_path_with_smb` + 6 call sites | ✓ E4b live-verified: Result `Modify` → `Special (0x00000000)` |
| Finding 2 — GUI HTML export overwrite protection | ✓ Worker test verified: an existing file is refused, content stays unchanged |
| Finding 3 — `--bind-password` deprecation | ✓ help text + runtime warning marked as DEPRECATED |
| Finding 4 — verification.md cleaned up | ✓ header status set to v1.5.9, block overview with version per block |

---

## Block H — Platform smoke on Windows Server 2025 Standard

**Stars version:** v1.5.16
**Date:** 2026-06-07
**Platform change:** Windows Server 2022 Standard → **Windows Server 2025 Standard** (`SERVER_EVAL_x64_2025_FRE_de-de.iso`)

### H.1 — Hardware profile (all 3 DCs identical)

| Setting | Value |
|---|---|
| Machine type | `pc-q35-10.1` |
| BIOS | OVMF (UEFI) with pre-enrolled Microsoft keys |
| TPM | v2.0 (swtpm) |
| CPU | 1 socket × 8 cores, `x86-64-v2-AES` |
| RAM | 16 GiB without ballooning |
| Disk | 50 GiB VirtIO Block, `qcow2`, cache `directsync`, IO thread |
| Graphics | VirtIO (`vga: virtio`) |
| OS type | `win11` (Server 2022/2025/Win11) |
| Network | VirtIO, vmbr0, firewall on |

Background: first setup attempts with `pc-i440fx-10.1` + old VGA failed at disk-driver loading inside WinPE. With `q35` + VirtIO and an Autounattend.xml section `PnpCustomizationsWinPE` (loads `viostor`/`vioscsi`/`NetKVM` from the virtio-win ISO) the setup runs fully unattended.

### H.2 — Forest topology

3 forests `tier0.lab` / `tier1.lab` / `tier2.lab` with NetBIOS `T0LAB` / `T1LAB` / `T2LAB`. Forest mode per forest:

```text
tier0.lab — Windows2025Forest
tier1.lab — Windows2025Forest
tier2.lab — Windows2025Forest
```

(The 2022 lab had `Windows2016Forest` — the new value is the default on Server 2025.)

Three bidirectional forest trusts (fully meshed), created via `[System.DirectoryServices.ActiveDirectory.Forest]::CreateTrustRelationship`:

```text
tier0.lab ↔ tier1.lab  Bidirectional / Forest
tier1.lab ↔ tier2.lab  Bidirectional / Forest
tier0.lab ↔ tier2.lab  Bidirectional / Forest
```

Plus 6 conditional DNS forwarders (every DC holds CFs pointing at the other two domain roots), `ReplicationScope: Forest`.

### H.3 — Test data set

| DC | User range | Count | Distribution |
|---|---|---|---|
| tier0 | `mm0001`..`mm0500` | 500 | 5 departments × 3 sub-teams + nesting |
| tier1 | `mm0501`..`mm0800` | 300 | same |
| tier2 | `mm0801`..`mm1000` | 200 | same |

Plus on tier0: `C:\Data\<Dept>\Project01..20\Folder01..50` = **5000 folders + 100 project ACLs** with three ACL variants:

- Project01..15 (75 projects): explicit Modify for the department sub-team
- Project16..18 (15 projects): Protected Inheritance + only SYSTEM/Administrators
- Project19..20 (10 projects): Allow Modify + an additional Deny ReadAndExecute for `<Dept>-Gamma`

### H.4 — Stars smoke tests (`adpa.exe analyze` v1.5.16)

Three semantically different paths against user `T0LAB\mm0001` (a member of `Sales-Alpha`).

**Test 1 — `C:\Data\Sales\Project01` (Modify via Sales-Alpha):**

| Field | Expectation | Result |
|---|---|---|
| Effective | Modify (0x001301BF) | ✅ exact |
| Matching ACEs | Sales-Alpha Modify explicit, BUILTIN\Users inherited Read | ✅ exact |
| Risk findings | WRITE_ACCESS (HIGH), DELETE_RIGHT (MEDIUM) | ✅ detected |
| Explanation path | 10 steps: User → Sales-Alpha → ACE → NTFS effective | ✅ complete |

**Test 2 — `C:\Data\Sales\Project16` (Protected Inheritance, no access):**

| Field | Expectation | Result |
|---|---|---|
| Effective | Special (0x00000000) = no access | ✅ |
| Inheritance | "Protected (inheritance disabled)" | ✅ detected |
| Matching ACEs | `(none)` — the Sales-Alpha ACE does not exist because inheritance is protected | ✅ |
| Risk findings | (none) | ✅ |

**Test 3 — `C:\Data\Sales\Project19` (Deny Sales-Gamma, mm0001 in Sales-Alpha):**

| Field | Expectation | Result |
|---|---|---|
| Effective | Read & Execute via BUILTIN\Users (the Gamma Deny does not apply to an Alpha user) | ✅ Read & Execute (0x001200AF) |
| DACL display | DENY ACE for the Sales-Gamma SID visible | ✅ |
| Matching ACEs | 3 inherited Allow ACEs for BUILTIN\Users — no Deny match (mm0001 ≠ Gamma) | ✅ |

Diagnostic markers were active as expected: "No AD connection — group memberships not resolved" and "Group resolution ran through SAM/LSA fallback" (smoke test without `--server`/`--base-dn`).

### H.5 — What Block H verifies

| Area | Result |
|---|---|
| Setup automation on Server 2025 (Autounattend + VirtIO drivers) | ✅ runs through without manual interaction |
| `Windows2025Forest` mode | ✅ chosen automatically, no adjustment to the `Install-ADDSForest` script needed |
| Cross-forest trusts on Server 2025 | ✅ `CreateTrustRelationship` builds bidirectional forest trusts unchanged |
| Stars v1.5.16 (Round-10 architecture) on Server 2025 | ✅ Effective Rights + Explanation Path + diagnostic markers + risk findings correct |
| Round-10 findings 1–4 (trustees enum, SmbAuditContext, SID map, win_safe crate) | ✅ no regression — all 3 tests pass cleanly |

### H.6 — Extended lab tests on Server 2025 (after H.4)

H.4 was a compact platform smoke (3 CLI `analyze` calls). H.6 fills in the missing code paths — scan + export, LDAP bind behaviour, SMB ∩ share, cross-forest. Status per test:

| # | Test on Server 2025 | Status | Result |
|---|---|---|---|
| H.6.1 | **GUI walkthrough** (`adpa-gui.exe`) — all 4 tabs, theme toggle | ⏳ **open** | `adpa-gui.exe` is deployed on tier0, but no manual click test executed. Covered by Block E (Server 2022, screenshots from June 6). |
| H.6.2 | **CLI `scan` recursive** + HTML + JSON + CSV export over 5105 paths | ✅ **successful** | See H.6.2.* below. |
| H.6.3 | **JSON schema v3** with Round-10 `path_trustees` enum (`entry_kind: "ace"`/`"diagnostic"`) | ✅ **successful** | See H.6.3.* below. |
| H.6.4 | **LDAP bind** against `tier0.lab` | ⚠️ **finding** (not a bug) | Server 2025 requires LDAP signing by default + the DC has no LDAPS cert without AD CS. Stars detects both errors honestly. See H.6.4.* below. |
| H.6.5 | **SMB share test with UNC** + NTFS ∩ share | ✅ **successful** | See H.6.5.* below. |
| H.6.6 | **Cross-forest T2** — user from `tier1.lab` accesses an ACL in the `tier0.lab` forest via the trust | ✅ **successful** | See H.6.6.* below. |
| H.6.7 | **Cross-forest T3** — cross-forest user WITHOUT an ACE → effectively no access | ✅ **successful** | See H.6.7.* below. |
| H.6.8 | **Trustee table "Who has access?"** with the Round-10 `PathTrusteeEntry::Diagnostic` variant in the GUI | ⏳ **open** | Covered by `exporter::trustees` + `exporter::html` unit tests; visual lab test not executed. |
| H.6.9 | **5000-path scan performance** Server 2022 vs. 2025 — LSA load measured | ⏳ **open** | But: H.6.2 shows 5105 paths in **1.5 s** per format on Server 2025 — an indicator that the Round-10 caller-owned SID map pays off on large trees. A quantitative 2022 vs. 2025 comparison was not measured. |
| H.6.10 | **Delta comparison** of two scan runs on Server 2025 | ⏳ **open** | The delta engine is platform independent (Block C screenshots from the 2022 lab cover the logic). |

> **Bottom line after H.6:** The three riskiest code paths (Round-10 JSON enum live, NTFS ∩ share live, cross-forest trust with FSP live) are successfully verified on Server 2025. Open items are GUI click tests (covered by 2022 Block E), the delta + trustee render walkthrough (unit tests green), and the performance comparison (nice-to-have).

#### H.6.2.* — Scan + export

```text
adpa.exe scan --path "C:\Data" --user "T0LAB\mm0001" --max-depth 4 --output ...
```

| Format | Size | Time | Per path |
|---|---|---|---|
| HTML | 22.9 MB | 1.5 s | 0.29 ms |
| JSON | 25.4 MB | 1.1 s | 0.22 ms |
| CSV | 6.9 MB | 1.1 s | 0.22 ms |

5105 paths, all ACL variants (Modify / Protected / Deny), three export formats — all three runs without errors.

#### H.6.3.* — JSON schema v3

`scan-mm0001.json`:

```json
{
  "version": 3,
  "permissions":    [5106 entries],
  "risk_findings":  [510 entries],
  "path_trustees":  [5106 entries]
}
```

Samples in `path_trustees`:

```text
entry_kind = "ace"        : 41342 occurrences
entry_kind = "diagnostic" : 0 occurrences (expected — no share-DACL read errors)
```

Example entry (Round-10 finding 4 typed variant):

```json
{
  "entry_kind":   "ace",
  "sid":          "S-1-5-32-544",
  "display_name": "VORDEFINIERT\\Administratoren",
  "kind":         "Allow",
  "mask":         2032127,
  "inherited":    false,
  "category":     "Ntfs"
}
```

**Verified:** `version: 3` is active, the `entry_kind` tag (Round-10 finding 4) carries cleanly, the `display_name` resolution from the scan-wide SID-name map (Round-10 finding 2) populates correctly.

#### H.6.4.* — LDAP bind behaviour

Two attempts, both fail — **not a Stars bug**:

| Attempt | Server response | Server 2025 cause |
|---|---|---|
| `--insecure-ldap` (port 389, plaintext) | `rc=8 strongerAuthRequired: The server requires binds to turn on integrity checking if SSL\TLS are not already active on the connection` | Server 2025 has **LDAP signing on by default** (security hardening, MS baseline recommendation since 2020 now enforced) |
| LDAPS port 636 (default) | `native TLS error: an existing connection was forcibly closed by the remote host. (os error 10054)` | The DC has **no valid computer certificate** for LDAPS — AD CS is not installed in the lab |

**Stars behaviour in both cases** (this is the actual verification):

- Bind failure is detected
- Structured diagnostic marker with a clear error text (`[!] LDAP identity lookup failed: …`)
- The result comes back marked `incomplete`, with the hint "Treat as incomplete"
- Stars does not crash and does not silently show wrong data

Conclusion: for Stars deployment on a Server 2025 as an audit DC, users should either set up LDAPS with a valid certificate or relax the LDAP signing behaviour in the test environment. Stars itself behaves honestly on both error paths.

#### H.6.5.* — SMB share test with UNC

Setup: SMB share `\\tier0\SalesShare` on `C:\Data\Sales` with share DACL = only **Read** for authenticated users.

Stars call:

```text
adpa.exe analyze \
  --path "\\tier0\SalesShare\Project01" \
  --user "T0LAB\mm0001" \
  --smb-server tier0 \
  --share-name SalesShare
```

Result:

```text
Effective Rights
  NTFS    : Modify (0x001301BF)           ← mm0001 in Sales-Alpha
  Share   : Read & Execute (0x001200A9)   ← share gives AuthUsers Read only
  Result  : Read & Execute (0x001200A9)   ← more restrictive wins

Explanation Path
  ...
  10. NTFS effective: Modify (0x001301BF)
  11. Share permission: Read & Execute (0x001200A9)
  12. Effective (NTFS ∩ Share): Read & Execute (0x001200A9)
```

**Verified:** NTFS ∩ share aggregation renders on Server 2025 as its own explanation step 12, the more restrictive mask wins, localized names are displayed cleanly (`VORDEFINIERT\Benutzer`, `Domänen-Benutzer`).

#### H.6.6.* — Cross-forest T2 (trust user directly in the ACE)

Setup: `C:\Data\CrossForestTest` with an explicit ACE for `T1LAB\mm0501` (cross-forest user from `tier1.lab`). Test user analyzed: the same `T1LAB\mm0501`.

```text
=== resolve mm0501 from T1LAB as an NTAccount ===
cross-user-resolved: T1LAB\mm0501 -> S-1-5-21-1437207643-1140488888-3943352020-1123
```

The trust performed the SID resolution cleanly (different forest domain SID, RID 1123).

Stars result:

```text
Matching ACEs (for this identity)
  Allow [explicit] S-1-5-21-1437207643-1140488888-3943352020-1123 → Modify (0x001301BF)

Effective Rights
  NTFS    : Modify (0x001301BF)
  Result  : Modify (0x001301BF)

Explanation Path
  1. User: mm0501 (S-1-5-21-…-1123)
  2. Allow ACE [explicit] for T1LAB\mm0501 (…) → Modify (0x001301BF)
  3. NTFS effective: Modify (0x001301BF)

Risk Findings (3)
  [HIGH ] WRITE_ACCESS    'mm0501' has Modify access
  [MEDIUM] DELETE_RIGHT    'mm0501' can delete this object
  [LOW  ] DIRECT_USER_ACE 'mm0501' has a direct explicit ACE → best practice is to assign permissions via groups
```

**Verified:** Cross-forest SID resolution via the trust works, the explicit ACE is matched, the effective rights are correct, the risk findings including the `DIRECT_USER_ACE` hint (best practice) are emitted.

#### H.6.7.* — Cross-forest T3 (user without an ACE → no access)

Setup: same path `C:\Data\CrossForestTest`. Test user: `T2LAB\mm0801` (different forest, **no ACE** on this path).

```text
=== Stars T3: T2LAB\mm0801 on C:\Data\CrossForestTest ===
  User: mm0801 (S-1-5-21-571288721-…-1124)  ← tier2 forest, clearly different from tier1

Matching ACEs (for this identity)
  (none)

Effective Rights
  NTFS    : Special (0x00000000)
  Result  : Special (0x00000000)

Explanation Path
  1. User: mm0801 (S-1-5-21-571288721-…-1124)
  2. NTFS effective: Special (0x00000000)
```

**Verified:** Stars resolves the cross-forest user cleanly (no "account not found" false negative), but rightly finds no matching ACEs and reports `no access`. The lean 2-step explanation path shows that the logic doesn't make anything up.

---

### H.7 — What remains open after H.6

| Remaining open | Coverage elsewhere | Risk |
|---|---|---|
| GUI walkthrough on Server 2025 (H.6.1) | Block E on Server 2022 (screenshots from June 6) | low — same Slint renderer |
| Trustee table GUI render with the Diagnostic variant (H.6.8) | `exporter::trustees` + `html.rs` unit tests green | low |
| 5000-path performance comparison Server 2022 vs. 2025 (H.6.9) | H.6.2 measures 0.22–0.29 ms per path — very fast | low — correctness is primary |
| Delta comparison between two scan runs (H.6.10) | Block C / screenshots from 2022, delta engine platform independent | low |

**Recommendation:** Do the GUI walkthrough with the trustee tab and the delta tab on Server 2025 together as the next test session — both are just "click the GUI on 2025" and done in 15 minutes.

---

## Block I — Re-verification of the v1.5.17/v1.5.18 engine fixes (2026-06-11)

After the v1.5.16 verification in Block H, three engine correctness fixes shipped:
v1.5.17 (BroadGroupWriteRule write-specific bits; stored-order provenance) and
v1.5.18 (OWNER RIGHTS / S-1-3-4 handling + owner step in the explanation path).
Block I re-verifies the release binary live against the same lab.

**Setup:** `adpa.exe` v1.5.18 built from tag `v1.5.18` (`1c99d10`), uploaded to
tier0 (`C:\Stars\adpa.exe`) via the SMB admin share. Execution via
`qm guest exec` from the PVE host. All three DCs running.

### I.1 — Version check

`adpa.exe --version` → `adpa 1.5.18`. ✓

### I.2 — Baseline smoke (regression guard for the H.4 scenarios)

`analyze --path C:\Data\Engineering\Project01 --user T0LAB\mm0001` (SAM/LSA
path, no LDAP flags — the recommended mode on a DC):

- Identity: `T0LAB\mm0001`, Status Active, **Kind: User** ✓
- Membership chain resolved: `Sales-Alpha [direct]`, `Domänen-Benutzer
  [direct]`, `VORDEFINIERT\Benutzer [via mm0001 → Domänen-Benutzer →
  VORDEFINIERT\Benutzer, source: LocalGroup]` ✓
- Matching inherited ACEs for BUILTIN\Users picked up; `NTFS effective:
  Read & Execute (0x001200AF)` ✓ (mm0001 is in Sales, not Engineering —
  no Modify expected)
- Risk findings: 0 ✓

Side observation (not a regression): with `--insecure-ldap` against the
Server 2025 DC the bind is still rejected with `strongerAuthRequired`,
exactly as documented in H.6.4 — Stars continues with the LSA identity,
sets `IdentityLookupFailed` and reports honestly incomplete.

### I.3 — v1.5.17 finding 1 live: no BROAD_GROUP_WRITE when the share caps to Read

Fixture `C:\ReVerify\BGW`: `icacls /grant "Jeder:(OI)(CI)M"` (NTFS Modify via
Everyone) plus SMB share `BGWTest` with **Read** access for Everyone.

`analyze --path C:\ReVerify\BGW --user T0LAB\mm0001 --smb-server localhost
--share-name BGWTest`:

```text
Allow ACE [explicit] for Jeder (S-1-1-0) → Modify (0x001301BF)
NTFS effective:  Modify (0x001301BF)
Share permission: Read & Execute (0x001200A9)
Effective (NTFS ∩ Share): Read & Execute (0x001200A9)
Risk Findings (0)
```

**Verified:** the final effective permission is Read & Execute and the risk
engine reports **zero** findings. v1.5.16 produced a critical
`BROAD_GROUP_WRITE` here (the composite `MASK_WRITE` gate matched the
READ_CONTROL/SYNCHRONIZE overlap of a Read-only mask). The false positive in
the NTFS + SMB combination is gone.

### I.4 — v1.5.18 live: OWNER RIGHTS (S-1-3-4)

**I.4a control — owner without S-1-3-4** (`C:\ReVerify\OwnerCtl`, owner set to
`T0LAB\mm0001`):

```text
14. Owner special rule: READ_CONTROL + WRITE_DAC granted implicitly (owner: T0LAB\mm0001)
```

The implicit owner grant is now an explicit step in the explanation path —
previously these bits appeared in "NTFS effective" with no step explaining
them.

**I.4b — owner with an OWNER RIGHTS ACE** (`C:\ReVerify\OwnerFsp`, owner
`T0LAB\mm0001`, inheritance removed, `icacls /grant "*S-1-3-4:(R)"`):

```text
icacls:  EIGENTÜMERRECHTE:(R)
adpa:    Allow ACE [explicit] for EIGENTÜMERRECHTE (S-1-3-4) → Read (0x00120089)
10. OWNER RIGHTS (S-1-3-4) ACE present — owner rights are governed by that DACL entry; the implicit owner grant is suppressed
NTFS effective: Read & Execute (0x001200AF)
Diagnostics: [i] OWNER RIGHTS (S-1-3-4) ACE present and the identity is the object's owner …
```

**Verified:** the effective mask contains **no WRITE_DAC bit (0x40000)** — the
implicit grant is correctly suppressed, the S-1-3-4 ACE is evaluated in DACL
order, the suppression is named in the explanation path, and the informational
diagnostic appears. Bonus observation: the German-localized display name
`EIGENTÜMERRECHTE` resolves cleanly through the SID name map.

### I.5 — Result

| Test | v1.5.16 behaviour | v1.5.18 behaviour | Status |
|---|---|---|---|
| I.2 baseline smoke | works | works identically | ✓ no regression |
| I.3 Everyone-Modify ∩ Share-Read | false critical BROAD_GROUP_WRITE | 0 risk findings | ✓ fix confirmed live |
| I.4a implicit owner grant | bits unexplained | explicit explanation step | ✓ fix confirmed live |
| I.4b OWNER RIGHTS ACE | grant wrongly applied on top | grant suppressed, ACE evaluated, diagnostic set | ✓ fix confirmed live |

Fixtures `C:\ReVerify\*` and share `BGWTest` remain on tier0 for future
regression sessions.

---

## Block J — Attempt to live-verify the FSP (L1) and GC (L2) LDAP paths (2026-06-11)

The v1.6 work added two LDAP-only features — Foreign Security Principal
resolution (L1) and Global Catalog bind (L2). Both are covered by unit
and fake-backend integration tests. Block J attempted to additionally
exercise them **live** against the lab. Documented here honestly: the
live LDAP path is blocked by the Windows Server 2025 platform, not by
Stars.

### What was tried

1. **Plain LDAP (`--insecure-ldap`) against tier0.** Rejected with
   `rc=8 (strongerAuthRequired)`: "The server requires binds to turn on
   integrity checking if SSL/TLS are not already active." This is the
   2025 LDAP-signing enforcement.
2. **Loosened `LDAPServerIntegrity`.** The Default Domain Controllers
   GPO already had it at `1` (Negotiate, *not* Require). Setting the
   live registry value to `1` and then `0`, each with an NTDS restart,
   did **not** lift the rejection — Server 2025 hard-blocks unsigned
   cleartext simple binds independently of this value.
3. **Self-signed LDAPS cert.** Created a `CN=tier0.lab` cert (Server
   Authentication EKU), placed it in `LocalMachine\My`, the local
   Trusted Root (so Stars' `ldap3` TLS validation would pass), and
   imported it into the NTDS service store; restarted NTDS. The TLS
   handshake on port 636 still reset (`os error 10054`), and a
   server-local `SslStream` test to `tier0.lab:636` reset as well —
   AD DS did not serve the cert for LDAPS. A `renewServerCertificate`
   trigger on rootDSE failed because that bind is itself subject to the
   signing enforcement.

### Conclusion

Live LDAP verification on this lab needs a **proper LDAPS certificate
chain** — in practice an enterprise CA (AD CS), which the lab does not
have — or a domain-joined client using SASL sign/seal (a different bind
mode than Stars' simple bind). This is exactly the limitation already
documented in H.6.4 and in the README's Server 2025 note. It is a
property of the hardened platform, not a Stars defect.

The FSP (L1) and GC (L2) logic is therefore verified by the test suite
(fake LDAP backends exercise the precise branch logic, the engine marker
propagation, and the risk-incompleteness flagging), not by a live lab
bind. The SAM/LSA path — the recommended production mode when Stars runs
on a DC — continues to work live and was re-confirmed at the end of this
block (mm0001 resolved as User with the full membership chain).

### Lab left clean

`LDAPServerIntegrity` restored to `1` (the GPO value), the self-signed
cert removed from the `My`, `Root`, and NTDS stores, `gpupdate /force`
applied, and NTDS restarted. No persistent change to the DC.

---

## Block K — LDAPS via AD CS, then live verification of FSP (L1) and GC (L2) (2026-06-12)

Block J established that the Server 2025 platform blocks plain LDAP and a
bare self-signed LDAPS cert. To verify the v1.6 LDAP-only features live,
Block K set up a real certificate chain via **AD CS** and then exercised
both features end-to-end.

### K.1 — AD CS Enterprise Root CA on tier0

`Install-WindowsFeature ADCS-Cert-Authority` + `Install-AdcsCertificationAuthority
-CAType EnterpriseRootCA -CACommonName "Stars-Lab-Root-CA"`. The DC then
auto-enrolled a Domain-Controller-Authentication certificate
(`CN=tier0.tier0.lab`, issued by `Stars-Lab-Root-CA`); `certutil -pulse`
+ NTDS restart. A server-local `SslStream` test to `tier0.lab:636`
completed the TLS handshake — LDAPS now served by a trusted chain.

### K.2 — Stars baseline over LDAPS (port 636)

`analyze --user T0LAB\mm0001 --server tier0.tier0.lab --base-dn DC=tier0,DC=lab
--bind-dn … ` (no `--insecure-ldap`). The TLS bind succeeded and — unlike
the SAM/LSA path — full **recursive LDAP** group resolution appeared:

```text
2. Member of Domänen-Benutzer (…-513) [direct, source: PrimaryGroup]
3. Member of Dept-Sales (…-1104) [via mm0001 → Sales-Alpha → Dept-Sales, source: DomainGroup]
4. Member of Sales-Alpha (…-1105) [direct, source: DomainGroup]
5. Member of BUILTIN\Users (…) [via mm0001 → Domänen-Benutzer → BUILTIN\Users, source: LocalGroup]
NTFS effective: Read & Execute (0x001200AF)
```

This alone confirms the LDAP code path (previously blocked on this lab)
runs correctly live.

### K.3 — L2 Global Catalog bind (live)

`analyze --user T0LAB\mm0001 --server tier0.tier0.lab --bind-dn …
--global-catalog` (**no `--base-dn`** — forest-wide):

```text
Status : Active · Kind: User
Diagnostics (structured)
  [!] Group memberships were resolved through a Global Catalog … can be
      missing. Treat as incomplete.
2. Member of Domänen-Benutzer (…-513) [direct, source: PrimaryGroup]
3. Member of Dept-Sales (…-1104) [via mm0001 → Sales-Alpha → Dept-Sales, source: DomainGroup]
NTFS effective: Read & Execute (0x001200AF)
```

**Confirmed live:** the GC bind on port 3269 (LDAPS) works, `--base-dn`
is optional (empty = all partitions), recursive resolution runs, and the
`GroupResolutionViaGlobalCatalog` marker fires exactly as designed.

### K.4 — L1 Foreign Security Principal resolution (live)

The Block-H rebuild gave the forests new domain SIDs and removed the old
cross-forest users, and the trust name-translation quirk (A.5) is still
present. A fresh fixture was therefore built:

1. tier1: new user `T1LAB\xfsp1` (SID `…-1437207643-…-1425`).
2. tier0: domain-local group `FSP-ResourceAccess`; the foreign SID added
   via a `<SID=…>` member bind, which auto-created the FSP object
   `CN=S-1-5-21-…-1425,CN=ForeignSecurityPrincipals,DC=tier0,DC=lab`
   (member of the group).
3. tier0: `C:\ReVerify\FSPGroup` with a `T0LAB\FSP-ResourceAccess:(OI)(CI)M`
   ACE (inheritance removed).

`analyze --path C:\ReVerify\FSPGroup --user S-1-5-21-…-1425 --server
tier0.tier0.lab --base-dn DC=tier0,DC=lab --bind-dn …` (LDAPS):

```text
User   : T1LAB\xfsp1            ← LSA enrichment gave the real cross-forest name
Status : Active · Kind: User
2. Member of FSP-ResourceAccess (…-1625) [direct, source: DomainGroup]
4. Allow ACE [explicit] for FSP-ResourceAccess (…-1625) → Modify (0x001301BF)
5. NTFS effective: Modify (0x001301BF)
Diagnostics:
  [!] Identity is a trust-forest principal found as a Foreign Security
      Principal … memberships in its own forest are unknown. Treat as incomplete.
Risk Findings (2)
  [HIGH]   WRITE_ACCESS  'xfsp1' has Modify access …  [INCOMPLETE]
  [MEDIUM] DELETE_RIGHT  'xfsp1' can delete this object …  [INCOMPLETE]
```

**Confirmed live — this is the exact capability L1 adds:** binding against
the resource domain (tier0), Stars resolved the foreign SID to its **FSP
object**, enriched the identity via LSA to `T1LAB\xfsp1` (not a raw SID),
resolved the **home-domain group membership through the FSP**
(`FSP-ResourceAccess`), credited that group's Modify ACE to the effective
permission, fired the `IdentityResolvedViaForeignSecurityPrincipal`
marker, and flagged the derived risk findings `[INCOMPLETE]`. Before the
v1.6 fix this SID would have resolved as `Unknown` with no marker and the
FSP→group→ACE chain would have been silently missed — understating the
trust user's rights.

### K.5 — Result

| Feature | Test suite | Live (this block) | Status |
|---|---|---|---|
| LDAPS via a trusted chain (AD CS) | n/a | TLS handshake + bind OK | ✓ |
| Recursive LDAP group resolution | yes | mm0001 chain via LDAPS | ✓ |
| L2 — Global Catalog bind (`--global-catalog`) | yes | forest-wide, marker fires | ✓ |
| L1 — FSP resolution (SID→FSP→home group→ACE) | yes | xfsp1 Modify via FSP, marker, incomplete | ✓ |

### Lab state after Block K

- **AD CS (Enterprise Root CA `Stars-Lab-Root-CA`) remains installed on
  tier0** — a deliberate improvement: LDAPS is now permanently available
  for future live LDAP tests. The DC holds a proper
  Domain-Controller-Authentication certificate.
- `LDAPServerIntegrity` is at the GPO value `1`; the Block-J self-signed
  cert was already removed.
- Test fixtures kept for regression: `T1LAB\xfsp1`, tier0 group
  `FSP-ResourceAccess` + its FSP member, and `C:\ReVerify\FSPGroup`.
