# Test campaign 2026-10 — constellations, complexity and evidence

This document records what Stars was tested against in the lab between 2026-10-24 and 2026-10-25, how the expected value ("ground truth") was obtained, what was measured, and what each result does and does not prove. It is written so that an auditor or an administrator can follow every step and judge the evidence.

The short lab notes for each block are in `docs/lab/verification.md` (blocks R–Y). The decisions are in the ADRs named here.

## 1. Principles

- **Windows is the reference, not Stars.** Every effective right Stars reports is compared with a value Windows itself produced. That value comes from one of two places:
  - **a real SMB logon** of the account (opening each object with single access rights, writing nothing)
  - **the Authz API** (`AuthzInitializeContextFromSid` + `AuthzAccessCheck`, MAXIMUM_ALLOWED) on the server that holds the object

  When the two disagree, the real logon counts.
- **"Exact" must be exact.** A result Stars reports without "NOT DETERMINABLE" must match Windows bit for bit. A result marked NOT DETERMINABLE must name its reason, and the Windows value must lie within what Stars states. A difference in either case is a finding.
- **No claim without evidence.** Where a test cannot prove something (for example, a third-domain SID on a forest trust), this document says so.
- **Regression proof before merge.** Every change was compared column by column with the previous binary over the release regression sets:
  - DC-01's data share: 37 identities, 25,493 rows
  - the group-types fixture: 78 rows
  - MS-01 with LDAP: 135 rows
  - MS-01 with local accounts: 135 rows
  - where relevant, the ext.test trust fixture with the trusted-domain connection: 65 rows

## 2. The lab

| VM | Role | OS | Address |
| --- | --- | --- | --- |
| DC-01 | corp.test (configured domain), DFS namespace server | Server 2022 de | .147 |
| DC-02 | ext.test, external trust with quarantine | Server 2022 de | .148 |
| MS-01 | member server corp.test | Server 2025 de | .149 |
| FS-01 | member server corp.test, 200 GB data disk | Server 2025 en-US | .160 |
| FS-02 | member server corp.test | Server 2022 de | .161 |
| WIN11-01 | client corp.test | Windows 11 Pro 25H2 en-US | .162 |
| DC-03 | partner.test (forest root), forest trust with corp.test | Server 2022 en-US | .163 |
| DC-04 | child.partner.test | Server 2025 en-US (LDAP signing required) | .164 |

corp.test holds 10,017 users and 5,115 groups. 5,000 of the groups are global groups, 3,575 of them nested in other groups. Stars ran from a workstation outside the domain and, where the case needed it, on the domain-joined MS-01.

## 3. Campaigns

### 3.1 Forest trust — domains of a trusted forest (ADR 0084)

**Question.** Does Stars evaluate an account of another forest correctly? This covers an account of a child domain of that forest, and an account whose token holds groups of other domains of that forest.

**Constellation.**

- **Trust:** bidirectional forest trust corp.test ⇄ partner.test. Its trust information lists `partner.test` and `child.partner.test`.
- **Accounts:**
  - `pt_user01` in a global, a universal and a domain-local group of partner.test
  - `pt_user02` in a universal group of the child domain
  - `ch_user01` in the child's global, universal and domain-local groups
  - `ch_user02` in a universal group of partner.test
- **Folders:** 13 folders on DC-01, each granting one of these principals. One of them is a corp.test domain-local group that holds both forests' global groups as Foreign Security Principals.

**Ground truth.** The Authz oracle on DC-01, and real SMB logons from MS-01 for all four accounts on all folders.

**Findings fixed.**

1. A child-domain account was reported as "neither the configured domain nor one of its trusts". That is misinformation.
2. Groups of another domain of the trusted forest were "not modelled", so the result was not determinable on every folder.
3. With a Global Catalog bind, even a directly trusted domain was "not one of its trusts".
4. A refused bind to the Server 2025 DC was hidden ("could not be read").

**Result.** 56 of 56 rows are determinable and equal to the real logons.

**Not proven.** SIDs of third domains and of the trusting forest on a forest trust (SID history from a migration), `TREAT_AS_EXTERNAL`, and disabled domain records. Stars reports all of these as not modelled. Testing them needs a SID-history migration (`DsAddSidHistory`).

### 3.2 Trusted-domain accounts on a domain-joined machine (ADR 0078 addendum)

**Question.** Does the trusted-domain connection work where admins usually run Stars, on a domain-joined machine?

**Finding.** There, Windows names every account of a trusted domain, and Stars never used the configured connection. On MS-01, five ext.test accounts gave 65 of 65 rows NOT DETERMINABLE.

**Result after the fix.** 65 of 65 rows are exact and identical to the run from a non-joined workstation. The partner and child accounts with signed LDAP (Kerberos across the forest trust) give 56 of 56 rows equal to the real logons.

### 3.3 DFS namespaces (ADR 0085)

**Question.** What does Stars report for `\\domain\namespace\folder\…`, and is it what a client gets?

**Constellation.**

- **Namespace:** domain-based namespace `\\corp.test\dfs`, root share `dfs` on DC-01 (Everyone Read).
- **Folder `Projects`:** two targets with different share and NTFS permissions on purpose.
  - FS-01: share Change; NTFS `rt_gt01` Modify
  - FS-02: share Read; NTFS `rt_gt02` Modify
- **Folder `Team`:** one target, on FS-02 (share Full).

**Ground truth.** Real SMB through the namespace, with sessions as the account to the namespace and both servers. `target.txt` in each target shows the referral.

**Finding fixed.** The NTFS part came from the target, but the share permissions, local groups and policies came from the namespace server. An account with Modify was shown with Read & Execute: a right under-reported.

**Result.**

- **`Team` (one target):** exact and equal to Windows, for example `rt_gt02` Modify.
- **`Projects` (two targets):** shows the referred target's values and is NOT DETERMINABLE, with the other target named. A client referred to FS-02 has other rights.
- **Namespace root scan:** folders on other shares are reported as "served from another share" and are not evaluated with the wrong share.

**Not proven.** Clients in other AD sites, offline targets, standalone namespaces, several namespace servers, and Access-based Enumeration.

### 3.4 Language and version of the server (FS-01 2025 en-US / FS-02 2022 de-DE)

**Constellation.** The same tree, built by SID, on both servers:

- BUILTIN\Users
- a local group holding a domain account
- Deny Write for Authenticated Users
- CREATOR OWNER and OWNER RIGHTS
- Remote Desktop Users holding a domain account
- a broken inheritance
- a file ACE
- INTERACTIVE and NETWORK
- a junction and a directory symbolic link

Four accounts were scanned over SMB.

**Result.** 52 rows, 0 differences between the two servers: masks, determinability, share and local-group status, markers, and the same scan errors.

**Finding fixed.** A symbolic link that Windows does not follow over SMB (error 1463, remote-to-local evaluation disabled) was reported as "Access denied". It now names the Windows reason.

**Limit.** Language and version vary together, so a difference could not have been attributed to one of them. With 0 differences that does not matter.

### 3.5 Mass scan and memory (ADR 0086)

**Constellation.** `T:\MassData` on FS-01: 1,500,560 files in 11,139 folders, in a regular structure:

- every 5th project breaks inheritance with group ACEs
- every 7th folder has a Modify ACE
- every 50th folder has a Deny Write
- long paths, Unicode names, credential-like file names

**Finding fixed.** The CLI scan kept every result until the end: 2 GB for 75,586 paths, about 40 GB projected for the whole tree. The export target was checked only after the scan.

**Result.** The same department streamed needs 29 MB instead of 2,001 MB, runs 22 % faster, and writes a byte-identical CSV and an identical database. A real Ctrl-C leaves a consistent partial run. The whole tree: see 3.5.1.

**Limit.** This tree is regular, with few distinct security descriptors. It proves the memory behaviour, not throughput on a real file server. That is the purpose of 3.6.

#### 3.5.1 Whole tree

**Run.** The CLI scanned all of `MassData` over SMB as `u00030` (about 70 groups), writing the database and a CSV export. It ran from the workstation, with a release build.

| Measure | Value |
| --- | --- |
| paths | 1,511,721 |
| time | 3,182 s (53 min), about 475 paths per second |
| peak working set / commit | 91 MB / 91 MB |
| CSV / database | 18,146 MB / 18,437 MB |
| scan errors | 0 |
| risk findings | 146,439 |

**Integrity.** A separate check (`mass_integrity.py`) read both outputs completely. The CSV and the database hold the same 1,511,721 rows with the same set of paths. The run is committed with its finish time.

**Regression before the merge.** The release regression sets (section 1) were run with the streaming build and with a fresh baseline of the previous build (main 1ca851b) on the same day: 25,906 rows, 0 differing values in any column. An earlier comparison against an older baseline had shown differences in the explanation column only. They came from the enterprise groups added to the directory in between, which nest the legacy groups and so lengthen the legacy accounts' membership lists. The fresh baseline confirmed this.

### 3.6 Enterprise campaign

**Question.** Does Stars give the right answer, for every object and completely, on a file server built the way companies build them? That means the AGDLP group design, tens of thousands of distinct ACLs, and every kind of exception an audit meets. And how fast is it there?

#### 3.6.1 Constellation — directory (corp.test)

- **Role groups:** the 5,000 global groups `g*` of the scale fixture, 3,575 of them nested in other groups.
- **Resource groups:** 1,476 domain-local groups (`ent-ad-fixture.ps1`, seeded), one per area and one per project:
  - `DL_ENT_<area>_<RW|RO|M>`
  - `DL_ENT_<area>_P<nn>_<RW|RO|M>` for 12 areas × 40 projects

  Each holds one to four role groups. This is AGDLP: accounts in global role groups, those in domain-local resource groups, and the resource groups in the ACLs.
- **Accounts.** "Groups in the token" is `tokenGroups` as Windows computes it on the DC.

| Account | Built as | Groups in the token |
| --- | --- | --- |
| `ent_std` | a typical employee: 10 role groups | 78 |
| `ent_heavy` | role groups added until the token neared the limit (`ent-ad-heavy.ps1`) | 874 |
| `ent_power` | 450 role groups and 80 resource groups | 1,721, over the limit of 1,015 group SIDs |
| `ent_svc` | a service account, directly in 60 resource groups | 62 |
| `ent_disabled` | disabled, in the groups of `ent_std` | 78 |
| `ent_local` | a local account of FS-01, in the local group `ENT_Local_RW` | — |
| `u00001` | a legacy account; direct ACEs and owners are drawn from 1,000 such accounts | — |
| `ext_partner01` | ext.test (external trust, quarantine), in `GG_ExtPartners` and `UG_ExtUniversal` | — |
| `pt_user01` | partner.test (forest trust), in `GG_PT_Staff` and `UG_PT_Forest` | — |

#### 3.6.2 Constellation — file server

**Location.** FS-01 (Server 2025 en-US), `T:\Enterprise`, share `Enterprise` (Everyone Change, Administrators Full). Built by `ent-fs-gen.cs` (seeded) in 648 s.

**Size.**

- 12 areas (11 departments and an archive), 25 projects each.
- 1,649,674 objects: 29,743 folders and 1,619,895 files.
- Up to 24 levels deep; paths up to 1,167 characters, 49 of them longer than 260.

**Permissions.**

- Every area is protected with its RO and RW resource groups.
- Every project is either protected (30 %) or has explicit RW and RO ACEs for its resource groups.
- The generator set 62,387 security descriptors. On disk there are 62,411 distinct descriptors, 54,690 of them used by one object only (`ent-sd-stats.ps1`).

| ACEs per descriptor | Objects |
| --- | --- |
| 0–4 | 90,125 |
| 5–10 | 1,466,190 |
| 11–50 | 1,562 |
| 51–100 | 23,498 |
| 101–200 | 66,574 |

**Exceptions.** Placed at random, each recorded in a manifest (`T:\Enterprise.manifest.tsv`):

| Feature | Objects | What it tests |
| --- | --- | --- |
| `file-explicit-user` | 33,016 | a file with an explicit Modify ACE for a user |
| `file-owner-user` | 16,228 | a file owned by a user (the implicit owner rights) |
| `file-protected` | 4,728 | a file with inheritance broken |
| `file-deny-group` | 3,161 | a file with a Deny Full Control for a role group |
| `explicit-allow` | 2,234 | a folder with an explicit Allow for a role group or a user |
| `owner-user` | 877 | a folder owned by a user |
| `inheritance-break` | 346 | a folder with inheritance broken and its own ACEs |
| `deny-delete` | 292 | a Deny Delete for a department's RW group |
| `legacy-dacl-large` | 276 | 60–200 ACEs, 5 % of them Deny (in the archive 5 % of all folders) |
| `orphan-sid` | 259 | an ACE for a deleted account (orphaned SID) |
| `project-explicit` / `project-protected` | 213 / 87 | the two project designs |
| `deny-write-user` | 141 | a Deny Write for a user |
| `foreign-sid` | 119 | Modify for a group or account of ext.test, partner.test or child.partner.test |
| `creator-owner-owner-rights` | 116 | CREATOR OWNER (inherit only) and OWNER RIGHTS |
| `local-group` | 104 | Modify for the local group `FS-01\ENT_Local_RW` |
| `deep` | 84 | a chain of 14–18 levels |
| `inherit-only` | 75 | an ACE that applies only to the children |
| `non-canonical` | 45 | a Deny after an Allow (non-canonical order) |
| `admin-free` | 30 | only one user has access, the administrators have none |
| `empty-dacl` | 16 | a DACL without entries (no access for anyone) |
| `long` | 13 | a long path (> 300 characters; 1,100 in the archive) |
| `dept-protected` | 12 | the protected areas |
| `hot-folder-12000` | 12 | a folder with 12,000 files |
| `junction-duplicate` | 12 | a junction to a sibling project: a second route |
| `junction-cycle` | 12 | a junction to its own department: a loop |
| `symlink-dir` | 12 | a directory symbolic link to a drive path of the server |
| `null-dacl` | 11 | no DACL at all (full access for everyone) |

The generator could not create 7,904 objects. They lie below the 30 admin-free and 16 empty-DACL folders, which no longer let it write once their DACL was set. These objects do not exist, so neither Stars nor Windows sees them.

#### 3.6.3 Ground truth — three independent sources

1. **The exhaustive oracle** (`ent-oracle-full.ps1`, on FS-01).
   - It walks the tree itself, without Stars, and reads each object's security descriptor once.
   - For each of nine identities, Windows computes the granted right: `AuthzInitializeContextFromSid` (the account's token from AD plus FS-01's local groups) and `AuthzAccessCheck` with `MAXIMUM_ALLOWED`.
   - 1,647,949 objects × 9 identities in 372 s.
   - It found the same 1,647,949 objects as Stars, with 36 reparse points and 46 folders that cannot be listed.
2. **The NTFS kernel with a real logon** (`nulldacl-kernel.ps1`, `wattr-probe.ps1`, on FS-01).
   - A real network logon of `ent_std` (`LogonUser`, type 3) is impersonated.
   - Each object is opened with `MAXIMUM_ALLOWED` or with one right, and the access the handle really got is read back (`NtQueryObject`).
   - Used where the oracle and another source disagree.
3. **Real SMB from a Windows 11 client** (`ent-smbprobe.ps1`, on WIN11-01).
   - The client connects as the account and opens each object with one right at a time, so the file server builds the account's real network token and applies NTFS and the share itself.
   - FILE_WRITE_ATTRIBUTES is also *exercised*: `FileBasicInfo` with every field 0, which changes nothing.
   - Sample: 9,094 objects from the whole tree (up to 120 per feature, three objects below each, 2,500 at random, all 36 links).

#### 3.6.4 Results

**Full tree, `ent_std` over SMB** (main a74a70a, release, from the workstation):

| Measure | Value |
| --- | --- |
| paths | 1,647,949 (the oracle's own count) |
| time | 4,716 s (78.6 min), 349 paths per second |
| peak working set | 292 MB |
| CSV / database | 2,562 MB / 3,455 MB |
| risk findings | 282,453 |
| scan errors | 82, all built in: 12 symbolic links, 12 duplicate routes, 12 cycles, 46 folders without administrator access |
| rows not determinable | 0 |

**Every row against Windows** (`ent_exhaustive.py`):

| Identity | Scope | Rows | Equal to Windows, bit for bit |
| --- | --- | --- | --- |
| `ent_std` | whole tree | 1,647,949 | 1,647,938, plus 11 NULL-DACL folders (see below) |
| `ent_heavy` (874 groups) | Archive | 243,262 | all |
| `ent_svc` | Archive | 243,262 | all |
| `u00001` | Archive | 243,345 | all |
| `ent_local` (local account of FS-01) | Archive | 243,262 | all |
| `ext_partner01` (external trust) | Archive | 243,345 | all |
| `pt_user01` (forest trust) | Archive | 243,289 | all |
| `ent_disabled` | Finance | 124,617 | all |
| `ext_partner01` | IT (15 foreign-SID folders) | 134,083 | all, including 2 NULL-DACL objects (kernel) |
| `pt_user01` | HR (15 foreign-SID folders) | 123,823 | all, including 1 NULL-DACL object (kernel) |
| `ent_local` | Production (14 local-group folders) | 126,800 | all |
| `ent_power` (1,721 groups) | Finance | 124,617 | Windows builds no context (Authz error 8); Stars reports every row NOT DETERMINABLE: "more than the 1015 [SIDs] that fit into a Windows logon token; a logon of this account fails" |

- **The 11 NULL-DACL folders:** Authz returns `0x001FFFFF` for `MAXIMUM_ALLOWED`, because it has no generic mapping for files. The NTFS kernel, with a real logon, grants exactly `0x001F01FF` (FILE_ALL_ACCESS), which is what Stars reports. Asked for a right without meaning for files (0x200), the kernel drops it.
- **Completeness:** in every run, each object Windows enumerated has a Stars row or is explained by a reported scan error, and every row names a real object. For each exact row, effective = NTFS ∩ share held, without exception.
- **The link rows:** compared with the link object's own oracle row, as both sources read the link's own descriptor. What opening such a path reaches is in the probe results below.

**Real SMB logons of `ent_std`** (9,094 objects, 13 rights each):

| Result | Objects | Meaning |
| --- | --- | --- |
| equal to Stars | 8,988 | |
| junction paths whose open gets exactly the target's Stars row | 22 | finding 3 |
| directory symbolic links, not followable from the client (error 3) | 12 | finding 1 |
| rights without SYNCHRONIZE | 69 | see finding 4 |
| link rows whose own value differs from what an open gets | 3 | finding 3 |

The first probe run reported FILE_WRITE_ATTRIBUTES (and sometimes FILE_EXECUTE) as granted on 195 objects where Stars, Authz and the kernel deny it. The cause is the Windows SMB client: while a handle to the same file is open or cached, it answers an attribute-only open itself, without the server checking. Three measurements showed this:

1. Asked as the *first* open of the object on a fresh session, the server refused the open (error 5) on all of them.
2. After a read open, the client reported success (handle `0x00100180`), but the server refused the actual use (`SetFileInformationByHandle`) with error 5.
3. The control, a folder with Modify, allowed both.

The probe therefore asks for these rights first and exercises WRITE_ATTRIBUTES. The same artifact explains an older observation of 0x180 / 0x1A0 attribute bits on a share root.

**Builds.** The full scan and the first eight identity scans ran with main a74a70a, and the last six with the fix of ADR 0088. Values do not differ between them: every row was compared with the same oracle.

**Why the archive does not cover every feature.** In the archive, the generator replaces every feature drawn below 5 % by a legacy DACL. The archive therefore holds no local-group, foreign-SID, NULL-DACL or admin-free folders. The three department scans above cover those features for the accounts they concern. `ent_std`, a member of the local group, covers all 104 local-group folders in the full scan.

**Delta between two scans** (`delta-fixture.ps1`, `deltadrv`, Stars' own `compare_scans`):

- **Setup:** a fixture of seven objects below MS-01's `MSData`, scanned as `u00030`.
- **The change in between:**
  - Modify for `u00030` on `A`
  - Deny Write on `B`
  - a new file `B\new.txt`
  - `C\c.txt` deleted
- **Result:** exactly four changes:
  - `A` and `A\a.txt` changed (No access to Modify; effective and NTFS masks)
  - `B\new.txt` added
  - `C\c.txt` removed

  The Deny on `B` does not appear, and rightly so: the account had no rights there, so nothing changed for it.

#### 3.6.5 Findings and what was done

1. **A symbolic link to a drive path of the server was called "a broken link"** (fixed, verification Block X).
   - Over SMB, the client resolves `T:\…` on itself.
   - Where it has no `T:`, Windows answers error 3; where it has the drive, 1463 (Block T).
   - Stars now names the target and who resolved it.
2. **With remote-to-local evaluation enabled on the scanning machine, its own folder was walked as part of the share** (fixed, Block X).
   - Proven on MS-01: a file that exists only on MS-01 appeared in the scan of FS-02 with Read & Execute.
3. **A link's row looked like the rights on its content** (fixed, ADR 0088, Block Y).
   - The row is exact for the link object, but opening the path reaches the target.
   - The real logon was refused where the row showed Modify.
   - The row now names the target and says so.
4. **Over SMB, an open also needs the right to read the object's attributes** (measured; known limitation L20, a follow-up decision).
   - Of the 69 objects whose right lacks SYNCHRONIZE (marker `SynchronizeNotGranted`, ADR 0080), an open without SYNCHRONIZE for exactly the right Stars shows was granted on the 5 whose parent grants List folder.
   - It was refused on the 64 whose parent does not.
   - The values are the exact AccessCheck result; over SMB these 64 cannot be used.
5. **A folder could be listed twice when its identity could not be read over SMB** (fixed, ADR 0088, Block Y).
   - 3 of 6 archive scans that ran in parallel listed objects twice, with correct values.
   - In one of them, a cycle went unrecognized.

## 4. What is not covered

What these campaigns do **not** prove, so nobody reads more into them:

- **Other file servers.** All file servers were Windows Server 2022 and 2025 with NTFS. Not tested:
  - ReFS
  - Samba
  - NAS appliances (NetApp, Synology, …)
  - Azure Files

  Non-Windows servers may report no file ID; Stars then marks the folders (ADR 0088), but their access checks were not measured.
- **Dynamic Access Control.** Central access policies and conditional ACEs are not in the fixtures. Stars does not evaluate them (known limitation L8) and marks such ACEs as not evaluable.
- **Mandatory integrity labels and SACLs.** Not in the fixtures, and not part of what Stars evaluates.
- **Changes during a scan.** The tree did not change while it was scanned. Stars reads each object once, so an object changed in the middle of a run shows the state at the moment it was read.
- **The share layer in depth.** The enterprise share has one share ACL (Everyone Change, Administrators Full). Combinations of share and NTFS permissions are covered by the regression sets and earlier blocks, not by this tree.
- **Real logons for every identity on every object.** The exhaustive comparison uses Windows' Authz API. Real logons cover samples, plus the kernel where a source disagreed. Accounts with a token over the limit cannot log on, so they can only be compared with "Windows builds no token".
- **Over SMB, an open also needs the right to read attributes** (finding 4). Stars shows the exact AccessCheck result. For an account without read-attributes on the object, and without List folder on its parent, it does not yet say that the rights cannot be used over SMB.
- **Throughput elsewhere.** All VMs ran on one Proxmox host and shared its storage, and Defender was active on FS-01. The numbers describe this lab, not a guarantee for other hardware.
- **Forest trusts with SIDs of third domains, `TREAT_AS_EXTERNAL`, disabled domain records** (see 3.1). These need a SID-history migration to test.
- **DFS beyond one site** (see 3.3): other AD sites, offline targets, several namespace servers, Access-based Enumeration.
