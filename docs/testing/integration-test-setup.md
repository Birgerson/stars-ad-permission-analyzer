# Integration Test Environment

Status: 2026-05-25

This document describes how to set up a test domain (`testdomain.local`) for the AD integration tests of the DevMS analyzer, plus a test file server for NTFS and SMB scenarios.

---

## 1. Why a dedicated VM is required

The integration tests need a **real Active Directory domain controller**.

- A domain controller requires the **Active Directory Domain Services (AD DS)** role. This role only exists on **Windows Server**, not on Windows 10/11 (client/workstation SKU, `ProductType=1`).
- Promotion (`Install-ADDSForest`) creates a forest and reboots the host. That is a deep, barely reversible change.
- A developer workstation must **never** be promoted to a domain controller.

**Recommendation:** an isolated, disposable VM (Hyper-V, VMware, VirtualBox, or similar) with **Windows Server 2019/2022/2025**. Take a snapshot before the setup so a clean rollback is possible.

> Read-only note: the DevMS analyzer never modifies target systems. The scripts under `scripts/test-env/` are **test environment provisioning only** and are not part of the analyzer. They are meant to run only on the test VM.

---

## 2. Prerequisites

| Component | Requirement |
|-----------|-------------|
| Test VM | Windows Server 2019 or newer, isolated test network |
| RAM | ≥ 4 GB for DC + file server combined |
| Privileges | Local administrator on the VM |
| Rust toolchain | Only needed on the developer machine (tests run against the VM via LDAP) |
| Network | Developer machine must reach the VM on TCP 389/636 |

DC and file server may live on the **same** VM — that is acceptable for tests.

---

## 3. Step 1 — Set up the domain controller

In an administrative PowerShell on the **test VM**:

```powershell
.\scripts\test-env\01-setup-dc.ps1
```

The script:

1. installs the AD DS role,
2. promotes the VM to the forest `testdomain.local` (NetBIOS `TESTDOMAIN`),
3. asks for a DSRM password,
4. **reboots the VM**.

After the reboot `testdomain.local` is active. Log in as `TESTDOMAIN\Administrator`.

---

## 4. Step 2 — Create AD test objects

After the reboot, again in an administrative PowerShell:

```powershell
.\scripts\test-env\02-setup-ad-objects.ps1
```

The script creates the following under `OU=DevMS-Test,DC=testdomain,DC=local`:

**Legacy users for integration tests**

| sAMAccountName | Purpose in tests |
|----------------|------------------|
| `max.mustermann` | Group resolution, transitive membership |
| `anna.schmidt` | Identity caching test |
| `Administrator` | Already present — `resolve_administrator_identity` |

**Seven departments as sub-OUs**

| Sub-OU | Members |
|--------|---------|
| `OU=Management` | birger.labinsch |
| `OU=HR` | susanne.mueller |
| `OU=Analysis` | thomas.hibel, markus.neuer |
| `OU=Production` | reiner.wanscher, frank.hilbert |
| `OU=Finance` | heidi.weger |
| `OU=Warehouse` | oscar.wolle |
| `OU=Science` | julia.kurz, jasmin.koppen |

In total **12 users** (10 from PASSWORD.md + 2 legacy). All users get the same test password, which the script prompts for interactively.

> The department assignment is an example — PASSWORD.md does not specify it. Adjust in the `$testUsers` array of `02-setup-ad-objects.ps1`.

**Groups and nesting**

Legacy (for `resolve_group_memberships_max_mustermann`):

```text
max.mustermann ─┬─ GRP_IT_Admins   (direct)  ── GRP_FullAccess_FS   (nested)
                └─ GRP_Development (direct)  ── GRP_ShareAccess_SMB  (nested)
```

One members group per department in its sub-OU:

```text
GRP_Management_Members
GRP_HR_Members
GRP_Analysis_Members
GRP_Production_Members
GRP_Finance_Members
GRP_Warehouse_Members
GRP_Science_Members
```

In total **11 groups** (4 legacy + 7 members).

The legacy structure is exactly what `crates/ad_resolver/src/resolver.rs` expects (`resolve_group_memberships_max_mustermann`). It must not be removed without also updating the test.

The script is idempotent — existing objects are skipped. For non-interactive runs it accepts `-UserPassword` as a SecureString.

---

## 5. Step 3 — Set up the test file server

```powershell
.\scripts\test-env\03-setup-fileserver.ps1
```

The script creates two structures under `C:\DevMS-TestData`:

**Legacy structure** (covers the analyzer's audit cases):

| Path | NTFS permission | Share | Test case |
|------|-----------------|-------|-----------|
| `Public` | `Everyone` Read | `Public$` (Full) | Everyone / broad-group rule |
| `IT` | `GRP_IT_Admins` Modify (inherited) | `IT` (Change) | Group / nested rights |
| `IT\maxdata` | additional `max.mustermann` explicit | — | `DIRECT_USER_ACE` |
| `Development` | `GRP_Development` Modify | — | Group rights |
| `Development\Restricted` | inheritance disabled, explicit Deny | — | Inheritance break, Deny |
| `Shared` | `GRP_FullAccess_FS` Full Control | `Shared` (Read) | NTFS ∩ share combination |
| `Secrets\passwords` | `GRP_IT_Admins` Read | — | `SENSITIVE_PATH` rule |

**Department structure** under `C:\DevMS-TestData\Departments` — one folder and one visible SMB share per sub-OU from step 2:

| Path | NTFS permission | Share |
|------|-----------------|-------|
| `Departments\Management` | `GRP_Management_Members` Modify | `Management` (Change) |
| `Departments\HR` | `GRP_HR_Members` Modify | `HR` (Change) |
| `Departments\Analysis` | `GRP_Analysis_Members` Modify | `Analysis` (Change) |
| `Departments\Production` | `GRP_Production_Members` Modify | `Production` (Change) |
| `Departments\Finance` | `GRP_Finance_Members` Modify | `Finance` (Change) |
| `Departments\Warehouse` | `GRP_Warehouse_Members` Modify | `Warehouse` (Change) |
| `Departments\Science` | `GRP_Science_Members` Modify | `Science` (Change) |

That gives every department user a dedicated permission scope including an SMB path (`\\<dc>\<Dept>`) the analyzer can evaluate.

> These write operations also affect the test VM only. The analyzer itself later only reads these structures.

---

## 6. Step 4 — Run the integration tests

The AD integration tests are marked `#[ignore]` and read their connection from environment variables. Without the variables set they return early (`test_config()` returns `None`).

Required environment variables:

| Variable | Example |
|----------|---------|
| `DEVMS_TEST_LDAP_SERVER` | `dc01.testdomain.local` |
| `DEVMS_TEST_LDAP_BASE_DN` | `DC=testdomain,DC=local` |
| `DEVMS_TEST_LDAP_BIND_DN` | `CN=Administrator,CN=Users,DC=testdomain,DC=local` |
| `DEVMS_TEST_LDAP_PASSWORD` | (bind password) |
| `DEVMS_TEST_LDAP_INSECURE` | `1` only if LDAPS is unavailable — otherwise omit |

Convenience script on the **developer machine** (prompts for the password securely):

```powershell
.\scripts\test-env\04-run-integration-tests.ps1 -Server dc01.testdomain.local
```

Or manually:

```powershell
$env:DEVMS_TEST_LDAP_SERVER  = "dc01.testdomain.local"
$env:DEVMS_TEST_LDAP_BASE_DN = "DC=testdomain,DC=local"
$env:DEVMS_TEST_LDAP_BIND_DN = "CN=Administrator,CN=Users,DC=testdomain,DC=local"
$env:DEVMS_TEST_LDAP_PASSWORD = (Read-Host -AsSecureString | ConvertFrom-SecureString -AsPlainText)
cargo test --workspace -- --ignored
```

Expected integration tests (`crates/ad_resolver/src/resolver.rs`):

- `resolve_administrator_identity`
- `resolve_group_memberships_max_mustermann`
- `orphaned_sid_returns_unknown`
- `identity_is_cached_after_first_lookup`

> **Security:** Never pass the bind password as a cleartext argument or leave it in the shell history. Set `DEVMS_TEST_LDAP_PASSWORD` only for the process. `DEVMS_TEST_LDAP_INSECURE=1` enables unencrypted LDAP — use only in isolated test networks.

---

## 7. Functional end-to-end CLI test

The analyzer can be verified directly against the test file server:

```powershell
# Effective rights of a user on a folder
adpa analyze --path C:\DevMS-TestData\Shared `
  --user max.mustermann `
  --server dc01.testdomain.local `
  --base-dn "DC=testdomain,DC=local" `
  --bind-dn "CN=Administrator,CN=Users,DC=testdomain,DC=local"

# Recursive scan with HTML report including risk findings
adpa scan --path C:\DevMS-TestData `
  --user max.mustermann `
  --server dc01.testdomain.local `
  --base-dn "DC=testdomain,DC=local" `
  --bind-dn "CN=Administrator,CN=Users,DC=testdomain,DC=local" `
  --output report.html
```

The bind password is read from `ADPA_BIND_PASSWORD` (see `adpa --help`).

---

## 8. Teardown

Preferred: **revert the VM snapshot**.

If the VM should be kept:

```powershell
.\scripts\test-env\99-teardown.ps1
```

The script removes the AD test OU, the shares, and `C:\DevMS-TestData`. Demoting the domain controller (`Uninstall-ADDSDomainController`) must be done deliberately by hand and is not part of the script.

---

## 9. Quick reference

```text
Test VM (Windows Server):
  1. scripts\test-env\01-setup-dc.ps1          -> DC, reboot
  2. scripts\test-env\02-setup-ad-objects.ps1  -> users + groups
  3. scripts\test-env\03-setup-fileserver.ps1  -> folders + ACLs + shares

Developer machine:
  4. scripts\test-env\04-run-integration-tests.ps1 -Server <dc-fqdn>
```
