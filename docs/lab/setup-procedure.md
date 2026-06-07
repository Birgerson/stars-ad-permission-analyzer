# Lab Setup — Reproducible Step Sequence

> Reproduction by a second person should be possible from this file plus the scripts under [`scripts/`](scripts/) alone. All gotchas are documented here so nobody has to work through the same quoting or prerequisite problems twice.

## Prerequisites

| Item | Requirement |
|------|----------------|
| Proxmox VE | 9.1.1 or newer |
| Template VM | Windows Server 2022 Standard (in the lab documented here: VMID 9000, name `MS-Server-2022-Std`, with active qemu-guest-agent and a default local administrator without a password) |
| Storage | at least 3 × 101 GB free for the clones (linked clones reference the template but are thin on writes → disk usage grows over their lifetime) |
| Bridge | `vmbr0` with routing to 192.168.11.0/24 |
| Admin tools on the control host | `plink`/`pscp` (PuTTY suite) or the OpenSSH client, plus `bash` (Git Bash or similar) for the scripts. The scripts under [`scripts/`](scripts/) run on the **PVE host**, not on the control machine. |
| Lab default password | The environment variable `LAB_ADMIN_PASSWORD` must be set when running the scripts. It replaces the previously hard-coded lab password and is not stored in the repo. |

## Phase overview

The setup ran in five numbered steps. They are versioned in [`scripts/`](scripts/) as `step1-*.sh` … `step5c-trusts.sh`.

```text
Phase A — Clone tier1 + tier2 from the template
Phase B — Repurpose existing VMID 100 (demote → RAM 16 GB → hostname tier0 → reboot)
Phase C — Install-ADDSForest tier0.lab / tier1.lab / tier2.lab (in parallel)
Phase D — Set conditional DNS forwarders
Phase E — Bidirectional forest trusts via Forest::CreateTrustRelationship
```

## Phase A — Cloning (`step?-clone.sh`)

Linked clones from template 9000:

```bash
qm clone 9000 101 --name tier1
qm set 101 --memory 16384
qm clone 9000 102 --name tier2
qm set 102 --memory 16384
qm start 101
qm start 102
```

Notes:
- `--storage` is **not permitted** for linked clones from templates. The cloned VM automatically lands in the template's storage.
- `--memory 16384` sets RAM to 16 GiB. It is staged while running and takes effect on reboot — on freshly cloned, not yet started VMs it applies immediately.

## Phase B — Repurpose VMID 100 (`step2-reboot-rename.sh`)

VMID 100 was previously the PDC of the domain `testdomain.local`. It gets:

1. **Demoted** (`Uninstall-ADDSDomainController -LastDomainControllerInDomain`):
   - Omit `-RemoveDnsDelegation` if the domain has no parent zone. Otherwise: `The argument RemoveDNSDelegation=Yes is invalid`.
   - `-Credential <NetBIOS>\Administrator` is mandatory, otherwise `Verification of user credential permissions failed` — LocalSystem (qemu-guest-agent) cannot implicitly authenticate as a domain admin.
2. Rebooted via `qm shutdown` + `qm start`.
3. Set to 16 GiB RAM and renamed in the PVE inventory via `qm set 100 --memory 16384 --name tier0`.
4. Renamed in the guest via `Rename-Computer -NewName tier0`.
5. Rebooted again so the computer name applies.

Result snapshot:

```text
hostname: tier0
domain  : WORKGROUP
role    : 2 (standalone server)
adds    : Installed
ip      : 192.168.11.100/24
dns     : 127.0.0.1
```

## Phase C — Forest promotion (`step3-promote.sh` and `step3b-promote.sh`)

In parallel on all three DCs:

```powershell
Install-ADDSForest `
    -DomainName "tier0.lab" `        # tier1.lab / tier2.lab
    -DomainNetbiosName "T0LAB" `     # T1LAB / T2LAB
    -SafeModeAdministratorPassword $pw `
    -InstallDns `
    -CreateDnsDelegation:$false `
    -Force `
    -Confirm:$false `
    -NoRebootOnCompletion
```

### Important gotchas

1. **NetBIOS conflict hostname ↔ domain**: Hostname `tier0` and domain NetBIOS name `TIER0` produced `The NetBIOS name TIER0 is already in use.` Solution: use distinct domain NetBIOS names (`T0LAB`, `T1LAB`, `T2LAB`).
2. **Local Administrator password empty**: The template had no local admin password set. `Install-ADDSForest` rejects this (`local Administrator password is blank`). Solution before promote: `net user Administrator $LAB_ADMIN_PASSWORD`.
3. **Warnings are harmless**: "Allow cryptography algorithms compatible with Windows NT 4.0" (default security setting) and "DNS delegation cannot be created" (no parent zone).
4. **`-NoRebootOnCompletion`** controls when the reboot happens; otherwise the promote reboot kills the `qm guest exec` connection mid-run.

After the promote on each VM: `qm shutdown` + `qm start` for a clean transition into the DC state.

## Phase D — Conditional DNS forwarders (`step5b-trusts.sh`)

Cross-forest resolution only works if every DC can resolve the other domain names. On every DC, CFs to the other two domains are added:

```powershell
Add-DnsServerConditionalForwarderZone -Name "tier1.lab" -MasterServers "192.168.11.101" -ReplicationScope Forest
Add-DnsServerConditionalForwarderZone -Name "tier2.lab" -MasterServers "192.168.11.102" -ReplicationScope Forest
```

### Wait time

Right after the DC promote, `Get-ADDomain` is not yet responsive. Script `step5b` polls `Get-ADDomain -ErrorAction Stop` for up to five minutes and only then runs the CFs. Saves the `EXIT 1` pirouette from the first run.

## Phase E — Forest trusts (`step5c-trusts.sh`)

Via the .NET reflection API `[System.DirectoryServices.ActiveDirectory.Forest]`:

```powershell
$localCtx  = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest", "tier0.lab")
$local     = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($localCtx)
$remoteCtx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest", "tier1.lab", "T1LAB\Administrator", $env:LAB_ADMIN_PASSWORD)
$remote    = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($remoteCtx)
$local.CreateTrustRelationship($remote, [System.DirectoryServices.ActiveDirectory.TrustDirection]::Bidirectional)
```

Calls:

- `tier0.lab` → `tier1.lab` (on tier0)
- `tier1.lab` → `tier2.lab` (on tier1)
- `tier0.lab` → `tier2.lab` (on tier0)

`CreateTrustRelationship` writes both sides of the trust relationship in a single call. Bidirectional + Forest-transitive is the default.

### Why not netdom

`netdom trust ... /Twoway /ForestTransitive:yes` returned rc=87 ("parameter is incorrect"), both during creation and during verify. The Forest reflection API is more robust and gives more detailed error messages.

## Clean PowerShell hand-off via bash

`qm guest exec ... powershell -EncodedCommand` is the reliable hand-off for multi-line PowerShell scripts. The scripts are placed on the PVE host in a `/tmp/*.ps1` (single-quoted heredoc → no bash variable expansion), then encoded with `iconv -t UTF-16LE | base64 -w0` and passed. This eliminates all quote conflicts between PowerShell outer shell ↔ bash ↔ Windows cmd.

## Not in the script (manual before the run)

- Confirm the PVE host's hostkey on first connect / pass it to plink via `-hostkey SHA256:…`.
- Export `LAB_ADMIN_PASSWORD` as an environment variable or put it on the PVE host as `/root/.lab-env` (chmod 600).
