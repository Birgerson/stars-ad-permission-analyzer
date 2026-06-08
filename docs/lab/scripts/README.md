# Lab setup scripts

These bash scripts run **on the Proxmox host** (via SSH or the PVE shell), not in the guest and not on the control machine. They use `qm clone`, `qm guest exec`, and PowerShell encoded commands to bring up the lab VMs.

## Prerequisites

- PVE 9.1.1+ with qemu-guest-agent in the Windows VMs
- Template VM exists (in this lab: VMID 9000, Windows Server 2022 Standard)
- Environment variable `LAB_ADMIN_PASSWORD` must be set — it is used in every script and **must not land in the repo**. Example:

  ```bash
  export LAB_ADMIN_PASSWORD='your-lab-password'
  bash 03-promote-forests.sh
  ```

## Scripts in order

| # | Script | Effect |
|---|---|---|
| 1 | [`01-clone-templates.sh`](01-clone-templates.sh) | Clones 2 more lab VMs from the template (linked clones, 16 GiB RAM). Existing VMID 100 is not touched here — the repurposing is described in [`setup-procedure.md`](../setup-procedure.md) as phase B and is lab-specific. |
| 2 | [`02-prepare-vms.sh`](02-prepare-vms.sh) | Sets static IP, DNS=127.0.0.1, hostname, and installs the AD DS feature in every cloned VM. Sets the local-admin password (the template has none). |
| 3 | [`03-promote-forests.sh`](03-promote-forests.sh) | Parallel `Install-ADDSForest` on all three DCs (separate forests, distinct NetBIOS names). `-NoRebootOnCompletion` so the reboot is driven from outside in a controlled manner. |
| 4 | [`04-reboot-and-wait.sh`](04-reboot-and-wait.sh) | Reboot of all three VMs after promotion and wait until `Get-ADDomain` responds. |
| 5 | [`05-conditional-forwarders.sh`](05-conditional-forwarders.sh) | Configures conditional forwarders between all three forests. |
| 6 | [`06-forest-trusts.sh`](06-forest-trusts.sh) | Bidirectional forest trusts via `Forest.CreateTrustRelationship`. |
| 7 | [`07-testdata.sh`](07-testdata.sh) | Test OUs, test users (alice/bob/carol), nested groups, test ACL including a cross-forest FSP ACE. |
| 8 | [`08-stars-smoke.sh`](08-stars-smoke.sh) | Runs three Stars CLI smoke tests against the lab. Requires `C:\Stars\adpa.exe` to exist on VMID 100 (see [`verification.md`](../verification.md)). |
| 9 | [`09-blockA-edge-cases.sh`](09-blockA-edge-cases.sh) | Block A (v1.5.7) — creates three edge-case fixtures (Deny ACE, protected inheritance, SMB share with a restrictive share permission) and runs Stars CLI against them. |
| 10 | [`10-blockB-gui-smoke.sh`](10-blockB-gui-smoke.sh) | Block B (v1.5.7) — starts `adpa-gui.exe` on tier0 for 15 s and verifies that Slint + winit-software boots cleanly on VirtIO-GPU and exits cleanly. Requires `C:\Stars\adpa-gui.exe`. |
| 11 | [`11-blockC-ad-bulk.sh`](11-blockC-ad-bulk.sh) | Block C.1 (v1.5.8) — creates OUs, 20 security groups per forest and 1000 users (`max.mustermann0001..1000`) across the three forests, with 3-level nesting (user → sub-team → department). |
| 12 | [`12-blockC-dirs-acls.sh`](12-blockC-dirs-acls.sh) | Block C.2/C.3 (v1.5.8) — creates 5000 folders on tier0 (`C:\Data\<Dept>\<Project>\<Folder>`) and sets 100 project ACLs with deliberate variation (standard, protected inheritance, Deny). |
| 13 | [`13-blockC-stars-perf.sh`](13-blockC-stars-perf.sh) | Block C.4 (v1.5.8) — Stars performance benchmark: `scan` over the 5105 folders with live LDAP resolution, plus an `analyze` call for a comparison value. |
| 14 | [`14-blockD-network-context.sh`](14-blockD-network-context.sh) | Block D (v1.5.9) — round-7 finding 1: a local path + `--smb-server`/`--share-name` must include NETWORK in the token. Three Stars invocations (local without hint / local with hint / UNC) verify the end-to-end behaviour. |

## These scripts are not production code

They are written so a second person can reproduce the lab in under 30 minutes. They are not meant for production environments: no TLS, no centralized logging, no rollback. Anyone rebuilding the setup takes responsibility for an isolated test network.
