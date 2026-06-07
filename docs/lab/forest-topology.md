# Forest Topology

State of the lab setup as captured on build day. Values from `Get-ADDomain` / `Get-ADForest` / `qm config`.

## VM data (Proxmox)

| VMID | Name | Bridge | MAC | Cores | RAM | Boot disk | Storage |
|------|------|--------|-----|-------|-----|-----------|---------|
| 100 | tier0 | vmbr0 | bc:24:11:7f:c0:c0 | 8 | 16 GiB | 101 GB (linked clone of 9000) | nvme0-VMs |
| 101 | tier1 | vmbr0 | bc:24:11:48:1b:f7 | 8 | 16 GiB | 101 GB (linked clone of 9000) | nvme0-VMs |
| 102 | tier2 | vmbr0 | bc:24:11:22:32:0c | 8 | 16 GiB | 101 GB (linked clone of 9000) | nvme0-VMs |
| 9000 | MS-Server-2022-Std | vmbr0 | bc:24:11:ae:a9:3d | 8 | 32 GiB | 101 GB | nvme0-VMs (template) |

Further PVE settings (all three DCs identical, inherited from template 9000):

- `bios: ovmf`, `machine: q35` (tier0) or `pc-i440fx-10.1` (tier1/tier2)
- `agent: 1` (qemu-guest-agent — needed for the entire automation)
- `scsihw: virtio-scsi-single`, `cpu: x86-64-v2-AES`
- `virtio0` with `aio=io_uring, cache=directsync, discard=on, iothread=1`
- TPM 2.0 (`tpmstate0`)

## OS

All three DCs:

- Microsoft Windows Server 2022 Standard
- Build 20348
- Static IPv4, DNS pointing at themselves (127.0.0.1)

## Domains / forests

| VMID | Hostname | IP | Domain (DNS root) | NetBIOS | Domain mode | Forest mode | Domain SID |
|------|----------|----|--------------------|---------|--------------|--------------|------------|
| 100 | tier0 | 192.168.11.100 | tier0.lab | T0LAB | Windows2016Domain | Windows2016Forest | S-1-5-21-82128098-3850859968-3663624259 |
| 101 | tier1 | 192.168.11.101 | tier1.lab | T1LAB | Windows2016Domain | Windows2016Forest | S-1-5-21-2422202677-580894712-1536135282 |
| 102 | tier2 | 192.168.11.102 | tier2.lab | T2LAB | Windows2016Domain | Windows2016Forest | S-1-5-21-2422907361-2909490334-1284861871 |

Each DC holds the FSMO roles Schema Master and Domain Naming Master in its own forest.

### Why separate NetBIOS names (T0LAB instead of TIER0)?

Hostname and domain NetBIOS name must not coincide. Hostname `tier0` and domain NetBIOS name `TIER0` were rejected by the promotion check as a conflict (`NetBIOS name TIER0 is already in use`). Solution: shorter, different NetBIOS names (`T0LAB`, `T1LAB`, `T2LAB`).

## Conditional DNS forwarders (CF)

Each DC is the DNS server for its own domain. To enable cross-forest resolution, every DC holds two conditional forwarders pointing at the other two DCs:

```text
tier0 (192.168.11.100) holds CF:
    tier1.lab -> 192.168.11.101
    tier2.lab -> 192.168.11.102

tier1 (192.168.11.101) holds CF:
    tier0.lab -> 192.168.11.100
    tier2.lab -> 192.168.11.102

tier2 (192.168.11.102) holds CF:
    tier0.lab -> 192.168.11.100
    tier1.lab -> 192.168.11.101
```

ReplicationScope is `Forest` (standard recommendation for AD-integrated CFs).

## Forest trusts

Three bidirectional forest trusts form a fully meshed trust net:

```text
              tier0.lab
              /        \
   Bidir/Forest    Bidir/Forest
            /            \
       tier1.lab ── Bidir/Forest ── tier2.lab
```

Enumeration via `[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().GetAllTrustRelationships()`:

| Local forest | Trust to | Direction | Type |
|----------------|----------|-----------|------|
| tier0.lab | tier1.lab | Bidirectional | Forest |
| tier0.lab | tier2.lab | Bidirectional | Forest |
| tier1.lab | tier0.lab | Bidirectional | Forest |
| tier1.lab | tier2.lab | Bidirectional | Forest |
| tier2.lab | tier0.lab | Bidirectional | Forest |
| tier2.lab | tier1.lab | Bidirectional | Forest |

No SID filtering, no quarantine — the test lab is allowed to be maximally visible.

## Known peculiarities

- `netdom trust ... /Verify /Quiet` returns `rc=87` ("syntax incorrect") on all three DCs. The trusts exist nevertheless (the Forest reflection API lists them). Verify can be run interactively without `/Quiet`, but that was not required for the automation.
- `Install-ADDSForest` warns twice per promotion:
  1. "Allow cryptography algorithms compatible with Windows NT 4.0" — default security setting on 2022, harmless.
  2. "A delegation for this DNS server cannot be created because the authoritative parent zone cannot be found" — expected, because `.lab` has no real DNS parent zone.
