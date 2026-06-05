# Forest-Topologie

Stand des Lab-Aufbaus, festgehalten am Build-Tag. Werte aus `Get-ADDomain` / `Get-ADForest` / `qm config`.

## VM-Daten (Proxmox)

| VMID | Name | Bridge | MAC | Cores | RAM | Boot-Disk | Storage |
|------|------|--------|-----|-------|-----|-----------|---------|
| 100 | tier0 | vmbr0 | bc:24:11:7f:c0:c0 | 8 | 16 GiB | 101 GB (linked clone v. 9000) | nvme0-VMs |
| 101 | tier1 | vmbr0 | bc:24:11:48:1b:f7 | 8 | 16 GiB | 101 GB (linked clone v. 9000) | nvme0-VMs |
| 102 | tier2 | vmbr0 | bc:24:11:22:32:0c | 8 | 16 GiB | 101 GB (linked clone v. 9000) | nvme0-VMs |
| 9000 | MS-Server-2022-Std | vmbr0 | bc:24:11:ae:a9:3d | 8 | 32 GiB | 101 GB | nvme0-VMs (Template) |

Weitere PVE-Settings (alle 3 DCs identisch, geerbt vom Template 9000):

- `bios: ovmf`, `machine: q35` (tier0) bzw. `pc-i440fx-10.1` (tier1/tier2)
- `agent: 1` (qemu-guest-agent — wird für gesamte Automatisierung gebraucht)
- `scsihw: virtio-scsi-single`, `cpu: x86-64-v2-AES`
- `virtio0` mit `aio=io_uring, cache=directsync, discard=on, iothread=1`
- TPM 2.0 (`tpmstate0`)

## OS

Alle drei DCs:

- Microsoft Windows Server 2022 Standard
- Build 20348
- Static IPv4, DNS auf sich selbst (127.0.0.1)

## Domains / Forests

| VMID | Hostname | IP | Domain (DNS-Root) | NetBIOS | Domain-Mode | Forest-Mode | Domain-SID |
|------|----------|----|--------------------|---------|--------------|--------------|------------|
| 100 | tier0 | 192.168.11.100 | tier0.lab | T0LAB | Windows2016Domain | Windows2016Forest | S-1-5-21-82128098-3850859968-3663624259 |
| 101 | tier1 | 192.168.11.101 | tier1.lab | T1LAB | Windows2016Domain | Windows2016Forest | S-1-5-21-2422202677-580894712-1536135282 |
| 102 | tier2 | 192.168.11.102 | tier2.lab | T2LAB | Windows2016Domain | Windows2016Forest | S-1-5-21-2422907361-2909490334-1284861871 |

Jeder DC hält in seinem Forest die FSMO-Rollen Schema-Master und Domain-Naming-Master.

### Warum getrennte NetBIOS-Namen (T0LAB statt TIER0)?

Hostname und Domain-NetBIOS-Name dürfen sich nicht decken. `tier0`-Hostname und Domain-NetBIOS-Name `TIER0` wurden vom Promotion-Check als Konflikt zurückgewiesen (`NetBIOS name TIER0 is already in use`). Lösung: kürzere, andere NetBIOS-Namen (`T0LAB`, `T1LAB`, `T2LAB`).

## Conditional DNS Forwarder (CF)

Jeder DC ist DNS-Server für seine eigene Domain. Damit Cross-Forest-Resolution möglich ist, hält jeder DC zwei Conditional Forwarder auf die jeweils anderen beiden DCs:

```text
tier0 (192.168.11.100) hält CF:
    tier1.lab -> 192.168.11.101
    tier2.lab -> 192.168.11.102

tier1 (192.168.11.101) hält CF:
    tier0.lab -> 192.168.11.100
    tier2.lab -> 192.168.11.102

tier2 (192.168.11.102) hält CF:
    tier0.lab -> 192.168.11.100
    tier1.lab -> 192.168.11.101
```

ReplicationScope ist `Forest` (Standardempfehlung für AD-integrierte CFs).

## Forest-Trusts

Drei bidirektionale Forest-Trusts bilden ein vollvermaschtes Trust-Netz:

```text
              tier0.lab
              /        \
   Bidir/Forest    Bidir/Forest
            /            \
       tier1.lab ── Bidir/Forest ── tier2.lab
```

Auflistung über `[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().GetAllTrustRelationships()`:

| Lokaler Forest | Trust zu | Direction | Type |
|----------------|----------|-----------|------|
| tier0.lab | tier1.lab | Bidirectional | Forest |
| tier0.lab | tier2.lab | Bidirectional | Forest |
| tier1.lab | tier0.lab | Bidirectional | Forest |
| tier1.lab | tier2.lab | Bidirectional | Forest |
| tier2.lab | tier0.lab | Bidirectional | Forest |
| tier2.lab | tier1.lab | Bidirectional | Forest |

Kein SID-Filtering, keine Quarantine — Test-Lab darf maximal sichtbar sein.

## Bekannte Auffälligkeiten

- `netdom trust ... /Verify /Quiet` liefert auf allen drei DCs `rc=87` ("syntax incorrect"). Die Trusts existieren trotzdem (Forest-Reflection-API listet sie). Verify lässt sich ohne `/Quiet` interaktiv ausführen, das war für die Automatisierung aber nicht notwendig.
- `Install-ADDSForest` warnt zweimal pro Promotion:
  1. "Allow cryptography algorithms compatible with Windows NT 4.0" — Default-Security-Setting auf 2022, harmlos.
  2. "A delegation for this DNS server cannot be created because the authoritative parent zone cannot be found" — erwartet, weil `.lab` keine echte DNS-Eltern-Zone besitzt.
