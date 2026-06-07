# Stars — Test Lab "Tri-Forest"

> **Stars' read-only principle applies unchanged.**
> Stars reads AD, NTFS, and SMB. The lab exists so we can test Stars against a **deliberately complex** AD topology. Even in the lab Stars changes nothing on domain objects, permissions, or shares — the VMs here are test *material*, not a production target.

## Purpose

The lab environment covers constellations a single DC cannot represent:

- Cross-forest SIDs and Foreign Security Principals
- Multiple independent schemas
- Bidirectional forest trusts
- Conditional DNS forwarders between separate forests
- Separate domain SIDs per forest (S-1-5-21-… differs per tier)
- Separate NetBIOS names (T0LAB / T1LAB / T2LAB) to avoid conflicts

That makes it possible to realistically check path explanations, SID resolution across forest boundaries, and behaviour on unresolvable cross-forest SIDs.

## Topology at a glance

```text
        Proxmox VE 9.1.1  (host 192.168.11.11)
        ────────────────────────────────────────
        │
        ├── VMID 100  tier0   192.168.11.100   Forest: tier0.lab  / NetBIOS: T0LAB
        ├── VMID 101  tier1   192.168.11.101   Forest: tier1.lab  / NetBIOS: T1LAB
        ├── VMID 102  tier2   192.168.11.102   Forest: tier2.lab  / NetBIOS: T2LAB
        └── VMID 9000 MS-Server-2022-Std       (template, stopped)

Forest trusts (all bidirectional, "Forest" trust type):

        tier0.lab ⟷ tier1.lab
        tier1.lab ⟷ tier2.lab
        tier0.lab ⟷ tier2.lab
```

More details: [`forest-topology.md`](forest-topology.md).

## Contents of this folder

| File | Content |
|---|---|
| [`README.md`](README.md) | This overview. |
| [`forest-topology.md`](forest-topology.md) | Forest and VM data, trust matrix, IP plan, DNS forwarders. |
| [`setup-procedure.md`](setup-procedure.md) | Reproducible step sequence of the lab setup, including fixed gotchas. |
| [`verification.md`](verification.md) | Verification results from build day, with PowerShell commands to re-check. |
| [`scripts/`](scripts/) | Sanitized bash scripts that performed the setup. **The lab default password is not in the repo** and is passed at runtime as an environment variable. |

## Security notes

- The VMs are only meant for **local tests** in an isolated network (192.168.11.0/24).
- The lab default password is **never** committed to this repository. It lives only in the maintainer's local development environment.
- Forest trusts are deliberately configured without SID filtering / quarantine because the lab is meant to produce maximum test visibility. The opposite applies in production.
- The test VMs must never become reachable from production networks.

## Stars-specific test use cases covered by the lab

| Use case | Prerequisite | Where covered |
|---|---|---|
| AD recursive group inside a single forest | at least one forest with ≥ 2 nested groups | tier0.lab (default groups suffice for an initial smoke test) |
| Foreign Security Principal (cross-forest SID on an ACE) | trust + test user in the source forest, FSP ACE in the target forest | tier0.lab ⟷ tier1.lab |
| Cross-forest trust with separate schemas | 2 independent forests | tier0.lab ⟷ tier2.lab |
| Local-group mediator explanation (finding 1) | at least one member server / DC with local groups | every DC has BUILTIN groups |

Concrete test-data population (test users, group nesting, ACEs on test paths) follows separately.
