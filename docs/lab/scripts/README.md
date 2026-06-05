# Lab-Aufbau-Skripte

Diese Bash-Skripte werden **auf dem Proxmox-Host** ausgeführt (per SSH oder PVE-Shell), nicht im Gast und nicht auf dem Steuer-Rechner. Sie benutzen `qm clone`, `qm guest exec` und PowerShell-Encoded-Commands, um die Lab-VMs aufzubauen.

## Voraussetzungen

- PVE 9.1.1+ mit qemu-guest-agent in den Windows-VMs
- Template-VM existiert (in diesem Lab: VMID 9000, Windows Server 2022 Standard)
- Umgebungsvariable `LAB_ADMIN_PASSWORD` muss gesetzt sein — sie wird in jedem Skript verwendet und **darf nicht im Repo landen**. Beispiel:

  ```bash
  export LAB_ADMIN_PASSWORD='your-lab-password'
  bash 03-promote-forests.sh
  ```

## Skripte in Reihenfolge

| # | Skript | Wirkung |
|---|---|---|
| 1 | [`01-clone-templates.sh`](01-clone-templates.sh) | Klont 2 weitere Lab-VMs aus dem Template (linked clones, 16 GiB RAM). Existierende VMID 100 wird hier nicht angefasst — die Umwidmung ist in [`setup-procedure.md`](../setup-procedure.md) als Phase B beschrieben und Lab-spezifisch. |
| 2 | [`02-prepare-vms.sh`](02-prepare-vms.sh) | Setzt statische IP, DNS=127.0.0.1, Hostname und installiert AD-DS-Feature in allen geklonten VMs. Setzt das Local-Admin-Passwort (das Template hat keins). |
| 3 | [`03-promote-forests.sh`](03-promote-forests.sh) | Parallel `Install-ADDSForest` auf allen drei DCs (separate Forests, eigene NetBIOS-Namen). `-NoRebootOnCompletion` damit der Reboot kontrolliert von außen kommt. |
| 4 | [`04-reboot-and-wait.sh`](04-reboot-and-wait.sh) | Reboot aller drei VMs nach Promote und wartet, bis `Get-ADDomain` antwortet. |
| 5 | [`05-conditional-forwarders.sh`](05-conditional-forwarders.sh) | Setzt Conditional Forwarder zwischen allen drei Forests. |
| 6 | [`06-forest-trusts.sh`](06-forest-trusts.sh) | Bidirektionale Forest-Trusts via `Forest.CreateTrustRelationship`. |
| 7 | [`07-testdata.sh`](07-testdata.sh) | Test-OUs, Test-User (alice/bob/carol), verschachtelte Gruppen, Test-ACL inkl. Cross-Forest-FSP-ACE. |
| 8 | [`08-stars-smoke.sh`](08-stars-smoke.sh) | Führt drei Stars-CLI-Smoke-Tests gegen das Lab aus. Voraussetzung: `C:\Stars\adpa.exe` existiert auf VMID 100 (siehe [`verification.md`](../verification.md)). |
| 9 | [`09-blockA-edge-cases.sh`](09-blockA-edge-cases.sh) | Block A (v1.5.7) — legt drei Edge-Case-Fixtures an (Deny-ACE, Protect-Inheritance, SMB-Share mit restriktiver Share-Permission) und prüft Stars-CLI dagegen. |
| 10 | [`10-blockB-gui-smoke.sh`](10-blockB-gui-smoke.sh) | Block B (v1.5.7) — startet `adpa-gui.exe` auf tier0 für 15 s und prüft, dass Slint + winit-software auf VirtIO-GPU sauber bootet und sich beenden lässt. Voraussetzung: `C:\Stars\adpa-gui.exe`. |

## Skripte sind kein Production-Code

Diese Skripte sind so geschrieben, dass eine zweite Person das Lab in unter 30 Minuten reproduzieren kann. Sie sind nicht für Produktivumgebungen gedacht: kein TLS, kein Logging in zentrale Quelle, kein Rollback. Wer das Setup nach-baut, übernimmt Verantwortung für eine isolierte Test-Netz-Umgebung.
