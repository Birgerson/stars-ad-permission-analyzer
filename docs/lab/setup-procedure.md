# Lab-Aufbau — reproduzierbare Schrittfolge

> Reproduktion durch eine zweite Person sollte ausschließlich aus dieser Datei plus den Skripten unter [`scripts/`](scripts/) möglich sein. Alle Stolpersteine sind hier dokumentiert, damit sich niemand zweimal an denselben Quoting- oder Prerequisite-Problemen abarbeitet.

## Voraussetzungen

| Item | Beschaffenheit |
|------|----------------|
| Proxmox VE | 9.1.1 oder neuer |
| Template-VM | Windows Server 2022 Standard (im hier dokumentierten Lab: VMID 9000, Name `MS-Server-2022-Std`, mit aktivem qemu-guest-agent und Default-Local-Administrator ohne Passwort) |
| Storage | mindestens 3 × 101 GB frei für die Klone (linked clones referenzieren das Template, sind aber bei Schreiben dünn → Plattenplatz wächst über die Lebensdauer) |
| Bridge | `vmbr0` mit Routing zu 192.168.11.0/24 |
| Admin-Tools auf dem Steuer-Host | `plink`/`pscp` (PuTTY-Suite) oder OpenSSH-Client, dazu `bash` (Git-Bash o.Ä.) für die Skripte. Die Skripte unter [`scripts/`](scripts/) werden auf dem **PVE-Host** ausgeführt, nicht auf dem Steuer-Rechner. |
| Lab-Default-Passwort | Eine Umgebungsvariable `LAB_ADMIN_PASSWORD` muss beim Lauf der Skripte gesetzt sein. Sie ersetzt das frühere hartkodierte Lab-Passwort und wird nicht im Repo abgelegt. |

## Phasen-Übersicht

Der Aufbau lief in fünf nummerierten Schritten. Sie sind in [`scripts/`](scripts/) als `step1-*.sh` … `step5c-trusts.sh` versioniert.

```text
Phase A — Klonen tier1 + tier2 vom Template
Phase B — Bestehende VMID 100 umwidmen (Demote → RAM 16 GB → Hostname tier0 → Reboot)
Phase C — Install-ADDSForest tier0.lab / tier1.lab / tier2.lab (parallel)
Phase D — Conditional DNS Forwarders setzen
Phase E — Bidirektionale Forest-Trusts via Forest::CreateTrustRelationship
```

## Phase A — Klonen (`step?-clone.sh`)

Linked Clones aus Template 9000:

```bash
qm clone 9000 101 --name tier1
qm set 101 --memory 16384
qm clone 9000 102 --name tier2
qm set 102 --memory 16384
qm start 101
qm start 102
```

Hinweise:
- `--storage` ist **nicht erlaubt** bei Linked Clones aus Templates. Die geklonte VM landet automatisch im Storage des Templates.
- `--memory 16384` setzt RAM auf 16 GiB. Wird im laufenden Zustand vorgehalten, wirksam nach Reboot — bei frisch geklonten, noch nicht gestarteten VMs sofort wirksam.

## Phase B — VMID 100 umwidmen (`step2-reboot-rename.sh`)

VMID 100 war zuvor PDC der Domain `testdomain.local`. Sie wird:

1. **Demoted** (`Uninstall-ADDSDomainController -LastDomainControllerInDomain`):
   - `-RemoveDnsDelegation` weglassen, wenn die Domain keine Eltern-Zone besitzt. Sonst: `The argument RemoveDNSDelegation=Yes is invalid`.
   - `-Credential <NetBIOS>\Administrator` ist Pflicht, sonst `Verification of user credential permissions failed` — LocalSystem (qemu-guest-agent) kann sich nicht implizit als Domain-Admin authentifizieren.
2. Über `qm shutdown` + `qm start` rebootet.
3. Über `qm set 100 --memory 16384 --name tier0` auf 16 GiB RAM gestellt und in der PVE-Inventar umbenannt.
4. Im Gast über `Rename-Computer -NewName tier0` umbenannt.
5. Erneut rebootet, damit der Computer-Name gilt.

Ergebnis-Snapshot:

```text
hostname: tier0
domain  : WORKGROUP
role    : 2 (standalone server)
adds    : Installed
ip      : 192.168.11.100/24
dns     : 127.0.0.1
```

## Phase C — Forest-Promotion (`step3-promote.sh` und `step3b-promote.sh`)

Auf allen drei DCs parallel:

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

### Wichtige Stolpersteine

1. **NetBIOS-Konflikt Hostname ↔ Domain**: Hostname `tier0` und Domain-NetBIOS-Name `TIER0` führten zu `The NetBIOS name TIER0 is already in use.` Lösung: Domain-NetBIOS-Namen unterscheiden (`T0LAB`, `T1LAB`, `T2LAB`).
2. **Local-Administrator-Passwort leer**: Das Template hatte kein Local-Admin-Passwort gesetzt. `Install-ADDSForest` lehnt das ab (`local Administrator password is blank`). Lösung vor Promote: `net user Administrator $LAB_ADMIN_PASSWORD`.
3. **Warnungen sind harmlos**: "Allow cryptography algorithms compatible with Windows NT 4.0" (Default Security-Setting) und "DNS delegation cannot be created" (keine Eltern-Zone).
4. **`-NoRebootOnCompletion`** kontrolliert wann Reboot passiert, sonst killt der Promote-Reboot die `qm guest exec`-Verbindung mitten im Lauf.

Nach Promote auf jeder VM: `qm shutdown` + `qm start` für sauberen Übergang in den DC-Zustand.

## Phase D — Conditional DNS Forwarders (`step5b-trusts.sh`)

Cross-Forest-Resolution funktioniert nur, wenn jeder DC die anderen Domain-Namen auflösen kann. Auf jedem DC werden CFs zu den jeweils anderen beiden Domains gesetzt:

```powershell
Add-DnsServerConditionalForwarderZone -Name "tier1.lab" -MasterServers "192.168.11.101" -ReplicationScope Forest
Add-DnsServerConditionalForwarderZone -Name "tier2.lab" -MasterServers "192.168.11.102" -ReplicationScope Forest
```

### Wartezeit

Direkt nach DC-Promote ist `Get-ADDomain` noch nicht responsiv. Skript `step5b` pollt mit `Get-ADDomain -ErrorAction Stop` bis zu 5 Minuten und führt CFs erst dann aus. Erspart die `EXIT 1`-Pirouette aus dem ersten Anlauf.

## Phase E — Forest-Trusts (`step5c-trusts.sh`)

Über die .NET-Reflection-API `[System.DirectoryServices.ActiveDirectory.Forest]`:

```powershell
$localCtx  = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest", "tier0.lab")
$local     = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($localCtx)
$remoteCtx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest", "tier1.lab", "T1LAB\Administrator", $env:LAB_ADMIN_PASSWORD)
$remote    = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($remoteCtx)
$local.CreateTrustRelationship($remote, [System.DirectoryServices.ActiveDirectory.TrustDirection]::Bidirectional)
```

Aufrufe:

- `tier0.lab` → `tier1.lab` (auf tier0)
- `tier1.lab` → `tier2.lab` (auf tier1)
- `tier0.lab` → `tier2.lab` (auf tier0)

`CreateTrustRelationship` schreibt beide Seiten der Trust-Beziehung in einem Aufruf. Bidirectional + Forest-Transitiv ist der Default.

### Warum nicht netdom

`netdom trust ... /Twoway /ForestTransitive:yes` lieferte rc=87 ("parameter is incorrect"), sowohl beim Anlegen als auch beim Verify. Die Forest-Reflection-API ist robuster und gibt detailliertere Fehlermeldungen.

## Saubere PowerShell-Übergabe via Bash

`qm guest exec ... powershell -EncodedCommand` ist die zuverlässige Übergabe für mehrzeilige PowerShell-Skripte. Die Skripte werden auf dem PVE-Host in einer `/tmp/*.ps1` abgelegt (single-quoted Heredoc → keine Bash-Variablen-Expansion), dann mit `iconv -t UTF-16LE | base64 -w0` encoded und übergeben. So entfallen alle Quote-Konflikte zwischen PowerShell-Outer-Shell ↔ Bash ↔ Windows-cmd.

## Was nicht im Skript steht (manuell vor dem Lauf)

- Hostkey-Eintrag des PVE-Hosts beim ersten Verbinden bestätigen / per `-hostkey SHA256:…` an plink durchreichen.
- `LAB_ADMIN_PASSWORD` als Umgebungsvariable exportieren oder im PVE-Host als `/root/.lab-env` ablegen (chmod 600).
