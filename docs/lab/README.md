# Stars — Test-Lab "Tri-Forest"

> **Read-only-Prinzip von Stars gilt unverändert.**
> Stars liest AD, NTFS und SMB. Das Lab existiert, um Stars gegen eine **bewusst komplexe** AD-Topologie zu testen. Stars verändert auch in diesem Lab nichts an Domain-Objekten, Berechtigungen oder Freigaben — die VMs hier sind Test-*Material*, kein Produktivziel.

## Zweck

Die Lab-Umgebung deckt Konstellationen ab, die ein einzelner DC nicht abbilden kann:

- Cross-Forest-SIDs und Foreign Security Principals
- mehrere unabhängige Schemata
- bidirektionale Forest-Trusts
- Conditional-DNS-Forwarder zwischen separaten Forests
- separate Domain-SIDs pro Forest (S-1-5-21-… verschieden je Tier)
- separate NetBIOS-Namen (T0LAB / T1LAB / T2LAB) zur Konflikt-Vermeidung

Damit lassen sich Pfad-Erklärungen, SID-Auflösung über Forest-Grenzen und das Verhalten bei nicht-auflösbaren Cross-Forest-SIDs realistisch prüfen.

## Topologie auf einen Blick

```text
        Proxmox VE 9.1.1  (Host 192.168.11.11)
        ────────────────────────────────────────
        │
        ├── VMID 100  tier0   192.168.11.100   Forest: tier0.lab  / NetBIOS: T0LAB
        ├── VMID 101  tier1   192.168.11.101   Forest: tier1.lab  / NetBIOS: T1LAB
        ├── VMID 102  tier2   192.168.11.102   Forest: tier2.lab  / NetBIOS: T2LAB
        └── VMID 9000 MS-Server-2022-Std       (Template, stopped)

Forest-Trusts (alle bidirektional, "Forest"-Trust-Typ):

        tier0.lab ⟷ tier1.lab
        tier1.lab ⟷ tier2.lab
        tier0.lab ⟷ tier2.lab
```

Mehr Details: [`forest-topology.md`](forest-topology.md).

## Inhalt dieses Ordners

| Datei | Inhalt |
|---|---|
| [`README.md`](README.md) | Diese Übersicht. |
| [`forest-topology.md`](forest-topology.md) | Forest- und VM-Daten, Trust-Matrix, IP-Plan, DNS-Forwarder. |
| [`setup-procedure.md`](setup-procedure.md) | Reproduzierbare Schrittfolge des Lab-Aufbaus inkl. behobener Stolpersteine. |
| [`verification.md`](verification.md) | Verifikationsergebnisse vom Build-Tag, mit PowerShell-Befehlen zum Nachprüfen. |
| [`scripts/`](scripts/) | Sanitized Bash-Skripte, die den Aufbau ausgeführt haben. **Lab-Default-Passwort steht nicht im Repo** und wird beim Lauf als Umgebungsvariable übergeben. |

## Sicherheits-Hinweise

- Die VMs sind ausschließlich für **lokale Tests** in einem isolierten Netz (192.168.11.0/24) bestimmt.
- Lab-Default-Passwort wird **niemals** in dieses Repository committet. Es lebt nur in der lokalen Entwicklungsumgebung des Betreibers.
- Forest-Trusts sind bewusst ohne SID-Filtering / Quarantine konfiguriert, weil das Lab maximale Test-Sichtbarkeit produzieren soll. Für Produktion gilt das Gegenteil.
- Die Test-VMs dürfen niemals in Produktionsnetzen erreichbar werden.

## Stars-spezifische Test-Use-Cases, die das Lab abdeckt

| Use-Case | Voraussetzung | Wo abgebildet |
|---|---|---|
| AD-Recursive-Gruppe innerhalb eines Forests | mind. ein Forest mit ≥ 2 verschachtelten Gruppen | tier0.lab (Default-Gruppen genügen für ersten Smoke-Test) |
| Foreign Security Principal (Cross-Forest-SID auf ACE) | Trust + Test-User in Quell-Forest, FSP-ACE in Ziel-Forest | tier0.lab ⟷ tier1.lab |
| Cross-Forest-Trust mit getrennten Schemas | 2 unabhängige Forests | tier0.lab ⟷ tier2.lab |
| Lokale Gruppen-Mediator-Erklärung (Finding 1) | mind. ein Member-Server / DC mit lokalen Gruppen | jeder DC hat BUILTIN-Gruppen |

Konkrete Testdaten-Bestückung (Testbenutzer, Gruppenverschachtelung, ACEs auf Test-Pfade) folgt separat.
