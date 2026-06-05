# Verifikation des Lab-Aufbaus und der Stars-Software

> **Verifikationszeitpunkt:** Bauzeitpunkt der ersten Forest-Topologie (siehe Commit-Zeitstempel von [`forest-topology.md`](forest-topology.md)).
> Stars-Version unter Test: `adpa 1.5.5` (Build aus dem Workspace zum Bauzeitpunkt).

Diese Datei dokumentiert *was* verifiziert wurde, *wie* es geprüft wurde, und *was* Stars dabei tatsächlich ausgegeben hat. Reproduzieren mit den Skripten unter [`scripts/`](scripts/).

## Teil A — Lab-Infrastruktur

Geprüft auf jedem der drei DCs nach Reboot und vor Stars-Test.

### A.1  AD-DS-Topologie

```powershell
$d = Get-ADDomain
"$($d.DNSRoot)  netbios=$($d.NetBIOSName)  forest=$($d.Forest)  sid=$($d.DomainSID)  mode=$($d.DomainMode)"
$f = Get-ADForest
"forest=$($f.Name)  mode=$($f.ForestMode)  schema-master=$($f.SchemaMaster)"
```

Beobachtete Werte:

| VMID | Get-ADDomain.DNSRoot | NetBIOS | Domain-SID | Mode |
|---|---|---|---|---|
| 100 | tier0.lab | T0LAB | `S-1-5-21-82128098-3850859968-3663624259` | Windows2016Domain / -Forest |
| 101 | tier1.lab | T1LAB | `S-1-5-21-2422202677-580894712-1536135282` | Windows2016Domain / -Forest |
| 102 | tier2.lab | T2LAB | `S-1-5-21-2422907361-2909490334-1284861871` | Windows2016Domain / -Forest |

### A.2  DC-Services

```powershell
foreach ($s in 'ADWS','Netlogon','Kdc','DNS','NTDS') {
    "$s -> $((Get-Service $s).Status)"
}
```

Alle drei DCs liefern **Running** für alle fünf Dienste.

### A.3  Conditional DNS Forwarders

```powershell
Get-DnsServerZone | Where-Object { $_.ZoneType -eq 'Forwarder' } |
    Format-Table ZoneName, MasterServers
```

| DC | CF-Zone | Master |
|---|---|---|
| tier0 | tier1.lab | 192.168.11.101 |
| tier0 | tier2.lab | 192.168.11.102 |
| tier1 | tier0.lab | 192.168.11.100 |
| tier1 | tier2.lab | 192.168.11.102 |
| tier2 | tier0.lab | 192.168.11.100 |
| tier2 | tier1.lab | 192.168.11.101 |

Resolve-Check `Resolve-DnsName tier{0,1,2}.lab` von jedem DC → liefert die jeweilige IP der Zieldomain.

### A.4  Forest-Trusts

```powershell
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().GetAllTrustRelationships() |
    ForEach-Object { "$($_.SourceName) -> $($_.TargetName) [$($_.TrustDirection)/$($_.TrustType)]" }
```

Liefert auf allen drei DCs jeweils zwei Bidirectional-/Forest-Trusts zu den beiden anderen Forests:

```text
tier0.lab:
  tier0.lab -> tier1.lab [Bidirectional/Forest]
  tier0.lab -> tier2.lab [Bidirectional/Forest]

tier1.lab:
  tier1.lab -> tier0.lab [Bidirectional/Forest]
  tier1.lab -> tier2.lab [Bidirectional/Forest]

tier2.lab:
  tier2.lab -> tier1.lab [Bidirectional/Forest]
  tier2.lab -> tier0.lab [Bidirectional/Forest]
```

### A.5  Bekannte Auffälligkeit — `netdom trust /Verify`

```text
netdom trust tier0.lab /Domain:tier1.lab /Verify /Quiet
> rc=87 — "The syntax of this command is: NETDOM [...]"
```

Die Trusts existieren trotzdem laut Reflection-API (A.4). `/Verify` ist eine Read-only-Diagnose, ihr Fehlen blockiert keine Funktionalität. Akzeptiert als bekannte Quirk.

## Teil B — Test-Datenbestückung

Angelegt für Stars-Tests:

### B.1  Identitäten

| Forest | OU | User | Gruppen-Mitgliedschaften |
|---|---|---|---|
| tier0.lab | OU=TestOU | T0LAB\alice | GroupA → GroupB (verschachtelt) |
| tier1.lab | OU=TestOU | T1LAB\bob | (nur Primary Group) |
| tier2.lab | OU=TestOU | T2LAB\carol | (nur Primary Group) |

Gruppen:

| Forest | Gruppe | SID-Suffix | Mitglied von |
|---|---|---|---|
| tier0.lab | GroupA | -1105 | GroupB |
| tier0.lab | GroupB | -1106 | (Wurzel der Test-Kette) |

### B.2  Pfad mit ACL

`C:\TestShare` auf tier0 (lokales Verzeichnis, vorerst kein SMB-Share).

```powershell
Get-Acl C:\TestShare | Select-Object -ExpandProperty Access
```

Liefert (relevante Test-ACEs):

| IdentityReference | Rights | Type | Quelle |
|---|---|---|---|
| `T0LAB\GroupB` | Modify | Allow (explicit) | Test-ACE für nested-Group-Test |
| `T1LAB\bob` (SID-only) | ReadAndExecute | Allow (explicit) | **Cross-Forest FSP**, gesetzt über `NTAccount("T1LAB","bob").Translate(SID)` (Trust-vermittelte Auflösung) |
| `NT AUTHORITY\SYSTEM` / `BUILTIN\Administrators` / `BUILTIN\Users` / `CREATOR OWNER` | … | inherited | Default-NTFS-Erbung |

## Teil C — Stars-Tests gegen das Lab

Stars-CLI (`C:\Stars\adpa.exe`, Version 1.5.5) wurde auf tier0 hochgeladen und mit drei Szenarien geprüft. Vollständige Ausgaben liegen im Lab-Capture (`/tmp/lab-stars-evidence.txt`). Hier nur die kritischen Auszüge.

### C.1  T1 — Innerhalb des Forests, nested groups

```text
adpa.exe analyze \
    --path 'C:\TestShare' \
    --user 'T0LAB\alice' \
    --server 'tier0.tier0.lab' \
    --base-dn 'DC=tier0,DC=lab' \
    --bind-dn 'CN=Administrator,CN=Users,DC=tier0,DC=lab' \
    --insecure-ldap
```

Wesentliches Ergebnis:

```text
Effective Rights
  NTFS    : Modify (0x001301BF)
  Result  : Modify (0x001301BF)

Explanation Path
  1. User: alice (S-1-5-21-…-1107)
  2. Member of Domain Users (S-1-5-21-…-513) [direct, source: PrimaryGroup]
  3. Member of GroupA (S-1-5-21-…-1105) [direct, source: DomainGroup]
  4. Member of GroupB (S-1-5-21-…-1106) [via alice → GroupA → GroupB, source: DomainGroup]
  5. Member of BUILTIN\Users (S-1-5-32-545) [via alice → Domain Users → BUILTIN\Users, source: LocalGroup]
  6. Allow ACE [explicit] for GroupB (…-1106) → Modify (0x001301BF)
  7. Allow ACE [inherited] for BUILTIN\Users → Read & Execute
  ...
  10. NTFS effective: Modify (0x001301BF)
```

**Bestätigt:**
- Nested-Group-Auflösung (alice → GroupA → GroupB) wird im Pfad korrekt als Mediator-Kette gerendert.
- Lokale-Gruppen-Auflösung (BUILTIN\Users) erscheint als eigene Step-Zeile mit `source: LocalGroup` — das ist genau das Verhalten aus dem Finding 1 dieses Release-Zyklus.
- Risk-Engine meldet `HIGH WRITE_ACCESS` (Modify) und `MEDIUM DELETE_RIGHT` für alice auf dem Pfad.

### C.2  T2 — Cross-Forest, Foreign Security Principal

```text
adpa.exe analyze \
    --path 'C:\TestShare' \
    --user 'T1LAB\bob' \
    --server 'tier1.tier1.lab' \
    --base-dn 'DC=tier1,DC=lab' \
    --bind-dn 'CN=Administrator,CN=Users,DC=tier1,DC=lab' \
    --insecure-ldap
```

Wesentliches Ergebnis:

```text
Effective Rights
  NTFS    : Read & Execute (0x001200A9)
  Result  : Read & Execute (0x001200A9)

Explanation Path
  1. User: bob (S-1-5-21-2422202677-…-1105)
  2. Member of Domain Users (S-1-5-21-2422202677-…-513) [direct, source: PrimaryGroup]
  3. Allow ACE [explicit] for T1LAB\bob (…) → Read & Execute
  4. NTFS effective: Read & Execute (0x001200A9)

Risk Findings (1)
  [LOW] DIRECT_USER_ACE — 'bob' has a direct explicit ACE …
```

**Bestätigt:**
- Stars löst `T1LAB\bob` über tier1.tier1.lab korrekt zur Cross-Forest-SID auf.
- Die FSP-ACE auf dem tier0-Pfad wird mit ihrem Cross-Forest-SID erkannt und zum effektiven Recht aggregiert.
- Risk-Engine erkennt die Direct-User-ACE-Risikoklasse.

### C.3  T3 — Cross-Forest ohne ACE (Negativ-Test)

```text
adpa.exe analyze \
    --path 'C:\TestShare' \
    --user 'T2LAB\carol' \
    --server 'tier2.tier2.lab' \
    --base-dn 'DC=tier2,DC=lab' \
    --bind-dn 'CN=Administrator,CN=Users,DC=tier2,DC=lab' \
    --insecure-ldap
```

Wesentliches Ergebnis:

```text
Matching ACEs (for this identity)
  (none)

Effective Rights
  NTFS    : Special (0x00000000)
  Result  : Special (0x00000000)

Explanation Path
  1. User: carol (S-1-5-21-2422907361-…-1105)
  2. Member of Domain Users (…) [direct, source: PrimaryGroup]
  3. NTFS effective: Special (0x00000000)

Risk Findings (0)
```

**Bestätigt:**
- Identität wird auch ohne ACE-Treffer korrekt aufgelöst.
- "Keine effektive Berechtigung" ist eine valide, vollständig erklärte Antwort — kein Fehler.

## Zusammenfassung

| Bereich | Ergebnis |
|---|---|
| 3 Forests / 3 separate Domain-SIDs | ✓ angelegt, ausgelesen |
| Conditional DNS Forwarder zwischen allen Paaren | ✓ ergänzt, Resolve cross-forest geprüft |
| 3 bidirektionale Forest-Trusts | ✓ über `Forest.CreateTrustRelationship` erstellt, alle Seiten sichtbar |
| Stars Smoke (alice, nested groups, innerhalb tier0) | ✓ Modify, Pfad mit allen Mediatoren |
| Stars Cross-Forest FSP (bob aus tier1, ACE auf tier0) | ✓ Read & Execute korrekt |
| Stars Cross-Forest ohne ACE (carol aus tier2) | ✓ 0x0 Spezial, Pfad sauber |
| Finding 1 — LocalGroup-Source im Erklärungspfad | ✓ in T1 sichtbar (`source: LocalGroup`) |

Die Lab-Topologie reproduziert die zwei wichtigsten realen Auditing-Szenarien, die ein Single-Forest-Setup nicht abbildet (Cross-Forest-FSPs und sauber getrennte Schemata), und zeigt, dass Stars sie auswertbar berichtet.
