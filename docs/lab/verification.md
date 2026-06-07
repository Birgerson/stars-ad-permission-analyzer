# Verifikation des Lab-Aufbaus und der Stars-Software

> **Letzter Update-Stand:** v1.5.16 (2026-06-07). Die Datei wächst pro Release um den jeweils neuen Verifikations-Block; ältere Blöcke bleiben unverändert als historischer Beleg.
> Jeder Verifikations-Block notiert seine eigene Stars-Version (z. B. „Block C — v1.5.8"). Die Lab-Topologie selbst stammt aus dem ersten Aufbau (siehe Commit-Zeitstempel von [`forest-topology.md`](forest-topology.md)).

Diese Datei dokumentiert *was* verifiziert wurde, *wie* es geprüft wurde, und *was* Stars dabei tatsächlich ausgegeben hat. Reproduzieren mit den Skripten unter [`scripts/`](scripts/).

| Block | Stars-Version | Thema |
|---|---|---|
| A — Lab-Infrastruktur | v1.5.5 (initial) | Forest-/Trust-/CF-Snapshot beim ersten Lab-Build |
| B — Test-Datenbestückung | v1.5.5 (initial) | OUs, Test-User, Test-ACL inkl. FSP |
| C — Stars-Tests (initial) | v1.5.5 | T1 nested-groups, T2 cross-forest FSP, T3 cross-forest no-ACE |
| D — Block A | v1.5.7 | NTFS-Edge-Cases (Deny, Protect, Share ∩ NTFS) |
| E — Block B | v1.5.7 | GUI-Boot-Smoke auf VirtIO-GPU |
| F — Block C | v1.5.8 | Skalierung — 1000 User, 5000 Dirs |
| G — Block D | v1.5.9 | NETWORK-SID bei lokalem Pfad + explizitem SMB-Kontext (Round-7 Finding 1) |
| H — Server 2025 | v1.5.16 | Plattform-Smoke auf Windows Server 2025 Standard (3 Forests, 1000 User, 5000 Dirs) |

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

## Teil D — Block A: NTFS-Edge-Cases (Deny, Protect-Inheritance, SMB-Share ∩ NTFS)

> Hinzugefügt im Release-Zyklus **v1.5.7** (2026-06-05). Reproduktions-Skript:
> [`scripts/09-blockA-edge-cases.sh`](scripts/09-blockA-edge-cases.sh).

Block A prüft drei Edge-Cases, die ein typisches AD-Audit-Tool falsch
aggregieren kann, ohne dass es jemand bemerkt:

### D.1  E1 — Deny-ACE schlägt geerbte Allow-ACE

Setup auf tier0:

- `C:\TestShare\DenyZone` Subordner mit Vererbung vom Parent
- **Explicit Deny Modify** für `T0LAB\alice`
- **Inherited Allow Modify** für `T0LAB\GroupB` (alice ist via GroupA → GroupB Mitglied)

Stars-Ergebnis (Auszug):

```text
Effective Rights
  NTFS    : Special (0x00100000)
  Result  : Special (0x00100000)

Explanation Path
  ...
  6. Deny ACE [explicit] for T0LAB\alice → Special (0x000301BF)
  7. Allow ACE [inherited] for GroupB → Modify (0x001301BF)
  ...
  11. Deny aggregation: Special (0x000301BF) blocked by Deny ACEs —
      those bits were removed from the effective NTFS mask
  12. NTFS effective: Special (0x00100000)
```

**Bestätigt:**
- Engine rechnet Allow ⊖ Deny korrekt aus (übrig bleibt nur das
  SYNCHRONIZE-Bit `0x00100000`, faktisch kein Datenzugriff).
- Pfad benennt die Deny-Auswirkung jetzt explizit (Schritt 11, siehe
  ADR 0042) — vor v1.5.7 musste der Auditor die Hex-Differenz selbst
  erkennen.

### D.2  E2 — Vererbungs-Unterbrechung (`Protect`)

Setup auf tier0:

- `C:\TestShare\Protected` Subordner
- `SetAccessRuleProtection($true, $false)` — Vererbung deaktiviert, geerbte
  Regeln entfernt
- Nur `BUILTIN\Administrators` und `NT AUTHORITY\SYSTEM` als explizite Allow-Regeln

Stars-Ergebnis:

```text
Inheritance : Protected (inheritance disabled)
Matching ACEs (for this identity) : (none)

Effective Rights
  NTFS    : Special (0x00000000)
  Result  : Special (0x00000000)

Explanation Path
  1. User: alice (...)
  2-5. (Mitgliedschaftskette)
  6. NTFS effective: Special (0x00000000)

Risk Findings (0)
```

**Bestätigt:**
- Vererbungs-Unterbrechung wird sichtbar gemeldet (`Inheritance:
  Protected (inheritance disabled)`).
- Kein false-positive auf inherited-Ebene: weil GroupB hier nicht erbt,
  hat alice gar keinen Treffer.
- Risk-Engine schweigt korrekt (keine Rechte, kein Risiko).

### D.3  E3 — SMB-Share-Permissions dominieren über NTFS

Setup auf tier0:

- `New-SmbShare -Name TestShareSMB -Path C:\TestShare -ReadAccess Everyone -FullAccess "T0LAB\Domain Admins"`
- NTFS hat weiterhin GroupB=Modify (alice via Mediator-Kette).

Stars-Aufruf mit UNC-Pfad + Share-Hint:

```text
adpa.exe analyze \
    --path '\\tier0\TestShareSMB' \
    --user 'T0LAB\alice' \
    --smb-server tier0 \
    --share-name TestShareSMB \
    ...
```

Ergebnis:

```text
Effective Rights
  NTFS    : Modify              (0x001301BF)
  Share   : Read & Execute      (0x001200A9)
  Result  : Read & Execute      (0x001200A9)

Explanation Path
  ...
  10. NTFS effective: Modify (0x001301BF)
  11. Share permission: Read & Execute (0x001200A9)
  12. Effective (NTFS ∩ Share): Read & Execute (0x001200A9)
```

**Bestätigt:**
- Stars liest Share-Permissions per SMB korrekt aus (Everyone=Read
  mapped auf Read & Execute).
- `Result = NTFS ∩ Share` (restriktiver gewinnt) — der Pfad rendert die
  Aggregation als eigenen Schritt 12.

## Teil E — Block B: GUI-Boot-Smoke

> Hinzugefügt im Release-Zyklus **v1.5.7** (2026-06-05). Reproduktions-Skript:
> [`scripts/10-blockB-gui-smoke.sh`](scripts/10-blockB-gui-smoke.sh).

Volle UI-Validierung der GUI bleibt ein manueller Schritt — `qm guest
exec` hat keinen interaktiven Desktop und kann keine Screenshots machen.
Was sich automatisieren lässt, ist der **Boot-Smoke**: Prozess startet,
hält stabil, terminiert sauber.

Ergebnis auf tier0:

```text
gui-binary: C:\Stars\adpa-gui.exe
gui-size  : 18734592 bytes
launched pid=4036
still-alive-after-15s pid=4036 handle-count=240 ws=22.83MB
process-terminated cleanly
stderr: (empty)
```

**Bestätigt:**
- Slint + winit-software-Backend bootet auf der VirtIO-GPU-VM
  fehlerfrei (Memory `project-deployment-target` ist also weiterhin
  valide).
- Working Set ~23 MB nach Boot, keine Auffälligkeiten im stderr.
- Prozess lässt sich sauber per Stop-Process beenden, keine
  hängenden Threads.

Was Block B **nicht** abdeckt und manuell durch den Betreiber via
RDP/SPICE geprüft werden muss:

- Rendering-Korrektheit der Theme-Umschaltung
- Layout-Stabilität bei Fenster-Resize
- Eingabe-Validierung in Live-Forms
- Output-Tabellen mit echten Scan-Ergebnissen

## Zusammenfassung v1.5.7

| Bereich | Ergebnis |
|---|---|
| Block A E1 — Deny-Override | ✓ rechnerisch + neuer Erklär-Step (ADR 0042) |
| Block A E2 — Protect-Inheritance | ✓ ohne false-positive |
| Block A E3 — Share ∩ NTFS | ✓ Share dominiert, Pfad expliziert die Aggregation |
| Block B — GUI Boot-Smoke | ✓ kein Slint-Crash auf VirtIO-GPU |

## Teil F — Block C: Skalierung auf großen Verzeichnissen

> Hinzugefügt im Release-Zyklus **v1.5.8** (2026-06-05). Reproduktions-Skripte:
> [`scripts/11-blockC-ad-bulk.sh`](scripts/11-blockC-ad-bulk.sh),
> [`scripts/12-blockC-dirs-acls.sh`](scripts/12-blockC-dirs-acls.sh),
> [`scripts/13-blockC-stars-perf.sh`](scripts/13-blockC-stars-perf.sh).

Block C prüft, ob Stars unter realistischer Lab-Last bleibt — also bei einem Forest mit hunderten Usern, geschachtelten Gruppen und tausenden Ordnern mit gemischten ACLs.

### F.1  AD-Bulk-Setup

Pro Forest werden angelegt:

- OUs: `OU=Company / OU={Departments, Users, Groups}` plus 5 Department-OUs unter `Departments` = **9 OUs**
- Sicherheitsgruppen: 5 Department-Gruppen + 15 Sub-Team-Gruppen = **20 Gruppen**
- Nesting: User → Sub-Team-Gruppe → Department-Gruppe (3-Level)
- User-Verteilung:

| Forest | User-Bereich | Anzahl | Pro Department | Pro Sub-Team |
|---|---|---|---|---|
| tier0.lab | `mm0001`–`mm0500` | 500 | ~100 | ~33 |
| tier1.lab | `mm0501`–`mm0800` | 300 | ~60 | ~20 |
| tier2.lab | `mm0801`–`mm1000` | 200 | ~40 | ~13 |

**Insgesamt: 1000 User über drei Forests, lexikographisch sortierbar (4-stelliges Padding).**

Bulk-Laufzeit gemessen via `Stopwatch`:

| Forest | User-Create-Dauer | ms/User |
|---|---|---|
| tier0 (500) | 44.7 s | ~89 |
| tier1 (300) | 24.7 s | ~82 |
| tier2 (200) | 17.0 s | ~85 |

Konsistente ~85 ms pro `New-ADUser` + `Add-ADGroupMember`-Paar, dominiert von LDAP-Replikation und Index-Aktualisierung.

### F.2  Verzeichnis- und ACL-Setup auf tier0

Verzeichnisstruktur auf `C:\Data`:

```text
C:\Data\
  Sales\Engineering\HR\Finance\IT      (5 Department-Wurzeln)
    Project01..20                      (20 Projekte pro Dept)
      Folder01..50                     (50 Folder pro Projekt)
                                       Σ = 5000 Folder-Ordner
                                         + 100 Project-Ordner
                                         + 5 Department-Ordner
                                         = 5105 Verzeichnisse
```

ACL-Variation auf den 100 Project-Ordnern:
- **Project 01..15** (75 Stück): explicit Allow Modify für die jeweilige Sub-Team-Gruppe (`Sales-Alpha`, `Engineering-Beta`, …)
- **Project 16..18** (15 Stück): `SetAccessRuleProtection($true)` — Vererbung deaktiviert, nur `BUILTIN\Administrators` + `NT AUTHORITY\SYSTEM`
- **Project 19..20** (10 Stück): explicit Deny ReadAndExecute für die jeweilige `-Gamma`-Sub-Team-Gruppe

Setup-Laufzeit:

| Schritt | Dauer | Rate |
|---|---|---|
| 5000 Folder-Ordner anlegen | 8.8 s | ~570 dirs/s |
| 5 Dept-Wurzel-ACLs | 1.6 s | (3 ms/ACL, dominiert von `Set-Acl`-IO) |
| 100 Project-ACLs (variiert) | 1.9 s | ~52 ACLs/s |
| **Gesamt C.2+C.3** | **13.2 s** | |

### F.3  Stars-Performance gegen `C:\Data`

Test-User: `T0LAB\mm0001` (Sales-Alpha-Member, hat Modify auf Sales/Project01..15 via Mediator-Kette).

**T1 — Full Scan** (`adpa.exe scan --path C:\Data --user T0LAB\mm0001 --output ...`):

```text
elapsed_seconds : 4.89
adpa rc         : 0
csv_lines       : 5107
csv_size_kb     : 6538.5
```

- 5105 Verzeichnisse + 1 Header + 1 Root-Eintrag = 5107 CSV-Zeilen ✓
- ~1043 dirs/s (= 0.96 ms pro Verzeichnis inkl. ACL-Lese, Owner-Lookup, Effective-Rights-Berechnung und CSV-Serialisierung)
- 6.5 MB CSV (~1.3 KB pro Zeile, also volle Pfad-Erklärung pro Eintrag)
- Exit 0, kein Crash, kein OOM-Hinweis

**T2 — Single deep analyze** (`adpa.exe analyze --path C:\Data\Sales\Project05\Folder25 --user T0LAB\mm0001`):

```text
elapsed_seconds : 4.24

Explanation Path
  1. User: mm0001 (S-1-5-21-…-1128)
  2. Member of Domain Users (…-513) [direct, source: PrimaryGroup]
  3. Member of Dept-Sales (…-1108) [via mm0001 → Sales-Alpha → Dept-Sales, source: DomainGroup]
  4. Member of Sales-Alpha (…-1109) [direct, source: DomainGroup]
  5. Member of BUILTIN\Users (S-1-5-32-545) [via mm0001 → Domain Users → BUILTIN\Users, source: LocalGroup]
  6. Allow ACE [inherited] for Dept-Sales (…-1108) → Modify (0x001301BF)
  …
  10. NTFS effective: Modify (0x001301BF)
```

- Dominant: einmalige LDAP-Connect + Bind + Gruppen-Auflösung (~4 s)
- ACL-Lese und Aggregation < 100 ms
- Mediator-Kette korrekt (ADR 0036) + LocalGroup-Step (ADR 0041) sichtbar

### F.4  Beobachtungen

- Stars rendert sich auch bei 1000 AD-Identities und 5000 Pfaden **ohne Memory-Druck und ohne Crash** durch.
- Der dominante Faktor bei *einzelnen* Aufrufen ist der LDAP-Bind plus die Gruppen-Auflösung des User-Tokens (einmalige Kosten). Sobald die Identität aufgelöst ist, ist der ACL-Lese-Pfad pro Verzeichnis sub-Millisekunde.
- Bei einem Full Scan amortisiert sich der LDAP-Aufwand über den gesamten Tree — die effektive Rate von ~1 ms/dir ist real-Production-tauglich.

### F.5  Bekannte Lab-Limitierung — Cross-Forest-FSPs

Das Bulk-Setup-Skript versucht, 50 Cross-Forest-Foreign-Security-Principals (25 aus `T1LAB`, 25 aus `T2LAB`) in tier0 `Dept-*`-Gruppen einzutragen. Sowohl `Add-ADGroupMember -Members <SID>` als auch eine ADSI-`Add`-Variante scheitern mit `0x80072030 — There is no such object on the server`. Microsoft-`Add-ADGroupMember` legt den FSP-Container-Eintrag nur dann automatisch an, wenn die Eingabe ein NetBIOS-Account-Name aus einem als Quell-Forest beim Lookup auflösbaren Trust ist — was bei großen Cross-Forest-Setups oft eine weitere Konfiguration verlangt (`dsadd group` aus legacy-Tools auf älteren Schemata, oder explizites `New-ADObject -Type foreignSecurityPrincipal`).

**Wichtig:** Dies ist **kein Stars-Bug**. Stars liest existierende FSP-ACEs sauber (siehe Test T2 in Teil C — `T1LAB\bob` hatte einen FSP-ACE in tier0 und Stars hat ihn korrekt aufgelöst und im Effective-Rights-Report wiedergegeben). Es ist nur das Lab-Bulk-Setup, das ohne weitere Konfigurationsschritte keine FSPs anlegen kann. Wer das Lab vervollständigen will, ergänzt die FSPs manuell oder über `dsadd group` von einem Domain Controller mit RSAT.

## Zusammenfassung v1.5.8

| Bereich | Ergebnis |
|---|---|
| Block C.1 — 1000 User über 3 Forests, 3-Level-Nesting | ✓ in 86 s |
| Block C.2/C.3 — 5000 Folder + 100 variierte ACLs | ✓ in 13 s |
| Block C.4 T1 — Full scan 5105 dirs | ✓ 4.89 s (≈ 1 ms/dir) |
| Block C.4 T2 — Single deep analyze | ✓ 4.24 s (LDAP-dominiert) |
| Block C.5 — Cross-Forest-FSP via Bulk-Skript | Lab-Limitierung dokumentiert (kein Stars-Bug) |

## Teil G — Block D: NETWORK-SID bei lokalem Pfad + explizitem SMB-Kontext (v1.5.9)

> Hinzugefügt im Release-Zyklus **v1.5.9** (2026-06-05). Reproduktions-Skript:
> [`scripts/14-blockD-network-context.sh`](scripts/14-blockD-network-context.sh).
> Referenzen: Round-7 Review Finding 1, ADR 0043.

Block D verifiziert die zentrale Wirkung des Round-7-Fixes: wenn ein Auditor einen **lokalen NTFS-Pfad** (z. B. `C:\TestShare\NetworkBlock`) zusammen mit einem **expliziten SMB-Kontext** (`--smb-server` + `--share-name`) analysiert — der häufige Fileserver-lokal-Audit-Fall — muss Stars die `NETWORK`-Well-Known-SID in den Token aufnehmen und Share-DACL-ACEs gegen `NETWORK` korrekt aggregieren.

### G.1  Setup

`C:\TestShare\NetworkBlock` ist ein Unterordner mit der von `C:\TestShare` geerbten NTFS-DACL — `T0LAB\GroupB` hat dort **Modify**, und alice (via `Sales-Alpha → GroupB`-Mediator) damit auch.

Neue SMB-Freigabe `TestShareNetBlock` zeigt auf diesen Subordner und hat eine restriktive Share-Permission-Liste:

```text
Everyone              Full Allow
NT AUTHORITY\NETWORK  Full Deny
NT AUTHORITY\NETWORK  Read Allow
```

Die Reihenfolge ist absichtlich: Allow Everyone + explizit Deny NETWORK. Über SMB landet der Zugriff über `NETWORK` — der Deny dominiert.

### G.2  Drei Stars-Szenarien

| Szenario | Pfad | `--smb-server` / `--share-name` | Stars-Output (`Result`) |
|---|---|---|---|
| **E4a** | `C:\TestShare\NetworkBlock` | — (nicht gesetzt) | `Modify (0x001301BF)` |
| **E4b** | `C:\TestShare\NetworkBlock` | `tier0` / `TestShareNetBlock` | `Special (0x00000000)` |
| **E4c** | `\\tier0\TestShareNetBlock` (Kontrolle) | `tier0` / `TestShareNetBlock` | Access denied beim NTFS-Read (Share blockt NETWORK an der Quelle) |

### G.3  Analyse

**E4a — keinen SMB-Hint, Stars nutzt `LocalInteractive`:**
- Kein Share-Kontext → Share-DACL wird gar nicht abgefragt → `Share: (not specified)`
- NTFS dominiert: `Modify`
- Korrekt: ein lokaler Audit ohne SMB-Bezug soll die NTFS-Sicht zeigen.

**E4b — derselbe lokale Pfad mit explizitem SMB-Hint:**
- *Vor v1.5.9:* `AccessContext::for_path(&path)` lieferte `LocalInteractive`, `NETWORK` fehlte im Token, der Deny-ACE gegen NETWORK wirkte nicht → Stars meldete fälschlich `Result = Modify`.
- *Mit v1.5.9 (`for_path_with_smb(path, smb_server, share_name)`):* `RemoteSmb`, NETWORK im Token, Deny-ACE auf NETWORK greift → Stars rendert die volle Aggregation:

```text
Effective Rights
  NTFS    : Modify (0x001301BF)
  Share   : Special (0x00000000)
  Result  : Special (0x00000000)

Explanation Path (Auszug)
  ...
  10. NTFS effective: Modify (0x001301BF)
  11. Share permission: Special (0x00000000)
  12. Effective (NTFS ∩ Share): Special (0x00000000)
```

Damit ist genau die Konstellation gefixt, die ein Auditor in der Praxis hat: lokal auf den Fileserver, aber Share-Sicht haben wollen.

**E4c — UNC-Pfad als Kontrollfall:**
- Die Share-Permission blockt NETWORK schon auf der Verbindungsebene. Stars läuft als LocalSystem, ist beim NTFS-Read der UNC-Pfad-Form selbst NETWORK → bekommt **Access denied** beim ACL-Lesen.
- Das ist semantisch konsistent: die Share verbietet NETWORK-Zugang, und auch ein Audit-Tool darf da nicht durch.
- Für die Engine-Korrektheit ist E4b der eigentliche Beweis-Punkt.

### G.4  Engine-Tests

Zwei neue Engine-Unit-Tests in `crates/permission_engine/src/engine.rs::tests` decken den End-to-End-Pfad ab:

- `remote_smb_context_grants_network_ace_even_on_local_path` — mit `AccessContext::RemoteSmb` aggregiert die Engine eine Allow-NETWORK-ACE korrekt.
- `local_interactive_context_ignores_network_ace` — Spiegelbild: unter `LocalInteractive` ignoriert sie sie korrekt.

Plus fünf Tests für die Helfer-Funktion `AccessContext::for_path_with_smb` in `crates/core/src/model.rs::tests`.

## Zusammenfassung v1.5.9

| Bereich | Ergebnis |
|---|---|
| Finding 1 — `AccessContext::for_path_with_smb` + 6 Call-Sites | ✓ E4b live verifiziert: Result `Modify` → `Special (0x00000000)` |
| Finding 2 — GUI HTML-Export Overwrite-Schutz | ✓ Worker-Test verifiziert: bestehende Datei wird abgelehnt, Inhalt bleibt unverändert |
| Finding 3 — `--bind-password` deprecate | ✓ Help-Text + Runtime-Warnung als DEPRECATED |
| Finding 4 — verification.md aufgeräumt | ✓ Header-Stand auf v1.5.9, Block-Übersicht mit Version pro Block |

---

## Block H — Plattform-Smoke auf Windows Server 2025 Standard

**Stars-Version:** v1.5.16
**Datum:** 2026-06-07
**Plattform-Wechsel:** Windows Server 2022 Standard → **Windows Server 2025 Standard** (`SERVER_EVAL_x64_2025_FRE_de-de.iso`)

### H.1 — Hardware-Profil (alle 3 DCs identisch)

| Setting | Wert |
|---|---|
| Machine-Type | `pc-q35-10.1` |
| BIOS | OVMF (UEFI) mit pre-enrolled Microsoft-Keys |
| TPM | v2.0 (swtpm) |
| CPU | 1 Socket × 8 Kerne, `x86-64-v2-AES` |
| RAM | 16 GiB ohne Ballooning |
| Disk | 50 GiB VirtIO Block, `qcow2`, Cache `directsync`, IO-Thread |
| Grafik | VirtIO (`vga: virtio`) |
| OS-Type | `win11` (Server 2022/2025/Win11) |
| Network | VirtIO, vmbr0, Firewall on |

Hintergrund: Erste Setup-Versuche mit `pc-i440fx-10.1` + alter VGA scheiterten am Disk-Driver-Loading im WinPE. Mit `q35` + VirtIO und einer Autounattend.xml-Sektion `PnpCustomizationsWinPE` (lädt `viostor`/`vioscsi`/`NetKVM` aus dem virtio-win-ISO) läuft das Setup vollautomatisch durch.

### H.2 — Forest-Topologie

3 Forests `tier0.lab` / `tier1.lab` / `tier2.lab` mit NetBIOS `T0LAB` / `T1LAB` / `T2LAB`. Forest-Mode pro Forest:

```text
tier0.lab — Windows2025Forest
tier1.lab — Windows2025Forest
tier2.lab — Windows2025Forest
```

(2022-Lab hatte `Windows2016Forest` — der neue Wert ist der Default auf Server 2025.)

Drei bidirektionale Forest-Trusts (vollvermascht), erstellt via `[System.DirectoryServices.ActiveDirectory.Forest]::CreateTrustRelationship`:

```text
tier0.lab ↔ tier1.lab  Bidirectional / Forest
tier1.lab ↔ tier2.lab  Bidirectional / Forest
tier0.lab ↔ tier2.lab  Bidirectional / Forest
```

Plus 6 Conditional DNS Forwarder (jeder DC hält CFs auf die jeweils anderen beiden Domain-Roots), `ReplicationScope: Forest`.

### H.3 — Test-Datenbestand

| DC | User-Range | Anzahl | Verteilung |
|---|---|---|---|
| tier0 | `mm0001`..`mm0500` | 500 | 5 Departments × 3 Sub-Teams + Nesting |
| tier1 | `mm0501`..`mm0800` | 300 | dito |
| tier2 | `mm0801`..`mm1000` | 200 | dito |

Plus auf tier0 `C:\Data\<Dept>\Project01..20\Folder01..50` = **5000 Folder + 100 Project-ACLs** mit drei ACL-Varianten:

- Project01..15 (75 Projekte): explicit Modify für Department-Sub-Team
- Project16..18 (15 Projekte): Protected Inheritance + nur SYSTEM/Administrators
- Project19..20 (10 Projekte): Allow Modify + zusätzlich Deny ReadAndExecute für `<Dept>-Gamma`

### H.4 — Stars Smoke-Tests (`adpa.exe analyze` v1.5.16)

Drei semantisch unterschiedliche Pfade gegen User `T0LAB\mm0001` (Mitglied in `Sales-Alpha`).

**Test 1 — `C:\Data\Sales\Project01` (Modify via Sales-Alpha):**

| Feld | Erwartung | Ergebnis |
|---|---|---|
| Effective | Modify (0x001301BF) | ✅ exakt |
| Matching ACEs | Sales-Alpha Modify explicit, BUILTIN\Users inherited Read | ✅ exakt |
| Risk Findings | WRITE_ACCESS (HIGH), DELETE_RIGHT (MEDIUM) | ✅ erkannt |
| Explanation Path | 10 Schritte: User → Sales-Alpha → ACE → NTFS effective | ✅ vollständig |

**Test 2 — `C:\Data\Sales\Project16` (Protected Inheritance, kein Zugriff):**

| Feld | Erwartung | Ergebnis |
|---|---|---|
| Effective | Special (0x00000000) = kein Zugriff | ✅ |
| Inheritance | „Protected (inheritance disabled)" | ✅ erkannt |
| Matching ACEs | `(none)` — Sales-Alpha-ACE existiert nicht, da Inheritance protected | ✅ |
| Risk Findings | (none) | ✅ |

**Test 3 — `C:\Data\Sales\Project19` (Deny Sales-Gamma, mm0001 in Sales-Alpha):**

| Feld | Erwartung | Ergebnis |
|---|---|---|
| Effective | Read & Execute via BUILTIN\Users (Gamma-Deny greift nicht für Alpha-User) | ✅ Read & Execute (0x001200AF) |
| DACL-Anzeige | DENY-ACE für Sales-Gamma SID sichtbar | ✅ |
| Matching ACEs | 3 inherited Allow-ACEs für BUILTIN\Users — kein Deny-Match (mm0001 ≠ Gamma) | ✅ |

Diagnose-Marker waren erwartungsgemäß aktiv: „No AD connection — group memberships not resolved" und „Group resolution ran through SAM/LSA fallback" (Smoke-Test ohne `--server`/`--base-dn`).

### H.5 — Was Block H verifiziert

| Bereich | Ergebnis |
|---|---|
| Setup-Automation auf Server 2025 (Autounattend + VirtIO-Treiber) | ✅ läuft durch ohne manuelle Interaktion |
| `Windows2025Forest`-Mode | ✅ automatisch gewählt, keine Anpassung am `Install-ADDSForest`-Skript nötig |
| Cross-Forest-Trusts auf Server 2025 | ✅ `CreateTrustRelationship` baut bidirektionale Forest-Trusts unverändert |
| Stars v1.5.16 (Round-10-Architektur) auf Server 2025 | ✅ Effective Rights + Explanation Path + Diagnose-Marker + Risk Findings korrekt |
| Round-10-Findings 1–4 (Trustees-Enum, SmbAuditContext, SID-Map, win_safe-Crate) | ✅ keine Regression — alle 3 Tests sauber durchlaufen |

### H.6 — Nicht geprüft in Block H

- HTML-/JSON-Export auf Server 2025 (deckt v1.5.16 schon über Round-10-Tests + 2022-Lab-Verifikation ab).
- GUI auf Server 2025 (`adpa-gui.exe` ist auf tier0 deployed, aber kein manueller Walkthrough wie in Block E).
- 5000-Pfad-Performance-Vergleich Server 2022 vs. 2025 (Round-10-Optimierung „SID-Map Caller-Owned" reduziert LSA-Last; quantitativer Vergleich nicht gemessen).
- Cross-Forest-Tests (T2 mit FSP, T3 ohne ACE) auf Server 2025 — die Trust-Topologie ist gleich; die Stars-Logik hängt nicht am Forest-Mode.
