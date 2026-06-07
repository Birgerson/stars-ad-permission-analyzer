# Stars — AD Permission Analyzer

[![Latest Release](https://img.shields.io/github/v/release/Birgerson/stars-ad-permission-analyzer?include_prereleases&label=Release&color=4fc3f7)](https://github.com/Birgerson/stars-ad-permission-analyzer/releases)
[![CI](https://github.com/Birgerson/stars-ad-permission-analyzer/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Birgerson/stars-ad-permission-analyzer/actions/workflows/ci.yml)

[**Deutsch**](#deutsch) · [**English**](#english)

---

## <a name="deutsch"></a>Deutsch

**Stars** ist ein Windows-Analysetool für Active-Directory-Berechtigungen, NTFS-Zugriffsrechte und SMB-Freigaben.

Das Tool zeigt für jeden Benutzer, welche effektiven Zugriffsrechte er tatsächlich auf Ordner und Dateien hat — und vor allem **wie** diese Rechte zustande kommen: über welche Gruppen, welche ACL-Einträge, welche Vererbungen.

> **Stars ist ausschließlich ein Lese- und Analysetool. Es verändert keine Berechtigungen, Gruppen oder AD-Objekte.**

![Stars Analyze-Tab (v1.5.16) — Zielpfad, Identität, Auflösungsmodus, SMB-Freigabe und die beiden Aktionsknöpfe „Analysieren" und „Wer hat Zugriff?"](docs/screenshots/stars-analyze-tab.png)

### Konkretes Beispiel in 10 Sekunden

Stars beantwortet pro Pfad **„was darf der Benutzer und warum"** — mit vollständigem Berechtigungspfad:

```text
Benutzer max.mustermann -> Mitglied von "Sales"
                        -> Mitglied von "FileServer_Read"
                        -> Allow ACE [geerbt] für FileServer_Read
                        -> NTFS: Read & Execute
                        -> Share-Berechtigung: Change
                        -> Effektiv (NTFS ∩ Share): Read & Execute
```

Genau diese Schritt-für-Schritt-Erklärung — inklusive Diagnose-Markern, wenn etwas unklar ist — bekommst du in der GUI, im CSV/JSON/HTML-Bericht und im CLI-Output. Für 1 Pfad oder 5000 Pfade gleich.

### Kann Stars dir helfen? — 30-Sekunden-Übersicht

> **Volle Übersicht:** [`docs/can-stars-help-you.md`](docs/can-stars-help-you.md) (DE + EN, mit Entscheidungs-Matrix).

**✅ Stars ist das richtige Tool, wenn du:**

- erklären musst, **warum** ein Benutzer auf einen Ordner / eine Freigabe genau diese effektive Berechtigung hat (mit vollständigem Pfad: Identität → Gruppe → Mediator → ACE → Aggregation)
- die Kombination aus NTFS- und SMB-Share-Rechten verstehen willst (die restriktivere Maske gewinnt — Stars rechnet das korrekt)
- mit verschachtelten AD-Gruppen, lokalen Server-Gruppen (`BUILTIN\…`), Deny-ACEs und Vererbungs-Unterbrechungen arbeitest
- ein Tool brauchst, das **nichts** an AD, NTFS oder SMB verändert — auch nicht „nur zur Reparatur"
- einen Berechtigungs-Snapshot eines Ordnerbaums (z. B. 5000 Verzeichnisse) als CSV / JSON / HTML brauchst

**❌ Stars ist *nicht* das richtige Tool für:**

| Bedarf | Stattdessen |
|---|---|
| Aktive Reparatur, ACL-Cleanup, Owner-Wechsel | dein bevorzugtes ACL-Management-Werkzeug |
| Kontinuierliches Auditing, Event-Stream, Logon-Tracking | ManageEngine ADAudit Plus / SIEM |
| AD-Security-Score, Forest-Härtungs-Bewertung | PingCastle, Purple Knight |
| Angriffspfad-Analyse aus Angreifer-Sicht | BloodHound CE |
| Access-Governance, Rezertifizierung, Workflows | SolarWinds ARM, Netwrix, Quest, Lepide |
| Breite AD-Inventarberichte (GPOs, Trusts, Sites) | ADRecon |

**Drei harte Grenzen, die Stars niemals überschreitet:**

1. **Read-only.** Kein Release wird je Schreibfunktionen für NTFS / SMB / AD bekommen.
2. **Kein Agent** auf Zielsystemen. Stars läuft auf einer Audit-Workstation oder einem Audit-DC.
3. **Keine Backdoor-Authentifizierung.** Stars bindet per LDAP (idealerweise LDAPS), sonst nichts.

### Download

Den aktuellen Windows-Installer gibt es auf der **[Releases-Seite](https://github.com/Birgerson/stars-ad-permission-analyzer/releases)**.

1. Auf den neuesten Release klicken (oben in der Liste).
2. `Stars-vX.Y.Z-Setup.exe` **und** `Stars-vX.Y.Z-Setup.exe.sha256` unter *Assets* herunterladen.
3. **Empfohlen:** Integrität verifizieren (siehe unten) — Stars hat aktuell kein Code-Signing.
4. Doppelklick auf den Installer — keine Administratorrechte erforderlich. Ein **Stars**-Symbol erscheint auf dem Desktop.

Systemvoraussetzungen: Windows 10, Windows 11 oder Windows Server. Keine weitere Laufzeitumgebung nötig.

#### Integrität verifizieren (SHA256)

Damit du prüfen kannst, dass dein Download mit dem in GitHub Actions gebauten Build bit-genau übereinstimmt:

```powershell
$exe = "Stars-v1.5.16-Setup.exe"  # an deine Version anpassen
$expected = (Get-Content "$exe.sha256").Split("  ")[0]
$actual   = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
if ($actual -eq $expected) { "OK — Datei stimmt" } else { "MISMATCH — NICHT verwenden" }
```

Auf WSL / Linux / macOS reicht `sha256sum -c Stars-v1.5.16-Setup.exe.sha256`.

> **Was das Hash-File leistet — und was nicht:** Der Hash schützt gegen verfälschte Downloads (Mirror-Modifikation, Mitm). Er ersetzt **kein** Code-Signing — die Echtheit der Quelle verifizierst du über das GitHub-Repo selbst, nicht über den Hash. Code-Signing ist eingeplant; siehe [`docs/codesigning.md`](docs/codesigning.md) für den Stand.

> **Getestete Plattformen:** Stars ist gegen **Windows Server 2022 Standard** und **Windows Server 2025 Standard** verifiziert (3-Forest-Lab, 1000 Test-User, 5000 Verzeichnisse).
>
> **Nutzung auf eigene Verantwortung. Vor produktivem Einsatz ein vollständiges Backup anlegen.** → [Vollständiger Haftungsausschluss](#haftungsausschluss)

### Was ist Stars?

Stars ist eine **native Windows-Anwendung** (`.exe`) für IT-Administratoren und Security-Auditoren.

Sie besteht aus zwei Programmen:

| Programm | Beschreibung |
|----------|-------------|
| `adpa-gui.exe` | Grafische Oberfläche (GUI) mit Analyze- und Scan-Ansicht |
| `adpa.exe` | Kommandozeileninterface (CLI) für Skripte und Automatisierung |

Beide Programme analysieren dieselben Daten und nutzen dieselbe Berechtigungslogik.

### Was analysiert Stars?

#### NTFS-Berechtigungen

Stars liest die Windows-Zugriffskontrolllisten (ACLs) direkt vom Dateisystem:

- Allow- und Deny-ACEs
- Explizite und geerbte Einträge
- Vererbungsunterbrechungen
- Besitzer-Sonderregel (Owner erhält immer READ_CONTROL + WRITE_DAC)
- Reparse Points, Junctions und symbolische Links (ohne Endlosschleifen)

#### Active Directory

Stars löst Benutzer und Gruppen über LDAP auf:

- Direkte und transitive Gruppenmitgliedschaften
- Vollständiger Mitgliedschaftspfad pro Gruppe (`User → Group A → Group B`), nicht nur „Member of B [transitive]"
- Primärgruppe des Benutzers
- Deaktivierte Konten
- Verwaiste SIDs
- Zyklische Gruppenstrukturen

#### SMB-Freigaben

Stars berücksichtigt Share-Berechtigungen bei der Berechnung:

- Enumeration aller Freigaben auf einem Server
- NULL DACL (jeder hat Vollzugriff) vs. leere DACL (niemand hat Zugriff) — beide Fälle werden korrekt unterschieden
- Kombination aus NTFS- und Share-Rechten: `effektiv = NTFS ∩ Share`

#### Effektive Berechtigungen

Das Kernergebnis ist die tatsächlich wirksame Berechtigung — mit vollständiger Erklärung:

```
Benutzer max.muster → Mitglied von "Buchhaltung" → Mitglied von "FileServer_Read"
→ Allow ACE [geerbt] für FileServer_Read → NTFS: Read & Execute
→ Share-Berechtigung: Change
→ Effektiv (NTFS ∩ Share): Read & Execute
```

### Wie wird Stars gestartet?

Stars wird über den **Setup-Installer** auf der [Release-Seite](https://github.com/Birgerson/stars-ad-permission-analyzer/releases) ausgeliefert — aktuell `Stars-v1.5.16-Setup.exe`. Der Installer legt die Anwendung nach `C:\Program Files\Stars\` ab, erstellt einen Start-Menü-Eintrag „Stars" und installiert **keine Hintergrunddienste** und **keine Auto-Start-Komponenten**.

> **Hinweis zur Signatur:** Der Installer ist aktuell **nicht codesigned**. Beim ersten Start warnt Windows SmartScreen entsprechend („Computer durch unbekannten Herausgeber geschützt"). Ein Code-Signing-Zertifikat ist eingeplant, aber noch nicht eingerichtet.

Für Entwickler und CI-Builds lassen sich die `.exe`-Dateien aus `target/release/` (`adpa.exe`, `adpa-gui.exe`) nach `cargo build --release` auch ohne Installer direkt starten — der reguläre Auslieferungsweg ist und bleibt der Installer.

**Systemvoraussetzungen:**
- Windows 10 / Windows 11 / Windows Server
- Netzwerkzugriff auf den Ziel-Dateiserver (für SMB-Freigaben)
- LDAP-Zugriff auf Active Directory (optional, für vollständige Gruppenauflösung)
- Ausreichende Leserechte auf die zu analysierenden Pfade

**Plattformstatus:**

| Plattform | Status |
|---|---|
| Windows Server 2022 Standard | ✅ verifiziert — Nutzung trotzdem auf eigene Verantwortung |
| Windows Server 2025 Standard | ✅ verifiziert (Lab-Smoke-Test am 2026-06-07) — Nutzung auf eigene Verantwortung |
| Windows 10 / 11, ältere Server-Versionen | sollte laufen, aber nicht im Lab geprüft — Nutzung auf eigene Verantwortung |

> Der Vermerk „verifiziert" bedeutet, dass die Audit-Funktionen auf dieser Plattform im Lab-Setup durchgelaufen sind — er ist **keine Garantie** auf Korrektheit, Vollständigkeit oder Eignung für einen bestimmten Zweck. Vollständiger Haftungsausschluss am Ende des Dokuments.

**GUI starten:** Start-Menü → „Stars" (nach Installer), oder direkt `C:\Program Files\Stars\adpa-gui.exe`.

**CLI:** Der Installer legt `adpa.exe` ins selbe Verzeichnis. Für bequeme Aufrufe ohne Pfadangabe das Verzeichnis manuell in die `PATH`-Umgebungsvariable aufnehmen.

**CLI — einzelnen Pfad analysieren:**
```
adpa.exe analyze --path "C:\Daten\Abteilung" --user S-1-5-21-...
```

**CLI — rekursiver Scan eines Verzeichnisbaums:**
```
adpa.exe scan --path "C:\Daten" --user S-1-5-21-... --max-depth 8
```

**CLI — mit LDAP für vollständige Gruppenauflösung:**
```
set ADPA_BIND_PASSWORD=GeheimesPasswort
adpa.exe analyze --path "\\server\share\Daten" --user S-1-5-21-... ^
  --server dc.domain.local --base-dn "DC=domain,DC=local" ^
  --bind-dn "CN=SvcScan,CN=Users,DC=domain,DC=local"
```
> LDAP verbindet standardmäßig über LDAPS (Port 636, verschlüsselt).
> Das Passwort wird über `ADPA_BIND_PASSWORD` übergeben, nicht als CLI-Argument
> (CLI-Argumente sind in Prozesslisten und Shell-History sichtbar).
> Für Testumgebungen ohne LDAPS: `--insecure-ldap` ergänzen.
>
> **Hinweis zu Windows Server 2025:** Server 2025 erzwingt LDAP-Signing per Default
> (`rc=8 strongerAuthRequired` bei unverschlüsseltem Bind). Für `--insecure-ldap`
> auf einem 2025-Ziel müsste das Server-seitig gelockert werden — produktiv
> nicht empfehlenswert. Für LDAPS braucht der DC ein gültiges Computer-Zertifikat
> (typischerweise via AD CS); ohne Zertifikat scheitert der TLS-Handshake. Stars
> erkennt beide Fälle und zeigt einen klaren Diagnose-Marker statt still
> unvollständige Ergebnisse zu liefern.

**CLI — UNC-Pfad mit automatischer Share-Erkennung:**
```
adpa.exe analyze --path "\\fileserver\Buchhaltung\Bilanzen" --user S-1-5-21-...
```
Stars erkennt den UNC-Pfad automatisch und bezieht die Share-Berechtigung in die Berechnung ein.

### GUI — die vier Tabs

Stars hat genau **vier Tabs:** `Analyze`, `Scan Tree`, `Delta`, `Info`. „Identität", „Trustees" und „Risk Findings" sind keine eigenen Tabs, sondern Sektionen innerhalb der vier echten Tabs.

#### Tab `Analyze`

Gibt die effektive Berechtigung für **einen einzelnen Pfad** zurück.

Eingaben:
- **Pfad** (lokal oder UNC) — beim Start vorbelegt mit `C:\Windows\SYSVOL\sysvol` (der wichtigste Pfad zum Auditieren auf jedem Domain Controller). Frei überschreibbar.
- **Benutzer/Gruppe** — Klartextname mit Live-Suche (siehe „Benutzereingabe" unten).
- **Benutzer-SID** — wird vom Namensfeld befüllt, kann auch direkt eingegeben werden.
- Optional: LDAP-Verbindungsdaten für Gruppenauflösung (auf einem DC nicht nötig — die SAM/LSA reicht).

Aktionen:
- **Analysieren** — identitätsbezogene Auswertung (NTFS- und Share-Recht, effektive Berechtigung, Erklärungspfad).
- **Wer hat Zugriff?** — pfadzentrische Trustee-Tabelle aller ACEs (NTFS und Share getrennt).

#### Tab `Scan Tree`

Scannt einen **gesamten Verzeichnisbaum** rekursiv.

Eingaben:
- **Wurzelpfad** (lokal oder UNC) — wie im `Analyze`-Tab mit `C:\Windows\SYSVOL\sysvol` vorbelegt.
- **Benutzer/Gruppe + SID** — wie `Analyze`, dieselbe Live-Suche.
- Optional: maximale Tiefe, SMB-Server/Share-Name, LDAP-Daten.

Ausgabe:
- Tabelle: Pfad | Berechtigung | Maske, jede Zeile aufklappbar mit vollständiger Erklärung.
- Fehlerprotokoll (Zugriff verweigert, nicht gefunden etc.).
- Filter nach Pfad-Teilstring.
- Risk-Findings-Sektion mit Severity-Farbcode.
- HTML-/JSON-/CSV-Berichts-Export.

#### Tab `Delta`

Vergleicht zwei persistierte Scan-Läufe und zeigt, was sich verändert hat — nicht nur am effektiven Recht, sondern auch an NTFS/Share-Komposition, Status (z. B. `ReadFailed`) und Diagnose-Markern.

Eingaben:
- „📂 Scan-Historie laden" liest aus der lokalen SQLite-DB.
- Je eine Zeile als „Alt" und „Neu" anhaken.

Ausgabe:
- Liste mit Pfad, Änderungsart (Hinzugefügt / Entfernt / Geändert), Rechte vorher/nachher.
- Spalte „Geändert (...)" benennt die konkreten Aenderungsursachen (z. B. „NTFS mask + share status").
- Farbcode: grün = Hinzugefügt, rot = Entfernt, gelb = Geändert.

#### Tab `Info`

Versionsstand, Plattform-Status („verifiziert gegen Server 2022 und 2025"), Lizenz, KI-Urheberschaft und Links zur Online-Doku. Kein interaktiver Inhalt.

### Benutzereingabe — Name oder SID

Ein Auditor kennt seine Benutzer meist beim Namen, nicht bei der SID. Stars vereinfacht das auf drei Wegen:

#### 1. Live-Suche im Namensfeld

Tippe ein paar Buchstaben in das Feld **„Benutzer/Gruppe"**. Direkt darunter erscheint eine Vorschlags­liste mit bis zu 15 passenden Identitäten. Klick auf einen Eintrag übernimmt den Namen und löst die SID automatisch auf.

Die Liste wird beim App-Start einmalig aus den lokalen NetAPI-Quellen aufgebaut: Domänen-User, globale Domänen­gruppen, lokale Gruppen, Well-Known-SIDs. Kein LDAP-Bind nötig — auf einem DC reicht die SAM/LSA.

**Legende der Typ-Marker:**

| Marker | Bedeutung | Beispiel |
|---|---|---|
| `[U]` | **User** — Domänen- oder lokales Benutzerkonto (`NetUserEnum`) | `[U] TESTDOMAIN\Administrator` |
| `[G]` | **Globale (Domänen-)Gruppe** (`NetGroupEnum`) | `[G] TESTDOMAIN\Domain Admins` |
| `[L]` | **Lokale Gruppe** (`NetLocalGroupEnum`, in der UI als `BUILTIN`-Authority) | `[L] BUILTIN\Administratoren` |
| `[W]` | **Well-Known-Identität** (audit-relevante Standard-SIDs aus einer eingebauten Tabelle) | `[W] NT AUTHORITY\Authenticated Users` |

#### 2. „🔍 SID auflösen"-Button

Wenn du den vollen Namen bereits weißt, tippe ihn ein und klick den Button — oder drück **Enter** im Namensfeld. Der Lookup läuft über `LookupAccountNameW`, akzeptiert beide Formen `Administrator` und `DOMÄNE\Administrator` und arbeitet auch für Gruppen (`BUILTIN\Administratoren`, `Everyone`).

#### 3. Direkte SID-Eingabe

Wer eine SID aus einem anderen Tool kopiert hat (z.B. `S-1-5-21-1234-5678-…-500`), tippt sie direkt ins SID-Feld. Funktioniert mit oder ohne Live-Suche.

### CLI-Befehle (Übersicht)

```
adpa.exe analyze   — effektive Berechtigung für einen einzelnen Pfad
adpa.exe scan      — rekursiver Scan eines Verzeichnisbaums
adpa.exe --help    — vollständige Hilfe mit allen Optionen
```

Die detaillierten Aufruf-Beispiele stehen oben unter „Wie wird Stars gestartet?".

### Was Stars nicht kann

Stars ist bewusst auf Analyse beschränkt. Folgendes ist nicht vorgesehen und wird nicht implementiert:

- Berechtigungen ändern
- ACLs bereinigen
- Gruppen­mitgliedschaften ändern
- Dateien oder Ordner auf Zielsystemen erstellen, verschieben oder löschen
- Automatische Reparaturvorschläge umsetzen

### Projektstruktur

Stars ist als Rust Workspace mit mehreren unabhängigen Modulen aufgebaut:

```
crates/
├── core/               — gemeinsame Datentypen und Traits
├── ad_resolver/        — Active Directory / LDAP-Anbindung
├── fs_scanner/         — NTFS-ACL-Auswertung
├── share_scanner/      — SMB-Freigaben
├── permission_engine/  — Berechnung effektiver Rechte
├── risk_engine/        — Risikoregeln (6 implementiert)
├── persistence/        — SQLite-Cache und Scan-Historie
├── exporter/           — CSV, JSON, HTML-Export
├── update_manager/     — sichere Update-Installation
├── validation/         — Eingabevalidierung
├── cli/                — Kommandozeilenprogramm (adpa.exe)
└── gui/                — grafische Oberfläche (adpa-gui.exe)
```

### Build

```powershell
cargo build --release -p cli   # adpa.exe
cargo build --release -p gui   # adpa-gui.exe
```

Voraussetzung: [Rust Toolchain](https://rustup.rs/) für Windows (MSVC-Target)

### Datenbank, Scan-Historie und Deinstallation

Stars persistiert die Scan-Historie in `%APPDATA%\Stars\stars_data.db` (SQLite, pro Benutzerprofil getrennt, überlebt eine Deinstallation). Die Datenbank ist seit v1.5.16 **snapshot-stabil** — historische Reports verändern sich nicht durch spätere Identity-Updates.

→ **Vollständige Details:**
- [`docs/scan-historie-und-datenbank.md`](docs/scan-historie-und-datenbank.md) — Standort, Tabellen, Delta-Vergleich, Inspizierbarkeit (DE + EN)
- [`docs/installation-und-deinstallation.md`](docs/installation-und-deinstallation.md) — Installer-Schritte, Uninstaller-Verhalten, was bleibt und was geht (DE + EN)

### Dokumentation

- **[Anwender-Handbuch](docs/anwender-handbuch.md)** — Schritt-für-Schritt-Anleitung für die GUI und CLI, alle Tabs erklärt, Identitätseingabe, AD-Anbindung, Marker-Lesart, FAQ. **Start hier, wenn Sie Stars zum ersten Mal benutzen.**
- **[Technische Dokumentation](docs/technische-dokumentation.md)** — wie Stars intern funktioniert: Architektur, Crate-Layering, Principal-Pipeline, Permission-Engine-Algorithmus, Diagnose-Marker-System, Threading-Modell. **Start hier, wenn Sie Code lesen oder beitragen wollen.**
- **[Features, Grenzen und Lesart der Ergebnisse](docs/features-and-limitations.md)** — was Stars zuverlässig kann, was bewusst nicht implementiert ist, und wie die Diagnose-Marker (`DomainGroupRecursionIncomplete`, `IdentityNotInConfiguredLdapBase`, …) zu lesen sind. **Start hier, wenn ein Befund unerwartet ist.**
- **[Bekannte Grenzen und Roadmap (v1.6+)](docs/known-limitations.md)** — strukturelle Lücken (FSP, GC-Bind, SID-History, Cross-Forest), die Stars markiert, aber nicht löst. Roadmap-Tracking für künftige Releases.
- **[Audit-Kriterien und Bewertungsprinzipien](docs/audit-kriterien.md)** — vollständige Lektüre darüber, nach welchen Regeln Stars Berechtigungen bewertet, welche Risikoregeln implementiert sind, welche Severities sie tragen und welche Rechte für welche Rolle als optimal gelten.
- **[Architektur-Entscheidungen (ADRs)](docs/adr/)** — historische Begründungen einzelner Technologie- und Modell­entscheidungen.
- **[Security Policy](SECURITY.md)** — wie Sicherheitslücken gemeldet werden.

### Über das Projekt

**Konzeption, Spezifikation, Steuerung und Review:**
**Birger Labinsch** — Fachinformatiker Anwendungs­entwicklung / Prompt Engineer

**Implementierung (Rust-Workspace, Slint-GUI, Engine, Resolver, Tests, Dokumentation):**
**Claude Opus 4.7** (Anthropic) — als KI-Modell unter direkter Anleitung und kontinuierlichem Review von Birger Labinsch.

Diese Zuschreibung ist bewusst transparent: Birger Labinsch hat den Code **nicht selbst geschrieben**, sondern als Prompt Engineer den gesamten Entwicklungs­prozess durch das KI-Modell geführt — von der Architektur­entscheidung über die einzelnen Code-Änderungen bis hin zu Tests, Bugfixes und Dokumentation. Jeder Commit dieses Repositories trägt deshalb auch eine `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`-Zeile, die den KI-Anteil pro Änderung sichtbar macht.

<a name="haftungsausschluss"></a>

### Haftungsausschluss

Stars wird ausschließlich **„wie besehen"** („as is") zur Verfügung gestellt, ohne ausdrückliche oder stillschweigende Zusicherung jeglicher Art — einschließlich, aber nicht beschränkt auf Eignung für einen bestimmten Zweck, Vollständigkeit, Korrektheit der Ergebnisse, ununterbrochene Verfügbarkeit oder Fehlerfreiheit.

Die Nutzung erfolgt **ausschließlich auf eigene Verantwortung des Anwenders** — auf **allen** Plattformen, auch auf denen, die in dieser README als „verifiziert" markiert sind. Der Vermerk „verifiziert" beschreibt lediglich, dass auf der genannten Plattform manuelle Funktionsprüfungen durchgeführt wurden; er ist **keine Zusicherung** und **kein Beleg** für Korrektheit oder Eignung in einer bestimmten produktiven Umgebung.

**Birger Labinsch übernimmt keinerlei Haftung** für:

- Schäden materieller oder immaterieller Art, die durch die Nutzung oder Nicht-Nutzung von Stars entstehen
- Datenverluste, fehlerhafte Audit-Ergebnisse oder daraus abgeleitete Geschäfts­entscheidungen
- Sicherheitsvorfälle, die durch unvollständige oder fehlerhafte Berechtigungs­auswertung nicht erkannt wurden
- Folgen aus der Anwendung der dokumentierten Audit-Kriterien auf nicht dafür vorgesehene Umgebungen
- Inkompatibilitäten mit anderer Software, Treibern, Sicherheits­lösungen oder Domain-Konfigurationen
- jegliche mittelbaren oder unmittelbaren Folgeschäden

Der Anwender ist verpflichtet, die Eignung von Stars für seinen konkreten Einsatz­zweck vor produktiver Nutzung **selbst zu prüfen** und die Ergebnisse durch geeignete Kontroll­maßnahmen abzusichern.

#### Pflicht zur Datensicherung vor Nutzung

Stars ist als **read-only-Analysewerkzeug** konzipiert und greift gemäß seiner Architektur weder schreibend auf NTFS-Berechtigungen, SMB-Freigaben, AD-Objekte noch auf Dateien oder Ordner der Zielsysteme zu (siehe [`docs/known-limitations.md`](docs/known-limitations.md) für die Liste der bewussten Architekturentscheidungen). Diese Architekturzusicherung ist jedoch **keine Garantie** gegen jeden denkbaren Nebeneffekt — etwa durch Inkompatibilitäten, Treiberfehler, Antiviren-Eingriffe, Sperrkonflikte, Logging-Nebenwirkungen oder die ungewollte Auslastung von Zielsystemen unter Last.

**Der Anwender ist deshalb verpflichtet, vor jeder Nutzung von Stars in einer produktiven oder produktions­nahen Umgebung ein vollständiges, getestetes Backup der betroffenen Systeme und Datenbestände anzufertigen** — einschließlich Domain Controller, Dateiserver, NTFS-Volumes und SMB-Share-Konfigurationen. Dies gilt **auch dann**, wenn Stars laut Architektur und Dokumentation ausschließlich lesend agiert. Birger Labinsch übernimmt **keinerlei Haftung** für Datenverluste, Konfigurations­schäden oder Betriebs­unterbrechungen, die durch fehlende, unvollständige oder nicht getestete Backups verursacht oder verschlimmert wurden.

Verifizieren Sie zusätzlich:
- dass die Backup-Wiederherstellung in einer **isolierten Testumgebung** funktioniert,
- dass Stars zunächst in einer Test- oder Pilot­umgebung evaluiert wurde, bevor es auf produktive Systeme angewendet wird,
- dass alle relevanten Stakeholder (Betriebs-, Security-, Compliance-Teams) vor der Anwendung informiert sind.

### Lizenz

**GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)** — siehe [LICENSE](LICENSE).

Konkret: Stars darf frei genutzt, studiert, geändert und weitergegeben werden. Wer Stars (oder einen abgeleiteten Fork) als Netzwerkdienst anbietet, muss den vollständigen Quellcode dieser veränderten Variante öffentlich verfügbar machen. Reine private oder interne Nutzung ist nicht betroffen.

---

## <a name="english"></a>English

**Stars** is a Windows analysis tool for Active Directory permissions, NTFS access rights, and SMB shares.

For every user, the tool shows the effective access rights that actually apply to folders and files — and above all **how** those rights come about: through which groups, which ACL entries, which inheritance.

> **Stars is exclusively a read-and-analyze tool. It does not modify any permissions, groups, or AD objects.**

![Stars Analyze tab (v1.5.16) — target path, identity, resolution mode, SMB share fields, and the two action buttons "Analyze" and "Who has access?"](docs/screenshots/stars-analyze-tab.png)

### Concrete example in 10 seconds

For every path Stars answers **"what does the user have, and why"** — with the full permission chain:

```text
User max.mustermann -> member of "Sales"
                    -> member of "FileServer_Read"
                    -> Allow ACE [inherited] for FileServer_Read
                    -> NTFS: Read & Execute
                    -> Share permission: Change
                    -> Effective (NTFS ∩ Share): Read & Execute
```

You get this step-by-step chain — including diagnostic markers when something is uncertain — in the GUI, in the CSV/JSON/HTML report, and in the CLI output. For 1 path or 5000 paths alike.

### Can Stars help you? — 30-second overview

> **Full overview:** [`docs/can-stars-help-you.md`](docs/can-stars-help-you.md) (DE + EN, decision matrix).

**✅ Stars is the right tool when you need to:**

- explain **why** a user has exactly this effective permission on a folder / share (full path: identity → group → mediator → ACE → aggregation)
- understand how NTFS and SMB share permissions combine (the more restrictive mask wins — Stars computes this correctly)
- handle nested AD groups, local server groups (`BUILTIN\…`), Deny ACEs, and protected inheritance
- use a tool that changes **nothing** in AD, NTFS, or SMB — not even “just to fix it”
- snapshot a directory tree (e.g. 5000 folders) as CSV / JSON / HTML

**❌ Stars is *not* the right tool for:**

| Need | Use instead |
|---|---|
| Active remediation, ACL cleanup, owner change | your preferred ACL management tool |
| Continuous auditing, event stream, logon tracking | ManageEngine ADAudit Plus / SIEM |
| AD security score, forest hardening assessment | PingCastle, Purple Knight |
| Attack-path analysis from an attacker’s perspective | BloodHound CE |
| Access governance, recertification, workflows | SolarWinds ARM, Netwrix, Quest, Lepide |
| Broad AD inventory reports (GPOs, trusts, sites) | ADRecon |

**Three hard limits Stars will never cross:**

1. **Read-only.** No release will ever ship write functions for NTFS / SMB / AD.
2. **No agent** on target systems. Stars runs on an audit workstation or audit DC.
3. **No backdoor auth.** Stars binds via LDAP (ideally LDAPS), nothing else.

### Download

Get the current Windows installer from the **[Releases page](https://github.com/Birgerson/stars-ad-permission-analyzer/releases)**.

1. Click the latest release at the top of the list.
2. Download `Stars-vX.Y.Z-Setup.exe` **and** `Stars-vX.Y.Z-Setup.exe.sha256` from *Assets*.
3. **Recommended:** verify integrity (see below) — Stars currently has no code-signing certificate.
4. Double-click the installer — no administrator rights required. A **Stars** icon appears on the desktop.

System requirements: Windows 10, Windows 11, or Windows Server. No additional runtime needed.

#### Verify integrity (SHA256)

So you can confirm your download is bit-for-bit identical to the build produced by GitHub Actions:

```powershell
$exe = "Stars-v1.5.16-Setup.exe"  # adapt to your version
$expected = (Get-Content "$exe.sha256").Split("  ")[0]
$actual   = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
if ($actual -eq $expected) { "OK — file matches" } else { "MISMATCH — do NOT use" }
```

On WSL / Linux / macOS, `sha256sum -c Stars-v1.5.16-Setup.exe.sha256` works directly.

> **What the hash file gives you — and what it doesn't:** The hash protects against tampered downloads (mirror modification, MITM). It does **not** replace code signing — you verify the authenticity of the source through the GitHub repo itself, not through the hash. Code signing is planned; see [`docs/codesigning.md`](docs/codesigning.md) for status.

> **Tested platforms:** Stars is verified against **Windows Server 2022 Standard** and **Windows Server 2025 Standard** (3-forest lab, 1000 test users, 5000 directories).
>
> **Use at your own risk. Make a full backup before any production use.** → [Full disclaimer](#disclaimer)

### What is Stars?

Stars is a **native Windows application** (`.exe`) for IT administrators and security auditors.

It consists of two programs:

| Program | Description |
|---------|-------------|
| `adpa-gui.exe` | Graphical interface (GUI) with Analyze, Scan, and Delta views |
| `adpa.exe` | Command-line interface (CLI) for scripting and automation |

Both programs analyze the same data and use the same permission logic.

### What does Stars analyze?

#### NTFS permissions

Stars reads Windows access control lists (ACLs) directly from the file system:

- Allow and Deny ACEs
- Explicit and inherited entries
- Inheritance breaks
- Owner special rule (owner always receives READ_CONTROL + WRITE_DAC)
- Reparse points, junctions, and symbolic links (without infinite loops)

#### Active Directory

Stars resolves users and groups via LDAP:

- Direct and transitive group memberships
- Full membership chain per group (`User → Group A → Group B`), not just "Member of B [transitive]"
- The user's primary group
- Disabled accounts
- Orphaned SIDs
- Cyclic group structures

#### SMB shares

Stars takes share permissions into account when computing effective access:

- Enumeration of all shares on a server
- NULL DACL (everyone has full access) vs. empty DACL (nobody has access) — Stars distinguishes both cases correctly
- Combined NTFS + share rights: `effective = NTFS ∩ Share`

#### Effective permissions

The core result is the permission that actually applies — with a complete explanation:

```
User max.muster → member of "Accounting" → member of "FileServer_Read"
→ Allow ACE [inherited] for FileServer_Read → NTFS: Read & Execute
→ Share permission: Change
→ Effective (NTFS ∩ Share): Read & Execute
```

### How is Stars started?

Stars is distributed as a **setup installer** on the [release page](https://github.com/Birgerson/stars-ad-permission-analyzer/releases) — currently `Stars-v1.5.16-Setup.exe`. The installer places the application under `C:\Program Files\Stars\`, adds a "Stars" start menu entry, and installs **no background services** and **no auto-start components**.

> **Note on code signing:** The installer is currently **not code-signed**. Windows SmartScreen will warn on first launch ("Windows protected your PC — unrecognized publisher"). A code-signing certificate is planned but not yet in place.

Developers and CI builds may also run the `.exe` files from `target/release/` (`adpa.exe`, `adpa-gui.exe`) directly after `cargo build --release` — the regular delivery path is and remains the installer.

**System requirements:**
- Windows 10 / Windows 11 / Windows Server
- Network access to the target file server (for SMB shares)
- LDAP access to Active Directory (optional, for full group resolution)
- Sufficient read rights on the paths to be analyzed

**Platform status:**

| Platform | Status |
|---|---|
| Windows Server 2022 Standard | ✅ verified — use at your own responsibility nonetheless |
| Windows Server 2025 Standard | ✅ verified (lab smoke test 2026-06-07) — use at your own responsibility |
| Windows 10 / 11, older Server versions | should work but not lab-verified — use at your own responsibility |

> "Verified" means the audit functions were exercised on that platform in the lab — it is **not a guarantee** of correctness, completeness, or fitness for any particular purpose. The full disclaimer is at the end of the document.

**Start the GUI:** Start menu → "Stars" (after installer), or run `C:\Program Files\Stars\adpa-gui.exe` directly.

**CLI:** The installer places `adpa.exe` in the same directory. For convenient calls without specifying the full path, add the directory to the `PATH` environment variable manually.

**CLI — analyze a single path:**
```
adpa.exe analyze --path "C:\Data\Department" --user S-1-5-21-...
```

**CLI — recursive scan of a directory tree:**
```
adpa.exe scan --path "C:\Data" --user S-1-5-21-... --max-depth 8
```

**CLI — with LDAP for full group resolution:**
```
set ADPA_BIND_PASSWORD=YourSecretPassword
adpa.exe analyze --path "\\server\share\Data" --user S-1-5-21-... ^
  --server dc.domain.local --base-dn "DC=domain,DC=local" ^
  --bind-dn "CN=SvcScan,CN=Users,DC=domain,DC=local"
```
> LDAP connects via LDAPS by default (port 636, encrypted).
> The password is passed through `ADPA_BIND_PASSWORD`, not as a CLI argument
> (CLI arguments are visible in process lists and shell history).
> For test environments without LDAPS, add `--insecure-ldap`.
>
> **Note for Windows Server 2025:** Server 2025 enforces LDAP signing by default
> (`rc=8 strongerAuthRequired` for unencrypted binds). To use `--insecure-ldap`
> against a 2025 target you would have to loosen this server-side — not advisable
> in production. For LDAPS, the DC needs a valid computer certificate (typically
> via AD CS); without a certificate the TLS handshake fails. Stars detects both
> cases and surfaces a clear diagnostic marker instead of silently returning
> incomplete results.

**CLI — UNC path with automatic share detection:**
```
adpa.exe analyze --path "\\fileserver\Accounting\Reports" --user S-1-5-21-...
```
Stars detects the UNC path automatically and factors the share permission into the calculation.

### GUI — the four tabs

Stars has exactly **four tabs:** `Analyze`, `Scan Tree`, `Delta`, `Info`. "Identity", "Trustees", and "Risk findings" are not separate tabs — they are sections inside the four real tabs.

#### `Analyze` tab

Returns the effective permission for **a single path**.

Inputs:
- **Path** (local or UNC) — pre-filled at startup with `C:\Windows\SYSVOL\sysvol` (the most important path to audit on any domain controller). Freely overwritable.
- **User/group** — plain-text name with live search (see "Identity input" below).
- **User SID** — populated by the name field; can also be entered directly.
- Optional: LDAP connection settings for group resolution (not needed on a DC — SAM/LSA is enough).

Actions:
- **Analyze** — identity-bound evaluation (NTFS and share rights, effective permission, full explanation chain).
- **Who has access?** — path-centric trustee table of all ACEs (NTFS and share separated).

#### `Scan Tree` tab

Scans a **whole directory tree** recursively.

Inputs:
- **Root path** (local or UNC) — pre-filled with `C:\Windows\SYSVOL\sysvol` like the `Analyze` tab.
- **User/group + SID** — same as `Analyze`, same live search.
- Optional: maximum depth, SMB server / share name, LDAP data.

Output:
- Table: Path | Permission | Mask, each row expandable with a complete explanation.
- Error log (access denied, not found, etc.).
- Filter by path substring.
- Risk findings section, color-coded by severity.
- HTML / JSON / CSV report export.

#### `Delta` tab

Compares two persisted scan runs and shows what has changed — not just the effective right, but also NTFS/share composition, status (e.g. `ReadFailed`), and diagnostic markers.

Inputs:
- "📂 Load scan history" reads from the local SQLite DB.
- Mark one run as "Old" and one as "New".

Output:
- List of path, change kind (Added / Removed / Changed), rights before and after.
- "Changed (...)" column names the concrete reasons (e.g. "NTFS mask + share status").
- Color code: green = Added, red = Removed, yellow = Changed.

#### `Info` tab

Version, platform status ("verified against Server 2022 and 2025"), license, AI authorship, and links to the online documentation. No interactive content.

### Identity input — name or SID

An auditor usually knows users by name, not by SID. Stars makes this easier in three ways:

#### 1. Live search in the name field

Type a few letters into the **"User/group"** field. A suggestion list with up to 15 matching identities appears directly underneath. Clicking an entry inserts the name and resolves the SID automatically.

The list is built once at app start from local NetAPI sources: domain users, global domain groups, local groups, well-known SIDs. No LDAP bind needed — SAM/LSA is enough on a DC.

**Type marker legend:**

| Marker | Meaning | Example |
|---|---|---|
| `[U]` | **User** — domain or local user account (`NetUserEnum`) | `[U] TESTDOMAIN\Administrator` |
| `[G]` | **Global (domain) group** (`NetGroupEnum`) | `[G] TESTDOMAIN\Domain Admins` |
| `[L]` | **Local group** (`NetLocalGroupEnum`, shown with `BUILTIN` authority in the UI) | `[L] BUILTIN\Administrators` |
| `[W]` | **Well-known identity** (audit-relevant standard SIDs from a built-in table) | `[W] NT AUTHORITY\Authenticated Users` |

#### 2. "🔍 Resolve SID" button

If you already know the full name, type it and click the button — or press **Enter** in the name field. The lookup goes through `LookupAccountNameW`, accepts both `Administrator` and `DOMAIN\Administrator`, and works for groups as well (`BUILTIN\Administrators`, `Everyone`).

#### 3. Direct SID input

If you have a SID copied from another tool (e.g. `S-1-5-21-1234-5678-…-500`), type it straight into the SID field. Works with or without the live search.

### CLI commands (overview)

```
adpa.exe analyze   — effective permission for a single path
adpa.exe scan      — recursive scan of a directory tree
adpa.exe --help    — full help with all options
```

Detailed invocation examples are above under "How is Stars started?".

### What Stars cannot do

Stars is deliberately limited to analysis. The following is **not** planned and will not be implemented:

- Change permissions
- Clean up ACLs
- Change group memberships
- Create, move, or delete files or folders on target systems
- Apply automated repair suggestions

### Project structure

Stars is built as a Rust workspace with several independent modules:

```
crates/
├── core/               — shared data types and traits
├── ad_resolver/        — Active Directory / LDAP connection
├── fs_scanner/         — NTFS ACL evaluation
├── share_scanner/      — SMB shares
├── permission_engine/  — effective rights computation
├── risk_engine/        — risk rules (6 implemented)
├── persistence/        — SQLite cache and scan history
├── exporter/           — CSV, JSON, HTML export
├── update_manager/     — secure update installation
├── validation/         — input validation
├── cli/                — command-line program (adpa.exe)
└── gui/                — graphical interface (adpa-gui.exe)
```

### Build

```powershell
cargo build --release -p cli   # adpa.exe
cargo build --release -p gui   # adpa-gui.exe
```

Prerequisite: [Rust Toolchain](https://rustup.rs/) for Windows (MSVC target).

### Database, scan history, and uninstallation

Stars persists its scan history in `%APPDATA%\Stars\stars_data.db` (SQLite, separate per user profile, survives uninstallation). Since v1.5.16 the database is **snapshot-stable** — historical reports no longer mutate when an identity is updated later.

→ **Full details:**
- [`docs/scan-historie-und-datenbank.md`](docs/scan-historie-und-datenbank.md) — location, tables, delta comparison, inspectability (DE + EN)
- [`docs/installation-und-deinstallation.md`](docs/installation-und-deinstallation.md) — installer steps, uninstaller behaviour, what stays and what goes (DE + EN)

### Documentation

- **[User Guide](docs/user-guide.md)** — step-by-step walkthrough of the GUI and CLI, every tab explained, identity input, AD binding, marker reading, FAQ. **Start here when using Stars for the first time.**
- **[Technical Documentation](docs/technical-documentation.md)** — how Stars works internally: architecture, crate layering, Principal pipeline, permission engine algorithm, diagnostic marker system, threading model. **Start here when reading or contributing code.**
- **[Features, limits and how to read the results](docs/features-and-limitations.md)** — what Stars reliably covers, what is deliberately out of scope, and how the diagnostic markers (`DomainGroupRecursionIncomplete`, `IdentityNotInConfiguredLdapBase`, …) should be read. **Start here when a finding is unexpected.** (Document is currently in German only.)
- **[Known limitations and roadmap (v1.6+)](docs/known-limitations.md)** — structural gaps (FSP, GC bind, SID history, cross-forest) that Stars flags but does not resolve. Roadmap tracking for future releases. (German only.)
- **[Audit Criteria and Evaluation Principles](docs/audit-kriterien.md)** — a complete write-up of which rules Stars uses to evaluate permissions, which risk rules are implemented, what severities they carry, and which permissions are considered optimal for which role.
- **[Architecture Decision Records (ADRs)](docs/adr/)** — historical justifications for individual technology and model decisions.
- **[Security Policy](SECURITY.md)** — how to report security vulnerabilities.

### About the project

**Concept, specification, direction, and review:**
**Birger Labinsch** — IT Specialist for Application Development / Prompt Engineer

**Implementation (Rust workspace, Slint GUI, engine, resolver, tests, documentation):**
**Claude Opus 4.7** (Anthropic) — as an AI model under direct guidance and continuous review by Birger Labinsch.

This attribution is deliberately transparent: Birger Labinsch did **not** write the code himself but, as a prompt engineer, directed the entire development process through the AI model — from architectural decisions to individual code changes to tests, bug fixes, and documentation. Every commit in this repository therefore also carries a `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>` line that makes the AI contribution visible per change.

<a name="disclaimer"></a>

### Disclaimer

Stars is provided **"as is"**, without any warranty of any kind, express or implied — including but not limited to fitness for a particular purpose, completeness, correctness of results, uninterrupted availability, or freedom from defects.

Use is **at the user's sole risk** — on **all** platforms, including those marked as "verified" in this README. The "verified" marker only states that manual functional checks were performed on the named platform; it is **not a guarantee** and **not proof** of correctness or suitability for any particular production environment.

**Birger Labinsch assumes no liability whatsoever** for:

- Material or immaterial damage arising from use or non-use of Stars
- Data loss, faulty audit results, or business decisions derived from them
- Security incidents that went undetected because of incomplete or faulty permission evaluation
- Consequences of applying the documented audit criteria in unsuitable environments
- Incompatibilities with other software, drivers, security products, or domain configurations
- Any indirect or direct consequential damages

The user is required to verify Stars' fitness for their specific use case before production use **themselves** and to safeguard the results through suitable control measures.

#### Mandatory backup before use

Stars is designed as a **read-only analysis tool** and, per its architecture, does not write to NTFS permissions, SMB shares, AD objects, or files and folders on target systems (see [`docs/known-limitations.md`](docs/known-limitations.md) for the list of deliberate architectural decisions). This architectural commitment is, however, **not a guarantee** against every conceivable side effect — for example through incompatibilities, driver bugs, antivirus interference, locking conflicts, logging side effects, or unintended load on target systems.

**The user is therefore required to create a complete, tested backup of all affected systems and data before each use of Stars in a production or production-like environment** — including domain controllers, file servers, NTFS volumes, and SMB share configurations. This applies **even though** Stars per its architecture and documentation only reads. Birger Labinsch assumes **no liability whatsoever** for data loss, configuration damage, or operational outages caused or worsened by missing, incomplete, or untested backups.

Additionally verify:
- that backup restoration works in an **isolated test environment**,
- that Stars has first been evaluated in a test or pilot environment before being applied to production systems,
- that all relevant stakeholders (operations, security, compliance teams) are informed before use.

### License

**GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)** — see [LICENSE](LICENSE).

In short: Stars may be used, studied, modified, and redistributed freely. Anyone who offers Stars (or a derived fork) as a network service must make the complete source code of that modified variant publicly available. Purely private or internal use is not affected.
