# Stars — AD Permission Analyzer

[![Latest Release](https://img.shields.io/github/v/release/Birgerson/Stars?include_prereleases&label=Release&color=4fc3f7)](https://github.com/Birgerson/Stars/releases)
[![CI](https://github.com/Birgerson/Stars/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/Birgerson/Stars/actions/workflows/ci.yml)

[**Deutsch**](#deutsch) · [**English**](#english)

---

## <a name="deutsch"></a>Deutsch

**Stars** ist ein Windows-Analysetool für Active-Directory-Berechtigungen, NTFS-Zugriffsrechte und SMB-Freigaben.

Das Tool zeigt für jeden Benutzer, welche effektiven Zugriffsrechte er tatsächlich auf Ordner und Dateien hat — inklusive vollständiger Erklärung, über welche Gruppen und ACL-Einträge diese Rechte zustande kommen.

> **Stars ist ausschließlich ein Lese- und Analysetool. Es verändert keine Berechtigungen, Gruppen oder AD-Objekte.**

### Download

Den aktuellen Windows-Installer gibt es auf der **[Releases-Seite](https://github.com/Birgerson/Stars/releases)**.

1. Auf den neuesten Release klicken (oben in der Liste).
2. `Stars-vX.Y.Z-Setup.exe` unter *Assets* herunterladen.
3. Doppelklick — keine Administratorrechte erforderlich. Ein **Stars**-Symbol erscheint auf dem Desktop.

Systemvoraussetzungen: Windows 10, Windows 11 oder Windows Server. Keine weitere Laufzeitumgebung nötig.

> **Getestete Plattform:** Stars ist gegen **Windows Server 2022 Standard** getestet.
> **Windows Server 2025 wurde bisher nicht geprüft.**
>
> **Haftungsausschluss:** Die Nutzung von Stars erfolgt **immer auf eigene Verantwortung** — auf allen Plattformen, auch auf den getesteten. Birger Labinsch übernimmt **keine Haftung** für Schäden, Datenverluste, falsche Audit-Ergebnisse oder Folgen aus der Nutzung dieser Software. Siehe Abschnitt „Haftungsausschluss" am Ende dieses Dokuments.

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
- Konkreter, geordneter Mitgliedschafts­pfad pro Gruppe (`User → Group A → Group B`) im Erklärungstext, nicht nur „Member of B [transitive]"
- Primärgruppe des Benutzers
- Deaktivierte Konten
- Verwaiste SIDs
- Zyklische Gruppenstrukturen

#### SMB-Freigaben

Stars berücksichtigt Share-Berechtigungen bei der Berechnung:

- Enumeration aller Freigaben auf einem Server
- NULL DACL vs. leere DACL (kein Unterschied in der Anzeige, aber korrektes Verhalten)
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

Stars wird über den **signierten Setup-Installer** auf der [Release-Seite](https://github.com/Birgerson/stars-ad-permission-analyzer/releases) bereitgestellt — aktuell `Stars-v1.5.3-Setup.exe`. Der Installer legt die Anwendung nach `C:\Program Files\Stars\` ab, erstellt einen Start-Menü-Eintrag „Stars" und richtet keine Hintergrunddienste oder Auto-Start-Komponenten ein.

Für Entwickler und CI-Builds können die `.exe`-Dateien aus `target/release/` (`adpa.exe`, `adpa-gui.exe`) nach `cargo build --release` auch ohne Installer direkt gestartet werden — der produktive Auslieferungsweg bleibt der Installer.

**Systemvoraussetzungen:**
- Windows 10 / Windows 11 / Windows Server
- Netzwerkzugriff auf den Ziel-Dateiserver (für SMB-Freigaben)
- LDAP-Zugriff auf Active Directory (optional, für vollständige Gruppenauflösung)
- Ausreichende Leserechte auf die zu analysierenden Pfade

**Plattformstatus:**

| Plattform | Status |
|---|---|
| Windows Server 2022 Standard | ✅ getestet — Nutzung trotzdem auf eigene Verantwortung |
| Windows Server 2025 | ⚠ noch nicht geprüft — Nutzung auf eigene Verantwortung |
| Windows 10 / 11, ältere Server-Versionen | Implementierungsziel, nicht systematisch verifiziert — Nutzung auf eigene Verantwortung |

> Der Vermerk „getestet" bedeutet, dass die Audit-Funktionen auf dieser Plattform durchlaufen wurden — er ist **keine Garantie** auf Korrektheit, Vollständigkeit oder Eignung für einen bestimmten Zweck. Vollständiger Haftungsausschluss am Ende des Dokuments.

**GUI starten:** Start-Menü → „Stars" (nach Installer), oder direkt `C:\Program Files\Stars\adpa-gui.exe`.

**CLI:** Die Setup-Installation legt `adpa.exe` im selben Verzeichnis ab. Für komfortable PATH-Nutzung kann das Verzeichnis manuell in die `PATH`-Umgebungsvariable aufgenommen werden.

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

**CLI — UNC-Pfad mit automatischer Share-Erkennung:**
```
adpa.exe analyze --path "\\fileserver\Buchhaltung\Bilanzen" --user S-1-5-21-...
```
Stars erkennt den UNC-Pfad automatisch und bezieht die Share-Berechtigung in die Berechnung ein.

### GUI — Ansichten

#### Analyze-Tab

Gibt die effektive Berechtigung für **einen einzelnen Pfad** zurück.

Eingaben:
- **Pfad** (lokal oder UNC) — beim Start vorbelegt mit `C:\Windows\SYSVOL\sysvol` (der audit-relevanteste Pfad auf einer Standard-DC). Frei überschreibbar.
- **Benutzer/Gruppe** — Klartextname mit Live-Suche (siehe „Benutzereingabe" unten)
- **Benutzer-SID** — wird vom Namensfeld befüllt, kann auch direkt eingegeben werden
- Optional: LDAP-Verbindungsdaten für Gruppenauflösung (auf einem DC nicht nötig — die SAM/LSA reicht)

Ausgabe:
- NTFS-Berechtigung, Share-Berechtigung (falls vorhanden), effektive Berechtigung
- Vollständiger Berechtigungspfad mit allen Schritten

#### Scan Tree-Tab

Scannt einen **gesamten Verzeichnisbaum** rekursiv.

Eingaben:
- **Wurzelpfad** (lokal oder UNC) — wie Analyze-Tab mit `C:\Windows\SYSVOL\sysvol` vorbelegt
- **Benutzer/Gruppe + SID** — wie Analyze-Tab, dieselbe Live-Suche
- Optional: maximale Tiefe, SMB-Server/Share-Name, LDAP-Daten

Ausgabe:
- Tabelle: Pfad | Berechtigung | Maske
- Jede Zeile aufklappbar mit vollständiger Erklärung (Klartextnamen statt nur SIDs)
- Fehlerprotokoll (Zugriff verweigert, nicht gefunden etc.)
- Filter nach Pfad-Teilstring
- Risikobefunde mit Severity-Farbcode
- HTML-Bericht-Export

#### Delta-Tab

Vergleicht zwei persistierte Scan-Läufe und zeigt, was sich verändert hat.

Eingaben:
- „📂 Scan-Historie laden" liest aus der lokalen SQLite-DB
- Je eine Zeile als „Alt" und „Neu" anhaken

Ausgabe:
- Liste mit Pfad, Änderungsart (Hinzugefügt / Entfernt / Geändert), Rechte vorher/nachher
- Farbcode: grün = Hinzugefügt, rot = Entfernt, gelb = Geändert
- Zähl-Headline pro Lauf

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
| `[W]` | **Well-Known-Identität** (hartcodierte audit-relevante SIDs) | `[W] NT AUTHORITY\Authenticated Users` |

#### 2. „🔍 SID auflösen"-Button

Wenn du den vollen Namen bereits weißt, tippe ihn ein und klick den Button — oder drück **Enter** im Namensfeld. Der Lookup läuft über `LookupAccountNameW`, akzeptiert beide Formen `Administrator` und `DOMÄNE\Administrator` und arbeitet auch für Gruppen (`BUILTIN\Administratoren`, `Everyone`).

#### 3. Direkte SID-Eingabe

Wer eine SID aus einem anderen Tool kopiert hat (z.B. `S-1-5-21-1234-5678-…-500`), tippt sie direkt ins SID-Feld. Funktioniert mit oder ohne Live-Suche.

### CLI-Befehle

```
adpa.exe scan      — Pfad analysieren
adpa.exe shares    — Freigaben auf einem Server auflisten
adpa.exe help      — Hilfe anzeigen
```

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

### Datenbank und gespeicherte Daten

Stars persistiert seine Scan-Historie in einer **SQLite-Datenbank**, damit der Delta-Tab zwei Läufe vergleichen kann und Identitäts­auflösungen über mehrere Sessions zwischengespeichert sind.

**Standort:**

```
%APPDATA%\Stars\stars_data.db
```

Auf einem typischen Windows-Server-DC ist das:

```
C:\Users\<Anwender>\AppData\Roaming\Stars\stars_data.db
```

Falls `%APPDATA%` nicht gesetzt ist, fällt die Anwendung auf das Verzeichnis der EXE zurück (relevant nur für `cargo run` während der Entwicklung).

**Was drin gespeichert wird:**

| Tabelle | Inhalt |
|---|---|
| `scan_runs` | Eine Zeile pro abgeschlossenem Scan: UUID, Startzeit, Endzeit, Zielpfad |
| `permissions` | Alle ausgewerteten Pfade pro Lauf mit Identität, NTFS-Maske, Share-Maske, effektiver Maske, Erklärungspfad |
| `scan_errors` | Walk- und Eval-Fehler pro Scan (z.B. „Access denied", „Path not found") |
| `identity_cache` | SAM-/LDAP-Auflösungs-Cache (SID → Name, Domäne, Gruppenmitgliedschaften) |

**Eigenschaften:**

* Wird beim ersten Start automatisch angelegt; Migrations­skripte (Schema v1 → aktuelle Version) laufen idempotent durch.
* **Pro Benutzer­profil getrennt** — jeder Windows-User hat seine eigene Historie.
* **Überlebt eine Deinstallation** — der Installer entfernt nur sein Install-Verzeichnis, die Audit-Historie bleibt erhalten. Wer die Historie loswerden will, löscht den Ordner `%APPDATA%\Stars\` manuell.
* **Kein Passwort, keine Verschlüsselung.** Wer Zugriff auf das Benutzer­profil hat, kann die Daten lesen. Für sensible Audit-Daten den Profilpfad selbst entsprechend absichern.
* **Inspizierbar mit jedem SQLite-Tool** (DB Browser for SQLite, DBeaver, `sqlite3.exe`) — read-only, ohne dass Stars läuft.

Schlägt das Öffnen oder Schreiben fehl (Schreibrechte, Plattenplatz), läuft der Scan trotzdem durch; die Persistenz-Meldung erscheint als Fehler in der Statuszeile, damit der Befund nicht still unter den Tisch fällt.

### Deinstallation

Stars wird über **„Programme und Features"** (`appwiz.cpl`) oder den Startmenü-Eintrag **„Stars deinstallieren"** entfernt. Der Uninstaller läuft im aktuellen Benutzerprofil — Administratorrechte sind nicht nötig.

**Vor der Deinstallation:** Stars beenden. Wenn `Stars.exe` noch läuft, bricht der Uninstaller mit einem Hinweis ab statt teilweise zu scheitern.

**Standardmäßig entfernt der Uninstaller:**
- `%LOCALAPPDATA%\Stars\` (Programmverzeichnis, Verknüpfungen, Uninstaller selbst)
- Den Eintrag in „Programme und Features"

**Standardmäßig bleibt erhalten:**
- `%APPDATA%\Stars\stars_data.db` (Scan-Historie, Identitäts-Cache)
- `%LOCALAPPDATA%\Stars\logs\` (Logfiles der GUI)

Beide überleben damit eine Neuinstallation — die Audit-Historie ist Beweismittel und sollte nicht versehentlich mit dem Tool verloren gehen.

**Wer alles vollständig entfernen will:** auf der Komponenten-Seite des Uninstallers die zusätzliche Option **„Audit-Historie und Logs entfernen"** anhaken. Diese ist bewusst standardmäßig **deaktiviert** — die Entscheidung soll explizit gefällt werden.

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

### Haftungsausschluss

Stars wird ausschließlich **„wie besehen"** („as is") zur Verfügung gestellt, ohne ausdrückliche oder stillschweigende Zusicherung jeglicher Art — einschließlich, aber nicht beschränkt auf Eignung für einen bestimmten Zweck, Vollständigkeit, Korrektheit der Ergebnisse, ununterbrochene Verfügbarkeit oder Fehlerfreiheit.

Die Nutzung erfolgt **ausschließlich auf eigene Verantwortung des Anwenders** — auf **allen** Plattformen, auch auf denen, die in dieser README als „getestet" markiert sind. Der Vermerk „getestet" beschreibt lediglich, dass auf der genannten Plattform manuelle Funktionsprüfungen durchgeführt wurden; er ist **keine Zusicherung** und **kein Beleg** für Korrektheit oder Eignung in einer bestimmten produktiven Umgebung.

**Birger Labinsch übernimmt keinerlei Haftung** für:

- Schäden materieller oder immaterieller Art, die durch die Nutzung oder Nicht-Nutzung von Stars entstehen
- Datenverluste, fehlerhafte Audit-Ergebnisse oder daraus abgeleitete Geschäfts­entscheidungen
- Sicherheitsvorfälle, die durch unvollständige oder fehlerhafte Berechtigungs­auswertung nicht erkannt wurden
- Folgen aus der Anwendung der dokumentierten Audit-Kriterien auf nicht dafür vorgesehene Umgebungen
- Inkompatibilitäten mit anderer Software, Treibern, Sicherheits­lösungen oder Domain-Konfigurationen
- jegliche mittelbaren oder unmittelbaren Folgeschäden

Der Anwender ist verpflichtet, die Eignung von Stars für seinen konkreten Einsatz­zweck vor produktiver Nutzung **selbst zu prüfen** und die Ergebnisse durch geeignete Kontroll­maßnahmen abzusichern.

### Lizenz

MIT License — siehe [LICENSE](LICENSE).

---

## <a name="english"></a>English

**Stars** is a Windows analysis tool for Active Directory permissions, NTFS access rights, and SMB shares.

For every user, the tool shows the effective access rights that actually apply to folders and files — including a complete explanation of which groups and ACL entries grant those rights.

> **Stars is exclusively a read-and-analyze tool. It does not modify any permissions, groups, or AD objects.**

### Download

Get the current Windows installer from the **[Releases page](https://github.com/Birgerson/Stars/releases)**.

1. Click the latest release at the top of the list.
2. Download `Stars-vX.Y.Z-Setup.exe` from *Assets*.
3. Double-click — no administrator rights required. A **Stars** icon appears on the desktop.

System requirements: Windows 10, Windows 11, or Windows Server. No additional runtime needed.

> **Tested platform:** Stars is verified against **Windows Server 2022 Standard**.
> **Windows Server 2025 has not been verified yet.**
>
> **Disclaimer:** Use of Stars is **always at your own risk** — on all platforms, including the tested ones. Birger Labinsch assumes **no liability** for damages, data loss, incorrect audit results, or any consequences arising from the use of this software. See the "Disclaimer" section at the end of this document.

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
- Concrete ordered membership chain per group (`User → Group A → Group B`) in the explanation text, not just "Member of B [transitive]"
- The user's primary group
- Disabled accounts
- Orphaned SIDs
- Cyclic group structures

#### SMB shares

Stars takes share permissions into account when computing effective access:

- Enumeration of all shares on a server
- NULL DACL vs. empty DACL (no visible difference, but correct behavior)
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

Stars is distributed as a **signed setup installer** on the [release page](https://github.com/Birgerson/stars-ad-permission-analyzer/releases) — currently `Stars-v1.5.3-Setup.exe`. The installer places the application under `C:\Program Files\Stars\`, adds a "Stars" start menu entry, and configures no background services or auto-start components.

Developers and CI builds may also run the `.exe` files from `target/release/` (`adpa.exe`, `adpa-gui.exe`) directly after `cargo build --release` — the production delivery path remains the installer.

**System requirements:**
- Windows 10 / Windows 11 / Windows Server
- Network access to the target file server (for SMB shares)
- LDAP access to Active Directory (optional, for full group resolution)
- Sufficient read rights on the paths to be analyzed

**Platform status:**

| Platform | Status |
|---|---|
| Windows Server 2022 Standard | ✅ tested — use at your own responsibility nonetheless |
| Windows Server 2025 | ⚠ not yet verified — use at your own responsibility |
| Windows 10 / 11, older Server versions | Implementation target, not systematically verified — use at your own responsibility |

> "Tested" means the audit functions were exercised on that platform — it is **not a guarantee** of correctness, completeness, or fitness for any particular purpose. The full disclaimer is at the end of the document.

**Start the GUI:** Start menu → "Stars" (after installer), or run `C:\Program Files\Stars\adpa-gui.exe` directly.

**CLI:** The installer places `adpa.exe` in the same directory. For convenient PATH usage you can add the directory to the `PATH` environment variable manually.

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

**CLI — UNC path with automatic share detection:**
```
adpa.exe analyze --path "\\fileserver\Accounting\Reports" --user S-1-5-21-...
```
Stars detects the UNC path automatically and factors the share permission into the calculation.

### GUI — Views

#### Analyze tab

Returns the effective permission for **a single path**.

Inputs:
- **Path** (local or UNC) — pre-filled at startup with `C:\Windows\SYSVOL\sysvol` (the most audit-relevant path on a default DC). Freely overwritable.
- **User/group** — plain-text name with live search (see "Identity input" below)
- **User SID** — populated by the name field; can also be entered directly
- Optional: LDAP connection settings for group resolution (not needed on a DC — SAM/LSA is enough)

Output:
- NTFS permission, share permission (if available), effective permission
- Full permission path with every step

#### Scan Tree tab

Scans a **whole directory tree** recursively.

Inputs:
- **Root path** (local or UNC) — pre-filled with `C:\Windows\SYSVOL\sysvol` like the Analyze tab
- **User/group + SID** — same as Analyze, same live search
- Optional: maximum depth, SMB server / share name, LDAP data

Output:
- Table: Path | Permission | Mask
- Each row is expandable with a complete explanation (plain-text names instead of just SIDs)
- Error log (access denied, not found, etc.)
- Filter by path substring
- Risk findings color-coded by severity
- HTML report export

#### Delta tab

Compares two persisted scan runs and shows what has changed.

Inputs:
- "📂 Load scan history" reads from the local SQLite DB
- Mark one run as "Old" and one as "New"

Output:
- List of path, change kind (Added / Removed / Changed), rights before and after
- Color code: green = Added, red = Removed, yellow = Changed
- Count headline per run

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
| `[W]` | **Well-known identity** (hard-coded audit-relevant SIDs) | `[W] NT AUTHORITY\Authenticated Users` |

#### 2. "🔍 Resolve SID" button

If you already know the full name, type it and click the button — or press **Enter** in the name field. The lookup goes through `LookupAccountNameW`, accepts both `Administrator` and `DOMAIN\Administrator`, and works for groups as well (`BUILTIN\Administrators`, `Everyone`).

#### 3. Direct SID input

If you have a SID copied from another tool (e.g. `S-1-5-21-1234-5678-…-500`), type it straight into the SID field. Works with or without the live search.

### CLI commands

```
adpa.exe scan      — analyze a path
adpa.exe shares    — list shares on a server
adpa.exe help      — show help
```

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

### Database and stored data

Stars persists its scan history in a **SQLite database** so the Delta tab can compare two runs and identity resolutions are cached across sessions.

**Location:**

```
%APPDATA%\Stars\stars_data.db
```

On a typical Windows Server DC this is:

```
C:\Users\<account>\AppData\Roaming\Stars\stars_data.db
```

If `%APPDATA%` is not set, the application falls back to the directory next to the EXE (only relevant for `cargo run` during development).

**What is stored:**

| Table | Content |
|---|---|
| `scan_runs` | One row per completed scan: UUID, start time, end time, target path |
| `permissions` | Every evaluated path per run with identity, NTFS mask, share mask, effective mask, explanation path |
| `scan_errors` | Walk and eval errors per scan (e.g. "Access denied", "Path not found") |
| `identity_cache` | SAM/LDAP resolution cache (SID → name, domain, group memberships) |

**Properties:**

* Created automatically on first start; migration scripts (schema v1 → current) run idempotently.
* **Separate per user profile** — every Windows user has their own history.
* **Survives uninstallation** — by default the uninstaller removes only its install directory; the audit history stays. To get rid of it, delete `%APPDATA%\Stars\` manually, or use the uninstaller's optional component (see below).
* **No password, no encryption.** Anyone with access to the user profile can read the data. Protect the profile path itself (NTFS permissions, BitLocker) for sensitive audit data.
* **Inspectable with any SQLite tool** (DB Browser for SQLite, DBeaver, `sqlite3.exe`) — read-only, without Stars running.

If opening or writing fails (write permissions, disk space), the scan still runs but the persistence message appears as an error in the status bar so the finding does not silently disappear.

### Uninstallation

Stars is removed via **"Programs and Features"** (`appwiz.cpl`) or the start menu entry **"Stars deinstallieren"**. The uninstaller runs in the current user profile — administrator rights are not required.

**Before uninstalling:** close Stars. If `Stars.exe` is still running, the uninstaller aborts with a notice instead of failing partway.

**By default, the uninstaller removes:**
- `%LOCALAPPDATA%\Stars\` (program directory, shortcuts, uninstaller itself)
- The "Programs and Features" entry

**By default, the uninstaller keeps:**
- `%APPDATA%\Stars\stars_data.db` (scan history, identity cache)
- `%LOCALAPPDATA%\Stars\logs\` (GUI log files)

Both therefore survive a reinstall — the audit history is evidence and should not vanish accidentally with the tool.

**To remove everything completely:** on the uninstaller's component page, check the additional **"Audit-Historie und Logs entfernen"** option. It is deliberately **off by default** — the decision must be made explicitly.

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

### Disclaimer

Stars is provided **"as is"**, without any warranty of any kind, express or implied — including but not limited to fitness for a particular purpose, completeness, correctness of results, uninterrupted availability, or freedom from defects.

Use is **at the user's sole risk** — on **all** platforms, including those marked as "tested" in this README. The "tested" marker only states that manual functional checks were performed on the named platform; it is **not a guarantee** and **not proof** of correctness or suitability for any particular production environment.

**Birger Labinsch assumes no liability whatsoever** for:

- Material or immaterial damage arising from use or non-use of Stars
- Data loss, faulty audit results, or business decisions derived from them
- Security incidents that went undetected because of incomplete or faulty permission evaluation
- Consequences of applying the documented audit criteria in unsuitable environments
- Incompatibilities with other software, drivers, security products, or domain configurations
- Any indirect or direct consequential damages

The user is required to verify Stars' fitness for their specific use case before production use **themselves** and to safeguard the results through suitable control measures.

### License

MIT License — see [LICENSE](LICENSE).
