# Stars — Anwender-Handbuch

**Version:** v1.5.11 (2026-06-05)
**Zielgruppe:** Windows-/AD-Administrator:innen, die NTFS- und
SMB-Berechtigungen auditieren wollen, ohne dabei etwas zu verändern.

> **Read-only-Prinzip:** Stars schreibt **nichts** an NTFS, SMB-Shares
> oder Active Directory. Es ist ein reines Analyse-, Anzeige- und
> Exportwerkzeug. Die produktive Behebung erkannter Probleme bleibt in
> Ihrer Hand.

---

## Inhaltsverzeichnis

1. [Was kann Stars?](#was-kann-stars)
2. [Installation und Voraussetzungen](#installation-und-voraussetzungen)
3. [Erster Start — die GUI](#erster-start--die-gui)
4. [Die fünf Tabs der GUI](#die-fünf-tabs-der-gui)
5. [Identitäten eingeben](#identitäten-eingeben)
6. [Active Directory anbinden (optional)](#active-directory-anbinden-optional)
7. [Lokale Pfade vs. SMB-Freigaben](#lokale-pfade-vs-smb-freigaben)
8. [Befunde lesen — die Diagnose-Marker](#befunde-lesen--die-diagnose-marker)
9. [Exportieren — CSV, JSON, HTML](#exportieren--csv-json-html)
10. [Die CLI](#die-cli)
11. [Wo werden Daten gespeichert?](#wo-werden-daten-gespeichert)
12. [Updates](#updates)
13. [Häufige Fragen](#häufige-fragen)
14. [Weiterführende Dokumente](#weiterführende-dokumente)

---

## Was kann Stars?

Stars beantwortet zwei Audit-Kernfragen für einen gegebenen NTFS-Pfad
oder eine SMB-Freigabe:

1. **„Was darf dieser Benutzer hier effektiv?"** — pro Pfad ein
   erklärbarer Befund (Read / Write / Modify / Full Control) mit
   einem nachvollziehbaren Berechtigungspfad.
2. **„Wer hat überhaupt Zugriff auf diesen Pfad?"** — pro Pfad eine
   Liste der Trustees (Benutzer/Gruppen), getrennt nach NTFS- und
   Share-DACL.

Stars wertet dafür aus:

- **Active Directory** (per LDAP-Bind): Identitäten, rekursive
  Gruppenmitgliedschaften (auch Cross-Domain mit Trust-Erkennung),
  primäre Gruppen, `userAccountControl` (Konto deaktiviert).
- **Lokale Server-Gruppen** auf dem Zielserver der Freigabe
  (`BUILTIN\Administrators`, lokale benutzerdefinierte Gruppen).
- **NTFS-DACL** aller Pfade — Allow- und Deny-ACEs, explizite und
  geerbte Einträge, Vererbungsflags, Owner.
- **SMB-Share-DACL** und kombiniert das restriktiver mit der
  NTFS-Maske (Share ∩ NTFS).
- **Reparse Points / Junctions / Symlinks** — werden gefolgt, Schleifen
  erkannt.
- **Lange Pfade** (`\\?\…`, UNC-Long-Path `\\?\UNC\…`).

Für jeden Befund baut Stars **strukturierte Diagnose-Marker** auf,
wenn Annahmen unsicher sind — der Bericht zeigt nie nur ein Recht,
sondern auch, was Stars dabei gewusst oder *nicht gewusst* hat.

### Was Stars **nicht** macht (per Design)

- Berechtigungen ändern (weder NTFS, noch Share, noch AD).
- AD-Konten oder Gruppenmitgliedschaften ändern.
- Dateien oder Ordner anlegen, verschieben, löschen.
- ACL-Reparatur, Berechtigungs-Cleanup, Remediation-Workflows.
- Automatische Empfehlungen umsetzen.
- Dateiinhalte öffnen (auch nicht zum Suchen nach Passwörtern; Dateien
  mit verdächtigen Namen werden nur **markiert**, nicht gelesen).

Eine ausführliche Liste steht in
[features-and-limitations.md](features-and-limitations.md).

---

## Installation und Voraussetzungen

### Voraussetzungen

- **Windows 10 / 11** oder **Windows Server 2019 / 2022 / 2025**.
- Für volle Funktion: **Domain-Mitgliedschaft** oder zumindest ein
  AD-Lesekonto.
- Mindestens **Lese-DACL-Berechtigung** auf den zu analysierenden
  Pfaden (oder das `SeBackupPrivilege`).
- Empfohlen: Stars als Konto mit Lese-Privilegien starten, **nicht**
  als Administrator.

### Download

Setup-Datei vom GitHub-Release herunterladen:
[releases](https://github.com/Birgerson/stars-ad-permission-analyzer/releases).
Aktuell empfohlen: `Stars-v1.5.11-Setup.exe`.

### Installation

1. Doppelklick auf die Setup-Datei.
2. Standard-Installationspfad: `C:\Program Files\Stars\`.
3. Es wird ein Startmenü-Eintrag „Stars" angelegt.
4. **Keine** Treiber, **keine** Dienste, **keine** Auto-Start-
   Komponenten — Stars läuft nur, solange Sie es starten.

### Erststart

Beim ersten Start legt Stars die Scan-Historie unter
`%APPDATA%\Stars\stars_data.db` an (SQLite-Datei, nur Sie haben
Lesezugriff).

---

## Erster Start — die GUI

Nach dem Start erscheint das Hauptfenster mit fünf Tabs. **Empfohlener
Erst-Workflow:**

1. **Tab „Identität"** — Wählen oder eingeben, *wer* analysiert werden
   soll.
2. **Tab „Analyze"** — Einzelnen Pfad eingeben, „Analyze" drücken.
3. Ergebnis lesen: das effektive Recht, die Erklärung, die
   Diagnose-Marker.

Wer schnell sehen will, was Stars überhaupt kann, beginnt mit einem
beliebigen lokalen Ordner und der eigenen User-SID — das funktioniert
ohne LDAP-Konfiguration und zeigt die Engine in Aktion.

---

## Die fünf Tabs der GUI

### Tab „Analyze" — Einzelpfad-Analyse

**Wofür:** Sie haben einen konkreten Pfad und wollen wissen, was ein
bestimmter Benutzer dort effektiv darf.

**Felder:**

- **Pfad** — lokal (`C:\data\…`) oder UNC (`\\server\share\…`).
- **User** — siehe [Identitäten eingeben](#identitäten-eingeben).
- **SMB-Server** und **Share-Name** (optional) — werden bei
  UNC-Pfaden automatisch erkannt. Bei lokalen Pfaden auf einer Freigabe
  manuell setzen, wenn Sie zusätzlich die Share-Maske auswerten wollen.
- **Analyze** — startet die Auswertung.

**Ergebnis:** ein Bericht pro Pfad mit:

- effektivem Recht (Read / Write / Modify / Full Control),
- NTFS- und Share-Recht getrennt,
- erklärbarem Berechtigungspfad
  (`User → Gruppe → … → ACE → normalisiertes Recht`),
- allen Diagnose-Markern.

### Tab „Scan" — Rekursiver Verzeichnis-Scan

**Wofür:** Sie wollen einen kompletten Verzeichnisbaum analysieren —
typisch für die Periodische Audit-Frage „wie sieht Q3 jetzt aus?".

**Felder:**

- **Wurzelpfad**, **User**, **SMB-Server**/**Share-Name** wie bei
  Analyze.
- **Maximale Scan-Tiefe** — schützt vor Endlos-Walks; leer = unbegrenzt.
- **Scan starten** — der Scan ist jederzeit über das **Cancel**-Symbol
  abbrechbar; die GUI bleibt während des Scans bedienbar.

**Ergebnis:** Tabelle mit allen Pfaden, ihren effektiven Rechten, und
einer eigenen Trustee-Tabelle pro Pfad. Das Ergebnis wird automatisch
in die Scan-Historie (SQLite) persistiert.

### Tab „Trustees" — Wer-hat-Zugriff-Sicht

**Wofür:** Anders als Analyze (das einen Benutzer pro Pfad zeigt)
listet Trustees pro Pfad **alle** Trustees mit ihren ACEs auf — NTFS
und Share getrennt mit `TrusteeCategory::Ntfs` / `Share`-Spalte.

**Bei SMB-Pfaden:** Stars liest die Share-DACL einmal und zeigt sie
zusätzlich zu den NTFS-Einträgen. Lesefehler werden als sichtbare
Pseudo-Zeile dargestellt — kein stilles Weglassen.

### Tab „Delta" — Was hat sich geändert?

**Wofür:** Zwei Scan-Läufe gegeneinander vergleichen. Stars zeigt
pro Pfad, was sich am effektiven Recht geändert hat.

**Felder:**

- **Linker Lauf** und **Rechter Lauf** aus der Scan-Historie wählen.
- **Vergleichen** — zeigt Tabelle mit `Vorher → Nachher` pro Pfad.

Pfade ohne Änderung werden ausgeblendet, damit nur das Relevante übrig
bleibt.

### Tab „Risk" — Risikoregeln und Findings

**Wofür:** Stars wendet sechs eingebaute Risikoregeln auf jeden Befund
an:

- **FullControlRule** (Critical) — User hat Full Control.
- **WriteAccessRule** (High) — User hat Schreibrechte.
- **AdminRightsRule** (High) — User trägt Admin-relevante Rechte
  (TakeOwnership, WriteDAC).
- **BroadGroupWriteRule** (Medium) — Schreibrechte über breite Gruppe
  (`Everyone`, `Authenticated Users`).
- **DirectUserAceRule** (Low) — direkter ACE auf User (nicht über
  Gruppe).
- **SensitivePathRule** (Variabel) — Pfad enthält sensitive
  Schlüsselwörter (`password`, `credentials`, …).

Findings tragen `incomplete = true`, wenn der zugrundeliegende Befund
unvollständig ist — siehe Diagnose-Marker.

---

## Identitäten eingeben

Stars akzeptiert **fünf Eingabeformen** und routet sie durch *dieselbe*
zentrale Pipeline:

| Form | Beispiel | Wann sinnvoll? |
| --- | --- | --- |
| `DOMAIN\user` | `CORP\alice` | Domain explizit, eindeutig, auch in Multi-Domain. |
| UPN | `alice@corp.local` | Standard für moderne AD-Umgebungen. |
| `sAMAccountName` | `alice` | Schnell, scheitert bei Mehrdeutigkeit (zwei `alice` in unterschiedlichen Domains). |
| SID | `S-1-5-21-…-1001` | Direkter Pfad, funktioniert auch offline. |
| Display-Name (nur GUI) | „Alice Beispiel" | Die GUI-Identitätssuche schlägt vor; Stars löst auf zur SID. |

**Whitespace wird automatisch entfernt** (gilt seit v1.5.2 für alle
Eingabewege).

**Mehrdeutige `sAMAccountName`-Eingaben** ergeben einen klaren
Fehler — Stars bittet Sie, `DOMAIN\user` oder UPN zu nutzen, statt
still den ersten Treffer zu wählen.

**UPN außerhalb der konfigurierten LDAP-Base** ergibt einen klaren
Fehler mit Hinweis, gegen den Global Catalog (Port 3268) zu binden
oder `DOMAIN\user` zu nutzen.

### Vorschlagsliste im GUI-Identitätspicker — was zeigt sie, was nicht?

Wenn Sie im GUI-Feld „Benutzer/Gruppe" Zeichen tippen, erscheint eine
Vorschlagsliste mit Treffern. **Diese Liste enthält ausschließlich
lokale Identitäten** (die Markierung `[L]` links steht für *Local*):

- lokale Benutzer (`Administrator`, `Guest`, …) und lokale Gruppen
  (`BUILTIN\Administrators`, `BUILTIN\Users`, `BUILTIN\Remote Desktop
  Users`, …)
- Well-Knowns aus der LSA des aktuellen Rechners

**Domain-Konten und Domain-Gruppen werden bewusst nicht live aus LDAP
nachgeschlagen**, während Sie tippen. Wenn Sie zum Beispiel `m` für
`max.mustermann001` eintippen, sehen Sie keine Vorschläge aus AD —
das ist **kein Fehler**, sondern Absicht (siehe Begründung weiter unten
und in der technischen Dokumentation).

**So geben Sie einen Domain-Benutzer ein, der nicht in der Vorschlagsliste
auftaucht:**

| Vorgehen | Beispiel |
|---|---|
| Tippen Sie den vollständigen `DOMAIN\Benutzer` direkt | `CORP\mustermann001` |
| Oder den UPN | `mustermann001@corp.local` |
| Oder die rohe SID, wenn bekannt | `S-1-5-21-…-1128` |
| Danach **„SID auflösen"** klicken | Stars führt einen einmaligen LDAP-Lookup aus und füllt das SID-Feld |

**Warum kein Live-Lookup beim Tippen?** Vor jedem Tastenanschlag eine
LDAP-Suche gegen den DC auszuführen, würde bei großen Verzeichnissen
(z. B. 10 000 Benutzer-Konten) jede Eingabe-Verzögerung in zehntel
Sekunden in eine spürbare Wartezeit verwandeln und nebenbei den DC mit
Such-Anfragen fluten. Die ausdrückliche Trennung — Vorschlagsliste lokal,
LDAP-Lookup nur auf Klick — hält die GUI auch in einer Umgebung mit
hunderttausenden Konten flüssig.

---

## Active Directory anbinden (optional)

**Wann brauchen Sie das?**

- Sie wollen **rekursive Gruppenauflösung** über
  `LDAP_MATCHING_RULE_IN_CHAIN` — der einzig korrekte Weg für
  verschachtelte AD-Gruppen.
- Sie wollen die GUI-**Identitätssuche** nach Anzeigenamen nutzen.
- Sie wollen den `userAccountControl`-Status (Konto deaktiviert) sehen.

**Wann nicht?**

- Schneller Smoke-Test auf einem Domain Controller — der lokale
  SAM/LSA-Fallback liefert dort die direkten Domain-Gruppen plus
  lokale Gruppen-Ketten. **Achtung:** verschachtelte Domain-Gruppen
  fehlen dann; Stars markiert die Befunde entsprechend mit
  `DomainGroupRecursionIncomplete`.

### LDAP-Konfiguration

Im Identitäts-Tab unter **„LDAP-Modus"**:

- **0 — Aus (SAM/LSA)**: kein LDAP, nur lokale APIs.
- **1 — LDAPS (verschlüsselt, Port 636)** — Standard für produktive
  Umgebungen.
- **2 — LDAP unverschlüsselt (Port 389)** — **nur** für Testumgebungen.
  Passwort fließt im Klartext.

Felder (alle werden vor der Verwendung automatisch getrimmt):

- **Server** — DC-Hostname (z. B. `dc01.corp.local`).
- **Base DN** — Wurzel-Domain-DN (z. B. `DC=corp,DC=local`).
- **Bind DN** — Konto für die LDAP-Bindung
  (`CN=stars-svc,CN=Users,DC=corp,DC=local`).
- **Passwort** — Bind-Passwort. **Wird nicht gespeichert**, gilt nur
  für die laufende Sitzung.

### Multi-Domain / Trust-Beziehungen

Wenn das konfigurierte `base_dn` nur **eine Domain** indexiert (Standard
in Multi-Domain-Forests), erkennt Stars Cross-Domain-Identities über
LSA und markiert sie als `IdentityNotInConfiguredLdapBase`.

Für **vollständige** Forest-Abdeckung:

- Zweite Stars-Analyse mit dem `base_dn` der Partner-Domain laufen
  lassen, oder
- Gegen den **Global Catalog** binden (`gc://dc.corp.local:3268`)
  — derzeit **noch nicht in Stars implementiert**, siehe
  [known-limitations.md L2](known-limitations.md).

---

## Lokale Pfade vs. SMB-Freigaben

**Lokale Pfade** (`C:\data\…`, auch in der Long-Path-Form
`\\?\C:\data\…`):

- Es wird **nur die NTFS-DACL** ausgewertet.
- Lokale Server-Gruppen werden vom *lokalen System* gelesen.

**UNC-Pfade** (`\\server\share\…`, auch in der Long-Path-Form
`\\?\UNC\server\share\…`):

- Stars erkennt Server und Share automatisch aus dem Pfad.
- Es wird **Share-DACL ∩ NTFS-DACL** ausgewertet — die effektive
  SMB-Berechtigung ist die *restriktivere* der beiden.
- Lokale Server-Gruppen werden vom Server der Freigabe gelesen.

**Manueller SMB-Kontext** (Felder `--smb-server` / `--share-name`
oder GUI-Checkbox „SMB-Kontext"):

Diese Felder gelten **nur als Paar**. Wenn Sie nur einen setzen,
liefert Stars einen klaren Fehler — sonst hätte das stille Folgen für
die Token-SID-Auflösung.

---

## Befunde lesen — die Diagnose-Marker

Jeder `EffectivePermission`-Eintrag in CLI, HTML oder JSON trägt eine
`diagnostics`-Liste. Wenn ein Marker auftaucht, hat Stars Sie *gewarnt*,
dass etwas an der Berechnungsgrundlage unsicher ist.

| Marker | Schwere | Risk-`incomplete`? | Was er Ihnen sagt |
| --- | --- | --- | --- |
| `NonCanonicalDaclOrder` | medium | nein | DACL ist nicht in Windows-Standardreihenfolge. AccessCheck läuft trotzdem in gespeicherter Reihenfolge — das Ergebnis kann von einer kanonisierten Erwartung abweichen. |
| `UnsupportedShareAces` | medium | **ja** | Share-DACL enthielt ACE-Typen, die der Parser nicht auswerten konnte (Object-/Callback-/Conditional-/herstellerspezifisch). Share-Maske ist potenziell unvollständig. |
| `DomainGroupRecursionIncomplete` | medium | **ja** | Gruppenauflösung lief über SAM/LSA statt LDAP. `NetUserGetGroups` liefert nur direkte globale Gruppen — verschachtelte Domain-Gruppen sind nicht rekursiv aufgelöst. |
| `IdentityDisabled` | info | nein | Konto ist in AD via `userAccountControl/UF_ACCOUNTDISABLE` deaktiviert. ACL-theoretische Rechte stimmen, aber das Konto kann sich normal nicht authentifizieren. |
| `IdentityNotInConfiguredLdapBase` | medium | **ja** | LSA hat SID aufgelöst, aber das konfigurierte LDAP-`base_dn` indexiert sie nicht. Typisch in Multi-Domain-Forests / Trusts — Cross-Domain-Mitgliedschaften können fehlen. |
| `IdentityDisabledStatusUnknown` | info | nein | `disabled`-Flag konnte nicht ermittelt werden (z. B. SAM-Pfad ohne `NetUserGetInfo`-Erfolg oder LDAP ohne User-Objekt). |
| `IdentityLookupFailed { reason }` | high | **ja** | LDAP-Identity-Lookup ist mit einem technischen Fehler gescheitert (Bind, Timeout, DC unerreichbar). Analyse läuft mit Platzhalter-Identity und leerem Token weiter — ACEs auf Domain-Gruppen können fehlen. `reason` trägt die ursprüngliche Fehlermeldung. |
| `GroupResolutionFailed { reason }` | high | **ja** | Rekursive Gruppenauflösung ist gescheitert oder wurde übersprungen (z. B. Cross-Domain-Pfad ohne GC-Crawl). ACEs auf Domain-Gruppen können fehlen. `reason` trägt die ursprüngliche Fehlermeldung. |

**Risk-`incomplete = true`** heißt: das Risk-Finding ist strukturell
unvollständig — der Auditor sollte zusätzlich manuell nachsehen.

**Goldene Regel:** Befund + Marker = ehrlicher Befund. Befund ohne
Marker = Stars hat Vertrauen in die Berechnung.

---

## Exportieren — CSV, JSON, HTML

Über das **Export**-Menü (oder die `--output`-Option in der CLI):

- **CSV** — flache Pfad-pro-Zeile-Sicht für Excel/Pivot. Diagnostik-
  Marker als Komma-separierte Variantenliste.
- **JSON** — variant-tagged Diagnostik-Marker (`{ "kind":
  "IdentityNotInConfiguredLdapBase" }`), inklusive `reason`-Texte für
  die Failed-Marker. Geeignet für Skripts und SIEM-Ingest.
- **HTML** — voll formatierter Audit-Bericht mit:
  - Risiko-Findings sortiert nach Severity,
  - Trustee-Tabelle pro Pfad (NTFS + Share getrennt),
  - Diagnose-Marker als farbige Badges,
  - Scan-Fehler in eigener Sektion.

Bestehende Export-Dateien werden ohne `--force` (CLI) bzw. ohne
ausdrückliche Bestätigung (GUI) **nicht überschrieben**.

---

## Die CLI

`adpa.exe` liegt nach der Installation neben `adpa-gui.exe`.

### Einzelpfad analysieren

```powershell
adpa analyze --path "C:\data\projekte" --user "CORP\alice" `
    --server "dc01.corp.local" --base-dn "DC=corp,DC=local" `
    --bind-dn "CN=stars-svc,CN=Users,DC=corp,DC=local" `
    --output "audit.csv"
```

Setzen Sie die Umgebungsvariable `ADPA_BIND_PASSWORD` für das
Bind-Passwort — das ist sicherer als die `--bind-password`-Option, die
im Process-Listing sichtbar bleibt.

### Rekursiver Scan

```powershell
adpa scan --path "\\fileserver\projekte" --user "CORP\alice" `
    --server "dc01.corp.local" --base-dn "DC=corp,DC=local" `
    --bind-dn "CN=stars-svc,CN=Users,DC=corp,DC=local" `
    --max-depth 8 --db "C:\audit\stars.db" --output "audit.json"
```

`Ctrl-C` löst einen sauberen Abbruch aus — der aktuelle Pfad wird
fertig analysiert, dann beendet Stars sich kooperativ.

### Weitere Optionen

`adpa --help` listet alle Optionen.

---

## Wo werden Daten gespeichert?

| Daten | Pfad | Bemerkung |
| --- | --- | --- |
| Scan-Historie (SQLite) | `%APPDATA%\Stars\stars_data.db` | Lokale Datei, nur Sie haben Zugriff. |
| Konfiguration | (keine — Stars speichert keine LDAP-Credentials persistent) | Bind-Passwort gilt nur für die laufende Sitzung. |
| Logs | `%APPDATA%\Stars\logs\` | Anwendungs-eigene Logs, nicht Zielsystem-Logs. |
| Exporte | dort, wo Sie sie speichern | Stars schreibt nur dorthin, wo Sie es anweisen. |

**Sensible Daten:** Stars protokolliert *keine* Passwörter, Tokens
oder Bind-Credentials. Pfade und Identitäten können vertraulich sein —
behandeln Sie die Scan-Historie und Exporte als sensibles Material.

---

## Updates

Stars trägt ein **Update-Manager-Skelett**, das Update-Pakete signaturbasiert
prüft (siehe ADR 0028 / 0030). Aktuell findet die Update-Installation
manuell statt:

1. Neue Setup-Datei vom Release herunterladen.
2. Installieren (überschreibt die alte Version).
3. Bei größeren Versionssprüngen prüft Stars beim Start, ob die
   SQLite-Scan-Historie eine Migration braucht — und führt sie
   transaktional aus.

Eine automatische Update-Funktion ist für eine spätere Version
geplant (signaturgeprüfte Updates aus konfigurierter Quelle).

---

## Häufige Fragen

### „Stars sagt `Orphaned`, aber der User existiert!"

Bis v1.4.1 konnten Trust-User je nach Eingabeform fälschlich als
`Orphaned` erscheinen. Seit v1.5.0 läuft die Pipeline für alle
Eingabeformen einheitlich; ein Trust-User wird jetzt als
`OutsideConfiguredLdapBase` markiert.

Wenn Sie trotzdem ein `Orphaned` sehen, prüfen Sie:

- Tragen Sie die SID exakt richtig? Whitespace wird seit v1.5.2 zwar
  getrimmt, aber ein Tippfehler bleibt einer.
- Existiert das Konto wirklich auf diesem System? `whoami /user` bzw.
  `Get-ADUser -Identity ...` als Gegenprobe.
- Wenn das Konto in einer Trust-Domain existiert: lässt Ihr
  konfigurierter LDAP-Bind die Trust-Domain überhaupt indexieren?
  (siehe `IdentityNotInConfiguredLdapBase`).

### „Warum unterschiedliche Rechte zwischen CLI und GUI?"

Das **darf nicht passieren** — beide nutzen seit v1.5.0 dieselbe
Principal-Pipeline und dieselbe Engine. Wenn Sie Unterschiede sehen,
liegt fast immer einer dieser Gründe vor:

- Unterschiedlicher SMB-Kontext (UNC vs. lokal, oder unterschiedlich
  gesetzte `--smb-server`/`--share-name`).
- Unterschiedliche LDAP-Konfiguration.
- Whitespace im Identity-Feld (gilt nicht mehr — seit v1.5.2 gefixt).

Wenn das Problem reproduzierbar ist, bitte ein
[GitHub-Issue](https://github.com/Birgerson/stars-ad-permission-analyzer/issues)
mit beiden Befunden als Vergleich.

### „Stars dauert ewig — was kann ich tun?"

Häufige Ursachen:

- **Sehr tiefe Verzeichnisbäume**: `--max-depth` setzen.
- **Langsamer DC**: das `LDAP-Timeout` greift; bei jedem hängenden
  Aufruf liefert Stars einen `LookupFailed`-Marker statt zu blockieren.
- **Riesige DACLs**: identische Security-Descriptoren werden per Hash
  dedupliziert, aber sehr breite Trees mit vielen unique ACLs brauchen
  Zeit.

Stars hat **keine** Hintergrund-Scans, **keine** Auto-Refresh,
**keine** Schreibvorgänge — wenn es lange dauert, liest es real.

### „Eine Datei heißt `passwords.txt` — was macht Stars damit?"

Stars **öffnet die Datei nicht**. Sie wird per `SensitivePathRule`
nur als „möglicherweise sensibel" markiert, damit der Auditor sie
bewusst weiterbehandelt. Inhalt liest Stars grundsätzlich nicht.

### „Stars zeigt eine Lücke, ich brauche das vollständige Bild — was tun?"

Wenn ein Marker `incomplete = true` ausgibt:

1. **`reason`-Text lesen.** Bei `IdentityLookupFailed { reason }` oder
   `GroupResolutionFailed { reason }` steht der ursprüngliche
   Fehler dort.
2. **Konfiguration prüfen.** LDAP-Server erreichbar? Bind-Konto noch
   gültig? `base_dn` deckt den User wirklich ab?
3. **Wenn Multi-Domain involviert:** zweite Stars-Analyse mit dem
   `base_dn` der Partner-Domain laufen lassen, oder den
   [known-limitations.md L2](known-limitations.md)-Workaround
   (Global Catalog) manuell anwenden.

Stars sagt Ihnen ehrlich, *was* fehlt — aber **es löst die
Konfigurations-Sache nicht für Sie**. Das ist Ihre Hoheit.

---

## Weiterführende Dokumente

- **[features-and-limitations.md](features-and-limitations.md)** —
  Vollständige Liste, was Stars zuverlässig kann und was per Design
  nicht.
- **[known-limitations.md](known-limitations.md)** — Bekannte
  strukturelle Lücken (FSP, GC-Bind, SID-History, Cross-Forest) mit
  Roadmap-Tracking.
- **[audit-kriterien.md](audit-kriterien.md)** — Fachliche
  Bewertungsregeln und Severities pro Risiko-Regel.
- **[adr/](adr/)** — Architektur-Entscheidungen (ADRs) — historische
  Begründungen einzelner Modell-, Pipeline- und API-Entscheidungen.
- **[../README.md](../README.md)** — Projektübersicht, Build-
  Anleitung, Lizenz.
- **[../SECURITY.md](../SECURITY.md)** — Sicherheitslücken melden.

---

## English version

An English version of this guide is available at
**[user-guide.md](user-guide.md)**.
