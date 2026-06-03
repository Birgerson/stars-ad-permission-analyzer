# Changelog

Alle nennenswerten Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

Das Format orientiert sich an [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) und das Projekt folgt [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Stand vor `v0.2.0-rc1` wird zusammenfassend abgehandelt, weil dort noch keine echten Release Notes geführt wurden. Ab `v0.2.0-rc1` ist jede Version einzeln aufgeschlüsselt.

---

## [Unreleased]

_Keine offenen Änderungen._

---

## [1.2.0] — 2026-06-02

**Minor-Release.** Drei vom Bediener konkret angesprochene GUI-Lücken geschlossen: pfadzentrierte Trustee-Sicht im Analyze-Tab, Löschen einzelner Scan-Läufe aus der Historie, sichtbarer Hinweis bei leerem Delta-Ergebnis. Reines Lese-Tool — keine Schreibvorgänge auf Zielsystemen, keine Berechtigungs­änderungen.

### Hinzugefügt
- **Trustee-Sicht im Analyze-Tab** („Wer hat Zugriff?"-Button). Listet alle ACEs eines Pfads pfadzentriert auf — eine Zeile pro ACE mit aufgelöstem `DOMAIN\Name`, Allow/Deny, normalisierten Rechten + Roh-Maske, explicit/inherited-Quelle, Windows-typischer „Applies to"-Bezeichnung und Schicht (NTFS / Share). Beantwortet die Audit-Frage „wer kann überhaupt auf X zugreifen?" als Komplement zur identitätsbasierten Effektiv-Analyse. SMB-Kontext optional — wenn aktiv, wird zusätzlich die Share-DACL mit angezeigt. NULL-DACL erscheint als sichtbare Auditor-Zeile statt einer leeren Tabelle.
- **Worker-Request `AnalyzeTrustees`** + Event `TrusteesDone` + `TrusteeRow`-Struct. Auflösung der SIDs erfolgt batched per `ad_resolver::build_sid_name_map` — eine LSA-Runde pro eindeutiger SID.
- **`Database::delete_scan_run(id)`** und **`ScanStore::delete_scan_run(id)`** in `persistence`. Löscht einen Scan-Lauf samt aller `effective_permissions`- und `scan_errors`-Zeilen in einer expliziten Transaktion (BEGIN IMMEDIATE / COMMIT / ROLLBACK). SQLite-Foreign-Keys sind im Schema nicht über `PRAGMA foreign_keys = ON` aktiv, deshalb explizite Kaskade. Liefert die Anzahl entfernter Scan-Lauf-Zeilen (0 bei unbekannter ID, 1 bei Erfolg).
- **Mülleimer-Button pro Scan-Lauf im Delta-Tab** plus inline-Bestätigungsdialog. Ein versehentlicher Klick löscht nichts — die Aktion startet erst nach „Endgültig löschen". Nach Abschluss wird die Selektion bereinigt, ein eventuell sichtbares Delta-Ergebnis ausgeblendet und die Liste frisch aus der DB nachgeladen, damit GUI-State und DB nicht auseinanderlaufen.
- **`WorkerRequest::DeleteScanRun`** + Event `ScanRunDeleted { run_id, result }`. Triggert auf Erfolg automatisch ein `ListScanRuns`, damit der Bediener nicht erneut auf „Scan-Historie laden" klicken muss.
- **`REQ_TX`-Thread-Local** in der GUI für Folge­aktionen aus Event-Handlern (analog zum bestehenden `EVENT_RX`).
- **Sichtbarer Hinweis im Delta-Tab bei leerem Ergebnis**: „Keine Unterschiede zwischen den beiden Scans gefunden. Beide Läufe enthalten dieselben Pfade mit identischen effektiven Berechtigungen." Vorher sah der Bediener nur die `0 / 0 / 0`-Zähler über einer leeren Tabelle und konnte nicht zwischen „Vergleich gelaufen, nichts gefunden" und „Aktion verloren gegangen" unterscheiden.

### Tests
- Drei neue `persistence`-Tests für `delete_scan_run`: vollständiges Cascade-Delete (Run + Permissions + Errors), unbekannte UUID liefert `0` und kein Fehler, andere Scan-Läufe bleiben unangetastet.

### Versionsbump
- Workspace-Version: `1.1.2` → `1.2.0`.

---

## [1.1.2] — 2026-06-01

**Patch-Release.** Behebt einen vertrauenskritischen Fehler im Verzeichnis-Walker, der Reparse Points (Junctions, Symlinks) bisher still übersprungen hat — Inhalt hinter einer Junction war im Scan-Ergebnis stumm fehlend, ohne dass die GUI das angezeigt hat. Tritt produktiv vor allem bei SYSVOL-Scans auf (`C:\Windows\SYSVOL\sysvol\<domain>` ist standardmäßig eine Junction auf `C:\Windows\SYSVOL\domain`).

### Geändert
- `fs_scanner::walker::walk_tree` verfolgt Reparse Points jetzt standardmäßig und entdeckt Schleifen über das kanonisierte Ziel. Ein `HashSet` der schon besuchten kanonischen Pfade wird beim Eintritt in jeden Reparse Point geprüft; bei Treffer wird die Rekursion gestoppt und ein sichtbarer `WalkError` mit erklärendem Text ins Ergebnis geschrieben. Die alte „still überspringen"-Logik fällt damit ersatzlos weg.
- Schlägt die Auflösung des Reparse-Ziels fehl (z. B. defekter Link), wird ebenfalls ein sichtbarer `WalkError` ausgegeben statt im `debug!`-Log zu verschwinden.

### Hinzugefügt
- Walker-Test `walker_follows_directory_junction_into_target` — verifiziert mit einer per `mklink /J` erzeugten Junction, dass Objekte hinter dem Link tatsächlich enumeriert werden.
- Walker-Test `walker_detects_junction_loop_and_emits_visible_error` — erzeugt eine zirkuläre Junction-Struktur (`a\b → root`) und stellt sicher, dass die Schleife sauber erkannt und als Fehler im Ergebnis sichtbar wird (kein Stack-Overflow, kein stilles Drop).

### Versionsbump
- Workspace-Version: `1.1.1` → `1.1.2`.

---

## [1.1.1] — 2026-06-01

**Patch-Release.** Beseitigt eine UX-Falle im Analyze-Tab: bisher wurden Analyse-Ergebnisse nicht persistiert und tauchten deshalb im Delta-Tab nie auf.

### Geändert
- Analyze-Tab persistiert das Ergebnis jetzt automatisch in die Scan-Historie — eine `EffectivePermission` landet als Scan-Lauf mit genau einer Permission. Damit sind Analyze-Auswertungen im Delta-Tab vergleichbar; vorher schrieb nur der Scan-Tree-Tab in die DB, was sich für Endnutzer als „Liste lädt meine Auswertung nicht" bemerkbar machte.
- Statuszeile des Analyze-Tabs spiegelt das Persistenz-Ergebnis: „Analyse abgeschlossen — in der Scan-Historie gespeichert." bei Erfolg, sichtbarer Fehler­text bei Persistenz-Problemen.
- `WorkerEvent::AnalyzeDone` ist von Tuple- auf Struct-Variante umgestellt und trägt zusätzlich `scan_run_id` und `persistence_error`. `result` ist geboxt, weil `EffectivePermission` deutlich größer ist als die übrigen Event-Varianten (sonst greift `clippy::large_enum_variant`).

### Hinzugefügt
- Hinweistext direkt unter dem „Analysieren"-Button: „Hinweis: jede Analyse wird automatisch in der Scan-Historie gespeichert und ist anschließend im Delta-Tab vergleichbar." — macht die Semantik vor dem Klick sichtbar.

### Versionsbump
- Workspace-Version: `1.1.0` → `1.1.1`.

---

## [1.1.0] — 2026-06-01

**Audit-Beweiskraft und sicherheits­relevante Vorlauf­arbeiten am Update-Manager.** Schließt alle offenen Befunde aus dem ChatGPT-Code-Review 2026-05-31 (Findings 1, 2, 6, 7); Findings 3–5 wurden bereits in v1.0.0 adressiert.

### Hinzugefügt
- `MembershipPath` als neues Datenmodell in `adpa_core`: trägt pro `GroupMembership` die konkrete SID-Kette vom Benutzer zur Zielgruppe, indexweise zugeordnete Anzeigenamen, eine Herkunfts­quelle (`PrimaryGroup`, `DomainGroup`, `LocalGroup`, `LdapMatchingRule`) und ein `complete`-Flag. Der LDAP-Resolver rekonstruiert die Ketten per BFS über die `memberOf`-Edges der schon geladenen Gruppen-Entries; ist die Rekonstruktion nicht möglich (z. B. wegen trunkiertem `memberOf` einer Zwischengruppe), bleibt der Pfad zwei SIDs lang und wird als `complete = false` markiert (ChatGPT-Code-Review Finding 1).
- `validate_manifest_relative_path` als zentrale Windows-sichere Pfadprüfung im Update-Manifest. Lehnt Laufwerksbuchstaben (`C:\…`, `C:x`), UNC- und Long-Path-Präfixe (`\\…`, `\\?\…`), `.`/`..`-Segmente, leere Segmente, reservierte Geräte­namen (`NUL`, `CON`, `COM1`, …), ADS-Notation (`file.txt:ads`), verbotene Zeichen und Steuerzeichen ab. Schließt einen Sicherheits-Vorlauf für die spätere Installationslogik (ChatGPT-Code-Review Finding 6).
- `verify_update_policy` + `UpdatePolicyContext` als getrennte Policy-Schicht zur Manifest-Freigabe. Prüft Plattform, freigegebenen Kanal, dotted-numerische Versions-Reihenfolge (mit optionalem `allow_downgrade`), ISO-8601-Parsebarkeit von `issued_at`, sowie Future-Skew- und Max-Age-Toleranz (ChatGPT-Code-Review Finding 7).

### Geändert
- `validate_path` akzeptiert jetzt zusätzlich die Windows-Long-Path-Schreibweise (`\\?\C:\…` und `\\?\UNC\server\share\…`) und normalisiert sie auf die kanonische Anzeigeform. CLI- und GUI-Eingaben verhalten sich damit nicht mehr strenger als die darunterliegende Scanner-API (ChatGPT-Code-Review Finding 2).
- Erklärungstext der `PermissionPath`-Steps zeigt für jede Mitgliedschaft mit konkretem Pfad die geordnete Kette `User → Group A → Group B` plus Quellen-Label statt nur `Member of X [transitive]`. Direkte Mitgliedschaften erhalten `[direct, source: …]`, unvollständige transitive Ketten werden mit `exact chain unknown — source: LdapMatchingRule, possibly truncated memberOf` markiert. Cache-Lesepfade ohne `MembershipPath` fallen auf das alte Format zurück.
- `verify_manifest` aus `update_manager` umbenannt in `verify_manifest_integrity`, da der Name die tatsächliche Funktion (Schema + Signatur + Datei-Hashes) sauber abgrenzt von der neuen Policy-Schicht. Ältere Aufrufer existieren nicht außerhalb des Crates; der alte Name wird nicht beibehalten, weil das Risiko größer wäre, als die Schicht­trennung verlässlich zu erzwingen (ChatGPT-Code-Review Finding 7).
- `UpdateManifest::validate_schema` ruft jetzt `validate_manifest_relative_path` pro Datei-Eintrag — die alte Substring-Prüfung auf `..` und führende Separatoren ist abgelöst (ChatGPT-Code-Review Finding 6).

### Tests
- Zehn neue Tests für `validate_path` mit Long-Path-Eingaben: lokale und UNC-Long-Path-Form, Überlänge > MAX_PATH, Roundtrip mit `to_windows_api_path`, Ablehnung für fehlende Drive-/Share-Komponente, leeres Präfix und nach Strip noch verbotene Zeichen.
- Vier neue Engine-Tests für das Membership-Pfad-Rendering: verschachtelte Kette in geordneter Reihenfolge (`User → A → B`), direkte Kante mit Quellen-Label, unvollständige transitive Kette mit explizitem Hinweis, Rückfall auf Legacy-Format bei `path = None` (Cache-Reads).
- Vierzehn neue Tests für `validate_manifest_relative_path`: akzeptierte relative Pfade (auch mit `/`-Separator), Ablehnung von absoluten Drive-Pfaden, drive-relativen Pfaden (`C:foo`), `..`- und `.`-Segmenten, reservierten Geräte­namen, ADS-Notation, UNC- und Long-Path-Präfix, führenden Separatoren, leeren Segmenten, verbotenen Zeichen, Steuerzeichen und Null-Bytes.
- Elf neue Tests für `verify_update_policy` und `compare_dotted_versions`: passende Plattform/Kanal/Version, falsche Plattform, falscher Kanal, Downgrade ohne Freigabe, gleiche Version (kein Re-Install), Downgrade mit Freigabe, `issued_at` weit in der Zukunft vs. innerhalb der Skew-Toleranz, abgelaufenes `issued_at`, nicht parsbares `issued_at`, dotted-numerische Ordnung (`1.10.0` vs `1.9.5`) und Strip von Pre-Release-Suffixen.

### Dokumentation
- ADR 0029 — Konkreter Mitgliedschafts-Pfad in der Erklärung.
- ADR 0030 — Update-Manager: Pfadvalidierung und Policy-Schicht.
- README ergänzt um den Mitgliedschafts-Pfad in der AD-Sektion (DE + EN).

### Versionsbump
- Workspace-Version: `1.0.0` → `1.1.0`.

---

## [1.0.0] — 2026-05-31

**Erstes stabiles Release. Repository ab hier öffentlich, neuer Repo-Name.**

### Hinzugefügt
- Stabile Veröffentlichung des AD-Permission-Analyzers mit allen Funktionen aus rc1–rc17:
  - Effektive-NTFS- und Share-Berechtigungs­berechnung mit erklärbarem Pfad
  - Sechs Risikoregeln (Full Control, Write Access, Admin Rights, Broad Group Write, Direct User ACE, Sensitive Path)
  - Slint-GUI mit Analyze-, Scan- und Delta-Tab
  - SAM-/LSA-basierte Identitätsauflösung auf einem DC (kein LDAP-Bind nötig)
  - Live-Suche im Namensfeld (NetUserEnum + NetGroupEnum + NetLocalGroupEnum + Well-Known-Tabelle)
  - HTML-/CSV-/JSON-Export
  - SQLite-Scan-Historie mit Delta-Vergleich
  - Sauberer NSIS-Uninstaller mit optionaler Daten-Bereinigung

### Geändert
- Workspace-Version: `0.2.0-rc17` → `1.0.0`
- Repository: umgezogen von `Birgerson/Stars.Rocks` (private, gelöscht) nach `Birgerson/Stars` mit frischer Git-History — saubere Trennung zwischen Entwicklungs­phase und stabilen Releases.
- `SensitivePathRule` und `DirectUserAceRule` melden Befunde jetzt als `incomplete = is_incomplete(p)` statt fix `false`, konsistent zu allen anderen Risikoregeln (ChatGPT-Code-Review 2026-05-31 Findings 3 und 4).
- `scripts/test-env/02-setup-ad-objects.ps1`: Beispiel-Block enthält jetzt einen Platzhalter (`<dein-Testpasswort>`) statt eines konkreten Passworts (ChatGPT-Review Finding 5).

### Tests
- Zwei neue Regressionstests für die `incomplete`-Markierung bei `ShareEvalStatus::ReadFailed` (`SensitivePathRule`, `DirectUserAceRule`).

### Bekannte Punkte für spätere Versionen
- ChatGPT-Review Finding 1 (konkrete Gruppen-Kette im Erklärungspfad): geplant für v1.1.
- Finding 2 (Long-Path-Präfixe in `validate_path`): geplant für v1.1.
- Findings 6 und 7 (Update-Manager-Pfadvalidierung, `verify_manifest`-Naming): werden mit der Installations­logik des `update_manager` zusammen umgesetzt.

---

## [0.2.0-rc17] — 2026-05-31

**LDAP-Modus als Dropdown + Tooltip-Hinweise auf den wichtigen Feldern.**

### Hinzugefügt
- **ComboBox „Modus"** statt zweier Checkboxen im LDAP-Bereich von Analyze- und Scan-Tab. Drei klar getrennte Optionen:
  - „Aus — SAM/LSA nutzen (empfohlen auf DC)"
  - „LDAPS — verschlüsselt, Port 636"
  - „LDAP unverschlüsselt — Port 389 (nur Test)"
- **HelpTip-Component** (ⓘ-Icon) mit Hover-Tooltip auf den LDAP-Modus-Wähler und allen LDAP-Eingabefeldern (Server, Base DN, Bind DN, Passwort). Jeder Tooltip erklärt Zweck, Format und typische Stolperfallen — Anwender muss nicht erst die Doku lesen, um zu verstehen, was wohin gehört.

### Geändert
- LDAP-Properties auf Slint-Seite konsolidiert: `a-ldap-enabled` + `a-ldap-insecure` → eine `a-ldap-mode` Integer-Property (0/1/2). Analog für den Scan-Tab. Rust-Callbacks lesen die Mode-Property direkt und bauen `LdapParams` mit `insecure` daraus ab.

---

## [0.2.0-rc16] — 2026-05-31

**Sauberer Uninstaller: Process-Check, dynamische Version, optionale Audit-Historie-Bereinigung.**

### Hinzugefügt
- `setup.nsi` baut beim Deinstallieren jetzt eine **Components-Seite** mit zwei Sektionen:
  1. **„Stars"** (Pflicht) — Programmdateien, Verknüpfungen, Registry-Eintrag.
  2. **„Audit-Historie und Logs entfernen"** (standardmäßig **aus**) — entfernt `%APPDATA%\Stars\` (SQLite-DB) und `%LOCALAPPDATA%\Stars\logs\` mit. Die Standardvorgabe schützt die Audit-Historie als Beweismittel, der Anwender muss bewusst opt-in.
- **Process-Check** vor der eigentlichen Deinstallation: läuft `Stars.exe` noch, erscheint eine Meldung „Stars läuft noch — bitte schließen und Deinstallation neu starten" und der Vorgang bricht ab, statt teilweise zu scheitern.
- **APP_VERSION** wird vom Release-Workflow dynamisch via `/DAPP_VERSION=<tag-ohne-v>` an `makensis` übergeben. Damit zeigt der „Programme und Features"-Eintrag jetzt die echte Release-Version (`0.2.0-rc16`) statt des bisher hartkodierten `1.0`.

### Dokumentation
- README: neue Sektion „Deinstallation" mit Pfaden und Hinweis auf die Opt-in-Checkbox.
- `docs/audit-kriterien.md` Kapitel 11 (Persistierte Daten): Hinweis ergänzt, dass die Audit-Historie standardmäßig auch eine Deinstallation überlebt — und wie man sie bewusst entfernen kann.

---

## [0.2.0-rc15] — 2026-05-31

**Live-Suche im Namensfeld — Auditor muss SIDs nicht mehr auswendig wissen.**

### Hinzugefügt
- Neues Modul `ad_resolver::enumerate` mit `IdentitySnapshot` und `enumerate_all()`. Sammelt Domänen-User (`NetUserEnum` Level 10), globale Domänen­gruppen (`NetGroupEnum` Level 1), lokale Gruppen (`NetLocalGroupEnum` Level 1) und eine hartcodierte Tabelle audit-relevanter Well-Known-Identitäten (`Everyone`, `Authenticated Users`, `SYSTEM`, `NETWORK`, `CREATOR OWNER` …). Alle Aufrufe `NetApiBufferFree`-sauber, alle `unsafe`-Blöcke mit SAFETY-Begründung.
- Neue Worker-Variante `WorkerRequest::ListIdentities` + Event `IdentitiesLoaded`. Wird einmalig beim App-Start gefeuert, das Ergebnis liegt in einem thread-lokalen Cache in der GUI.
- Live-Suche unter dem Namensfeld in Analyze- und Scan-Tab: User tippt `ad`, eine kleine Vorschlags­liste erscheint mit Klartextnamen (`[U] Administrator`, `[G] Domain Admins`, `[L] BUILTIN\Administrators`, `[W] Authenticated Users` …). Klick übernimmt den Namen und löst die SID automatisch auf.
- Maximal 15 Treffer angezeigt — wer mehr braucht, tippt präziser.

### Technisches
- Filterung läuft rein lokal gegen den Cache, kein Worker-Roundtrip pro Tastendruck.
- Bei leerer Eingabe verschwindet die Vorschlags­liste automatisch.
- Fällt die Enumeration fehl (z.B. fehlende Rechte für `NetUserEnum`), läuft die GUI ohne Vorschläge weiter — Direkt-Eingabe und `🔍 SID auflösen`-Button funktionieren unabhängig vom Cache.

---

## [0.2.0-rc14] — 2026-05-31

**UX: Benutzername → SID-Auflösung direkt in der Maske.**

### Hinzugefügt
- Analyze- und Scan-Tab haben jetzt ein zusätzliches Feld „Benutzer/Gruppe" mit einem „🔍 SID auflösen"-Button (und Enter-Taste). Der Name wird per `LookupAccountNameW` über die lokale LSA in die SID übersetzt und ins SID-Feld geschrieben. Funktioniert ohne LDAP, für User UND Gruppen, mit oder ohne Domänen­präfix (`Administrator`, `DOMÄNE\\max.muster`, `BUILTIN\\Administrators`). Nicht aufgelöste Namen erscheinen als rote Fehlermeldung unter den Feldern.
- Neue Hilfsfunktion `resolve_name_to_sid` im GUI-Crate, `#[cfg(windows)]`-gegated, mit einer No-Op-Variante für nicht-Windows-Builds.

---

## [0.2.0-rc13] — 2026-05-31

**UX-Politur + nachgepflegte Dokumentation.**

### Hinzugefügt
- Analyze- und Scan-Tab haben jetzt `C:\Windows\SYSVOL\sysvol` als Pfad-Vorauswahl. Erspart auf einer Standard-DC-Installation den ersten Tippvorgang; bleibt überschreibbar.

### Dokumentation
- README „Entwicklungsstand"-Tabelle korrigiert (Risikoanalyse, HTML-Bericht, Delta-Vergleich nicht mehr „geplant").
- README: neue Sektion „Datenbank und gespeicherte Daten" beschreibt Standort und Schutz­charakter der SQLite-Historie.
- `docs/audit-kriterien.md`: neues Kapitel 11 „Persistierte Daten und Scan-Historie" + Workflow-Empfehlung um Delta-Tab erweitert + Anhang B um Persistence-Verweise ergänzt.

---

## [0.2.0-rc12] — 2026-05-30

**Phase 2c: Delta-Tab funktional — Feature-Parität mit der eframe-Vorgängerversion.**

### Hinzugefügt
- Vergleich zweier persistierter Scan-Läufe direkt in der GUI: historische Scans laden, je einen Lauf für „Alt" und „Neu" anhaken, mit einem Klick die Differenz lesen.
- Zwei neue ViewModels in der Slint-Definition: `ScanRunVm` (id, label, selected_as_old, selected_as_new) und `DeltaRowVm` (path, kind_label, kind_color, old_rights, new_rights).
- Zwei neue `WorkerRequest`-Varianten (`ListScanRuns`, `ComputeDelta`) mit den passenden Antwort-Events (`ScanRunsLoaded`, `DeltaComputed`).
- Delta-Tabelle mit farbcodierten Markern (grün = Hinzugefügt, rot = Entfernt, gelb = Geändert) und Zähl-Headline.

### Dokumentation
- README: „Entwicklungsstand"-Tabelle korrigiert — Risikoanalyse, HTML-Bericht und Delta-Vergleich stehen nicht mehr auf „geplant", sondern auf „✓".
- README: neue Sektion „Datenbank und gespeicherte Daten" beschreibt Standort (`%APPDATA%\Stars\stars_data.db`), Tabellenstruktur, Lebensdauer (überlebt Deinstallation) und Schutz­charakter (kein Passwort, kein Verschlüsselung — Profilpfad selbst absichern).
- Audit-Doku und CHANGELOG entsprechend nachgepflegt.

---

## [Unveröffentlicht in v0.2.0-rc11] — Dokumentations-Konsolidierung
- Audit-Kriterien und Bewertungsprinzipien als eigene, ausführliche Lektüre (`docs/audit-kriterien.md`).
- Urheberschaft transparent ausgewiesen: Birger Labinsch als Prompt Engineer, Implementierung durch Claude Opus 4.7.
- Plattformstatus (Server 2022 getestet, 2025 ungeprüft) und Haftungsausschluss in README und Audit-Doku.
- Repo-Topics und gekürzte Repo-Description direkt am GitHub-Repository gesetzt.

---

## [0.2.0-rc11] — 2026-05-30

**Klartext statt SID-Wüste im Berechtigungspfad.**

### Hinzugefügt
- `GroupMembership.group_name` und `PermissionEvaluationInput.sid_names` — Gruppen- und ACE-Trustee-SIDs erscheinen jetzt mit Namen im Erklärungstext (z. B. `Member of Domain Admins (S-1-5-…-512) [direct]` statt nur der SID).
- `ad_resolver::sam::build_sid_name_map` als zentraler Aufbau für die SID→Name-Tabelle; CLI und GUI bauen die Tabelle einmal pro Lauf, Trustees werden über alle DACLs unique gesammelt.

### Geändert
- SAM-Resolver setzt `group_name` direkt aus `NetUserGetGroups` und löst lokale Gruppen-SIDs (z. B. `BUILTIN\Administrators`) per `LookupAccountSidW` zurück in den Klartextnamen auf.
- LDAP-Resolver schreibt `sAMAccountName` (Fallback `cn`) der Gruppe in die Membership.
- Persistence-Cache liest weiterhin nur die Mitgliedschaftstopologie, `group_name` bleibt beim Cache-Hit `None` — der Live-Resolver liefert den Namen bei der nächsten Auswertung. Keine DB-Migration nötig.

### Tests
- Vier neue Engine-Tests für die SID-Name-Auflösung (Membership-Name, sid_names-Fallback, ACE-Trustee, voller Fallback ohne Namen).

---

## [0.2.0-rc10] — 2026-05-30

**Phase 2b: Scan-Tab in Slint funktional + Klartext-Rechte.**

### Hinzugefügt
- Scan-Tab in Slint vollständig verdrahtet: Live-Tabelle, klickbare Zeilen mit Aufklappen des Berechtigungspfads, Filter, Fehlerliste, farbcodierte Risikobefunde, HTML-Export-Sektion.
- Drei neue Slint-ViewModels (`ScanRowVm`, `ScanErrorVm`, `RiskItemVm`).
- Cancel-Token aus `spawn_worker` wird jetzt tatsächlich gehalten und an den Abbrechen-Button gebunden — der vorherige `_cancel` wurde verworfen.

### Geändert
- Analyze-Tab zeigt die effektiven Rechte als Langform mit icacls-Kürzel (`Modify (M)` statt nur `M`), damit Auditor und icacls 1:1 abgleichbar sind.

---

## [0.2.0-rc9] — 2026-05-30

**SAM-Pfad: Identitäten und Gruppen ohne LDAP auflösen, plus echter UNC-Test.**

### Hinzugefügt
- Neues Modul `ad_resolver::sam` mit `lookup_account_for_sid`, `user_global_group_names`, `lookup_sid_for_account`, `resolve_identity_via_sam`. Auf einem Domain Controller liefert das die vollständige Token-SID-Liste ohne LDAP-Bind, ganz so wie Windows beim Login.

### Behoben
- `unc_components` zerlegte lokale Pfade als UNC — `C:\Windows` landete als `NetShareGetInfo("C:", "Windows")` im share_scanner und scheiterte mit Status 53, obwohl SMB gar nicht angefragt war.
- Worker fällt jetzt ohne LDAP-Haken auf den SAM-Pfad zurück; Administrator zeigt damit korrekte effektive Rechte (vorher 0x00000000, weil das nackte SID-Token keine Gruppen-SIDs trug).

### Tests
- Vier locale-unabhängige Smoke-Tests gegen `S-1-5-32-544` und `S-1-5-18` (funktionieren auch auf deutsch lokalisierten Systemen, wo `BUILTIN` zu `VORDEFINIERT` wird).
- Zwei Negativtests und ein `#[ignore]`-Integrationstest gegen einen lokalen Administrator.

---

## [0.2.0-rc8] — 2026-05-30

**Phase 2a: Analyze-Tab in Slint funktional.**

### Hinzugefügt
- TabWidget mit drei Tabs (Analyze gefüllt, Scan + Delta als Platzhalter).
- Analyze-Eingaben mit Pfad, SID, optionaler LDAP-Sektion (inkl. Password-Input-Type und insecure-Flag) und optionaler SMB-Sektion.
- Analyze-Ergebnis: Rechte-Label, Access-Mask als Hex, Share-Status-Erläuterung, vollständiger Berechtigungspfad nummeriert.
- Worker-Anbindung über `NotifyFn` (Arc-Callback) statt egui-Context; Slints `invoke_from_event_loop` pumpt die Events im UI-Thread.

---

## [0.2.0-rc7] — 2026-05-30

**Phase 1: Wechsel von eframe/wgpu auf Slint mit Software-Renderer.**

### Geändert
- GUI-Crate von eframe/wgpu auf Slint 1.x mit `renderer-software` umgestellt. Slint schreibt direkt in eine GDI-Bitmap und läuft damit auf einem Windows-Server-Domain-Controller unter Proxmox mit VirtIO-GPU, wo eframe/wgpu mangels D3D12-/modernem-OpenGL-Pfad scheiterte.
- `SLINT_BACKEND=winit-software` hart gesetzt, damit kein Szenario auf einen GPU-Pfad zurückfällt.

### Entfernt
- Alle bisherigen eframe-basierten View-Dateien (`analyze_view.rs`, `scan_view.rs`, `delta_view.rs`, `identity_picker.rs`, `app.rs`, `worker.rs` mit egui-Kopplung) — konsequent gelöscht, kein Frankenstein-Stack.

---

## [0.2.0-rc4 — rc6] — 2026-05-30 (zurückgezogene wgpu-Versuche)

Drei kurzlebige Releases, die das wgpu-Backend auf einem Server ohne GPU lauffähig zu machen versuchten. Die Quintessenz: ein GPU-basiertes Toolkit ist auf einem DC mit VirtIO-GPU der falsche Stack. Inhaltlich Zwischenstationen, die mit `rc7` (Wechsel zu Slint Software-Renderer) obsolet wurden — aber lehrreich als Dokumentation des Sackgassen-Pfads.

### rc6
- wgpu-Instance und Adapter selbst vorab via `force_fallback_adapter: true` erstellen (WARP), an eframe als `WgpuSetup::Existing` übergeben.

### rc5
- `native_adapter_selector` mit Adapter-Logging und Reihenfolge echte GPU → WARP → letzter Ausweg. Auf dem DC lieferte `enumerate_adapters` weiterhin null — der Selector half nicht.

### rc4
- Logfile (`%LOCALAPPDATA%\Stars\logs\stars-gui.log`), Panic-Hook und MessageBox-Fallback eingeführt, damit Startfehler auf einem nackten Server überhaupt sichtbar werden.
- eframe von glow (OpenGL) auf wgpu (DX12) umgestellt, weil OpenGL in RDP-Sessions stillschweigend scheitert.

---

## [0.2.0-rc3] — 2026-05-25

### Behoben
- MSVC-CRT statisch linken, damit `Stars.exe` ohne installiertes VC-Redist startet.

### Dokumentation
- README-Download-Sektion mit Release-Badge auf die Startseite.

---

## [0.2.0-rc2] — 2026-05-25

**Großer Audit-Pass mit vielen Review-Findings.**

### Hinzugefügt
- `update_manager` mit Manifest-Schema, pluggable Signaturprüfung und Migrations-Logik.
- HTML-Summary trägt eine Diagnostics-Karte für unvollständige Pfade.
- CLI zeigt strukturierte `PermissionDiagnostic`-Marker pro Pfad.
- GitHub Actions Workflow für fmt + clippy + test bei jedem Push.
- Test-Umgebungsdaten (7 Abteilungen, 10 Test-Benutzer, Abteilungs-Fileserver) als Skripte.

### Behoben
- `share_scanner` wertet Share-DACL in Stored Order aus.
- Share-Token nutzt `AccessContext`.
- `matched_aces` filtert INHERIT_ONLY-Einträge.
- NULL-DACL-Klassifikation korrigiert.
- `SensitivePathRule` setzt effektiven Zugriff voraus (vorher Falschmeldung bei deny-all).
- Unsupported Share-ACEs werden als strukturierte Diagnose durchgereicht.
- `max_depth` wird durch den Validator am Boundary geprüft.
- Persistence: v1-Daten überleben Migration auf v6.

### Architekturentscheidung
- ADR 0026 — `ShareScanResult.share_dacls` trägt `ShareDaclScan`.

---

## [0.2.0-rc1] — 2026-05-24

**Erste Release-Candidate-Reihe mit kompletter Re-Review-Welle.**

### Hinzugefügt
- `JsonExporter`-Implementierung.
- `ShareMaskStatus::Unrestricted` für NULL-Share-DACLs (statt erfundener `0xFFFFFFFF`-Maske).
- `LocalGroupEvalStatus` als strukturierter Status der lokalen Gruppenauflösung.
- `AccessContext` für token-SIDs (`NETWORK` bei SMB, `INTERACTIVE`/`LOCAL` bei lokalem Zugriff).
- Strukturierte Diagnose-Marker pro Berechtigung in Core, Engine, Persistence, Exporter, GUI.
- Risikoauswertung im CLI-Pfad samt Export.
- Abbrechbare lange Scans (`CancellationToken`).
- `DirectUserAceRule` stützt sich auf strukturierte ACE-Daten (`matched_aces`) statt auf den Erklärungstext — lokalisierungssicher.
- `AdminRightsRule` erfasst destruktive und administrative Einzelrechte (`WRITE_DAC`, `WRITE_OWNER`, `DELETE`, `DELETE_CHILD`).
- AD-Identitäts-Picker in der GUI.
- LDAPS-Default (plain LDAP nur mit explizitem `--insecure-ldap`).
- Setup-Anleitung und Skripte für die AD-Integrationstest-Umgebung.

### Behoben
- NULL-DACL wird im kombinierten Scan korrekt erhalten.
- GUI-Scans persistieren Walk- und Eval-Fehler.
- Long-Path-Normalisierung für Win32 (`\\?\` / `\\?\UNC\…`).
- Paged LDAP-Search und transitive Gruppen via `LDAP_MATCHING_RULE_IN_CHAIN`.
- `Debug`-Impl von `LdapParams` maskiert das Bind-Passwort, damit `{params:?}` keine Secrets in Logs schreibt.
- Windows-Pfade werden strenger validiert; CSV trägt jetzt auch `local_group_status`, `matched_aces`, `contributing_sids`.
- Share-DACL-Lesefehler werden als Warnung im Risiko-View sichtbar (`Incomplete`-Marker).
- Exportdatei nur mit `--force` überschreiben.
- `share_scanner` mit Level-502-Enumeration, lokalem Pfad und Localhost-UNC-Behandlung.
- `BroadGroupWriteRule`: False-Positive behoben — meldet jetzt nur, wenn der breite Principal tatsächlich Write-Bits beigetragen hat.

---

## [0.1.0] — 2026-05-21

**Erste lauffähige Version: CLI, GUI-Prototyp, alle Kern-Crates.**

### Hinzugefügt
- Workspace-Setup mit `adpa_core` und `ad_resolver`.
- NTFS-DACL-Lesen via `GetNamedSecurityInfoW` (`fs_scanner`).
- ACE-Normalisierung über `NormalizedRights`.
- Effektive-NTFS-Berechtigungs-Berechnung in `permission_engine`.
- CLI-Prototyp mit formatierter Ausgabe (Steps 8 + 9).
- CSV-Export mit CLI-`--output`-Flag (Step 10).
- SQLite-Cache und Scan-Historie (`persistence`, Step 11).
- Mehr-Ordner-Tree-Scan mit DB-Persistenz (Step 12).
- SMB-Share-Scanner (`share_scanner`, Step 13).
- NTFS ∩ Share-Kombination im CLI-Scan (Step 14).
- GUI-Prototyp mit `egui`/`eframe`, Analyze- und Scan-Tab (Step 15).
- Risk-Engine, HTML-Export, Delta-Vergleich, Installer-Skript (Steps 16-19).
- README mit Projektbeschreibung, Nutzung und Entwicklungsstand.
- GitHub-Actions-Release-Pipeline.

---

## Urheberschaft

**Konzeption, Spezifikation, Steuerung und Review:** Birger Labinsch — Fachinformatiker Anwendungs­entwicklung / Prompt Engineer.
**Implementierung:** Claude Opus 4.7 (Anthropic) als KI-Modell, unter direkter Anleitung von Birger Labinsch.

Jeder Commit dieses Repositories trägt eine `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`-Zeile, die den KI-Anteil pro Änderung sichtbar macht.
