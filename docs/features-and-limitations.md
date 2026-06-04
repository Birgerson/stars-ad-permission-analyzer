# Stars — Features, Grenzen und Hinweise zur Lesart der Ergebnisse

**Zielgruppe:** Windows-/AD-Administratoren mit Mischbestand
(Wald-und-Wiesen-Umgebung — Domain Controller, Fileserver, NTFS-Volumes,
SMB-Freigaben).
**Sprachregel:** Diese Datei ist die zentrale User-Doku für die Frage
„Was zeigt mir Stars korrekt, was nicht?". Wenn ein Feature hier nicht
steht oder ausdrücklich als Einschränkung markiert ist, gilt das auch.

> **Grundprinzip:** Stars ist und bleibt ein read-only-Analyse-Tool.
> Stars **schreibt nichts** an NTFS, SMB-Shares oder AD. Findings sind
> Hinweise — die produktive Behebung macht der Admin selbst.

---

## Was Stars zuverlässig kann

### Identität und Gruppen

- **SID ↔ Name-Auflösung** via LDAP (`objectSid`-Suche) und über die
  Windows-LSA (`LookupAccountSidW`, `LookupAccountNameW`).
- **Eingabe-Formate**: `DOMAIN\user`, `user@domain.tld` (UPN), reine
  `sAMAccountName` und SIDs (`S-1-5-…`). Mehrdeutige
  `sAMAccountName`-Treffer werden als Eindeutigkeits-Fehler gemeldet
  (kein stilles Auswählen) — siehe ADR 0032.
- **Rekursive Gruppenauflösung über LDAP**: über `memberOf` mit
  `LDAP_MATCHING_RULE_IN_CHAIN`. Damit gibt es keine N+1-Recursion und
  keine Range-Retrieval-Probleme bei großen Gruppen — auch keine
  Zyklen.
- **Primäre Gruppe** wird separat über `primaryGroupID` ausgewertet.
- **`disabled`-Status** wird im LDAP-Pfad über `userAccountControl`
  und im SAM-Pfad über `NetUserGetInfo` Level 1 gelesen — siehe ADR
  0033 und ADR 0035.

### NTFS-DACL-Auswertung

- **Allow- und Deny-ACEs**, **explizite und geerbte** Einträge,
  **Vererbungsflags** und **Propagation Flags** werden gelesen und im
  Pfad-Bericht getrennt ausgewiesen.
- **Owner**-SID und benannter Owner werden separat ausgewiesen.
- **Access-Mask-Normalisierung**: Windows-Access-Mask-Bits werden in
  normalisierte Rechte (Read, Write, Modify, Full Control, …)
  übersetzt; Rohdaten bleiben erhalten.
- **Identische Security Descriptoren** werden per Hash dedupliziert —
  die GUI zeigt einen Hinweis, wenn die DACL über große Pfadbäume
  identisch durchgereicht wird.
- **Lange Pfade** (`\\?\…`, UNC-Long-Path-Form `\\?\UNC\server\…`)
  werden unterstützt — siehe ADR 0031.
- **Reparse Points / Junctions / Symlinks** verursachen keine
  Endlosschleifen mehr; Schleifen werden erkannt und sichtbar gemacht.

### SMB-Share-Auswertung

- **Share-DACL und NTFS-DACL bleiben getrennt** im Datenmodell und im
  Bericht. Die effektive SMB-Berechtigung ist die restriktive
  Kombination aus beidem (Maske ∩ NTFS).
- **Administrative Freigaben** (`C$`, `ADMIN$`, …) sind standardmäßig
  als solche markiert.
- **UNC-Pfade und lokale Zielpfade** werden konsistent normalisiert
  (`validation::path::effective_smb_target`, ADR 0031).
- **`--smb-server` ohne `--share-name`** (und umgekehrt) wird als
  Konfigurationsfehler abgelehnt — sonst verunreinigt der unvollständige
  SMB-Kontext die lokale-Gruppen-Auflösung still. Closes Review
  2026-06-04 Runde 2, Finding 2.

### Berechtigungspfad-Erklärung

- Jeder Befund trägt einen **erklärbaren Pfad** in der Form
  `User → Group A → Group B → ACL-Eintrag → normalisiertes Recht`.
- **Lokale Gruppen-Ketten** auf dem Zielserver werden über
  `NetLocalGroupGetMembers` rekonstruiert (ADR 0029) — die
  Vermittler-Schicht (z. B. `Domain Admins → BUILTIN\Administrators`)
  ist im Pfad sichtbar.
- **SID → Name-Tabelle** wird einmal pro Scan aufgebaut; jeder
  Erklärungspfad rendert `DOMAIN\Name` statt nackter SIDs.

### Scan, Persistenz und Export

- **Abbrechbare Scans** über Cancel-Token; die GUI bleibt während des
  Scans bedienbar.
- **Scan-Historie** in SQLite (lokal, `persistence`-Crate) — siehe
  ADR 0026.
- **Delta-Vergleich** zwischen zwei Scans (was hat sich pro Pfad an
  effektivem Recht geändert?).
- **Trustee-Ansicht** pro Pfad (Wer-hat-Zugriff?), ergänzt zum
  klassischen pro-Benutzer-Bericht.
- **Exporter**: CSV, JSON (variant-tagged Diagnostics — ADR 0021),
  HTML mit Diagnostik-Badges.
- **Update-Manager-Skelett**: Versionierung, Signaturprüfung,
  Update-Pfad-Validierung sind als eigene Komponente ausgewiesen
  (ADR 0028, ADR 0030).

### Strukturierte Diagnose-Marker pro Befund

Jeder `EffectivePermission` trägt einen `diagnostics`-Vector mit
variant-tagged JSON. CLI, HTML und JSON rendern jeden Marker mit
eigener Beschreibung — eine Liste der Marker und ihre Bedeutung:

| Marker | Schweregrad | Risk-`incomplete`? | Bedeutung |
| --- | --- | --- | --- |
| `NonCanonicalDaclOrder { at_index }` | medium | nein | DACL ist nicht in Windows-Canonical-Order. AccessCheck läuft trotzdem in gespeicherter Reihenfolge — das Ergebnis kann von einer kanonisierten Erwartung abweichen. |
| `UnsupportedShareAces { count }` | medium | **ja** | Share-DACL enthielt ACE-Typen, die der Parser nicht auswerten konnte (Object-/Callback-/Conditional-/herstellerspezifisch). Share-Maske ist potentiell unvollständig. |
| `DomainGroupRecursionIncomplete` | medium | **ja** | Gruppenauflösung lief über SAM/LSA statt LDAP. `NetUserGetGroups` liefert nur direkte globale Gruppen — verschachtelte Domain-Gruppen sind nicht rekursiv. |
| `IdentityDisabled` | info | nein | Konto ist in AD via `userAccountControl/UF_ACCOUNTDISABLE` deaktiviert. ACL-theoretische Rechte stimmen, aber das Konto kann sich normal nicht authentifizieren. |
| `IdentityNotInConfiguredLdapBase` | medium | **ja** | LSA hat SID aufgelöst, aber das konfigurierte LDAP-`base_dn` indexiert sie nicht. Typisch in Multi-Domain-Forests / Trusts — Cross-Domain-Mitgliedschaften können fehlen. |
| `IdentityDisabledStatusUnknown` | info | nein | `disabled`-Flag konnte nicht ermittelt werden (z. B. SAM-Pfad ohne `NetUserGetInfo`-Erfolg oder LDAP ohne User-Objekt). |

Die Spalte „Risk-`incomplete`?" zeigt, ob `risk_engine::is_incomplete()`
diesen Marker matched — `incomplete = true` heißt: das Risk-Finding ist
strukturell unvollständig und sollte als solches im Audit erscheinen.

---

## Was Stars **nicht** macht (per Design)

Stars verändert grundsätzlich **nichts** an Zielsystemen. Folgende
Funktionen sind dauerhaft kein Teil des Produkts:

- NTFS-Berechtigungen ändern, bereinigen oder reparieren.
- Owner ändern, Vererbung aktivieren/deaktivieren.
- SMB-Share-Berechtigungen ändern.
- AD-Benutzer, AD-Gruppen, AD-Computer ändern.
- Gruppenmitgliedschaften ändern.
- Dateien oder Ordner auf Zielsystemen erstellen, ändern, verschieben,
  löschen.
- ACL-Auto-Reparatur, Remediation-Workflows, Repair-Recipes.
- Automatische Berechtigungsempfehlungen mit Umsetzung.
- Credential Harvesting; Dateinamen-Treffer auf
  `password|secret|credentials|…` werden markiert, **aber nicht
  geöffnet oder inhaltlich verarbeitet**.
- Agenten-Rollout auf Fremdsysteme.
- Aktive SIEM-Reaktion.

> Diese Liste folgt direkt der CLAUDE.md/AGENTS.md-Projektgrenze. Jeder
> Beitrag, der eine schreibende Operation in den Code einführt, wird
> als Bruch dieser Grenze gewertet.

---

## Bekannte Einschränkungen und ihre Lesart

### 1. SAM-Fallback ohne LDAP (Domain Controller / lokal)

- **Wann:** Wenn Stars ohne `--server`/LDAP-Bind läuft (z. B. auf
  einem DC oder einer Workstation als schnelle Voranalyse).
- **Was passiert:** Gruppen kommen über `NetUserGetGroups` +
  `NetLocalGroupGetMembers`. Diese liefern nur **direkte** Domänen-
  und lokale Gruppen.
- **Folge:** Verschachtelte Domain-Gruppen jenseits der direkten
  Mitgliedschaft sind nicht im Token. ACEs auf solche tief
  verschachtelten Gruppen werden im Befund nicht erkannt.
- **Wie sichtbar:** Marker `DomainGroupRecursionIncomplete` an jedem
  Befund; Risk-Findings sind `incomplete = true`. CLI druckt den
  Hinweis im Diagnostics-Block; HTML zeigt ein `badge-medium`.
- **Lösung:** `--server`, `--base-dn`, `--bind-dn` und Passwort
  setzen — dann läuft die rekursive Auflösung serverseitig per
  `LDAP_MATCHING_RULE_IN_CHAIN`. Siehe ADR 0033.

### 2. Multi-Domain-Forest / Trusted Domains

- **Wann:** Identity wird per `DOMAIN\user` oder UPN aufgelöst, das
  konfigurierte LDAP-`base_dn` zeigt aber nur auf eine einzelne Domain
  (typischer Fall: forest-weiter Trust).
- **Was passiert:** LSA löst die SID korrekt auf; LDAP findet das
  Objekt nicht — Stars fällt jetzt auf eine **LSA-only-Identity**
  zurück (Name + Domain aus LSA, keine `userAccountControl`-Information).
- **Folge:** Gruppenrekursion läuft nur in der konfigurierten
  Domain — Cross-Domain-Mitgliedschaften des Trust-Partners können
  fehlen. `disabled` ist nicht bekannt.
- **Wie sichtbar:** Marker `IdentityNotInConfiguredLdapBase` (medium,
  `incomplete = true`) **und** `IdentityDisabledStatusUnknown` (info).
- **Lösung (manuell):** Zweite Stars-Analyse mit dem `base_dn` der
  Partner-Domain laufen lassen, oder gegen den Global Catalog binden
  (`gc://…:3268/…`). Siehe ADR 0034.

### 3. Zugriff verweigert während des Scans

- **Wann:** Stars hat keine Leserechte auf einen Pfad oder dessen
  DACL (Access Denied).
- **Was passiert:** Der einzelne Pfad wird im Scan-Fehlerprotokoll
  vermerkt (mit Pfad und Ursache); der Scan läuft weiter.
- **Wie sichtbar:** Im CLI als `[scan error]`-Zeile, in der GUI als
  Eintrag in der Scan-Fehlerliste, im HTML-Bericht eigene Sektion
  „Scan errors".
- **Lösung:** Stars als Konto starten, das mindestens
  `SeBackupPrivilege` oder Lese-DACL-Rechte auf den Zielpfad hat.

### 4. Unsupported Share-ACEs

- **Wann:** Die Share-DACL enthält Object-ACEs, Callback-ACEs,
  Conditional-ACEs oder herstellerspezifische Einträge.
- **Was passiert:** Diese ACEs werden gezählt und übersprungen — die
  Share-Maske ist potentiell unvollständig.
- **Wie sichtbar:** Marker `UnsupportedShareAces { count }` (medium,
  `incomplete = true`). Risk-Findings sind als unvollständig
  ausgewiesen.

### 5. Nicht-kanonische DACL-Reihenfolge

- **Wann:** Die DACL eines Objekts ist nicht in
  Windows-Canonical-Order (z. B. Allow vor Deny). Windows wertet die
  Liste trotzdem in gespeicherter Reihenfolge aus.
- **Was passiert:** Stars wertet ebenfalls in gespeicherter Reihenfolge
  aus und meldet die Abweichung.
- **Wie sichtbar:** Marker `NonCanonicalDaclOrder { at_index }`
  (medium, nicht `incomplete`).
- **Lesart:** Ein Auditor sollte die DACL nachordnen lassen — Stars
  tut das nicht.

### 6. Deaktivierte Konten

- **Wann:** Konto trägt `UF_ACCOUNTDISABLE` (LDAP) oder
  `NetUserGetInfo` liefert das gesetzte Flag (SAM).
- **Was passiert:** ACL-theoretische Rechte werden weiter berechnet
  und ausgewiesen.
- **Wie sichtbar:** Marker `IdentityDisabled` (info). Audit-Konsumenten
  trennen so „die ACL würde Modify gewähren" von „der Account kann
  sich authentifizieren". Siehe ADR 0033.
- **Hinweis:** Bei SAM-Pfad mit fehlgeschlagenem `NetUserGetInfo`
  erscheint stattdessen `IdentityDisabledStatusUnknown` — siehe
  Einschränkung 2.

### 7. Reparse Points, Junctions, symbolische Links

- **Wann:** Der Scan stößt auf Reparse Points (NTFS-Links auf andere
  Verzeichnisse oder Volumes).
- **Was passiert:** Der Walker folgt Reparse Points und erkennt
  Schleifen anhand der Pfad-Identität — Endlosschleifen sind
  ausgeschlossen.
- **Wie sichtbar:** Reparse-Point-Treffer und erkannte Schleifen
  werden in der GUI-Trefferliste sichtbar markiert; im HTML-Bericht
  eigener Hinweis.
- **Lesart:** Folgen ist eingebaut, weil ein Wechsel auf ein anderes
  Volume sonst „verschwindet". Wer das nicht will, schneidet den
  Pfad in der Scan-Wurzel aus.

### 8. Verwaiste SIDs (echte Orphans)

- **Wann:** Eine ACE referenziert eine SID, zu der weder LDAP noch
  LSA ein Konto findet (typisch nach AD-Object-Löschung).
- **Was passiert:** Identity ist `IdentityKind::Orphaned`, Name ist
  nicht gesetzt; die SID bleibt erhalten und wird angezeigt.
- **Wie sichtbar:** Pfadanzeige enthält die rohe SID; Audit-Konsumenten
  sehen „SID existiert in der DACL, hat aber keinen Träger mehr".
- **Wichtig:** Eine SID, die in einer **anderen Domain** existiert (die
  das konfigurierte LDAP nur nicht indexiert), ist **keine** Orphan
  — sie taucht jetzt mit Name + Marker
  `IdentityNotInConfiguredLdapBase` auf. Siehe Einschränkung 2.

### 9. Lokale Gruppen vom Zielserver

- **Wann:** Die NTFS-DACL referenziert eine lokale Gruppe des
  Datei-/SMB-Servers (z. B. `BUILTIN\Administrators` oder eine
  selbst angelegte lokale Gruppe).
- **Was passiert:** Stars löst lokale Server-Gruppen vom selben Server
  auf wie die Share-DACL (`effective_smb_target`, ADR 0031). Bei
  expliziter Vorgabe gewinnt `--smb-server`.
- **Wenn die Auflösung scheitert:** `LocalGroupEvalStatus::NotAvailable`
  → Eintrag im Diagnostics-Block; das Ergebnis ist als unvollständig
  ausgewiesen.
- **Lesart:** Ohne erfolgreiche lokale-Gruppen-Auflösung können ACEs
  auf lokale Gruppen für den Benutzer unsichtbar bleiben — Marker
  „local groups unavailable" weist genau darauf hin.

### 10. Berechtigungen über Token-Privilegien

- **Was wir nicht modellieren:** Privileg-basierter Zugriff
  (`SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`).
  Diese gewähren effektiv Zugriff, sind aber **kein** Teil der DACL.
- **Folge:** Ein Backup-Operator kann produktiv lesen, was die DACL
  ihm nicht gewährt. Stars zeigt nur den ACL-Befund.
- **Lesart:** Wenn der Auditor wissen will, „kommt dieser User
  effektiv ran?", muss er Token-Privilegien manuell ergänzen — Stars
  beantwortet die Frage „was sagt die ACL?".

### 11. Dynamic Access Control (DAC) / Conditional ACEs

- **Was wir nicht modellieren:** Claims-basierte ACEs (Windows DAC).
  Diese werden als „unsupported" gezählt — siehe Einschränkung 4.
- **Lesart:** Stars ist ein DACL-Auditor, kein Claims-Auswerter.

### 12. SMB-Session-Layer

- **Was wir nicht modellieren:** SMB-Encryption-Policy, Signing-Pflicht,
  SMB-Versionsanforderungen, IP-Restriktionen via Firewall.
- **Lesart:** Stars vergleicht Share-DACL ∩ NTFS-DACL. Wer
  „darf der User überhaupt SMB?" beantworten will, braucht zusätzlich
  die SMB-Server-Konfiguration.

---

## Lesart eines Befunds — Schritt für Schritt

Ein typischer EffectivePermission-Eintrag enthält:

1. **Pfad** (normalisiert).
2. **Identität** (SID + Name + Domain + Kind).
3. **Effektive Rechte** (Read / Write / Modify / Full Control, …).
4. **NTFS-Rechte** und **Share-Rechte** getrennt (oder „—" wenn nicht
   relevant).
5. **Diagnostics**: variant-tagged Marker-Liste — siehe Tabelle oben.
6. **PermissionPath**: pro Schritt eine Zeile
   `User → Group → … → ACE → normalisiertes Recht`.

> **Goldene Regel:** Wenn ein Befund Marker enthält, gehört das
> Wort „möglicherweise" davor. Marker zeigen, dass die Auswertung
> bewusst nicht 100 % vollständig war — nicht, dass Stars geraten hat.

---

## Wenn ein Befund unerwartet ist

1. **Marker prüfen.** Steht `DomainGroupRecursionIncomplete` oder
   `IdentityNotInConfiguredLdapBase` dran, ist die Auflösung
   strukturell unvollständig. → Mit LDAP-Bind oder gegen den Global
   Catalog neu fahren.
2. **PermissionPath lesen.** Jede Stufe ist sichtbar — wo bricht die
   Erklärung ab? Welche Gruppe fehlt?
3. **Scan-Fehler prüfen.** Access Denied auf ein einzelnes Verzeichnis
   führt zu Lücken, die im Fehler-Tab/CLI-Block sichtbar sind.
4. **CLI als Gegenprobe.** Die GUI ist nur die Anzeigeschicht. Die
   CLI baut auf derselben Engine — wenn ein Befund in GUI und CLI
   identisch ist, liegt die Ursache nicht an der Darstellung.
5. **Schreibender Eingriff bleibt beim Admin.** Stars schlägt nicht
   vor, wie ACLs umzubauen sind — das wäre außerhalb des Scopes.

---

## Verweise

- [ADR-Index](adr/) — komplette Liste der Architekturentscheidungen.
- ADR 0021 — Permission Diagnostics als variant-tagged Enum.
- ADR 0026 — Persistente Scan-Historie.
- ADR 0029 — Membership-Path-Rekonstruktion.
- ADR 0031 — Shared UNC-Components und `effective_smb_target`.
- ADR 0032 — Identity-Input-Dispatcher und LDAP-Timeouts.
- ADR 0033 — Sichtbare Diagnostik für SAM-Fallback und deaktivierte
  Identitäten.
- ADR 0034 — Multi-Domain-LSA-Fallback für Identitätsauflösung.
- ADR 0035 — SAM-Pfad bestätigt `disabled` per `NetUserGetInfo`.
- [Audit-Kriterien](audit-kriterien.md) — Was Stars fachlich abdeckt.
