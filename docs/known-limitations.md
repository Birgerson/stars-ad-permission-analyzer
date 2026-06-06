# Stars — Bekannte Grenzen und Roadmap (v1.6+)

**Stand:** v1.5.12 — 2026-06-05
**Zweck:** Ehrliche Aufzählung der Stellen, an denen Stars **strukturell
nicht garantieren kann**, ein vollständiges Bild zu liefern.

Stars ist und bleibt ein read-only-Anzeigetool. Diese Datei beschreibt
Bereiche, in denen die aktuelle Implementierung **erkennt**, dass etwas
fehlt (`incomplete = true`), das fehlende Wissen aber **nicht produktiv
auflösen** kann. Jede Limitation ist ein eigener Eintrag, damit
spätere Beiträge sie einzeln adressieren können.

> **Bezug zur Marker-Tabelle in
> [features-and-limitations.md](features-and-limitations.md):** Die
> dort dokumentierten Marker (`IdentityNotInConfiguredLdapBase`,
> `IdentityLookupFailed`, `GroupResolutionFailed`, …) machen die hier
> beschriebenen Lücken **sichtbar**. Diese Datei beschreibt, *was*
> Stars an strukturellen Lücken hat, die Marker-Tabelle beschreibt,
> *wie* sie im Befund erscheinen.

---

## L1 — Foreign Security Principals (FSP) werden nicht explizit erkannt

**Priorität:** High
**Tracking:** v1.6.0 Kandidat
**Bezug:** ADR 0036 (Erweiterungspunkt), ADR 0034

### Problem

In Multi-Domain-Forests oder Inter-Forest-Trusts werden Trust-Principals
in der Home-Domain als **Foreign Security Principal (FSP)** im Container
`CN=ForeignSecurityPrincipals,DC=…` repräsentiert. Das FSP-Objekt trägt
die Trust-SID als `objectSid`, aber das Mitgliedschafts-Schema läuft
über das FSP-Objekt, nicht über das User-Objekt in der Trust-Domain.

Aktueller Stars-Pfad bei einer Trust-SID:

1. LDAP-Suche per `objectSid` im konfigurierten `base_dn` → Miss (das
   FSP liegt in einem anderen LDAP-Subtree).
2. LSA-Reverse-Lookup → Hit.
3. → `IdentityScopeStatus::OutsideConfiguredLdapBase` + Marker.

Stars sieht damit **nicht**, dass eine lokale Home-Domain-Gruppe (z. B.
`Domain Admins` der Home-Domain) den FSP als Mitglied enthält. Solche
Gruppen-ACEs wirken effektiv für den Trust-User, werden aber nicht
ausgewertet.

### Effekt

Der Befund unterschätzt die Rechte des Trust-Users in der Home-Domain.
Marker (`IdentityNotInConfiguredLdapBase`, `GroupResolutionFailed`)
sind gesetzt — der Auditor weiß, dass etwas fehlt — aber Stars zeigt
nicht, *welche* Home-Domain-Gruppen den User über FSP erfassen.

### Lösungsansatz

- Bei `OutsideConfiguredLdapBase` zusätzlich im
  `CN=ForeignSecurityPrincipals`-Container der konfigurierten Home-Domain
  per `objectSid` suchen.
- Bei Treffer: Mitgliedschaften des FSP-Objekts rekursiv auflösen
  (LDAP-`memberOf` auf dem FSP-Objekt → Home-Domain-Gruppen).
- Neuer Diagnose-Marker `IdentityResolvedViaForeignSecurityPrincipal`
  oder `IdentityScopeStatus::OutsideConfiguredLdapBaseViaFsp`.
- Memberships ergänzen (nicht ersetzen) — Trust-Domain-Gruppen kennt
  Stars weiterhin nicht.

### Test-Plan

LDAP-Fake erweitern um FSP-Container + Home-Domain-Gruppe, die den FSP
als Member trägt. Erwartung: `engine_flags` enthalten die
Home-Domain-Gruppe, neuer Marker erscheint.

---

## L2 — Global Catalog (GC) Bind wird nicht unterstützt

**Priorität:** High
**Tracking:** v1.6.0 Kandidat
**Bezug:** ADR 0034, features-and-limitations.md Abschnitt 2

### Problem

UPN-Lookup und SID-Suche sind im Active Directory nur dann
forestweit eindeutig, wenn man gegen den **Global Catalog (Port 3268)**
bindet. Stars nutzt aktuell nur den normalen LDAP-Port (389/636) und
sucht damit ausschließlich in der konfigurierten Domain.

Stars *dokumentiert* den GC-Workaround:
- ADR 0034 nennt ihn.
- Der UPN-Fehlertext sagt explizit „bind against a Global Catalog (port
  3268)".
- features-and-limitations.md verweist auf `gc://…:3268/…`.

Aber Stars *implementiert* ihn nicht — der Anwender muss manuell eine
zweite Stars-Analyse mit dem `base_dn` der Partner-Domain laufen
lassen.

### Effekt

Multi-Domain-Audit braucht aktuell entweder mehrere Stars-Läufe oder
gibt unvollständige Ergebnisse. Beides ist Markiert (incomplete), aber
beides ist unkomfortabel.

### Lösungsansatz

- Neuer Konfig-Modus „GC" in `LdapConfig` (Port 3268, leerer `base_dn`
  zulässig).
- `PrincipalResolver` erkennt GC-Mode und überspringt die
  `OutsideConfiguredLdapBase`-Klassifikation, weil der GC forestweit
  indexiert.
- Doku in features-and-limitations.md anpassen.

### Test-Plan

Live-Test gegen einen DC mit GC-Rolle (kein Fake-Backend nötig, weil
das LDAP-Protokoll dasselbe ist — nur der Port und Scope ändert sich).

---

## L3 — SID-History wird nicht ausgewertet

**Priorität:** Medium
**Tracking:** v1.7+ Kandidat

### Problem

In Domain-Migrationsszenarien tragen User das Attribut `sIDHistory`,
das frühere SIDs aus migrierten Domains enthält. NTFS-DACLs, die nicht
mit-migriert wurden, referenzieren teilweise diese alten SIDs.

Stars wertet `sIDHistory` aktuell nicht aus. Wenn die DACL eine
SID-History-SID enthält, kann der match auf den User nicht erfolgen.

### Effekt

Befunde unterschätzen die Rechte migrierter User in nicht-migrierten
Filesystem-Strukturen. Anders als bei L1 produziert das hier **keinen
Marker** — Stars sieht die alte SID einfach als "anderer User" und
findet keinen Match.

### Lösungsansatz

- `parse_identity_from_entry` zusätzlich das `sIDHistory`-Multi-Value-
  Attribut auswerten.
- `PrincipalResolution` um `historical_sids: Vec<Sid>` erweitern.
- Token-Bau in `build_token_sids_with_context` ergänzt die
  History-SIDs.
- Neuer Marker `MembershipResolvedViaSidHistory` mit historischer SID
  im Reason, damit der Auditor sieht, dass ein Recht über die alte
  SID greift.

### Test-Plan

LDAP-Fake erweitern um `sIDHistory`-Attribut. ACE auf alter SID,
Erwartung: Recht wird gewährt und Marker erscheint.

---

## L4 — Cross-Forest-Trust-Effekte sind nicht modelliert

**Priorität:** Medium
**Tracking:** v1.7+ Kandidat
**Bezug:** L1, L2

### Problem

Forest-Trusts haben Konfigurationsoptionen, die zur Laufzeit am DC
wirken:

- **Selective Authentication** (auch „Authentication Firewall"): der
  Trust-User darf nur an bestimmten Servern authentifizieren —
  selbst wenn die DACL ihm Rechte gewährt, kann er sich nicht
  anmelden.
- **SID Filtering / Quarantine**: bestimmte SIDs aus dem Trust werden
  ignoriert (Schutz vor SID-Spoofing).

Stars sieht die rohe DACL und berechnet, was sie *theoretisch* gewährt.
Was am realen DC dann tatsächlich gefiltert wird, sieht Stars nicht.

### Effekt

Stars-Befunde für Trust-User können **zu hoch** sein — die DACL würde
gewähren, aber Selective Auth oder SID Filtering blockt zur Laufzeit.

### Lösungsansatz

- Stars-Doku: features-and-limitations.md klar dokumentieren, dass
  Stars die DACL-Sicht zeigt, nicht das gefilterte Laufzeit-Ergebnis.
- (Optional) `trustAttributes` und `trustDirection` aus AD lesen und
  als Read-Only-Info im Bericht zeigen.
- Echte Erkennung der Filter-Wirkung würde voraussetzen, dass Stars
  einen synthetischen Logon-Versuch macht — verletzt das
  Read-Only-Prinzip → bewusst **nicht** implementieren.

### Test-Plan

Keine automatisierte Erkennung möglich; Doku-only.

---

## L5 — `OutsideConfiguredLdapBase`-Identities haben leere Memberships

**Priorität:** Medium
**Tracking:** v1.7+ Kandidat
**Bezug:** L1, L2, ADR 0039

### Problem

Wenn Stars eine SID per LSA auflöst, aber das konfigurierte LDAP-`base_dn`
sie nicht indexiert, läuft die Pipeline in
`scope_status = OutsideConfiguredLdapBase`,
`group_resolution_status = NotAttempted`. Seit v1.5.2 ist das mit einem
`group_resolution_failure_reason` markiert (Befund ist `incomplete`),
aber die tatsächlichen Memberships bleiben **leer**.

### Effekt

Cross-Domain-Mitgliedschaften des Trust-Users werden nicht ausgewertet.
Der Befund ist als incomplete markiert, das Recht wird aber im Zweifel
zu niedrig berechnet.

### Lösungsansatz

Zweigleisig (kann unabhängig implementiert werden):

a) **L1 (FSP-Pfad):** Mitgliedschaften des FSP-Objekts in der
   Home-Domain ergänzen.
b) **L2 (GC-Pfad):** Wenn ein GC konfiguriert ist, Mitgliedschaften
   forestweit über den GC abfragen.

Ohne L1 oder L2 bleibt L5 strukturell offen.

### Test-Plan

Siehe L1 und L2.

---

## L6 — Multi-Domain-Live-Integrationstests fehlen

**Priorität:** High (Validierung der vorhandenen Architektur)
**Tracking:** Sobald ein Test-Forest verfügbar ist

### Problem

Die zentrale Principal-Pipeline (ADR 0036) ist mit **In-Memory-Fakes**
abgedeckt:

- `FakeLdapBackend` simuliert LDAP-Hit/Miss/Fehler.
- `FakeLsaBackend` simuliert LSA-Hit/Miss.

Das deckt die *strukturelle* Korrektheit ab — die Pipeline tut, was die
Code-Logik vorgibt. **Niemand hat das gegen einen echten
Multi-Domain-Forest mit Trust laufen lassen.**

Die `#[ignore]`-markierten Integrationstests im Code (`sam.rs`,
`local_groups.rs`, …) laufen nur, wenn man explizit
`cargo test -- --ignored` auf einem DC ausführt.

### Effekt

Unbekannte Real-World-Fallstricke (LDAP-Server-Eigenheiten, Referrals,
spezifische Trust-Konfigurationen) sind nicht abgedeckt. Strukturell
richtig ≠ in der Wildnis bestätigt.

### Lösungsansatz

- Test-Forest in Proxmox aufsetzen (passt zu
  [Deployment-Ziel](anwender-handbuch.md)): zwei Domains, ein Trust.
- Stars-Smoke-Test-Skript, das die Pipeline-Cases (L1, L2, L5)
  manuell durchspielt und das Ergebnis gegen Erwartungen prüft.
- Ergebnisse als Markdown-Tabelle ins Repo.

### Test-Plan

Eigene Aufgabe; vermutlich initial manuell, später als
`#[ignore]`-Test mit dokumentierten Voraussetzungen.

---

## L7 — Token-Privilegien (`SeBackupPrivilege`, …) werden nicht modelliert

**Priorität:** Low
**Tracking:** vermutlich nie — Out-of-Scope

### Problem

Windows gewährt Konten mit Token-Privilegien (`SeBackupPrivilege`,
`SeRestorePrivilege`, `SeTakeOwnershipPrivilege`) effektiven Zugriff
unabhängig von der DACL. Backup-Operator kann produktiv lesen, was die
DACL nicht gewährt.

### Effekt

Stars-Befunde zeigen nur die DACL-Sicht. Wer wissen will, *kommt
dieser User effektiv ran*, muss Token-Privilegien manuell ergänzen.

### Lösungsansatz

- features-and-limitations.md dokumentiert das bereits (Einschränkung
  10).
- Stars könnte aus `Domain Admins`, `Backup Operators` etc. die
  Mitgliedschaft als Hinweis rendern — macht es aktuell nicht.

### Test-Plan

Out-of-Scope. Doku reicht.

---

## L8 — Dynamic Access Control (DAC) / Conditional ACEs werden nicht ausgewertet

**Priorität:** Low
**Tracking:** vermutlich nie — Out-of-Scope

### Problem

Windows DAC (Claims-basierte ACEs) wird vom Stars-Parser nicht
verstanden. Conditional ACEs werden als `UnsupportedShareAces` /
`unsupported_ace_count` gezählt und übersprungen.

### Effekt

Stars markiert das als `incomplete`. Die DAC-Logik ist aber nicht
ausgewertet.

### Lösungsansatz

- features-and-limitations.md dokumentiert das (Einschränkung 11).
- DAC-Parser wäre eine eigene große Arbeit (SDDL-Conditional-Expression).
- Verbleibt als bewusste Out-of-Scope-Entscheidung.

### Test-Plan

Out-of-Scope.

---

## Status-Übersicht

| Limit | Priorität | Marker vorhanden? | Auflösung möglich? |
| --- | --- | --- | --- |
| L1 — FSP | High | teilweise (Outside + GroupResolutionFailed) | ja, mit Implementierung |
| L2 — GC-Bind | High | teilweise (Outside + UPN-Fehler) | ja, mit Implementierung |
| L3 — SID-History | Medium | **nein** | ja, mit Implementierung |
| L4 — Cross-Forest-Filter | Medium | nein | nein (Doku-only) |
| L5 — Leere Memberships | Medium | ja (incomplete) | nur via L1/L2 |
| L6 — Live-Tests | High | n/a | ja, mit Setup |
| L7 — Token-Privilegien | Low | nein | bewusst out-of-scope |
| L8 — DAC | Low | ja (incomplete) | bewusst out-of-scope |

## Beitragspolitik

Wer eine dieser Limits adressieren will:

1. ADR schreiben (Format `docs/adr/00NN-...md`), die Architektur-
   entscheidung dokumentieren.
2. Tests mit Fakes (für L1, L3, L5) oder gegen Live-Setup (L2, L6).
3. features-and-limitations.md aktualisieren (Status,
   eventuell neue Marker).
4. CHANGELOG-Eintrag.
5. Diese Datei beim entsprechenden Eintrag auf "geschlossen in vX.Y.Z"
   setzen.

Read-Only-Prinzip bleibt bei jeder Erweiterung gewahrt: Stars
**zeigt** Lücken, **erklärt** sie, **schließt** sie strukturell —
verändert aber nie Zielsysteme.
