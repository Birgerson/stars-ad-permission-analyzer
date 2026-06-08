# ADR 0016 — GUI-Scans persistieren Walk-/Eval-Fehler in `scan_errors`

**Status:** Accepted  
**Date:** 2026-05-24

## Context

Der GUI-Worker sendete Walk-, Permission-Eval- und Setup-Fehler an die
UI (`WorkerEvent::ScanError`), aber `persist_scan` schrieb nur die
erfolgreichen `EffectivePermission`-Einträge und (bei `cancelled`)
einen einzelnen Abbruch-Marker in die SQLite-Historie. Access-Denied-,
Path-Not-Found-, Security-Descriptor- oder Eval-Fehler verschwanden
nach Schließen des Scan-Fensters.

Folgen:

- Historische GUI-Scans wirkten vollständiger als sie waren.
- Delta-Vergleiche und spätere Audits konnten nicht erkennen, welche
  Pfade gar nicht gelesen wurden.
- Der CLI-Pfad speicherte solche Fehler bereits korrekt — GUI und CLI
  hatten damit divergierende Audit-Pfade.

Siehe Review-Befund 6.

## Decision

1. **`ScanSummary` trägt jetzt eine strukturierte Fehlerliste.**
   `errors: usize` → `errors: Vec<ScanError>`. Die UI-Anzeige nutzt
   weiterhin `errors.len()` (im `ScanDone`-Event).

2. **Alle Fehlerquellen sammeln, nicht nur Walk-Fehler.** Der Worker
   füllt `summary_errors` aus drei Quellen:

   - Frühe Setup-Fehler (Pfad-/SID-Validierung, Connection-Inputs,
     Identity-Resolution) — gesammelt über einen Closure
     `make_early_summary`, der den Eintrag sowohl an die UI sendet als
     auch in die Summary aufnimmt.
   - Lokale-Gruppen-Auflösung mit `NotAvailable`-Status — bisher nur
     UI-Event, jetzt zusätzlich in der Summary.
   - Walk-Fehler aus `walk.errors` (Access-Denied, Path-Not-Found etc.).
   - Permission-Eval-Fehler aus dem Engine-Aufruf.

3. **`persist_scan` schreibt jeden Eintrag.** Signatur erweitert um
   `errors: &[ScanError]`; pro Eintrag ein `store.insert_error(&run_id, …)`.
   Der bestehende Abbruch-Marker (`path: None`,
   `"Scan cancelled by user — results are partial"`) wird wie zuvor
   nach den strukturierten Fehlern eingefügt.

4. **Neue `ScanStore::list_errors_for`** liest persistierte Fehler in
   Einfüge-Reihenfolge (per rowid) zurück. Wird vom GUI-Worker-Test
   genutzt und ist sinnvolle Diagnose-API für zukünftige Historien-
   Ansichten.

## Rationale

- **Parität CLI ↔ GUI:** Die Audit-Erwartung an „der Scan-Lauf in der
  Historie ist vollständig" muss in beiden Pfaden gleich sein.
- **Closure statt vierfacher Duplizierung:** Die früheren vier
  Early-Return-Sites bauten jeweils ein identisches
  `ScanSummary { ..., errors: 1, ... }`. `make_early_summary` ersetzt
  alle vier und garantiert, dass kein Pfad das UI-Event und die
  Persistenz aus der Synchronität laufen lässt.
- **`Vec<ScanError>` statt `usize`** als Single-Source-of-Truth: aus
  einer Liste kann man den Count ableiten, umgekehrt nicht.

## Consequences

- 3 neue Tests in `gui::worker::tests` (persistiert Walk-Fehler,
  ergänzt Abbruch-Marker, leerer Lauf bleibt leer).
- 2 neue Tests in `persistence::scan_store::tests` für die neue
  `list_errors_for`-API (Reihenfolge + Lauf-Isolation).
- Kein Schema-Migrationsbedarf — `scan_errors` existiert bereits und
  unterstützt `path` als nullable Spalte. Bestehende GUI-Scan-Historien
  sind weiterhin lesbar; nur neue Läufe profitieren von der vollen
  Fehler-Persistenz.
- Die Anzahl-Anzeige im `ScanDone`-Event und in der UI bleibt
  unverändert (semantisch und visuell).
