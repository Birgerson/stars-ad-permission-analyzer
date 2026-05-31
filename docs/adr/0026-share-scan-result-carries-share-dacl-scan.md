# ADR 0026 — `ShareScanResult.share_dacls` trägt `ShareDaclScan`

**Status:** Akzeptiert / Accepted  
**Datum / Date:** 2026-05-25

## Kontext / Context

ADR 0024 hatte `ShareDaclScan { dacl, unsupported_count }` als
Return-Typ von `get_share_dacl` eingeführt, sodass der CLI/GUI-pro-Pfad-
Flow die Audit-Diagnose pro Share an die Engine durchreichen kann.

`scan_shares` (Aggregat-Funktion über alle Freigaben eines Servers)
bekam diese Information auch, aber das Feld
`ShareScanResult.share_dacls` blieb `Vec<(String, ShareDacl)>`. Der
`unsupported_count` floss damit nur in das Abschluss-Log (als
`unsupported_share_aces_total`) und wurde danach pro-Share verworfen.

Konsequenz für Konsumenten, die das volle `scan_shares`-Ergebnis statt
des pro-Pfad-Pfades nutzen: sie konnten zwar das Aggregat sehen, aber
nicht entscheiden, **welche** Freigabe wegen nicht ausgewerteter ACE-
Typen als `incomplete` gilt.

Review 2026-05-25, Finding 2 (Medium).

## Entscheidung / Decision

**`ShareScanResult.share_dacls` ist jetzt `Vec<(String, ShareDaclScan)>`.**
Pro Share wandert der komplette `ShareDaclScan` (DACL + unsupported
count) ins Ergebnis — keine Daten gehen am Aggregations-Boundary mehr
verloren.

Die Aufrufstelle in `scan_shares` pusht nicht mehr `(share.name,
scan.dacl)`, sondern `(share.name, scan)`. Das aggregierende
`unsupported_share_aces_total`-Log bleibt als operativer Schnellüberblick.

## Begründung / Rationale

- **Single source of truth**: pro Share gibt es jetzt genau einen Ort,
  an dem alle relevanten Audit-Daten liegen — die Aufrufer-Sicht ist
  einheitlich, egal ob sie `get_share_dacl` (eine Share) oder
  `scan_shares` (alle Shares) nutzen.
- **Datenverlust verhindern**: Audit-Diagnosen, die der Parser sammelt,
  dürfen am Aggregations-Boundary nicht abhanden kommen.
- **Geringer Bruch**: das Feld wurde laut Grep nur in den eigenen
  Tests des `share_scanner`-Crates konsumiert. Externe Konsumenten
  gibt es nicht.

## Konsequenzen / Consequences

- 1 neuer Test in `share_scanner::scanner::tests`:
  `share_dacls_field_preserves_per_share_unsupported_count` —
  konstruiert ein `ShareScanResult` mit `unsupported_count: 7` und
  prüft, dass der Wert über die Speicherung in `share_dacls`
  zugreifbar bleibt.
- Zwei bestehende Tests umgeschrieben, damit sie das neue
  `ShareDaclScan`-Tuple konstruieren bzw. `&scan.dacl` statt `dacl`
  matchen:
  - `permissions_equals_flattened_acl_entries_from_share_dacls`
  - `null_dacl_distinguishable_from_empty_acl_in_share_dacls`
- Keine API-Brüche außerhalb des Crates (kein externer Konsument).
- Keine Schema- oder Persistenz-Auswirkungen — `share_dacls` lebt nur
  in-Memory in `ShareScanResult`.
