# ADR 0018 — CSV-Export: Vollständigkeits-Diagnose und strukturierte Audit-Daten

**Status:** Akzeptiert / Accepted  
**Datum / Date:** 2026-05-24

## Kontext / Context

Der CSV-Export trug bisher 15 Spalten — alle Top-Level-Felder einer
`EffectivePermission` plus `share_status` und `unsupported_aces` als
Diagnose. Drei wichtige Audit-Aspekte fehlten:

1. **`local_group_status`** — der `LocalGroupEvalStatus` markiert das
   Ergebnis als unvollständig, wenn lokale Server-Gruppen nicht
   aufgelöst werden konnten (Access Denied, RPC-Fehler, …). Der
   JSON-Export trägt das strukturiert; CSV machte den Audit-Nutzer
   blind dafür.
2. **`matched_aces`** — strukturierte Liste der ACEs, deren Trustee
   im Token war. Vom Risk-Engine genutzt; für externe Audit-
   Pipelines im CSV nicht zugänglich.
3. **`contributing_sids`** — pro SID welche Bits effektiv beigetragen
   haben (für Broad-Group-Risikoanalyse). Ebenfalls nur im JSON
   verfügbar.

Risk Findings selbst waren bereits dokumentiert nicht im CSV (CLI gibt
einen `[Note]`-Hinweis aus), für sie ist HTML bzw. JSON das passende
Format.

Siehe Review-Befund 9.

## Entscheidung / Decision

1. **Vier neue Spalten am Ende der CSV** — Reihenfolge bewusst so,
   dass bestehende Importer mit fester Spaltenposition für die ersten
   15 Spalten unverändert weiterlaufen:

   | # | Spalte | Inhalt |
   |---|---|---|
   | 16 | `local_group_status` | `not_queried` / `applied` / `not_available` |
   | 17 | `local_group_error` | Fehlertext bei `not_available`, sonst leer |
   | 18 | `matched_aces_json` | Kompaktes JSON-Array, immer gefüllt (`[]` wenn leer) |
   | 19 | `contributing_sids_json` | Kompaktes JSON-Array, immer gefüllt (`[]` wenn leer) |

2. **Status und Begründung in getrennten Spalten** (nicht
   `not_available:<reason>` als ein Feld) — damit Excel-/grep-Filter
   weiter auf reine Status-Werte ansprechen können. Das ist eine
   bewusste Abweichung vom Format der `share_status`-Spalte
   (`read_failed:<reason>`), wo aus Rückwärtskompatibilität nichts
   geändert wurde.

3. **JSON-in-CSV-Zellen** für `matched_aces` und `contributing_sids`:
   - Pro `matched_aces`-Eintrag: `{sid, kind, mask: "0xHHHHHHHH", inherited}`
   - Pro `contributing_sids`-Eintrag: `{sid, mask: "0xHHHHHHHH"}`

   Leere Listen erscheinen als `"[]"` (nicht als leere Zelle), damit
   Konsumenten die Spalte garantiert als JSON parsen können.

4. **Risk Findings bleiben außerhalb der CSV.** Der CLI-`[Note]`-
   Hinweis ist präziser geworden: er nennt explizit JSON als
   strukturiertes Format für Risks, Matched ACEs und Contributing
   SIDs in ihrer vollen Tiefe. CSV ist die Top-Level-Tabelle, JSON
   ist die kanonische maschinenlesbare Form für den ganzen Baum.

## Begründung / Rationale

- **Diagnostische Lücke schließen, ohne Strukturentscheidungen
  umzuwerfen:** Audit-Nutzer, die CSV als ihr primäres Format haben
  (Excel, Power BI, simple Pipelines), sehen jetzt die unvollständige
  Berechnung anstatt sie zu übersehen.
- **JSON-Strings in CSV-Zellen sind ein bewusster Trade-off:** Die
  Detail-Listen sind variabel lang und passen schlecht in ein flaches
  Tabellen-Schema. Eine zweite Detail-CSV pro Detail-Liste wäre
  sauber, aber zwingt Konsumenten zu Joins und vervielfacht
  Dateioperationen. JSON-Zellen sind weit verbreitet (Snowflake,
  BigQuery, jq) und vermeiden das.
- **Append-only** der neuen Spalten bewahrt rückwärtskompatible
  Spaltenpositionen 1–15.
- **Risk-Findings explizit JSON-only** trennt zwei Ebenen sauber:
  CSV = pro-(Pfad,Identität)-Zeile; JSON = vollständiger Bericht.

## Konsequenzen / Consequences

- 5 neue Tests in `exporter::csv::tests`:
  - `local_group_status_applied_serialized_correctly`
  - `local_group_status_not_available_records_reason_separately`
  - `matched_aces_serialized_as_compact_json_array`
  - `contributing_sids_serialized_as_compact_json_array`
  - `empty_matched_aces_and_contributing_sids_yield_empty_json_arrays`
- `headers_match_expected` wurde erweitert (15 → 19 Spalten).
- CLI-Hinweis bei CSV-Export ergänzt: weist jetzt auf JSON für
  strukturierte Details und Risks hin.
- Keine Schema-Änderung in `EffectivePermission` — die Daten sind
  bereits da; nur der CSV-Exporter zieht sie jetzt mit.
- `exporter` hatte `serde_json` bereits als Workspace-Dep — keine
  neue Abhängigkeit.
