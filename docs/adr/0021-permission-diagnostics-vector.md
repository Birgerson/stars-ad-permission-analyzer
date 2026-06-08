# ADR 0021 — Strukturierte Diagnose-Marker pro Berechtigung

**Status:** Accepted  
**Date:** 2026-05-24

## Context

ADR 0012 (Stored-Order DACL-Auswertung) entscheidet bewusst, nicht-
kanonisch sortierte DACLs nach Windows-AccessCheck-Semantik in
gespeicherter Reihenfolge auszuwerten. Die Engine erkannte den Fall
über `first_non_canonical_position` und emittierte ein `tracing::warn!`.

ADR 0012 selbst notierte den Trade-off explizit: *„Eine spätere
strukturierte Diagnose (etwa ein `non_canonical_dacl: bool`-Feld) ist
möglich, sobald ein konkreter Audit-Use-Case sie verlangt."*

Der Folge-Review (2026-05-24) macht den Use-Case konkret: ein
log-only-Marker überlebt weder CLI-Lauf, GUI-Lauf, DB-Historie noch
Export. Ein Auditor, der ein überraschendes Effective-Rights-Ergebnis
sieht, hat keine Spur, **warum** es von der kanonisierten Erwartung
abweicht.

Folge-Befund 3.

## Decision

1. **Neuer Variant-tagged Enum `PermissionDiagnostic`** in
   `adpa_core::model`. Erster Marker:
   `NonCanonicalDaclOrder { at_index: usize }`.

   Tag-Format (`#[serde(tag = "kind")]`) lässt zukünftige Marker —
   z. B. „inheritance disabled", „SACL nicht lesbar" — ergänzen, ohne
   bestehende JSON-/DB-Daten zu brechen.

2. **`EffectivePermission.diagnostics: Vec<PermissionDiagnostic>`**
   als neues Pflichtfeld mit `#[serde(default)]`. Per Default leer;
   die Engine populiert es über den neuen Helfer
   `collect_diagnostics(dacl, path)`, der gleichzeitig das bisherige
   `warn!`-Log emittiert.

3. **Persistenz: neue TEXT-Spalte `diagnostics`** auf
   `effective_permissions` (Migration v6) mit `DEFAULT '[]'`. Alte
   Zeilen lesen sich als „keine Marker"; neue Zeilen tragen das
   JSON-Array. INSERT/SELECT erweitert; Round-Trip-Test deckt das ab.

4. **Exports und GUI:**
   - **JSON-Export:** automatisch via `Serialize` — ohne Extra-Arbeit.
   - **CSV-Export:** neue Spalte `diagnostics_json` (immer befüllt,
     leere Liste als `"[]"` — konsistent zu `matched_aces_json`).
   - **GUI Scan-View:** pro Zeile zeigt der Warn-Badge jetzt
     gemeinsam `N unsupported ACE(s), M diagnostic(s)`; eine
     aggregierte Meldung am Tabellenende fasst die Pfade mit
     Diagnose-Markern zusammen.

5. **`evaluate_dacl_ordered` warnt nicht mehr selbst.** Die Diagnose-
   Detektion ist zentral in `collect_diagnostics` — Single Source of
   Truth zwischen Log und strukturiertem Marker.

## Rationale

- **Audit-Wirksamkeit:** Ein Marker, der nicht ins persistente
  Artefakt eingeht, ist für einen Auditor wertlos.
- **Vorwärtskompatibilität:** Tagged Enum + JSON-Spalte + `serde(default)`
  erlauben neue Marker ohne Schema-Sprünge.
- **GUI-Symmetrie:** Die existierende `unsupported_aces`-Badge-Logik
  wird einfach um die zweite Diagnose-Spalte erweitert — gleiche
  Sicht, gleiche Farbe, eine Quelle weniger Überraschung.
- **HTML-Export bleibt vorerst unverändert:** JSON ist der
  kanonische Audit-Pfad, CSV trägt die Marker, GUI macht sie sichtbar.
  HTML kann später dieselben Daten visualisieren — bewusst nicht in
  diese Iteration gepackt, um die Änderung fokussiert zu halten.

## Consequences

- 4 neue Tests in `permission_engine::engine::tests`:
  - `non_canonical_dacl_yields_diagnostic_marker`
  - `canonical_dacl_yields_no_diagnostic_marker`
  - `null_dacl_yields_no_diagnostic_marker`
  - (bestehende ACE-Order-Tests bleiben gültig)
- 1 neuer Test in `persistence::scan_store::tests`:
  `diagnostics_round_trip`
- 2 neue Tests in `exporter::csv::tests`:
  `diagnostics_serialized_as_tagged_json`,
  `empty_diagnostics_yield_empty_json_array`
- CSV-Header-Test erweitert (19 → 20 Spalten).
- Migration v6 ergänzt — `fresh_database_gets_latest_version` zieht
  auf 6 hoch.
- ScanRow trägt `diagnostic_count`; GUI-Scan-View aggregiert das.
- Kein Bruch für bestehende Aufrufer von `EffectivePermission` —
  `diagnostics` ist `#[serde(default)]` und alte Konstruktionssites
  wurden um `diagnostics: vec![]` ergänzt.
- Spätere HTML-Erweiterung um eine „Diagnostics"-Sektion ist eine
  natürliche Folgearbeit.
