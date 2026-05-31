# ADR 0024 — Unsupported Share-ACEs als strukturierte Diagnose

**Status:** Akzeptiert / Accepted  
**Datum / Date:** 2026-05-25

## Kontext / Context

`FileSystemObject.unsupported_aces` und
`EffectivePermission.unsupported_ace_count` zeichnen seit ADR 0004
auf, wenn der NTFS-DACL-Parser ACE-Typen übersprungen hat (Object-,
Callback-, Conditional- oder vendor-spezifische ACEs). Die
Risk-Engine nutzt das zur `incomplete = true`-Markierung.

Auf der Share-Seite gab es kein Pendant: `parse_share_dacl`
protokollierte unsupported Share-ACE-Typen nur auf `debug!`-Level
und ließ den Parsevorgang stillschweigend weiterlaufen. Der Aufrufer
bekam ein `ShareDacl::Acl(perms)` zurück, das den Fehlerteil nicht
mehr enthielt. Konsequenz: die Share-Maske konnte unvollständig sein
(z. B. wenn ein versteckter Deny-Object-ACE in der DACL stand),
Risk-Findings wurden als `confirmed` ausgewiesen, CSV-/JSON-/HTML-
Reports zeigten keine Warnung.

Folge-Review (2026-05-25), Finding 2 (Medium).

## Entscheidung / Decision

1. **Neue Variant `PermissionDiagnostic::UnsupportedShareAces { count }`**
   in `adpa_core::model`. Nutzt das in ADR 0021 etablierte
   tagged-Enum-Format (`#[serde(tag = "kind")]`) — **keine Schema-
   Migration nötig**: die Variante fließt automatisch durch
   Persistenz (JSON-Spalte `diagnostics`), JSON-Export, CSV
   (`diagnostics_json`) und HTML (neuer Badge).

2. **Neuer Wrapper-Typ `ShareDaclScan { dacl, unsupported_count }`**
   als Return von `get_share_dacl`. Trägt die unverändert
   strukturierte `ShareDacl` plus den Audit-Count. Damit bleiben die
   30+ existierenden Pattern-Matches auf `ShareDacl::Acl(...)`
   unverändert; nur die `get_share_dacl`-Aufrufer entpacken den Wrapper.

3. **`parse_share_dacl`** zählt unsupported ACE-Typen und gibt das
   Tupel `(perms, unsupported_count)` zurück. Loglevel wechselt von
   `debug!` auf `warn!`, weil das jetzt eine echte Audit-Diagnose ist
   (analog zum NTFS-Parser).

4. **Neues Pflichtfeld
   `PermissionEvaluationInput.unsupported_share_ace_count: usize`**.
   CLI (`resolve_scan_share_status`) und GUI (`resolve_share_status`)
   liefern ab jetzt `(ShareMaskStatus, usize)`-Tupel zurück; die
   Aufrufer reichen den Wert an `evaluate()` durch.

5. **Engine** pusht bei `unsupported_share_ace_count > 0` einen
   `PermissionDiagnostic::UnsupportedShareAces { count }` in
   `EffectivePermission.diagnostics`. Die Logik liegt zentral im
   `evaluate`-Pfad — kein Aufrufer muss das Diagnostic-Push manuell
   machen.

6. **Risk-Engine `is_incomplete`** erkennt den neuen Marker und
   flaggt jedes Risk-Finding der betroffenen Berechtigung als
   `incomplete = true`. Damit ist die Share-Seite symmetrisch zur
   `unsupported_ace_count`-Logik der NTFS-Seite.

7. **HTML-Exporter** rendert einen eigenen Badge
   `⚠ {count} unsupported share ACE(s)` mit Tooltip-Erklärung in der
   Diagnostics-Spalte. CSV (`diagnostics_json`) und JSON tragen die
   Variant automatisch über Serialize.

8. **Bewusster Trade-off:** `NonCanonicalDaclOrder` (ADR 0021)
   markiert NICHT als incomplete — es ist Audit-Info, kein
   Korrektheitsproblem. `UnsupportedShareAces` markiert sehr wohl
   als incomplete, weil ein verstecktes Deny im unsupported-Teil
   die Maske direkt verändert hätte. Der Risk-Engine-Test
   `non_canonical_dacl_diagnostic_alone_does_not_mark_incomplete`
   dokumentiert die Unterscheidung explizit.

## Begründung / Rationale

- **Symmetrie zur NTFS-Seite:** beide DACL-Welten haben jetzt das
  gleiche „ich konnte einen ACE nicht auswerten"-Signal in Modell,
  Persistenz, Export und Risiko-Bewertung.
- **Keine Schema-Migration:** das tagged-Enum-Format aus ADR 0021
  zahlt sich aus — Schema v6 reicht weiter.
- **Wrapper-Typ statt Enum-Erweiterung:** ein neues
  `ShareDaclScan`-Struct über `ShareDacl` zu legen ist invasiver
  als nötig, aber spart 30+ Test-Anpassungen für den minimal-
  invasiven Pfad.
- **Engine als Single-Source-of-Truth für das Push:** Aufrufer
  müssen sich nicht merken, das Diagnostic selbst zu setzen — sie
  liefern nur den Count, die Engine entscheidet.
- **CLI gibt Warnung aus** wenn `unsupported_share_ace_count > 0` —
  damit ist die Diagnose bereits im Konsolen-Output sichtbar, nicht
  nur in den Exporten. GUI-Worker propagiert es in `scan_errors`
  (persistiert).

## Konsequenzen / Consequences

- 1 neuer Test in `share_scanner::scanner::tests`
  (`share_dacl_scan_carries_dacl_and_unsupported_count`).
- 2 neue Tests in `permission_engine::engine::tests`
  (`unsupported_share_aces_count_emits_diagnostic`,
  `zero_unsupported_share_aces_no_diagnostic`).
- 2 neue Tests in `risk_engine::rules::tests`
  (`unsupported_share_aces_diagnostic_marks_finding_incomplete`,
  `non_canonical_dacl_diagnostic_alone_does_not_mark_incomplete` —
  letzterer dokumentiert den bewussten Trade-off).
- 1 neuer Test in `exporter::html::tests`
  (`permissions_table_renders_unsupported_share_aces_badge`);
  `permissions_table_renders_combined_diagnostics` um den neuen
  Badge erweitert.
- CLI/GUI-Tests bleiben grün — keine Anpassungen nötig, da die
  Tests `PermissionEvaluationInput` nicht selbst konstruieren.
- `PermissionEvaluationInput`-Konstruktionen in Engine-Tests
  bekamen `unsupported_share_ace_count: 0` ergänzt (8 Stellen via
  `replace_all`).
- Keine Schema-Migration, kein DB-Bruch.
- Symmetrie NTFS/Share ist damit auch auf der Diagnose-Ebene
  geschlossen — die letzte erkennbare Asymmetrie aus der
  Audit-Pipeline.
