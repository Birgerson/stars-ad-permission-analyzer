# ADR 0020 — `matched_aces` filtert INHERIT_ONLY-Einträge

**Status:** Accepted  
**Date:** 2026-05-24

## Context

Seit ADR 0012 filtert die Engine `INHERIT_ONLY_ACE` (Flag 0x08) bei der
Effective-Rights-Berechnung korrekt aus — solche ACEs wirken nur auf
Kinder, nicht auf das aktuelle Objekt. `collect_matched_aces` führte
diese Filterung jedoch nicht durch und lieferte alle ACEs zurück, deren
Trustee-SID im Token war.

Folge: `DirectUserAceRule` im `risk_engine` (best-practice-Regel
„Berechtigungen über Gruppen, nicht direkt am User") konsumiert
`matched_aces` und fragt nach expliziten Benutzer-ACEs. Ein
explizit-aber-Inherit-Only-Benutzer-ACE würde dort als
`DIRECT_USER_ACE`-Befund auftauchen, obwohl er das aktuelle Objekt gar
nicht berührt — Falschmeldung.

Folge-Review (2026-05-24), Befund 2.

## Decision

`collect_matched_aces` filtert jetzt zusätzlich über
`ace_applies_to_current_object(ace)` — derselbe Helfer, den die
Engine-Auswertung und `collect_contributing_sids` schon nutzen.
Damit wird `EffectivePermission.matched_aces` auf die ACEs reduziert,
die tatsächlich auf das aktuelle Objekt anwendbar sind.

Die explanatorische Information über IO-ACEs geht nicht verloren:
`build_explanation` markiert IO-Einträge im `PermissionPath` weiterhin
mit `[inherit-only — not applied to this object]` (eingeführt in
ADR 0012). Risikoregeln arbeiten mit `matched_aces`, Reports mit der
Erklärung — die Trennung passt.

## Rationale

- **Minimale Invasivität:** Eine Zeile Filter-Logik, kein
  Modellwechsel, keine Persistenz-Migration. Die Alternative — ein
  `applies_to_current_object: bool`-Flag auf `AceEntry` — wäre
  korrekter im Sinne von „Information bewahren", hätte aber
  Schemafelder, Serialisierung, DB-Persistenz und Exports berührt.
  Die Erklärung trägt die Info bereits, der Filter behebt den
  Falschmelder.
- **Symmetrie zur Engine:** `evaluate_dacl_ordered` und
  `collect_contributing_sids` filtern bereits über
  `ace_applies_to_current_object`. `collect_matched_aces` folgt
  diesem Muster.

## Consequences

- 1 neuer Engine-Test (`inherit_only_ace_not_in_matched_aces`).
- 1 neuer Risk-Engine-Test
  (`inherit_only_explicit_user_ace_does_not_trigger_direct_user_finding`)
  — dokumentiert den Downstream-Effekt im konkreten Audit-Use-Case.
- Keine Schema- oder API-Änderung.
- Hinweis für Konsumenten: wer in zukünftigen Use-Cases die IO-ACEs
  explizit sehen will (z. B. „welche Vererbungs-Erwartungen hat das
  Objekt für seine Kinder?"), kann sie weiterhin aus dem rohen
  `FileSystemObject.dacl` ableiten — `matched_aces` ist bewusst die
  „was wirkt jetzt"-Sicht.
