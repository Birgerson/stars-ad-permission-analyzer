# ADR 0042 — Deny-Aggregation als eigener Erklärungspfad-Schritt

**Status:** Accepted
**Date:** 2026-06-05

## Context

Die Stars-Engine aggregiert NTFS-Allow- und Deny-ACEs in einer einzigen
finalen `ntfs_raw`-Maske (Funktion `evaluate_dacl_ordered`). Diese Maske
fließt in den Erklärungspfad als ein einziger Schritt:

```text
NTFS effective: Special (0x00100000)
```

Solange nur Allow-ACEs beteiligt sind, ist das selbsterklärend — die ACE-Steps
darüber zeigen, woher die Bits kommen. Sobald aber eine Deny-ACE im Spiel
ist und Bits einer Allow-ACE blockiert, **fehlt im Pfad ein Hinweis darauf,
was passiert ist**. Block A der 2026-06-05-Lab-Verifikation zeigte das
Symptom konkret (Szenario E1, `C:\TestShare\DenyZone`):

```text
DACL:
  Deny  explicit  T0LAB\alice → Special (0x000301BF)
  Allow inherited T0LAB\GroupB → Modify (0x001301BF)
  …

Effective Rights:
  NTFS    : Special (0x00100000)
  Result  : Special (0x00100000)

Explanation Path (Auszug):
  6. Deny ACE [explicit] for T0LAB\alice → Special (0x000301BF)
  7. Allow ACE [inherited] for GroupB → Modify (0x001301BF)
  …
  11. NTFS effective: Special (0x00100000)
```

Ein versierter Admin liest das richtig (Deny hat die Modify-Bits entfernt,
übrig blieb das SYNCHRONIZE-Bit). Aber `Special (0x00100000)` ist für die
Hauptzielgruppe — den Wald-und-Wiesen-Admin — eine kryptische Antwort.
Die Engine kennt zu diesem Zeitpunkt aber sehr wohl, welche Bits durch Deny
weggefallen sind: in `evaluate_dacl_ordered` läuft eine zweite Maske
`denied` mit, die alle "first decision = Deny"-Bits aufsammelt. Diese
Information wurde bisher nicht aus der Funktion herausgereicht.

## Decision

`evaluate_dacl_ordered` gibt jetzt `(granted, denied)` zurück. Die Engine
reicht `denied_raw` an `build_explanation` durch, und `build_explanation`
fügt — sofern `denied_raw != 0` — einen expliziten Schritt direkt vor dem
„NTFS effective"-Step ein:

```text
Deny aggregation: Special (0x000301BF) blocked by Deny ACEs — those bits
were removed from the effective NTFS mask
NTFS effective: Special (0x00100000)
```

Damit ist die Brücke zwischen "ich sehe einen Deny-ACE" und "ich sehe ein
unerwartet kleines Effective" sichtbar im Pfad selbst, statt nur in der
Differenz der Hex-Werte.

Wenn keine Deny-ACE im DACL der relevanten SIDs ist, bleibt der Pfad
unverändert — der neue Schritt erscheint nicht, damit ganz normale Berichte
(die in der überwiegenden Mehrheit aller Audits) sauber lesbar bleiben.

## Consequences

### Positiv

- **Wald-und-Wiesen-Admin liest direkt**, dass Deny die Allow-Bits
  zermalmt hat. Kein Hex-Differenz-Detektivspiel.
- **Konsistent mit dem Share-Step**: Stars rendert seit jeher
  `NTFS ∩ Share`-Aggregation als eigenen Schritt; jetzt auch
  `Allow ⊖ Deny`.
- **Honest-by-default**: Wer einen Audit-Bericht liest, sieht alle drei
  Aggregations-Stufen explizit, ohne zwischen den Zeilen rechnen zu müssen.
- **Keine API-Brüche**: `evaluate_dacl_ordered` ist Engine-intern; einziger
  Aufruf-Pfad wurde mit aktualisiert. Öffentliche Modelle bleiben gleich.

### Negativ / Trade-offs

- Pfad bekommt einen Schritt mehr, wenn Deny im Spiel ist. Da Deny in
  Produktion eher Ausnahme als Regel ist, ist die Lärmlast gering.
- `NormalizedRights::display_name()` zeigt für eine Deny-Maske wie
  `0x000301BF` weiterhin "Special" (kein "Modify"), weil das Sync-Bit
  fehlt. Das ist konsistent mit der bisherigen Darstellung, könnte aber
  ein zukünftiges Folge-Refactoring auslösen, wenn die Lesbarkeit der
  Bit-Namen noch weiter verbessert werden soll.

### Tests

Zwei neue Engine-Tests in `crates/permission_engine/src/engine.rs::tests`:

- `deny_aggregation_step_surfaces_blocked_bits` — verifiziert, dass der
  neue Step erscheint, wenn Deny Modify das Allow Modify überschreibt,
  und dass er die korrekte blockierte Maske benennt.
- `deny_aggregation_step_absent_when_no_deny` — verifiziert, dass der Step
  **nicht** erscheint, wenn keine Deny-ACE im Spiel ist.

Live-Verifikation gegen das 3-Forest-Lab in
[`docs/lab/verification.md`](../lab/verification.md), Block A Szenario E1:
der Step erscheint als Schritt 11 im Pfad mit dem genauen Hex-Wert
`0x000301BF`.

## Beziehung zu anderen ADRs

- **ADR 0039** (Diagnose-Marker): denselben Ansatz — eine bisher implizit
  bekannte Information explizit machen, damit Auditoren nicht selbst
  rätseln müssen.
- **ADR 0041** (LocalGroup-Mitgliedschaften im Erklärungspfad): hat den
  gleichen Mechanismus für die Gruppen-Quelle eingeführt, jetzt für die
  ACE-Aggregation.
