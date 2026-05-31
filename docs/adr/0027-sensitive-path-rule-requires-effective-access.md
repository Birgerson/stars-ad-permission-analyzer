# ADR 0027 — `SensitivePathRule` setzt tatsächlichen Zugriff voraus

**Status:** Akzeptiert / Accepted  
**Datum / Date:** 2026-05-25

## Kontext / Context

`SensitivePathRule` flaggt Pfade, deren Name auf sensible Daten
hindeutet (`password`, `secret`, `token`, …). Die Finding-Beschreibung
lautet wörtlich:

> Path contains keyword '<kw>' — may contain credentials or secrets;
> '<name>' has access

Bisher prüfte die Regel ausschließlich den Pfadnamen. Eine
Berechtigung mit `effective_mask == 0` (z. B. weil NTFS denyt oder
`NTFS ∩ Share = 0`) wurde trotzdem als „has access" gemeldet. Das ist
eine Falschmeldung: der Auditor liest ein Risiko, das real nicht
besteht. Bei Audit-Berichten als Beweis-Artefakt (vgl. AGENTS.md
„Exporte müssen als sensibel betrachtet werden") besonders kritisch.

Review 2026-05-25, Finding 3 (Medium).

## Entscheidung / Decision

**`SensitivePathRule.evaluate` filtert `p.effective_mask.0 > 0` vor**
der Keyword-Prüfung. Pfade, auf die der Benutzer **kein** Zugriffs-
recht hat, erzeugen kein Finding mehr.

Begründungstext im Code:

> the rule claims "has access" — so only emit a finding when the
> identity actually has access. Otherwise a deny-all result would be
> misreported as a positive risk.

## Begründung / Rationale

- **Findung muss zur Aussage passen.** „Has access" ohne effektiven
  Zugriff ist semantisch inkorrekt.
- **Falsch-Positive sind im Audit-Kontext teuer.** Sie untergraben
  Vertrauen in den Bericht und kosten Operator-Zeit zur Verifikation.
- **Effektive Maske, nicht NTFS-Maske, ist maßgeblich.** Wenn die
  Share-Seite blockt (`NTFS Full Control ∩ Share Read = Read &
  Execute` als Beispiel aus den Live-Scans), aber Share `0` macht,
  muss das Ergebnis konsistent sein — der Regression-Test
  `sensitive_path_uses_effective_not_ntfs_mask` schreibt das fest.
- **Bewusst keine Aufteilung in zwei Regeln** (z. B. „sensitive path
  observed" vs. „access to sensitive path"). Der Reviewer hat das
  optional vorgeschlagen, aber: die existierende Regel heißt
  `SENSITIVE_PATH`, beschreibt textuell „has access" und ist als ein
  Konzept etabliert. Falls später ein dedizierter „pure-naming"-
  Befund gewünscht ist, wird das eine separate Regel mit eigener ID.

## Konsequenzen / Consequences

- 2 neue Tests in `risk_engine::rules::tests`:
  - `sensitive_path_with_zero_effective_mask_not_flagged`
    (Kern-Regression aus dem Reviewer-Beispiel)
  - `sensitive_path_uses_effective_not_ntfs_mask`
    (Edge-Case: NTFS Full, aber effective_mask = 0)
- `sensitive_path_flagged` bleibt unverändert grün — Standardfall
  mit `MASK_READ` als effective_mask.
- Keine API-Änderung, keine Schemamigration.
- Risk-Engine-Output für Berichte ist stiller bei Pfaden ohne
  tatsächlichen Zugriff — die übrigen Regeln (`WRITE_ACCESS`,
  `DELETE_RIGHT`, etc.) prüfen bereits explizit auf die effektive
  Maske oder konkrete Bits, sind also unverändert korrekt.
