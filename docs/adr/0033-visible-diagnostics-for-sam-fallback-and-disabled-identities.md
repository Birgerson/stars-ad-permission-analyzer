# ADR 0033 — Sichtbare Diagnostik für SAM-Fallback und deaktivierte Identitäten

**Status:** Akzeptiert / Accepted
**Datum / Date:** 2026-06-04

## Kontext / Context

Zwei Findings aus dem ChatGPT-Code-Review 2026-06-04 trafen denselben
Mechanismus — strukturierte Diagnose-Marker an der
`EffectivePermission`:

- **Finding 6 (Medium):** Der SAM/LSA-Fallback ohne LDAP nutzt
  `NetUserGetGroups`, das nur direkte globale Gruppen liefert.
  Verschachtelte Domain-Gruppen werden nicht rekursiv aufgelöst; auf
  einem Domain Controller ist das Ergebnis besser als ein nackter
  SID-Fallback, aber nicht vollständig für tief verschachtelte
  AD-Gruppen. Diese Einschränkung war bisher nur im Code-Kommentar
  erwähnt — ein Audit-Leser konnte nicht erkennen, dass die Berechnung
  lückenhaft sein könnte.

- **Finding 7 (Low):** Der LDAP-Resolver erkennt deaktivierte Benutzer
  korrekt über `userAccountControl`. Die Permission Engine berechnet
  dennoch die theoretischen Rechte aus SID und Gruppen unverändert. Das
  ist für „ACL-derived rights" sinnvoll, aber für tatsächlichen
  Remote-SMB-Zugriff eines deaktivierten Accounts nicht dasselbe wie ein
  authentifizierbarer Zugriff. CLI/HTML/JSON trennten beide Sichten
  bisher nicht klar.

## Entscheidung / Decision

Beide Lücken werden über die schon vorhandene
`PermissionDiagnostic`-Vector-Infrastruktur geschlossen (ADR 0021), die
ohnehin per Variante-tagged JSON serialisiert wird und damit
zukunftssicher um weitere Marker erweitert werden kann.

1. **Zwei neue Varianten in `adpa_core::model::PermissionDiagnostic`:**

   - `DomainGroupRecursionIncomplete` — gesetzt, sobald die
     Gruppen­auflösung über den SAM/LSA-Fallback statt LDAP läuft.
     Risk-Findings für diese Berechtigung müssen `incomplete = true`
     tragen.
   - `IdentityDisabled` — gesetzt, sobald die analysierte Identität im
     AD als deaktiviert markiert ist (`userAccountControl`
     `ACCOUNTDISABLE`, Bit `0x0002`).

2. **Neues Eingabe-Feld
   `PermissionEvaluationInput.group_resolution_via_sam_fallback: bool`**
   (Default `false`). Der Aufrufer setzt das Flag, wenn er den SAM-Pfad
   nutzt. Die Engine pusht dann automatisch
   `DomainGroupRecursionIncomplete` ins Ergebnis.

3. **Engine-Logik für `IdentityDisabled`**: pusht den Marker
   automatisch, wenn `input.identity.disabled == true`. Kein zusätzliches
   Eingabe-Feld notwendig — die `Identity` trägt das Bit ohnehin.

4. **Caller-Plumbing:**

   - **GUI**: `resolve_identity_sids` liefert jetzt ein
     `used_sam_fallback`-Flag (3-Tupel `(Identity, Memberships, bool)`).
     Der Worker leitet es in `PermissionEvaluationInput`.
   - **CLI**: nutzt das schon vorhandene `ResolvedIdentity::ad_connected`
     mit Negation (`group_resolution_via_sam_fallback = !ad_connected`).

5. **Sichtbare Darstellung:**

   - **HTML-Bericht** (`exporter::html`) zeigt für
     `DomainGroupRecursionIncomplete` eine gelbe
     `⚠ SAM fallback — nested groups not resolved`-Badge mit
     Tooltip-Erklärung; für `IdentityDisabled` einen blauen
     `ℹ disabled account`-Hinweis.
   - **CLI-Output** (`output::print_report`) gibt zwei zusätzliche
     Diagnose-Blöcke aus: `[!] Group resolution ran through the SAM/LSA
     fallback…` und `[i] Identity is flagged as disabled in AD…`.

## Begründung / Rationale

- **Wieder­verwendung der vorhandenen Diagnose-Schicht.** ADR 0021 hat
  den `PermissionDiagnostic`-Vector genau für diesen Anwendungsfall
  etabliert: strukturiert, variant-tagged-serialisiert, von
  CLI/HTML/JSON konsistent gerendert. Neue Audit-Marker einzuhängen ist
  ein Einzeiler in `model.rs` plus jeweiligen Renderer-Pfad.
- **Nicht-Block-Stil — Audit-Leser darf weiter lesen.** Ein deaktiviertes
  Konto erzeugt keinen Engine-Fehler; es ist ein Hinweis, kein Blocker.
  Genau dafür gibt es die Diagnose-Schicht.
- **Risk-Findings konsistent halten.** Mehrere Risk-Rules nutzen
  `is_incomplete(p)`. Beide neuen Marker passen in dieses Schema —
  Risk-Findings für betroffene Berechtigungen werden automatisch als
  `incomplete = true` gerendert, ohne dass die Rules angepasst werden
  müssen.

## Konsequenzen / Consequences

- Bestehende Konstruktions­sites von `PermissionEvaluationInput` müssen
  das neue Feld `group_resolution_via_sam_fallback` setzen — Default
  `false` wäre möglich, ist aber bewusst weggelassen, damit Aufrufer den
  Wert explizit setzen.
- Die zwei neuen Varianten brauchen Match-Arme in CLI / HTML; das ist
  durch den Compiler erzwungen — kein stilles Vergessen möglich.
- Künftige weitere Diagnose-Marker (z. B. „Kerberos-Ticket abgelaufen",
  „Account gesperrt", „Passwort abgelaufen") können dem gleichen Muster
  folgen.

## Tests / Tests

Workspace-Tests bleiben grün. Die zwei neuen Marker werden über die
schon vorhandene Diagnose-Anzeige-Pipeline gerendert, die durch die
existierenden Engine- und Exporter-Tests abgedeckt ist. Real-AD-
Verifikation läuft über die `#[ignore]`-Integrations­tests gegen die
Test­domain.

## Schließt / Closes

ChatGPT-Code-Review 2026-06-04, Findings 6 (Medium) und 7 (Low).
