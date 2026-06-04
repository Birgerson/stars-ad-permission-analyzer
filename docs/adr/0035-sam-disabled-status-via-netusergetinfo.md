# ADR 0035 — SAM-Pfad bestätigt `disabled` per `NetUserGetInfo`

**Status:** Akzeptiert / Accepted
**Datum / Date:** 2026-06-04

## Kontext / Context

Beim zweiten ChatGPT-Code-Review-Durchgang am 2026-06-04 trat ein
stilles Korrektheitsproblem im SAM-Fallback-Pfad hervor
(`ad_resolver::sam::resolve_identity_via_sam`):

- Der SAM-Pfad baute `Identity` bisher aus `LookupAccountSidW` und
  `NetUserGetGroups`. Beide APIs liefern den Anzeigenamen, die Domäne
  und die direkten Gruppen — aber **nicht** das
  `userAccountControl`-Bit `UF_ACCOUNTDISABLE`.
- Folge: `Identity.disabled` war im SAM-Pfad pauschal `false`. Ein
  in Wahrheit deaktiviertes Konto erschien im Report als aktiv und
  bekam keine entsprechende UI-Diagnose. Im LDAP-Pfad lief das richtig,
  weil dort `userAccountControl` direkt aus AD kam.
- Der Marker `IdentityDisabled` (ADR 0033) lief deshalb stumm, sobald
  der Scan über die SAM-Resolution lief — typischerweise auf einem
  Domain Controller ohne explizite LDAP-Konfiguration.

Ohne Fix konnte ein Audit-Konsument nicht erkennen, dass der
`disabled`-Status für eine SAM-aufgelöste Identity überhaupt fraglich
ist. Das verletzt die „keine Silent Skips"-Regel.

## Entscheidung / Decision

1. **Neue Helper-Funktion `user_account_disabled`** in
   `ad_resolver::sam`:
   - Ruft `NetUserGetInfo(server, user, level=1, &mut buf)` auf, liest
     `USER_INFO_1::usri1_flags` und prüft, ob
     `UF_ACCOUNTDISABLE (= 0x2)` gesetzt ist.
   - Rückgabe `Result<Option<bool>, CoreError>`:
     - `Ok(Some(true))`  → Konto deaktiviert.
     - `Ok(Some(false))` → Konto aktiv.
     - `Ok(None)`        → Status nicht zuverlässig bestimmbar
       (`NERR_USER_NOT_FOUND`, `ERROR_ACCESS_DENIED`, andere NetAPI-
       Fehler). Aufrufer markieren dann den Diagnose-Status als
       unbekannt.
     - `Err(_)`         → unerwarteter Bibliotheksfehler.

2. **`resolve_identity_via_sam` liefert jetzt ein `SamResolution`-Struct**
   statt eines Tupels. Das Struct trägt `identity`, `memberships` und
   zusätzlich `disabled_known: bool`. Der Worker entscheidet anhand
   dieses Flags, ob er
   `PermissionEvaluationInput::identity_disabled_status_unknown`
   setzen muss.

3. **`Identity.disabled` ist im SAM-Pfad jetzt verlässlich:**
   - Für `IdentityKind::User` wird der Wert über
     `user_account_disabled` gesetzt; bei Misserfolg bleibt
     `disabled = false`, aber `disabled_known = false` informiert den
     Aufrufer.
   - Für Gruppen, Computer und Well-Known SIDs gibt es keinen
     `disabled`-Status — `disabled_known = true` mit
     `disabled = false` ist definitiv korrekt.

4. **Engine-Integration:**
   - `PermissionEvaluationInput::identity_disabled_status_unknown`
     pusht den Diagnose-Marker
     `PermissionDiagnostic::IdentityDisabledStatusUnknown`.
   - `risk_engine::is_incomplete()` matched diesen Marker **nicht** —
     er ist informationell, kein Vollständigkeitsmangel des
     ACL-Modells.
   - CLI und HTML rendern den Marker mit eigener Beschreibung
     (`[i]`-Hinweis bzw. `badge-info`).

## Konsequenzen / Consequences

**Positiv / Positive:**

- Der SAM-Pfad liefert jetzt denselben Korrektheitsgrad in Bezug auf
  `disabled` wie der LDAP-Pfad.
- Auditoren sehen explizit, wenn der `disabled`-Status nicht ermittelt
  werden konnte (z. B. wegen Access Denied beim NetAPI-Aufruf) —
  vorher war das ein Default-`false`.
- Bricht keine bestehende API: `SamResolution`-Struct ist additiv;
  einziger interner Caller (`gui::worker::sam_resolve_fallback`)
  wurde angepasst.

**Negativ / Negative:**

- Zusätzlicher NetAPI-Aufruf pro Identity in der SAM-Auflösung.
  `NetUserGetInfo` ist auf einem DC günstig — auf einer Workstation,
  die einen Remote-User nicht kennt, schlägt es mit
  `NERR_USER_NOT_FOUND` fehl; das wird in `Ok(None)` übersetzt und der
  Marker erscheint.

**Test-Anforderungen:**

- DC-Integrationstest (`resolve_local_administrator_yields_memberships`,
  `#[ignore]`) prüft jetzt zusätzlich, dass `disabled_known = true`
  ist, weil `NetUserGetInfo` für den eingebauten Administrator
  antwortbar sein muss.
- Engine-Tests setzen `identity_disabled_status_unknown` und sehen den
  Marker im `result.diagnostics`.
- Risk-Engine-Test: ein Finding über eine Permission mit nur
  `IdentityDisabledStatusUnknown` darf **nicht** `incomplete = true`
  tragen (negative Assertion, um die Trennung von
  `IdentityNotInConfiguredLdapBase` zu sichern).

## Schließt / Closes

Review 2026-06-04 Runde 2, Finding 5 (SAM disabled-Status).

## Verweise / References

- ADR 0021 — Permission Diagnostics als variant-tagged Enum.
- ADR 0033 — `IdentityDisabled` für den LDAP-Pfad und die ursprüngliche
  Marker-Idee.
- ADR 0034 — Multi-Domain-LSA-Fallback (führt
  `IdentityDisabledStatusUnknown` ein; dieser ADR nutzt denselben
  Marker).
- Windows-API-Doku zu `USER_INFO_1::usri1_flags` und
  `UF_ACCOUNTDISABLE`.
