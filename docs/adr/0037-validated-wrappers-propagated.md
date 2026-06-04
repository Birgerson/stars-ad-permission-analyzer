# ADR 0037 — Validierte Wrapper konsequent propagieren

**Status:** Akzeptiert / Accepted
**Datum / Date:** 2026-06-04

## Kontext / Context

Review 2026-06-04 Runde 3 Finding 2 (Medium) zeigte, dass die
Validierungsschicht zwar formal korrekt arbeitete (`validate_sid`,
`validate_ldap_endpoint`, `validate_dn`, `validate_smb_server`,
`validate_share_name`, `validate_identity_query` liefern typisierte
Wrapper mit getrimmten Werten zurück), die Aufrufer aber an mehreren
Stellen **den Rohstring weiter verarbeiteten**:

- `validate_sid("  S-1-5-18  ")` liefert `ValidatedSid("S-1-5-18")` —
  CLI und GUI prüften aber mit `user.starts_with("S-1-")` auf dem Roh-
  String. Whitespace-umgebene SIDs wurden dadurch nicht als SID
  klassifiziert und landeten in der Name-Suche.
- `validate_connection_inputs(...)` gab nur `Result<(), Err>` zurück —
  die getrimmten Werte aus `validate_ldap_endpoint`, `validate_dn`
  etc. wurden verworfen, der ursprüngliche `Option<String>`-Rohwert
  ging unverändert an `LdapConfig::new(...)` und
  `get_share_dacl(...)`.

Konsequenz: produktiv konnten zwei Audit-Läufe mit identischen
sichtbaren Eingaben (einer mit, einer ohne Whitespace) zu
unterschiedlichen Ergebnissen führen — ein Audit-Reproduzierbarkeits-
defekt, der die Architekturregel **„Validierung vor Verarbeitung"**
materiell verletzte.

## Entscheidung / Decision

`validate_connection_inputs` liefert in CLI und GUI jetzt eine
**normalisierte Struktur** zurück, deren Felder die getrimmten Werte
enthalten:

```rust
// CLI
struct NormalizedConnectionInputs {
    server:     Option<String>,
    base_dn:    Option<String>,
    bind_dn:    Option<String>,
    smb_server: Option<String>,
    share_name: Option<String>,
}

// GUI (zusätzlich der gesamte LdapParams-Klon mit getrimmten Feldern)
pub struct NormalizedConnectionInputs {
    smb_server: Option<String>,
    share_name: Option<String>,
    ldap:       Option<LdapParams>,  // getrimmt
}
```

Die Verbraucher (CLI `run_analyze`/`run_scan`, GUI
`handle_analyze`/`handle_scan_path`) verwenden ab der Validierung
**ausschließlich** die normalisierten Werte. Die ursprünglichen
`Option<String>`-Felder werden nach dem Validierungsaufruf neu
zugewiesen oder geshadowed.

Auch für die User-Eingabe gilt das jetzt konsequent:

```rust
let user = if user.starts_with("S-1-") {
    validate_sid(&user)?.0      // getrimmte SID
} else {
    validate_identity_query(&user)?.0  // getrimmter Name
};
```

`PrincipalInput::Auto(...)` trimmt zusätzlich in der Klassifikation
(`classify()`) — Schutz in der Tiefe.

## Konsequenzen / Consequences

**Positiv / Positive:**

- Reproduzierbare Audit-Ergebnisse zwischen CLI und GUI bei
  Whitespace-belasteten Eingaben.
- Die Architekturregel „Validierung vor Verarbeitung" ist jetzt nicht
  nur nominal, sondern materiell erfüllt — die getrimmten Werte
  fließen tatsächlich an LDAP-/NetAPI-/SID-Verarbeitung weiter.
- Klar erkennbarer Eintrittspunkt für künftige
  Validierungserweiterungen (z. B. zusätzliche
  Hostnamen-Normalisierung).

**Negativ / Negative:**

- Etwas mehr Code an den Aufrufstellen (5 zusätzliche `let`-
  Zuweisungen pro Validierungsblock). Akzeptiert.

## Schließt / Closes

Review 2026-06-04 Runde 3, Finding 2 (validierte Identitäts- und
Verbindungswerte als Rohstrings).

## Verweise / References

- ADR 0036 — Einheitliche Principal-Resolution-Pipeline (nutzt
  ebenfalls getrimmte Inputs).
- AGENTS.md DoD-Regel 11: „Alle betroffenen Eingaben validieren";
  DoD-Regel 12: „Validierungsfehler getestet".
