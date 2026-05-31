# ADR 0002 — Crate-Name `adpa_core` statt `core`

**Status:** Akzeptiert / Accepted  
**Datum / Date:** 2026-05-20

## Kontext / Context

Der Core-Crate war zunächst als `core` benannt. Rusts eingebautes `core`-Crate
(`std::core`, `core::pin`, `core::future`, …) wird von Proc-Makros wie `async_trait`
direkt referenziert. Ein eigener Crate namens `core` überlappt diesen Namensraum
und führt zu Kompilierungsfehlern wie `cannot find pin in core`.

## Entscheidung / Decision

Der Crate wird in `adpa_core` umbenannt
(AD Permission Analyzer Core).

## Begründung / Rationale

- Vermeidet die Kollision mit Rusts eingebautem `core`-Crate.
- Der Name `adpa_core` ist eindeutig und sprechend.
- Alle anderen Crates importieren über `use adpa_core::…`.

## Konsequenzen / Consequences

- Alle Cargo.toml-Abhängigkeiten und `use`-Pfade wurden aktualisiert.
- Der `doctest = false`-Workaround in `core/Cargo.toml` wurde entfernt.
- Doctests laufen jetzt wieder normal.
