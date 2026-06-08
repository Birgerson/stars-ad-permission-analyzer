# ADR 0032 — Identitäts-Eingabe-Dispatcher und durchgesetzte LDAP-Timeouts

**Status:** Accepted
**Date:** 2026-06-04

## Context

Zwei Findings aus dem ChatGPT-Code-Review 2026-06-04 zeigten Schwächen
in der LDAP-Auflösung, die direkt fachliche Korrektheit betrafen:

- **Finding 3 (High):** `LdapResolver::lookup_by_samaccount` akzeptierte
  `DOMAIN\username`, schnitt den Domainteil aber stillschweigend ab und
  suchte nur `(sAMAccountName=username)` unter `base_dn`. In
  Multi-Domain-Forests oder bei doppeltem `sAMAccountName` konnte das die
  SID des **falschen** Benutzers zurückliefern; selbst in einer einzelnen
  Domäne war die Eingabe formal qualifiziert, aber semantisch verworfen.

- **Finding 5 (Medium):** `LdapConfig::timeout_secs` war konfigurierbar,
  wurde aber nirgends mit `tokio::time::timeout` durchgesetzt. Ein
  unerreichbarer DC, ein Firewall-Drop, DNS-Probleme oder ein langsamer
  Global Catalog konnten die Analyse beliebig lange blockieren.

## Decision

### Finding 3 — drei explizite Eingabeformen, drei dedizierte Pfade

`LdapResolver::lookup_by_samaccount` ist ein Dispatcher mit klarer
Routing-Tabelle:

| Eingabe | Pfad | Begründung |
|---|---|---|
| `DOMAIN\user` | Windows-LSA (`LookupAccountNameW`) | LSA ist **domain-aware**; gibt eine eindeutige SID zurück. Anschliessend Identity-Details per `resolve_identity_internal` (LDAP-SID-Suche). |
| `user@domain.tld` (UPN) | LDAP `(userPrincipalName=…)` | UPN ist **forestweit eindeutig**. |
| `username` (plain) | LDAP `(sAMAccountName=…)` mit Eindeutigkeits-Check | Bei `len() > 1` gibt der Helper `Err(CoreError::Validation("Ambiguous sAMAccountName …"))` zurück statt blind `next()`. |

Leere Eingabe → `Err(CoreError::Validation(…))` statt stumm No-Op.

Neue Helfer in `ldap_client`:

- `search_all_by_samaccount` (liefert **alle** Treffer für die
  Eindeutigkeits-Prüfung — `search_by_samaccount` ist jetzt ein dünner
  Wrapper, der `Ok(into_iter().next())` zurückgibt).
- `search_by_upn` für die UPN-Variante.

### Finding 5 — Timeout-Wrapper als zentrale Schicht

Neuer `pub async fn ldap_client::with_timeout(operation, duration, fut)`
plus `pub fn ldap_timeout(&config) -> Duration`. Ein Timeout-Hit liefert
`CoreError::LdapQuery("LDAP operation '<op>' timed out after Ns")`.

`LdapResolver::lookup_by_samaccount`, `resolve_identity_internal` und
`resolve_memberships_internal` (über einen neuen `inner`-Helper) klammern
ihre gesamte LDAP-Logik einmal mit dem konfigurierten Timeout. `connect`
selbst klammert TCP/TLS-Aufbau und Bind zusätzlich separat ein — eine
hängende Verbindung wird so direkt im Aufbau abgefangen, nicht erst beim
ersten Search.

## Rationale

- **Pro Form ein eigener Pfad** ist robuster als Heuristik. Wer
  `DOMAIN\user` schreibt, soll genau diese Domain treffen — nicht eine
  per Zufall gewählte gleichnamige Identität.
- **LSA-Pfad für `DOMAIN\user`** spart einen LDAP-Roundtrip und nutzt
  die domain-aware Auflösung, die Windows ohnehin betreibt — kein
  Re-Implementieren der Domain-DN-Logik im Client.
- **Eindeutigkeits-Check statt `next()`** macht die Verantwortlichkeit
  klar: wer mehrere Treffer hat, muss bewusst disambiguieren.
- **Timeout-Wrapper auf Methoden-Ebene** ist die richtige Granularität.
  Ein logischer Vorgang ist eine Einheit; der Aufrufer setzt
  `timeout_secs` für die ganze Operation, nicht pro Sub-Call.

## Consequences

- Aufrufer, die `lookup_by_samaccount("admin")` schreiben, bekommen jetzt
  in Multi-Match-Szenarien einen klaren Fehler statt einer falschen SID.
  Migration: explizit `DOMAIN\admin` oder `admin@domain.tld` schreiben.
- `LdapConfig::timeout_secs` wirkt jetzt tatsächlich. Wer ein sehr
  grosses transitives Gruppen-Ergebnis erwartet, sollte den Wert
  entsprechend setzen (Default 10s).
- Der LSA-Pfad ist `#[cfg(windows)]`-spezifisch; auf nicht-Windows
  liefert die Funktion einen `Validation`-Fehler — Stars zielt ohnehin
  auf Windows.

## Tests

Unit-Tests für den Dispatcher selbst lassen sich nur eingeschränkt
ohne echte LDAP/LSA-Umgebung schreiben. Build-Verifikation deckt die
Signatur-Konsistenz; die schon vorhandenen `#[ignore]`-Integrations­tests
(`resolve_administrator_identity`,
`resolve_group_memberships_max_mustermann`, …) werden gegen eine echte
TESTDOMAIN ausgeführt und decken Dispatch und Timeout-Wrapper ab.

## Schließt / Closes

ChatGPT-Code-Review 2026-06-04, Findings 3 (High) und 5 (Medium).
