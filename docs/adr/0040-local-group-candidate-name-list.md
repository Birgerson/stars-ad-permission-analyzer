# ADR 0040 — Kandidatenliste für lokale Gruppen-Auflösung

**Status:** Accepted
**Date:** 2026-06-04

## Context

Review 2026-06-04 Runde 5 Finding 1 (High) hat eine **stille
Rechteunterbewertung** im lokalen Gruppen-Pfad offengelegt:

`format_account_for_local_groups()` baute den Accountnamen für
`NetUserGetLocalGroups` blind als `name@domain`. Bei Identities, die
aus dem LSA-/Trust-Pfad kommen (ADR 0034 / 0036), ist `domain` aber
sehr häufig ein **NetBIOS-Name** wie `TRUSTED`, nicht ein DNS-Suffix.
`alice@TRUSTED` ist keine gültige UPN-Form — `NetUserGetLocalGroups`
liefert `NERR_USER_NOT_FOUND`.

`resolve_local_group_sids()` hatte den `NERR_USER_NOT_FOUND`-Fall
explizit als `Ok(Vec::new())` behandelt — fachlich begründet mit "kein
Fehler im strengen Sinn". Die Aufrufer (`collect_local_group_sids_for_path`
in CLI und GUI) sahen ein `Ok(v)` und setzten
`LocalGroupEvalStatus::Applied`. Der Befund:

1. Trust-User korrekt per LSA aufgelöst.
2. Domain-Gruppen bereits als unvollständig markiert
   (`IdentityNotInConfiguredLdapBase`).
3. Lokale Gruppen-Suche mit `alice@TRUSTED` → `NERR_USER_NOT_FOUND`.
4. Stars sieht `LocalGroupEvalStatus::Applied(0)` — "lokale Gruppen
   erfolgreich ausgewertet, keine drin".
5. **ACEs auf lokale Server-Gruppen (z. B. `BUILTIN\Administrators`,
   in dem die Trust-Domain-Gruppe Mitglied ist) bleiben unsichtbar.**
6. Effektive Rechte können zu niedrig berechnet sein, ohne
   `incomplete`-Signal aus diesem Pfad.

Für ein AD/DC-Analysewerkzeug ist genau diese Art stiller
Unterbewertung der gefährlichste Bug-Klassentyp: Stars *zeigt*
Rechte, die der Auditor für korrekt hält, obwohl die
Berechnungsgrundlage unvollständig war.

## Decision

**Drei Änderungen** in `crates/ad_resolver/src/local_groups.rs`:

### 1. Kandidatenliste statt einzelner Accountname

Neue Funktion `format_account_candidates_for_local_groups(identity)`
liefert `Vec<String>` in Präferenzreihenfolge:

1. `userPrincipalName` (echter UPN, wenn AD ihn gesetzt hat).
2. `DOMAIN\name` — funktioniert sowohl für NetBIOS- als auch
   DNS-Domains, der robusteste klassische NetAPI-Form.
3. `name@domain` — **nur** wenn `domain` wie ein DNS-Suffix aussieht
   (enthält mindestens einen Punkt). Heuristik:
   `looks_like_dns_domain()`.
4. `name` (rein) — lokale Konten ohne Domain.

Die alte `format_account_for_local_groups()` bleibt als
Convenience-Wrapper erhalten (gibt den ersten Kandidaten zurück),
damit externe Konsumenten nicht brechen — ist intern aber nicht mehr
in Verwendung.

### 2. Strict-Variante mit explizitem Outcome

Neuer Typ `LocalGroupLookupOutcome`:

```rust
pub enum LocalGroupLookupOutcome {
    WithGroups(Vec<Sid>),
    UserNotFoundOnServer,
}
```

Neue Funktion `resolve_local_group_sids_strict()` liefert diesen
Typ — explizit getrennt zwischen "User gefunden, hier sind die
(möglicherweise leeren) Gruppen" und "User nicht auf dem Server
bekannt".

Die alte `resolve_local_group_sids()` bleibt als Backward-Compat-
Wrapper erhalten: bei `UserNotFoundOnServer` gibt sie weiterhin
`Ok(Vec::new())` zurück. So bricht die Public-API nicht.

### 3. Identity-Wrapper mit Kandidaten-Loop

Neue Funktion `resolve_local_group_sids_for_identity(server, identity)`
ist der **neue, korrekte** Pfad für die CLI/GUI-Verbraucher:

1. Baut die Kandidatenliste über
   `format_account_candidates_for_local_groups`.
2. Probiert nacheinander mit `resolve_local_group_sids_strict`.
3. Erster `WithGroups`-Treffer gewinnt — auch wenn die Liste leer
   ist (das bedeutet dann ehrlich: "Account ist bekannt, hat aber
   keine lokalen Gruppen", was die korrekte Antwort ist).
4. Wenn **alle** Kandidaten `UserNotFoundOnServer` liefern: gibt
   einen `CoreError::Validation(reason)` zurück — der Aufrufer
   setzt `LocalGroupEvalStatus::NotAvailable(reason)`, und das
   treibt die `incomplete = true`-Logik in der Risk-Engine.
5. Bei jedem anderen technischen Fehler (Access Denied, NetAPI-
   Fehler): sofort propagieren, kein Weiterprobieren.

**CLI** (`crates/cli/src/main.rs::collect_local_group_sids_for_path`)
und **GUI** (`crates/gui/src/worker.rs::collect_local_group_sids_for_path`)
rufen jetzt `resolve_local_group_sids_for_identity` direkt mit
der `&Identity` auf, nicht mehr `format_account_for_local_groups` +
`resolve_local_group_sids`.

## Consequences

**Positiv / Positive:**

- Trust-/Multi-Domain-Identities mit NetBIOS-Domain werden über
  `DOMAIN\name` jetzt regelmäßig erkannt — der typische Produktivfall
  funktioniert.
- Wenn der Account auf dem Zielserver tatsächlich nicht bekannt ist,
  surfaced das jetzt als `LocalGroupEvalStatus::NotAvailable(...)`
  mit konkretem `tried`-Reason — kein stiller Skip mehr.
- Risk-Engine markiert solche Befunde automatisch als
  `incomplete = true` (`LocalGroupEvalStatus::NotAvailable` ist seit
  v1.0 ein Incomplete-Trigger).
- Backward-Compat: die alten Public-APIs bleiben erhalten.

**Negativ / Negative:**

- Bis zu vier NetAPI-Aufrufe pro Identity im schlechtesten Fall
  (UPN, DOMAIN\name, name@dns, name). In der Praxis trifft der erste
  oder zweite Kandidat — der Overhead ist gering.
- `LocalGroupEvalStatus::NotAvailable` taucht häufiger auf als
  vorher, weil der Pfad jetzt ehrlich ist. Das ist gewollt — der
  Auditor sah vorher stille `Applied(0)`-Befunde, die in Wahrheit
  Lücken waren.

**Test-Anforderungen:**

- 5 neue Unit-Tests in `local_groups::tests`:
  - `format_falls_back_to_domain_backslash_name_for_dns_domain`
  - `format_netbios_domain_only_emits_domain_backslash_form`
  - `format_returns_plain_name_without_domain` (erweitert)
  - `looks_like_dns_domain_distinguishes_netbios_and_dns`
  - `format_upn_wins_over_domain_form`
- Bestehende `format_ignores_empty_upn` an neue
  `DOMAIN\name`-First-Reihenfolge angepasst.
- Bestehende `format_returns_none_without_name` umbenannt zu
  `format_returns_empty_without_name` (Kandidatenliste statt
  Option).

**Was bewusst NICHT geändert wurde:**

- `resolve_local_groups` (mit Gruppennamen, intern für
  `resolve_local_group_chains` in `sam.rs` — das ist eine andere
  API-Ebene und nicht der ChatGPT-Pfad). Dort wird `account.name`
  von LSA direkt verwendet; der Fix kann bei Bedarf in einem
  späteren ADR übertragen werden.
- `resolve_local_group_sids` selbst (öffentliche API) bleibt
  rückwärtskompatibel mit `Ok(Vec::new())` bei NERR — neue
  Aufrufer sollten aber `_for_identity` oder `_strict` verwenden.

## Schließt / Closes

Review 2026-06-04 Runde 5, Finding 1 (Lokale Servergruppen können
bei LSA-/Trust-Identitäten still fehlen).

## Verweise / References

- ADR 0033 — Sichtbare Diagnostik für SAM-Fallback und deaktivierte
  Identitäten.
- ADR 0034 — Multi-Domain-LSA-Fallback für Identitätsauflösung.
- ADR 0036 — Einheitliche Principal-Resolution-Pipeline.
- ADR 0039 — Diagnostik für gescheiterte Identity- und Group-
  Auflösung (parallel: Incomplete-Marker auf `EffectivePermission`-
  Ebene; dieser ADR ergänzt das auf `LocalGroupEvalStatus`-Ebene).
- [known-limitations.md L5](../known-limitations.md) — leere
  Memberships im Outside-Pfad.
