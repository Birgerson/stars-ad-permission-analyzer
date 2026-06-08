# ADR 0036 — Einheitliche Principal-Resolution-Pipeline

**Status:** Accepted
**Date:** 2026-06-04

## Context

Die ChatGPT-Code-Review 2026-06-04 Runde 3 (Finding 1, High) hat
offengelegt, dass der in v1.4.1 eingeführte Multi-Domain-/Trust-
Fallback **nur für `DOMAIN\user`** griff. Drei weitere Eingabewege
landeten an der zentralen Logik vorbei:

- **GUI Name → SID-Workflow**: `resolve_name_to_sid` löste den Namen
  per LSA auf, schrieb aber **nur die SID** ins UI-Feld. Die spätere
  Analyse rief `resolve_identity_sids(sid, ldap)` mit einem nackten
  SID-String auf — die LSA-Information verschwand, der LDAP-Miss endete
  in einer fälschlich-`Orphaned`-Klassifikation.
- **CLI direkte SID-Eingabe**: derselbe direkte
  `resolver.resolve_identity(&sid)`-Pfad, mit hartcodierten
  Diagnose-Flags `(false, false)`.
- **UPN-Pfad**: `lookup_via_upn` suchte nur unter der konfigurierten
  `base_dn` und gab bei Miss `None` zurück, obwohl die Doku einen
  Multi-Domain-Fallback versprach.

Zusätzlich verhielt sich der Identity-Cache toxisch: ein
`resolve_identity_internal`-Aufruf cached bei LDAP-Miss eine
`Orphaned`-Identity **bevor** `lookup_via_lsa` die LSA-only-Identity
baute — ein Folge-Aufruf für dieselbe SID konnte stale `Orphaned`-Daten
zurückliefern.

Damit konnte derselbe reale Trust-Principal je nach UI-/CLI-Eingabeform
mal korrekt mit Diagnose-Markern, mal still als verwaiste SID erscheinen.
Für AD-/DC-Audits ist das nicht akzeptabel — der ganze Sinn der Marker
aus ADR 0033 (Severity-Sichtbarkeit) wurde dadurch unterlaufen.

## Decision

Neue Pipeline `ad_resolver::principal` mit **einer einzigen
Public-Entry-Point-Methode**, die alle Eingabeformen einheitlich
behandelt und die Diagnose-Quelle in **einem** Modell konsolidiert:

```text
PrincipalInput::Auto(...)
   ↓ classify() — trimmt + klassifiziert
PrincipalResolver::resolve()
   ├─ DomainQualified / DisplayName → LSA-First-Pfad
   │       ↓ LSA: Name → SID
   │       ↓ dann gleicher Pfad wie SID
   ├─ Sid                             → LDAP-Lookup
   │       ↓ LDAP-Miss + LSA-Hit      → LSA-only Identity
   │                                     scope = OutsideConfiguredLdapBase
   │       ↓ LDAP-Miss + LSA-Miss     → OrphanedSid
   │       ↓ LDAP-Error               → LookupFailed { reason }
   ├─ Upn                             → LDAP-Lookup, Miss = explicit error
   │                                      mit GC-Hinweis (kein stiller Fallback)
   └─ SamAccount                      → LDAP-Lookup mit Eindeutigkeitsprüfung
                                     ↓
              PrincipalResolution {
                  sid, identity, memberships,
                  scope_status:           IdentityScopeStatus,
                  group_resolution_status: GroupResolutionStatus,
                  disabled_status:        DisabledStatus (Tri-State),
                  diagnostics:            Vec<PermissionDiagnostic>,
              }
                                     ↓
              EngineFlags { 3 Bool-Flags für PermissionEvaluationInput }
```

**Vier Tri-State-/Enum-Modelle** ersetzen die früheren Bool-Flag-
Sondertupel-Konstruktionen:

- `IdentityScopeStatus` — `InsideConfiguredLdapBase` /
  `OutsideConfiguredLdapBase` (Trust/Multi-Domain) / `OrphanedSid` /
  `LookupFailed { reason }`. **Trennt** echte verwaiste SIDs von realen
  Cross-Domain-Principals.
- `GroupResolutionStatus` — `LdapRecursive` / `SamFlat` / `Failed { reason }`
  / `NotAttempted`. **Trennt** "Auflösung passierte mit Lücke" von
  "Auflösung passierte gar nicht".
- `DisabledStatus` — Tri-State `Known(bool)` / `Unknown`. **Trennt**
  "Account aktiv" von "Account-Status nicht bekannt".
- `EngineFlags` — die drei Booleans, die in `PermissionEvaluationInput`
  fließen. **Single Source of Truth**: alle Aufrufer leiten sie über
  `PrincipalResolution::engine_flags()` ab.

**Backend-Traits** (`IdentityBackend`, `LsaBackend`) machen den
Resolver fakable — Phase 2 baute eine 11-Fall-Test-Matrix mit
In-Memory-LDAP- und LSA-Fakes, die genau die Eingabe-/Ergebnis-
Kombinationen abdeckt, an denen die alte Architektur leise versagte.

**Cache-Bug**: `resolve_identity_internal` cached jetzt keine
`Orphaned`-Identities mehr — der nächste Aufruf bekommt frische Daten,
LSA-Reklassifikation kann immer einsteigen.

## Consequences

**Positiv / Positive:**

- Derselbe Principal liefert in CLI und GUI bei jeder Eingabeform
  bit-genau dasselbe Resolution-Ergebnis. Keine stillen
  Klassifikations-Drifts mehr.
- Vier scharf abgegrenzte States ersetzen drei Bool-Flags — neue
  Diagnose-Marker können ohne API-Drift ergänzt werden.
- Die UPN-Doku entspricht jetzt der Implementierung: UPN-Miss ist ein
  expliziter Validation-Fehler mit Hinweis auf GC-Bind, nicht ein
  stiller Orphan.
- Die `_via_*`-Helfer und das alte `LookupResult`-Struct sind weg —
  weniger Public-API-Oberfläche, weniger Sonderpfade.
- Test-Matrix mit Fakes läuft im normalen `cargo test --workspace`,
  nicht nur als `#[ignore]`-Integrationstests.

**Negativ / Negative:**

- Interne API-Bruch: alle Caller mussten umgestellt werden (CLI 2
  Stellen, GUI 2 Stellen). Bricht keine öffentlichen Konsumenten,
  weil Stars keine externen Embedder hat.
- Das `principal`-Modul ist nicht-trivial groß (~700 Zeilen inkl.
  Tests). Akzeptiert als notwendige Komplexität für eine korrekte
  Pipeline.

**Test-Anforderungen:**

- 11 Tests in `principal::tests`:
  - `domain_user_ldap_hit_is_inside_base`
  - `domain_user_ldap_miss_with_lsa_hit_is_outside_base`
  - `direct_sid_ldap_miss_with_lsa_hit_is_outside_base` (Kernregression)
  - `display_name_workflow_uses_lsa_then_cross_checks`
  - `upn_outside_configured_base_returns_explicit_error`
  - `unknown_sid_with_no_lsa_match_is_orphaned`
  - `ldap_disabled_account_pushes_identity_disabled_marker`
  - `ldap_miss_without_lsa_backend_is_orphaned`
  - `ldap_error_yields_lookup_failed_not_orphaned`
  - `ambiguous_sam_returns_uniqueness_error`
  - `auto_dispatcher_classifies_by_syntax_and_trims`

## Schließt / Closes

Review 2026-06-04 Runde 3, Finding 1 (Multi-Domain-Fallback nur für
`DOMAIN\user`) inkl. der Cache-Vergiftung als implizitem Sub-Befund.

## Verweise / References

- ADR 0021 — Permission Diagnostics als variant-tagged Enum.
- ADR 0032 — Identity-Input-Dispatcher und LDAP-Timeouts.
- ADR 0033 — Sichtbare Diagnostik für SAM-Fallback und deaktivierte
  Identitäten.
- ADR 0034 — Multi-Domain-LSA-Fallback (v1.4.1, **nur `DOMAIN\user`**;
  dieser ADR generalisiert).
- ADR 0035 — SAM-Pfad `disabled` per `NetUserGetInfo`.
- ADR 0037 — Validierte Wrapper konsequent propagieren (parallel).
- ADR 0038 — Share-DACL-Trustees im Scan-Pfad (parallel).
