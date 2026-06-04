# ADR 0039 — Diagnostik für gescheiterte Identity- und Group-Auflösung

**Status:** Akzeptiert / Accepted
**Datum / Date:** 2026-06-04

## Kontext / Context

Review 2026-06-04 Runde 4 Finding 1 (High) hat einen Folgemangel der
in ADR 0036 eingeführten zentralen Principal-Pipeline aufgedeckt: die
neuen Status-Werte `IdentityScopeStatus::LookupFailed { reason }`,
`GroupResolutionStatus::Failed { reason }` und in bestimmten
Konstellationen auch `GroupResolutionStatus::NotAttempted` haben
**keine sichtbaren Diagnose-Marker** erzeugt.

Konkrete Folge:

- LDAP-Bind-Fehler, Timeout oder Query-Crash in `resolve_by_sid` wurde
  in `LookupFailed { reason }` umgewandelt — die Analyse lief mit
  Platzhalter-Identity und leeren Memberships weiter.
- `resolve_groups` wandelte Fehler in `Failed { reason }` um und gab
  leere Memberships zurück; die Engine sah das als „kein
  Multi-Domain"-Standardfall.
- `engine_flags()` setzte nur drei Booleans (`Outside`, `Unknown`,
  `SamFlat`); `LookupFailed` und `Failed` flossen nirgendwohin.
- Permission-Engine pushte keinen entsprechenden Marker; Risk-Engine
  konnte nicht `incomplete = true` setzen.

In der Praxis konnte damit ein Befund **„sauber" aussehen**, obwohl er
mit leerem Token gerechnet wurde. Genau das Anti-Pattern, das die
ganze Marker-Architektur seit ADR 0021 vermeiden soll.

(Selbstkritik: dieses Problem hatte ich in der ehrlichen Status-
Antwort am Ende der v1.4.1-Diskussion bereits selbst identifiziert,
in v1.5.0 aber als „LookupFailed ist Edge-Case" offen gelassen. Das
war ein Fehler — Edge-Cases sind genau das, wo Marker sichtbar sein
müssen.)

## Entscheidung / Decision

Zwei neue strukturierte Diagnose-Marker in
`adpa_core::model::PermissionDiagnostic`:

```rust
PermissionDiagnostic::IdentityLookupFailed { reason: String }
PermissionDiagnostic::GroupResolutionFailed { reason: String }
```

Beide tragen den ursprünglichen Fehlertext mit, damit Auditoren das
wirkliche Problem (Bind-Fehler, Timeout, DC-Adresse falsch …) im
Bericht sehen. Beide sind **Incompleteness-Trigger** — die Risk-Engine
matched sie in `is_incomplete()`.

Datenfluss:

```text
PrincipalResolution.scope_status / group_resolution_status
   ↓ PrincipalResolution::engine_flags()
EngineFlags {
   …,
   identity_lookup_failure_reason: Option<String>,
   group_resolution_failure_reason: Option<String>,
}
   ↓ in PermissionEvaluationInput
PermissionEvaluationInput {
   …,
   identity_lookup_failure_reason: Option<String>,
   group_resolution_failure_reason: Option<String>,
}
   ↓ Engine pusht je Some-Wert den passenden Marker
EffectivePermission.diagnostics +=
   IdentityLookupFailed { reason }
   GroupResolutionFailed { reason }
   ↓ Risk-Engine is_incomplete() matched beide
RiskFinding.incomplete = true
   ↓ CLI- und HTML-Renderer beschreiben beide Marker
   ↓ JSON-Export trägt sie variant-tagged
```

**Drei Ableitungsregeln** in `engine_flags()`:

1. `IdentityScopeStatus::LookupFailed { reason }` →
   `identity_lookup_failure_reason = Some(reason)`.
2. `GroupResolutionStatus::Failed { reason }` →
   `group_resolution_failure_reason = Some(reason)`.
3. `IdentityScopeStatus::OutsideConfiguredLdapBase` +
   `GroupResolutionStatus::NotAttempted` →
   `group_resolution_failure_reason = Some("group resolution skipped:
   identity is outside the configured LDAP base")`. Vorher konnte der
   Outside-Pfad still ohne Gruppen rechnen.

**Renderer:**

- CLI (`output::print_report`) druckt `[!]`-Hinweis für beide Marker
  mit Reason-Text.
- HTML-Exporter (`exporter::html`) rendert beide als `badge-high`
  mit Reason im `title`-Attribut (HTML-escaped).

## Konsequenzen / Consequences

**Positiv / Positive:**

- Technische LDAP-/NetAPI-Fehler tauchen jetzt explizit in CLI, HTML
  und JSON auf — Auditoren wissen, warum ein Befund unvollständig
  ist.
- Risk-Findings werden automatisch als `incomplete = true` markiert
  — symmetrisch zu allen anderen Incompleteness-Quellen.
- Der `OutsideConfiguredLdapBase + NotAttempted`-Pfad ist nicht
  länger ein stiller Skip; die Lücke wird beim Auditor sichtbar.

**Negativ / Negative:**

- `EngineFlags` ist nicht mehr `Copy` (enthält jetzt `Option<String>`).
  Aufrufer müssen `.clone()` verwenden, wenn sie sie mehrfach
  konsumieren. Aktuelle Aufrufer wurden entsprechend angepasst.
- `PermissionEvaluationInput` wächst um zwei optionale Felder;
  Migration ist additiv.

**Test-Anforderungen:**

- 3 Principal-Tests:
  - `ldap_error_yields_lookup_failed_not_orphaned` (erweitert um
    `engine_flags()`-Assertion)
  - `group_resolution_error_after_identity_hit_carries_reason`
  - `outside_base_with_skipped_groups_yields_group_failure_reason`
- 2 Engine-Tests:
  - `engine_pushes_identity_lookup_failed_diagnostic_with_reason`
  - `engine_pushes_group_resolution_failed_diagnostic_with_reason`
- 2 Risk-Engine-Tests (positive `incomplete = true`-Assertion):
  - `full_control_marks_finding_incomplete_on_identity_lookup_failed`
  - `full_control_marks_finding_incomplete_on_group_resolution_failed`

## Schließt / Closes

Review 2026-06-04 Runde 4, Finding 1.

## Verweise / References

- ADR 0021 — Permission Diagnostics als variant-tagged Enum.
- ADR 0033 — Sichtbare Diagnostik für SAM-Fallback und deaktivierte
  Identitäten (Marker-Schema-Vorbild).
- ADR 0034 — Multi-Domain-LSA-Fallback.
- ADR 0035 — SAM-Pfad `disabled` per `NetUserGetInfo`.
- ADR 0036 — Einheitliche Principal-Resolution-Pipeline (führt die
  Status-Enums ein, deren Reasons hier durchgereicht werden).
- ADR 0037 — Validierte Wrapper konsequent propagieren.
- ADR 0038 — Share-Trustees im Scan-Output.
