# ADR 0034 — Multi-Domain-LSA-Fallback für Identitätsauflösung

**Status:** Accepted
**Date:** 2026-06-04

## Context

Beim zweiten ChatGPT-Code-Review-Durchgang am 2026-06-04 stand der
`DOMAIN\user`-Pfad in `ad_resolver::resolver::LdapResolver` im Fokus.
Bisheriges Verhalten:

1. `LookupAccountNameW` (LSA) löst `DOMAIN\user` korrekt zur SID auf —
   auch für vertrauenswürdige Domänen außerhalb der Forest-Root.
2. Anschließend versucht `resolve_identity_internal(sid)` per LDAP über
   `objectSid` die zugehörige Identity zu finden.
3. Liefert die LDAP-Suche `None` (Standardfall in Multi-Domain-Forests,
   weil `base_dn` auf eine einzelne Domain zeigt), entstand bisher eine
   `IdentityKind::Orphaned`-Identity. Das traf besonders Konten aus
   Trusted Domains und Cross-Forest-Trusts.

Folgen der bisherigen Klassifikation:

- Reale Domain-User wurden als „verwaiste SID" gerendert.
- Die Erklärungspfade hatten keinen Namen.
- Audit-Konsumenten konnten nicht unterscheiden, ob die SID wirklich
  unbekannt ist oder ob das `base_dn` einfach nur die falsche Domain
  indexiert.
- Die Gruppenauflösung lief auf eine nackte Liste — eine echte
  rekursive Domain-Gruppen-Auflösung war in dieser Konstellation nicht
  möglich.

## Decision

Wenn LSA eine gültige SID liefert, LDAP die SID aber nicht indexiert,
fällt der Resolver auf eine **LSA-only-Identity** zurück und markiert
das Ergebnis über zwei strukturierte Diagnose-Marker an der
`EffectivePermission`:

1. **Neue Diagnose-Variante `IdentityNotInConfiguredLdapBase`**
   - Wird gesetzt, sobald `lookup_via_lsa` zwar eine SID auflösen konnte,
     der konfigurierte LDAP-`base_dn` die SID aber nicht überstreicht.
   - Engine pusht den Marker; `risk_engine::is_incomplete()` matched
     ihn (wie `DomainGroupRecursionIncomplete`) — abgeleitete Risk-
     Findings werden als `incomplete = true` ausgewiesen.

2. **Neue Diagnose-Variante `IdentityDisabledStatusUnknown`**
   - Wird zusätzlich gesetzt, weil im LSA-only-Pfad weder `disabled`
     noch `userPrincipalName` zuverlässig bekannt sind.
   - `risk_engine::is_incomplete()` matched die Variante bewusst
     **nicht** — sie ist rein informationell. ACL-Auswertung selbst ist
     korrekt; nur die Frage „kann der Account sich überhaupt
     authentifizieren?" bleibt offen.

3. **Datenfluss durch die ganze Pipeline:**
   - `LookupResult` (neu in `ad_resolver`) trägt beide Flags.
   - `ResolvedIdentity` (CLI) und `IdentityResolution` (GUI-Worker)
     reichen sie durch.
   - Beide Felder in `PermissionEvaluationInput` (`identity_not_in_
     configured_ldap_base`, `identity_disabled_status_unknown`).
   - Engine prüft beide Flags und pusht jeweils den passenden Marker.

4. **LSA-only Identity-Aufbau:**
   - Helper `build_identity_from_lsa(sid)` in `resolver.rs` ruft
     `lookup_account_for_sid` auf und baut eine Identity mit
     `kind` aus `sid_use_to_kind`, `disabled = false` (konservativer
     Default) und `user_principal_name = None`. Bei LSA-Fehler bleibt
     der `Orphaned`-Pfad als letzte Stufe erhalten.

5. **Renderer:**
   - CLI (`output::print_report`) druckt `[!]`-Hinweis für
     `IdentityNotInConfiguredLdapBase` und `[i]`-Hinweis für
     `IdentityDisabledStatusUnknown`.
   - HTML-Exporter (`exporter::html`) rendert ein `badge-medium` bzw.
     `badge-info`.

## Consequences

**Positiv / Positive:**

- Audit-Konsumenten sehen explizit, warum ein Befund unvollständig
  ist — keine stillen Falsch-`Orphaned`-Klassifikationen mehr.
- `IdentityNotInConfiguredLdapBase` macht die Konfiguration sichtbar:
  Wer den Forest vollständig auswerten will, weiß sofort, dass eine
  zweite (oder Global-Catalog-)`base_dn` nötig ist.
- Engine, CLI, GUI, HTML/CSV/JSON gehen einheitlich durch die
  `PermissionDiagnostic`-Pipeline — kein Sonderpfad, kein Re-Render.
- Bricht keine bestehenden Konsumenten: Variant-tagged JSON ist
  vorwärtskompatibel.

**Negativ / Negative:**

- Im LSA-only-Pfad sind verschachtelte Domain-Gruppen *des
  Trust-Partners* weiterhin nicht aufgelöst. Der Marker macht das
  sichtbar, aber löst es nicht.
- `disabled` ist im LSA-Pfad nicht zuverlässig. ADR 0035 deckt den
  analogen SAM-Pfad mit `NetUserGetInfo` ab — für reine LSA-Resolutions
  wäre dafür eine zusätzliche `NetUserGetInfo`-Abfrage am
  Trust-Partner-Server nötig (außerhalb dieses ADRs).

**Test-Anforderungen:**

- Permission-Engine-Tests, die `identity_not_in_configured_ldap_base =
  true` setzen, müssen den entsprechenden Marker in `result.diagnostics`
  sehen.
- Risk-Engine-Tests: ein Finding über eine Permission mit
  `IdentityNotInConfiguredLdapBase` muss `incomplete = true` tragen.
- Renderer-Snapshots (HTML/CSV): die zwei neuen Marker dürfen den
  String der Variante nicht erfinden, sondern müssen die UI-Beschreibung
  rendern.

## Schließt / Closes

Review 2026-06-04 Runde 2, Finding 1 (Multi-Domain-LSA-Fallback).

## Verweise / References

- ADR 0021 — Permission Diagnostics als variant-tagged Enum.
- ADR 0032 — Identity-Input-Dispatcher und LDAP-Timeouts (führt den
  `DOMAIN\user`-Pfad ein).
- ADR 0033 — Sichtbare Diagnostik für SAM-Fallback und deaktivierte
  Identitäten (Variant-Schema und Flag-Propagation als Vorbild).
- ADR 0035 — SAM-Pfad bestätigt `disabled` per `NetUserGetInfo`
  (komplementär zu diesem ADR).
