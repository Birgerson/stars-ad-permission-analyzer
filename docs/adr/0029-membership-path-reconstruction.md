# ADR 0029 — Konkreter Mitgliedschafts-Pfad in der Erklärung

**Status:** Akzeptiert / Accepted
**Datum / Date:** 2026-06-01

## Kontext / Context

ADR 0014 hat die transitive Gruppenauflösung serverseitig per
`LDAP_MATCHING_RULE_IN_CHAIN` umgesetzt. Das liefert eine vollständige
Menge aller Gruppen, in denen ein Principal transitiv enthalten ist —
aber keinen Pfad. Der Erklärungstext eines `EffectivePermission`-
Ergebnisses zeigte deshalb pro Gruppe nur `Member of GRP_B [transitive]`.

Für ein Audit ist das nicht ausreichend: ein Prüfer muss den
Berechtigungsweg nachvollziehen können, also „über welche
Zwischengruppe wirkt die ACE auf den Benutzer?". Reviewer-Befund
2026-05-31 #1 stuft das als High ein, weil die Effektiv-Berechnung
zwar korrekt ist, der Beweisweg aber unvollständig bleibt.

## Entscheidung / Decision

1. **Neues Datenmodell `MembershipPath` in `adpa_core::model`.**
   Trägt:
   - `nodes: Vec<Sid>` — Kette `Member → … → Zielgruppe`, beginnend mit
     der Identitäts-SID.
   - `names: Vec<Option<String>>` — index-aligned zu `nodes`, lesbarer
     Anzeigename pro Knoten (sofern bekannt).
   - `source: MembershipPathSource` —
     `PrimaryGroup | DomainGroup | LocalGroup | LdapMatchingRule`.
   - `complete: bool` — `true` nur, wenn die Kette aus konkreten
     `member`-Edges rekonstruiert wurde.

2. **`GroupMembership.path: Option<MembershipPath>`** — neues Feld mit
   `#[serde(default)]`, damit ältere Cache-Einträge ohne dieses Feld
   weiterhin lesbar bleiben.

3. **LDAP-Resolver: BFS-Rekonstruktion über `memberOf`-Edges.**
   - Nach der bestehenden Transitivsuche wird aus den schon geladenen
     Gruppen-Entries ein Forward-Graph `group_dn → [memberOf-DNs]`
     aufgebaut.
   - Startknoten der BFS sind die direkten `memberOf`-DNs des Benutzers
     und (falls vorhanden) die Primärgruppe.
   - Die BFS markiert pro erreichtem Gruppen-DN einen Vorgänger
     (`came_from`). Die kürzeste Kette zur Zielgruppe wird durch
     Rückwärtslesen rekonstruiert und in SIDs übersetzt.
   - Wird ein transitiv bestätigtes Ziel nicht erreicht (z. B. weil
     `memberOf` einer Zwischengruppe vom Server trunkiert wurde),
     bleibt der Pfad zwei SIDs lang und wird als
     `complete = false` mit `source = LdapMatchingRule` markiert.

4. **SAM-Resolver: analoge Pfade.** `NetUserGetGroups` liefert direkte
   Kanten — Pfad `[user_sid, group_sid]`, `source = DomainGroup`,
   `complete = true`. `NetUserGetLocalGroups` liefert die Endmenge,
   ohne konkrete Zwischenketten — Pfad `[user_sid, group_sid]`,
   `source = LocalGroup`, `complete = false`.

5. **Engine-Rendering.** Pro Mitgliedschaft mit konkretem Pfad gibt die
   Engine genau einen Schritt aus:

   ```text
   Member of GRP_B (S-1-5-21-…) [via max.mustermann → GRP_A → GRP_B, source: DomainGroup]
   ```

   Direkte Kanten erhalten `[direct, source: …]`. Unvollständige
   transitive Ketten werden mit
   `[transitive, exact chain unknown — source: LdapMatchingRule, possibly truncated memberOf]`
   markiert. `path = None` (Cache-Reads) fällt auf das alte Format
   `Member of X [direct/transitive]` zurück.

6. **Persistenz speichert weiter nur Topologie.** `identity_cache`
   schreibt `MembershipPath` bewusst nicht zurück — die Rekonstruktion
   ist eine Live-Auswertung und kostet pro Lauf nichts, was eine
   Persistierung rechtfertigen würde.

## Begründung / Rationale

- **Audit-Korrektheit.** AGENTS.md fordert pro Ergebnis eine
  nachvollziehbare Kette, nicht nur die Endaussage. Ohne diesen Pfad
  bleibt die Effektiv-Berechnung wahr, aber unbeweisbar.
- **Keine zusätzlichen LDAP-Roundtrips.** Die Rekonstruktion läuft auf
  Entries, die ohnehin schon geladen werden (Transitivsuche bringt die
  Gruppen-Entries mit `memberOf`-Attribut zurück; siehe
  `MEMBERSHIP_ATTRS` in `ldap_client`).
- **Backwards-kompatibel.** Das neue Feld ist `Option`. Cache-Reads und
  externe Konsumenten ohne Pfad bekommen weiterhin sinnvollen Output.
- **`complete`-Flag macht den Unterschied sichtbar.** Wenn die Kette
  nicht rekonstruierbar ist (z. B. wegen `memberOf`-Trunkierung), wird
  das im Bericht explizit ausgewiesen statt einer plausibel aussehenden,
  aber irreführenden Direkt-Aussage.

## Konsequenzen / Consequences

- Erklärungstexte sind länger geworden. Für GUI-Listenansichten kann
  das eine optische Anpassung erfordern (Wrap-/Truncation-Verhalten).
- Die BFS arbeitet ausschließlich auf den bekannten Entries — wenn der
  Server `memberOf` eines transitiven Zwischenglieds trunkiert,
  enthält der Pfad nur die Endpunkte (`complete = false`). Das ist die
  ehrlichere Antwort als ein erratener Pfad.
- Risikoregeln in `risk_engine` werten weiterhin `matched_aces` und
  `contributing_sids` aus — sie hängen nicht am Erklärungstext. Diese
  Trennung wird durch ADR 0029 verstärkt: der Pfad ist
  Audit-Information, kein Berechnungs-Input.

## Tests / Tests

Vier neue Engine-Tests in `crates/permission_engine/src/engine.rs`:

- `explanation_contains_nested_chain_in_order` — Kernforderung des
  Reviews: für `User → GRP_A → GRP_B → ACE on GRP_B` muss der
  Erklärungsschritt die Reihenfolge `max.mustermann → GRP_A → GRP_B`
  innerhalb des `via …`-Blocks enthalten.
- `explanation_direct_membership_with_source_label` — direkte Kante
  zeigt `[direct, source: PrimaryGroup]`.
- `explanation_incomplete_transitive_marks_unknown_chain` —
  `complete = false` schreibt `exact chain unknown` ins Ergebnis.
- `explanation_falls_back_to_legacy_format_when_path_missing` —
  Rückwärtskompatibilität mit `path = None`.

## Schließt / Closes

ChatGPT-Code-Review 2026-05-31, Finding 1 (High).
