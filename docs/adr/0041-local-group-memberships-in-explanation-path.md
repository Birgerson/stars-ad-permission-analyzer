# ADR 0041 — Lokale-Gruppen-Mitgliedschaften im Erklärungspfad

**Status:** Accepted
**Date:** 2026-06-05

## Context

ADR 0040 hat die *Auswertung* lokaler Server-Gruppen für Trust-Identities
geschlossen: Eine Kandidatenliste (`format_account_candidates_for_local_groups`)
sorgt dafür, dass `NetUserGetLocalGroups` für NetBIOS-Trust-Identities die
korrekten lokalen Gruppen-SIDs zurückliefert. Diese SIDs fließen in das
Token-Set ein, mit dem die Engine ACEs gegen die Identität matcht.

Was ADR 0040 **nicht** gelöst hat: die **Erklärung**. Die lokalen
Gruppen-SIDs landeten ausschließlich im `local_group_sids`-Token der
Engine. `group_memberships` — der Datenstrom, aus dem
`format_membership_step()` die Pfad-Schritte rendert — sah sie **nicht**.

Der sichtbare Effekt im Bericht:

```text
Effective Rights: Modify (0x001301BF)
Explanation Path
  1. User: alice
  2. Member of Domain Users [direct, source: PrimaryGroup]
  3. Allow ACE [explicit] for BUILTIN\Administrators → Modify
  4. NTFS effective: Modify
```

Schritt 3 nennt zwar die ACE, lässt aber offen, **warum** alice in
`BUILTIN\Administrators` ist. Der Auditor sieht „Modify gilt für eine
lokale Gruppe", ohne den Mediator-Schritt zu sehen, der diese Mitgliedschaft
begründet (z. B. `alice → Domain Admins → BUILTIN\Administrators`).

Review 2026-06-05 Runde 6 Finding 1 hat das als **High** klassifiziert:
Stars meldet korrektes Effective-Right, gibt aber im Erklärungspfad keine
nachvollziehbare Begründung — was direkt gegen das Read-only-Auditing-Versprechen
verstößt, jeden Rechte-Befund nachvollziehbar zu machen.

## Decision

Der `ad_resolver` produziert pro Identität nicht mehr nur ein
SID-Vec für lokale Gruppen, sondern ein **`Vec<GroupMembership>` mit
`MembershipPathSource::LocalGroup`**.

### 1. Neue Resolver-Funktion

`crates/ad_resolver/src/local_groups.rs::resolve_local_group_chains_for_identity`:

```rust
pub fn resolve_local_group_chains_for_identity(
    server: Option<&str>,
    identity: &Identity,
    known_member_sids_to_names: &HashMap<String, String>,
) -> Result<Vec<GroupMembership>, CoreError>
```

Die Funktion:

1. Bildet Account-Kandidaten via `format_account_candidates_for_local_groups`
   (ADR 0040 — wiederverwendet).
2. Ruft pro Kandidat `resolve_local_group_chains` auf, das zusätzlich zu
   den SIDs auch die **Member-Chain** liefert (Pfad-Knoten und
   `complete`-Flag).
3. Konvertiert jede gefundene Chain in `GroupMembership { source = LocalGroup }`.
   Direkte Mitgliedschaft (`path.nodes.len() == 2 && complete`) wird mit
   `direct: true` markiert; mehrstufige Ketten oder unvollständige
   Lookups mit `direct: false`.
4. Sobald ein Kandidat erfolgreich war (`WithGroups`), bricht die Schleife
   ab — gleiche Reihenfolgesemantik wie bei ADR 0040.

### 2. CLI und GUI mergen die Mitgliedschaften

`crates/cli/src/main.rs` und `crates/gui/src/worker.rs`:
`collect_local_group_sids_for_path` gibt ein 3-Tupel zurück:

```rust
(Vec<Sid>, Vec<GroupMembership>, LocalGroupEvalStatus)
```

Die SIDs werden wie bisher in `PermissionEvaluationInput::local_group_sids`
gefüllt. Die Memberships werden mit den AD-Memberships **gemergt** und
in `PermissionEvaluationInput::group_memberships` übergeben:

```rust
let all_memberships =
    resolved.resolution.memberships.clone()
        .into_iter()
        .chain(local_group_memberships)
        .collect();
```

### 3. Engine rendert LocalGroup-Step

`permission_engine::engine::format_membership_step` und
`source_label` waren bereits auf `MembershipPathSource::LocalGroup`
vorbereitet (siehe ADR 0036). Die Ausgabe für die neue Konstellation:

```text
Member of BUILTIN\Administrators (S-1-5-32-544)
    [via alice → Domain Admins → BUILTIN\Administrators, source: LocalGroup]
```

Bei unvollständiger Member-Chain (`complete: false`):

```text
Member of BUILTIN\Administrators (S-1-5-32-544)
    [exact chain unknown, source: LocalGroup]
```

## Consequences

### Positiv

- **Vollständig nachvollziehbare Pfade** — auch wenn lokale Server-Gruppen
  Teil der effektiven Berechtigung sind, kann der Auditor exakt sehen,
  welche Mediator-Gruppe(n) den Zugang vermitteln.
- **`exact chain unknown` als ehrliches Diagnose-Signal** — wenn die
  Member-Liste der lokalen Gruppe nicht lesbar ist, wird das im Pfad
  benannt, statt stillschweigend eine Lücke zu lassen.
- **ADR 0036's Versprechen (Unified Pipeline) ist eingehalten** — die
  Erklärung ist konsistent, egal ob die Mitgliedschaft aus AD oder aus
  einem lokalen Lookup stammt.
- **Token und Erklärung sind konsistent**: vorher konnte die Engine
  über eine SID matchen, ohne in der Erklärung eine Spur zu hinterlassen.

### Negativ / Trade-offs

- `resolve_local_group_chains_for_identity` ist langsamer als die reine
  SID-Variante, weil sie zusätzlich Member-Lookups pro Gruppe ausführt.
  Das ist akzeptabel — der Aufruf ist on-demand und cached den
  SID-zu-Namen-Lookup über `known_member_sids_to_names`.
- Doppelt referenzierte Memberships (sowohl AD als auch LocalGroup
  finden „alice → Domain Admins") sind möglich. Die Engine entdeckt
  das per `MembershipPath`-Vergleich nicht aktiv — der Pfad zeigt dann
  zwei Schritte mit unterschiedlicher Quelle. Für die Erklärung ist
  das tolerabel, weil beide Quellen tatsächlich existieren.

### Test-Abdeckung

Zwei neue Tests in `crates/permission_engine/src/engine.rs::tests`:

- `local_group_membership_renders_in_explanation_path` — vollständige
  Chain, `source: LocalGroup` muss im Pfad-Schritt erscheinen, Mediator
  (`Domain Admins`) muss in der Step-Zeile auftauchen.
- `local_group_membership_with_incomplete_path_renders_unknown_chain` —
  `complete: false` muss als `exact chain unknown` gerendert werden, die
  Quelle muss weiterhin als `LocalGroup` markiert sein.

Live-Verifikation gegen ein echtes 3-Forest-Lab in
[`docs/lab/verification.md`](../lab/verification.md) (Test T1, alice@tier0.lab):
der `BUILTIN\Users`-Mitgliedschafts-Step erscheint dort mit
`[via alice → Domain Users → BUILTIN\Users, source: LocalGroup]`.

## Beziehung zu anderen ADRs

- **ADR 0034** (LSA-Fallback): bringt die Trust-Identity überhaupt erst
  bis zur lokalen Gruppen-Auflösung.
- **ADR 0036** (Unified Principal Resolution Pipeline): definiert die
  einheitliche Mediator-Step-Semantik, die hier auf lokale Gruppen
  erweitert wird.
- **ADR 0040** (Kandidatenliste): wird wiederverwendet, sowohl für die
  Token-SID-Variante (`resolve_local_group_sids_for_identity`) als auch
  für die jetzt ergänzte Chain-Variante.
