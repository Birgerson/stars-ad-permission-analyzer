# ADR 0023 — Share-DACL in Stored-Order auswerten (Symmetrie zur NTFS-Engine)

**Status:** Accepted  
**Date:** 2026-05-25

## Context

ADR 0012 hat die NTFS-Engine auf Windows-`AccessCheck`-Semantik
umgestellt: DACL in gespeicherter ACE-Reihenfolge auswerten, erste
Entscheidung pro Recht-Bit gewinnt. Die Share-Seite blieb auf dem
alten Bucket-Modell:

```rust
let mut allow: u32 = 0;
let mut deny: u32 = 0;
for perm in perms {
    if user_sids.contains(&perm.sid.0) {
        let expanded = expand_generic_rights(perm.mask.0);
        match perm.kind {
            AceKind::Allow => allow |= expanded,
            AceKind::Deny  => deny  |= expanded,
        }
    }
}
Some(AccessMask(allow & !deny))
```

Bei nicht-kanonischer Share-DACL liefert das ein anderes Ergebnis als
Windows. Reviewer-Beispiel (Folge-Review 2026-05-25, Finding 1):
Allow-Everyone-Read gefolgt von Deny-Everyone-Read.

- NTFS-Engine (stored order): erstes Allow gewinnt → Read gewährt
- Share-Pfad (bucket): Deny wird mit allow-OR-kombiniert → Read entzogen

Da das Endresultat `NTFS ∩ Share` ist, vergiftet eine asymmetrisch
falsche Share-Maske jede Effective-Rights-Berechnung über UNC-Pfade,
selbst wenn die NTFS-Seite korrekt rechnet.

## Decision

1. **`effective_share_mask` walkt die Share-DACL in gespeicherter
   ACE-Reihenfolge.** Der Algorithmus ist exakt symmetrisch zu
   `permission_engine::engine::evaluate_dacl_ordered`:

   ```text
   granted, denied = 0, 0
   for perm in dacl:
       if perm.sid nicht im Token: skip
       mask = expand_generic_rights(perm.mask)
       undecided = ¬(granted ∨ denied)
       bits = mask ∧ undecided
       match perm.kind:
           Allow → granted |= bits
           Deny  → denied  |= bits
   return granted
   ```

   Bei kanonischer DACL (Deny vor Allow) ist das Ergebnis identisch
   zum vorigen Bucket-Modell; bei nicht-kanonischer DACL entspricht
   es exakt dem, was Windows-`AccessCheck` zur Laufzeit liefert.

2. **Nicht-kanonische Share-DACLs werden über `tracing::warn!`
   protokolliert.** Die strukturierte Diagnose in
   `EffectivePermission.diagnostics` ist NTFS-spezifisch (vgl.
   ADR 0021); eine Erweiterung auf die Share-Seite (entweder über
   eine zusätzliche Variante `NonCanonicalShareDaclOrder` oder über
   ein Diagnose-Feld in `ShareMaskStatus::Applied`) bleibt offen
   für eine spätere Iteration. Der Log-Pfad ist ausreichend, bis
   ein konkreter Audit-Use-Case Share-Diagnostik strukturell
   verlangt.

3. **Neuer Detektor `first_non_canonical_position(&[SharePermission])`**
   analog zum NTFS-Pendant in `engine.rs`. Share-DACLs tragen
   technisch nie ein INHERITED-Flag (keine Share-zu-Share-Vererbung),
   daher reduziert sich der Phasenraum praktisch auf 0 (Deny) und
   1 (Allow). Das 4-Phasen-Modell bleibt strukturell als Symmetrie
   zur NTFS-Variante erhalten.

## Rationale

- **Korrektheit hat Vorrang** (AGENTS.md Grundregel 1) und gilt
  symmetrisch für NTFS und Share. Eine zur Hälfte gefixte
  AccessCheck-Treue ist schlimmer als gar keine, weil sie eine
  falsche Sicherheit suggeriert.
- **Single-source-of-truth-Symmetrie:** der gleiche Algorithmus
  läuft auf beiden DACL-Typen, was zukünftige Anpassungen einfacher
  konsistent macht.
- **Bewusster Trade-off bei der Diagnose:** ein `warn!`-Log fängt
  den Audit-Fall heute schon, eine strukturelle Persistenz wäre
  invasiver (Schema/Export/Persistence-Migration) und kommt, wenn
  ein konkreter Use-Case sie verlangt — dasselbe Muster wie bei
  ADR 0012 → ADR 0021.

## Consequences

- 5 neue Tests in `share_scanner::scanner::tests`:
  - `non_canonical_allow_before_deny_first_wins`
    (Reviewer-Beispiel, direkter Beweis der neuen Semantik)
  - `canonical_deny_before_allow_first_wins`
    (Standardfall, identisches Ergebnis vor/nach Fix)
  - `partial_overlap_first_decision_per_bit`
    (Disjunkte Deny/Allow-Bits: pro Bit gewinnt der erste Treffer)
  - `detects_non_canonical_share_dacl_position`
  - `canonical_share_dacl_passes_detector`
- 2 bestehende Tests auf kanonische Reihenfolge umgestellt:
  - `deny_overrides_allow`
  - `generic_read_deny_blocks_file_read_bits`

  Beide setzten implizit das Bucket-Verhalten voraus
  (`[Allow, Deny]` → Deny gewinnt). Mit Stored-Order-Semantik gilt
  „Deny gewinnt nur, wenn es zuerst kommt", was der Windows-
  kanonischen Reihenfolge entspricht. Aussage und Intent bleiben
  identisch; nur die ACE-Reihenfolge der Fixtures wurde angepasst.
- Keine API-Änderung, keine Schemamigration.
- Aufrufer (CLI/GUI über `resolve_(scan_)share_status`) sind nicht
  betroffen — das Funktions-Interface bleibt unverändert.
- Diese Änderung allein behebt **nicht** Finding 2 aus dem gleichen
  Review (Unsupported Share-ACE-Typen ohne Diagnose) — das ist eine
  separate Folgearbeit.
