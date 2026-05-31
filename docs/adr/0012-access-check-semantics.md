# ADR 0012 — DACL-Auswertung mit Windows-AccessCheck-Semantik

**Status:** Akzeptiert / Accepted  
**Datum / Date:** 2026-05-24

## Kontext / Context

Die ursprüngliche Implementierung in `DefaultPermissionEngine` hat alle
DACL-Einträge in vier Eimer (explicit/inherited × allow/deny) gesammelt
und daraus pauschale Masken kombiniert. Dieses Vorgehen war einfach,
aber wich in mehreren Punkten von der Windows-`AccessCheck`-Semantik ab:

1. **ACE-Reihenfolge wurde ignoriert.** Bei nicht-kanonischen DACLs kann
   eine spätere Deny-ACE eine frühere Allow-ACE nicht mehr umstoßen —
   Windows wertet ACEs in gespeicherter Reihenfolge aus. Der Bucket-
   Algorithmus konnte deshalb in seltenen, aber realen Fällen
   abweichende effektive Rechte berechnen (siehe Review-Befund 2).
2. **`INHERIT_ONLY_ACE` (0x08) wurde nicht ausgewertet.** ACEs mit
   diesem Flag gelten ausschließlich für Kinder und dürfen für das
   aktuelle Objekt keine Bits beitragen. Sie sind in der DACL vorhanden,
   sind aber für das aktuelle Objekt fachlich inert (Befund 1).
3. **Generische Rechte (GENERIC_READ/WRITE/EXECUTE/ALL, Bits 28–31)
   wurden im NTFS-Pfad nicht expandiert.** Ein `GENERIC_ALL`-Allow
   konnte deshalb als „Special" durchgereicht und im
   `NTFS ∩ Share`-AND auf 0 fallen. Der Share-Pfad expandierte bereits,
   der NTFS-Pfad nicht — die Inkonsistenz war ein Korrektheitsfehler
   (Befund 3).

## Entscheidung / Decision

1. **Auswertung erfolgt in gespeicherter ACE-Reihenfolge.**
   `evaluate_dacl_ordered` läuft die DACL einmal von vorne nach hinten
   durch. Pro Recht-Bit gewinnt die erste passende Entscheidung; bereits
   entschiedene Bits sind „immun" gegen spätere ACEs:

   ```text
   granted, denied = 0, 0
   for ace in dacl:
       if ace nicht anwendbar (INHERIT_ONLY) oder SID nicht im Token: skip
       mask = expand_generic_rights(ace.mask)
       undecided = ¬(granted ∨ denied)
       bits = mask ∧ undecided
       match ace.kind:
           Allow → granted |= bits
           Deny  → denied  |= bits
   return granted
   ```

   Bei kanonisch sortierter DACL ist das Ergebnis identisch zum vorigen
   Vier-Phasen-Modell; bei nicht-kanonischen DACLs entspricht es exakt
   dem, was `AccessCheck` zur Laufzeit liefert.

2. **`INHERIT_ONLY_ACE` wird vor der Auswertung gefiltert.** Der
   `fs_scanner`-Parser zerlegt `ACE_HEADER::AceFlags` jetzt sauber in
   `inheritance_flags` (OI | CI — *welche* Kinder erben) und
   `propagation_flags` (NP | IO — *wie* es propagiert). Der
   `INHERITED`-Bit (0x10) bleibt im separaten `inherited: bool`. Die
   Engine filtert ACEs mit gesetztem IO-Bit für das aktuelle Objekt
   konsequent aus.

3. **Generische Rechte werden zentral expandiert.**
   `permission_engine::mask::expand_generic_rights()` bildet
   `GENERIC_READ/WRITE/EXECUTE/ALL` auf die zugehörigen
   `FILE_GENERIC_*`-Bits bzw. `MASK_FULL_CONTROL` ab. NTFS-Engine,
   Erklärungsausgabe und `share_scanner` rufen alle die gleiche
   Funktion auf — der Share-Pfad hat seine lokale Kopie aufgegeben.

4. **Nicht-kanonische DACLs werden erkannt und protokolliert.**
   `first_non_canonical_position` markiert die erste ACE, die die
   Windows-Kanonik (explizit-Deny → explizit-Allow → inherited-Deny
   → inherited-Allow) bricht. Die Auswertung folgt trotzdem dem
   Stored Order; eine Warnung über `tracing::warn!` macht den Befund
   für Audits sichtbar, ohne das Datenmodell oder das DB-Schema
   ändern zu müssen.

## Begründung / Rationale

- **Korrektheit hat Vorrang vor Geschwindigkeit** (AGENTS.md, Grundregel 1).
  Der frühere Bucket-Ansatz war schneller, aber an einer entscheidenden
  Stelle inkorrekt — Behebung ist nicht optional.
- **Einheitliche Maskennormalisierung** macht den NTFS- und Share-Pfad
  konsistent. Eine doppelte Implementierung wäre eine Quelle für
  zukünftige Drift.
- Der Diagnose-Pfad über `tracing::warn!` ist bewusst gering invasiv:
  `EffectivePermission`, das DB-Schema, GUI/CLI/Export-Formate bleiben
  unverändert. Eine spätere strukturierte Diagnose (etwa ein
  `non_canonical_dacl: bool`-Feld) ist möglich, sobald ein konkreter
  Audit-Use-Case sie verlangt.

## Konsequenzen / Consequences

- Neue Regressionstests in `permission_engine::engine::tests` für
  INHERIT_ONLY, GENERIC_*-Bits, Allow-vor-Deny-Reihenfolge und den
  Non-Canonical-Detektor.
- Neue Tests in `fs_scanner::acl::tests` für `split_ace_flags`.
- `share_scanner` hängt jetzt von `permission_engine` ab — die gemeinsame
  Funktion `expand_generic_rights` liegt im Permission-Modul, weil die
  Mask-Expansion eine Permission-Semantik ist, keine FS-Semantik.
- `contributing_sids` filtert INHERIT_ONLY-ACEs aus und expandiert
  Generic-Bits vor dem AND mit dem Ergebnis; vorher konnten
  `GENERIC_ALL`-ACEs fälschlich als „nichts beigetragen" erscheinen.
