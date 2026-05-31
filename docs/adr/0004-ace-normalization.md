# ADR 0004 — ACE-Normalisierung: NormalizedRights

**Status:** Akzeptiert / Accepted  
**Datum / Date:** 2026-05-20

## Kontext / Context

Rohe Windows-AccessMask-Werte (u32) aus DACL-Einträgen sind für Menschen
nicht direkt lesbar. Die Berechtigunslogik und spätere Exporter brauchen
eine benannte, vergleichbare Darstellung.

## Entscheidung / Decision

`NormalizedRights` in `permission_engine::mask` als eigenständiger Wrapper
um den rohen u32-Wert mit:

- Einzelbit-Getter (z. B. `read_data()`, `delete()`)
- Zusammengesetzte Prüfungen (`is_full_control()`, `is_modify()`, ...)
- `label()` / `display_name()` für icacls-kompatible Kurzform / Langform
- `intersect()` für die restriktivere NTFS-∩-Share-Kombination
- `From<AccessMask>` / `Into<AccessMask>` für typensichere Umwandlung

## Begründung / Rationale

- Kein Datenverlust: raw-Wert bleibt erhalten, alle Bits abfragbar
- Zusammengesetzte Masken entsprechen genau der Windows-icacls-Semantik
- `intersect()` implementiert die Kernregel: effektive Berechtigung =
  restriktivere Kombination aus NTFS und Share (vgl. AGENTS.md)
- Hierarchie-Tests stellen sicher: Full Control ⊃ Modify ⊃ RX ⊃ Read

## Composite-Masken-Werte / Composite mask values

| Name         | Hex          | Bits |
|--------------|--------------|------|
| Full Control | 0x001F_01FF  | STANDARD_RIGHTS_ALL \| SYNCHRONIZE \| 0x1FF |
| Modify       | 0x0013_01BF  | FC ohne WRITE_DAC, WRITE_OWNER, DELETE_CHILD |
| Read+Execute | 0x0012_00A9  | FILE_GENERIC_READ \| FILE_EXECUTE |
| Read         | 0x0012_0089  | FILE_GENERIC_READ |
| Write        | 0x0012_0116  | FILE_GENERIC_WRITE |

## Konsequenzen / Consequences

- Unit-Tests decken alle Composite-Prüfungen, Bit-Checks, Hierarchie
  und die Share-∩-NTFS-Kombinationslogik ab.
- `NormalizedRights` selbst ist passiv: es nimmt einen u32 entgegen und
  interpretiert ihn. Die Expansion generischer Bits (GENERIC_READ/WRITE/
  EXECUTE/ALL) erfolgt explizit über `expand_generic_rights()` und muss
  vor jeder Allow-/Deny-Auswertung aufgerufen werden (siehe ADR 0012).
- `permission_engine::engine` (DefaultPermissionEvaluator) nutzt
  `NormalizedRights` für Anzeige und Composite-Prüfungen sowie
  `expand_generic_rights()` für die fachliche Auswertung.
