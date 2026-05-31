-- Migration v6: Strukturierte Diagnose-Marker pro Berechtigung persistieren.
-- Migration v6: Persist structured diagnostic markers per permission.
--
-- Ergänzt effective_permissions um eine TEXT-Spalte `diagnostics`, die ein
-- JSON-Array von `PermissionDiagnostic`-Varianten trägt (Folge-Befund 3).
-- Aktuell nur `NonCanonicalDaclOrder { at_index }`; weitere Marker
-- (z. B. „inheritance disabled", „SACL nicht lesbar") können später
-- ergänzt werden, ohne erneute Schema-Migration — das Tagged-Enum-Format
-- bleibt vorwärtskompatibel.
--
-- Defaultwert '[]' macht ältere Zeilen lesbar als „keine Diagnose-Marker"
-- und vermeidet NULL-Branches im Reader.
--
-- Extends effective_permissions with a TEXT column `diagnostics` carrying a
-- JSON array of `PermissionDiagnostic` variants (follow-up finding 3).
-- Currently only `NonCanonicalDaclOrder { at_index }`; further markers
-- (e.g. "inheritance disabled", "SACL unreadable") can be added later
-- without another schema migration — the tagged enum format stays
-- forward-compatible.
--
-- Default '[]' makes older rows readable as "no diagnostic markers" and
-- avoids NULL branches in the reader.

ALTER TABLE effective_permissions
    ADD COLUMN diagnostics TEXT NOT NULL DEFAULT '[]';
