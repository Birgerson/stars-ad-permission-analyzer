-- Migration v6: Persist structured diagnostic markers per permission.
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
