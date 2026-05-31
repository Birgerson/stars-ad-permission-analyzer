-- Migration v3: Diagnose nicht unterstützter ACE-Typen persistieren.
-- Migration v3: Persist the unsupported-ACE-type diagnostic.
--
-- Ergänzt effective_permissions um die Anzahl der ACEs, deren Typ beim Scan
-- nicht ausgewertet werden konnte. Ein Wert > 0 markiert eine möglicherweise
-- unvollständige DACL-Auswertung auch in historischen Scans.
-- Extends effective_permissions with the count of ACEs whose type could not be
-- evaluated during the scan. A value > 0 marks a potentially incomplete DACL
-- evaluation, including in historical scans.

ALTER TABLE effective_permissions
    ADD COLUMN unsupported_ace_count INTEGER NOT NULL DEFAULT 0;
