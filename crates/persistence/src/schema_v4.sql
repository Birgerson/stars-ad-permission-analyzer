-- Migration v4: Strukturierte ACE-Herkunft persistieren.
-- Migration v4: Persist structured ACE origin.
--
-- Ergänzt effective_permissions um die zur Identität passenden DACL-Einträge
-- (matched_aces) als JSON. Damit lassen sich Risikoregeln wie DIRECT_USER_ACE
-- auch auf historischen Scans korrekt nachrechnen.
-- Extends effective_permissions with the DACL entries matching the identity
-- (matched_aces) as JSON, so risk rules such as DIRECT_USER_ACE can be
-- recomputed correctly on historical scans.

ALTER TABLE effective_permissions
    ADD COLUMN matched_aces TEXT NOT NULL DEFAULT '[]';
