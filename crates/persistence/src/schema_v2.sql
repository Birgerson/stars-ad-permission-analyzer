-- Migration v2: Sicherheitsrelevante Bewertungsdetails persistieren.
-- Migration v2: Persist security-relevant evaluation details.
--
-- Ergänzt effective_permissions um Share-Auswertungsstatus, Share-Fehlertext
-- und die beitragenden SIDs, damit historische Scans roundtrip-fähig bleiben.
-- Extends effective_permissions with share evaluation status, share error text,
-- and contributing SIDs so historical scans round-trip faithfully.

ALTER TABLE effective_permissions
    ADD COLUMN share_status TEXT NOT NULL DEFAULT 'NotApplicable';

ALTER TABLE effective_permissions
    ADD COLUMN share_error TEXT;

ALTER TABLE effective_permissions
    ADD COLUMN contributing_sids TEXT NOT NULL DEFAULT '[]';
