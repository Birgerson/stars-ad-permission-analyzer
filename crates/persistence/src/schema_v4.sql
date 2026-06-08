-- Migration v4: Persist structured ACE origin.
--
-- Extends effective_permissions with the DACL entries matching the identity
-- (matched_aces) as JSON, so risk rules such as DIRECT_USER_ACE can be
-- recomputed correctly on historical scans.

ALTER TABLE effective_permissions
    ADD COLUMN matched_aces TEXT NOT NULL DEFAULT '[]';
