-- Migration v5: Persist the local server group resolution status.
--
-- Extends effective_permissions with two columns mirroring share_status /
-- share_error. local_group_status may be 'NotQueried', 'Applied' or
-- 'NotAvailable'; local_group_error carries the reason on failure. Risk
-- rules and reports can derive from this whether a permission is incomplete
-- due to missing local groups.

ALTER TABLE effective_permissions
    ADD COLUMN local_group_status TEXT NOT NULL DEFAULT 'NotQueried';
ALTER TABLE effective_permissions
    ADD COLUMN local_group_error TEXT;
