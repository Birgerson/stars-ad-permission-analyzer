-- Migration v8: indexes for run-scoped reads and deletes
-- (persistence review 2026-07-26, PS-3).
--
-- Until v7 neither child table had an index on scan_run_id, so
-- get_permissions (twice per delta comparison), list_errors_for and
-- delete_scan_run scanned the ENTIRE history table. With large
-- environments as the standard case, both lookups must be O(rows of the
-- run), not O(rows of all runs ever stored).
--
-- IF NOT EXISTS keeps the migration idempotent; index creation is
-- transactional like every other migration step.

CREATE INDEX IF NOT EXISTS idx_effective_permissions_scan_run_id
    ON effective_permissions(scan_run_id);

CREATE INDEX IF NOT EXISTS idx_scan_errors_scan_run_id
    ON scan_errors(scan_run_id);
