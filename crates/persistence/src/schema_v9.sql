-- Migration v9 (review CR-19): what a run covered, so the delta comparison
-- can refuse runs of a different scope or depth limit.
-- scope: 'scan' or 'analyze'; NULL for a run stored before v9 (unknown).
-- max_depth: the scan's depth limit; NULL = unlimited when scope is set.
ALTER TABLE scan_runs ADD COLUMN scope TEXT;
ALTER TABLE scan_runs ADD COLUMN max_depth INTEGER;
