-- Migration v7: per-permission identity snapshot
-- (Code review 2026-06-07, finding 1)
--
-- Until v6, `effective_permissions` carried only the SID, and
-- name/domain/kind/disabled were resolved on read via
-- `LEFT JOIN identities` against the current global row. But the
-- `identities` table was upserted on every insert — meaning a later
-- scan could retroactively change how earlier runs looked when
-- reloaded (user gets disabled, the old scan shows disabled=true
-- on re-read even though they were active at scan time). This
-- breaks the audit property "evidence is immutable".
--
-- Fix: four snapshot columns directly on `effective_permissions`.
-- On insert the current identity values are copied alongside. On
-- read the snapshot is the primary source; `identities` remains as
-- a cache for SID lookups that aren't in any permission row yet
-- (e.g. when `identity_cache.rs` is queried separately).
--
-- Backfill: existing rows are populated from the `identities`
-- table. This is the best available approximation because the
-- original state at scan time was never preserved. New scans after
-- this migration are correct from run-start onwards.

ALTER TABLE effective_permissions ADD COLUMN identity_name TEXT;
ALTER TABLE effective_permissions ADD COLUMN identity_domain TEXT;
ALTER TABLE effective_permissions ADD COLUMN identity_kind TEXT NOT NULL DEFAULT 'Unknown';
ALTER TABLE effective_permissions ADD COLUMN identity_disabled INTEGER NOT NULL DEFAULT 0;

-- Backfill from the identities cache (best-effort).
UPDATE effective_permissions
SET identity_name     = (SELECT name     FROM identities WHERE identities.sid = effective_permissions.sid),
    identity_domain   = (SELECT domain   FROM identities WHERE identities.sid = effective_permissions.sid),
    identity_kind     = COALESCE(
                            (SELECT kind     FROM identities WHERE identities.sid = effective_permissions.sid),
                            'Unknown'),
    identity_disabled = COALESCE(
                            (SELECT disabled FROM identities WHERE identities.sid = effective_permissions.sid),
                            0)
WHERE EXISTS (SELECT 1 FROM identities WHERE identities.sid = effective_permissions.sid);
