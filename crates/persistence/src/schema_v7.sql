-- Migration v7: Identity-Snapshot pro Permission-Zeile
-- (Code Review 2026-06-07, Finding 1)
-- Migration v7: per-permission identity snapshot
-- (Code review 2026-06-07, finding 1)
--
-- Bis v6 hatte `effective_permissions` nur die SID, und Name/Domain/
-- Kind/Disabled wurden beim Lesen ueber `LEFT JOIN identities` per
-- aktueller globaler Zeile aufgeloest. `identities` wurde aber von
-- jedem Insert per Upsert ueberschrieben — d.h. ein spaeterer Scan
-- konnte alte Runs rueckwirkend anders aussehen lassen (User wird
-- deaktiviert, alter Scan zeigt nach Re-Read disabled=true, obwohl er
-- zum Zeitpunkt des Scans aktiv war). Das verletzt die
-- Audit-Eigenschaft "Evidence ist unveraenderlich".
--
-- Fix: vier Snapshot-Spalten direkt an `effective_permissions`. Beim
-- Einfuegen werden die aktuellen Identity-Werte mitkopiert. Beim
-- Lesen wird primaer der Snapshot verwendet; `identities` bleibt als
-- Cache fuer Lookups von SIDs, die noch nicht im Snapshot stehen
-- (z.B. wenn `identity_cache.rs` getrennt befragt wird).
--
-- Backfill: bestehende Zeilen werden aus der `identities`-Tabelle
-- nachgezogen. Das ist die beste verfuegbare Naeherung, weil der
-- urspruengliche Zustand zum Scan-Zeitpunkt nirgends erhalten wurde.
-- Neue Scans nach der Migration sind ab Run-Start korrekt.
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

-- Backfill aus identities-Cache (best-effort).
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
