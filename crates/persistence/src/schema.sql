-- Migration v1: Initiales Schema / initial schema
-- Ausgeführt einmalig; PRAGMA user_version wird danach auf 1 gesetzt.
-- Applied once; PRAGMA user_version is set to 1 afterwards.

CREATE TABLE IF NOT EXISTS scan_runs (
    id          TEXT    PRIMARY KEY,
    started_at  TEXT    NOT NULL,
    finished_at TEXT,
    target      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_errors (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id TEXT    NOT NULL REFERENCES scan_runs(id),
    path        TEXT,
    message     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS identities (
    sid      TEXT    PRIMARY KEY,
    name     TEXT,
    domain   TEXT,
    kind     TEXT    NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS group_memberships (
    member_sid TEXT    NOT NULL,
    group_sid  TEXT    NOT NULL,
    direct     INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (member_sid, group_sid)
);

CREATE TABLE IF NOT EXISTS effective_permissions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id    TEXT    NOT NULL REFERENCES scan_runs(id),
    sid            TEXT    NOT NULL,
    path           TEXT    NOT NULL,
    ntfs_mask      INTEGER NOT NULL,
    share_mask     INTEGER,
    effective_mask INTEGER NOT NULL,
    explanation    TEXT    NOT NULL DEFAULT '[]'
);
