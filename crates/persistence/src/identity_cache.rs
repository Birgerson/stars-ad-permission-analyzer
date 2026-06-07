// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! SQLite cache for identities and group memberships.

use adpa_core::{
    error::CoreError,
    model::{GroupMembership, Identity, IdentityKind, Sid},
};
use rusqlite::{params, Connection};

pub struct IdentityCache<'a> {
    conn: &'a Connection,
}

impl<'a> IdentityCache<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Stores or updates an identity in the cache.
    pub fn upsert(&self, identity: &Identity) -> Result<(), CoreError> {
        self.conn
            .execute(
                "INSERT INTO identities (sid, name, domain, kind, disabled)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(sid) DO UPDATE SET
                     name     = excluded.name,
                     domain   = excluded.domain,
                     kind     = excluded.kind,
                     disabled = excluded.disabled",
                params![
                    identity.sid.0,
                    identity.name,
                    identity.domain,
                    kind_to_str(&identity.kind),
                    identity.disabled as i32,
                ],
            )
            .map_err(|e| CoreError::Database(format!("Identity upsert failed: {e}")))?;
        Ok(())
    }

    /// Looks up an identity by SID.
    pub fn lookup(&self, sid: &Sid) -> Result<Option<Identity>, CoreError> {
        let result = self.conn.query_row(
            "SELECT sid, name, domain, kind, disabled FROM identities WHERE sid = ?1",
            params![sid.0],
            row_to_identity,
        );
        match result {
            Ok(identity) => Ok(Some(identity)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(CoreError::Database(format!("Identity lookup failed: {e}"))),
        }
    }

    /// Stores group memberships. Existing entries are skipped.
    pub fn upsert_memberships(&self, memberships: &[GroupMembership]) -> Result<(), CoreError> {
        for m in memberships {
            self.conn
                .execute(
                    "INSERT INTO group_memberships (member_sid, group_sid, direct)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(member_sid, group_sid) DO UPDATE SET
                         direct = excluded.direct",
                    params![m.member_sid.0, m.group_sid.0, m.direct as i32],
                )
                .map_err(|e| CoreError::Database(format!("Group membership upsert failed: {e}")))?;
        }
        Ok(())
    }

    /// Returns all stored group memberships for a SID.
    pub fn lookup_memberships(&self, sid: &Sid) -> Result<Vec<GroupMembership>, CoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT member_sid, group_sid, direct
                 FROM group_memberships
                 WHERE member_sid = ?1",
            )
            .map_err(|e| CoreError::Database(format!("Prepare failed: {e}")))?;

        let rows = stmt
            .query_map(params![sid.0], |row| {
                Ok(GroupMembership {
                    member_sid: Sid(row.get(0)?),
                    group_sid: Sid(row.get(1)?),
                    direct: row.get::<_, i32>(2)? != 0,
                    // Topologie ab.
                    // The cache deliberately does not store names — they
                    // come from the live resolver (LDAP/SAM) at the next
                    // evaluation; the cache only carries the membership
                    // topology.
                    group_name: None,
                    // Wie group_name auch: konkrete Mitgliedschafts-Pfade
                    // persistiert, weil sie pro Lauf neu rekonstruiert
                    // werden.
                    // Like group_name: concrete membership paths are a
                    // live-resolution concern and are not persisted here —
                    // they are reconstructed on every run.
                    path: None,
                })
            })
            .map_err(|e| CoreError::Database(format!("Group membership query failed: {e}")))?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| CoreError::Database(e.to_string()))?);
        }
        Ok(result)
    }
}

fn kind_to_str(kind: &IdentityKind) -> &'static str {
    match kind {
        IdentityKind::User => "User",
        IdentityKind::Group => "Group",
        IdentityKind::Computer => "Computer",
        IdentityKind::WellKnown => "WellKnown",
        IdentityKind::Orphaned => "Orphaned",
        IdentityKind::Unknown => "Unknown",
    }
}

fn kind_from_str(s: &str) -> IdentityKind {
    match s {
        "User" => IdentityKind::User,
        "Group" => IdentityKind::Group,
        "Computer" => IdentityKind::Computer,
        "WellKnown" => IdentityKind::WellKnown,
        "Orphaned" => IdentityKind::Orphaned,
        _ => IdentityKind::Unknown,
    }
}

fn row_to_identity(row: &rusqlite::Row<'_>) -> rusqlite::Result<Identity> {
    let kind_str: String = row.get(3)?;
    Ok(Identity {
        sid: Sid(row.get(0)?),
        name: row.get(1)?,
        domain: row.get(2)?,
        kind: kind_from_str(&kind_str),
        disabled: row.get::<_, i32>(4)? != 0,
        // UPN is not persisted in the identity cache (see scan_store).
        user_principal_name: None,
    })
}

#[cfg(test)]
mod tests {
    use adpa_core::model::{GroupMembership, Identity, IdentityKind, Sid};
    use rusqlite::Connection;

    use super::IdentityCache;
    use crate::migrations::run_migrations;

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        conn
    }

    fn make_identity(sid: &str, name: &str, kind: IdentityKind) -> Identity {
        Identity {
            sid: Sid(sid.to_owned()),
            name: Some(name.to_owned()),
            domain: Some("TESTDOMAIN".to_owned()),
            kind,
            disabled: false,
            user_principal_name: None,
        }
    }

    #[test]
    fn upsert_and_lookup_found() {
        let conn = setup();
        let cache = IdentityCache::new(&conn);
        let id = make_identity("S-1-5-21-1-2-3-1000", "MaxMustermann", IdentityKind::User);
        cache.upsert(&id).unwrap();
        let found = cache.lookup(&id.sid).unwrap().unwrap();
        assert_eq!(found.sid.0, "S-1-5-21-1-2-3-1000");
        assert_eq!(found.name.as_deref(), Some("MaxMustermann"));
        assert_eq!(found.domain.as_deref(), Some("TESTDOMAIN"));
        assert!(matches!(found.kind, IdentityKind::User));
        assert!(!found.disabled);
    }

    #[test]
    fn lookup_unknown_sid_returns_none() {
        let conn = setup();
        let cache = IdentityCache::new(&conn);
        let result = cache
            .lookup(&Sid("S-1-5-21-9-9-9-9999".to_owned()))
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn upsert_overwrites_existing_entry() {
        let conn = setup();
        let cache = IdentityCache::new(&conn);
        let id = make_identity("S-1-5-21-1-2-3-1000", "OldName", IdentityKind::Unknown);
        cache.upsert(&id).unwrap();
        let updated = Identity {
            name: Some("NewName".to_owned()),
            kind: IdentityKind::User,
            disabled: true,
            ..id.clone()
        };
        cache.upsert(&updated).unwrap();
        let found = cache.lookup(&id.sid).unwrap().unwrap();
        assert_eq!(found.name.as_deref(), Some("NewName"));
        assert!(matches!(found.kind, IdentityKind::User));
        assert!(found.disabled);
    }

    #[test]
    fn all_identity_kinds_roundtrip() {
        let conn = setup();
        let cache = IdentityCache::new(&conn);
        let kinds = [
            ("S-1-1", IdentityKind::User),
            ("S-1-2", IdentityKind::Group),
            ("S-1-3", IdentityKind::Computer),
            ("S-1-4", IdentityKind::WellKnown),
            ("S-1-5", IdentityKind::Orphaned),
            ("S-1-6", IdentityKind::Unknown),
        ];
        for (sid, kind) in &kinds {
            let id = Identity {
                sid: Sid((*sid).to_owned()),
                name: None,
                domain: None,
                kind: kind.clone(),
                disabled: false,
                user_principal_name: None,
            };
            cache.upsert(&id).unwrap();
            let found = cache.lookup(&id.sid).unwrap().unwrap();
            assert_eq!(found.kind, *kind);
        }
    }

    #[test]
    fn upsert_and_lookup_memberships() {
        let conn = setup();
        let cache = IdentityCache::new(&conn);
        let sid = Sid("S-1-5-21-1-2-3-1000".to_owned());
        let memberships = vec![
            GroupMembership {
                member_sid: sid.clone(),
                group_sid: Sid("S-1-5-21-1-2-3-500".to_owned()),
                direct: true,
                group_name: None,
                path: None,
            },
            GroupMembership {
                member_sid: sid.clone(),
                group_sid: Sid("S-1-5-21-1-2-3-501".to_owned()),
                direct: false,
                group_name: None,
                path: None,
            },
        ];
        cache.upsert_memberships(&memberships).unwrap();
        let found = cache.lookup_memberships(&sid).unwrap();
        assert_eq!(found.len(), 2);
        let direct: Vec<_> = found.iter().filter(|m| m.direct).collect();
        let transitive: Vec<_> = found.iter().filter(|m| !m.direct).collect();
        assert_eq!(direct.len(), 1);
        assert_eq!(transitive.len(), 1);
    }

    #[test]
    fn lookup_memberships_unknown_sid_returns_empty() {
        let conn = setup();
        let cache = IdentityCache::new(&conn);
        let result = cache
            .lookup_memberships(&Sid("S-1-5-21-9-9-9-9999".to_owned()))
            .unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn membership_upsert_updates_direct_flag() {
        let conn = setup();
        let cache = IdentityCache::new(&conn);
        let sid = Sid("S-1-5-21-1-2-3-1000".to_owned());
        let group = Sid("S-1-5-21-1-2-3-500".to_owned());
        cache
            .upsert_memberships(&[GroupMembership {
                member_sid: sid.clone(),
                group_sid: group.clone(),
                direct: false,
                group_name: None,
                path: None,
            }])
            .unwrap();
        cache
            .upsert_memberships(&[GroupMembership {
                member_sid: sid.clone(),
                group_sid: group.clone(),
                direct: true,
                group_name: None,
                path: None,
            }])
            .unwrap();
        let found = cache.lookup_memberships(&sid).unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].direct);
    }
}
