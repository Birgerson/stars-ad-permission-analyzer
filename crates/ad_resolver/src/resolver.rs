//! LdapResolver — implementiert IdentityResolver über LDAP gegen Active Directory.
//! LdapResolver — implements IdentityResolver via LDAP against Active Directory.
//!
//! Fachliche Regeln die hier umgesetzt werden:
//! Domain rules implemented here:
//!
//! - SID ist die primäre technische Identität, nicht der Anzeigename.
//!   SID is the primary technical identity, not the display name.
//! - Deaktivierte Benutzer werden erkannt und markiert.
//!   Disabled users are detected and marked.
//! - Verwaiste SIDs (kein AD-Objekt gefunden) werden als Unknown markiert.
//!   Orphaned SIDs (no AD object found) are marked as Unknown.
//! - Transitive Gruppenmitgliedschaft wird serverseitig über
//!   `LDAP_MATCHING_RULE_IN_CHAIN` aufgelöst — damit umgehen wir das
//!   `memberOf`-Range-Retrieval (das AD bei > ~1500 Werten abschneidet)
//!   und vermeiden die N+1-Rekursion pro Hierarchieebene. Zyklen sind
//!   in dieser Form unmöglich.
//!   Transitive group membership is resolved server-side via
//!   `LDAP_MATCHING_RULE_IN_CHAIN`, which avoids `memberOf` range
//!   retrieval (AD truncates beyond ~1500 values) and the per-level
//!   N+1 recursion. Cycles cannot occur in this scheme.
//! - SID-zu-Identity-Auflösungen werden gecacht.
//!   SID-to-Identity resolutions are cached.
//! - Die primäre Gruppe eines Benutzers wird gesondert berücksichtigt,
//!   da sie über `primaryGroupID` (nicht `member`) modelliert ist.
//!   The primary group of a user is handled separately because it is
//!   modelled via `primaryGroupID` (not `member`).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use adpa_core::{
    error::CoreError,
    model::{GroupMembership, Identity, IdentityKind, Sid},
    traits::IdentityResolver,
};

use crate::{
    config::LdapConfig,
    ldap_client::{self, RawEntry},
    sid_util::bytes_to_sid_str,
};

/// AD-Benutzer userAccountControl-Bit für deaktivierte Konten.
/// AD userAccountControl bit for disabled accounts.
const UAC_ACCOUNT_DISABLE: u32 = 0x0002;

/// Implementiert IdentityResolver über LDAP mit In-Memory-Cache.
/// Implements IdentityResolver via LDAP with an in-memory cache.
pub struct LdapResolver {
    config: Arc<LdapConfig>,
    /// Cache: SID-String → Identity
    identity_cache: Arc<Mutex<HashMap<String, Identity>>>,
}

impl LdapResolver {
    /// Erstellt einen neuen LdapResolver mit der gegebenen Konfiguration.
    /// Creates a new LdapResolver with the given configuration.
    pub fn new(config: LdapConfig) -> Self {
        Self {
            config: Arc::new(config),
            identity_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Sucht einen Benutzer/Gruppe per sAMAccountName und gibt SID + Identity zurück.
    /// Looks up a user/group by sAMAccountName and returns SID + Identity.
    ///
    /// Unterstützt `DOMAIN\username` (Domäne wird ignoriert).
    /// Supports `DOMAIN\username` format (domain part is stripped).
    pub async fn lookup_by_samaccount(
        &self,
        user_input: &str,
    ) -> Result<Option<(Sid, Identity)>, CoreError> {
        let sam = match user_input.rfind('\\') {
            Some(pos) => &user_input[pos + 1..],
            None => user_input,
        };

        let mut ldap = ldap_client::connect(&self.config).await?;
        let result = ldap_client::search_by_samaccount(&mut ldap, &self.config.base_dn, sam).await;
        ldap_client::disconnect(ldap).await;

        match result? {
            None => Ok(None),
            Some(entry) => {
                let sid = extract_sid_from_entry(&entry).ok_or_else(|| {
                    CoreError::SidResolution(format!(
                        "Kein objectSid für sAMAccountName / No objectSid for sAMAccountName: {sam}"
                    ))
                })?;
                let identity = parse_identity_from_entry(&entry, &sid);
                self.identity_cache
                    .lock()
                    .await
                    .insert(sid.0.clone(), identity.clone());
                Ok(Some((sid, identity)))
            }
        }
    }

    /// Gibt die Anzahl gecachter Identitäten zurück (für Tests und Diagnose).
    /// Returns the number of cached identities (for tests and diagnostics).
    pub async fn cache_size(&self) -> usize {
        self.identity_cache.lock().await.len()
    }

    /// Löst eine Identität auf — erst aus Cache, dann per LDAP.
    /// Resolves an identity — first from cache, then via LDAP.
    async fn resolve_identity_internal(&self, sid: &Sid) -> Result<Identity, CoreError> {
        // Cache-Treffer prüfen
        // Check cache hit
        {
            let cache = self.identity_cache.lock().await;
            if let Some(identity) = cache.get(&sid.0) {
                debug!("Cache-Treffer / cache hit: {}", sid.0);
                return Ok(identity.clone());
            }
        }

        let mut ldap = ldap_client::connect(&self.config).await?;
        let result = ldap_client::search_by_sid(&mut ldap, &self.config.base_dn, &sid.0).await;
        ldap_client::disconnect(ldap).await;

        let identity = match result? {
            Some(entry) => parse_identity_from_entry(&entry, sid),
            None => {
                // Verwaiste SID — kein AD-Objekt gefunden
                // Orphaned SID — no AD object found
                warn!("Verwaiste SID / Orphaned SID: {}", sid.0);
                Identity {
                    sid: sid.clone(),
                    name: None,
                    domain: None,
                    kind: IdentityKind::Orphaned,
                    disabled: false,
                    user_principal_name: None,
                }
            }
        };

        // In Cache legen
        // Store in cache
        self.identity_cache
            .lock()
            .await
            .insert(sid.0.clone(), identity.clone());

        Ok(identity)
    }

    /// Löst alle Gruppenmitgliedschaften transitiv auf — serverseitig via
    /// `LDAP_MATCHING_RULE_IN_CHAIN`, ergänzt um die Primärgruppe (die nicht
    /// über `member` verlinkt ist) und deren transitive Eltern.
    ///
    /// Resolves all group memberships transitively — server-side via
    /// `LDAP_MATCHING_RULE_IN_CHAIN`, plus the primary group (which is not
    /// linked via `member`) and its transitive parents.
    async fn resolve_memberships_internal(
        &self,
        sid: &Sid,
    ) -> Result<Vec<GroupMembership>, CoreError> {
        let mut ldap = ldap_client::connect(&self.config).await?;

        let mut memberships = Vec::new();
        let mut visited: HashSet<String> = HashSet::new();
        visited.insert(sid.0.clone());

        // 1) Den Benutzer-/Gruppen-Eintrag laden — wir brauchen den DN für
        //    die transitive Suche und ggf. die primaryGroupID.
        // 1) Load the principal entry — we need the DN for the transitive
        //    search and possibly the primaryGroupID.
        let entry = ldap_client::search_by_sid(&mut ldap, &self.config.base_dn, &sid.0).await?;

        if let Some(entry) = entry {
            // 2) Primärgruppe verarbeiten. Sie ist über primaryGroupID an
            //    den Benutzer gebunden und taucht NICHT in `member`-basierten
            //    Suchen auf — wir müssen sie separat auflösen.
            // 2) Handle primary group. It is bound to the user via
            //    primaryGroupID and does NOT show up in `member`-based
            //    searches — resolve it separately.
            let primary_group_sid =
                resolve_primary_group(&entry, &self.config.base_dn, &mut ldap).await;
            if let Some(ref pg_sid) = primary_group_sid {
                if visited.insert(pg_sid.0.clone()) {
                    memberships.push(GroupMembership {
                        member_sid: sid.clone(),
                        group_sid: pg_sid.clone(),
                        direct: true,
                        // Primärgruppe wird per primaryGroupID referenziert,
                        // ohne dass wir hier ihren Namen aus dem Entry haben.
                        // Der Worker löst das später via LSA nach.
                        // Primary group is referenced via primaryGroupID
                        // without giving us its name from the entry here.
                        // The worker resolves it later via LSA.
                        group_name: None,
                    });
                }
            }

            // 3) Transitive Mitgliedschaft serverseitig auflösen. Liefert in
            //    einem Roundtrip ALLE Gruppen, in denen der Principal über
            //    geschachtelte `member`-Ketten enthalten ist. Damit entfällt
            //    der Range-Retrieval-Trick auf `memberOf` und der N+1-Lookup.
            // 3) Resolve transitive membership server-side. One round-trip
            //    returns ALL groups in which the principal is nested via
            //    `member` chains. Avoids `memberOf` range-retrieval and N+1.
            let transitive_groups = ldap_client::search_transitive_groups_for_member(
                &mut ldap,
                &self.config.base_dn,
                &entry.dn,
            )
            .await?;

            // 4) Direkte vs. transitive Mitgliedschaft markieren. Eine
            //    Gruppe ist direkt, wenn ihr DN in der `memberOf`-Liste des
            //    Principal steht; ansonsten transitiv. memberOf kann bei
            //    sehr großen Tokens trunkiert sein — die Liste der
            //    Mitgliedschaften kommt aus der Transitivsuche; memberOf
            //    dient hier nur als „direkt"-Marker.
            // 4) Mark direct vs. transitive. A group is direct if its DN
            //    is in the principal's `memberOf` list; otherwise
            //    transitive. `memberOf` may be truncated on very large
            //    tokens — the membership *list* comes from the transitive
            //    search; `memberOf` is used here only as a "direct" marker.
            let direct_dns: HashSet<String> = entry
                .all_attr("memberOf")
                .iter()
                .map(|dn| dn.to_ascii_lowercase())
                .collect();

            for group_entry in &transitive_groups {
                let group_sid = match extract_sid_from_entry(group_entry) {
                    Some(s) => s,
                    None => continue,
                };
                if !visited.insert(group_sid.0.clone()) {
                    continue;
                }
                let direct = direct_dns.contains(&group_entry.dn.to_ascii_lowercase());
                // sAMAccountName ist der NetBIOS-Name der Gruppe (z. B.
                // "Domain Admins"). Fallback auf cn, weil ältere Gruppen
                // ohne sAMAccountName möglich sind.
                // sAMAccountName is the group's NetBIOS name (e.g.
                // "Domain Admins"). Falls back to cn since older groups
                // may not carry sAMAccountName.
                let group_name = group_entry
                    .first_attr("sAMAccountName")
                    .or_else(|| group_entry.first_attr("cn"))
                    .map(str::to_owned);
                memberships.push(GroupMembership {
                    member_sid: sid.clone(),
                    group_sid,
                    direct,
                    group_name,
                });
            }

            // 5) Eltern der Primärgruppe transitiv ergänzen, da die
            //    LDAP_MATCHING_RULE_IN_CHAIN-Suche oben den Principal —
            //    nicht die Primärgruppe — als Member behandelt.
            // 5) Add the primary group's transitive parents, since the
            //    LDAP_MATCHING_RULE_IN_CHAIN search above starts at the
            //    principal — not at the primary group.
            if let Some(ref pg_sid) = primary_group_sid {
                if let Ok(Some(pg_entry)) =
                    ldap_client::search_by_sid(&mut ldap, &self.config.base_dn, &pg_sid.0).await
                {
                    let pg_parents = ldap_client::search_transitive_groups_for_member(
                        &mut ldap,
                        &self.config.base_dn,
                        &pg_entry.dn,
                    )
                    .await?;
                    for parent_entry in &pg_parents {
                        if let Some(parent_sid) = extract_sid_from_entry(parent_entry) {
                            if visited.insert(parent_sid.0.clone()) {
                                let group_name = parent_entry
                                    .first_attr("sAMAccountName")
                                    .or_else(|| parent_entry.first_attr("cn"))
                                    .map(str::to_owned);
                                memberships.push(GroupMembership {
                                    member_sid: sid.clone(),
                                    group_sid: parent_sid,
                                    direct: false,
                                    group_name,
                                });
                            }
                        }
                    }
                }
            }
        }

        ldap_client::disconnect(ldap).await;
        Ok(memberships)
    }
}

#[async_trait]
impl IdentityResolver for LdapResolver {
    async fn resolve_identity(&self, sid: &Sid) -> Result<Identity, CoreError> {
        self.resolve_identity_internal(sid).await
    }

    async fn resolve_group_memberships(
        &self,
        sid: &Sid,
    ) -> Result<Vec<GroupMembership>, CoreError> {
        self.resolve_memberships_internal(sid).await
    }
}

// --- Hilfsfunktionen / Helper functions ---

/// Parst eine Identity aus einem LDAP-Eintrag.
/// Parses an Identity from an LDAP entry.
fn parse_identity_from_entry(entry: &RawEntry, sid: &Sid) -> Identity {
    let name = entry
        .first_attr("sAMAccountName")
        .or_else(|| entry.first_attr("cn"))
        .map(String::from);

    let domain = dn_to_domain(&entry.dn);

    let user_principal_name = entry
        .first_attr("userPrincipalName")
        .filter(|s| !s.is_empty())
        .map(String::from);

    let object_classes: Vec<&str> = entry
        .attrs
        .get("objectClass")
        .map(|v| v.iter().map(String::as_str).collect())
        .unwrap_or_default();

    let kind = classify_identity(&object_classes);

    let disabled = entry
        .first_attr("userAccountControl")
        .and_then(|v| v.parse::<u32>().ok())
        .map(|uac| uac & UAC_ACCOUNT_DISABLE != 0)
        .unwrap_or(false);

    Identity {
        sid: sid.clone(),
        name,
        domain,
        kind,
        disabled,
        user_principal_name,
    }
}

/// Bestimmt den IdentityKind aus den objectClass-Werten.
/// Determines the IdentityKind from objectClass values.
fn classify_identity(object_classes: &[&str]) -> IdentityKind {
    // Reihenfolge ist wichtig: Computer hat auch "user" in objectClass
    // Order matters: computers also have "user" in objectClass
    if object_classes.contains(&"computer") {
        IdentityKind::Computer
    } else if object_classes.contains(&"group") {
        IdentityKind::Group
    } else if object_classes.contains(&"user") {
        IdentityKind::User
    } else {
        IdentityKind::Unknown
    }
}

/// Extrahiert die SID aus einem LDAP-Eintrag (binäres objectSid-Attribut).
/// Extracts the SID from an LDAP entry (binary objectSid attribute).
pub fn extract_sid_from_entry(entry: &RawEntry) -> Option<Sid> {
    let bytes = entry.first_bin_attr("objectSid")?;
    match bytes_to_sid_str(bytes) {
        Ok(sid_str) => Some(Sid(sid_str)),
        Err(e) => {
            warn!("SID-Konvertierung fehlgeschlagen / SID conversion failed: {e}");
            None
        }
    }
}

/// Extrahiert den Domänennamen aus einem Distinguished Name.
/// Extracts the domain name from a distinguished name.
///
/// "CN=User,CN=Users,DC=testdomain,DC=local" → Some("testdomain.local")
fn dn_to_domain(dn: &str) -> Option<String> {
    let dc_parts: Vec<&str> = dn
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            part.strip_prefix("DC=")
        })
        .collect();

    if dc_parts.is_empty() {
        None
    } else {
        Some(dc_parts.join("."))
    }
}

/// Löst die primäre Gruppe eines Benutzers auf (nicht in memberOf enthalten).
/// Resolves the primary group of a user (not included in memberOf).
///
/// Die primäre Gruppe ergibt sich aus: Domänen-SID + primaryGroupID als RID.
/// Primary group = domain SID + primaryGroupID as RID.
async fn resolve_primary_group(
    entry: &RawEntry,
    base_dn: &str,
    ldap: &mut ldap3::Ldap,
) -> Option<Sid> {
    let primary_group_id: u32 = entry
        .first_attr("primaryGroupID")
        .and_then(|v| v.parse().ok())?;

    // Domänen-SID aus der Benutzer-SID ableiten (alle Sub-Authorities außer dem letzten RID)
    // Derive domain SID from user SID (all sub-authorities except the last RID)
    let user_sid_bytes = entry.first_bin_attr("objectSid")?;
    let user_sid_str = bytes_to_sid_str(user_sid_bytes).ok()?;

    let mut parts: Vec<&str> = user_sid_str.split('-').collect();
    if parts.len() < 4 {
        return None;
    }
    // Letzten Teil (RID) durch primaryGroupID ersetzen
    // Replace last part (RID) with primaryGroupID
    *parts.last_mut()? = "";
    let domain_sid_prefix = parts[..parts.len() - 1].join("-");
    let primary_group_sid_str = format!("{domain_sid_prefix}-{primary_group_id}");

    // Validieren, ob diese Gruppe wirklich existiert
    // Validate that this group actually exists
    match ldap_client::search_by_sid(ldap, base_dn, &primary_group_sid_str).await {
        Ok(Some(_)) => Some(Sid(primary_group_sid_str)),
        Ok(None) => {
            warn!("Primärgruppe nicht gefunden / Primary group not found: {primary_group_sid_str}");
            None
        }
        Err(e) => {
            warn!("Primärgruppen-Suche fehlgeschlagen / Primary group search failed: {e}");
            None
        }
    }
}

// --- Integrationstests ---
// Diese Tests erfordern eine laufende TESTDOMAIN-Umgebung und sind standardmäßig
// mit #[ignore] markiert. Ausführung: cargo test -- --ignored
//
// --- Integration tests ---
// These tests require a running TESTDOMAIN environment and are marked #[ignore]
// by default. Run with: cargo test -- --ignored
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LdapConfig;

    fn test_config() -> Option<LdapConfig> {
        let server = std::env::var("DEVMS_TEST_LDAP_SERVER").ok()?;
        let base_dn = std::env::var("DEVMS_TEST_LDAP_BASE_DN").ok()?;
        let bind_dn = std::env::var("DEVMS_TEST_LDAP_BIND_DN").ok()?;
        let password = std::env::var("DEVMS_TEST_LDAP_PASSWORD").ok()?;
        // DEVMS_TEST_LDAP_INSECURE=1 allows plain LDAP for test environments without LDAPS
        let insecure = std::env::var("DEVMS_TEST_LDAP_INSECURE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if insecure {
            Some(LdapConfig::new_insecure(
                &server, &base_dn, &bind_dn, &password,
            ))
        } else {
            Some(LdapConfig::new(&server, &base_dn, &bind_dn, &password))
        }
    }

    #[tokio::test]
    #[ignore = "Erfordert laufende TESTDOMAIN-Umgebung / Requires running TESTDOMAIN environment"]
    async fn resolve_administrator_identity() {
        let Some(cfg) = test_config() else { return };
        let base_dn = cfg.base_dn.clone();
        let resolver = LdapResolver::new(cfg.clone());
        // Administrator-SID beginnt immer mit S-1-5-21-...-500
        // Administrator SID always ends with -500
        // Wir suchen zuerst per sAMAccountName um die SID zu bekommen
        // We first search by sAMAccountName to get the SID
        let mut ldap = ldap_client::connect(&cfg).await.unwrap();
        let entry = ldap_client::search_by_samaccount(&mut ldap, &base_dn, "Administrator")
            .await
            .unwrap()
            .expect("Administrator muss existieren / Administrator must exist");
        ldap_client::disconnect(ldap).await;

        let sid = extract_sid_from_entry(&entry)
            .expect("Administrator muss SID haben / Administrator must have SID");
        let identity = resolver.resolve_identity(&sid).await.unwrap();

        assert_eq!(identity.kind, IdentityKind::User);
        assert!(!identity.disabled);
        assert_eq!(identity.name.as_deref(), Some("Administrator"));
    }

    #[tokio::test]
    #[ignore = "Erfordert laufende TESTDOMAIN-Umgebung / Requires running TESTDOMAIN environment"]
    async fn resolve_group_memberships_max_mustermann() {
        let Some(cfg) = test_config() else { return };
        let base_dn = cfg.base_dn.clone();
        let resolver = LdapResolver::new(cfg.clone());

        let mut ldap = ldap_client::connect(&cfg).await.unwrap();
        let entry = ldap_client::search_by_samaccount(&mut ldap, &base_dn, "max.mustermann")
            .await
            .unwrap()
            .expect("max.mustermann muss existieren");
        ldap_client::disconnect(ldap).await;

        let sid = extract_sid_from_entry(&entry).unwrap();
        let memberships = resolver.resolve_group_memberships(&sid).await.unwrap();

        // max.mustermann ist in GRP_IT_Admins und GRP_Development (direkt)
        // und transitiv in GRP_FullAccess_FS und GRP_ShareAccess_SMB
        let group_names: Vec<String> = {
            let mut ldap2 = ldap_client::connect(&cfg).await.unwrap();
            let mut names = Vec::new();
            for m in &memberships {
                if let Ok(Some(e)) =
                    ldap_client::search_by_sid(&mut ldap2, &base_dn, &m.group_sid.0).await
                {
                    if let Some(n) = e.first_attr("sAMAccountName") {
                        names.push(n.to_string());
                    }
                }
            }
            ldap_client::disconnect(ldap2).await;
            names
        };

        // Basisprüfung: Mindestens Domain Users (Primärgruppe) muss aufgelöst werden.
        // Basic check: at least Domain Users (primary group) must be resolved.
        assert!(
            !group_names.is_empty(),
            "Mindestens eine Gruppe muss aufgelöst werden / At least one group must be resolved"
        );
        assert!(
            group_names.contains(&"Domain Users".to_string()),
            "Domain Users (Primärgruppe) muss immer enthalten sein / Domain Users (primary group) must always be present"
        );

        // Transitivitätsprüfung gegen die im Setup-Script
        // (scripts/test-env/02-setup-ad-objects.ps1) angelegte AD-Struktur:
        //   max.mustermann → GRP_IT_Admins   (direct)
        //   max.mustermann → GRP_Development (direct)
        //   GRP_IT_Admins  → GRP_FullAccess_FS    (nested)
        //   GRP_Development → GRP_ShareAccess_SMB (nested)
        //
        // Diese Asserts setzen voraus, dass Finding 8 wirkt — die transitive
        // Auflösung läuft jetzt serverseitig via LDAP_MATCHING_RULE_IN_CHAIN.
        // These asserts depend on Finding 8 — transitive resolution now runs
        // server-side via LDAP_MATCHING_RULE_IN_CHAIN.
        assert!(
            group_names.contains(&"GRP_IT_Admins".to_string()),
            "GRP_IT_Admins (direkt) fehlt — vorhandene Gruppen: {group_names:?}"
        );
        assert!(
            group_names.contains(&"GRP_Development".to_string()),
            "GRP_Development (direkt) fehlt — vorhandene Gruppen: {group_names:?}"
        );
        assert!(
            group_names.contains(&"GRP_FullAccess_FS".to_string()),
            "GRP_FullAccess_FS (transitiv) fehlt — vorhandene Gruppen: {group_names:?}"
        );
        assert!(
            group_names.contains(&"GRP_ShareAccess_SMB".to_string()),
            "GRP_ShareAccess_SMB (transitiv) fehlt — vorhandene Gruppen: {group_names:?}"
        );

        // Direkt-Markierung prüfen: GRP_IT_Admins und GRP_Development müssen
        // als direct=true geliefert werden, GRP_FullAccess_FS und
        // GRP_ShareAccess_SMB als direct=false.
        // Verify direct flag: GRP_IT_Admins and GRP_Development must be
        // direct=true, while GRP_FullAccess_FS and GRP_ShareAccess_SMB must
        // be direct=false.
        let mut direct_by_name: std::collections::HashMap<String, bool> =
            std::collections::HashMap::new();
        {
            let mut ldap3 = ldap_client::connect(&cfg).await.unwrap();
            for m in &memberships {
                if let Ok(Some(e)) =
                    ldap_client::search_by_sid(&mut ldap3, &base_dn, &m.group_sid.0).await
                {
                    if let Some(n) = e.first_attr("sAMAccountName") {
                        direct_by_name.insert(n.to_string(), m.direct);
                    }
                }
            }
            ldap_client::disconnect(ldap3).await;
        }
        assert_eq!(
            direct_by_name.get("GRP_IT_Admins"),
            Some(&true),
            "GRP_IT_Admins muss direct=true sein"
        );
        assert_eq!(
            direct_by_name.get("GRP_Development"),
            Some(&true),
            "GRP_Development muss direct=true sein"
        );
        assert_eq!(
            direct_by_name.get("GRP_FullAccess_FS"),
            Some(&false),
            "GRP_FullAccess_FS muss direct=false (transitiv) sein"
        );
        assert_eq!(
            direct_by_name.get("GRP_ShareAccess_SMB"),
            Some(&false),
            "GRP_ShareAccess_SMB muss direct=false (transitiv) sein"
        );
    }

    #[tokio::test]
    #[ignore = "Erfordert laufende TESTDOMAIN-Umgebung / Requires running TESTDOMAIN environment"]
    async fn orphaned_sid_returns_unknown() {
        let Some(cfg) = test_config() else { return };
        let resolver = LdapResolver::new(cfg);
        // SID die sicher nicht in der Testdomäne existiert (gültige u32-Sub-Authorities).
        // SID that definitely does not exist in the test domain (valid u32 sub-authorities).
        let fake_sid = Sid("S-1-5-21-1111111111-2222222222-3333333333-9999".to_string());
        let identity = resolver.resolve_identity(&fake_sid).await.unwrap();
        assert_eq!(identity.kind, IdentityKind::Orphaned);
    }

    #[tokio::test]
    #[ignore = "Erfordert laufende TESTDOMAIN-Umgebung / Requires running TESTDOMAIN environment"]
    async fn identity_is_cached_after_first_lookup() {
        let Some(cfg) = test_config() else { return };
        let base_dn = cfg.base_dn.clone();
        let resolver = LdapResolver::new(cfg.clone());

        let mut ldap = ldap_client::connect(&cfg).await.unwrap();
        let entry = ldap_client::search_by_samaccount(&mut ldap, &base_dn, "anna.schmidt")
            .await
            .unwrap()
            .unwrap();
        ldap_client::disconnect(ldap).await;

        let sid = extract_sid_from_entry(&entry).unwrap();

        assert_eq!(resolver.cache_size().await, 0);
        resolver.resolve_identity(&sid).await.unwrap();
        assert_eq!(resolver.cache_size().await, 1);
        // Zweiter Aufruf: muss aus Cache kommen, Cache-Größe bleibt 1
        // Second call: must come from cache, cache size stays 1
        resolver.resolve_identity(&sid).await.unwrap();
        assert_eq!(resolver.cache_size().await, 1);
    }

    #[test]
    fn dn_to_domain_correct() {
        let dn = "CN=max.mustermann,CN=Users,DC=testdomain,DC=local";
        assert_eq!(dn_to_domain(dn), Some("testdomain.local".to_string()));
    }

    #[test]
    fn dn_to_domain_single_dc() {
        let dn = "CN=obj,DC=corp";
        assert_eq!(dn_to_domain(dn), Some("corp".to_string()));
    }

    #[test]
    fn dn_to_domain_no_dc_returns_none() {
        let dn = "CN=obj,OU=users";
        assert_eq!(dn_to_domain(dn), None);
    }

    #[test]
    fn classify_user() {
        assert_eq!(
            classify_identity(&["top", "person", "user"]),
            IdentityKind::User
        );
    }

    #[test]
    fn classify_group() {
        assert_eq!(classify_identity(&["top", "group"]), IdentityKind::Group);
    }

    #[test]
    fn classify_computer_over_user() {
        // Computer-Objekte haben auch "user" in objectClass — Computer hat Vorrang
        // Computer objects also have "user" in objectClass — Computer takes precedence
        assert_eq!(
            classify_identity(&["top", "person", "user", "computer"]),
            IdentityKind::Computer
        );
    }
}
