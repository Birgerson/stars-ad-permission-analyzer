//! Low-Level-LDAP-Operationen gegen Active Directory.
//! Low-level LDAP operations against Active Directory.
//!
//! Kapselt alle ldap3-Aufrufe. Keine fachliche Logik — nur Verbindung,
//! Authentifizierung und rohe Suchergebnisse.
//!
//! Encapsulates all ldap3 calls. No domain logic — only connection,
//! authentication, and raw search results.

use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{Ldap, LdapConnAsync, Scope, SearchEntry};
use tracing::{debug, warn};

/// Standard-Seitengröße für AD-Paged-Search.
/// 1000 entspricht dem AD-Default für `MaxPageSize` und ist ein guter
/// Kompromiss aus Round-Trip-Zahl und Server-Last.
///
/// Default page size for AD paged search. 1000 matches the AD default
/// `MaxPageSize` and balances round-trip count against server load.
const DEFAULT_PAGE_SIZE: i32 = 1000;

/// OID der AD-Matching-Rule „in chain" für transitive Gruppenauflösung
/// (`LDAP_MATCHING_RULE_IN_CHAIN`).
/// OID for AD's `LDAP_MATCHING_RULE_IN_CHAIN` extended matching rule —
/// resolves group transitivity server-side.
pub const LDAP_MATCHING_RULE_IN_CHAIN: &str = "1.2.840.113556.1.4.1941";

use adpa_core::error::CoreError;

use crate::config::LdapConfig;
use crate::sid_util::sid_str_to_ldap_filter;

/// Attribute, die bei Identitäts-Suchen gelesen werden.
///
/// `memberOf` ist hier enthalten, weil der Resolver es als „direkt"-Marker
/// für die Mitgliedschaftsauflösung verwendet (siehe ADR 0014). Auf großen
/// Tokens kann AD diese Liste range-trunkieren — die maßgebliche Liste
/// kommt jedoch aus der transitiven Suche; `memberOf` dient hier nur zur
/// Klassifikation direkt vs. transitiv.
///
/// Attributes read during identity searches. `memberOf` is included so the
/// resolver can use it as a "direct" marker for membership classification
/// (see ADR 0014). On large tokens AD may range-truncate this attribute —
/// the authoritative list comes from the transitive search; `memberOf` is
/// used here only to classify direct vs. transitive.
const IDENTITY_ATTRS: &[&str] = &[
    "objectSid",
    "sAMAccountName",
    "displayName",
    "cn",
    "objectClass",
    "userAccountControl",
    "userPrincipalName",
    "distinguishedName",
    "primaryGroupID",
    "memberOf",
];

/// Attribute, die bei Gruppen-Suchen gelesen werden.
/// Attributes read during group searches.
const MEMBERSHIP_ATTRS: &[&str] = &[
    "objectSid",
    "sAMAccountName",
    "memberOf",
    "distinguishedName",
];

/// Roher LDAP-Eintrag nach einer Suche.
/// Raw LDAP entry after a search.
#[derive(Debug)]
pub struct RawEntry {
    pub dn: String,
    pub attrs: std::collections::HashMap<String, Vec<String>>,
    pub bin_attrs: std::collections::HashMap<String, Vec<Vec<u8>>>,
}

impl RawEntry {
    fn from_search_entry(entry: ldap3::ResultEntry) -> Self {
        let se = SearchEntry::construct(entry);
        Self {
            dn: se.dn,
            attrs: se.attrs,
            bin_attrs: se.bin_attrs,
        }
    }

    /// Gibt den ersten String-Wert eines Attributs zurück.
    /// Returns the first string value of an attribute.
    pub fn first_attr(&self, name: &str) -> Option<&str> {
        self.attrs.get(name)?.first().map(String::as_str)
    }

    /// Gibt die Binärdaten eines Attributs zurück (z.B. objectSid).
    /// Returns the binary data of an attribute (e.g. objectSid).
    pub fn first_bin_attr(&self, name: &str) -> Option<&[u8]> {
        self.bin_attrs.get(name)?.first().map(Vec::as_slice)
    }

    /// Gibt alle Werte eines String-Attributs zurück (z.B. memberOf).
    /// Returns all values of a string attribute (e.g. memberOf).
    pub fn all_attr(&self, name: &str) -> &[String] {
        self.attrs.get(name).map(Vec::as_slice).unwrap_or(&[])
    }
}

/// Baut eine authentifizierte LDAP-Verbindung auf.
/// Establishes an authenticated LDAP connection.
///
/// TLS-Modus / TLS mode:
/// - `Ldaps` (Standard): ldaps://server:636 — TLS ab dem ersten Byte, empfohlen.
///   `Ldaps` (default): ldaps://server:636 — TLS from the first byte, recommended.
/// - `Insecure`: ldap://server:389 — Passwort im Klartext, nur für Testumgebungen.
///   `Insecure`: ldap://server:389 — password in plaintext, test environments only.
pub async fn connect(config: &LdapConfig) -> Result<Ldap, CoreError> {
    let url = config.url();
    debug!(url, tls_mode = ?config.tls_mode, "LDAP verbinden / connecting");

    let (conn, mut ldap) = LdapConnAsync::new(&url).await.map_err(|e| {
        CoreError::AdConnection(format!(
            "LDAP-Verbindung fehlgeschlagen / connection failed ({url}): {e}"
        ))
    })?;

    // Verbindungs-Task im Hintergrund treiben
    // Drive connection task in background
    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            warn!("LDAP connection task error: {e}");
        }
    });

    ldap.simple_bind(&config.bind_dn, &config.bind_password)
        .await
        .map_err(|e| {
            CoreError::AdConnection(format!("LDAP-Bind fehlgeschlagen / bind failed: {e}"))
        })?
        .success()
        .map_err(|e| {
            CoreError::AdConnection(format!("LDAP-Bind abgelehnt / bind rejected: {e}"))
        })?;

    debug!("LDAP verbunden / connected as: {}", config.bind_dn);
    Ok(ldap)
}

/// Sucht ein AD-Objekt anhand seiner SID.
/// Searches for an AD object by its SID.
pub async fn search_by_sid(
    ldap: &mut Ldap,
    base_dn: &str,
    sid_str: &str,
) -> Result<Option<RawEntry>, CoreError> {
    let escaped = sid_str_to_ldap_filter(sid_str)?;
    let filter = format!("(objectSid={escaped})");

    debug!("LDAP-Suche / search: base={base_dn} filter={filter}");

    let (rs, _res) = ldap
        .search(base_dn, Scope::Subtree, &filter, IDENTITY_ATTRS)
        .await
        .map_err(|e| CoreError::LdapQuery(format!("Suche fehlgeschlagen / search failed: {e}")))?
        .success()
        .map_err(|e| {
            CoreError::LdapQuery(format!("Suchergebnis-Fehler / search result error: {e}"))
        })?;

    Ok(rs.into_iter().next().map(RawEntry::from_search_entry))
}

/// Sucht ein AD-Objekt anhand seines Distinguished Name.
/// Searches for an AD object by its distinguished name.
pub async fn search_by_dn(
    ldap: &mut Ldap,
    base_dn: &str,
    dn: &str,
) -> Result<Option<RawEntry>, CoreError> {
    // DN-Sonderzeichen escapen
    // Escape special DN characters
    let escaped_dn = escape_dn_for_filter(dn);
    let filter = format!("(distinguishedName={escaped_dn})");

    debug!("LDAP-Suche nach DN / search by DN: {dn}");

    let (rs, _res) = ldap
        .search(base_dn, Scope::Subtree, &filter, MEMBERSHIP_ATTRS)
        .await
        .map_err(|e| {
            CoreError::LdapQuery(format!("DN-Suche fehlgeschlagen / DN search failed: {e}"))
        })?
        .success()
        .map_err(|e| {
            CoreError::LdapQuery(format!(
                "DN-Suchergebnis-Fehler / DN search result error: {e}"
            ))
        })?;

    Ok(rs.into_iter().next().map(RawEntry::from_search_entry))
}

/// Sucht Gruppenmitglieder anhand des sAMAccountName.
/// Searches for group members by sAMAccountName.
pub async fn search_by_samaccount(
    ldap: &mut Ldap,
    base_dn: &str,
    sam: &str,
) -> Result<Option<RawEntry>, CoreError> {
    let filter = format!("(sAMAccountName={})", escape_filter_value(sam));

    debug!("LDAP-Suche nach sAMAccountName / search by sAMAccountName: {sam}");

    let (rs, _res) = ldap
        .search(base_dn, Scope::Subtree, &filter, IDENTITY_ATTRS)
        .await
        .map_err(|e| {
            CoreError::LdapQuery(format!("sAM-Suche fehlgeschlagen / sAM search failed: {e}"))
        })?
        .success()
        .map_err(|e| {
            CoreError::LdapQuery(format!(
                "sAM-Suchergebnis-Fehler / sAM search result error: {e}"
            ))
        })?;

    Ok(rs.into_iter().next().map(RawEntry::from_search_entry))
}

/// Sucht Benutzer und Gruppen anhand eines Teilstring-Suchbegriffs (max. 50 Treffer).
/// Searches users and groups by a partial name substring (max 50 results).
///
/// Durchsucht sAMAccountName, displayName und cn. Nutzt Paged Search, damit
/// auch in großen Verzeichnissen keine Serverseitige Begrenzung
/// (`MaxPageSize`, Standard 1000) das Ergebnis stillschweigend abschneidet.
/// Die Client-Begrenzung auf 50 bleibt erhalten — sobald 50 Treffer
/// vorliegen, wird die Suche abgebrochen.
///
/// Searches sAMAccountName, displayName, and cn. Uses paged search so that
/// the server-side `MaxPageSize` (default 1000) cannot silently truncate
/// results in large directories. The client-side cap of 50 stays —
/// the search aborts once 50 hits are collected.
pub async fn search_by_query(
    ldap: &mut Ldap,
    base_dn: &str,
    query: &str,
) -> Result<Vec<RawEntry>, CoreError> {
    let escaped = escape_filter_value(query);
    // Users: objectCategory=person, Groups: objectClass=group
    // Wildcards (*) added by us are safe — user input is escaped via escape_filter_value
    let filter = format!(
        "(&(|(objectCategory=person)(objectClass=group))\
         (|(sAMAccountName=*{escaped}*)(displayName=*{escaped}*)(cn=*{escaped}*)))"
    );

    debug!("LDAP-Namenssuche / name search: base={base_dn} query={query}");

    search_paged_with_limit(ldap, base_dn, &filter, IDENTITY_ATTRS, Some(50)).await
}

/// Sucht transitiv alle Gruppen, in denen `member_dn` (direkt oder über
/// verschachtelte Gruppen) Mitglied ist. Nutzt AD-spezifisches
/// `LDAP_MATCHING_RULE_IN_CHAIN` (OID `1.2.840.113556.1.4.1941`) — der
/// Domain Controller löst die Transitivität in einem einzigen Roundtrip
/// auf, statt dass der Client `memberOf` rekursiv nachfragen muss. Damit
/// entfällt das Range-Retrieval-Problem (mehr als ~1500 `memberOf`-Werte
/// werden vom AD-Server abgeschnitten) und der N+1-Lookup pro Hierarchieebene.
///
/// Wichtig: Die Primärgruppe (`primaryGroupID`) ist nicht über
/// `member`-Beziehungen modelliert und muss vom Aufrufer separat behandelt
/// werden.
///
/// Transitively finds all groups in which `member_dn` is a member (directly
/// or through nested groups). Uses the AD-specific
/// `LDAP_MATCHING_RULE_IN_CHAIN` (OID `1.2.840.113556.1.4.1941`) — the DC
/// resolves transitivity in a single round-trip instead of the client
/// recursively walking `memberOf`. This avoids both range retrieval (where
/// AD truncates `memberOf` beyond ~1500 values) and the per-level N+1 lookup.
///
/// Note: the primary group (`primaryGroupID`) is not modelled via `member`
/// and must be handled separately by the caller.
pub async fn search_transitive_groups_for_member(
    ldap: &mut Ldap,
    base_dn: &str,
    member_dn: &str,
) -> Result<Vec<RawEntry>, CoreError> {
    let escaped = escape_filter_value(member_dn);
    let filter = format!("(&(objectClass=group)(member:{LDAP_MATCHING_RULE_IN_CHAIN}:={escaped}))");

    debug!("LDAP-Transitivsuche / transitive group search: base={base_dn} member={member_dn}");

    search_paged_with_limit(ldap, base_dn, &filter, MEMBERSHIP_ATTRS, None).await
}

/// Paged-Search-Wrapper: führt die LDAP-Suche mit dem Paged-Results-Control
/// aus, damit Ergebnisse > `MaxPageSize` nicht stillschweigend
/// abgeschnitten werden. Optionales `client_limit` bricht ab, sobald die
/// gewünschte Anzahl Treffer erreicht ist — der Server wird informiert
/// (Cookie wird verworfen).
///
/// Paged-search wrapper: runs the LDAP search with the paged-results
/// control so that results larger than `MaxPageSize` are not silently
/// truncated. An optional `client_limit` stops collection once enough
/// entries are gathered.
async fn search_paged_with_limit(
    ldap: &mut Ldap,
    base_dn: &str,
    filter: &str,
    attrs: &[&str],
    client_limit: Option<usize>,
) -> Result<Vec<RawEntry>, CoreError> {
    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(DEFAULT_PAGE_SIZE)),
    ];

    let mut stream = ldap
        .streaming_search_with(adapters, base_dn, Scope::Subtree, filter, attrs.to_vec())
        .await
        .map_err(|e| {
            CoreError::LdapQuery(format!(
                "Paged-Suche fehlgeschlagen / paged search failed: {e}"
            ))
        })?;

    let mut entries = Vec::new();
    loop {
        match stream.next().await {
            Ok(Some(entry)) => {
                entries.push(RawEntry::from_search_entry(entry));
                if let Some(limit) = client_limit {
                    if entries.len() >= limit {
                        break;
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                let _ = stream.finish().await;
                return Err(CoreError::LdapQuery(format!(
                    "Paged-Suche-Fehler / paged search stream error: {e}"
                )));
            }
        }
    }
    // finish() consumes the stream — Ergebnis trotzdem prüfen.
    // finish() consumes the stream — still check the result.
    let result = stream.finish().await;
    result.success().map_err(|e| {
        CoreError::LdapQuery(format!(
            "Paged-Suche-Endstatus / paged search final status: {e}"
        ))
    })?;
    Ok(entries)
}

/// Trennt die LDAP-Verbindung ordnungsgemäß.
/// Terminates the LDAP connection properly.
pub async fn disconnect(mut ldap: Ldap) {
    if let Err(e) = ldap.unbind().await {
        warn!("LDAP unbind error: {e}");
    }
}

/// Escaped Sonderzeichen in LDAP-Filterwerten gemäß RFC 4515.
/// Escapes special characters in LDAP filter values according to RFC 4515.
fn escape_filter_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            c => out.push(c),
        }
    }
    out
}

/// Escaped Sonderzeichen in DN-Werten für LDAP-Filter.
/// Escapes special characters in DN values for LDAP filters.
fn escape_dn_for_filter(dn: &str) -> String {
    // Im Filter müssen Komma und Gleich nicht escaped werden, aber Klammern schon
    // In a filter, commas and equals don't need escaping, but parentheses do
    escape_filter_value(dn)
}
