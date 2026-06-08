// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Low-Level-LDAP-Operationen gegen Active Directory.
//! Low-level LDAP operations against Active Directory.
//!
//!
//! Encapsulates all ldap3 calls. No domain logic — only connection,
//! authentication, and raw search results.

use std::future::Future;
use std::time::Duration;

use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{Ldap, LdapConnAsync, Scope, SearchEntry};
use tracing::{debug, warn};

///
/// Default page size for AD paged search. 1000 matches the AD default
/// `MaxPageSize` and balances round-trip count against server load.
const DEFAULT_PAGE_SIZE: i32 = 1000;

/// (`LDAP_MATCHING_RULE_IN_CHAIN`).
/// OID for AD's `LDAP_MATCHING_RULE_IN_CHAIN` extended matching rule —
/// resolves group transitivity server-side.
pub const LDAP_MATCHING_RULE_IN_CHAIN: &str = "1.2.840.113556.1.4.1941";

use adpa_core::error::CoreError;

use crate::config::LdapConfig;

///
/// Wraps an LDAP operation in `tokio::time::timeout`. Closes review finding 5:
/// `LdapConfig::timeout_secs` was configurable but never actually enforced —
/// an unreachable DC could block the analysis indefinitely.
pub async fn with_timeout<F, T>(operation: &str, timeout: Duration, fut: F) -> Result<T, CoreError>
where
    F: Future<Output = Result<T, CoreError>>,
{
    match tokio::time::timeout(timeout, fut).await {
        Ok(inner) => inner,
        Err(_) => Err(CoreError::LdapQuery(format!(
            "LDAP operation '{operation}' timed out after {}s",
            timeout.as_secs()
        ))),
    }
}

/// Convenience: build a `Duration` for the timeout wrappers from the
/// seconds field on `LdapConfig`.
pub fn ldap_timeout(config: &LdapConfig) -> Duration {
    Duration::from_secs(config.timeout_secs)
}
use crate::sid_util::sid_str_to_ldap_filter;

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

/// Attributes read during group searches.
const MEMBERSHIP_ATTRS: &[&str] = &[
    "objectSid",
    "sAMAccountName",
    "memberOf",
    "distinguishedName",
];

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

    /// Returns the first string value of an attribute.
    pub fn first_attr(&self, name: &str) -> Option<&str> {
        self.attrs.get(name)?.first().map(String::as_str)
    }

    /// Returns the binary data of an attribute (e.g. objectSid).
    pub fn first_bin_attr(&self, name: &str) -> Option<&[u8]> {
        self.bin_attrs.get(name)?.first().map(Vec::as_slice)
    }

    /// Returns all values of a string attribute (e.g. memberOf).
    pub fn all_attr(&self, name: &str) -> &[String] {
        self.attrs.get(name).map(Vec::as_slice).unwrap_or(&[])
    }
}

/// Establishes an authenticated LDAP connection.
///
/// TLS-Modus / TLS mode:
///   `Ldaps` (default): ldaps://server:636 — TLS from the first byte, recommended.
///   `Insecure`: ldap://server:389 — password in plaintext, test environments only.
pub async fn connect(config: &LdapConfig) -> Result<Ldap, CoreError> {
    let url = config.url();
    debug!(url, tls_mode = ?config.tls_mode, "LDAP connecting");

    // Wrap TCP/TLS setup — otherwise an unreachable DC can hang here
    // indefinitely (review finding 5).
    let url_owned = url.clone();
    let (conn, mut ldap) = with_timeout("connect", ldap_timeout(config), async move {
        LdapConnAsync::new(&url_owned)
            .await
            .map_err(|e| CoreError::AdConnection(format!("LDAP connection failed: {e}")))
    })
    .await?;

    // Drive connection task in background
    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            warn!("LDAP connection task error: {e}");
        }
    });

    // Wrap the bind as well — wrong credentials usually don't hang, but a
    // server with a slow LSA reply can.
    with_timeout("bind", ldap_timeout(config), async {
        ldap.simple_bind(&config.bind_dn, &config.bind_password)
            .await
            .map_err(|e| CoreError::AdConnection(format!("LDAP bind failed: {e}")))?
            .success()
            .map_err(|e| CoreError::AdConnection(format!("LDAP bind rejected: {e}")))?;
        Ok(())
    })
    .await?;

    debug!("LDAP connected as: {}", config.bind_dn);
    Ok(ldap)
}

/// Searches for an AD object by its SID.
pub async fn search_by_sid(
    ldap: &mut Ldap,
    base_dn: &str,
    sid_str: &str,
) -> Result<Option<RawEntry>, CoreError> {
    let escaped = sid_str_to_ldap_filter(sid_str)?;
    let filter = format!("(objectSid={escaped})");

    debug!("LDAP search: base={base_dn} filter={filter}");

    let (rs, _res) = ldap
        .search(base_dn, Scope::Subtree, &filter, IDENTITY_ATTRS)
        .await
        .map_err(|e| CoreError::LdapQuery(format!("search failed: {e}")))?
        .success()
        .map_err(|e| CoreError::LdapQuery(format!("search result error: {e}")))?;

    Ok(rs.into_iter().next().map(RawEntry::from_search_entry))
}

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

    debug!("LDAP search by DN: {dn}");

    let (rs, _res) = ldap
        .search(base_dn, Scope::Subtree, &filter, MEMBERSHIP_ATTRS)
        .await
        .map_err(|e| CoreError::LdapQuery(format!("DN search failed: {e}")))?
        .success()
        .map_err(|e| CoreError::LdapQuery(format!("DN search result error: {e}")))?;

    Ok(rs.into_iter().next().map(RawEntry::from_search_entry))
}

/// Searches for group members by sAMAccountName. Returns only the first hit —
/// historic API, complemented by `search_all_by_samaccount` for the
/// uniqueness check (review finding 3).
pub async fn search_by_samaccount(
    ldap: &mut Ldap,
    base_dn: &str,
    sam: &str,
) -> Result<Option<RawEntry>, CoreError> {
    let all = search_all_by_samaccount(ldap, base_dn, sam).await?;
    Ok(all.into_iter().next())
}

/// Raises a uniqueness error — closes review finding 3 (`DOMAIN\user`
/// Searches for **all** AD entries with a given sAMAccountName and returns
/// them as a vector. Callers can detect multi-match and surface a uniqueness
/// error — closes review finding 3 (`DOMAIN\user` was accepted but the
/// domain part was ignored, and multi-match was silently resolved via
/// `next()`).
pub async fn search_all_by_samaccount(
    ldap: &mut Ldap,
    base_dn: &str,
    sam: &str,
) -> Result<Vec<RawEntry>, CoreError> {
    let filter = format!("(sAMAccountName={})", escape_filter_value(sam));

    debug!("LDAP search by sAMAccountName: {sam}");

    let (rs, _res) = ldap
        .search(base_dn, Scope::Subtree, &filter, IDENTITY_ATTRS)
        .await
        .map_err(|e| CoreError::LdapQuery(format!("sAM search failed: {e}")))?
        .success()
        .map_err(|e| CoreError::LdapQuery(format!("sAM search result error: {e}")))?;

    Ok(rs.into_iter().map(RawEntry::from_search_entry).collect())
}

/// (review finding 3).
/// Searches for an AD object by its `userPrincipalName` (UPN, form
/// `user@domain.tld`). UPNs are unique forest-wide — prevents the
/// ambiguity `sAMAccountName` exhibits in multi-domain forests (review
/// finding 3).
pub async fn search_by_upn(
    ldap: &mut Ldap,
    base_dn: &str,
    upn: &str,
) -> Result<Option<RawEntry>, CoreError> {
    let filter = format!("(userPrincipalName={})", escape_filter_value(upn));

    debug!("LDAP search by UPN: {upn}");

    let (rs, _res) = ldap
        .search(base_dn, Scope::Subtree, &filter, IDENTITY_ATTRS)
        .await
        .map_err(|e| CoreError::LdapQuery(format!("UPN search failed: {e}")))?
        .success()
        .map_err(|e| CoreError::LdapQuery(format!("UPN search result error: {e}")))?;

    Ok(rs.into_iter().next().map(RawEntry::from_search_entry))
}

/// Searches users and groups by a partial name substring (max 50 results).
///
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

    debug!("LDAP name search: base={base_dn} query={query}");

    search_paged_with_limit(ldap, base_dn, &filter, IDENTITY_ATTRS, Some(50)).await
}

///
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

    debug!("LDAP transitive group search: base={base_dn} member={member_dn}");

    search_paged_with_limit(ldap, base_dn, &filter, MEMBERSHIP_ATTRS, None).await
}

///
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
        .map_err(|e| CoreError::LdapQuery(format!("paged search failed: {e}")))?;

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
                    "paged search stream error: {e}"
                )));
            }
        }
    }
    // finish() consumes the stream — still check the result.
    let result = stream.finish().await;
    result
        .success()
        .map_err(|e| CoreError::LdapQuery(format!("paged search final status: {e}")))?;
    Ok(entries)
}

/// Terminates the LDAP connection properly.
pub async fn disconnect(mut ldap: Ldap) {
    if let Err(e) = ldap.unbind().await {
        warn!("LDAP unbind error: {e}");
    }
}

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

/// Escapes special characters in DN values for LDAP filters.
fn escape_dn_for_filter(dn: &str) -> String {
    // In a filter, commas and equals don't need escaping, but parentheses do
    escape_filter_value(dn)
}
