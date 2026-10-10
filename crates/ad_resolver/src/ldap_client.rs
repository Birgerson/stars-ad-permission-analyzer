// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Low-level LDAP operations against Active Directory.
//!
//! Encapsulates all ldap3 calls. No domain logic — only connection,
//! authentication, and raw search results.

use std::future::Future;
use std::time::Duration;

use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{Ldap, LdapConnAsync, Scope, SearchEntry};
use tracing::{debug, warn};
use validation::ldap::escape_filter_value;

///
/// Default page size for AD paged search. 1000 matches the AD default
/// `MaxPageSize` and balances round-trip count against server load.
const DEFAULT_PAGE_SIZE: i32 = 1000;

/// (`LDAP_MATCHING_RULE_IN_CHAIN`).
/// OID for AD's `LDAP_MATCHING_RULE_IN_CHAIN` extended matching rule —
/// resolves group transitivity server-side.
pub const LDAP_MATCHING_RULE_IN_CHAIN: &str = "1.2.840.113556.1.4.1941";

use adpa_core::error::CoreError;

use crate::config::{LdapConfig, TlsMode};

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
    // Group scope bits (0x2 global, 0x4 domain-local, 0x8 universal; sign bit
    // = security group). The members view uses the universal bit to warn that
    // a domain bind cannot see cross-domain members (ADR 0055 / finding F2).
    "groupType",
    // Binary, multi-valued: historical SIDs from a domain/forest migration.
    // The values are parsed and evaluated into the token (ADR 0056); the
    // count stays the authoritative total so an unparseable value remains
    // visible as "present, not evaluated". May be unreadable for a
    // least-privilege bind, in which case count and values are empty
    // (markers just stay silent — no false positive).
    "sIDHistory",
];

/// Attributes read during group searches.
const MEMBERSHIP_ATTRS: &[&str] = &[
    "objectSid",
    "sAMAccountName",
    "memberOf",
    "distinguishedName",
    // Binary, multi-valued: the group's own historical SIDs. The PAC
    // includes the history SIDs of the token groups, so these are parsed
    // and evaluated into the token like the user's (ADR 0059).
    "sIDHistory",
];

/// Attributes read from `trustedDomain` objects for the read-only trust
/// inventory (L4). All are ordinary directory attributes — reading them
/// changes nothing.
const TRUST_ATTRS: &[&str] = &[
    "trustPartner",
    "flatName",
    "trustDirection",
    "trustAttributes",
    "trustType",
    "securityIdentifier",
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

    /// Returns the binary data of an attribute (e.g. objectSid), whichever
    /// map the LDAP layer put it in.
    ///
    /// ldap3 stores a value whose bytes happen to be valid UTF-8 in `attrs`,
    /// not `bin_attrs` — and every builtin SID (`S-1-5-32-*`, e.g.
    /// BUILTIN\Users) consists only of bytes below 0x80. Reading only
    /// `bin_attrs` therefore lost those SIDs, and with them the groups, from
    /// every LDAP result; the same could hit any SID whose bytes form valid
    /// UTF-8 by chance. Found in the lab through the ADR 0066 gap report.
    pub fn first_bin_attr(&self, name: &str) -> Option<&[u8]> {
        self.bin_attrs
            .get(name)
            .and_then(|v| v.first())
            .map(Vec::as_slice)
            .or_else(|| {
                self.attrs
                    .get(name)
                    .and_then(|v| v.first())
                    .map(|s| s.as_bytes())
            })
    }

    /// Returns all values of a string attribute (e.g. memberOf).
    pub fn all_attr(&self, name: &str) -> &[String] {
        self.attrs.get(name).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Total number of values for an attribute, regardless of whether the
    /// LDAP layer classified them as string or binary. Used for multi-valued
    /// binary attributes such as `sIDHistory`, where the count is the
    /// authoritative total even when a value fails to parse.
    pub fn value_count(&self, name: &str) -> usize {
        self.attrs.get(name).map(Vec::len).unwrap_or(0)
            + self.bin_attrs.get(name).map(Vec::len).unwrap_or(0)
    }

    /// All values of an attribute as raw bytes, regardless of whether the
    /// LDAP layer classified them as string or binary. The classification
    /// happens per value: binary SID bytes that happen to form valid UTF-8
    /// land in `attrs`, all others in `bin_attrs` — so a caller parsing
    /// binary values (e.g. `sIDHistory`, ADR 0056) must consider both maps.
    pub fn all_values(&self, name: &str) -> Vec<&[u8]> {
        let mut out: Vec<&[u8]> = Vec::new();
        if let Some(vals) = self.attrs.get(name) {
            out.extend(vals.iter().map(|s| s.as_bytes()));
        }
        if let Some(vals) = self.bin_attrs.get(name) {
            out.extend(vals.iter().map(Vec::as_slice));
        }
        out
    }
}

/// Establishes an authenticated LDAP connection.
///
/// TLS mode:
///   `Ldaps` (default): ldaps://server:636 — TLS from the first byte, recommended.
///   `Insecure`: ldap://server:389 — password in plaintext, test environments only.
///   `GssapiSign`: ldap://server:389 with a SASL GSSAPI/Kerberos sign+seal
///     layer; cert-free path for hardened DCs (ADR 0051). Uses the current
///     Windows logon (SSPI SSO); `server` must be the DC's FQDN for the SPN.
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
        match config.tls_mode {
            TlsMode::GssapiSign => {
                // SASL GSSAPI/Kerberos bind using the current Windows logon
                // (SSPI single sign-on). On this clear connection it also
                // installs the Kerberos confidentiality (sign+seal) layer,
                // satisfying a hardened DC's LDAP-signing requirement without
                // a certificate (ADR 0051). `server` must be the DC's FQDN —
                // it is used to build the `ldap/<fqdn>` service principal name.
                ldap.sasl_gssapi_bind(&config.server)
                    .await
                    .map_err(|e| CoreError::AdConnection(format!("LDAP GSSAPI bind failed: {e}")))?
                    .success()
                    .map_err(|e| {
                        CoreError::AdConnection(format!("LDAP GSSAPI bind rejected: {e}"))
                    })?;
            }
            TlsMode::Ldaps | TlsMode::Insecure => {
                ldap.simple_bind(&config.bind_dn, &config.bind_password)
                    .await
                    .map_err(|e| CoreError::AdConnection(format!("LDAP bind failed: {e}")))?
                    .success()
                    .map_err(|e| CoreError::AdConnection(format!("LDAP bind rejected: {e}")))?;
            }
        }
        Ok(())
    })
    .await?;

    match config.tls_mode {
        TlsMode::GssapiSign => debug!("LDAP connected via GSSAPI sign+seal (current logon)"),
        _ => debug!("LDAP connected as: {}", config.bind_dn),
    }
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

/// Reads the `objectSid` of the domain head object at `domain_root_dn`
/// (base-scope search) — the domain SID that every account SID of that
/// domain starts with. `Ok(None)` when the object has no readable SID.
/// Used to classify a SID the directory has no object for: only when the
/// SID belongs to this domain does a miss prove the account no longer
/// exists (lab finding AD3-1).
pub async fn search_domain_sid(
    ldap: &mut Ldap,
    domain_root_dn: &str,
) -> Result<Option<String>, CoreError> {
    debug!("LDAP domain SID lookup: base={domain_root_dn}");
    let (rs, _res) = ldap
        .search(
            domain_root_dn,
            Scope::Base,
            "(objectClass=*)",
            vec!["objectSid"],
        )
        .await
        .map_err(|e| CoreError::LdapQuery(format!("domain SID search failed: {e}")))?
        .success()
        .map_err(|e| CoreError::LdapQuery(format!("domain SID search result error: {e}")))?;
    let Some(entry) = rs.into_iter().next().map(RawEntry::from_search_entry) else {
        return Ok(None);
    };
    Ok(entry
        .first_bin_attr("objectSid")
        .and_then(|b| crate::sid_util::bytes_to_sid_str(b).ok()))
}

/// Domain SIDs of every domain head object (`domainDNS`) visible under
/// `base_dn` — on a Global Catalog bind with an empty base, every domain of
/// the forest. Paged, so a large forest is not truncated.
pub async fn search_forest_domain_sids(
    ldap: &mut Ldap,
    base_dn: &str,
) -> Result<Vec<String>, CoreError> {
    let entries = search_paged_with_limit(
        ldap,
        base_dn,
        "(objectClass=domainDNS)",
        &["objectSid"],
        None,
    )
    .await?;
    Ok(entries
        .iter()
        .filter_map(|e| e.first_bin_attr("objectSid"))
        .filter_map(|b| crate::sid_util::bytes_to_sid_str(b).ok())
        .collect())
}

/// Reads the domain's `trustedDomain` objects for the read-only trust
/// inventory (L4). Trust objects live under `CN=System,<domain DN>`, so a
/// subtree search from the domain-root `base_dn` finds them. Returns the raw
/// entries for the caller to parse. Read-only: Stars never writes a trust.
pub async fn search_domain_trusts(
    ldap: &mut Ldap,
    base_dn: &str,
) -> Result<Vec<RawEntry>, CoreError> {
    let filter = "(objectClass=trustedDomain)";
    debug!("LDAP search for domain trusts: base={base_dn}");

    let (rs, _res) = ldap
        .search(base_dn, Scope::Subtree, filter, TRUST_ATTRS)
        .await
        .map_err(|e| CoreError::LdapQuery(format!("trust search failed: {e}")))?
        .success()
        .map_err(|e| CoreError::LdapQuery(format!("trust search result error: {e}")))?;

    Ok(rs.into_iter().map(RawEntry::from_search_entry).collect())
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

/// Direct members of a group by its `member` **back-link** (`memberOf`).
///
/// Instead of reading the group's multi-valued `member` attribute — which AD
/// returns in 1500-value ranges (`member;range=0-1499`) and would truncate
/// silently if the range paging were mishandled — this searches for the objects
/// that carry the group's DN in their `memberOf`. That is a normal paged
/// search (`PagedResults`), so the standard, tested paging applies and there is
/// no range boundary to get wrong. `memberOf` is AD's referential back-link of
/// `member`, so it returns exactly the group's direct members. Note this does
/// **not** include `primaryGroupID` members — those are fetched separately (see
/// [`search_by_primary_group`]). ADR 0055.
pub async fn search_members_by_backlink(
    ldap: &mut Ldap,
    base_dn: &str,
    group_dn: &str,
) -> Result<Vec<RawEntry>, CoreError> {
    let escaped = escape_dn_for_filter(group_dn);
    let filter = format!("(memberOf={escaped})");
    debug!("LDAP member back-link search: base={base_dn} group={group_dn}");
    search_paged_with_limit(ldap, base_dn, &filter, IDENTITY_ATTRS, None).await
}

/// Members whose **primary** group is the group with the given RID.
///
/// `primaryGroupID` holds the RID of a user's/computer's primary group; those
/// members are **not** listed in the group's `member` attribute nor found via
/// the `memberOf` back-link. Classic case: every user's primary group is Domain
/// Users (RID 513), so without this query Domain Users appears to have zero
/// members. The attribute exists only on security principals (users,
/// computers), so `(primaryGroupID=<rid>)` returns exactly the primary-group
/// members. `rid` is numeric (the last component of the group SID), so no
/// filter escaping is required. ADR 0055.
pub async fn search_by_primary_group(
    ldap: &mut Ldap,
    base_dn: &str,
    rid: u32,
) -> Result<Vec<RawEntry>, CoreError> {
    let filter = format!("(primaryGroupID={rid})");
    debug!("LDAP primaryGroupID search: base={base_dn} rid={rid}");
    search_paged_with_limit(ldap, base_dn, &filter, IDENTITY_ATTRS, None).await
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
    let mut stopped_at_limit = false;
    loop {
        match stream.next().await {
            Ok(Some(entry)) => {
                entries.push(RawEntry::from_search_entry(entry));
                if let Some(limit) = client_limit {
                    if entries.len() >= limit {
                        stopped_at_limit = true;
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
    // finish() consumes the stream. When we deliberately stopped early at the
    // client limit, ldap3 abandons the still-open paged search, which the
    // server reports as a non-success final status (`rc=88`, "cancelled").
    // That abandon is *expected* — treating it as an error would discard the
    // entries we already collected (identity-picker bug found in lab Block P:
    // any query matching more than the limit failed). So we only validate the
    // final status when we consumed the whole result set; a mid-stream server
    // error is still caught by the `Err` arm above.
    let result = stream.finish().await;
    if !stopped_at_limit {
        result
            .success()
            .map_err(|e| CoreError::LdapQuery(format!("paged search final status: {e}")))?;
    }
    Ok(entries)
}

/// Upper bound for range-retrieval rounds — 1,000 rounds of 1,500 values
/// each covers 1.5 million values, far beyond any real `memberOf`; the
/// bound only guards against a server that never reports the last chunk.
const MAX_RANGE_ROUNDS: usize = 1_000;

/// Parses the range suffix of an attribute description returned by AD for a
/// multi-valued attribute larger than `MaxValRange`: `memberOf;range=0-1499`
/// → `(0, Some(1499))`, the final chunk `memberOf;range=1500-*` →
/// `(1500, None)`. `None` when `key` is not a ranged form of `attr`.
pub(crate) fn parse_range_suffix(key: &str, attr: &str) -> Option<(u32, Option<u32>)> {
    let prefix_len = attr.len() + ";range=".len();
    let head = key.get(..prefix_len)?;
    if !head.eq_ignore_ascii_case(&format!("{attr};range=")) {
        return None;
    }
    let (start, end) = key.get(prefix_len..)?.split_once('-')?;
    let start: u32 = start.parse().ok()?;
    let end = if end == "*" {
        None
    } else {
        let end: u32 = end.parse().ok()?;
        if end < start {
            return None;
        }
        Some(end)
    };
    Some((start, end))
}

fn ranged_key(entry: &RawEntry, attr: &str) -> Option<(String, u32, Option<u32>)> {
    entry
        .attrs
        .keys()
        .find_map(|key| parse_range_suffix(key, attr).map(|(start, end)| (key.clone(), start, end)))
}

/// Completes `attr` on `entry` through AD **range retrieval** when the
/// server returned only the first range (`memberOf;range=0-1499` instead of
/// `memberOf`) because the attribute holds more values than `MaxValRange`.
/// Afterwards `entry.attrs[attr]` holds every value and `Ok(true)` is
/// returned; `Ok(false)` when the attribute was not ranged.
///
/// Until ADR 0066 a ranged `memberOf` was read as empty: direct memberships
/// counted as nested and further routes went unseen. Every server answer is
/// validated — each chunk must start right after the previous one, and the
/// loop is bounded — and any inconsistency is an error, never a silently
/// shortened list.
pub async fn complete_ranged_attribute(
    ldap: &mut Ldap,
    entry: &mut RawEntry,
    attr: &str,
) -> Result<bool, CoreError> {
    let Some((key, start, mut end)) = ranged_key(entry, attr) else {
        return Ok(false);
    };
    if start != 0 {
        return Err(CoreError::LdapQuery(format!(
            "range retrieval of {attr} on {}: first chunk starts at {start}, not 0",
            entry.dn
        )));
    }
    let mut values = entry.attrs.remove(&key).unwrap_or_default();
    let mut rounds = 0usize;
    while let Some(last) = end {
        rounds += 1;
        if rounds > MAX_RANGE_ROUNDS {
            return Err(CoreError::LdapQuery(format!(
                "range retrieval of {attr} on {} did not finish after {MAX_RANGE_ROUNDS} rounds",
                entry.dn
            )));
        }
        let next = last.checked_add(1).ok_or_else(|| {
            CoreError::LdapQuery(format!("range retrieval of {attr}: range end overflow"))
        })?;
        let request = format!("{attr};range={next}-*");
        debug!(dn = %entry.dn, %request, "LDAP range retrieval");
        let (rs, _res) = ldap
            .search(
                &entry.dn,
                Scope::Base,
                "(objectClass=*)",
                vec![request.as_str()],
            )
            .await
            .map_err(|e| CoreError::LdapQuery(format!("range retrieval failed: {e}")))?
            .success()
            .map_err(|e| CoreError::LdapQuery(format!("range retrieval result error: {e}")))?;
        let chunk = rs
            .into_iter()
            .next()
            .map(RawEntry::from_search_entry)
            .ok_or_else(|| {
                CoreError::LdapQuery(format!(
                    "range retrieval of {attr} on {}: entry vanished",
                    entry.dn
                ))
            })?;
        let Some((chunk_key, chunk_start, chunk_end)) = ranged_key(&chunk, attr) else {
            return Err(CoreError::LdapQuery(format!(
                "range retrieval of {attr} on {}: no values for range {next}-*",
                entry.dn
            )));
        };
        if chunk_start != next {
            return Err(CoreError::LdapQuery(format!(
                "range retrieval of {attr} on {}: expected range starting at {next}, got {chunk_start}",
                entry.dn
            )));
        }
        values.extend(chunk.attrs.get(&chunk_key).cloned().unwrap_or_default());
        end = chunk_end;
    }
    debug!(dn = %entry.dn, attr, count = values.len(), "Ranged attribute completed");
    entry.attrs.insert(attr.to_owned(), values);
    Ok(true)
}

/// Terminates the LDAP connection properly.
pub async fn disconnect(mut ldap: Ldap) {
    if let Err(e) = ldap.unbind().await {
        warn!("LDAP unbind error: {e}");
    }
}

/// Escapes special characters in DN values for LDAP filters.
fn escape_dn_for_filter(dn: &str) -> String {
    // In a filter, commas and equals don't need escaping, but parentheses do.
    // The RFC-4515 value escaper lives centrally in `validation::ldap`
    // (review finding V1).
    escape_filter_value(dn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn value_count_counts_binary_values() {
        // sIDHistory is returned as binary SID values, landing in bin_attrs.
        let mut bin = HashMap::new();
        bin.insert("sIDHistory".to_string(), vec![vec![1u8], vec![2u8]]);
        let e = RawEntry {
            dn: String::new(),
            attrs: HashMap::new(),
            bin_attrs: bin,
        };
        assert_eq!(e.value_count("sIDHistory"), 2);
    }

    #[test]
    fn value_count_is_zero_when_attribute_absent() {
        let e = RawEntry {
            dn: String::new(),
            attrs: HashMap::new(),
            bin_attrs: HashMap::new(),
        };
        assert_eq!(e.value_count("sIDHistory"), 0);
    }

    #[test]
    fn value_count_sums_string_and_binary_maps() {
        // Defensive: a value lands in exactly one map; the count is their sum.
        let mut attrs = HashMap::new();
        attrs.insert("attr".to_string(), vec!["a".to_string(), "b".to_string()]);
        let mut bin = HashMap::new();
        bin.insert("attr".to_string(), vec![vec![0u8]]);
        let e = RawEntry {
            dn: String::new(),
            attrs,
            bin_attrs: bin,
        };
        assert_eq!(e.value_count("attr"), 3);
    }

    /// A builtin SID (S-1-5-32-545, BUILTIN\Users) is valid UTF-8 and lands
    /// in `attrs`; it must still be readable as binary.
    #[test]
    fn binary_attribute_that_is_valid_utf8_is_still_readable() {
        let sid_bytes = crate::sid_util::sid_str_to_bytes("S-1-5-32-545").expect("encode");
        let as_text = String::from_utf8(sid_bytes.clone()).expect("builtin SIDs are valid UTF-8");
        let mut attrs = HashMap::new();
        attrs.insert("objectSid".to_string(), vec![as_text]);
        let e = RawEntry {
            dn: "CN=Users,CN=Builtin,DC=corp,DC=test".to_string(),
            attrs,
            bin_attrs: HashMap::new(),
        };
        assert_eq!(e.first_bin_attr("objectSid"), Some(sid_bytes.as_slice()));
        assert_eq!(
            crate::resolver::extract_sid_from_entry(&e).map(|s| s.0),
            Some("S-1-5-32-545".to_string())
        );
    }

    #[test]
    fn range_suffix_parsing_accepts_only_valid_ranges() {
        assert_eq!(
            parse_range_suffix("memberOf;range=0-1499", "memberOf"),
            Some((0, Some(1499)))
        );
        assert_eq!(
            parse_range_suffix("memberof;RANGE=1500-*", "memberOf"),
            Some((1500, None))
        );
        assert_eq!(parse_range_suffix("memberOf", "memberOf"), None);
        assert_eq!(parse_range_suffix("member;range=0-1499", "memberOf"), None);
        assert_eq!(parse_range_suffix("memberOf;range=10-5", "memberOf"), None);
        assert_eq!(parse_range_suffix("memberOf;range=a-5", "memberOf"), None);
        assert_eq!(parse_range_suffix("memberOf;range=0", "memberOf"), None);
    }

    #[test]
    fn ranged_key_finds_the_ranged_description() {
        let mut attrs = HashMap::new();
        attrs.insert(
            "memberOf;range=0-1499".to_string(),
            vec!["CN=a,DC=x".to_string()],
        );
        let e = RawEntry {
            dn: "CN=u,DC=x".to_string(),
            attrs,
            bin_attrs: HashMap::new(),
        };
        assert_eq!(
            ranged_key(&e, "memberOf"),
            Some(("memberOf;range=0-1499".to_string(), 0, Some(1499)))
        );
        // The plain accessor sees nothing — exactly the pre-ADR-0066 bug.
        assert!(e.all_attr("memberOf").is_empty());
    }
}
