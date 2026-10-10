// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::CoreError;

/// Typed SID — prevents accidental mix-ups with arbitrary strings.
///
/// The inner field stays public for serde round-tripping and for
/// trusted, already-validated construction (LDAP/LSA results,
/// well-known SIDs). Production code that turns **untrusted input**
/// into a `Sid` should go through [`Sid::try_new`], which enforces the
/// `S-1-…` syntax invariant, rather than the bare tuple constructor
/// (engine review 2026-06-12 finding 4).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sid(pub String);

impl Sid {
    /// Validates the `S-1-<authority>(-<sub-authority>)+` syntax and
    /// returns a `Sid` on success. This is the single canonical SID
    /// syntax check in the workspace — `validation::validate_sid`
    /// delegates to it.
    ///
    /// Rules: non-empty (after trim), starts with `S-1-`, at least four
    /// `-`-separated components (`S-1-X-Y`), and every component after
    /// the leading `S` is numeric. The value is trimmed.
    pub fn try_new(input: &str) -> Result<Self, CoreError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(CoreError::Validation("SID must not be empty".into()));
        }
        if !trimmed.starts_with("S-1-") {
            return Err(CoreError::Validation(format!(
                "Invalid SID format (must start with 'S-1-'): {trimmed}"
            )));
        }
        let parts: Vec<&str> = trimmed.split('-').collect();
        if parts.len() < 4 {
            return Err(CoreError::Validation(format!(
                "SID has too few components (minimum S-1-X-Y): {trimmed}"
            )));
        }
        for part in &parts[1..] {
            if part.parse::<u64>().is_err() {
                return Err(CoreError::Validation(format!(
                    "SID contains non-numeric component '{part}': {trimmed}"
                )));
            }
        }
        Ok(Sid(trimmed.to_string()))
    }

    /// Constructs a `Sid` without validation — for trusted sources that
    /// already produce well-formed SIDs (LDAP `objectSid` conversion,
    /// LSA lookups, hard-coded well-known SIDs, deserialization). Use
    /// [`Sid::try_new`] for untrusted input.
    pub fn new_unchecked(value: impl Into<String>) -> Self {
        Sid(value.into())
    }

    /// `true` when `input` is a syntactically valid SID per
    /// [`Sid::try_new`].
    pub fn is_valid_syntax(input: &str) -> bool {
        Self::try_new(input).is_ok()
    }
}

/// Normalized, validated path.
///
/// As with [`Sid`], the inner field is public for serde and trusted
/// construction; untrusted input should be funneled through
/// [`NormalizedPath::try_new`], which rejects the structurally invalid
/// cases that must never reach filesystem or display logic (engine
/// review 2026-06-12 finding 4).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NormalizedPath(pub String);

impl NormalizedPath {
    /// Validates a path string and returns a `NormalizedPath`. The check
    /// is deliberately conservative — full UNC/local-path validation
    /// lives in the `validation` crate; this guards the core invariant
    /// that a `NormalizedPath` is never empty and never carries NUL or
    /// other control characters (which would corrupt Win32 calls, logs,
    /// and reports). The value is trimmed of surrounding whitespace.
    pub fn try_new(input: &str) -> Result<Self, CoreError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(CoreError::Validation("Path must not be empty".into()));
        }
        if let Some(bad) = trimmed.chars().find(|c| *c == '\0' || c.is_control()) {
            return Err(CoreError::Validation(format!(
                "Path contains an invalid control character (U+{:04X})",
                bad as u32
            )));
        }
        Ok(NormalizedPath(trimmed.to_string()))
    }

    /// Constructs a `NormalizedPath` without validation — for values
    /// already normalized by the scanner or filesystem layer, and for
    /// deserialization. Use [`NormalizedPath::try_new`] for untrusted
    /// input.
    pub fn new_unchecked(value: impl Into<String>) -> Self {
        NormalizedPath(value.into())
    }
}

/// Windows Access Mask (raw u32 value)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessMask(pub u32);

/// Kind of identity
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityKind {
    User,
    Group,
    Computer,
    WellKnown,
    /// A Foreign Security Principal object
    /// (`CN=ForeignSecurityPrincipals,…`) standing in for a principal
    /// from a trusted forest. Used as the fallback kind when the FSP
    /// could not be enriched via LSA into the real principal type.
    ForeignSecurityPrincipal,
    Orphaned,
    Unknown,
}

/// Represents an AD user, group, or computer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub sid: Sid,
    pub name: Option<String>,
    pub domain: Option<String>,
    pub kind: IdentityKind,
    pub disabled: bool,
    /// userPrincipalName from AD (e.g. `max.mustermann@testdomain.local`).
    /// Preferred for Windows NetAPI calls like `NetUserGetLocalGroups`,
    /// since the `DOMAIN\sAMAccountName` form strictly requires the NetBIOS
    /// name which we cannot reliably derive from the DN.
    #[serde(default)]
    pub user_principal_name: Option<String>,
    /// Total number of historical SIDs (`sIDHistory`) the account carries —
    /// set when resolved via the direct in-base LDAP path, `0` otherwise
    /// (the SAM/LSA and FSP paths cannot read the attribute). This is the
    /// authoritative total as reported by LDAP; `sid_history` holds the
    /// parsed values and may be shorter when a value was malformed. The
    /// difference (`sid_history_count - sid_history.len()`) is what stays
    /// **un-evaluated** and is surfaced as
    /// `PermissionDiagnostic::SidHistoryPresent` (incompleteness trigger);
    /// the parsed values are evaluated into the token and surfaced as
    /// `PermissionDiagnostic::SidHistoryEvaluated` (ADR 0056).
    /// `#[serde(default)]` keeps older persisted rows readable.
    #[serde(default)]
    pub sid_history_count: usize,
    /// Parsed historical SIDs (`sIDHistory`) of the account. Windows
    /// includes these SIDs in the real logon token unconditionally within
    /// the account's forest, so the permission engine adds them to the
    /// evaluated token and the explanation path names each one (ADR 0056).
    /// Empty when the resolver path cannot read the attribute (then
    /// `sid_history_count` is also `0`) or for rows persisted before this
    /// field existed (`#[serde(default)]`).
    #[serde(default)]
    pub sid_history: Vec<Sid>,
}

impl Identity {
    /// Diagnostic classification of this identity's `sIDHistory` state —
    /// the single source of truth consumed by both the permission engine
    /// and the membership view so the two surfaces cannot drift (ADR 0056).
    ///
    /// - Parsed values (`sid_history`) are evaluated into the token →
    ///   `SidHistoryEvaluated { count }`, informational.
    /// - The remainder (`sid_history_count - sid_history.len()`, e.g.
    ///   malformed values, or rows persisted under ADR 0052 where values
    ///   were never fetched) stays un-evaluated →
    ///   `SidHistoryPresent { count }`, an incompleteness trigger.
    pub fn sid_history_diagnostics(&self) -> Vec<PermissionDiagnostic> {
        let mut d = Vec::new();
        let evaluated = self.sid_history.len();
        if evaluated > 0 {
            d.push(PermissionDiagnostic::SidHistoryEvaluated { count: evaluated });
        }
        let unevaluated = self.sid_history_count.saturating_sub(evaluated);
        if unevaluated > 0 {
            d.push(PermissionDiagnostic::SidHistoryPresent { count: unevaluated });
        }
        d
    }
}

/// Access context for permission evaluation.
///
/// Windows adds different well-known SIDs to the access token depending
/// on logon type. For a faithful AccessCheck reproduction the engine
/// needs to know whether to simulate a local or remote (SMB) access:
/// ACEs targeting `NETWORK` (S-1-5-2) only apply over SMB; ACEs
/// targeting `INTERACTIVE` (S-1-5-4) and `LOCAL` (S-1-2-0) only apply
/// to local logons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AccessContext {
    /// Local interactive evaluation — `INTERACTIVE` and `LOCAL` are added
    /// to the token implicitly.
    LocalInteractive,
    /// Remote SMB access — `NETWORK` is added to the token implicitly.
    RemoteSmb,
    /// No explicit context — only the universal well-knowns (`Everyone`,
    /// `Authenticated Users`) apply. Default for backwards compatibility.
    #[default]
    Unspecified,
}

impl AccessContext {
    /// Derives the context from the path shape. UNC paths — including the
    /// long-path form `\\?\UNC\server\share\…` — count as `RemoteSmb`;
    /// local paths (incl. `\\?\C:\…`) count as `LocalInteractive`.
    pub fn for_path(path: &str) -> Self {
        if let Some(rest) = path.strip_prefix(r"\\?\") {
            if rest.starts_with("UNC\\") || rest.starts_with("UNC/") {
                return Self::RemoteSmb;
            }
            return Self::LocalInteractive;
        }
        if path.starts_with(r"\\") {
            return Self::RemoteSmb;
        }
        Self::LocalInteractive
    }

    /// Like [`Self::for_path`], but forces `RemoteSmb` as soon as an explicit
    /// SMB context is supplied (`--smb-server` / `--share-name` on the CLI,
    /// the corresponding GUI fields). This fixes round-7 finding 1: a local
    /// NTFS path analysed with an explicit SMB context previously produced
    /// `LocalInteractive` — `NETWORK` was missing from the token and share
    /// DACL ACEs targeting `NETWORK`/`INTERACTIVE`/`LOCAL` were aggregated
    /// incorrectly.
    pub fn for_path_with_smb(
        path: &str,
        smb_server: Option<&str>,
        share_name: Option<&str>,
    ) -> Self {
        let has_explicit_smb = smb_server.map(|s| !s.is_empty()).unwrap_or(false)
            || share_name.map(|s| !s.is_empty()).unwrap_or(false);
        if has_explicit_smb {
            return Self::RemoteSmb;
        }
        Self::for_path(path)
    }
}

/// Membership of an identity in a group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMembership {
    pub member_sid: Sid,
    pub group_sid: Sid,
    pub direct: bool,
    /// Human-readable group name when the resolver was able to provide
    /// one (e.g. `Domain Admins` from LDAP/NetUserGetGroups or
    /// `BUILTIN\Administrators` from LookupAccountSidW). `None` does not
    /// mean "no name exists" — it means "this resolver did not supply a
    /// name". `#[serde(default)]` keeps older cache entries lacking this
    /// field compatible.
    #[serde(default)]
    pub group_name: Option<String>,
    /// Concrete membership path from `member_sid` to `group_sid` (see
    /// [`MembershipPath`]). Populated by the live resolver; the SQLite
    /// cache does not store it because it is reconstructed on every
    /// run. `None` means "this resolver did not supply a path" — the
    /// `#[serde(default)]` keeps older cache entries compatible.
    #[serde(default)]
    pub path: Option<MembershipPath>,
    /// Total number of historical SIDs (`sIDHistory`) the **group itself**
    /// carries — same count/values model as on [`Identity`] (ADR 0056 /
    /// ADR 0059). Set on the LDAP membership path; the SAM/LSA fallback
    /// cannot read it (`0` — that path already carries the
    /// recursion-incomplete marker) and local server groups have no
    /// `sIDHistory` (`0` is exact). `group_sid_history.len() <= count`;
    /// the difference is what stays un-evaluated
    /// (`GroupSidHistoryPresent`).
    #[serde(default)]
    pub group_sid_history_count: usize,
    /// Parsed historical SIDs of the group. The Windows PAC includes the
    /// history SIDs of the token groups, so the engine adds these to the
    /// evaluated token and the membership step in the explanation names
    /// them (ADR 0059).
    #[serde(default)]
    pub group_sid_history: Vec<Sid>,
}

/// Diagnostic classification of the **groups'** `sIDHistory` state across
/// a membership set — the single source of truth consumed by both the
/// permission engine and the membership view (ADR 0059), mirroring
/// [`Identity::sid_history_diagnostics`] for the user's own history.
pub fn group_sid_history_diagnostics(memberships: &[GroupMembership]) -> Vec<PermissionDiagnostic> {
    let mut groups = 0usize;
    let mut evaluated = 0usize;
    let mut unevaluated = 0usize;
    // De-duplicate by group SID: the same group can be listed through
    // several membership entries (e.g. the AD + local-group combination)
    // and must not inflate the counts.
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for gm in memberships {
        if !seen.insert(gm.group_sid.0.as_str()) {
            continue;
        }
        if gm.group_sid_history_count == 0 {
            continue;
        }
        let parsed = gm.group_sid_history.len();
        if parsed > 0 {
            groups += 1;
            evaluated += parsed;
        }
        unevaluated += gm.group_sid_history_count.saturating_sub(parsed);
    }
    let mut d = Vec::new();
    if evaluated > 0 {
        d.push(PermissionDiagnostic::GroupSidHistoryEvaluated {
            groups,
            count: evaluated,
        });
    }
    if unevaluated > 0 {
        d.push(PermissionDiagnostic::GroupSidHistoryPresent { count: unevaluated });
    }
    d
}

/// Concrete membership chain from an identity to a group.
///
/// `nodes[0]` is the starting SID (user, computer or group), `nodes[n-1]`
/// is the target group. Intermediate indices are the nested groups in
/// direct `member`-edge order.
///
/// `names` is index-aligned with `nodes` and carries the display name
/// per SID when known — the engine can render a readable explanation
/// path without re-resolving.
///
/// `complete` is `true` when the chain was fully reconstructed from
/// concrete `member` edges. `false` means only the transitive
/// membership is established (e.g. via `LDAP_MATCHING_RULE_IN_CHAIN`)
/// but the exact intermediate sequence is not — typical when the
/// `memberOf` of an intermediate group entry was truncated by the
/// server, so the chain could not be walked further. Renderers then
/// label the path "chain not fully reconstructed".
///
/// `nodes` shows **one** shortest route. Which one is chosen when several
/// equally short routes exist is deterministic (ADR 0063): walking back
/// from the target, each hop takes the member group with the
/// alphabetically first distinguished name among those one hop closer to
/// the identity. All *other* entries into the target are listed in
/// `also_via`, so a reader never mistakes the shown route for the only one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipPath {
    pub nodes: Vec<Sid>,
    #[serde(default)]
    pub names: Vec<Option<String>>,
    pub source: MembershipPathSource,
    pub complete: bool,
    /// Further groups through which `nodes[0]` **also** reaches the target
    /// group, besides the last hop shown in `nodes`. Each entry is a group
    /// the identity is itself (directly or transitively) a member of and
    /// that is a direct member of the target. Non-empty means the identity
    /// keeps the target membership even if the shown route is removed —
    /// the explanation says so instead of implying a single route
    /// (ADR 0063). Sorted for reproducible output. Empty when the shown
    /// route is the only entry the resolver could see, and for rows
    /// written before this field existed (`#[serde(default)]`).
    #[serde(default)]
    pub also_via: Vec<MembershipHop>,
}

/// One further entry into a target group — see [`MembershipPath::also_via`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipHop {
    pub sid: Sid,
    /// Display name when the resolver knew one.
    #[serde(default)]
    pub name: Option<String>,
}

impl MembershipHop {
    /// `name (SID)` when a name is known, the bare SID otherwise.
    pub fn display(&self) -> String {
        match self.name.as_deref().filter(|n| !n.is_empty()) {
            Some(name) => format!("{name} ({})", self.sid.0),
            None => self.sid.0.clone(),
        }
    }
}

/// How many `also_via` entries renderers spell out before summarising the
/// rest as "+N more" — keeps a step readable for a group that is reached
/// through dozens of nested groups, while the full list stays in the data
/// model (JSON export).
pub const ALSO_VIA_DISPLAY_LIMIT: usize = 5;

/// Renders `also_via` as `A (SID), B (SID) (+3 more)`, or `None` when the
/// list is empty. Shared by the explanation path and the membership views
/// so both word alternative routes identically.
pub fn format_also_via(also_via: &[MembershipHop]) -> Option<String> {
    if also_via.is_empty() {
        return None;
    }
    let shown: Vec<String> = also_via
        .iter()
        .take(ALSO_VIA_DISPLAY_LIMIT)
        .map(MembershipHop::display)
        .collect();
    let mut text = shown.join(", ");
    if also_via.len() > ALSO_VIA_DISPLAY_LIMIT {
        text.push_str(&format!(
            " (+{} more)",
            also_via.len() - ALSO_VIA_DISPLAY_LIMIT
        ));
    }
    Some(text)
}

/// Source of a reconstructed membership chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipPathSource {
    /// Primary AD group (`primaryGroupID`) — a single edge from the user
    /// to the primary group, with transitive parents recorded as their
    /// own memberships.
    PrimaryGroup,
    /// Direct or nested domain group membership reconstructed via
    /// concrete `member` edges.
    DomainGroup,
    /// Local group on the target server (NetUserGetLocalGroups or
    /// NetLocalGroupGetMembers).
    LocalGroup,
    /// Transitive membership is certain (e.g. via
    /// `LDAP_MATCHING_RULE_IN_CHAIN`) but the concrete path could not
    /// be fully reconstructed. `complete` is `false` in this case.
    LdapMatchingRule,
}

impl GroupMembership {
    /// How informative this entry is, for picking **one** entry per group SID
    /// when the same group arrives through several resolution sources (e.g.
    /// a domain-local group on a domain controller comes from LDAP *and* from
    /// the local-group lookup). Higher is better, compared lexicographically:
    /// **direct** beats nested, a **complete path** beats an incomplete one,
    /// **more resolved names** beat fewer, and a **named** group beats an
    /// unnamed one. Single source of truth for the membership report and the
    /// explanation path (review 2026-07-01 finding 2, lab finding CLI3-1).
    pub fn informativeness_rank(&self) -> (bool, bool, usize, bool) {
        let (complete, resolved_names) = match &self.path {
            Some(p) => (p.complete, p.names.iter().filter(|n| n.is_some()).count()),
            None => (false, 0),
        };
        (
            self.direct,
            complete,
            resolved_names,
            self.group_name.is_some(),
        )
    }

    /// Human-readable description of how this membership arose — `"primary
    /// group"`, `"local group"`, `"direct"`, `"nested"`, or the resolved
    /// chain `"via A → B"` — followed by any further routes into the group
    /// (`"; also through C"`, ADR 0063). Shared by the CLI and GUI membership
    /// views so both word it identically.
    pub fn origin_label(&self) -> String {
        let base = self.origin_label_base();
        match self
            .path
            .as_ref()
            .and_then(|p| format_also_via(&p.also_via))
        {
            Some(also) => format!("{base}; also a member through {also}"),
            None => base,
        }
    }

    fn origin_label_base(&self) -> String {
        if let Some(p) = &self.path {
            match p.source {
                MembershipPathSource::PrimaryGroup => return "primary group".to_owned(),
                MembershipPathSource::LocalGroup => return "local group".to_owned(),
                _ => {}
            }
        }
        if self.direct {
            return "direct".to_owned();
        }
        match &self.path {
            Some(p) => {
                let chain: Vec<String> = p
                    .nodes
                    .iter()
                    .enumerate()
                    .map(|(i, sid)| {
                        p.names
                            .get(i)
                            .and_then(|n| n.clone())
                            .unwrap_or_else(|| sid.0.clone())
                    })
                    .collect();
                let arrow = chain.join(" \u{2192} ");
                if p.complete {
                    format!("via {arrow}")
                } else {
                    format!("via {arrow} (chain not fully reconstructed)")
                }
            }
            None => "nested".to_owned(),
        }
    }
}

/// One entry per group SID, keeping the most informative entry
/// ([`GroupMembership::informativeness_rank`]) and the first-appearance
/// order of each group SID for deterministic output. Used wherever the same
/// group can arrive twice — the AD/LDAP memberships plus the target server's
/// local-group memberships — so a group is listed once instead of once per
/// source (lab finding CLI3-1). The token itself is a set and unaffected.
pub fn best_membership_per_group(memberships: &[GroupMembership]) -> Vec<&GroupMembership> {
    let mut order: Vec<&str> = Vec::new();
    let mut best: std::collections::HashMap<&str, &GroupMembership> =
        std::collections::HashMap::new();
    for m in memberships {
        let key = m.group_sid.0.as_str();
        match best.get(key) {
            None => {
                order.push(key);
                best.insert(key, m);
            }
            Some(existing) if m.informativeness_rank() > existing.informativeness_rank() => {
                best.insert(key, m);
            }
            Some(_) => {}
        }
    }
    // `order` drives the output; the map is only a lookup, so its iteration
    // order never reaches the result.
    order
        .into_iter()
        .filter_map(|k| best.get(k).copied())
        .collect()
}

/// Like [`best_membership_per_group`], but **merges** the routes of the
/// entries that are dropped: the kept entry's `also_via` gains the last hop
/// of every other entry for the same group (when it differs) and their own
/// `also_via` entries. So a domain-local or builtin group that arrives from
/// LDAP *and* from the local-group lookup is listed once without losing a
/// route the second source knew (lab finding CLI3-1, ADR 0063). Output order
/// and the kept entry follow `best_membership_per_group`; `also_via` is
/// sorted by name (case-insensitive), then SID.
pub fn merged_memberships_per_group(memberships: &[GroupMembership]) -> Vec<GroupMembership> {
    let mut merged: Vec<GroupMembership> = best_membership_per_group(memberships)
        .into_iter()
        .cloned()
        .collect();
    for kept in merged.iter_mut() {
        let Some(path) = kept.path.as_mut() else {
            continue;
        };
        let kept_last_hop = path
            .nodes
            .len()
            .checked_sub(2)
            .and_then(|i| path.nodes.get(i))
            .cloned();
        let mut extra: Vec<MembershipHop> = Vec::new();
        for other in memberships.iter().filter(|m| m.group_sid == kept.group_sid) {
            let Some(other_path) = other.path.as_ref() else {
                continue;
            };
            if other_path.nodes.len() >= 3 {
                let i = other_path.nodes.len() - 2;
                let hop = &other_path.nodes[i];
                if Some(hop) != kept_last_hop.as_ref() && *hop != other.member_sid {
                    extra.push(MembershipHop {
                        sid: hop.clone(),
                        name: other_path.names.get(i).cloned().flatten(),
                    });
                }
            }
            extra.extend(other_path.also_via.iter().cloned());
        }
        if extra.is_empty() {
            // Single source: keep the resolver's order untouched.
            continue;
        }
        // One hop per SID, a named occurrence preferred; the kept chain's
        // own last hop is not a "further" route.
        let mut by_sid: std::collections::BTreeMap<String, MembershipHop> =
            std::collections::BTreeMap::new();
        for hop in path.also_via.drain(..).chain(extra) {
            if Some(&hop.sid) == kept_last_hop.as_ref() {
                continue;
            }
            match by_sid.get_mut(&hop.sid.0) {
                Some(existing) if existing.name.is_none() => existing.name = hop.name,
                Some(_) => {}
                None => {
                    by_sid.insert(hop.sid.0.clone(), hop);
                }
            }
        }
        let mut hops: Vec<MembershipHop> = by_sid.into_values().collect();
        hops.sort_by(|a, b| {
            let an = a.name.as_deref().unwrap_or("").to_lowercase();
            let bn = b.name.as_deref().unwrap_or("").to_lowercase();
            an.cmp(&bn).then_with(|| a.sid.0.cmp(&b.sid.0))
        });
        path.also_via = hops;
    }
    merged
}

/// Well-known **privileged** role name if `sid` is a built-in or
/// default-domain privileged group — `None` otherwise. Built-in aliases are
/// matched by their constant SID, domain groups by their well-known RID
/// suffix (`-512` Domain Admins, `-519` Enterprise Admins, …). Used to flag a
/// sensitive membership ("⚠ member of Domain Admins") in the membership view.
pub fn privileged_group_role(sid: &Sid) -> Option<&'static str> {
    match sid.0.as_str() {
        "S-1-5-32-544" => return Some("Administrators"),
        "S-1-5-32-548" => return Some("Account Operators"),
        "S-1-5-32-549" => return Some("Server Operators"),
        "S-1-5-32-550" => return Some("Print Operators"),
        "S-1-5-32-551" => return Some("Backup Operators"),
        _ => {}
    }
    // Domain groups: `S-1-5-21-<domain>-<RID>`, identified by the RID suffix.
    let rid = sid
        .0
        .strip_prefix("S-1-5-21-")
        .and_then(|rest| rest.rsplit('-').next())?;
    match rid {
        "512" => Some("Domain Admins"),
        "519" => Some("Enterprise Admins"),
        "518" => Some("Schema Admins"),
        "520" => Some("Group Policy Creator Owners"),
        "526" => Some("Key Admins"),
        "527" => Some("Enterprise Key Admins"),
        _ => None,
    }
}

/// A standalone "which groups is this identity in?" report — no path, no ACL,
/// no effective rights (those stay in `analyze` / `scan`). Rendered by the CLI
/// `groups` command and the GUI Groups tab from one shared structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipReport {
    pub identity: Identity,
    /// `true` when an AD/LDAP connection backed the resolution (as opposed to
    /// the SAM/LSA fallback, which returns only direct global groups).
    pub ad_connected: bool,
    /// Recursive group memberships, deduplicated by group SID.
    pub memberships: Vec<GroupMembership>,
    /// Identity-/resolution-level diagnostic markers (the same set the engine
    /// surfaces for an identity, without the path-specific ones).
    pub diagnostics: Vec<PermissionDiagnostic>,
}

impl MembershipReport {
    /// Memberships that resolve to a privileged group, as
    /// `(group SID, role name)` — the high-value audit signal.
    pub fn privileged(&self) -> Vec<(&Sid, &'static str)> {
        self.memberships
            .iter()
            .filter_map(|m| privileged_group_role(&m.group_sid).map(|role| (&m.group_sid, role)))
            .collect()
    }
}

/// How a member ended up in a group — the audit-relevant distinction between
/// the two AD enumeration sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberVia {
    /// Listed in the group's `member` attribute (equivalently, the object
    /// carries the group's DN in its `memberOf` back-link).
    Direct,
    /// The group is the member's **primary** group (`primaryGroupID`). Such
    /// members are **not** in `member` — classically every user has Domain
    /// Users as primary group, so a naive `member`-only read reports zero.
    PrimaryGroup,
}

impl MemberVia {
    /// Short, stable label for the CLI/GUI ("direct" / "via primaryGroupID").
    pub fn label(&self) -> &'static str {
        match self {
            MemberVia::Direct => "direct",
            MemberVia::PrimaryGroup => "via primaryGroupID",
        }
    }
}

/// One member of a group. `children` stays empty in v1 (direct members only);
/// v2 will populate it for nested subgroups (recursive tree with cycle
/// detection), which is why the field exists now — the serialized shape stays
/// stable across the two versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberNode {
    pub identity: Identity,
    pub via: MemberVia,
    /// Nested members when this member is itself a group and recursion is on
    /// (v2). Empty for direct-only enumeration and for non-group members.
    #[serde(default)]
    pub children: Vec<MemberNode>,
}

/// The reverse of [`MembershipReport`]: **who is in this group?** — the group
/// plus its members (users and subgroups). Read-only, no path/ACL/rights, same
/// scope discipline as the upward view. Rendered by the CLI `members` command
/// and the GUI Groups tab (direction "Members") from one shared structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMembersReport {
    /// The group whose members were enumerated.
    pub group: Identity,
    /// Direct members: those in `member` (`MemberVia::Direct`) plus those whose
    /// primary group is this group (`MemberVia::PrimaryGroup`). In v1 all nodes
    /// are direct; `children` is always empty.
    pub members: Vec<MemberNode>,
    /// Resolution-level markers (primary-group inclusion, incompleteness).
    pub diagnostics: Vec<PermissionDiagnostic>,
}

/// Shared CLI/GUI guard for the members view: `None` when `identity` is a
/// group, otherwise the operator-facing rejection message — worded once here
/// so both surfaces say the same thing. Unresolved kinds get a "could not be
/// resolved" wording instead of the cryptic "resolved to a Unknown"
/// (review 2026-07-03, finding F4).
pub fn members_view_rejection(identity: &Identity) -> Option<String> {
    let display = identity.name.as_deref().unwrap_or(identity.sid.0.as_str());
    match identity.kind {
        IdentityKind::Group => None,
        IdentityKind::Unknown | IdentityKind::Orphaned => Some(format!(
            "'{display}' could not be resolved as a group in the directory."
        )),
        ref kind => Some(format!(
            "'{display}' is a {kind:?}, not a group — the members view only applies to groups."
        )),
    }
}

impl GroupMembersReport {
    /// Count of direct members (top level), split by source — the headline the
    /// CLI/GUI show ("N members — M direct, K via primaryGroupID").
    pub fn direct_counts(&self) -> (usize, usize) {
        let via_primary = self
            .members
            .iter()
            .filter(|m| matches!(m.via, MemberVia::PrimaryGroup))
            .count();
        (self.members.len(), via_primary)
    }

    /// Members that are themselves a privileged group — a nested privileged
    /// group is as sensitive here as a privileged parent is in the upward view.
    pub fn privileged_members(&self) -> Vec<(&Sid, &'static str)> {
        self.members
            .iter()
            .filter_map(|m| {
                privileged_group_role(&m.identity.sid).map(|role| (&m.identity.sid, role))
            })
            .collect()
    }
}

/// ACE type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AceKind {
    Allow,
    Deny,
}

/// Single ACL entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AceEntry {
    pub kind: AceKind,
    pub sid: Sid,
    pub mask: AccessMask,
    pub inherited: bool,
    pub inheritance_flags: u32,
    pub propagation_flags: u32,
}

/// ACE type that cannot be fully interpreted by the parser.
///
/// Occurs with object, callback, or vendor-specific ACE types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsupportedAce {
    /// Raw value from ACE_HEADER.AceType.
    pub ace_type: u8,
    /// Raw value from ACE_HEADER.AceFlags.
    pub flags: u8,
    /// Access mask — for standard ACE types (0–15) Mask is immediately after the header.
    pub mask: u32,
}

/// Synthetic `ace_type` marking **"the ACL itself could not be read"** —
/// `GetAclInformation` failed, so not a single ACE could be enumerated
/// (fs_scanner review 2026-07-25, FS-1).
///
/// Recorded as one [`UnsupportedAce`] so the object is flagged incomplete
/// instead of presenting an unread ACL as a legitimately empty DACL (which
/// the model defines as "deny all" — an authoritative-looking wrong answer).
/// `0xFF` is not a valid Windows ACE type, so it cannot collide with a real
/// one.
///
/// Lives in the core model (moved from `fs_scanner` in the exporter review
/// 2026-07-26, EX-1) because consumers of [`UnsupportedAce`] — e.g. the
/// trustee report — must be able to distinguish "ACL unreadable" from
/// "N ACEs unevaluated" without coupling to a scanner implementation.
pub const ACE_TYPE_ACL_UNREADABLE: u8 = 0xFF;

/// Synthetic `ace_type` marking **"this single ACE could not be retrieved"**
/// — `GetAce` failed or returned null for an index inside `AceCount`
/// (fs_scanner review 2026-07-25, FS-2). Same rationale as
/// [`ACE_TYPE_ACL_UNREADABLE`]: a silently skipped Deny would over-report
/// access. `0xFE` is not a valid Windows ACE type.
pub const ACE_TYPE_ACE_UNREADABLE: u8 = 0xFE;

// Compile-time guarantee that the two synthetic markers stay distinct from
// each other and from every real Windows ACE type (those are small values,
// far below 0x40) — a read failure must never be reportable as a genuine
// unsupported ACE type. Enforced at build time rather than by a test.
const _: () = assert!(ACE_TYPE_ACL_UNREADABLE != ACE_TYPE_ACE_UNREADABLE);
const _: () = assert!(ACE_TYPE_ACL_UNREADABLE > 0x40 && ACE_TYPE_ACE_UNREADABLE > 0x40);

/// File system object (folder or file)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSystemObject {
    pub path: NormalizedPath,
    pub is_directory: bool,
    pub owner_sid: Option<Sid>,
    pub dacl: Vec<AceEntry>,
    pub inheritance_disabled: bool,
    pub is_reparse_point: bool,
    /// ACEs whose type is not supported by the parser (object, callback ACEs, etc.).
    #[serde(default)]
    pub unsupported_aces: Vec<UnsupportedAce>,
    /// `true` if the object's DACL is NULL. A NULL DACL means "no access
    /// control" (full access for everyone) — distinct from an empty DACL
    /// (`dacl` empty but `null_dacl == false`), which means "no access".
    #[serde(default)]
    pub null_dacl: bool,
    /// Stable hash of the raw security descriptor bytes, when known.
    /// Identical security descriptors (the common case for a directory
    /// tree that inherits one DACL from a shared parent) produce the same
    /// hash, which lets the **scanner** parse and evaluate each distinct
    /// descriptor only once per scan (engine review 2026-06-12 finding 2).
    ///
    /// Scope, stated honestly (engine review 2026-06-13 finding 2): this
    /// is currently a **scan-local** optimization only. The hash is *not*
    /// persisted — the database has no `sd_hash` column or descriptor
    /// table — so storage-level deduplication of identical explanation /
    /// ACE / diagnostic payloads across rows is **not yet implemented**.
    /// A future descriptor table keyed by this hash could add it; see
    /// `docs/known-limitations.md`.
    ///
    /// `None` when the object was constructed without a descriptor read.
    /// `#[serde(default)]` keeps older cache entries readable.
    #[serde(default)]
    pub sd_hash: Option<u64>,
}

/// SMB share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub name: String,
    pub unc_path: String,
    pub local_path: Option<NormalizedPath>,
    /// A system administrative share (`STYPE_SPECIAL`: `C$`, `ADMIN$`,
    /// `IPC$`, …) — the shares AGENTS.md wants hideable by default.
    pub is_admin_share: bool,
    /// The name ends in `$`, so the share is not listed when browsing the
    /// network. Independent of `is_admin_share`: a data share named `Data$`
    /// is hidden but NOT administrative, and must stay visible in an audit —
    /// a hidden, broadly granted data share is exactly what an auditor needs
    /// to see.
    #[serde(default)]
    pub is_hidden: bool,
}

/// Permission on a share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharePermission {
    pub share_name: String,
    pub sid: Sid,
    pub mask: AccessMask,
    pub kind: AceKind,
}

/// Evaluation status of the share DACL for a result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ShareEvalStatus {
    /// No SMB context requested — result shows NTFS permissions only (correct).
    #[default]
    NotApplicable,
    /// Share DACL successfully read and included in the calculation.
    Applied,
    /// Share DACL is NULL — no SMB-side restriction; the result matches the
    /// NTFS computation. Dedicated variant so the report does not surface a
    /// fake "special" share mask `0xFFFFFFFF`.
    Unrestricted,
    /// Share DACL read failed — result shows NTFS permissions only (potentially incomplete).
    ReadFailed(String),
}

/// Input state of the share side for a permission evaluation. Carries both
/// status and mask in the `Applied` case — prevents the ambiguous separation
/// between "no SMB context" and "share read failed", which both previously
/// looked like `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ShareMaskStatus {
    /// No SMB context — result is the NTFS permission only.
    #[default]
    NotApplicable,
    /// Share DACL was read; `mask` is the computed share mask.
    Applied(AccessMask),
    /// Share has a NULL DACL — semantically "no restriction over SMB". The
    /// effective computation must then come from NTFS only. Modeled separately
    /// from `Applied(0xFFFFFFFF)` to avoid confusing audit semantics with a
    /// real "special access" mask.
    Unrestricted,
    /// Share DACL read failed — effective_mask is uncertain and must be treated
    /// as incomplete downstream.
    ReadFailed(String),
}

/// Evaluation status of the local server group resolution for a result.
///
/// The target server's local-group SIDs belong to the Windows access token and
/// affect both NTFS and share evaluations. When resolution fails (access denied,
/// RPC errors, name lookup issues) those SIDs are missing from the token —
/// effective rights may then be too low.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum LocalGroupEvalStatus {
    /// Local groups were not requested (local path without target server, or
    /// identity without a usable account name).
    #[default]
    NotQueried,
    /// Resolution succeeded; SIDs are included in the token.
    Applied,
    /// Resolution failed; token is incomplete, result must be treated as
    /// incomplete downstream.
    NotAvailable(String),
}

/// Allow ACE that contributed at least one bit to the NTFS result.
///
/// `mask` contains only the bits of this ACE that appear in the final ntfs_raw
/// (ACE mask AND ntfs_raw), accumulated across all ACEs of the same SID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributingAce {
    pub sid: Sid,
    pub mask: AccessMask,
}

/// Normalized effective permission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectivePermission {
    pub identity: Identity,
    pub path: NormalizedPath,
    pub ntfs_mask: AccessMask,
    pub share_mask: Option<AccessMask>,
    /// More restrictive combination of NTFS and share
    pub effective_mask: AccessMask,
    pub path_explanation: PermissionPath,
    /// Share DACL evaluation status — set by the caller after the engine call.
    #[serde(default)]
    pub share_status: ShareEvalStatus,

    /// Evaluation status of the local server group resolution. `NotAvailable`
    /// marks the result as incomplete — risk findings derived from this
    /// permission should carry `incomplete = true`.
    #[serde(default)]
    pub local_group_status: LocalGroupEvalStatus,

    /// Allow ACEs that contributed at least one bit to the NTFS result, each with the subset
    /// of bits actually contributed.
    #[serde(default)]
    pub contributing_sids: Vec<ContributingAce>,

    /// Number of ACEs on this path whose type the parser could not evaluate.
    /// When this value is > 0, the DACL evaluation is potentially incomplete.
    #[serde(default)]
    pub unsupported_ace_count: usize,

    /// DACL entries whose trustee SID belongs to this identity's token SID set
    /// (own SID or a group SID). Structured ACE origin for risk rules — more robust
    /// than parsing the explanation text.
    #[serde(default)]
    pub matched_aces: Vec<AceEntry>,

    /// Structured diagnostic markers for this path. Captures findings relevant
    /// to an auditor but outside the pure rights result — e.g. a non-canonical
    /// DACL ordering that Windows evaluates in stored order (follow-up
    /// finding 3).
    #[serde(default)]
    pub diagnostics: Vec<PermissionDiagnostic>,
}

impl EffectivePermission {
    /// Whether the underlying evaluation has gaps, so the computed rights may
    /// be wrong — the share DACL could not be read, the DACL contained ACE
    /// types the parser could not evaluate, local server groups could not be
    /// resolved, or any attached diagnostic is an incompleteness trigger.
    ///
    /// Single source of truth: the risk engine flags derived findings
    /// `incomplete` through this, and the GUI uses it to decide whether a row
    /// is a warning (vs. only informational markers).
    pub fn is_incomplete(&self) -> bool {
        !self.uncertainty().is_empty()
    }

    /// Every reason why the shown result may differ from what Windows would
    /// compute, each tagged with the part it affects (ADR 0065). Empty means
    /// the result is exact. Derived from the stored statuses and markers, so
    /// persisted rows, exports and every frontend arrive at the same answer.
    pub fn uncertainty(&self) -> Vec<Uncertainty> {
        let mut out: Vec<Uncertainty> = Vec::new();
        if let ShareEvalStatus::ReadFailed(reason) = &self.share_status {
            out.push(Uncertainty {
                layer: UncertainLayer::Share,
                reason: format!("The share permissions could not be read ({reason})."),
            });
        }
        let has_ntfs_marker = self
            .diagnostics
            .iter()
            .any(|d| matches!(d, PermissionDiagnostic::UnsupportedNtfsAces { .. }));
        if self.unsupported_ace_count > 0 && !has_ntfs_marker {
            out.push(Uncertainty {
                layer: UncertainLayer::Ntfs,
                reason: format!(
                    "{} NTFS ACE(s) could not be evaluated — a hidden Deny among them could \
                     change the result.",
                    self.unsupported_ace_count
                ),
            });
        }
        if let LocalGroupEvalStatus::NotAvailable(reason) = &self.local_group_status {
            out.push(Uncertainty {
                layer: UncertainLayer::Token,
                reason: format!(
                    "The local groups of the target server could not be resolved ({reason}) — \
                     ACEs for local groups may apply to this identity."
                ),
            });
        }
        for d in &self.diagnostics {
            if let Some(layer) = d.uncertain_layer() {
                let reason = d.summary();
                if !out.iter().any(|u| u.reason == reason) {
                    out.push(Uncertainty { layer, reason });
                }
            }
        }
        out
    }

    /// The NTFS mask is exactly what Windows would compute: nothing makes
    /// the token or the NTFS walk uncertain.
    pub fn ntfs_determinable(&self) -> bool {
        !self
            .uncertainty()
            .iter()
            .any(|u| matches!(u.layer, UncertainLayer::Token | UncertainLayer::Ntfs))
    }

    /// The share mask is exactly what Windows would compute: nothing makes
    /// the token or the share evaluation uncertain.
    pub fn share_determinable(&self) -> bool {
        !self
            .uncertainty()
            .iter()
            .any(|u| matches!(u.layer, UncertainLayer::Token | UncertainLayer::Share))
    }

    /// The effective right is exactly what Windows would compute.
    pub fn effective_determinable(&self) -> bool {
        self.uncertainty().is_empty()
    }
}

/// Which part of a result an uncertainty affects (ADR 0065).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UncertainLayer {
    /// The evaluated token may lack SIDs — affects NTFS and share alike.
    Token,
    /// The NTFS DACL could not be evaluated completely.
    Ntfs,
    /// The share DACL could not be evaluated completely.
    Share,
}

/// One reason why a result is not determinable, as stated to a reader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Uncertainty {
    pub layer: UncertainLayer,
    pub reason: String,
}

/// Structured diagnostic marker attached to an effective permission.
/// Variant-tagged JSON serialization so future markers can be added without
/// breaking persisted data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum PermissionDiagnostic {
    /// The path's DACL is not in Windows-canonical order
    /// (explicit-deny → explicit-allow → inherited-deny → inherited-allow).
    /// The engine evaluates it in stored order — matches Windows
    /// `AccessCheck`, but may differ from canonicalized expectations.
    /// `at_index` is the index of the first ACE that breaks the order.
    NonCanonicalDaclOrder { at_index: usize },

    /// The share-side DACL parser skipped ACE types (e.g. object,
    /// callback or vendor-specific ACEs). The share mask is therefore
    /// potentially incomplete — risk findings for this permission must
    /// carry `incomplete = true`. `count` is the number of skipped
    /// share ACEs.
    ///
    /// The NTFS counterpart (`unsupported_ace_count` on
    /// `EffectivePermission`) has existed for a while; this marker is
    /// the mirror-image for the share side (follow-up finding 2 from
    /// the 2026-05-25 review).
    UnsupportedShareAces { count: usize },

    /// The NTFS DACL parser could not fully evaluate `count` ACEs. Two
    /// causes are counted together, because their audit effect is identical
    /// (an un-evaluated ACE that a hidden Deny could hide behind): an ACE
    /// **type** the parser cannot interpret (object, callback, conditional /
    /// Dynamic Access Control, or vendor-specific), and a **supported**
    /// Allow/Deny ACE whose trustee **SID could not be read** (review
    /// finding F1), an ACE that **could not be retrieved** at all, or a
    /// **DACL that could not be read** (fs_scanner review FS-1/FS-2) — each
    /// was previously dropped silently. A hidden
    /// Deny among them could materially change the result, so the displayed
    /// effective permission is a **lower-confidence approximation** — risk
    /// findings for this permission carry `incomplete = true`. `count` is
    /// the number of un-evaluated NTFS ACEs.
    ///
    /// This is the structured, first-class counterpart to the raw
    /// `unsupported_ace_count` on `EffectivePermission`, mirroring
    /// `UnsupportedShareAces` for the NTFS side (engine review
    /// 2026-06-12 finding 3): the gap is now surfaced uniformly through
    /// the diagnostics list in every output, not only as a bare count.
    UnsupportedNtfsAces { count: usize },

    ///
    /// Closes ChatGPT code review 2026-06-04 finding 6.
    ///
    /// Group resolution runs through the SAM/LSA fallback (no LDAP) and
    /// therefore through `NetUserGetGroups`. That API only returns
    /// **direct** global groups — nested domain groups are not resolved
    /// recursively without LDAP, and local groups are only mediated via
    /// already-known direct members. The token SID set can be incomplete
    /// and ACEs targeting deeply nested domain groups may be missed.
    /// Risk findings for this permission must carry `incomplete = true`.
    ///
    /// Closes ChatGPT code review 2026-06-04 finding 6.
    DomainGroupRecursionIncomplete,

    /// Closes ChatGPT code review 2026-06-04 finding 7.
    ///
    /// The analyzed identity is flagged as disabled in AD
    /// (`userAccountControl` bit `ACCOUNTDISABLE`, 0x0002). The computed
    /// rights are **ACL-theoretically correct** — but `disabled`
    /// accounts normally **cannot authenticate** and cannot access SMB.
    /// To prevent an audit reader from confusing this theoretical right
    /// with a real right, this marker appears on every result for a
    /// disabled identity.
    ///
    /// Closes ChatGPT code review 2026-06-04 finding 7.
    IdentityDisabled,

    ///
    /// ChatGPT code review 2026-06-04 round 2 finding 1.
    ///
    /// The analyzed identity was unambiguously resolved to a SID via LSA
    /// (`LookupAccountNameW` for `DOMAIN\user`), **but the configured
    /// LDAP `base_dn` does not index that SID** — typical in
    /// multi-domain forests, trust relationships or AD migrations. The
    /// identity is **real**, but domain group recursion runs without
    /// LDAP — the token SID set can be incomplete and ACEs targeting
    /// deeply nested domain groups are missed. Risk findings for this
    /// permission must carry `incomplete = true`.
    ///
    /// Before this marker `IdentityKind::Orphaned` would have been used
    /// — a real user from a trusted domain would have been
    /// mis-classified as a stale SID. Closes ChatGPT code review
    /// 2026-06-04 round 2 finding 1.
    IdentityNotInConfiguredLdapBase,

    ///
    ///
    /// The analyzed identity was resolved via LSA, but its
    /// `userAccountControl` (whether the account is disabled) could not
    /// be determined — typical for the SAM/LSA path without LDAP when
    /// `NetUserGetInfo` fails for non-local accounts or with
    /// `ERROR_ACCESS_DENIED`. The computed rights are ACL-theoretically
    /// correct, but Stars cannot decide whether the account can
    /// authenticate at all. The marker is not an incompleteness trigger
    /// — it only signals a knowledge gap about the account state.
    ///
    /// Closes ChatGPT code review 2026-06-04 round 2 finding 5.
    IdentityDisabledStatusUnknown,

    /// `incomplete = true` ausgewiesen.
    ///
    ///
    /// The LDAP identity lookup failed with a technical error (bind,
    /// timeout, DC unreachable, query error). Stars returns a
    /// placeholder identity and continues the evaluation — but the
    /// token SID set is structurally incomplete. This marker is an
    /// incompleteness trigger; derived risk findings are flagged
    /// `incomplete = true`.
    ///
    /// Closes ChatGPT code review 2026-06-04 round 4 finding 1.
    IdentityLookupFailed { reason: String },

    /// Recursive group resolution failed or was skipped. ACEs on
    /// domain groups may be missed — this marker is an incompleteness
    /// trigger.
    ///
    /// Closes ChatGPT code review 2026-06-04 round 4 finding 1.
    GroupResolutionFailed { reason: String },

    /// The DACL contains at least one ACE for the well-known SID
    /// `S-1-3-4` ("OWNER RIGHTS") **and** the analyzed identity is the
    /// owner of the object. Per Windows semantics (Server 2008+), the
    /// OWNER RIGHTS entries replace the implicit owner grant of
    /// `READ_CONTROL + WRITE_DAC` — the engine therefore evaluated the
    /// S-1-3-4 ACEs in DACL order instead of applying the implicit
    /// grant. This marker is informational, not an incompleteness
    /// trigger: the evaluation is exact, the marker only surfaces that
    /// the unusual owner-rights mechanism was in play so an auditor
    /// does not expect the implicit owner bonus.
    ///
    /// Engine review 2026-06-09 finding 1.
    OwnerRightsAceApplied,

    /// The analyzed identity is a principal from a trusted forest whose
    /// SID was found as a **Foreign Security Principal** object
    /// (`CN=ForeignSecurityPrincipals,…`) in the configured home domain.
    /// Home-domain group memberships were resolved through the FSP
    /// object — but the trust domain itself was not queried, so the
    /// principal's memberships **in its own forest** are unknown. The
    /// token SID set can be incomplete; risk findings for this
    /// permission must carry `incomplete = true`.
    ///
    /// Closes known-limitations entry L1 (engine review 2026-06-09 /
    /// v1.6 work package).
    IdentityResolvedViaForeignSecurityPrincipal,

    /// Group memberships were resolved through a **Global Catalog**
    /// bind (port 3269/3268). The GC indexes identities forest-wide,
    /// but only **universal** group memberships replicate completely
    /// to the GC — global and domain-local memberships of foreign
    /// domains can be missing from the token. Risk findings for this
    /// permission must carry `incomplete = true`.
    ///
    /// Closes known-limitations entry L2 (v1.6 work package).
    GroupResolutionViaGlobalCatalog,

    /// A persisted scan row could not be decoded faithfully when read
    /// back from the database: an optional JSON evidence field (e.g. the
    /// stored diagnostics list) failed to parse, or a stored status value
    /// was not recognized. Rather than silently substituting an empty
    /// list or a normal-looking default — which would make damaged
    /// historical evidence look cleaner and more complete than it is —
    /// the reconstructed permission carries this marker so reports and
    /// the risk engine treat it as incomplete. `detail` names what could
    /// not be decoded. Required evidence fields (the explanation,
    /// contributing SIDs, matched ACEs) are not defaulted at all — a
    /// decode failure there is a hard database error. Engine review
    /// 2026-06-13 (Codex) finding 3.
    PersistedEvidenceDecodeFailed { detail: String },

    /// The analyzed identity carries historical SIDs (`sIDHistory`) that
    /// were **not evaluated** into the token. Since ADR 0056 parsed values
    /// *are* evaluated (see [`SidHistoryEvaluated`]), so this marker now
    /// covers only the un-evaluated remainder: values that could not be
    /// parsed, and rows persisted under ADR 0052 where values were never
    /// fetched. The real Windows logon token includes those SIDs, so an
    /// ACE granting access to one of them is not matched and the effective
    /// right can be **understated** ("looks safe, isn't safe"). This
    /// marker is an incompleteness trigger; derived risk findings carry
    /// `incomplete = true`. `count` is the number of un-evaluated
    /// historical SIDs.
    ///
    /// [`SidHistoryEvaluated`]: PermissionDiagnostic::SidHistoryEvaluated
    SidHistoryPresent { count: usize },

    /// `count` historical SIDs (`sIDHistory`) of the analyzed identity
    /// **were evaluated** into the token (ADR 0056): within the account's
    /// forest Windows includes them in the real logon token
    /// unconditionally, so ACEs referencing an old SID now match exactly
    /// as `AccessCheck` would. Informational, **not** an incompleteness
    /// trigger — it exists so the token composition change is never
    /// silent: an ACE matching an unfamiliar SID is explained here and in
    /// the explanation path. Note: only identities resolved on the direct
    /// in-base LDAP path carry history values; cross-boundary identities
    /// (FSP / outside base) keep their own markers instead — see
    /// [`TrustBoundaryEffectsNotModeled`].
    ///
    /// [`TrustBoundaryEffectsNotModeled`]:
    /// PermissionDiagnostic::TrustBoundaryEffectsNotModeled
    SidHistoryEvaluated { count: usize },

    /// `count` historical SIDs (`sIDHistory`) carried by `groups` of the
    /// token **groups** were evaluated into the token (ADR 0059): the
    /// Windows PAC includes the history SIDs of the token groups, so ACEs
    /// referencing a migrated group's old SID now match like at runtime.
    /// Informational, **not** an incompleteness trigger — the membership
    /// steps in the explanation path name each historical SID. The same
    /// forest-scope caveat as for the user's history applies (L4 /
    /// verification.md M.5).
    GroupSidHistoryEvaluated { groups: usize, count: usize },

    /// `count` historical SIDs (`sIDHistory`) on token **groups** could
    /// **not** be evaluated (malformed values). The real token includes
    /// them, so ACEs on those old group SIDs are not matched and the
    /// effective right can be understated. Incompleteness trigger;
    /// derived risk findings carry `incomplete = true` (ADR 0059).
    GroupSidHistoryPresent { count: usize },

    /// The analyzed identity was resolved **across a domain or trust
    /// boundary** — either via a Foreign Security Principal object (a
    /// principal from a trusted external/forest domain) or via LSA because
    /// it lies outside the configured LDAP base (another domain, possibly in
    /// another forest). Stars computes effective rights assuming every SID
    /// passes and that authentication is allowed. **If that boundary is a
    /// forest trust**, the DC may apply **SID filtering / quarantine**
    /// (dropping SIDs, which lowers access) and **Selective Authentication**
    /// (blocking the logon before the ACL is evaluated at all). Stars does
    /// not read trust attributes, so for a cross-forest identity the shown
    /// access can be **higher** than the runtime result ("over-report").
    /// (For a purely intra-forest cross-domain identity those filters usually
    /// do not apply, so the marker is then only a precautionary note.) This
    /// marker is informational: it fires alongside the FSP / outside-base
    /// markers, which already set `incomplete = true`, so it deliberately
    /// does **not** raise a second incompleteness trigger. See ADR 0052.
    TrustBoundaryEffectsNotModeled,

    /// The group-members view (reverse direction) included `count` members
    /// found via their **`primaryGroupID`** — accounts whose primary group is
    /// this group and which therefore do **not** appear in the `member`
    /// attribute (classically every user for Domain Users). This marker makes
    /// the *inclusion* transparent so the number is trusted; it is **not** an
    /// incompleteness trigger (those members were found, not missed). Neutral.
    MembersViaPrimaryGroupIncluded { count: usize },

    /// The group-members view could not enumerate the group's members
    /// completely — e.g. an LDAP page/read failed partway. Rather than
    /// presenting a short list as if it were the whole group, the report
    /// carries this trigger so the count is treated as a lower bound.
    /// `reason` names what went wrong. Incompleteness trigger; Concern.
    GroupMemberEnumerationIncomplete { reason: String },

    /// The enumerated group is a **universal** group queried over a plain
    /// domain bind: members from *other* domains of the forest live in other
    /// directory partitions and are not visible from this bind, so the list
    /// may be incomplete in a multi-domain forest (in a single-domain forest
    /// this is only a formal caveat). The upward view marks the equivalent
    /// boundary (Global Catalog / outside-base); this is the downward
    /// counterpart. Incompleteness trigger, but Neutral — an expected
    /// bind-scope caveat, not an error (ADR 0055, review 2026-07-03 F2).
    UniversalGroupCrossDomainMembersNotVisible,

    /// The analyzed SID could not be resolved — no object under the
    /// configured LDAP base, not resolvable by the local LSA — and the
    /// available evidence does **not** show that the account no longer
    /// exists: the SID belongs to a trusted or another domain, or the
    /// configured base covers only part of the domain, or the domain could
    /// not be determined. `reason` says which. The account's group
    /// memberships are unknown, so the rights computed for the bare SID can
    /// be too low or too high. Before ADR 0064 such SIDs were reported as
    /// `Orphaned` with a confident result (lab finding AD3-1).
    /// Incompleteness trigger; Concern.
    IdentityNotResolvable { reason: String },

    /// The SID belongs to the configured domain, the configured base covers
    /// that whole domain, and the directory has no object for it: the
    /// account no longer exists (orphaned / deleted). Nobody can log on with
    /// this SID; the rights shown are what a logon with it would get, and an
    /// ACE naming it is a dead entry. Informational (ADR 0064).
    IdentityOrphaned,

    /// The DACL has applicable ACEs for well-known SIDs whose presence in
    /// the real token depends on how the user logs on — This Organization,
    /// authentication assertion or package (NTLM / SChannel / Digest),
    /// remote-interactive or console logon, local account — and those ACEs
    /// decide bits of this result. Stars does not model them, so the NTFS
    /// right lies between `min_mask` and `max_mask` (inclusive bounds; the
    /// shown mask treats them as absent). Until ADR 0065 such ACEs were
    /// silently treated as not applying. Incompleteness trigger; Notice.
    LogonDependentTrustees {
        sids: Vec<String>,
        min_mask: u32,
        max_mask: u32,
    },

    /// The group resolution succeeded, but `reason` names groups that may be
    /// missing from the evaluated token: a primary group that could not be
    /// read, a group entry without a readable SID, memberships in groups
    /// outside the resolved set (e.g. outside the configured LDAP base), a
    /// `memberOf` list that could not be read completely, or a local group
    /// whose SID could not be looked up. Before ADR 0066 these cases were
    /// dropped silently. Incompleteness trigger; Concern.
    GroupResolutionIncomplete { reason: String },
}

/// Account state as it may be stated to a reader — the single source for
/// every "Status" line and the CSV `disabled` column, so no surface claims
/// "Active" when the state is unknown (lab finding AD3-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    /// Account known to be enabled.
    Active,
    /// Account known to be disabled.
    Disabled,
    /// Account exists (or may exist), but its state could not be read.
    Unknown,
    /// Not an account (group, well-known principal) — no enabled state.
    NotAnAccount,
    /// The SID has no account any more (orphaned).
    DoesNotExist,
}

impl AccountStatus {
    /// Derives the status from the identity and the diagnostics attached to
    /// the result or report. A `disabled = false` flag counts as "Active"
    /// only when no marker says the state is unknown and the identity was
    /// actually resolved.
    pub fn of(identity: &Identity, diagnostics: &[PermissionDiagnostic]) -> Self {
        match identity.kind {
            IdentityKind::Orphaned => return AccountStatus::DoesNotExist,
            IdentityKind::Group | IdentityKind::WellKnown => return AccountStatus::NotAnAccount,
            IdentityKind::Unknown => return AccountStatus::Unknown,
            _ => {}
        }
        if diagnostics.iter().any(|d| {
            matches!(
                d,
                PermissionDiagnostic::IdentityDisabledStatusUnknown
                    | PermissionDiagnostic::IdentityNotResolvable { .. }
                    | PermissionDiagnostic::IdentityLookupFailed { .. }
            )
        }) {
            return AccountStatus::Unknown;
        }
        if identity.disabled {
            AccountStatus::Disabled
        } else {
            AccountStatus::Active
        }
    }

    /// Human-readable label for status lines.
    pub fn label(&self) -> &'static str {
        match self {
            AccountStatus::Active => "Active",
            AccountStatus::Disabled => "DISABLED",
            AccountStatus::Unknown => "unknown (could not be determined)",
            AccountStatus::NotAnAccount => "n/a (not an account)",
            AccountStatus::DoesNotExist => "does not exist (orphaned SID)",
        }
    }

    /// Value of the CSV `disabled` column: `true`/`false` only when known.
    pub fn csv_value(&self) -> &'static str {
        match self {
            AccountStatus::Active => "false",
            AccountStatus::Disabled => "true",
            AccountStatus::Unknown => "unknown",
            AccountStatus::NotAnAccount | AccountStatus::DoesNotExist => "n/a",
        }
    }
}

/// **Visual attention** of a [`PermissionDiagnostic`] — "do I need to look?".
/// Deliberately decoupled from [`PermissionDiagnostic::is_incompleteness_trigger`]
/// (the *correctness* flag): an expected caveat such as the SAM/LSA fallback is
/// still an incompleteness trigger, but should not raise visual alarm.
///
/// - `Neutral` — correct, or expected context; no action implied (grey).
/// - `Notice` — worth a look (amber).
/// - `Concern` — likely a real gap / under-report (orange-red).
///
/// Single source of truth for the marker colour in the GUI and HTML report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticSeverity {
    Neutral,
    Notice,
    Concern,
}

impl PermissionDiagnostic {
    /// Concise, single-line, auditor-readable reason for this diagnostic.
    ///
    /// This is the **single source of truth** for the short human-readable
    /// form of a diagnostic, intended for compact surfaces such as the GUI
    /// scan-row detail or a tooltip. It is deliberately one sentence: the
    /// CLI (`cli::output`) and the HTML report keep their own richer,
    /// multi-line / badge presentations, but they all describe the same
    /// underlying markers. Returning an owned `String` because the variants
    /// carrying `count`/`reason`/`detail` need interpolation.
    pub fn summary(&self) -> String {
        match self {
            PermissionDiagnostic::NonCanonicalDaclOrder { at_index } => format!(
                "Non-canonical DACL order (first at ACE #{at_index}); evaluated in \
                 stored order like Windows, may differ from canonical expectations."
            ),
            PermissionDiagnostic::UnsupportedShareAces { count } => format!(
                "{count} share ACE(s) could not be evaluated (unsupported type, unreadable \
                 trustee, or a trustee whose presence depends on how the user logs on) — \
                 the share mask is potentially incomplete."
            ),
            PermissionDiagnostic::UnsupportedNtfsAces { count } => format!(
                "{count} NTFS ACE(s) could not be evaluated (unsupported type, an \
                 unreadable trustee SID, or a DACL that could not be read at all) — a \
                 hidden Deny among them could change the result."
            ),
            PermissionDiagnostic::DomainGroupRecursionIncomplete => {
                "Group resolution used the SAM/LSA fallback (no LDAP); nested domain \
                 groups are not resolved recursively, ACEs on them may be missed."
                    .to_owned()
            }
            PermissionDiagnostic::IdentityDisabled => {
                "Identity is flagged disabled in AD — rights are ACL-theoretically \
                 correct, but the account normally cannot authenticate."
                    .to_owned()
            }
            PermissionDiagnostic::IdentityNotInConfiguredLdapBase => {
                "Identity resolved via LSA but the configured LDAP base DN does not index \
                 its SID; cross-domain nested memberships may be missing."
                    .to_owned()
            }
            PermissionDiagnostic::IdentityDisabledStatusUnknown => {
                "The disabled flag for this identity could not be determined — rights are \
                 correct, but whether the account is enabled is unknown."
                    .to_owned()
            }
            PermissionDiagnostic::IdentityLookupFailed { reason } => format!(
                "LDAP identity lookup failed ({reason}); analysis ran with a placeholder \
                 identity, ACEs on domain groups may be missing."
            ),
            PermissionDiagnostic::GroupResolutionFailed { reason } => format!(
                "Recursive group resolution failed or was skipped ({reason}); ACEs on \
                 domain groups may be missing."
            ),
            PermissionDiagnostic::OwnerRightsAceApplied => {
                "OWNER RIGHTS (S-1-3-4) ACE governs the owner's rights; the implicit \
                 READ_CONTROL + WRITE_DAC owner grant was suppressed. Exact — informational."
                    .to_owned()
            }
            PermissionDiagnostic::IdentityResolvedViaForeignSecurityPrincipal => {
                "Identity is a trust-forest principal resolved via a Foreign Security \
                 Principal; its memberships in its own forest are unknown."
                    .to_owned()
            }
            PermissionDiagnostic::GroupResolutionViaGlobalCatalog => {
                "Memberships came from a Global Catalog bind; only universal groups \
                 replicate fully to the GC, foreign-domain global/domain-local may be missing."
                    .to_owned()
            }
            PermissionDiagnostic::PersistedEvidenceDecodeFailed { detail } => format!(
                "A persisted (historical) row could not be fully decoded ({detail}); the \
                 reconstructed result may be less complete than the original."
            ),
            PermissionDiagnostic::SidHistoryPresent { count } => format!(
                "Identity carries {count} historical SID(s) (sIDHistory) that were NOT \
                 evaluated into the token — effective rights may be understated."
            ),
            PermissionDiagnostic::SidHistoryEvaluated { count } => format!(
                "{count} historical SID(s) (sIDHistory) of this identity were evaluated \
                 into the token — ACEs referencing an old SID match like in the real \
                 logon token (see the explanation path)."
            ),
            PermissionDiagnostic::GroupSidHistoryEvaluated { groups, count } => format!(
                "{count} historical SID(s) (sIDHistory) carried by {groups} token group(s) \
                 were evaluated into the token — ACEs referencing a migrated group's old \
                 SID match like in the real logon token (see the membership steps)."
            ),
            PermissionDiagnostic::GroupSidHistoryPresent { count } => format!(
                "{count} historical SID(s) (sIDHistory) on token groups could NOT be \
                 evaluated into the token — effective rights may be understated."
            ),
            PermissionDiagnostic::TrustBoundaryEffectsNotModeled => {
                "Identity resolved across a domain/trust boundary; if it is a forest trust, \
                 SID filtering and Selective Authentication may reduce actual access (not modeled)."
                    .to_owned()
            }
            PermissionDiagnostic::MembersViaPrimaryGroupIncluded { count } => format!(
                "{count} member(s) were found via their primaryGroupID — accounts whose \
                 primary group is this group do not appear in the 'member' attribute and are \
                 included here so the count is complete."
            ),
            PermissionDiagnostic::GroupMemberEnumerationIncomplete { reason } => format!(
                "Group members could not be enumerated completely ({reason}); the member list \
                 is a lower bound and may be missing entries."
            ),
            PermissionDiagnostic::UniversalGroupCrossDomainMembersNotVisible => {
                "This is a universal group queried over a domain bind — members from other \
                 domains of the forest are not visible here, so in a multi-domain forest the \
                 list may be incomplete."
                    .to_owned()
            }
            PermissionDiagnostic::IdentityNotResolvable { reason } => format!(
                "The identity could not be resolved: {reason}. Its group memberships are \
                 unknown, so the rights computed for the bare SID can be too low or too high."
            ),
            PermissionDiagnostic::IdentityOrphaned => {
                "The SID has no account in its domain any more (orphaned / deleted account): \
                 nobody can log on with it. The rights shown are what a logon with this SID \
                 would get; an ACE naming it is a dead entry."
                    .to_owned()
            }
            PermissionDiagnostic::LogonDependentTrustees {
                sids,
                min_mask,
                max_mask,
            } => format!(
                "ACE(s) for {} apply only for certain logons (authentication type, \
                 organization, logon type), which Stars does not model — the NTFS right \
                 lies between 0x{min_mask:08X} and 0x{max_mask:08X}.",
                sids.join(", ")
            ),
            PermissionDiagnostic::GroupResolutionIncomplete { reason } => {
                format!("Group resolution is incomplete: {reason}.")
            }
        }
    }

    /// Whether this diagnostic means the computed rights may be **wrong /
    /// incomplete** (the *correctness* flag), consumed by
    /// `EffectivePermission::is_incomplete` and the risk engine. Deliberately
    /// **independent** of [`Self::severity`]: an expected caveat (e.g. the
    /// SAM/LSA fallback) is an incompleteness trigger yet visually `Neutral`.
    ///
    /// Exhaustive `match` on purpose, exactly like [`Self::severity`]
    /// (core review 2026-07-25, C-2): a new variant must be classified
    /// deliberately — with a `matches!` list it would silently default to
    /// "complete", the looks-safe-isn't-safe failure mode.
    pub fn is_incompleteness_trigger(&self) -> bool {
        self.uncertain_layer().is_some()
    }

    /// Which part of a result this diagnostic makes **not determinable** —
    /// `None` when the result stays exact. The single source of truth behind
    /// [`Self::is_incompleteness_trigger`] and
    /// [`EffectivePermission::uncertainty`] (ADR 0065), so "incomplete" and
    /// "not determinable" can never disagree. Exhaustive on purpose (core
    /// review C-2): a new variant must be classified deliberately.
    pub fn uncertain_layer(&self) -> Option<UncertainLayer> {
        match self {
            // The share mask may be wrong.
            PermissionDiagnostic::UnsupportedShareAces { .. } => Some(UncertainLayer::Share),
            // The NTFS walk may be wrong.
            PermissionDiagnostic::UnsupportedNtfsAces { .. }
            | PermissionDiagnostic::LogonDependentTrustees { .. } => Some(UncertainLayer::Ntfs),
            // The evaluated token may lack SIDs (or the whole record is
            // damaged) — affects the NTFS and the share evaluation alike.
            PermissionDiagnostic::DomainGroupRecursionIncomplete
            | PermissionDiagnostic::IdentityNotInConfiguredLdapBase
            | PermissionDiagnostic::IdentityLookupFailed { .. }
            | PermissionDiagnostic::GroupResolutionFailed { .. }
            | PermissionDiagnostic::IdentityResolvedViaForeignSecurityPrincipal
            | PermissionDiagnostic::GroupResolutionViaGlobalCatalog
            | PermissionDiagnostic::PersistedEvidenceDecodeFailed { .. }
            | PermissionDiagnostic::SidHistoryPresent { .. }
            | PermissionDiagnostic::GroupSidHistoryPresent { .. }
            | PermissionDiagnostic::GroupMemberEnumerationIncomplete { .. }
            | PermissionDiagnostic::UniversalGroupCrossDomainMembersNotVisible
            | PermissionDiagnostic::IdentityNotResolvable { .. }
            | PermissionDiagnostic::GroupResolutionIncomplete { .. } => Some(UncertainLayer::Token),
            // Informational — the result itself is exact.
            PermissionDiagnostic::NonCanonicalDaclOrder { .. }
            | PermissionDiagnostic::IdentityDisabled
            | PermissionDiagnostic::IdentityDisabledStatusUnknown
            | PermissionDiagnostic::OwnerRightsAceApplied
            | PermissionDiagnostic::TrustBoundaryEffectsNotModeled
            | PermissionDiagnostic::SidHistoryEvaluated { .. }
            | PermissionDiagnostic::GroupSidHistoryEvaluated { .. }
            | PermissionDiagnostic::MembersViaPrimaryGroupIncluded { .. }
            | PermissionDiagnostic::IdentityOrphaned => None,
        }
    }

    /// Visual attention — the single source of truth for marker colour (GUI /
    /// HTML). "Do I need to look?" rather than "is it incomplete?". Exhaustive
    /// so a new variant must be classified deliberately.
    pub fn severity(&self) -> DiagnosticSeverity {
        match self {
            // Correct or expected context — no action, grey.
            PermissionDiagnostic::NonCanonicalDaclOrder { .. }
            | PermissionDiagnostic::IdentityDisabled
            | PermissionDiagnostic::IdentityDisabledStatusUnknown
            | PermissionDiagnostic::OwnerRightsAceApplied
            | PermissionDiagnostic::TrustBoundaryEffectsNotModeled
            | PermissionDiagnostic::DomainGroupRecursionIncomplete
            | PermissionDiagnostic::IdentityNotInConfiguredLdapBase
            | PermissionDiagnostic::IdentityResolvedViaForeignSecurityPrincipal
            | PermissionDiagnostic::MembersViaPrimaryGroupIncluded { .. }
            | PermissionDiagnostic::UniversalGroupCrossDomainMembersNotVisible
            | PermissionDiagnostic::SidHistoryEvaluated { .. }
            | PermissionDiagnostic::GroupSidHistoryEvaluated { .. }
            | PermissionDiagnostic::GroupResolutionViaGlobalCatalog
            | PermissionDiagnostic::IdentityOrphaned => DiagnosticSeverity::Neutral,
            // Worth a look — a hidden Deny among skipped ACEs could change the
            // result.
            PermissionDiagnostic::UnsupportedShareAces { .. }
            | PermissionDiagnostic::UnsupportedNtfsAces { .. }
            | PermissionDiagnostic::LogonDependentTrustees { .. } => DiagnosticSeverity::Notice,
            // Likely a real gap — under-report or a hard resolution failure.
            PermissionDiagnostic::SidHistoryPresent { .. }
            | PermissionDiagnostic::GroupSidHistoryPresent { .. }
            | PermissionDiagnostic::IdentityLookupFailed { .. }
            | PermissionDiagnostic::GroupResolutionFailed { .. }
            | PermissionDiagnostic::GroupMemberEnumerationIncomplete { .. }
            | PermissionDiagnostic::PersistedEvidenceDecodeFailed { .. }
            | PermissionDiagnostic::IdentityNotResolvable { .. }
            | PermissionDiagnostic::GroupResolutionIncomplete { .. } => DiagnosticSeverity::Concern,
        }
    }
}

/// Explainable permission path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionPath {
    pub steps: Vec<String>,
}

/// Scan result of a single run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRun {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub target: String,
    pub errors: Vec<ScanError>,
}

/// Error during a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    pub path: Option<NormalizedPath>,
    pub message: String,
}

/// Layer of a trustee entry in the path-centric view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrusteeCategory {
    /// NTFS DACL of the object.
    Ntfs,
    /// SMB share DACL of the surrounding share.
    Share,
}

/// A path-centric ACE entry with raw data — no display formatting. Render
/// code (GUI / HTML / CSV) derives its own representation from this.
/// Answers the audit question "who can access X at all?" identity-free.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathTrustee {
    /// Trustee SID — primary technical identity (cf. AGENTS.md).
    pub sid: Sid,
    /// Readable name (`DOMAIN\Name`) when resolved. `None` does not mean
    /// "does not exist" — it means "not resolved". Exporters should fall
    /// back to the SID display in that case.
    #[serde(default)]
    pub display_name: Option<String>,
    pub kind: AceKind,
    pub mask: AccessMask,
    pub inherited: bool,
    pub inheritance_flags: u32,
    pub propagation_flags: u32,
    pub category: TrusteeCategory,
}

/// Entry in the path-centric trustee list — either a real ACE or a
/// diagnostic hint (for example "share DACL could not be read",
/// "NULL DACL detected"). Before review round 10 diagnostic hints
/// were modelled as synthetic `PathTrustee` records with `kind = Allow`
/// and empty SID — misleading for JSON consumers because the
/// diagnostic looked like a real Allow ACE. With the enum the
/// distinction is typed and visible in the JSON output via the tag
/// (`"kind": "ace"` vs. `"kind": "diagnostic"`).
// The discriminator is deliberately named `entry_kind`, NOT `kind`.
// Reason: `PathTrustee` carries a field `kind: AceKind` (Allow/Deny).
// An internally-tagged enum with `tag = "kind"` would silently
// overwrite that field name in JSON (Serde does not raise a compile
// error here). A dedicated tag name avoids the collision.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "entry_kind", rename_all = "snake_case")]
pub enum PathTrusteeEntry {
    /// A real ACE from the DACL.
    Ace(PathTrustee),
    /// A diagnostic hint. `category` says which layer (NTFS or share)
    /// it refers to; `message` carries the auditor-readable reason.
    Diagnostic {
        category: TrusteeCategory,
        message: String,
    },
}

impl PathTrusteeEntry {
    /// Helper: returns the `TrusteeCategory` regardless of the variant.
    /// Render code does not need to match itself.
    pub fn category(&self) -> TrusteeCategory {
        match self {
            PathTrusteeEntry::Ace(ace) => ace.category,
            PathTrusteeEntry::Diagnostic { category, .. } => *category,
        }
    }

    /// Constructor for diagnostic hints.
    pub fn diagnostic(category: TrusteeCategory, message: impl Into<String>) -> Self {
        PathTrusteeEntry::Diagnostic {
            category,
            message: message.into(),
        }
    }
}

/// Per-path trustee listing: path → list of its ACEs and diagnostic hints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathTrustees {
    pub path: NormalizedPath,
    pub trustees: Vec<PathTrusteeEntry>,
}

/// Risk finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFinding {
    pub rule_id: String,
    pub severity: RiskSeverity,
    pub description: String,
    pub affected_path: Option<NormalizedPath>,
    pub affected_identity: Option<Sid>,
    /// `true` if the underlying permission evaluation was incomplete (e.g.
    /// share DACL not readable). Consumers should treat the finding cautiously.
    #[serde(default)]
    pub incomplete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Direction of an Active Directory domain/forest trust (`trustDirection`,
/// MS-ADTS 6.1.6.7.12). Read-only inventory data (L4); Stars never changes a
/// trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustDirection {
    /// The trust object exists but is disabled (0).
    Disabled,
    /// Inbound only (1): the *other* domain trusts this one.
    Inbound,
    /// Outbound only (2): this domain trusts the other.
    Outbound,
    /// Two-way (3).
    Bidirectional,
    /// A value outside the documented 0–3 range; the raw code is preserved.
    Unknown(u32),
}

impl TrustDirection {
    /// Maps the raw `trustDirection` code to the enum.
    pub fn from_code(code: u32) -> Self {
        match code {
            0 => Self::Disabled,
            1 => Self::Inbound,
            2 => Self::Outbound,
            3 => Self::Bidirectional,
            other => Self::Unknown(other),
        }
    }

    /// Short human-readable label for the read-only report.
    pub fn label(&self) -> String {
        match self {
            Self::Disabled => "disabled".to_string(),
            Self::Inbound => "inbound".to_string(),
            Self::Outbound => "outbound".to_string(),
            Self::Bidirectional => "bidirectional".to_string(),
            Self::Unknown(c) => format!("unknown ({c})"),
        }
    }
}

/// Parsed `trustAttributes` bitmask (MS-ADTS 6.1.6.7.9). Read-only inventory
/// data (L4): Stars surfaces these so an auditor can see whether a trust is
/// configured to filter SIDs or gate authentication, but it deliberately does
/// **not** model the runtime effect — that would require a synthetic logon,
/// which violates the read-only principle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TrustAttributes {
    /// The raw bitmask, preserved so nothing is lost.
    pub raw: u32,
}

impl TrustAttributes {
    // MS-ADTS trustAttributes flag values.
    pub const NON_TRANSITIVE: u32 = 0x0000_0001;
    pub const UPLEVEL_ONLY: u32 = 0x0000_0002;
    /// SID filtering / quarantine enabled.
    pub const QUARANTINED_DOMAIN: u32 = 0x0000_0004;
    pub const FOREST_TRANSITIVE: u32 = 0x0000_0008;
    /// Selective Authentication enabled.
    pub const CROSS_ORGANIZATION: u32 = 0x0000_0010;
    pub const WITHIN_FOREST: u32 = 0x0000_0020;
    pub const TREAT_AS_EXTERNAL: u32 = 0x0000_0040;
    pub const USES_RC4_ENCRYPTION: u32 = 0x0000_0080;
    pub const CROSS_ORGANIZATION_NO_TGT_DELEGATION: u32 = 0x0000_0200;
    pub const PIM_TRUST: u32 = 0x0000_0400;

    /// Wraps a raw `trustAttributes` value.
    pub fn from_bits(raw: u32) -> Self {
        Self { raw }
    }

    fn has(&self, flag: u32) -> bool {
        self.raw & flag != 0
    }

    /// `true` when SID filtering / quarantine is enabled — historical and
    /// foreign SIDs presented across this trust are dropped at runtime. This
    /// is the attribute most likely to make a Stars finding *over*-report
    /// (see known-limitations L4 / verification.md M.5).
    pub fn sid_filtering_enabled(&self) -> bool {
        self.has(Self::QUARANTINED_DOMAIN)
    }

    /// `true` when Selective Authentication is enabled — trust principals must
    /// be explicitly allowed to authenticate on a target, so a DACL grant
    /// alone does not imply real access.
    pub fn selective_authentication(&self) -> bool {
        self.has(Self::CROSS_ORGANIZATION)
    }

    /// `true` for a forest trust (transitive across the whole forest).
    pub fn forest_transitive(&self) -> bool {
        self.has(Self::FOREST_TRANSITIVE)
    }

    /// `true` for an intra-forest trust (between domains of the same forest).
    pub fn within_forest(&self) -> bool {
        self.has(Self::WITHIN_FOREST)
    }

    /// Human-readable names of the set flags, for the read-only report.
    pub fn labels(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.has(Self::NON_TRANSITIVE) {
            v.push("non-transitive");
        }
        if self.has(Self::UPLEVEL_ONLY) {
            v.push("uplevel-only");
        }
        if self.has(Self::QUARANTINED_DOMAIN) {
            v.push("SID-filtering (quarantined)");
        }
        if self.has(Self::FOREST_TRANSITIVE) {
            v.push("forest-transitive");
        }
        if self.has(Self::CROSS_ORGANIZATION) {
            v.push("selective-authentication");
        }
        if self.has(Self::WITHIN_FOREST) {
            v.push("within-forest");
        }
        if self.has(Self::TREAT_AS_EXTERNAL) {
            v.push("treat-as-external");
        }
        if self.has(Self::USES_RC4_ENCRYPTION) {
            v.push("uses-RC4");
        }
        if self.has(Self::CROSS_ORGANIZATION_NO_TGT_DELEGATION) {
            v.push("no-TGT-delegation");
        }
        if self.has(Self::PIM_TRUST) {
            v.push("PIM-trust");
        }
        v
    }
}

/// One Active Directory trust relationship, read from a `trustedDomain`
/// object (read-only inventory, L4). Stars never modifies trusts — this type
/// exists so an auditor can see the trust topology that governs whether
/// cross-forest / historical SIDs are honored at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainTrust {
    /// DNS name of the trusted domain/forest (`trustPartner`).
    pub partner: String,
    /// NetBIOS / flat name (`flatName`), when present.
    pub flat_name: Option<String>,
    /// Trust direction (`trustDirection`).
    pub direction: TrustDirection,
    /// Parsed `trustAttributes`.
    pub attributes: TrustAttributes,
    /// Domain SID of the trusted domain (`securityIdentifier`), when present.
    pub sid: Option<Sid>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Core review 2026-07-25 C-3: the trust inventory must be exportable and
    /// persistable like every other model type — the serde round-trip must be
    /// lossless, including the raw bitmask (unknown high bits) and an
    /// out-of-range direction code.
    #[test]
    fn domain_trust_serde_roundtrip_is_lossless() {
        let t = DomainTrust {
            partner: "ext.test".to_owned(),
            flat_name: Some("EXT".to_owned()),
            direction: TrustDirection::Unknown(9),
            attributes: TrustAttributes::from_bits(0x8000_001C),
            sid: Some(Sid("S-1-5-21-1-2-3".to_owned())),
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: DomainTrust = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }

    /// Test helper: an identity carrying `count` historical SIDs of which
    /// `parsed` could be read as values (core review 2026-07-25, C-6).
    fn identity_with_history(count: usize, parsed: usize) -> Identity {
        Identity {
            sid: Sid("S-1-5-21-1-2-3-1000".to_owned()),
            name: Some("u1".to_owned()),
            domain: Some("CORP".to_owned()),
            kind: IdentityKind::User,
            disabled: false,
            user_principal_name: None,
            sid_history_count: count,
            sid_history: (0..parsed)
                .map(|i| Sid(format!("S-1-5-21-9-9-9-{}", 1100 + i)))
                .collect(),
        }
    }

    /// ADR 0056 split on the user side: parsed values are evaluated
    /// (informational), the remainder stays an incompleteness trigger —
    /// the under-report path must never get lost.
    #[test]
    fn identity_sid_history_diagnostics_splits_evaluated_and_remainder() {
        let d = identity_with_history(3, 2).sid_history_diagnostics();
        assert_eq!(
            d,
            vec![
                PermissionDiagnostic::SidHistoryEvaluated { count: 2 },
                PermissionDiagnostic::SidHistoryPresent { count: 1 },
            ]
        );
    }

    #[test]
    fn identity_sid_history_diagnostics_edge_cases() {
        // All values parsed -> informational marker only.
        let d = identity_with_history(2, 2).sid_history_diagnostics();
        assert_eq!(
            d,
            vec![PermissionDiagnostic::SidHistoryEvaluated { count: 2 }]
        );
        // No history -> no markers (no false positive).
        assert!(identity_with_history(0, 0)
            .sid_history_diagnostics()
            .is_empty());
        // Count-only rows (persisted under ADR 0052, values never fetched)
        // -> everything stays visible as un-evaluated.
        let d = identity_with_history(2, 0).sid_history_diagnostics();
        assert_eq!(
            d,
            vec![PermissionDiagnostic::SidHistoryPresent { count: 2 }]
        );
    }

    /// Core review 2026-07-25 C-5: `origin_label` is user-visible wording
    /// shared by CLI and GUI — pin all five outcomes.
    #[test]
    fn origin_label_covers_all_five_wordings() {
        let base = GroupMembership {
            member_sid: Sid("S-1-5-21-1-2-3-1000".to_owned()),
            group_sid: Sid("S-1-5-21-1-2-3-512".to_owned()),
            direct: false,
            group_name: None,
            path: None,
            group_sid_history_count: 0,
            group_sid_history: Vec::new(),
        };
        let with_path =
            |source, complete, nodes: Vec<&str>, names: Vec<Option<&str>>| GroupMembership {
                path: Some(MembershipPath {
                    nodes: nodes.into_iter().map(|s| Sid(s.to_owned())).collect(),
                    names: names.into_iter().map(|n| n.map(str::to_owned)).collect(),
                    source,
                    complete,
                    also_via: Vec::new(),
                }),
                ..base.clone()
            };

        // 1) primary group and 2) local group win over everything else.
        let primary = with_path(
            MembershipPathSource::PrimaryGroup,
            true,
            vec!["S-1", "S-2"],
            vec![None, None],
        );
        assert_eq!(primary.origin_label(), "primary group");
        let local = with_path(
            MembershipPathSource::LocalGroup,
            true,
            vec!["S-1", "S-2"],
            vec![None, None],
        );
        assert_eq!(local.origin_label(), "local group");

        // 3) direct membership.
        let direct = GroupMembership {
            direct: true,
            ..base.clone()
        };
        assert_eq!(direct.origin_label(), "direct");

        // 4) complete chain: names where known, raw-SID fallback otherwise.
        let chain = with_path(
            MembershipPathSource::DomainGroup,
            true,
            vec!["S-1", "S-2", "S-3"],
            vec![Some("u1"), None, Some("G")],
        );
        assert_eq!(chain.origin_label(), "via u1 \u{2192} S-2 \u{2192} G");

        // 5) incomplete chain carries the caveat; no path at all -> "nested".
        let incomplete = with_path(
            MembershipPathSource::LdapMatchingRule,
            false,
            vec!["S-1", "S-3"],
            vec![None, None],
        );
        assert_eq!(
            incomplete.origin_label(),
            "via S-1 \u{2192} S-3 (chain not fully reconstructed)"
        );
        assert_eq!(base.origin_label(), "nested");
    }

    fn hop(sid: &str, name: Option<&str>) -> MembershipHop {
        MembershipHop {
            sid: Sid(sid.to_owned()),
            name: name.map(str::to_owned),
        }
    }

    fn gm(
        group: &str,
        direct: bool,
        complete: bool,
        also_via: Vec<MembershipHop>,
    ) -> GroupMembership {
        GroupMembership {
            member_sid: Sid("S-1-5-21-9-9-9-1000".to_owned()),
            group_sid: Sid(group.to_owned()),
            direct,
            group_name: None,
            path: Some(MembershipPath {
                nodes: vec![Sid("S-1-5-21-9-9-9-1000".to_owned()), Sid(group.to_owned())],
                names: vec![Some("u".to_owned()), Some("G".to_owned())],
                source: MembershipPathSource::DomainGroup,
                complete,
                also_via,
            }),
            group_sid_history_count: 0,
            group_sid_history: Vec::new(),
        }
    }

    #[test]
    fn origin_label_names_further_routes() {
        let m = gm(
            "S-1-5-21-9-9-9-2000",
            true,
            true,
            vec![
                hop("S-1-5-21-9-9-9-2001", Some("gB")),
                hop("S-1-5-21-9-9-9-2002", None),
            ],
        );
        assert_eq!(
            m.origin_label(),
            "direct; also a member through gB (S-1-5-21-9-9-9-2001), S-1-5-21-9-9-9-2002"
        );
        let single = gm("S-1-5-21-9-9-9-2000", true, true, vec![]);
        assert_eq!(single.origin_label(), "direct");
    }

    #[test]
    fn format_also_via_spells_out_five_and_counts_the_rest() {
        assert_eq!(format_also_via(&[]), None);
        let hops: Vec<MembershipHop> = (0..7)
            .map(|i| {
                hop(
                    &format!("S-1-5-21-9-9-9-{}", 3000 + i),
                    Some(&format!("g{i}")),
                )
            })
            .collect();
        let text = format_also_via(&hops).expect("non-empty");
        assert!(text.starts_with("g0 (S-1-5-21-9-9-9-3000), g1"), "{text}");
        assert!(text.contains("g4 (S-1-5-21-9-9-9-3004)"), "{text}");
        assert!(!text.contains("g5"), "{text}");
        assert!(text.ends_with("(+2 more)"), "{text}");
    }

    fn chain(
        group: &str,
        via: &str,
        via_name: &str,
        source: MembershipPathSource,
    ) -> GroupMembership {
        let user = Sid("S-1-5-21-9-9-9-1000".to_owned());
        GroupMembership {
            member_sid: user.clone(),
            group_sid: Sid(group.to_owned()),
            direct: false,
            group_name: Some("BUILTIN\\Users".to_owned()),
            path: Some(MembershipPath {
                nodes: vec![user, Sid(via.to_owned()), Sid(group.to_owned())],
                names: vec![
                    Some("u".to_owned()),
                    Some(via_name.to_owned()),
                    Some("BUILTIN\\Users".to_owned()),
                ],
                source,
                complete: true,
                also_via: Vec::new(),
            }),
            group_sid_history_count: 0,
            group_sid_history: Vec::new(),
        }
    }

    /// Lab finding CLI3-1: a group from LDAP and from the local-group lookup
    /// is listed once; a mediator only the second source knew is kept as a
    /// further route.
    #[test]
    fn merged_memberships_keep_one_entry_and_every_route() {
        let ldap = chain(
            "S-1-5-32-545",
            "S-1-5-21-9-9-9-513",
            "Domain Users",
            MembershipPathSource::DomainGroup,
        );
        let local_same = chain(
            "S-1-5-32-545",
            "S-1-5-21-9-9-9-513",
            "Domain Users",
            MembershipPathSource::LocalGroup,
        );
        let local_other = chain(
            "S-1-5-32-545",
            "S-1-5-21-9-9-9-512",
            "Domain Admins",
            MembershipPathSource::LocalGroup,
        );
        let merged = merged_memberships_per_group(&[ldap.clone(), local_same]);
        assert_eq!(merged.len(), 1);
        assert!(
            merged[0]
                .path
                .as_ref()
                .is_some_and(|p| p.also_via.is_empty()),
            "the same mediator is not a further route"
        );
        let merged = merged_memberships_per_group(&[ldap, local_other]);
        assert_eq!(merged.len(), 1);
        let path = merged[0].path.as_ref().expect("path");
        assert_eq!(
            path.source,
            MembershipPathSource::DomainGroup,
            "first source kept"
        );
        assert_eq!(path.also_via.len(), 1);
        assert_eq!(path.also_via[0].sid.0, "S-1-5-21-9-9-9-512");
        assert_eq!(path.also_via[0].name.as_deref(), Some("Domain Admins"));
    }

    #[test]
    fn best_membership_per_group_keeps_the_best_entry_in_first_seen_order() {
        let a_incomplete = gm("S-1-5-21-9-9-9-4001", false, false, vec![]);
        let b = gm("S-1-5-21-9-9-9-4002", false, true, vec![]);
        let a_complete = gm("S-1-5-21-9-9-9-4001", false, true, vec![]);
        let list = vec![a_incomplete, b, a_complete];
        let best = best_membership_per_group(&list);
        let order: Vec<&str> = best.iter().map(|m| m.group_sid.0.as_str()).collect();
        assert_eq!(order, ["S-1-5-21-9-9-9-4001", "S-1-5-21-9-9-9-4002"]);
        assert!(best[0].path.as_ref().is_some_and(|p| p.complete));
    }

    fn account(kind: IdentityKind, disabled: bool) -> Identity {
        Identity {
            sid: Sid("S-1-5-21-9-9-9-1000".to_owned()),
            name: Some("u".to_owned()),
            domain: None,
            kind,
            disabled,
            user_principal_name: None,
            sid_history_count: 0,
            sid_history: Vec::new(),
        }
    }

    /// Lab finding AD3-2: "Active" only when the state is known.
    #[test]
    fn account_status_says_active_only_when_known() {
        let user = account(IdentityKind::User, false);
        assert_eq!(AccountStatus::of(&user, &[]), AccountStatus::Active);
        assert_eq!(
            AccountStatus::of(&account(IdentityKind::User, true), &[]),
            AccountStatus::Disabled
        );
        for unknown_marker in [
            PermissionDiagnostic::IdentityDisabledStatusUnknown,
            PermissionDiagnostic::IdentityNotResolvable {
                reason: "r".to_owned(),
            },
            PermissionDiagnostic::IdentityLookupFailed {
                reason: "r".to_owned(),
            },
        ] {
            assert_eq!(
                AccountStatus::of(&user, std::slice::from_ref(&unknown_marker)),
                AccountStatus::Unknown,
                "{unknown_marker:?}"
            );
        }
        assert_eq!(
            AccountStatus::of(&account(IdentityKind::Unknown, false), &[]),
            AccountStatus::Unknown
        );
        assert_eq!(
            AccountStatus::of(&account(IdentityKind::Orphaned, false), &[]),
            AccountStatus::DoesNotExist
        );
        assert_eq!(
            AccountStatus::of(&account(IdentityKind::Group, false), &[]),
            AccountStatus::NotAnAccount
        );
        assert_eq!(AccountStatus::Unknown.csv_value(), "unknown");
        assert_eq!(AccountStatus::Active.csv_value(), "false");
        assert_eq!(AccountStatus::Disabled.csv_value(), "true");
        assert_eq!(AccountStatus::NotAnAccount.csv_value(), "n/a");
        assert!(!AccountStatus::Unknown.label().contains("Active"));
    }

    fn permission() -> EffectivePermission {
        EffectivePermission {
            identity: account(IdentityKind::User, false),
            path: NormalizedPath("C:\\x".to_owned()),
            ntfs_mask: AccessMask(0x0012_0089),
            share_mask: Some(AccessMask(0x0012_0089)),
            effective_mask: AccessMask(0x0012_0089),
            path_explanation: PermissionPath { steps: vec![] },
            share_status: ShareEvalStatus::Applied,
            local_group_status: LocalGroupEvalStatus::Applied,
            contributing_sids: vec![],
            unsupported_ace_count: 0,
            matched_aces: vec![],
            diagnostics: vec![],
        }
    }

    /// ADR 0065: each uncertainty is attributed to the part it affects.
    #[test]
    fn uncertainty_is_attributed_to_the_affected_layer() {
        let clean = permission();
        assert!(clean.uncertainty().is_empty());
        assert!(clean.effective_determinable() && !clean.is_incomplete());

        let mut share = permission();
        share.share_status = ShareEvalStatus::ReadFailed("access denied".to_owned());
        assert!(
            share.ntfs_determinable(),
            "a share failure leaves NTFS exact"
        );
        assert!(!share.share_determinable());
        assert!(!share.effective_determinable());

        let mut ntfs = permission();
        ntfs.unsupported_ace_count = 2;
        ntfs.diagnostics = vec![PermissionDiagnostic::UnsupportedNtfsAces { count: 2 }];
        assert_eq!(
            ntfs.uncertainty().len(),
            1,
            "count and marker are one reason"
        );
        assert!(!ntfs.ntfs_determinable());
        assert!(
            ntfs.share_determinable(),
            "an NTFS gap leaves the share mask exact"
        );

        let mut token = permission();
        token.local_group_status = LocalGroupEvalStatus::NotAvailable("RPC".to_owned());
        assert!(!token.ntfs_determinable() && !token.share_determinable());

        let mut informational = permission();
        informational.diagnostics = vec![
            PermissionDiagnostic::NonCanonicalDaclOrder { at_index: 0 },
            PermissionDiagnostic::IdentityOrphaned,
            PermissionDiagnostic::SidHistoryEvaluated { count: 1 },
        ];
        assert!(informational.effective_determinable());
    }

    #[test]
    fn incompleteness_trigger_and_uncertain_layer_agree() {
        let all = [
            PermissionDiagnostic::NonCanonicalDaclOrder { at_index: 0 },
            PermissionDiagnostic::UnsupportedShareAces { count: 1 },
            PermissionDiagnostic::UnsupportedNtfsAces { count: 1 },
            PermissionDiagnostic::DomainGroupRecursionIncomplete,
            PermissionDiagnostic::IdentityDisabled,
            PermissionDiagnostic::IdentityNotInConfiguredLdapBase,
            PermissionDiagnostic::IdentityDisabledStatusUnknown,
            PermissionDiagnostic::IdentityLookupFailed { reason: "r".into() },
            PermissionDiagnostic::GroupResolutionFailed { reason: "r".into() },
            PermissionDiagnostic::OwnerRightsAceApplied,
            PermissionDiagnostic::IdentityResolvedViaForeignSecurityPrincipal,
            PermissionDiagnostic::GroupResolutionViaGlobalCatalog,
            PermissionDiagnostic::PersistedEvidenceDecodeFailed { detail: "d".into() },
            PermissionDiagnostic::SidHistoryPresent { count: 1 },
            PermissionDiagnostic::SidHistoryEvaluated { count: 1 },
            PermissionDiagnostic::GroupSidHistoryEvaluated {
                groups: 1,
                count: 1,
            },
            PermissionDiagnostic::GroupSidHistoryPresent { count: 1 },
            PermissionDiagnostic::TrustBoundaryEffectsNotModeled,
            PermissionDiagnostic::MembersViaPrimaryGroupIncluded { count: 1 },
            PermissionDiagnostic::GroupMemberEnumerationIncomplete { reason: "r".into() },
            PermissionDiagnostic::UniversalGroupCrossDomainMembersNotVisible,
            PermissionDiagnostic::IdentityNotResolvable { reason: "r".into() },
            PermissionDiagnostic::IdentityOrphaned,
            PermissionDiagnostic::LogonDependentTrustees {
                sids: vec!["S-1-5-15".into()],
                min_mask: 0,
                max_mask: 1,
            },
            PermissionDiagnostic::GroupResolutionIncomplete { reason: "r".into() },
        ];
        for d in &all {
            assert_eq!(
                d.is_incompleteness_trigger(),
                d.uncertain_layer().is_some(),
                "{d:?}"
            );
            let mut p = permission();
            p.diagnostics = vec![d.clone()];
            assert_eq!(p.is_incomplete(), d.is_incompleteness_trigger(), "{d:?}");
        }
    }

    #[test]
    fn unresolvable_identity_is_incomplete_orphaned_is_informational() {
        let unresolvable = PermissionDiagnostic::IdentityNotResolvable {
            reason: "trusted domain".to_owned(),
        };
        assert!(unresolvable.is_incompleteness_trigger());
        assert_eq!(unresolvable.severity(), DiagnosticSeverity::Concern);
        assert!(unresolvable.summary().contains("trusted domain"));
        assert!(!PermissionDiagnostic::IdentityOrphaned.is_incompleteness_trigger());
        assert_eq!(
            PermissionDiagnostic::IdentityOrphaned.severity(),
            DiagnosticSeverity::Neutral
        );
    }

    #[test]
    fn trust_direction_from_code_maps_known_and_preserves_unknown() {
        assert_eq!(TrustDirection::from_code(0), TrustDirection::Disabled);
        assert_eq!(TrustDirection::from_code(1), TrustDirection::Inbound);
        assert_eq!(TrustDirection::from_code(2), TrustDirection::Outbound);
        assert_eq!(TrustDirection::from_code(3), TrustDirection::Bidirectional);
        assert_eq!(TrustDirection::from_code(9), TrustDirection::Unknown(9));
        assert_eq!(TrustDirection::from_code(9).label(), "unknown (9)");
    }

    #[test]
    fn trust_attributes_decode_named_flags() {
        // A forest trust with SID filtering AND selective authentication.
        let a = TrustAttributes::from_bits(
            TrustAttributes::FOREST_TRANSITIVE
                | TrustAttributes::QUARANTINED_DOMAIN
                | TrustAttributes::CROSS_ORGANIZATION,
        );
        assert!(a.forest_transitive());
        assert!(a.sid_filtering_enabled());
        assert!(a.selective_authentication());
        assert!(!a.within_forest());
        let labels = a.labels();
        assert!(labels.contains(&"forest-transitive"));
        assert!(labels.contains(&"SID-filtering (quarantined)"));
        assert!(labels.contains(&"selective-authentication"));

        // The raw value is preserved even with unknown high bits set.
        let raw = 0x8000_0004;
        let b = TrustAttributes::from_bits(raw);
        assert_eq!(b.raw, raw);
        assert!(b.sid_filtering_enabled());
    }

    #[test]
    fn trust_attributes_empty_has_no_flags() {
        let a = TrustAttributes::default();
        assert!(!a.sid_filtering_enabled());
        assert!(!a.selective_authentication());
        assert!(a.labels().is_empty());
    }

    // --- Diagnostic summaries (engine review 2026-06-13 finding 2) ---
    //
    // The GUI scan-row detail surfaces the per-variant reason via
    // `summary()`. Guard that every variant yields a non-empty, single-line
    // string with the interpolated payload present, so a newly added variant
    // cannot silently render as an empty row.

    #[test]
    fn diagnostic_summary_is_non_empty_and_single_line() {
        let variants = [
            PermissionDiagnostic::NonCanonicalDaclOrder { at_index: 3 },
            PermissionDiagnostic::UnsupportedShareAces { count: 2 },
            PermissionDiagnostic::UnsupportedNtfsAces { count: 5 },
            PermissionDiagnostic::DomainGroupRecursionIncomplete,
            PermissionDiagnostic::IdentityDisabled,
            PermissionDiagnostic::IdentityNotInConfiguredLdapBase,
            PermissionDiagnostic::IdentityDisabledStatusUnknown,
            PermissionDiagnostic::IdentityLookupFailed {
                reason: "bind timeout".to_owned(),
            },
            PermissionDiagnostic::GroupResolutionFailed {
                reason: "DC unreachable".to_owned(),
            },
            PermissionDiagnostic::OwnerRightsAceApplied,
            PermissionDiagnostic::IdentityResolvedViaForeignSecurityPrincipal,
            PermissionDiagnostic::GroupResolutionViaGlobalCatalog,
            PermissionDiagnostic::PersistedEvidenceDecodeFailed {
                detail: "diagnostics field".to_owned(),
            },
        ];
        for d in &variants {
            let s = d.summary();
            assert!(!s.trim().is_empty(), "empty summary for {d:?}");
            assert!(
                !s.contains('\n'),
                "summary must be single-line for GUI rows, got newline in {d:?}"
            );
        }
    }

    #[test]
    fn diagnostic_summary_includes_payload() {
        assert!(PermissionDiagnostic::UnsupportedNtfsAces { count: 7 }
            .summary()
            .contains('7'));
        assert!(PermissionDiagnostic::NonCanonicalDaclOrder { at_index: 9 }
            .summary()
            .contains('9'));
        assert!(PermissionDiagnostic::IdentityLookupFailed {
            reason: "specific-reason-text".to_owned()
        }
        .summary()
        .contains("specific-reason-text"));
        assert!(PermissionDiagnostic::PersistedEvidenceDecodeFailed {
            detail: "specific-detail-text".to_owned()
        }
        .summary()
        .contains("specific-detail-text"));
    }

    // --- Validated construction (engine review 2026-06-12 finding 4) ---

    #[test]
    fn sid_try_new_accepts_wellknown_and_user_sids() {
        assert_eq!(Sid::try_new("S-1-5-18").unwrap().0, "S-1-5-18");
        assert!(Sid::try_new("S-1-5-21-1-2-3-1001").is_ok());
        // Trimmed.
        assert_eq!(Sid::try_new("  S-1-5-18  ").unwrap().0, "S-1-5-18");
    }

    #[test]
    fn sid_try_new_rejects_malformed() {
        assert!(Sid::try_new("").is_err());
        assert!(Sid::try_new("not-a-sid").is_err());
        assert!(Sid::try_new("X-1-5-18").is_err());
        assert!(Sid::try_new("S-1-5").is_err()); // too few components
        assert!(Sid::try_new("S-1-5-abc").is_err()); // non-numeric component
    }

    #[test]
    fn sid_is_valid_syntax_matches_try_new() {
        assert!(Sid::is_valid_syntax("S-1-5-32-544"));
        assert!(!Sid::is_valid_syntax("garbage"));
    }

    #[test]
    fn sid_new_unchecked_bypasses_validation() {
        // Deliberately allowed for trusted construction paths.
        assert_eq!(Sid::new_unchecked("anything").0, "anything");
    }

    #[test]
    fn normalized_path_try_new_accepts_and_trims() {
        assert_eq!(
            NormalizedPath::try_new(r"  C:\Data\Share  ").unwrap().0,
            r"C:\Data\Share"
        );
        assert!(NormalizedPath::try_new(r"\\server\share\folder").is_ok());
    }

    #[test]
    fn normalized_path_try_new_rejects_empty_and_control_chars() {
        assert!(NormalizedPath::try_new("").is_err());
        assert!(NormalizedPath::try_new("   ").is_err());
        assert!(NormalizedPath::try_new("C:\\a\0b").is_err()); // NUL
        assert!(NormalizedPath::try_new("C:\\a\tb").is_err()); // control char
    }

    #[test]
    fn access_context_default_is_unspecified() {
        assert_eq!(AccessContext::default(), AccessContext::Unspecified);
    }

    #[test]
    fn access_context_for_unc_path_is_remote_smb() {
        assert_eq!(
            AccessContext::for_path(r"\\server\share\folder"),
            AccessContext::RemoteSmb
        );
        assert_eq!(
            AccessContext::for_path(r"\\198.51.100.100\Shared"),
            AccessContext::RemoteSmb
        );
    }

    #[test]
    fn access_context_for_long_path_unc_is_remote_smb() {
        assert_eq!(
            AccessContext::for_path(r"\\?\UNC\server\share\folder"),
            AccessContext::RemoteSmb
        );
    }

    #[test]
    fn access_context_for_local_path_is_local_interactive() {
        assert_eq!(
            AccessContext::for_path(r"C:\Windows"),
            AccessContext::LocalInteractive
        );
        assert_eq!(
            AccessContext::for_path(r"D:\Data\file.txt"),
            AccessContext::LocalInteractive
        );
    }

    #[test]
    fn access_context_for_long_path_local_is_local_interactive() {
        assert_eq!(
            AccessContext::for_path(r"\\?\C:\very\long\path"),
            AccessContext::LocalInteractive
        );
    }

    // Round-7 finding 1: a local path with an explicit SMB context must
    // yield RemoteSmb so NETWORK lands in the token and share DACL ACEs
    // targeting NETWORK are aggregated correctly.
    #[test]
    fn access_context_for_path_with_smb_forces_remote_when_smb_server_given() {
        assert_eq!(
            AccessContext::for_path_with_smb(r"C:\TestShare", Some("fs01"), None),
            AccessContext::RemoteSmb
        );
    }

    #[test]
    fn access_context_for_path_with_smb_forces_remote_when_share_name_given() {
        assert_eq!(
            AccessContext::for_path_with_smb(r"D:\data", None, Some("Data")),
            AccessContext::RemoteSmb
        );
    }

    #[test]
    fn access_context_for_path_with_smb_keeps_unc_as_remote() {
        assert_eq!(
            AccessContext::for_path_with_smb(r"\\server\share", None, None),
            AccessContext::RemoteSmb
        );
    }

    #[test]
    fn access_context_for_path_with_smb_keeps_local_when_no_smb_hint() {
        assert_eq!(
            AccessContext::for_path_with_smb(r"C:\Windows", None, None),
            AccessContext::LocalInteractive
        );
    }

    #[test]
    fn access_context_for_path_with_smb_ignores_empty_smb_hints() {
        // Empty-string SMB hints (e.g. an unfilled GUI field) must NOT
        // override the path-based default.
        assert_eq!(
            AccessContext::for_path_with_smb(r"C:\Windows", Some(""), Some("")),
            AccessContext::LocalInteractive
        );
    }

    // --- Privileged-group detection (membership view) ---

    #[test]
    fn privileged_group_role_matches_builtin_aliases() {
        assert_eq!(
            privileged_group_role(&Sid("S-1-5-32-544".into())),
            Some("Administrators")
        );
        assert_eq!(
            privileged_group_role(&Sid("S-1-5-32-551".into())),
            Some("Backup Operators")
        );
    }

    #[test]
    fn privileged_group_role_matches_domain_rids_independent_of_domain() {
        // Same RID under two different domains both resolve to the role.
        assert_eq!(
            privileged_group_role(&Sid("S-1-5-21-111-222-333-512".into())),
            Some("Domain Admins")
        );
        assert_eq!(
            privileged_group_role(&Sid("S-1-5-21-9-8-7-512".into())),
            Some("Domain Admins")
        );
        assert_eq!(
            privileged_group_role(&Sid("S-1-5-21-1-2-3-519".into())),
            Some("Enterprise Admins")
        );
    }

    #[test]
    fn privileged_group_role_rejects_non_privileged_and_builtin_users() {
        // BUILTIN\Users (545) and Domain Users (513) are NOT privileged.
        assert_eq!(privileged_group_role(&Sid("S-1-5-32-545".into())), None);
        assert_eq!(
            privileged_group_role(&Sid("S-1-5-21-1-2-3-513".into())),
            None
        );
        // A plain user RID (1104) must not be flagged.
        assert_eq!(
            privileged_group_role(&Sid("S-1-5-21-1-2-3-1104".into())),
            None
        );
        // A built-in well-known SID that is not in the privileged set.
        assert_eq!(privileged_group_role(&Sid("S-1-1-0".into())), None);
    }

    #[test]
    fn membership_report_privileged_collects_only_privileged_groups() {
        let report = MembershipReport {
            identity: Identity {
                sid: Sid("S-1-5-21-1-2-3-1104".into()),
                name: Some("alice".into()),
                domain: Some("CORP".into()),
                kind: IdentityKind::User,
                disabled: false,
                user_principal_name: None,
                sid_history_count: 0,
                sid_history: Vec::new(),
            },
            ad_connected: true,
            memberships: vec![
                GroupMembership {
                    member_sid: Sid("S-1-5-21-1-2-3-1104".into()),
                    group_sid: Sid("S-1-5-21-1-2-3-512".into()), // Domain Admins
                    direct: false,
                    group_name: Some("Domain Admins".into()),
                    path: None,
                    group_sid_history_count: 0,
                    group_sid_history: Vec::new(),
                },
                GroupMembership {
                    member_sid: Sid("S-1-5-21-1-2-3-1104".into()),
                    group_sid: Sid("S-1-5-21-1-2-3-513".into()), // Domain Users (not priv.)
                    direct: true,
                    group_name: Some("Domain Users".into()),
                    path: None,
                    group_sid_history_count: 0,
                    group_sid_history: Vec::new(),
                },
            ],
            diagnostics: vec![],
        };
        let privileged = report.privileged();
        assert_eq!(privileged.len(), 1);
        assert_eq!(privileged[0].1, "Domain Admins");
    }

    // --- Group sIDHistory diagnostics (ADR 0059) ---

    fn gm_with_history(group_sid: &str, count: usize, parsed: &[&str]) -> GroupMembership {
        GroupMembership {
            member_sid: Sid("S-1-5-21-1-2-3-1104".into()),
            group_sid: Sid(group_sid.into()),
            direct: true,
            group_name: None,
            path: None,
            group_sid_history_count: count,
            group_sid_history: parsed.iter().map(|s| Sid((*s).into())).collect(),
        }
    }

    #[test]
    fn group_sid_history_diagnostics_splits_evaluated_and_unevaluated() {
        let memberships = vec![
            gm_with_history(
                "S-1-5-21-1-2-3-512",
                2,
                &["S-1-5-21-9-9-9-1", "S-1-5-21-9-9-9-2"],
            ),
            gm_with_history("S-1-5-21-1-2-3-513", 2, &["S-1-5-21-9-9-9-3"]),
            gm_with_history("S-1-5-21-1-2-3-514", 0, &[]),
        ];
        let d = group_sid_history_diagnostics(&memberships);
        assert!(
            d.contains(&PermissionDiagnostic::GroupSidHistoryEvaluated {
                groups: 2,
                count: 3
            }),
            "3 parsed values across 2 groups must be evaluated: {d:?}"
        );
        assert!(
            d.contains(&PermissionDiagnostic::GroupSidHistoryPresent { count: 1 }),
            "1 unparsed value must stay visible: {d:?}"
        );
    }

    #[test]
    fn group_sid_history_diagnostics_deduplicates_by_group_sid() {
        // The same group listed twice (e.g. the AD + local combination)
        // must not double-count its history.
        let memberships = vec![
            gm_with_history("S-1-5-21-1-2-3-512", 1, &["S-1-5-21-9-9-9-1"]),
            gm_with_history("S-1-5-21-1-2-3-512", 1, &["S-1-5-21-9-9-9-1"]),
        ];
        let d = group_sid_history_diagnostics(&memberships);
        assert!(
            d.contains(&PermissionDiagnostic::GroupSidHistoryEvaluated {
                groups: 1,
                count: 1
            }),
            "duplicate membership entries must not inflate counts: {d:?}"
        );
    }

    #[test]
    fn group_sid_history_diagnostics_silent_without_history() {
        let memberships = vec![gm_with_history("S-1-5-21-1-2-3-512", 0, &[])];
        assert!(
            group_sid_history_diagnostics(&memberships).is_empty(),
            "no history → no markers (no false positives)"
        );
    }

    // --- Group → Members (reverse view) ---

    fn member(sid: &str, name: &str, kind: IdentityKind, via: MemberVia) -> MemberNode {
        MemberNode {
            identity: Identity {
                sid: Sid(sid.into()),
                name: Some(name.into()),
                domain: Some("CORP".into()),
                kind,
                disabled: false,
                user_principal_name: None,
                sid_history_count: 0,
                sid_history: Vec::new(),
            },
            via,
            children: vec![],
        }
    }

    fn members_report(members: Vec<MemberNode>) -> GroupMembersReport {
        GroupMembersReport {
            group: Identity {
                sid: Sid("S-1-5-21-1-2-3-513".into()),
                name: Some("Domain Users".into()),
                domain: Some("CORP".into()),
                kind: IdentityKind::Group,
                disabled: false,
                user_principal_name: None,
                sid_history_count: 0,
                sid_history: Vec::new(),
            },
            members,
            diagnostics: vec![],
        }
    }

    #[test]
    fn member_via_labels_are_stable() {
        assert_eq!(MemberVia::Direct.label(), "direct");
        assert_eq!(MemberVia::PrimaryGroup.label(), "via primaryGroupID");
    }

    #[test]
    fn direct_counts_splits_total_and_primary_group() {
        let report = members_report(vec![
            member(
                "S-1-5-21-1-2-3-1104",
                "alice",
                IdentityKind::User,
                MemberVia::Direct,
            ),
            member(
                "S-1-5-21-1-2-3-1105",
                "bob",
                IdentityKind::User,
                MemberVia::PrimaryGroup,
            ),
            member(
                "S-1-5-21-1-2-3-1106",
                "carol",
                IdentityKind::User,
                MemberVia::PrimaryGroup,
            ),
        ]);
        let (total, via_primary) = report.direct_counts();
        assert_eq!(total, 3);
        assert_eq!(via_primary, 2);
    }

    #[test]
    fn privileged_members_flags_nested_privileged_group() {
        let report = members_report(vec![
            member(
                "S-1-5-21-1-2-3-1104",
                "alice",
                IdentityKind::User,
                MemberVia::Direct,
            ),
            // Domain Admins nested as a member — as sensitive here as a
            // privileged parent is in the upward view.
            member(
                "S-1-5-21-1-2-3-512",
                "Domain Admins",
                IdentityKind::Group,
                MemberVia::Direct,
            ),
        ]);
        let priv_members = report.privileged_members();
        assert_eq!(priv_members.len(), 1);
        assert_eq!(priv_members[0].1, "Domain Admins");
    }

    #[test]
    fn primary_group_inclusion_marker_is_neutral_and_not_incompleteness() {
        let d = PermissionDiagnostic::MembersViaPrimaryGroupIncluded { count: 2000 };
        assert_eq!(d.severity(), DiagnosticSeverity::Neutral);
        assert!(
            !d.is_incompleteness_trigger(),
            "primary-group members were included, not missed"
        );
        assert!(d.summary().contains("2000"));
    }

    #[test]
    fn members_view_rejection_wording_by_kind() {
        let identity = |kind: IdentityKind| Identity {
            sid: Sid("S-1-5-21-1-2-3-500".into()),
            name: Some("x".into()),
            domain: None,
            kind,
            disabled: false,
            user_principal_name: None,
            sid_history_count: 0,
            sid_history: Vec::new(),
        };
        // A group passes.
        assert!(members_view_rejection(&identity(IdentityKind::Group)).is_none());
        // A user is rejected with the "not a group" wording.
        let user_msg = members_view_rejection(&identity(IdentityKind::User)).unwrap();
        assert!(user_msg.contains("not a group"), "{user_msg}");
        // Unresolved kinds get the honest "could not be resolved" wording,
        // not a cryptic "is a Unknown" (review 2026-07-03, F4).
        let unknown_msg = members_view_rejection(&identity(IdentityKind::Unknown)).unwrap();
        assert!(
            unknown_msg.contains("could not be resolved"),
            "{unknown_msg}"
        );
        assert!(!unknown_msg.contains("Unknown"), "{unknown_msg}");
    }

    #[test]
    fn universal_group_marker_is_neutral_but_incompleteness_trigger() {
        let d = PermissionDiagnostic::UniversalGroupCrossDomainMembersNotVisible;
        assert_eq!(d.severity(), DiagnosticSeverity::Neutral);
        assert!(d.is_incompleteness_trigger());
        assert!(d.summary().contains("universal"));
    }

    #[test]
    fn member_enumeration_incomplete_marker_is_concern_and_incompleteness() {
        let d = PermissionDiagnostic::GroupMemberEnumerationIncomplete {
            reason: "LDAP page read failed".into(),
        };
        assert_eq!(d.severity(), DiagnosticSeverity::Concern);
        assert!(d.is_incompleteness_trigger());
        assert!(d.summary().contains("LDAP page read failed"));
    }
}
