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
    /// userPrincipalName from AD (e.g. `max.mustermann@testdomain.local`).
    /// Preferred for Windows NetAPI calls like `NetUserGetLocalGroups`,
    /// since the `DOMAIN\sAMAccountName` form strictly requires the NetBIOS
    /// name which we cannot reliably derive from the DN.
    #[serde(default)]
    pub user_principal_name: Option<String>,
}

/// Access context for permission evaluation.
///
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

    ///
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
    /// mean "no name exists" — it means "this resolver did not supply
    /// `#[serde(default)]` keeps older cache entries lacking this field
    /// compatible.
    #[serde(default)]
    pub group_name: Option<String>,
    /// Concrete membership path from `member_sid` to `group_sid` (see
    /// [`MembershipPath`]). Populated by the live resolver; the SQLite
    /// cache does not store it because it is reconstructed on every
    /// run. `None` means "this resolver did not supply a path" — the
    /// `#[serde(default)]` keeps older cache entries compatible.
    #[serde(default)]
    pub path: Option<MembershipPath>,
}

///
///
///
///
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipPath {
    pub nodes: Vec<Sid>,
    #[serde(default)]
    pub names: Vec<Option<String>>,
    pub source: MembershipPathSource,
    pub complete: bool,
}

/// Source of a reconstructed membership chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipPathSource {
    /// Mitgliedschaften.
    /// Primary AD group (`primaryGroupID`) — a single edge from the user
    /// to the primary group, with transitive parents recorded as their
    /// own memberships.
    PrimaryGroup,
    /// Direct or nested domain group membership reconstructed via
    /// concrete `member` edges.
    DomainGroup,
    /// NetLocalGroupGetMembers).
    /// Local group on the target server (NetUserGetLocalGroups or
    /// NetLocalGroupGetMembers).
    LocalGroup,
    /// Fall `false`.
    /// Transitive membership is certain (e.g. via
    /// `LDAP_MATCHING_RULE_IN_CHAIN`) but the concrete path could not
    /// be fully reconstructed. `complete` is `false` in this case.
    LdapMatchingRule,
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
    /// Rohwert von ACE_HEADER.AceType.
    /// Raw value from ACE_HEADER.AceType.
    pub ace_type: u8,
    /// Rohwert von ACE_HEADER.AceFlags.
    /// Raw value from ACE_HEADER.AceFlags.
    pub flags: u8,
    /// Access mask — for standard ACE types (0–15) Mask is immediately after the header.
    pub mask: u32,
}

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
/// SMB share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub name: String,
    pub unc_path: String,
    pub local_path: Option<NormalizedPath>,
    pub is_admin_share: bool,
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

///
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

///
///
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

///
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

    ///
    /// (follow-up finding 2 from the 2026-05-25 review).
    ///
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

    /// The NTFS DACL parser skipped ACE types it cannot interpret
    /// (object, callback, conditional / Dynamic Access Control, or
    /// vendor-specific ACEs). A hidden Deny among them could materially
    /// change the result, so the displayed effective permission is a
    /// **lower-confidence approximation** — risk findings for this
    /// permission carry `incomplete = true`. `count` is the number of
    /// skipped NTFS ACEs.
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
                "{count} share ACE(s) of an unsupported type were skipped — the share \
                 mask is potentially incomplete."
            ),
            PermissionDiagnostic::UnsupportedNtfsAces { count } => format!(
                "{count} NTFS ACE(s) could not be evaluated (object/callback/conditional/\
                 vendor) — a hidden Deny among them could change the result."
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

///
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

/// `"kind": "diagnostic"`) eindeutig.
///
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
    /// Auditoren lesbare Begruendung.
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
    /// vorsichtig interpretieren.
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

#[cfg(test)]
mod tests {
    use super::*;

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
            AccessContext::for_path(r"\\192.168.11.100\Shared"),
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
}
