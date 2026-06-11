// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Calculation of effective NTFS permissions.
//!
//! Evaluation walks the DACL in its stored order (Windows AccessCheck
//! semantics): the first decision per right-bit wins. INHERIT_ONLY ACEs are
//! skipped for the current object because they only apply to children.
//! Generic bits (GENERIC_*) are expanded into specific file bits before
//! evaluation. Non-canonical DACL orderings are detected and logged as a
//! warning; evaluation still follows the stored order, which matches the
//! actual Windows AccessCheck behavior.
//!
//! Final effective right = the more restrictive combination of NTFS and share
//! (bitwise AND).

use std::collections::{HashMap, HashSet};

use adpa_core::{
    error::CoreError,
    model::{
        AccessContext, AccessMask, AceEntry, AceKind, ContributingAce, EffectivePermission,
        GroupMembership, Identity, MembershipPathSource, PermissionDiagnostic, PermissionPath,
        ShareEvalStatus, ShareMaskStatus, Sid,
    },
    traits::{PermissionEvaluationInput, PermissionEvaluator},
};

use crate::mask::{
    expand_generic_rights, NormalizedRights, FILE_READ_CONTROL, FILE_WRITE_DAC, INHERIT_ONLY_ACE,
    MASK_FULL_CONTROL,
};
use tracing::{debug, warn};

pub struct DefaultPermissionEngine;

impl PermissionEvaluator for DefaultPermissionEngine {
    fn evaluate(&self, input: PermissionEvaluationInput) -> Result<EffectivePermission, CoreError> {
        debug!(
            user = %input.identity.sid.0,
            path = %input.file_system_object.path.0,
            groups = input.group_memberships.len(),
            "Evaluating effective permissions"
        );
        let user_sids = collect_user_sids(
            &input.identity,
            &input.group_memberships,
            &input.local_group_sids,
            input.access_context,
        );

        // Owner handling (engine review 2026-06-09 finding 1).
        //
        // Windows semantics: the owner of an object is implicitly granted
        // READ_CONTROL + WRITE_DAC — UNLESS the DACL contains an ACE for
        // the well-known SID S-1-3-4 ("OWNER RIGHTS", Server 2008+). When
        // such an ACE exists, it REPLACES the implicit grant: the S-1-3-4
        // entries are evaluated in DACL order as if they named the owner,
        // and no implicit bonus applies.
        let user_is_owner = input
            .file_system_object
            .owner_sid
            .as_ref()
            .is_some_and(|owner| user_sids.contains(&owner.0));
        let owner_rights_ace_present = user_is_owner
            && input
                .file_system_object
                .dacl
                .iter()
                .any(|ace| ace.sid.0 == SID_OWNER_RIGHTS && ace_applies_to_current_object(ace));

        // The SID set used for ACE matching. When the user is the owner,
        // S-1-3-4 entries apply to them — extend the match set so the
        // stored-order walk picks those ACEs up naturally.
        let match_sids: HashSet<String> = if user_is_owner {
            let mut s = user_sids.clone();
            s.insert(SID_OWNER_RIGHTS.to_string());
            s
        } else {
            user_sids.clone()
        };

        // NULL DACL means "no access control" — Windows grants everyone full access.
        // An empty DACL (dacl == [] && null_dacl == false) by contrast denies everything.
        let walk = if input.file_system_object.null_dacl {
            DaclWalkOutcome {
                granted: MASK_FULL_CONTROL,
                denied: 0,
                contributions: Vec::new(),
            }
        } else {
            walk_dacl_stored_order(&input.file_system_object.dacl, &match_sids)
        };
        let mut ntfs_raw = walk.granted;
        let denied_raw = walk.denied;
        let contributing_sids = walk.contributions;

        // Implicit owner grant — only when no OWNER RIGHTS ACE governs
        // the owner's rights. The grant bypasses the DACL entirely in
        // Windows (it is applied before AccessCheck walks the DACL), so
        // OR-ing after the walk is equivalent: even explicitly denied
        // READ_CONTROL/WRITE_DAC bits are restored for the owner.
        let owner_implicit_bits: u32 = if user_is_owner && !owner_rights_ace_present {
            FILE_READ_CONTROL | FILE_WRITE_DAC
        } else {
            0
        };
        ntfs_raw |= owner_implicit_bits;

        // Evaluate the share status: NotApplicable → effective = NTFS;
        // Applied → effective = NTFS ∩ Share; ReadFailed → effective = NTFS but
        // the result carries the ReadFailed marker (incomplete).
        let (share_mask_for_output, output_share_status, effective_raw) = match &input.share_status
        {
            ShareMaskStatus::NotApplicable => (None, ShareEvalStatus::NotApplicable, ntfs_raw),
            ShareMaskStatus::Applied(mask) => {
                (Some(*mask), ShareEvalStatus::Applied, ntfs_raw & mask.0)
            }
            // NULL share DACL: SMB does not restrict → effective = NTFS.
            // share_mask stays None so reports do not display an artificial
            // mask 0xFFFFFFFF. The Unrestricted status cleanly separates this
            // case from a real "special" mask that was actually read.
            ShareMaskStatus::Unrestricted => (None, ShareEvalStatus::Unrestricted, ntfs_raw),
            ShareMaskStatus::ReadFailed(msg) => {
                (None, ShareEvalStatus::ReadFailed(msg.clone()), ntfs_raw)
            }
        };

        let path_explanation = build_explanation(ExplanationInput {
            identity: &input.identity,
            memberships: &input.group_memberships,
            dacl: &input.file_system_object.dacl,
            match_sids: &match_sids,
            ntfs_raw,
            denied_raw,
            owner_implicit_bits,
            owner_rights_ace_present,
            owner_sid: input.file_system_object.owner_sid.as_ref(),
            share_mask: share_mask_for_output,
            effective_raw,
            sid_names: &input.sid_names,
        });

        let matched_aces = collect_matched_aces(&input.file_system_object.dacl, &match_sids);

        // Structured diagnostic markers.
        //  - Follow-up finding 3 (NTFS): non-canonical DACL ordering. A
        //    NULL DACL has no ACEs to order — only the real DACL.
        //  - Follow-up finding 2 (share): unsupported share ACE types
        //    the share parser had to skip. The caller passes the count
        //    via `unsupported_share_ace_count`.
        let mut diagnostics = if input.file_system_object.null_dacl {
            Vec::new()
        } else {
            collect_diagnostics(
                &input.file_system_object.dacl,
                &input.file_system_object.path.0,
            )
        };
        if input.unsupported_share_ace_count > 0 {
            diagnostics.push(PermissionDiagnostic::UnsupportedShareAces {
                count: input.unsupported_share_ace_count,
            });
        }
        // Finding 6: SAM fallback without LDAP — nested domain groups are
        // not recursively resolved.
        if input.group_resolution_via_sam_fallback {
            diagnostics.push(PermissionDiagnostic::DomainGroupRecursionIncomplete);
        }
        // authentifizieren.
        // Finding 7: disabled identity — ACL-theoretical rights computed,
        // but the account normally cannot authenticate.
        if input.identity.disabled {
            diagnostics.push(PermissionDiagnostic::IdentityDisabled);
        }
        // Review 2026-06-04 round 2 finding 1: identity resolved via LSA,
        // Review 2026-06-04 round 2 finding 1: identity resolved via LSA but
        // LDAP base does not index it (multi-domain).
        if input.identity_not_in_configured_ldap_base {
            diagnostics.push(PermissionDiagnostic::IdentityNotInConfiguredLdapBase);
        }
        // ermittelbar.
        // Review 2026-06-04 round 2 finding 5: disabled status could not be
        // determined.
        if input.identity_disabled_status_unknown {
            diagnostics.push(PermissionDiagnostic::IdentityDisabledStatusUnknown);
        }
        // auszusehen.
        // Review 2026-06-04 round 4 finding 1: a technical LDAP identity
        // lookup failure is incompleteness; the report must surface it
        // instead of looking clean with a placeholder identity.
        if let Some(reason) = input.identity_lookup_failure_reason {
            diagnostics.push(PermissionDiagnostic::IdentityLookupFailed { reason });
        }
        // Review 2026-06-04 round 4 finding 1: failed or skipped group
        // resolution must be visible as incomplete.
        if let Some(reason) = input.group_resolution_failure_reason {
            diagnostics.push(PermissionDiagnostic::GroupResolutionFailed { reason });
        }
        // Engine review 2026-06-09 finding 1: OWNER RIGHTS (S-1-3-4)
        // governed the owner's rights instead of the implicit grant.
        // Informational, not an incompleteness trigger.
        if owner_rights_ace_present {
            diagnostics.push(PermissionDiagnostic::OwnerRightsAceApplied);
        }
        // Known-limitations L1: cross-forest principal resolved through
        // a Foreign Security Principal object — home-domain groups are
        // in the token, trust-forest groups are unknown. Incompleteness
        // trigger for derived risk findings.
        if input.identity_resolved_via_fsp {
            diagnostics.push(PermissionDiagnostic::IdentityResolvedViaForeignSecurityPrincipal);
        }
        // Known-limitations L2: memberships came from a Global Catalog
        // bind — only universal group memberships replicate fully to
        // the GC. Incompleteness trigger.
        if input.group_resolution_via_global_catalog {
            diagnostics.push(PermissionDiagnostic::GroupResolutionViaGlobalCatalog);
        }

        let result = EffectivePermission {
            identity: input.identity,
            path: input.file_system_object.path.clone(),
            ntfs_mask: AccessMask(ntfs_raw),
            share_mask: share_mask_for_output,
            effective_mask: AccessMask(effective_raw),
            path_explanation,
            share_status: output_share_status,
            local_group_status: input.local_group_status,
            contributing_sids,
            // Diagnostic: surface unsupported ACE types found on this path.
            unsupported_ace_count: input.file_system_object.unsupported_aces.len(),
            matched_aces,
            diagnostics,
        };
        debug!(
            user = %result.identity.sid.0,
            path = %result.path.0,
            ntfs = format_args!("0x{:08X}", ntfs_raw),
            effective = format_args!("0x{:08X}", effective_raw),
            "Permission evaluation complete"
        );
        Ok(result)
    }
}

/// Builds the token SID set for a user.
///
/// Contains the user SID, all group SIDs, and the implicit well-known principals
/// `Everyone` (S-1-1-0) and `Authenticated Users` (S-1-5-11), which are present
/// in every Windows access token.
///
/// Use this function everywhere a SID set is needed — CLI output, GUI share mask,
/// and the permission engine — so all three stay consistent.
///
/// Note: uses `AccessContext::Unspecified` and therefore does not add
/// context-specific well-knowns like `NETWORK`.
pub fn build_token_sids(user_sid: &str, memberships: &[GroupMembership]) -> HashSet<String> {
    build_token_sids_with_context(user_sid, memberships, &[], AccessContext::Unspecified)
}

/// Like [`build_token_sids`], plus additional SIDs of local groups on the target
/// server (e.g. `BUILTIN\Administrators`) in which the user is a member.
///
/// **Deprecated:** implicitly uses `AccessContext::Unspecified` and therefore
/// adds no context-specific well-knowns — for SMB paths e.g. `NETWORK` is
/// missing from the token, making share ACEs targeting `NETWORK` invisible
/// (see ADR 0019). Use `build_token_sids_with_context` with an explicit
/// `AccessContext::for_path(path)` instead.
#[deprecated(
    since = "0.2.0-rc1",
    note = "Use build_token_sids_with_context with an explicit AccessContext \
            (e.g. AccessContext::for_path(path)) — see ADR 0019. \
            build_token_sids_with_local implicitly uses Unspecified and \
            misses NETWORK / INTERACTIVE / LOCAL in the token."
)]
pub fn build_token_sids_with_local(
    user_sid: &str,
    memberships: &[GroupMembership],
    local_group_sids: &[Sid],
) -> HashSet<String> {
    build_token_sids_with_context(
        user_sid,
        memberships,
        local_group_sids,
        AccessContext::Unspecified,
    )
}

/// Full token construction: own SID, AD groups, local server groups, the
/// universal well-knowns (`Everyone`, `Authenticated Users`), and the
/// context-specific well-knowns:
///
/// - `RemoteSmb` → `NETWORK` (S-1-5-2)
/// - `LocalInteractive` → `INTERACTIVE` (S-1-5-4) + `LOCAL` (S-1-2-0)
/// - `Unspecified` → no additional well-knowns
pub fn build_token_sids_with_context(
    user_sid: &str,
    memberships: &[GroupMembership],
    local_group_sids: &[Sid],
    access_context: AccessContext,
) -> HashSet<String> {
    let mut sids = HashSet::new();
    sids.insert(user_sid.to_string());
    for gm in memberships {
        sids.insert(gm.group_sid.0.clone());
    }
    for local in local_group_sids {
        sids.insert(local.0.clone());
    }
    // Implicit well-known principals present in every Windows access token
    sids.insert("S-1-1-0".to_string()); // Everyone
    sids.insert("S-1-5-11".to_string()); // Authenticated Users

    // Context-specific well-knowns.
    match access_context {
        AccessContext::RemoteSmb => {
            sids.insert("S-1-5-2".to_string()); // NETWORK
        }
        AccessContext::LocalInteractive => {
            sids.insert("S-1-5-4".to_string()); // INTERACTIVE
            sids.insert("S-1-2-0".to_string()); // LOCAL
        }
        AccessContext::Unspecified => {}
    }
    sids
}

fn collect_user_sids(
    identity: &Identity,
    memberships: &[GroupMembership],
    local_group_sids: &[Sid],
    access_context: AccessContext,
) -> HashSet<String> {
    build_token_sids_with_context(
        &identity.sid.0,
        memberships,
        local_group_sids,
        access_context,
    )
}

/// Checks whether an ACE applies to the current object.
///
/// ACEs flagged with INHERIT_ONLY_ACE apply only to children and must not
/// contribute to the effective permission on the current object. Without
/// this filter the engine would, for example, grant a directory rights
/// that Windows would not apply in `AccessCheck` for that directory.
fn ace_applies_to_current_object(ace: &AceEntry) -> bool {
    ace.propagation_flags & INHERIT_ONLY_ACE == 0
}

/// Well-known SID "OWNER RIGHTS" (Windows Server 2008+). When the DACL
/// contains an ACE for this SID and the analyzed identity is the object's
/// owner, the ACE governs the owner's rights and the implicit
/// `READ_CONTROL + WRITE_DAC` owner grant is suppressed.
pub const SID_OWNER_RIGHTS: &str = "S-1-3-4";

/// Result of the single stored-order DACL walk: the granted/denied bit
/// sets plus the per-SID contribution provenance, all derived from the
/// same pass so they cannot drift apart (engine review 2026-06-09
/// finding 4 — the 2026-06-08 provenance bug existed precisely because
/// two separate walks diverged).
struct DaclWalkOutcome {
    granted: u32,
    denied: u32,
    contributions: Vec<ContributingAce>,
}

/// Walks the DACL in its stored order — the single source of truth for
/// evaluation AND provenance.
///
/// For each right-bit the first matching decision wins, analogous to
/// Windows `AccessCheck`. Generic rights (GENERIC_*) are expanded into
/// specific file bits before evaluation; ACEs flagged INHERIT_ONLY_ACE
/// are skipped for the current object.
///
/// `granted` is the effective NTFS mask. `denied` is the union of bits a
/// Deny ACE decided before any Allow could grant them — surfaced
/// separately so the explanation path can call out "those bits were
/// decided by Deny". `contributions` records, per Allow-ACE SID, exactly
/// the bits that ACE flipped from undecided to granted (review
/// 2026-06-08 finding 2: provenance must follow stored order, not mask
/// overlap).
fn walk_dacl_stored_order(dacl: &[AceEntry], match_sids: &HashSet<String>) -> DaclWalkOutcome {
    let mut granted: u32 = 0;
    let mut denied: u32 = 0;
    let mut by_sid: HashMap<String, u32> = HashMap::new();
    for ace in dacl {
        if !ace_applies_to_current_object(ace) {
            continue;
        }
        if !match_sids.contains(&ace.sid.0) {
            continue;
        }
        let mask = expand_generic_rights(ace.mask.0);
        // First decision per bit wins — bits already decided cannot flip.
        let undecided = !(granted | denied);
        let bits = mask & undecided;
        if bits == 0 {
            continue;
        }
        match ace.kind {
            AceKind::Allow => {
                granted |= bits;
                *by_sid.entry(ace.sid.0.clone()).or_insert(0) |= bits;
            }
            AceKind::Deny => denied |= bits,
        }
    }
    DaclWalkOutcome {
        granted,
        denied,
        contributions: by_sid
            .into_iter()
            .map(|(sid_str, mask)| ContributingAce {
                sid: Sid(sid_str),
                mask: AccessMask(mask),
            })
            .collect(),
    }
}

/// Collects DACL entries that actually apply to the current object and whose
/// trustee SID belongs to the match SID set (token plus `S-1-3-4` when the
/// user is the owner).
///
/// **Important:** ACEs flagged `INHERIT_ONLY_ACE` are filtered out. They
/// apply only to children; a risk rule like `DirectUserAceRule` would
/// otherwise fire on an explicit user ACE that does not affect the current
/// object at all (follow-up finding 2).
fn collect_matched_aces(dacl: &[AceEntry], user_sids: &HashSet<String>) -> Vec<AceEntry> {
    dacl.iter()
        .filter(|ace| ace_applies_to_current_object(ace) && user_sids.contains(&ace.sid.0))
        .cloned()
        .collect()
}

/// Collects structured diagnostic markers for the DACL itself; also emits
/// a `warn!` per finding. The structured list flows into
/// `EffectivePermission.diagnostics` and from there into the DB history
/// and exports.
fn collect_diagnostics(dacl: &[AceEntry], path: &str) -> Vec<PermissionDiagnostic> {
    let mut out = Vec::new();
    if let Some(at) = first_non_canonical_position(dacl) {
        warn!(
            path,
            at,
            "DACL ordering differs from single-level canonical form — evaluation follows \
             stored ACE order (matches Windows AccessCheck). Note: with multi-level \
             inheritance this ordering can be legitimate; see docs/known-limitations.md"
        );
        out.push(PermissionDiagnostic::NonCanonicalDaclOrder { at_index: at });
    }
    out
}

/// Windows-canonical DACL order: each ACE has a monotonically increasing
/// phase 0 (explicit deny) → 1 (explicit allow) → 2 (inherited deny) →
/// 3 (inherited allow). Returns the index of the first ACE that violates it.
fn first_non_canonical_position(dacl: &[AceEntry]) -> Option<usize> {
    let mut max_phase = 0u8;
    for (i, ace) in dacl.iter().enumerate() {
        let phase: u8 = match (ace.inherited, &ace.kind) {
            (false, AceKind::Deny) => 0,
            (false, AceKind::Allow) => 1,
            (true, AceKind::Deny) => 2,
            (true, AceKind::Allow) => 3,
        };
        if phase < max_phase {
            return Some(i);
        }
        max_phase = phase;
    }
    None
}

/// Human-readable label for the source kind shown in the explanation.
fn source_label(source: &MembershipPathSource) -> &'static str {
    match source {
        MembershipPathSource::PrimaryGroup => "PrimaryGroup",
        MembershipPathSource::DomainGroup => "DomainGroup",
        MembershipPathSource::LocalGroup => "LocalGroup",
        MembershipPathSource::LdapMatchingRule => "LdapMatchingRule",
    }
}

/// dann globale SID→Name-Tabelle, dann nackte SID.
/// Preferred display for a SID in the chain: explicitly attached name,
/// then global SID→name table, then raw SID.
fn display_for_sid<'a>(
    sid: &'a Sid,
    explicit_name: Option<&'a str>,
    sid_names: &'a std::collections::BTreeMap<String, String>,
) -> String {
    if let Some(name) = explicit_name {
        return name.to_owned();
    }
    if let Some(name) = sid_names.get(&sid.0) {
        return name.clone();
    }
    sid.0.clone()
}

/// Formats a single membership step in the explanation path. When the
/// membership carries a concrete chain (`gm.path`), the chain is rendered
/// as an ordered sequence "A → B → C" — the auditor can read the path
/// from the user to the ACE-bearing group directly (finding 1 from the
/// 2026-05-31 review).
fn format_membership_step(
    gm: &GroupMembership,
    sid_names: &std::collections::BTreeMap<String, String>,
) -> String {
    let target_name = gm
        .group_name
        .as_deref()
        .or_else(|| sid_names.get(&gm.group_sid.0).map(String::as_str));
    let target_display = match target_name {
        Some(name) => format!("{} ({})", name, gm.group_sid.0),
        None => gm.group_sid.0.clone(),
    };

    let Some(path) = gm.path.as_ref() else {
        // No concrete path known — fall back to the legacy format.
        let via = if gm.direct { "direct" } else { "transitive" };
        return format!("Member of {target_display} [{via}]");
    };

    let source = source_label(&path.source);

    if !path.complete {
        // Transitive membership confirmed, exact route not
        // reconstructable — flag explicitly so audits can tell apart
        // from a fully reconstructed chain.
        return format!(
            "Member of {target_display} [transitive, exact chain unknown — source: {source}, possibly truncated memberOf]"
        );
    }

    if path.nodes.len() <= 2 {
        // Two nodes = direct hop; no intermediates.
        return format!("Member of {target_display} [direct, source: {source}]");
    }

    // Concrete chain: render each node by SID/name and join with „ → ".
    let chain_text: Vec<String> = path
        .nodes
        .iter()
        .enumerate()
        .map(|(i, node_sid)| {
            let explicit = path
                .names
                .get(i)
                .and_then(|opt| opt.as_deref())
                .filter(|s| !s.is_empty());
            display_for_sid(node_sid, explicit, sid_names)
        })
        .collect();
    let chain_joined = chain_text.join(" → ");
    format!("Member of {target_display} [via {chain_joined}, source: {source}]")
}

/// Bundles the inputs for [`build_explanation`] — replaces the previous
/// 9-argument signature with named fields (engine review 2026-06-09).
struct ExplanationInput<'a> {
    identity: &'a Identity,
    memberships: &'a [GroupMembership],
    dacl: &'a [AceEntry],
    /// SID set used for ACE matching — includes `S-1-3-4` when the user
    /// is the owner, so OWNER RIGHTS ACEs show up in the step list.
    match_sids: &'a HashSet<String>,
    ntfs_raw: u32,
    denied_raw: u32,
    /// Bits added by the implicit owner rule (`0` when the rule did not
    /// fire or was suppressed by an OWNER RIGHTS ACE).
    owner_implicit_bits: u32,
    /// True when an `S-1-3-4` ACE governed the owner's rights.
    owner_rights_ace_present: bool,
    owner_sid: Option<&'a Sid>,
    share_mask: Option<AccessMask>,
    effective_raw: u32,
    sid_names: &'a std::collections::BTreeMap<String, String>,
}

/// Creates an explainable permission path.
fn build_explanation(input: ExplanationInput<'_>) -> PermissionPath {
    let ExplanationInput {
        identity,
        memberships,
        dacl,
        match_sids,
        ntfs_raw,
        denied_raw,
        owner_implicit_bits,
        owner_rights_ace_present,
        owner_sid,
        share_mask,
        effective_raw,
        sid_names,
    } = input;
    let mut steps: Vec<String> = Vec::new();

    let display_name = identity.name.as_deref().unwrap_or(identity.sid.0.as_str());
    steps.push(format!("User: {} ({})", display_name, identity.sid.0));

    // 2. Group memberships.
    for gm in memberships {
        steps.push(format_membership_step(gm, sid_names));
    }

    // 3. Matching ACEs.
    for ace in dacl {
        if !match_sids.contains(&ace.sid.0) {
            continue;
        }
        let kind = match ace.kind {
            AceKind::Allow => "Allow",
            AceKind::Deny => "Deny",
        };
        let scope = if ace.inherited {
            "[inherited]"
        } else {
            "[explicit]"
        };
        // Expand generic bits for display so e.g. GENERIC_ALL shows as "Full
        // Control" instead of "Special".
        let expanded = expand_generic_rights(ace.mask.0);
        let rights = NormalizedRights::new(expanded);
        let inherit_only_note = if ace_applies_to_current_object(ace) {
            ""
        } else {
            " [inherit-only — not applied to this object]"
        };
        let trustee_display = sid_names.get(&ace.sid.0);
        match trustee_display {
            Some(name) => steps.push(format!(
                "{} ACE {} for {} ({}) → {} (0x{:08X}){}",
                kind,
                scope,
                name,
                ace.sid.0,
                rights.display_name(),
                ace.mask.0,
                inherit_only_note,
            )),
            None => steps.push(format!(
                "{} ACE {} for {} → {} (0x{:08X}){}",
                kind,
                scope,
                ace.sid.0,
                rights.display_name(),
                ace.mask.0,
                inherit_only_note,
            )),
        }
    }

    // 3b. Deny aggregation step: makes it visible that the NTFS mask
    // below was reduced by Deny ACEs. Without it the reader has to diff
    // the hex values to realize Allow bits got blocked (especially
    // confusing when the result is "Special (0x00100000)" — only the
    // SYNCHRONIZE bit left).
    //
    // Engine review 2026-06-09 finding 2: bits the implicit owner rule
    // restores are excluded from this step — otherwise the text would
    // claim bits were "decided by Deny" while the final NTFS mask
    // contains them again via the owner rule.
    let denied_for_display = denied_raw & !owner_implicit_bits;
    if denied_for_display != 0 {
        let deny_rights = NormalizedRights::new(denied_for_display);
        steps.push(format!(
            "Deny aggregation: {} (0x{:08X}) decided by Deny ACEs before any Allow could grant them — removed from the effective NTFS mask",
            deny_rights.display_name(),
            denied_for_display,
        ));
    }

    // 3c. Owner special rule (engine review 2026-06-09 findings 1+2):
    // either the implicit grant fired — then say so, because no listed
    // ACE explains those bits — or an OWNER RIGHTS ACE replaced it.
    if owner_implicit_bits != 0 {
        let owner_display = owner_sid
            .map(|s| display_for_sid(s, None, sid_names))
            .unwrap_or_else(|| "(unknown)".to_string());
        steps.push(format!(
            "Owner special rule: READ_CONTROL + WRITE_DAC granted implicitly (owner: {owner_display})"
        ));
    } else if owner_rights_ace_present {
        steps.push(
            "OWNER RIGHTS (S-1-3-4) ACE present — owner rights are governed by that DACL entry; the implicit owner grant is suppressed".to_string(),
        );
    }

    // 4. NTFS effective
    let ntfs_rights = NormalizedRights::new(ntfs_raw);
    steps.push(format!(
        "NTFS effective: {} (0x{:08X})",
        ntfs_rights.display_name(),
        ntfs_raw
    ));

    if let Some(share) = share_mask {
        let share_rights = NormalizedRights::new(share.0);
        steps.push(format!(
            "Share permission: {} (0x{:08X})",
            share_rights.display_name(),
            share.0
        ));
        let eff_rights = NormalizedRights::new(effective_raw);
        steps.push(format!(
            "Effective (NTFS \u{2229} Share): {} (0x{:08X})",
            eff_rights.display_name(),
            effective_raw
        ));
    }

    PermissionPath { steps }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mask::*;
    use adpa_core::model::{
        AccessMask, AceEntry, AceKind, FileSystemObject, GroupMembership, Identity, IdentityKind,
        MembershipPath, MembershipPathSource, NormalizedPath, Sid,
    };

    const USER: &str = "S-1-5-21-1000-1000-1000-1001";
    const GROUP_A: &str = "S-1-5-21-1000-1000-1000-1100";
    const GROUP_B: &str = "S-1-5-21-1000-1000-1000-1200";
    const OTHER: &str = "S-1-5-21-1000-1000-1000-9999";

    fn user(sid: &str) -> Identity {
        Identity {
            sid: Sid(sid.into()),
            name: Some(sid.into()),
            domain: None,
            kind: IdentityKind::User,
            disabled: false,
            user_principal_name: None,
        }
    }

    fn membership(user_sid: &str, group_sid: &str) -> GroupMembership {
        GroupMembership {
            member_sid: Sid(user_sid.into()),
            group_sid: Sid(group_sid.into()),
            direct: true,
            group_name: None,
            path: None,
        }
    }

    fn allow_ace(sid: &str, mask: u32, inherited: bool) -> AceEntry {
        AceEntry {
            kind: AceKind::Allow,
            sid: Sid(sid.into()),
            mask: AccessMask(mask),
            inherited,
            inheritance_flags: 0,
            propagation_flags: 0,
        }
    }

    fn deny_ace(sid: &str, mask: u32, inherited: bool) -> AceEntry {
        AceEntry {
            kind: AceKind::Deny,
            sid: Sid(sid.into()),
            mask: AccessMask(mask),
            inherited,
            inheritance_flags: 0,
            propagation_flags: 0,
        }
    }

    fn allow_ace_inherit_only(sid: &str, mask: u32, inherited: bool) -> AceEntry {
        AceEntry {
            kind: AceKind::Allow,
            sid: Sid(sid.into()),
            mask: AccessMask(mask),
            inherited,
            inheritance_flags: 0,
            propagation_flags: INHERIT_ONLY_ACE,
        }
    }

    fn deny_ace_inherit_only(sid: &str, mask: u32, inherited: bool) -> AceEntry {
        AceEntry {
            kind: AceKind::Deny,
            sid: Sid(sid.into()),
            mask: AccessMask(mask),
            inherited,
            inheritance_flags: 0,
            propagation_flags: INHERIT_ONLY_ACE,
        }
    }

    fn fso(owner: Option<&str>, dacl: Vec<AceEntry>) -> FileSystemObject {
        FileSystemObject {
            path: NormalizedPath("C:\\test".into()),
            is_directory: true,
            owner_sid: owner.map(|s| Sid(s.into())),
            dacl,
            inheritance_disabled: false,
            is_reparse_point: false,
            unsupported_aces: vec![],
            null_dacl: false,
        }
    }

    fn fso_null_dacl() -> FileSystemObject {
        FileSystemObject {
            path: NormalizedPath("C:\\null".into()),
            is_directory: true,
            owner_sid: None,
            dacl: vec![],
            inheritance_disabled: false,
            is_reparse_point: false,
            unsupported_aces: vec![],
            null_dacl: true,
        }
    }

    fn eval(
        identity: Identity,
        groups: Vec<GroupMembership>,
        file_system_object: FileSystemObject,
        share_mask: Option<AccessMask>,
    ) -> EffectivePermission {
        DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity,
                group_memberships: groups,
                file_system_object,
                share_status: to_share_status(share_mask),
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap()
    }

    fn eval_with_local(
        identity: Identity,
        groups: Vec<GroupMembership>,
        file_system_object: FileSystemObject,
        share_mask: Option<AccessMask>,
        local_group_sids: Vec<Sid>,
    ) -> EffectivePermission {
        DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity,
                group_memberships: groups,
                file_system_object,
                share_status: to_share_status(share_mask),
                local_group_sids,
                local_group_status: adpa_core::model::LocalGroupEvalStatus::Applied,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap()
    }

    fn eval_with_context(
        identity: Identity,
        groups: Vec<GroupMembership>,
        file_system_object: FileSystemObject,
        share_mask: Option<AccessMask>,
        access_context: AccessContext,
    ) -> EffectivePermission {
        DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity,
                group_memberships: groups,
                file_system_object,
                share_status: to_share_status(share_mask),
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                access_context,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap()
    }

    fn to_share_status(share_mask: Option<AccessMask>) -> ShareMaskStatus {
        match share_mask {
            None => ShareMaskStatus::NotApplicable,
            Some(m) => ShareMaskStatus::Applied(m),
        }
    }

    // --- Direkte Rechte / direct rights ---

    #[test]
    fn direct_allow_read() {
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, MASK_READ, false)]),
            None,
        );
        assert_eq!(p.ntfs_mask.0, MASK_READ);
        assert_eq!(p.effective_mask.0, MASK_READ);
    }

    #[test]
    fn direct_allow_full_control() {
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, MASK_FULL_CONTROL, false)]),
            None,
        );
        assert!(NormalizedRights::new(p.ntfs_mask.0).is_full_control());
    }

    // --- Gruppenrechte / group rights ---

    #[test]
    fn group_allow_read() {
        let p = eval(
            user(USER),
            vec![membership(USER, GROUP_A)],
            fso(None, vec![allow_ace(GROUP_A, MASK_READ, false)]),
            None,
        );
        assert_eq!(p.ntfs_mask.0, MASK_READ);
    }

    #[test]
    fn multiple_groups_rights_combined() {
        // Group A: Read, Group B: Write → effective Read | Write
        let p = eval(
            user(USER),
            vec![membership(USER, GROUP_A), membership(USER, GROUP_B)],
            fso(
                None,
                vec![
                    allow_ace(GROUP_A, MASK_READ, false),
                    allow_ace(GROUP_B, MASK_WRITE, false),
                ],
            ),
            None,
        );
        let r = NormalizedRights::new(p.ntfs_mask.0);
        assert!(r.is_read(), "must have Read from GROUP_A");
        assert!(r.is_write(), "must have Write from GROUP_B");
    }

    // --- Deny-Regeln / deny rules ---

    #[test]
    fn explicit_deny_blocks_explicit_allow() {
        let p = eval(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    deny_ace(USER, MASK_READ, false),
                    allow_ace(USER, MASK_READ, false),
                ],
            ),
            None,
        );
        assert_eq!(
            p.ntfs_mask.0 & MASK_READ,
            0,
            "explicit deny must override explicit allow"
        );
    }

    #[test]
    fn deny_one_group_allow_another_group() {
        let p = eval(
            user(USER),
            vec![membership(USER, GROUP_A), membership(USER, GROUP_B)],
            fso(
                None,
                vec![
                    deny_ace(GROUP_A, MASK_READ, false),
                    allow_ace(GROUP_B, MASK_READ, false),
                ],
            ),
            None,
        );
        assert_eq!(
            p.ntfs_mask.0 & MASK_READ,
            0,
            "deny from GROUP_A must block allow from GROUP_B"
        );
    }

    // --- Vererbungsvorrang / inheritance precedence ---

    #[test]
    fn explicit_allow_overrides_inherited_deny() {
        // Critical Windows rule: explicit allow beats inherited deny
        let p = eval(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    allow_ace(USER, MASK_READ, false), // explicit
                    deny_ace(USER, MASK_READ, true),   // inherited
                ],
            ),
            None,
        );
        assert!(
            p.ntfs_mask.0 & MASK_READ == MASK_READ,
            "explicit allow must override inherited deny"
        );
    }

    #[test]
    fn inherited_deny_blocks_inherited_allow() {
        let p = eval(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    deny_ace(USER, MASK_READ, true),
                    allow_ace(USER, MASK_READ, true),
                ],
            ),
            None,
        );
        assert_eq!(
            p.ntfs_mask.0 & MASK_READ,
            0,
            "inherited deny must block inherited allow"
        );
    }

    #[test]
    fn inherited_allow_grants_rights() {
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, MASK_READ, true)]),
            None,
        );
        assert!(NormalizedRights::new(p.ntfs_mask.0).is_read());
    }

    #[test]
    fn empty_dacl_yields_no_access() {
        let p = eval(user(USER), vec![], fso(None, vec![]), None);
        assert_eq!(p.ntfs_mask.0, 0);
        assert_eq!(p.effective_mask.0, 0);
    }

    #[test]
    fn non_matching_sid_ignored() {
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(OTHER, MASK_FULL_CONTROL, false)]),
            None,
        );
        assert_eq!(p.ntfs_mask.0, 0);
    }

    // --- Owner-Sonderregel / owner special rule ---

    #[test]
    fn owner_always_gets_read_control_and_write_dac() {
        let p = eval(user(USER), vec![], fso(Some(USER), vec![]), None);
        assert_ne!(
            p.ntfs_mask.0 & FILE_READ_CONTROL,
            0,
            "owner must have READ_CONTROL"
        );
        assert_ne!(
            p.ntfs_mask.0 & FILE_WRITE_DAC,
            0,
            "owner must have WRITE_DAC"
        );
    }

    #[test]
    fn non_owner_gets_no_owner_bonus() {
        let p = eval(user(USER), vec![], fso(Some(OTHER), vec![]), None);
        assert_eq!(p.ntfs_mask.0, 0);
    }

    // --- OWNER RIGHTS SID S-1-3-4 (engine review 2026-06-09 finding 1) ---

    /// An OWNER RIGHTS ACE replaces the implicit owner grant. Here it
    /// allows Read only — the owner must get exactly Read, NOT the
    /// implicit READ_CONTROL + WRITE_DAC bonus on top.
    #[test]
    fn owner_rights_ace_replaces_implicit_owner_grant() {
        let p = eval(
            user(USER),
            vec![],
            fso(
                Some(USER),
                vec![allow_ace(SID_OWNER_RIGHTS, MASK_READ, false)],
            ),
            None,
        );
        assert_eq!(
            p.ntfs_mask.0, MASK_READ,
            "owner must get exactly what the OWNER RIGHTS ACE grants"
        );
        assert_eq!(
            p.ntfs_mask.0 & FILE_WRITE_DAC,
            0,
            "implicit WRITE_DAC must be suppressed when S-1-3-4 governs owner rights"
        );
        assert!(
            p.diagnostics
                .iter()
                .any(|d| matches!(d, PermissionDiagnostic::OwnerRightsAceApplied)),
            "OwnerRightsAceApplied diagnostic must be present; got: {:?}",
            p.diagnostics
        );
    }

    /// An OWNER RIGHTS Deny ACE blocks bits for the owner that the
    /// implicit rule would otherwise have granted.
    #[test]
    fn owner_rights_deny_ace_blocks_owner_bits() {
        let p = eval(
            user(USER),
            vec![],
            fso(
                Some(USER),
                vec![
                    deny_ace(SID_OWNER_RIGHTS, FILE_WRITE_DAC, false),
                    allow_ace(USER, MASK_READ, false),
                ],
            ),
            None,
        );
        assert_eq!(
            p.ntfs_mask.0 & FILE_WRITE_DAC,
            0,
            "S-1-3-4 Deny must block WRITE_DAC for the owner — the implicit grant must not restore it"
        );
        assert_ne!(p.ntfs_mask.0 & MASK_READ, 0, "regular Allow still applies");
    }

    /// A non-owner is unaffected by OWNER RIGHTS ACEs — they apply only
    /// to the object's owner.
    #[test]
    fn owner_rights_ace_ignored_for_non_owner() {
        let p = eval(
            user(USER),
            vec![],
            fso(
                Some(OTHER),
                vec![allow_ace(SID_OWNER_RIGHTS, MASK_FULL_CONTROL, false)],
            ),
            None,
        );
        assert_eq!(
            p.ntfs_mask.0, 0,
            "S-1-3-4 ACE must not grant anything to a non-owner"
        );
        assert!(
            !p.diagnostics
                .iter()
                .any(|d| matches!(d, PermissionDiagnostic::OwnerRightsAceApplied)),
            "diagnostic must not fire for non-owners"
        );
    }

    /// An INHERIT_ONLY S-1-3-4 ACE does not apply to the current object
    /// — the implicit owner grant must still fire.
    #[test]
    fn inherit_only_owner_rights_ace_keeps_implicit_grant() {
        let mut ace = allow_ace(SID_OWNER_RIGHTS, MASK_READ, false);
        ace.propagation_flags = INHERIT_ONLY_ACE;
        let p = eval(user(USER), vec![], fso(Some(USER), vec![ace]), None);
        assert_ne!(
            p.ntfs_mask.0 & FILE_WRITE_DAC,
            0,
            "inherit-only S-1-3-4 does not govern the current object — implicit grant applies"
        );
    }

    // --- Owner rule in the explanation path (finding 2) ---

    /// When the implicit owner grant fires, the explanation must say so —
    /// otherwise the NTFS-effective step shows bits no listed ACE grants.
    #[test]
    fn explanation_contains_owner_special_rule_step() {
        let p = eval(user(USER), vec![], fso(Some(USER), vec![]), None);
        assert!(
            p.path_explanation
                .steps
                .iter()
                .any(|s| s.contains("Owner special rule")),
            "explanation must name the owner special rule; got: {:?}",
            p.path_explanation.steps
        );
    }

    /// When an OWNER RIGHTS ACE suppresses the implicit grant, the
    /// explanation must name that instead.
    #[test]
    fn explanation_names_owner_rights_ace_suppression() {
        let p = eval(
            user(USER),
            vec![],
            fso(
                Some(USER),
                vec![allow_ace(SID_OWNER_RIGHTS, MASK_READ, false)],
            ),
            None,
        );
        assert!(
            p.path_explanation
                .steps
                .iter()
                .any(|s| s.contains("OWNER RIGHTS (S-1-3-4)")),
            "explanation must surface the S-1-3-4 mechanism; got: {:?}",
            p.path_explanation.steps
        );
        assert!(
            !p.path_explanation
                .steps
                .iter()
                .any(|s| s.contains("Owner special rule")),
            "implicit-grant step must not appear when S-1-3-4 governs"
        );
    }

    /// Deny step interaction (finding 2): a Deny that takes READ_CONTROL/
    /// WRITE_DAC from the owner is overridden by the implicit grant — the
    /// deny-aggregation step must not claim those bits were removed.
    #[test]
    fn deny_step_excludes_owner_restored_bits() {
        let p = eval(
            user(USER),
            vec![],
            fso(
                Some(USER),
                vec![deny_ace(USER, FILE_READ_CONTROL | FILE_WRITE_DAC, false)],
            ),
            None,
        );
        assert_ne!(
            p.ntfs_mask.0 & (FILE_READ_CONTROL | FILE_WRITE_DAC),
            0,
            "implicit owner grant restores the denied bits"
        );
        assert!(
            !p.path_explanation
                .steps
                .iter()
                .any(|s| s.contains("Deny aggregation")),
            "deny step must not claim bits were removed that the owner rule restored; got: {:?}",
            p.path_explanation.steps
        );
    }

    // --- Share-∩-NTFS-Kombination / share ∩ NTFS combination ---

    #[test]
    fn share_read_ntfs_modify_yields_read() {
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, MASK_MODIFY, false)]),
            Some(AccessMask(MASK_READ)),
        );
        let r = NormalizedRights::new(p.effective_mask.0);
        assert!(
            r.is_read(),
            "effective must be Read (share is more restrictive)"
        );
        assert!(!r.is_modify(), "effective must not be Modify");
    }

    #[test]
    fn share_full_ntfs_read_yields_read() {
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, MASK_READ, false)]),
            Some(AccessMask(MASK_FULL_CONTROL)),
        );
        let r = NormalizedRights::new(p.effective_mask.0);
        assert!(r.is_read());
        assert!(!r.is_modify());
    }

    #[test]
    fn no_share_mask_effective_equals_ntfs() {
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, MASK_MODIFY, false)]),
            None,
        );
        assert_eq!(p.effective_mask.0, p.ntfs_mask.0);
    }

    // --- permission path ---

    #[test]
    fn explanation_contains_user_and_ace_info() {
        let p = eval(
            user(USER),
            vec![membership(USER, GROUP_A)],
            fso(None, vec![allow_ace(GROUP_A, MASK_READ, false)]),
            None,
        );
        let steps = p.path_explanation.steps.join(" ");
        assert!(steps.contains(USER), "explanation must mention user SID");
        assert!(
            steps.contains(GROUP_A),
            "explanation must mention group SID"
        );
        assert!(
            steps.contains("Allow"),
            "explanation must mention Allow ACE"
        );
    }

    #[test]
    fn explanation_mentions_share_when_present() {
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, MASK_MODIFY, false)]),
            Some(AccessMask(MASK_READ)),
        );
        let steps = p.path_explanation.steps.join(" ");
        assert!(steps.contains("Share"), "explanation must mention Share");
    }

    // --- Well-known / implicit principals ---

    #[test]
    fn everyone_ace_grants_rights_to_any_user() {
        // ACE on S-1-1-0 (Everyone) must apply to any user.
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace("S-1-1-0", MASK_READ, false)]),
            None,
        );
        assert!(
            NormalizedRights::new(p.ntfs_mask.0).is_read(),
            "Everyone ACE must grant Read to any user"
        );
    }

    #[test]
    fn authenticated_users_ace_grants_rights_to_any_user() {
        // ACE on S-1-5-11 (Authenticated Users) must apply to any authenticated user.
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace("S-1-5-11", MASK_READ, false)]),
            None,
        );
        assert!(
            NormalizedRights::new(p.ntfs_mask.0).is_read(),
            "Authenticated Users ACE must grant Read to any user"
        );
    }

    #[test]
    fn unsupported_aces_count_propagated_to_result() {
        use adpa_core::model::UnsupportedAce;
        let mut file_system_object = fso(None, vec![allow_ace(USER, MASK_READ, false)]);
        file_system_object.unsupported_aces = vec![
            UnsupportedAce {
                ace_type: 2,
                flags: 0,
                mask: 0x001F_01FF,
            },
            UnsupportedAce {
                ace_type: 9,
                flags: 0,
                mask: 0x0012_0089,
            },
        ];
        let p = eval(user(USER), vec![], file_system_object, None);
        assert_eq!(
            p.unsupported_ace_count, 2,
            "unsupported ACE count must be propagated from the FSO into the result"
        );
    }

    #[test]
    fn no_unsupported_aces_yields_zero_count() {
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, MASK_READ, false)]),
            None,
        );
        assert_eq!(p.unsupported_ace_count, 0);
    }

    // --- Strukturierte ACE-Herkunft / structured ACE origin ---

    #[test]
    fn matched_aces_capture_user_and_group_aces() {
        let p = eval(
            user(USER),
            vec![membership(USER, GROUP_A)],
            fso(
                None,
                vec![
                    allow_ace(USER, MASK_READ, false),
                    allow_ace(GROUP_A, MASK_WRITE, true),
                    allow_ace(OTHER, MASK_FULL_CONTROL, false),
                ],
            ),
            None,
        );
        assert_eq!(p.matched_aces.len(), 2, "only the user's ACEs must match");
        assert!(p
            .matched_aces
            .iter()
            .any(|a| a.sid.0 == USER && !a.inherited));
        assert!(p
            .matched_aces
            .iter()
            .any(|a| a.sid.0 == GROUP_A && a.inherited));
        assert!(p.matched_aces.iter().all(|a| a.sid.0 != OTHER));
    }

    #[test]
    fn matched_aces_empty_when_no_ace_applies() {
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(OTHER, MASK_READ, false)]),
            None,
        );
        assert!(p.matched_aces.is_empty());
    }

    #[test]
    fn null_dacl_grants_full_control_to_any_user() {
        // Windows semantics: NULL DACL = no access protection = everyone has full control.
        let p = eval(user(USER), vec![], fso_null_dacl(), None);
        assert!(
            NormalizedRights::new(p.ntfs_mask.0).is_full_control(),
            "NULL DACL must yield Full Control; got 0x{:08X}",
            p.ntfs_mask.0
        );
    }

    #[test]
    fn empty_dacl_still_denies_access() {
        let p = eval(user(USER), vec![], fso(None, vec![]), None);
        assert_eq!(p.ntfs_mask.0, 0);
        assert_eq!(p.effective_mask.0, 0);
    }

    #[test]
    fn null_dacl_grants_even_to_user_with_no_groups() {
        let p = eval(user(OTHER), vec![], fso_null_dacl(), None);
        assert!(NormalizedRights::new(p.ntfs_mask.0).is_full_control());
    }

    #[test]
    fn share_read_failed_propagates_and_keeps_ntfs_mask() {
        let p = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![],
                file_system_object: fso(None, vec![allow_ace(USER, MASK_FULL_CONTROL, false)]),
                share_status: ShareMaskStatus::ReadFailed("access denied".to_owned()),
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap();
        assert_eq!(
            p.effective_mask.0, p.ntfs_mask.0,
            "ReadFailed: effective falls back to NTFS"
        );
        assert!(
            matches!(p.share_status, ShareEvalStatus::ReadFailed(ref r) if r == "access denied"),
            "engine must propagate ReadFailed with reason into the result"
        );
        assert!(p.share_mask.is_none());
    }

    #[test]
    fn share_applied_intersects_with_ntfs() {
        let p = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![],
                file_system_object: fso(None, vec![allow_ace(USER, MASK_FULL_CONTROL, false)]),
                share_status: ShareMaskStatus::Applied(AccessMask(MASK_READ)),
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap();
        assert!(NormalizedRights::new(p.effective_mask.0).is_read());
        assert!(!NormalizedRights::new(p.effective_mask.0).is_modify());
        assert_eq!(p.share_status, ShareEvalStatus::Applied);
        assert_eq!(p.share_mask.unwrap().0, MASK_READ);
    }

    /// NULL share DACL → effective = NTFS, no fake `Applied(0xFFFFFFFF)`.
    #[test]
    fn share_unrestricted_keeps_ntfs_and_clears_share_mask() {
        let p = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![],
                file_system_object: fso(None, vec![allow_ace(USER, MASK_FULL_CONTROL, false)]),
                share_status: ShareMaskStatus::Unrestricted,
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap();
        assert_eq!(
            p.effective_mask.0, p.ntfs_mask.0,
            "Unrestricted: effective == NTFS (no share-side restriction)"
        );
        assert_eq!(p.share_status, ShareEvalStatus::Unrestricted);
        assert!(
            p.share_mask.is_none(),
            "Unrestricted must not surface a fake share mask"
        );
    }

    #[test]
    fn local_group_ace_grants_rights() {
        // ACE on a local server group SID must apply when the SID is in the
        // token's `local_group_sids` — even without an AD membership.
        const LOCAL_ADMINS: &str = "S-1-5-32-544";
        let p = eval_with_local(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(LOCAL_ADMINS, MASK_MODIFY, false)]),
            None,
            vec![Sid(LOCAL_ADMINS.into())],
        );
        assert!(
            NormalizedRights::new(p.ntfs_mask.0).is_modify(),
            "ACE on local group SID must grant rights when SID is in token"
        );
    }

    #[test]
    fn local_group_sid_ignored_when_absent() {
        // Without the local group SID in the token, the same ACE does not apply.
        const LOCAL_ADMINS: &str = "S-1-5-32-544";
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(LOCAL_ADMINS, MASK_MODIFY, false)]),
            None,
        );
        assert_eq!(
            p.ntfs_mask.0, 0,
            "without local group SID, ACE must not apply"
        );
    }

    #[test]
    fn everyone_deny_blocks_rights() {
        // Windows-AccessCheck (Stored Order, erste Entscheidung gewinnt).
        // Explicit Deny on Everyone must block Read — in canonical order
        // (deny before allow). Before Finding 2 the bucket logic ignored
        // order; behavior now matches Windows AccessCheck (stored order,
        // first decision wins).
        let p = eval(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    deny_ace("S-1-1-0", MASK_READ, false),
                    allow_ace(USER, MASK_READ, false),
                ],
            ),
            None,
        );
        assert_eq!(
            p.ntfs_mask.0 & MASK_READ,
            0,
            "Everyone Deny must block explicit user Allow"
        );
    }

    // --- Finding 1: INHERIT_ONLY_ACE must not affect the current object ---

    #[test]
    fn inherit_only_allow_does_not_grant_to_current_object() {
        // An ACE flagged IO applies only to children; it must not contribute
        // rights to the current object itself.
        let p = eval(
            user(USER),
            vec![],
            fso(
                None,
                vec![allow_ace_inherit_only(USER, MASK_FULL_CONTROL, false)],
            ),
            None,
        );
        assert_eq!(
            p.ntfs_mask.0, 0,
            "INHERIT_ONLY allow must not apply to current object"
        );
    }

    #[test]
    fn inherit_only_deny_does_not_block_for_current_object() {
        // An IO deny must not eat a normal allow on the current object — the
        // IO deny applies only to children.
        let p = eval(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    deny_ace_inherit_only(USER, MASK_READ, false),
                    allow_ace(USER, MASK_READ, false),
                ],
            ),
            None,
        );
        assert!(
            NormalizedRights::new(p.ntfs_mask.0).is_read(),
            "INHERIT_ONLY deny must not block allow on current object"
        );
    }

    #[test]
    fn inherit_only_ace_not_in_matched_aces() {
        // Follow-up finding 2: risk rules (e.g. DirectUserAceRule) consume
        // matched_aces. INHERIT_ONLY ACEs must therefore be filtered out
        // here too — otherwise the rule fires on an ACE that does not
        // affect the current object at all.
        let p = eval(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    allow_ace(USER, MASK_READ, false),
                    allow_ace_inherit_only(USER, MASK_FULL_CONTROL, false),
                ],
            ),
            None,
        );
        assert_eq!(
            p.matched_aces.len(),
            1,
            "INHERIT_ONLY ACE must not appear in matched_aces: {:?}",
            p.matched_aces
        );
        assert_eq!(p.matched_aces[0].mask.0, MASK_READ);
    }

    #[test]
    fn inherit_only_ace_not_listed_as_contributing() {
        let p = eval(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    allow_ace(USER, MASK_READ, false),
                    allow_ace_inherit_only(USER, MASK_FULL_CONTROL, false),
                ],
            ),
            None,
        );
        assert!(
            p.contributing_sids.iter().all(|c| c.mask.0 == MASK_READ),
            "INHERIT_ONLY ACE must not show up in contributing_sids"
        );
    }

    // --- Review 2026-06-08 finding 2: stored-order provenance ---

    /// Allow specific group Modify, then Allow Everyone Modify in the SAME
    /// DACL. Stored order: the first Allow decides every Modify bit, so the
    /// later Everyone ACE contributes **no newly decided bit**. Before the
    /// fix Everyone showed up as contributing Modify (via mask overlap),
    /// which caused false BROAD_GROUP_WRITE findings. After the fix,
    /// Everyone must not appear in contributing_sids at all.
    #[test]
    fn stored_order_later_everyone_allow_does_not_contribute_if_already_granted() {
        const GROUP_A: &str = "S-1-5-21-1000-1000-1000-5000";
        const EVERYONE: &str = "S-1-1-0";
        let memberships = vec![
            membership(USER, GROUP_A),
            membership(USER, EVERYONE), // user is in Everyone via the token
        ];
        let p = eval(
            user(USER),
            memberships,
            fso(
                None,
                vec![
                    allow_ace(GROUP_A, MASK_MODIFY, false),
                    allow_ace(EVERYONE, MASK_MODIFY, false),
                ],
            ),
            None,
        );
        assert_eq!(
            p.effective_mask.0, MASK_MODIFY,
            "engine result still Modify"
        );
        let cs_everyone: Vec<_> = p
            .contributing_sids
            .iter()
            .filter(|cs| cs.sid.0 == EVERYONE)
            .collect();
        assert!(
            cs_everyone.is_empty(),
            "Everyone must not be in contributing_sids when an earlier ACE \
             already decided all Modify bits — was: {:?}",
            p.contributing_sids
        );
        let cs_group: Vec<_> = p
            .contributing_sids
            .iter()
            .filter(|cs| cs.sid.0 == GROUP_A)
            .collect();
        assert_eq!(cs_group.len(), 1);
        assert_eq!(cs_group[0].mask.0, MASK_MODIFY);
    }

    /// Allow Everyone Read first, then Allow specific group Modify. Stored
    /// order: Everyone contributes the Read bits (decided first), the group
    /// contributes the remaining Modify bits (the ones still undecided
    /// after the Read decision). Both must appear with non-overlapping
    /// bit sets.
    #[test]
    fn stored_order_first_everyone_read_contributes_only_read_bits() {
        const GROUP_A: &str = "S-1-5-21-1000-1000-1000-5000";
        const EVERYONE: &str = "S-1-1-0";
        let memberships = vec![membership(USER, GROUP_A), membership(USER, EVERYONE)];
        let p = eval(
            user(USER),
            memberships,
            fso(
                None,
                vec![
                    allow_ace(EVERYONE, MASK_READ, false),
                    allow_ace(GROUP_A, MASK_MODIFY, false),
                ],
            ),
            None,
        );
        assert_eq!(p.effective_mask.0, MASK_MODIFY);
        let everyone = p
            .contributing_sids
            .iter()
            .find(|cs| cs.sid.0 == EVERYONE)
            .expect("Everyone should contribute its Read bits");
        assert_eq!(
            everyone.mask.0, MASK_READ,
            "Everyone must contribute exactly the Read bits it decided first"
        );
        let group = p
            .contributing_sids
            .iter()
            .find(|cs| cs.sid.0 == GROUP_A)
            .expect("the specific group should still contribute its remaining Modify bits");
        assert_eq!(
            group.mask.0 & MASK_READ,
            0,
            "the specific group's contribution must not double-count Read bits \
             Everyone already decided — got: {:#x}",
            group.mask.0
        );
    }

    /// Deny Everyone Write first, then Allow Everyone Modify. The Deny
    /// takes the Write bits before any Allow can grant them. The Allow
    /// still decides the read-style bits in Modify that the Deny did not
    /// take. Everyone's contributing entry must NOT include the denied
    /// write bits — those were never actually granted to anyone.
    #[test]
    fn stored_order_deny_first_excludes_denied_bits_from_contribution() {
        const EVERYONE: &str = "S-1-1-0";
        let memberships = vec![membership(USER, EVERYONE)];
        let p = eval(
            user(USER),
            memberships,
            fso(
                None,
                vec![
                    deny_ace(EVERYONE, MASK_WRITE, false),
                    allow_ace(EVERYONE, MASK_MODIFY, false),
                ],
            ),
            None,
        );
        let everyone = p.contributing_sids.iter().find(|cs| cs.sid.0 == EVERYONE);
        if let Some(cs) = everyone {
            assert_eq!(
                cs.mask.0 & MASK_WRITE & !MASK_READ,
                0,
                "denied write-specific bits must not appear as Everyone's contribution"
            );
        }
    }

    // --- Finding 3: expand generic bits (GENERIC_*) in the NTFS path ---

    #[test]
    fn generic_all_ace_yields_full_control() {
        // A GENERIC_ALL NTFS allow must evaluate to Full Control — it must
        // not get stuck as "Special".
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, GENERIC_ALL, false)]),
            None,
        );
        assert!(
            NormalizedRights::new(p.ntfs_mask.0).is_full_control(),
            "GENERIC_ALL must expand to Full Control; got 0x{:08X}",
            p.ntfs_mask.0
        );
    }

    #[test]
    fn generic_read_ace_yields_read() {
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, GENERIC_READ, false)]),
            None,
        );
        assert!(
            NormalizedRights::new(p.ntfs_mask.0).is_read(),
            "GENERIC_READ must expand to Read"
        );
    }

    #[test]
    fn generic_all_intersects_with_share_correctly() {
        // Schnittmenge nach Expansion.
        // Previously: GENERIC_ALL & share_mask was 0. Expected: correct
        // intersection after expansion.
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, GENERIC_ALL, false)]),
            Some(AccessMask(MASK_READ)),
        );
        assert!(
            NormalizedRights::new(p.effective_mask.0).is_read(),
            "GENERIC_ALL ∩ Share(Read) must yield Read; got 0x{:08X}",
            p.effective_mask.0
        );
    }

    #[test]
    fn generic_all_deny_blocks_full_control() {
        // GENERIC_ALL deny must block all bits — before Finding 3 the raw
        // deny bit 0x10000000 would not have blocked any specific bit.
        let p = eval(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    deny_ace(USER, GENERIC_ALL, false),
                    allow_ace(USER, MASK_FULL_CONTROL, false),
                ],
            ),
            None,
        );
        assert_eq!(
            p.ntfs_mask.0, 0,
            "GENERIC_ALL deny must block subsequent specific allows"
        );
    }

    // --- Finding 2: ACE ordering / non-canonical DACLs ---
    // --- Finding 2: ACE order / non-canonical DACLs ---

    #[test]
    fn non_canonical_allow_before_deny_first_wins() {
        // Non-canonical (allow before deny for same trustee+bit). Windows
        // AccessCheck walks in order → the first allow wins. The old bucket
        // algorithm would have incorrectly produced "deny wins".
        let p = eval(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    allow_ace(USER, MASK_READ, false),
                    deny_ace(USER, MASK_READ, false),
                ],
            ),
            None,
        );
        assert!(
            NormalizedRights::new(p.ntfs_mask.0).is_read(),
            "In stored order, the allow comes first and wins per Windows AccessCheck"
        );
    }

    #[test]
    fn inherited_deny_after_explicit_allow_does_not_revoke() {
        // Canonical case, asserted explicitly to confirm the order-based
        // logic reproduces the prior precedence rule.
        let p = eval(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    allow_ace(USER, MASK_READ, false), // explicit
                    deny_ace(USER, MASK_READ, true),   // inherited (would come later in canonical)
                ],
            ),
            None,
        );
        assert!(
            NormalizedRights::new(p.ntfs_mask.0).is_read(),
            "explicit allow must keep its bit; inherited deny is too late"
        );
    }

    #[test]
    fn order_first_deny_blocks_subsequent_allow() {
        let p = eval(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    deny_ace(USER, MASK_READ, false),
                    allow_ace(USER, MASK_FULL_CONTROL, false),
                ],
            ),
            None,
        );
        assert_eq!(
            p.ntfs_mask.0 & MASK_READ,
            0,
            "explicit deny first must block matching bits in later allow"
        );
        assert!(
            p.ntfs_mask.0 & FILE_WRITE_DATA != 0,
            "non-denied bits from the allow must survive"
        );
    }

    #[test]
    fn detects_non_canonical_dacl_position() {
        let dacl = vec![
            allow_ace(USER, MASK_READ, false),
            deny_ace(USER, MASK_READ, false),
        ];
        assert_eq!(
            super::first_non_canonical_position(&dacl),
            Some(1),
            "deny at index 1 follows allow at index 0 — non-canonical"
        );
    }

    /// Follow-up finding 3: a non-canonical DACL must surface as a
    /// structured marker in `EffectivePermission.diagnostics`, not only
    /// as a warn log.
    #[test]
    fn non_canonical_dacl_yields_diagnostic_marker() {
        use adpa_core::model::PermissionDiagnostic;
        let p = eval(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    allow_ace(USER, MASK_READ, false), // explicit allow at index 0
                    deny_ace(USER, MASK_READ, false),  // explicit deny at index 1 — non-canonical
                ],
            ),
            None,
        );
        assert_eq!(p.diagnostics.len(), 1);
        assert_eq!(
            p.diagnostics[0],
            PermissionDiagnostic::NonCanonicalDaclOrder { at_index: 1 }
        );
    }

    #[test]
    fn canonical_dacl_yields_no_diagnostic_marker() {
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, MASK_READ, false)]),
            None,
        );
        assert!(p.diagnostics.is_empty());
    }

    #[test]
    fn null_dacl_yields_no_diagnostic_marker() {
        let p = eval(user(USER), vec![], fso_null_dacl(), None);
        assert!(p.diagnostics.is_empty());
    }

    /// Follow-up finding 2: the engine pushes `UnsupportedShareAces`
    /// into the structured diagnostics when the caller provides a
    /// count > 0. Share diagnostics become symmetric to NTFS side.
    #[test]
    fn unsupported_share_aces_count_emits_diagnostic() {
        use adpa_core::model::PermissionDiagnostic;
        let p = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![],
                file_system_object: fso(None, vec![allow_ace(USER, MASK_READ, false)]),
                share_status: ShareMaskStatus::Applied(AccessMask(MASK_READ)),
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 4,
                sid_names: std::collections::BTreeMap::new(),
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap();
        assert!(
            p.diagnostics.iter().any(
                |d| matches!(d, PermissionDiagnostic::UnsupportedShareAces { count } if *count == 4)
            ),
            "diagnostics must include UnsupportedShareAces {{ count: 4 }}, got: {:?}",
            p.diagnostics
        );
    }

    #[test]
    fn zero_unsupported_share_aces_no_diagnostic() {
        use adpa_core::model::PermissionDiagnostic;
        let p = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![],
                file_system_object: fso(None, vec![allow_ace(USER, MASK_READ, false)]),
                share_status: ShareMaskStatus::Applied(AccessMask(MASK_READ)),
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap();
        assert!(
            !p.diagnostics
                .iter()
                .any(|d| matches!(d, PermissionDiagnostic::UnsupportedShareAces { .. })),
            "no UnsupportedShareAces diagnostic when count == 0"
        );
    }

    // --- Explanation path: name resolution via sid_names + group_name ---

    /// Memberships carrying `group_name` should inject the name into the
    /// step text without requiring anything from `sid_names`.
    #[test]
    fn member_step_uses_group_name_when_present() {
        let mut gm = membership(USER, GROUP_A);
        gm.group_name = Some("Domain Admins".to_owned());
        let p = eval(
            user(USER),
            vec![gm],
            fso(None, vec![allow_ace(GROUP_A, MASK_READ, false)]),
            None,
        );
        let member_step = p
            .path_explanation
            .steps
            .iter()
            .find(|s| s.starts_with("Member of "))
            .expect("explanation must contain a Member-of step");
        assert!(
            member_step.contains("Domain Admins"),
            "Member step should contain group name 'Domain Admins', got: {member_step}"
        );
        assert!(
            member_step.contains(GROUP_A),
            "Member step should still carry the SID for disambiguation, got: {member_step}"
        );
    }

    /// Without `group_name` set the engine should consult the `sid_names`
    /// table — an entry there must have the same effect.
    #[test]
    fn member_step_uses_sid_names_table_as_fallback() {
        let gm = membership(USER, GROUP_A);
        let mut sid_names = std::collections::BTreeMap::new();
        sid_names.insert(GROUP_A.to_owned(), "EXAMPLE\\AdminGroup".to_owned());
        let p = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![gm],
                file_system_object: fso(None, vec![allow_ace(GROUP_A, MASK_READ, false)]),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names,
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap();
        let member_step = p
            .path_explanation
            .steps
            .iter()
            .find(|s| s.starts_with("Member of "))
            .expect("explanation must contain a Member-of step");
        assert!(
            member_step.contains("EXAMPLE\\AdminGroup"),
            "Member step should contain the name from sid_names, got: {member_step}"
        );
    }

    /// `Allow ACE for BUILTIN\Administrators (S-1-5-32-544) → Modify`
    /// statt nur `Allow ACE for S-1-5-32-544 → Modify` erscheint.
    /// `Allow ACE for BUILTIN\Administrators (S-1-5-32-544) → Modify`
    /// appears instead of just `Allow ACE for S-1-5-32-544 → Modify`.
    #[test]
    fn ace_step_uses_sid_names_for_trustee() {
        let gm = membership(USER, GROUP_A);
        let mut sid_names = std::collections::BTreeMap::new();
        sid_names.insert(GROUP_A.to_owned(), "BUILTIN\\Administrators".to_owned());
        let p = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![gm],
                file_system_object: fso(None, vec![allow_ace(GROUP_A, MASK_READ, false)]),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names,
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap();
        let ace_step = p
            .path_explanation
            .steps
            .iter()
            .find(|s| s.starts_with("Allow ACE "))
            .expect("explanation must contain an Allow ACE step");
        assert!(
            ace_step.contains("BUILTIN\\Administrators"),
            "ACE step should include the trustee name, got: {ace_step}"
        );
        assert!(
            ace_step.contains(GROUP_A),
            "ACE step should still carry the SID, got: {ace_step}"
        );
    }

    /// With no name in either source the previous behaviour must hold —
    /// only the SID appears, no fabricated parentheses.
    #[test]
    fn member_and_ace_steps_fall_back_to_sid_when_no_name_known() {
        let p = eval(
            user(USER),
            vec![membership(USER, GROUP_A)],
            fso(None, vec![allow_ace(GROUP_A, MASK_READ, false)]),
            None,
        );
        let member_step = p
            .path_explanation
            .steps
            .iter()
            .find(|s| s.starts_with("Member of "))
            .expect("explanation must contain a Member-of step");
        assert_eq!(
            member_step,
            &format!("Member of {GROUP_A} [direct]"),
            "without names the member step must be SID-only"
        );
        let ace_step = p
            .path_explanation
            .steps
            .iter()
            .find(|s| s.starts_with("Allow ACE "))
            .expect("explanation must contain an Allow ACE step");
        assert!(
            ace_step.starts_with(&format!("Allow ACE [explicit] for {GROUP_A} ")),
            "without names the ACE step must lead with the SID, got: {ace_step}"
        );
    }

    #[test]
    fn canonical_dacl_passes_detector() {
        let dacl = vec![
            deny_ace(USER, MASK_READ, false),  // explicit deny
            allow_ace(USER, MASK_READ, false), // explicit allow
            deny_ace(USER, MASK_WRITE, true),  // inherited deny
            allow_ace(USER, MASK_READ, true),  // inherited allow
        ];
        assert_eq!(super::first_non_canonical_position(&dacl), None);
    }

    // --- Finding 4: AccessContext / kontextspezifische Well-Known-SIDs ---
    // --- Finding 4: AccessContext / context-specific well-known SIDs ---

    /// S-1-5-2 = NETWORK
    const SID_NETWORK: &str = "S-1-5-2";
    /// S-1-5-4 = INTERACTIVE
    const SID_INTERACTIVE: &str = "S-1-5-4";
    /// S-1-2-0 = LOCAL
    const SID_LOCAL: &str = "S-1-2-0";

    #[test]
    fn network_ace_applies_in_remote_smb_context() {
        // NETWORK-ACE matcht.
        // SMB access: NETWORK must implicitly be in the token so a NETWORK
        // ACE matches.
        let p = eval_with_context(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(SID_NETWORK, MASK_READ, false)]),
            None,
            AccessContext::RemoteSmb,
        );
        assert!(
            NormalizedRights::new(p.ntfs_mask.0).is_read(),
            "NETWORK ACE must apply in RemoteSmb context"
        );
    }

    #[test]
    fn network_ace_does_not_apply_in_local_interactive_context() {
        // Local interactive access: NETWORK is NOT in the token. A NETWORK
        // ACE must not contribute.
        let p = eval_with_context(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(SID_NETWORK, MASK_READ, false)]),
            None,
            AccessContext::LocalInteractive,
        );
        assert_eq!(
            p.ntfs_mask.0, 0,
            "NETWORK ACE must not apply in LocalInteractive context"
        );
    }

    #[test]
    fn network_ace_does_not_apply_in_unspecified_context() {
        // Default context: no context-specific well-knowns. NETWORK ACE has
        // no effect — same behavior as pre-Finding 4 for callers that don't
        // set a context yet.
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(SID_NETWORK, MASK_READ, false)]),
            None,
        );
        assert_eq!(
            p.ntfs_mask.0, 0,
            "Unspecified context must not implicitly add NETWORK"
        );
    }

    #[test]
    fn interactive_ace_applies_in_local_interactive_context() {
        let p = eval_with_context(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(SID_INTERACTIVE, MASK_READ, false)]),
            None,
            AccessContext::LocalInteractive,
        );
        assert!(
            NormalizedRights::new(p.ntfs_mask.0).is_read(),
            "INTERACTIVE ACE must apply in LocalInteractive context"
        );
    }

    #[test]
    fn interactive_ace_does_not_apply_in_remote_smb_context() {
        let p = eval_with_context(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(SID_INTERACTIVE, MASK_READ, false)]),
            None,
            AccessContext::RemoteSmb,
        );
        assert_eq!(
            p.ntfs_mask.0, 0,
            "INTERACTIVE ACE must not apply in RemoteSmb context"
        );
    }

    #[test]
    fn local_ace_applies_in_local_interactive_context() {
        let p = eval_with_context(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(SID_LOCAL, MASK_READ, false)]),
            None,
            AccessContext::LocalInteractive,
        );
        assert!(
            NormalizedRights::new(p.ntfs_mask.0).is_read(),
            "LOCAL (S-1-2-0) ACE must apply in LocalInteractive context"
        );
    }

    #[test]
    fn network_deny_blocks_user_allow_in_remote_smb_context() {
        // Direct audit use case: a "Deny NETWORK" must apply over SMB and
        // override an allow for the user — pre-Finding 4 this was ignored
        // because NETWORK was not in the token.
        let p = eval_with_context(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    deny_ace(SID_NETWORK, MASK_READ, false),
                    allow_ace(USER, MASK_READ, false),
                ],
            ),
            None,
            AccessContext::RemoteSmb,
        );
        assert_eq!(
            p.ntfs_mask.0 & MASK_READ,
            0,
            "Deny on NETWORK must override user allow over SMB"
        );
    }

    #[test]
    fn build_token_sids_with_context_includes_universal_well_knowns_for_unspecified() {
        let token =
            super::build_token_sids_with_context(USER, &[], &[], AccessContext::Unspecified);
        assert!(token.contains("S-1-1-0"), "Everyone must be present");
        assert!(
            token.contains("S-1-5-11"),
            "Authenticated Users must be present"
        );
        assert!(
            !token.contains(SID_NETWORK),
            "NETWORK must NOT be present in Unspecified context"
        );
        assert!(
            !token.contains(SID_INTERACTIVE),
            "INTERACTIVE must NOT be present in Unspecified context"
        );
    }

    #[test]
    fn build_token_sids_with_context_adds_network_for_remote_smb() {
        let token = super::build_token_sids_with_context(USER, &[], &[], AccessContext::RemoteSmb);
        assert!(
            token.contains(SID_NETWORK),
            "NETWORK must be added for RemoteSmb"
        );
        assert!(
            !token.contains(SID_INTERACTIVE),
            "INTERACTIVE must NOT be added for RemoteSmb"
        );
    }

    #[test]
    fn build_token_sids_with_context_adds_interactive_and_local_for_local_interactive() {
        let token =
            super::build_token_sids_with_context(USER, &[], &[], AccessContext::LocalInteractive);
        assert!(
            token.contains(SID_INTERACTIVE),
            "INTERACTIVE must be added for LocalInteractive"
        );
        assert!(
            token.contains(SID_LOCAL),
            "LOCAL must be added for LocalInteractive"
        );
        assert!(
            !token.contains(SID_NETWORK),
            "NETWORK must NOT be added for LocalInteractive"
        );
    }

    // ------------------------------------------------------------------
    // Finding 1 / Review 2026-05-31 — Membership path in the explanation
    // ------------------------------------------------------------------

    /// Builds a nested membership with a concrete path. The resulting
    /// explanation must contain the intermediate groups in the correct
    /// order — core requirement from finding 1.
    fn nested_membership(
        user_sid: &str,
        user_name: &str,
        group_a_sid: &str,
        group_a_name: &str,
        group_b_sid: &str,
        group_b_name: &str,
    ) -> GroupMembership {
        GroupMembership {
            member_sid: Sid(user_sid.into()),
            group_sid: Sid(group_b_sid.into()),
            direct: false,
            group_name: Some(group_b_name.into()),
            path: Some(MembershipPath {
                nodes: vec![
                    Sid(user_sid.into()),
                    Sid(group_a_sid.into()),
                    Sid(group_b_sid.into()),
                ],
                names: vec![
                    Some(user_name.into()),
                    Some(group_a_name.into()),
                    Some(group_b_name.into()),
                ],
                source: MembershipPathSource::DomainGroup,
                complete: true,
            }),
        }
    }

    fn direct_membership_with_path(
        user_sid: &str,
        user_name: &str,
        group_sid: &str,
        group_name: &str,
        source: MembershipPathSource,
    ) -> GroupMembership {
        GroupMembership {
            member_sid: Sid(user_sid.into()),
            group_sid: Sid(group_sid.into()),
            direct: true,
            group_name: Some(group_name.into()),
            path: Some(MembershipPath {
                nodes: vec![Sid(user_sid.into()), Sid(group_sid.into())],
                names: vec![Some(user_name.into()), Some(group_name.into())],
                source,
                complete: true,
            }),
        }
    }

    fn incomplete_transitive_membership(
        user_sid: &str,
        user_name: &str,
        group_sid: &str,
        group_name: &str,
    ) -> GroupMembership {
        GroupMembership {
            member_sid: Sid(user_sid.into()),
            group_sid: Sid(group_sid.into()),
            direct: false,
            group_name: Some(group_name.into()),
            path: Some(MembershipPath {
                nodes: vec![Sid(user_sid.into()), Sid(group_sid.into())],
                names: vec![Some(user_name.into()), Some(group_name.into())],
                source: MembershipPathSource::LdapMatchingRule,
                complete: false,
            }),
        }
    }

    fn fso_with_dacl(dacl: Vec<AceEntry>) -> FileSystemObject {
        FileSystemObject {
            path: NormalizedPath(r"C:\test".into()),
            is_directory: true,
            owner_sid: None,
            dacl,
            inheritance_disabled: false,
            is_reparse_point: false,
            unsupported_aces: vec![],
            null_dacl: false,
        }
    }

    #[test]
    fn explanation_contains_nested_chain_in_order() {
        // User → GRP_A → GRP_B → ACE on GRP_B → Modify.
        // User → GRP_A → GRP_B → ACE on GRP_B → Modify. The explanation
        // text must contain "GRP_A → GRP_B" exactly in that order — in
        // a single step (no splitting allowed).
        let identity = user(USER);
        let memberships = vec![nested_membership(
            USER,
            "max.mustermann",
            GROUP_A,
            "GRP_A",
            GROUP_B,
            "GRP_B",
        )];
        let dacl = vec![allow_ace(
            GROUP_B,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            true,
        )];
        let result = eval(identity, memberships, fso_with_dacl(dacl), None);
        let joined = result.path_explanation.steps.join("\n");

        // Exactly one membership step for the nested chain.
        let chain_step = result
            .path_explanation
            .steps
            .iter()
            .find(|s| s.contains("Member of") && s.contains("GRP_B"))
            .unwrap_or_else(|| panic!("no membership step for GRP_B found in:\n{joined}"));

        // Verify order within the chain block (after "via ") — the target
        // group already appears in the display prefix.
        let via_block = chain_step
            .split_once("via ")
            .map(|(_, rest)| rest)
            .unwrap_or_else(|| panic!("chain step missing 'via' marker:\n{chain_step}"));
        let user_pos = via_block.find("max.mustermann").unwrap_or_else(|| {
            panic!("user name not in chain block:\n{via_block}");
        });
        let a_pos = via_block
            .find("GRP_A")
            .unwrap_or_else(|| panic!("GRP_A not in chain block:\n{via_block}"));
        let b_pos = via_block
            .find("GRP_B")
            .unwrap_or_else(|| panic!("GRP_B not in chain block:\n{via_block}"));
        assert!(
            user_pos < a_pos && a_pos < b_pos,
            "chain order must be User → A → B, got:\n{via_block}"
        );
        assert!(
            chain_step.contains("DomainGroup"),
            "source label must be present in chain step:\n{chain_step}"
        );
    }

    #[test]
    fn explanation_direct_membership_with_source_label() {
        let identity = user(USER);
        let memberships = vec![direct_membership_with_path(
            USER,
            "max.mustermann",
            GROUP_A,
            "GRP_A",
            MembershipPathSource::PrimaryGroup,
        )];
        let dacl = vec![allow_ace(GROUP_A, FILE_GENERIC_READ, true)];
        let result = eval(identity, memberships, fso_with_dacl(dacl), None);
        let step = result
            .path_explanation
            .steps
            .iter()
            .find(|s| s.contains("Member of"))
            .expect("membership step missing");
        assert!(
            step.contains("direct, source: PrimaryGroup"),
            "expected '[direct, source: PrimaryGroup]', got: {step}"
        );
    }

    #[test]
    fn explanation_incomplete_transitive_marks_unknown_chain() {
        let identity = user(USER);
        let memberships = vec![incomplete_transitive_membership(
            USER,
            "max.mustermann",
            GROUP_B,
            "GRP_B",
        )];
        let dacl = vec![allow_ace(GROUP_B, FILE_GENERIC_READ, true)];
        let result = eval(identity, memberships, fso_with_dacl(dacl), None);
        let step = result
            .path_explanation
            .steps
            .iter()
            .find(|s| s.contains("Member of"))
            .expect("membership step missing");
        assert!(
            step.contains("exact chain unknown"),
            "incomplete chain must be flagged, got: {step}"
        );
        assert!(
            step.contains("LdapMatchingRule"),
            "source must be labelled, got: {step}"
        );
    }

    #[test]
    fn explanation_falls_back_to_legacy_format_when_path_missing() {
        // alte Schema „[direct]" / „[transitive]" produzieren.
        // Cache reads return path=None; the engine must then fall back
        // to the legacy "[direct]" / "[transitive]" format.
        let identity = user(USER);
        let memberships = vec![GroupMembership {
            member_sid: Sid(USER.into()),
            group_sid: Sid(GROUP_A.into()),
            direct: true,
            group_name: Some("GRP_A".into()),
            path: None,
        }];
        let dacl = vec![allow_ace(GROUP_A, FILE_GENERIC_READ, true)];
        let result = eval(identity, memberships, fso_with_dacl(dacl), None);
        let step = result
            .path_explanation
            .steps
            .iter()
            .find(|s| s.contains("Member of"))
            .expect("membership step missing");
        assert!(
            step.contains("[direct]"),
            "legacy format must be used when path is None, got: {step}"
        );
        assert!(
            !step.contains("source:"),
            "legacy format must NOT contain the new source label, got: {step}"
        );
    }

    /// When `identity_not_in_configured_ldap_base = true` flows into the
    /// engine input, `IdentityNotInConfiguredLdapBase` must appear in
    /// the `diagnostics` vector. Closes review 2026-06-04 round 2
    /// finding 1 on the engine side.
    #[test]
    fn engine_pushes_identity_not_in_configured_ldap_base_diagnostic() {
        let result = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![],
                file_system_object: fso(None, vec![allow_ace(USER, MASK_READ, false)]),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: true,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap();
        assert!(
            result
                .diagnostics
                .contains(&PermissionDiagnostic::IdentityNotInConfiguredLdapBase),
            "engine must push IdentityNotInConfiguredLdapBase when the caller flag is set; got {:?}",
            result.diagnostics
        );
    }

    /// When `identity_disabled_status_unknown = true` flows into the
    /// engine input, `IdentityDisabledStatusUnknown` must appear in the
    /// `diagnostics` vector — e.g. when the SAM path could not run
    /// `NetUserGetInfo`. Closes review 2026-06-04 round 2 finding 5 on
    /// the engine side.
    #[test]
    fn engine_pushes_identity_disabled_status_unknown_diagnostic() {
        let result = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![],
                file_system_object: fso(None, vec![allow_ace(USER, MASK_READ, false)]),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: true,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap();
        assert!(
            result
                .diagnostics
                .contains(&PermissionDiagnostic::IdentityDisabledStatusUnknown),
            "engine must push IdentityDisabledStatusUnknown when the caller flag is set; got {:?}",
            result.diagnostics
        );
    }

    /// "sauber" aus.
    /// Round 4 finding 1: an LDAP identity lookup error must surface.
    #[test]
    fn engine_pushes_identity_lookup_failed_diagnostic_with_reason() {
        let result = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![],
                file_system_object: fso(None, vec![allow_ace(USER, MASK_READ, false)]),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: Some(
                    "LDAP bind failed: connection refused".to_owned(),
                ),
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap();
        let found = result
            .diagnostics
            .iter()
            .find_map(|d| match d {
                PermissionDiagnostic::IdentityLookupFailed { reason } => Some(reason.clone()),
                _ => None,
            })
            .expect("engine must push IdentityLookupFailed when the caller flag is Some");
        assert!(
            found.contains("connection refused"),
            "reason must carry the underlying message, got: {found}"
        );
    }

    /// Review 2026-06-04 round 4 finding 1: a failed
    /// `GroupResolutionFailed { reason }`-Marker.
    /// Round 4 finding 1: failed group resolution after identity hit.
    #[test]
    fn engine_pushes_group_resolution_failed_diagnostic_with_reason() {
        let result = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![],
                file_system_object: fso(None, vec![allow_ace(USER, MASK_READ, false)]),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: Some(
                    "LDAP group query timed out after 30s".to_owned(),
                ),
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap();
        let found = result
            .diagnostics
            .iter()
            .find_map(|d| match d {
                PermissionDiagnostic::GroupResolutionFailed { reason } => Some(reason.clone()),
                _ => None,
            })
            .expect("engine must push GroupResolutionFailed when the caller flag is Some");
        assert!(
            found.contains("timed out"),
            "reason must carry the underlying message, got: {found}"
        );
    }

    /// Known-limitations L1: when the identity was resolved through a
    /// Foreign Security Principal, the engine must push the structured
    /// marker so reports and risk rules see the trust-side gap.
    #[test]
    fn fsp_flag_pushes_identity_resolved_via_fsp_diagnostic() {
        let result = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![],
                file_system_object: fso(None, vec![allow_ace(USER, MASK_READ, false)]),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: true,
                group_resolution_via_global_catalog: false,
            })
            .unwrap();
        assert!(
            result.diagnostics.iter().any(|d| matches!(
                d,
                PermissionDiagnostic::IdentityResolvedViaForeignSecurityPrincipal
            )),
            "FSP marker must be present; got: {:?}",
            result.diagnostics
        );
    }

    /// Known-limitations L2: the GC flag must surface as a structured
    /// marker so reports and risk rules see the partial-membership gap.
    #[test]
    fn gc_flag_pushes_group_resolution_via_global_catalog_diagnostic() {
        let result = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![],
                file_system_object: fso(None, vec![allow_ace(USER, MASK_READ, false)]),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: true,
            })
            .unwrap();
        assert!(
            result
                .diagnostics
                .iter()
                .any(|d| matches!(d, PermissionDiagnostic::GroupResolutionViaGlobalCatalog)),
            "GC marker must be present; got: {:?}",
            result.diagnostics
        );
    }

    /// Round 6 finding 1: a LocalGroup-sourced GroupMembership must
    /// render as a Member-of step with mediator chain in the
    /// explanation path.
    #[test]
    fn local_group_membership_renders_in_explanation_path() {
        use adpa_core::model::{MembershipPath, MembershipPathSource};

        // BUILTIN\Administrators.
        // Build mediator chain: User → Domain Admins → BUILTIN\Administrators.
        const BUILTIN_ADMINS: &str = "S-1-5-32-544";
        let mut sid_names = std::collections::BTreeMap::new();
        sid_names.insert(USER.to_owned(), "EXAMPLE\\alice".to_owned());
        sid_names.insert(GROUP_A.to_owned(), "EXAMPLE\\Domain Admins".to_owned());
        sid_names.insert(
            BUILTIN_ADMINS.to_owned(),
            "BUILTIN\\Administrators".to_owned(),
        );

        let local_membership = GroupMembership {
            member_sid: Sid(USER.to_owned()),
            group_sid: Sid(BUILTIN_ADMINS.to_owned()),
            direct: false,
            group_name: Some("BUILTIN\\Administrators".to_owned()),
            path: Some(MembershipPath {
                nodes: vec![
                    Sid(USER.to_owned()),
                    Sid(GROUP_A.to_owned()),
                    Sid(BUILTIN_ADMINS.to_owned()),
                ],
                names: vec![
                    Some("EXAMPLE\\alice".to_owned()),
                    Some("EXAMPLE\\Domain Admins".to_owned()),
                    Some("BUILTIN\\Administrators".to_owned()),
                ],
                source: MembershipPathSource::LocalGroup,
                complete: true,
            }),
        };

        let result = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![membership(USER, GROUP_A), local_membership],
                file_system_object: fso(None, vec![allow_ace(BUILTIN_ADMINS, MASK_MODIFY, false)]),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: vec![Sid(BUILTIN_ADMINS.to_owned())],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::Applied,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names,
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap();

        assert_eq!(result.effective_mask.0, MASK_MODIFY);

        // Kette enthalten.
        let local_step = result
            .path_explanation
            .steps
            .iter()
            .find(|s| s.contains("BUILTIN\\Administrators") && s.contains("LocalGroup"))
            .unwrap_or_else(|| {
                panic!(
                    "explanation must contain a LocalGroup-sourced Member step for BUILTIN\\\\Administrators; got: {:?}",
                    result.path_explanation.steps
                )
            });
        assert!(
            local_step.contains("Domain Admins"),
            "mediator (Domain Admins) must appear in the LocalGroup chain step; got: {local_step}"
        );
    }

    /// Unvollstaendigkeit sieht.
    /// Round 6 finding 1: `complete: false` paths must render as
    /// "exact chain unknown" so the auditor sees the incompleteness.
    #[test]
    fn local_group_membership_with_incomplete_path_renders_unknown_chain() {
        use adpa_core::model::{MembershipPath, MembershipPathSource};

        const BUILTIN_ADMINS: &str = "S-1-5-32-544";
        let local_membership = GroupMembership {
            member_sid: Sid(USER.to_owned()),
            group_sid: Sid(BUILTIN_ADMINS.to_owned()),
            direct: false,
            group_name: Some("BUILTIN\\Administrators".to_owned()),
            path: Some(MembershipPath {
                nodes: vec![Sid(USER.to_owned()), Sid(BUILTIN_ADMINS.to_owned())],
                names: vec![None, Some("BUILTIN\\Administrators".to_owned())],
                source: MembershipPathSource::LocalGroup,
                complete: false,
            }),
        };

        let result = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![local_membership],
                file_system_object: fso(None, vec![allow_ace(BUILTIN_ADMINS, MASK_READ, false)]),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: vec![Sid(BUILTIN_ADMINS.to_owned())],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::Applied,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap();

        let step = result
            .path_explanation
            .steps
            .iter()
            .find(|s| s.contains("BUILTIN\\Administrators"))
            .expect("must find a Member step for BUILTIN\\Administrators");
        assert!(
            step.contains("exact chain unknown"),
            "incomplete local-group path must render as 'exact chain unknown'; got: {step}"
        );
        assert!(
            step.contains("LocalGroup"),
            "source must still be labelled LocalGroup; got: {step}"
        );
    }

    /// Block A verification 2026-06-05: a Deny ACE that overrides an Allow
    /// must surface as its own "Deny aggregation" step. Otherwise the reader
    /// only sees "Effective: Special (0x...)" without grasping that Deny
    /// stripped the Allow bits.
    #[test]
    fn deny_aggregation_step_surfaces_blocked_bits() {
        let result = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![membership(USER, GROUP_A)],
                file_system_object: fso(
                    None,
                    vec![
                        // Explicit Deny Modify for the user (cannonical first).
                        deny_ace(USER, MASK_MODIFY, false),
                        // Inherited Allow Modify via group membership.
                        allow_ace(GROUP_A, MASK_MODIFY, true),
                    ],
                ),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: Vec::new(),
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap();

        // Deny wins for all overlapping bits → effective is 0.
        assert_eq!(
            result.effective_mask.0, 0,
            "Deny Modify must zero out Allow Modify, got 0x{:08X}",
            result.effective_mask.0
        );

        let deny_step = result
            .path_explanation
            .steps
            .iter()
            .find(|s| s.contains("Deny aggregation"))
            .unwrap_or_else(|| {
                panic!(
                    "explanation must contain a 'Deny aggregation' step; got: {:?}",
                    result.path_explanation.steps
                )
            });
        assert!(
            deny_step.contains(&format!("0x{:08X}", MASK_MODIFY)),
            "Deny aggregation step must name the blocked mask 0x{:08X}; got: {deny_step}",
            MASK_MODIFY
        );
        assert!(
            deny_step.contains("decided by Deny ACEs"),
            "Deny aggregation step must spell out 'decided by Deny ACEs'; got: {deny_step}"
        );
    }

    /// Complement: if there is no Deny ACE, the new step must not appear,
    /// otherwise it would clutter every normal report.
    #[test]
    fn deny_aggregation_step_absent_when_no_deny() {
        let result = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![membership(USER, GROUP_A)],
                file_system_object: fso(None, vec![allow_ace(GROUP_A, MASK_MODIFY, true)]),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: Vec::new(),
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap();

        let has_deny_step = result
            .path_explanation
            .steps
            .iter()
            .any(|s| s.contains("Deny aggregation"));
        assert!(
            !has_deny_step,
            "no Deny ACE present → no Deny aggregation step expected; got: {:?}",
            result.path_explanation.steps
        );
    }

    /// zeigt.
    /// Round-7 finding 1 (end-to-end): with `AccessContext::RemoteSmb` the
    /// `NETWORK` well-known (S-1-5-2) must land in the token and an Allow
    /// ACE on NETWORK must drive the effective mask — regardless of whether
    /// the path is UNC or local. This is the engine-side prerequisite for
    /// `AccessContext::for_path_with_smb` to do anything useful.
    #[test]
    fn remote_smb_context_grants_network_ace_even_on_local_path() {
        const NETWORK_SID: &str = "S-1-5-2";
        let result = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: Vec::new(),
                file_system_object: fso(None, vec![allow_ace(NETWORK_SID, MASK_READ, false)]),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: Vec::new(),
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                // Key setting: local-looking input, explicit RemoteSmb —
                // mirrors what CLI/GUI now produce via for_path_with_smb
                // when --smb-server / --share-name is provided.
                access_context: AccessContext::RemoteSmb,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap();
        assert_eq!(
            result.effective_mask.0, MASK_READ,
            "NETWORK Allow Read must take effect under RemoteSmb (got 0x{:08X})",
            result.effective_mask.0
        );
    }

    /// Counterpart: under `LocalInteractive` a NETWORK Allow ACE must NOT
    /// take effect — that was the silent-wrong outcome for local-path +
    /// SMB-context before the round-7 fix.
    #[test]
    fn local_interactive_context_ignores_network_ace() {
        const NETWORK_SID: &str = "S-1-5-2";
        let result = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: Vec::new(),
                file_system_object: fso(None, vec![allow_ace(NETWORK_SID, MASK_READ, false)]),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: Vec::new(),
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                access_context: AccessContext::LocalInteractive,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                group_resolution_via_sam_fallback: false,
                identity_not_in_configured_ldap_base: false,
                identity_disabled_status_unknown: false,
                identity_lookup_failure_reason: None,
                group_resolution_failure_reason: None,
                identity_resolved_via_fsp: false,
                group_resolution_via_global_catalog: false,
            })
            .unwrap();
        assert_eq!(
            result.effective_mask.0, 0,
            "NETWORK Allow must NOT take effect under LocalInteractive (got 0x{:08X})",
            result.effective_mask.0
        );
    }
}
