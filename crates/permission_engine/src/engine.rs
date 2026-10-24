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

use std::collections::HashSet;

use adpa_core::{
    error::CoreError,
    model::{
        format_also_via, AccessContext, AccessMask, AceEffect, AceEntry, AceKind, AceOutcome,
        ContributingAce, EffectivePermission, GroupMembership, Identity, LocalGroupDescriptor,
        LocalGroupEntry, LocalGroupExpansion, MembershipHop, MembershipPathSource,
        PermissionDiagnostic, PermissionPath, PermissionTrace, PolicyDword, RemoteUacFiltering,
        ShareEvalStatus, ShareMaskStatus, Sid, SynchronizeGap, TraceGroup, TraceGroupState,
        TraceLayer, UncertainLayer, Uncertainty,
    },
    traits::{PermissionEvaluationInput, PermissionEvaluator, SelectiveAuthenticationCheck},
};

use crate::mask::{
    expand_generic_rights, rights_statement, NormalizedRights, FILE_DELETE, FILE_READ_CONTROL,
    FILE_SYNCHRONIZE, FILE_WRITE_DAC, INHERIT_ONLY_ACE, MASK_FULL_CONTROL, NOT_DETERMINABLE,
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
        let mut user_sids = collect_user_sids(
            &input.identity,
            &input.group_memberships,
            &input.local_group_sids,
            input.access_context,
        );
        // ADR 0070: a group User Account Control may filter is never an
        // enabled token group here, whichever list it arrived in — it is
        // deny-only below, and its Allow side is bounded.
        for filtered in &input.uac_filtered_group_sids {
            user_sids.remove(&filtered.0);
        }
        // L17: EveryoneIncludesAnonymous read from the target decides Everyone.
        if anonymous_gets_everyone(&input.identity.sid.0, input.anonymous_everyone) {
            user_sids.insert(SID_EVERYONE.to_owned());
        }
        // Lab (ADR 0071): Windows leaves Cryptographic Operators out of the
        // token when the account is also in another UAC-filtered group — over
        // the network too — and makes it deny-only in a filtered token. A
        // membership, from LDAP or the local-group table, is therefore never
        // certain: bounded like a logon-dependent group.
        let crypto_operators_uncertain = user_sids.remove(SID_CRYPTOGRAPHIC_OPERATORS);

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

        // ADR 0070: groups User Account Control may filter out of a local
        // account's token. A filtered group is deny-only — it matches Deny
        // ACEs, never Allow ACEs — so the shown result is the filtered token
        // and the Allow side is bounded below.
        let deny_only_sids: HashSet<String> = input
            .uac_filtered_group_sids
            .iter()
            .map(|s| s.0.clone())
            .collect();
        // The owner is a filtered group of the token: whether the implicit
        // owner grant (and OWNER RIGHTS ACEs) apply depends on the filtering.
        // ADR 0076: remote UAC decided from the target's policies — the
        // filtered groups are then certainly deny-only (not bounded).
        let uac_certain_reason: Option<String> = match &input.remote_uac {
            RemoteUacFiltering::Filtered { reason } => Some(reason.clone()),
            _ => None,
        };
        let uac_filter_certain = uac_certain_reason.is_some();
        let uncertain_owner: Option<&str> = input
            .file_system_object
            .owner_sid
            .as_ref()
            .map(|o| o.0.as_str())
            .filter(|o| deny_only_sids.contains(*o) && !uac_filter_certain);

        // NULL DACL means "no access control" — Windows grants everyone full access.
        // An empty DACL (dacl == [] && null_dacl == false) by contrast denies everything.
        let walk = if input.file_system_object.null_dacl {
            DaclWalkOutcome {
                granted: MASK_FULL_CONTROL,
                denied: 0,
                contributions: Vec::new(),
                // A NULL DACL has no ACEs to attribute contributions to.
                decided_per_ace: Vec::new(),
            }
        } else {
            walk_dacl_stored_order(&input.file_system_object.dacl, &match_sids, &deny_only_sids)
        };
        let mut ntfs_raw = walk.granted;
        let denied_raw = walk.denied;
        let contributing_sids = walk.contributions;
        let decided_per_ace = walk.decided_per_ace;

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

        // ADR 0065: ACEs for well-known SIDs whose presence in the real token
        // depends on how the user logs on (This Organization, NTLM
        // authentication, console logon, …) are not modelled. Instead of
        // silently treating them as "not in the token", bound the result:
        // the upper bound counts every such Allow as matching and no such
        // Deny, the lower bound the opposite. Equal bounds mean those ACEs
        // cannot change this result — it stays exact.
        let mut logon_dependent_groups: HashSet<String> = input
            .logon_dependent_group_sids
            .iter()
            .map(|s| s.0.clone())
            .collect();
        if crypto_operators_uncertain {
            logon_dependent_groups.insert(SID_CRYPTOGRAPHIC_OPERATORS.to_owned());
        }
        // Review CR-8: Guest / anonymous — Authenticated Users (and, for
        // anonymous, Everyone) bound the result.
        logon_dependent_groups.extend(
            uncertain_well_knowns_with(&input.identity.sid.0, input.anonymous_everyone)
                .iter()
                .map(|s| (*s).to_owned()),
        );
        let logon_dependent = if input.file_system_object.null_dacl {
            None
        } else {
            logon_dependent_bounds(
                &input.file_system_object.dacl,
                &match_sids,
                input.access_context,
                &logon_dependent_groups,
                &deny_only_sids,
                owner_implicit_bits,
                uncertain_owner,
                uac_filter_certain,
            )
        };

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

        let matched_aces =
            collect_matched_aces(&input.file_system_object.dacl, &match_sids, &deny_only_sids);

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
        // Engine review 2026-06-12 finding 3: NTFS ACEs the parser could
        // not interpret are now a first-class structured diagnostic, not
        // only a bare count — surfaced uniformly in every output.
        let unsupported_ntfs_count = input.file_system_object.unsupported_aces.len();
        if unsupported_ntfs_count > 0 {
            diagnostics.push(PermissionDiagnostic::UnsupportedNtfsAces {
                count: unsupported_ntfs_count,
            });
        }
        // ADR 0065: logon-dependent trustees that decide bits of this result.
        if let Some(bounds) = &logon_dependent {
            diagnostics.push(PermissionDiagnostic::LogonDependentTrustees {
                sids: bounds.sids.clone(),
                min_mask: bounds.min,
                max_mask: bounds.max,
            });
        }
        // Finding 6: SAM fallback without LDAP — nested domain groups are
        // not recursively resolved.
        if input.resolution.group_resolution_via_sam_fallback {
            diagnostics.push(PermissionDiagnostic::DomainGroupRecursionIncomplete);
        }
        // Finding 7: disabled identity — ACL-theoretical rights computed,
        // but the account normally cannot authenticate.
        if input.identity.disabled {
            diagnostics.push(PermissionDiagnostic::IdentityDisabled);
        }
        // Review 2026-06-04 round 2 finding 1: identity resolved via LSA,
        // Review 2026-06-04 round 2 finding 1: identity resolved via LSA but
        // LDAP base does not index it (multi-domain).
        if input.resolution.identity_not_in_configured_ldap_base {
            diagnostics.push(PermissionDiagnostic::IdentityNotInConfiguredLdapBase);
        }
        // Review 2026-06-04 round 2 finding 5: disabled status could not be
        // determined.
        if input.resolution.identity_disabled_status_unknown {
            diagnostics.push(PermissionDiagnostic::IdentityDisabledStatusUnknown);
        }
        // Review 2026-06-04 round 4 finding 1: a technical LDAP identity
        // lookup failure is incompleteness; the report must surface it
        // instead of looking clean with a placeholder identity.
        if let Some(reason) = input.resolution.identity_lookup_failure_reason {
            diagnostics.push(PermissionDiagnostic::IdentityLookupFailed { reason });
        }
        // Review 2026-06-04 round 4 finding 1: failed or skipped group
        // resolution must be visible as incomplete.
        if let Some(reason) = input.resolution.group_resolution_failure_reason {
            diagnostics.push(PermissionDiagnostic::GroupResolutionFailed { reason });
        }
        // ADR 0066: groups that may be missing from a successful resolution.
        for reason in input.resolution.group_resolution_gaps {
            diagnostics.push(PermissionDiagnostic::GroupResolutionIncomplete { reason });
        }
        // ADR 0070: UAC-filtered groups of a local account — named, so the
        // bounds they cause are explained.
        if !input.uac_filtered_group_sids.is_empty() {
            let groups = input
                .uac_filtered_group_sids
                .iter()
                .map(|s| match input.sid_names.get(&s.0) {
                    Some(name) => format!("{name} ({})", s.0),
                    None => s.0.clone(),
                })
                .collect();
            diagnostics.push(PermissionDiagnostic::UacFilteredGroups { groups });
        }
        // ADR 0076: the target's policies decided remote UAC — say so.
        match &input.remote_uac {
            RemoteUacFiltering::Filtered { reason } => {
                diagnostics.push(PermissionDiagnostic::RemoteUacPolicy {
                    filtered: true,
                    reason: reason.clone(),
                })
            }
            RemoteUacFiltering::NotFiltered { reason } => {
                diagnostics.push(PermissionDiagnostic::RemoteUacPolicy {
                    filtered: false,
                    reason: reason.clone(),
                })
            }
            RemoteUacFiltering::Unknown => {}
        }
        // ADR 0072: name the well-knowns a Guest / anonymous token lacks
        // (absent) or may lack (uncertain).
        let mut guest_sids: Vec<String> = identity_absent_well_knowns(&input.identity.sid.0)
            .iter()
            .chain(uncertain_well_knowns_with(
                &input.identity.sid.0,
                input.anonymous_everyone,
            ))
            .map(|s| (*s).to_owned())
            .collect();
        // L17: Everyone read as absent from an anonymous token is named too.
        if input.identity.sid.0 == SID_ANONYMOUS_LOGON && input.anonymous_everyone == Some(false) {
            guest_sids.push(SID_EVERYONE.to_owned());
        }
        if !guest_sids.is_empty() {
            diagnostics.push(PermissionDiagnostic::GuestOrAnonymousToken { sids: guest_sids });
        }
        // ADR 0067: groups left out of the token — visible, never silent.
        if !input.resolution.excluded_non_security_groups.is_empty() {
            diagnostics.push(PermissionDiagnostic::NonSecurityGroupsExcluded {
                groups: input.resolution.excluded_non_security_groups,
            });
        }
        // ADR 0064 (lab finding AD3-1): a SID that could not be resolved is
        // only called orphaned when the evidence shows the account no longer
        // exists; otherwise its memberships are unknown — incompleteness.
        if let Some(reason) = input.resolution.identity_unresolvable_reason {
            diagnostics.push(PermissionDiagnostic::IdentityNotResolvable { reason });
        }
        if input.identity.kind == adpa_core::model::IdentityKind::Orphaned {
            diagnostics.push(PermissionDiagnostic::IdentityOrphaned);
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
        if input.resolution.identity_resolved_via_fsp {
            diagnostics.push(PermissionDiagnostic::IdentityResolvedViaForeignSecurityPrincipal);
        }
        // Known-limitations L2: memberships came from a Global Catalog
        // bind — only universal group memberships replicate fully to
        // the GC. Incompleteness trigger.
        if input.resolution.group_resolution_via_global_catalog {
            diagnostics.push(PermissionDiagnostic::GroupResolutionViaGlobalCatalog);
        }
        // ADR 0052 (L3) / ADR 0056: historical SIDs (sIDHistory). Parsed
        // values were evaluated into the token via `collect_user_sids`
        // (SidHistoryEvaluated, informational); an un-parsed remainder
        // stays un-evaluated and keeps the incompleteness trigger
        // (SidHistoryPresent). Single source of truth:
        // `Identity::sid_history_diagnostics` — shared with the
        // membership view so the two surfaces cannot drift.
        diagnostics.extend(input.identity.sid_history_diagnostics());
        // ADR 0059: same split for the historical SIDs of the token
        // GROUPS (evaluated → informational; un-parsed remainder →
        // incompleteness trigger). Shared helper, same no-drift rationale.
        diagnostics.extend(adpa_core::model::group_sid_history_diagnostics(
            &input.group_memberships,
        ));
        // ADR 0052 (L4): the identity crosses a forest trust — resolved via a
        // Foreign Security Principal or found outside the configured LDAP
        // base. SID filtering / quarantine and Selective Authentication are
        // not modeled, so actual access may be lower than shown.
        // Informational only: the FSP / outside-base markers above already
        // set incompleteness, so this deliberately adds no second trigger.
        if input.resolution.identity_resolved_via_fsp
            || input.resolution.identity_not_in_configured_ldap_base
        {
            diagnostics.push(PermissionDiagnostic::TrustBoundaryEffectsNotModeled);
        }
        // ADR 0078 (L15): an account of a trusted domain resolved on a DC of
        // that domain. SID filtering (quarantine) is applied by the resolver;
        // Selective Authentication is not modelled, so only then the trust
        // caveat. Same markers and order as the membership view.
        if let Some(t) = &input.resolution.trusted_domain {
            diagnostics.push(PermissionDiagnostic::TrustedDomainAccountResolved {
                domain: t.domain.clone(),
                home_only_groups: t.home_only_groups.clone(),
                sid_filtered: t.sid_filtered.clone(),
            });
            // ADR 0079: with the Selective Authentication check done for the
            // target, the trust's effect is modelled — the caveat stays only
            // where no check could be made.
            if t.selective_authentication && input.selective_authentication.is_none() {
                diagnostics.push(PermissionDiagnostic::TrustBoundaryEffectsNotModeled);
            }
        }
        // ADR 0085: a DFS path names the target it was evaluated on.
        if let Some(dfs) = &input.dfs {
            diagnostics.push(dfs.marker());
        }
        // ADR 0079 (L4): Selective Authentication decides whether the account
        // may log on to the target at all.
        let mut logon_refused = false;
        if let Some(check) = &input.selective_authentication {
            diagnostics.push(match check {
                SelectiveAuthenticationCheck::Allowed { server, via } => {
                    PermissionDiagnostic::SelectiveAuthenticationAllowed {
                        server: server.clone(),
                        via: via.clone(),
                    }
                }
                SelectiveAuthenticationCheck::Denied { server } => {
                    logon_refused = true;
                    PermissionDiagnostic::SelectiveAuthenticationDenied {
                        server: server.clone(),
                    }
                }
                SelectiveAuthenticationCheck::Unknown { server, reason } => {
                    PermissionDiagnostic::SelectiveAuthenticationUnknown {
                        server: server.clone(),
                        reason: reason.clone(),
                        // Decided below, once the DACL result is known.
                        affects_result: true,
                    }
                }
            });
        }

        let mut result = EffectivePermission {
            identity: input.identity,
            path: input.file_system_object.path.clone(),
            ntfs_mask: AccessMask(ntfs_raw),
            share_mask: share_mask_for_output,
            effective_mask: AccessMask(effective_raw),
            // Built below from the finished result (review CR-5).
            path_explanation: PermissionPath { steps: Vec::new() },
            share_status: output_share_status,
            local_group_status: input.local_group_status,
            contributing_sids,
            // Diagnostic: surface unsupported ACE types found on this path.
            unsupported_ace_count: input.file_system_object.unsupported_aces.len(),
            matched_aces,
            diagnostics,
            trace: Default::default(),
        };
        // ADR 0079 addendum: an undeterminable logon opens the range between
        // No access and the DACL result. When the DACL result is exactly No
        // access — nothing else uncertain, nothing granted — both ends meet:
        // refused or allowed, the account has no access. The result is exact;
        // the marker stays as information.
        if effective_raw == 0
            && result
                .uncertainty()
                .iter()
                .all(|u| u.layer == UncertainLayer::Logon)
        {
            for d in &mut result.diagnostics {
                if let PermissionDiagnostic::SelectiveAuthenticationUnknown {
                    affects_result, ..
                } = d
                {
                    *affects_result = false;
                }
            }
        }
        // Review CR-5: the explanation path states each value with the same
        // determinability as the result lines, derived from the finished
        // result (statuses and every marker) — the two cannot disagree.
        let uncertainty = result.uncertainty();
        let (path_explanation, trace) = build_explanation(ExplanationInput {
            identity: &result.identity,
            memberships: &input.group_memberships,
            dacl: &input.file_system_object.dacl,
            match_sids: &match_sids,
            deny_only_sids: &deny_only_sids,
            decided_per_ace: &decided_per_ace,
            unsupported_ntfs_count: input.file_system_object.unsupported_aces.len(),
            ntfs_raw,
            denied_raw,
            owner_implicit_bits,
            owner_rights_ace_present,
            owner_sid: input.file_system_object.owner_sid.as_ref(),
            share_mask: result.share_mask,
            share_status: &result.share_status,
            effective_raw,
            sid_names: &input.sid_names,
            logon_dependent: logon_dependent.as_ref(),
            access_context: input.access_context,
            null_dacl: input.file_system_object.null_dacl,
            is_directory: input.file_system_object.is_directory,
            uncertain_sids: &logon_dependent_groups,
            uncertain_owner,
            uac_certain_reason: uac_certain_reason.as_deref(),
            anonymous_everyone: input.anonymous_everyone,
            ntfs_determinable: result.ntfs_determinable(),
            share_determinable: result.share_determinable(),
            effective_determinable: result.effective_determinable(),
            uncertainty: &uncertainty,
            share_trace: &input.share_trace,
        });
        result.path_explanation = path_explanation;
        result.trace = trace;
        // ADR 0080 (lab 2026-10-18): SYNCHRONIZE missing from the effective
        // right. The rights stay the exact AccessCheck result — each was
        // measured exercisable without SYNCHRONIZE, locally and over SMB — but
        // every open that requests SYNCHRONIZE fails, and CreateFile (Explorer,
        // most programs) always requests it. Named, never hidden.
        if !logon_refused {
            if let Some(cause) = synchronize_gap(&result, ntfs_raw, denied_raw) {
                let marker = PermissionDiagnostic::SynchronizeNotGranted {
                    cause,
                    certain: result.effective_determinable(),
                };
                result
                    .path_explanation
                    .steps
                    .push(format!("Note — {}", marker.summary()));
                result.diagnostics.push(marker);
            }
        }
        // ADR 0079: the logon decision closes the path. The lines above stay
        // the permissions' view; a refused logon makes the effective right No
        // access — exact, because Windows never evaluates the DACL then.
        if let Some(d) = result.diagnostics.iter().find(|d| {
            matches!(
                d,
                PermissionDiagnostic::SelectiveAuthenticationAllowed { .. }
                    | PermissionDiagnostic::SelectiveAuthenticationDenied { .. }
                    | PermissionDiagnostic::SelectiveAuthenticationUnknown { .. }
            )
        }) {
            let step = match d {
                PermissionDiagnostic::SelectiveAuthenticationDenied { .. } => format!(
                    "Logon refused — {} Effective: No access (0x00000000); the lines above show \
                     what the permissions grant once the account may authenticate.",
                    d.summary()
                ),
                PermissionDiagnostic::SelectiveAuthenticationUnknown {
                    affects_result: true,
                    ..
                } => format!("{NOT_DETERMINABLE} — logon: {}", d.summary()),
                PermissionDiagnostic::SelectiveAuthenticationUnknown { .. } => format!(
                    "Logon not determinable — {} Effective: No access (0x00000000).",
                    d.summary()
                ),
                _ => format!("Logon allowed — {}", d.summary()),
            };
            result.path_explanation.steps.push(step);
        }
        if logon_refused {
            result.effective_mask = AccessMask(0);
        }
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

/// ADR 0080: why the effective right holds rights but not SYNCHRONIZE —
/// `None` when it holds SYNCHRONIZE (or its upper bound may), or nothing
/// besides it.
fn synchronize_gap(
    result: &EffectivePermission,
    ntfs_raw: u32,
    denied_raw: u32,
) -> Option<SynchronizeGap> {
    if result.effective_mask.0 & !FILE_SYNCHRONIZE == 0
        || result.effective_upper_bound() & FILE_SYNCHRONIZE != 0
    {
        return None;
    }
    Some(if ntfs_raw & FILE_SYNCHRONIZE == 0 {
        if denied_raw & FILE_SYNCHRONIZE != 0 {
            SynchronizeGap::DeniedByNtfsAce
        } else {
            SynchronizeGap::NotGrantedByNtfs
        }
    } else {
        SynchronizeGap::NotGrantedByShare
    })
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
    build_token_sids_with_context(user_sid, &[], memberships, &[], AccessContext::Unspecified)
}

/// Full token construction: own SID, the user's historical SIDs
/// (`sIDHistory` — Windows includes them in the logon token
/// unconditionally within the account's forest, ADR 0056), AD groups,
/// local server groups, the universal well-knowns (`Everyone`,
/// `Authenticated Users`), and the context-specific well-knowns:
///
/// - `RemoteSmb` → `NETWORK` (S-1-5-2)
/// - `LocalInteractive` → `INTERACTIVE` (S-1-5-4) — `LOCAL` (S-1-2-0) is
///   not certain for a local logon and is bounded instead (ADR 0069)
/// - `Unspecified` → no additional well-knowns
pub fn build_token_sids_with_context(
    user_sid: &str,
    sid_history: &[Sid],
    memberships: &[GroupMembership],
    local_group_sids: &[Sid],
    access_context: AccessContext,
) -> HashSet<String> {
    let mut sids = HashSet::new();
    sids.insert(user_sid.to_string());
    for old in sid_history {
        sids.insert(old.0.clone());
    }
    for gm in memberships {
        sids.insert(gm.group_sid.0.clone());
        // ADR 0059: the PAC also carries the historical SIDs of the token
        // groups — ACEs on a migrated group's old SID apply to members.
        for old in &gm.group_sid_history {
            sids.insert(old.0.clone());
        }
    }
    for local in local_group_sids {
        sids.insert(local.0.clone());
    }
    // Implicit well-known principals present in every Windows access token —
    // except for the Guest account and anonymous logons (ADR 0072, measured):
    // Authenticated Users is absent, Everyone is uncertain for anonymous.
    let uncertain_well_knowns = identity_uncertain_well_knowns(user_sid);
    let absent_well_knowns = identity_absent_well_knowns(user_sid);
    for well_known in [SID_EVERYONE, SID_AUTHENTICATED_USERS] {
        if !uncertain_well_knowns.contains(&well_known) && !absent_well_knowns.contains(&well_known)
        {
            sids.insert(well_known.to_string());
        }
    }

    // Context-specific well-knowns.
    match access_context {
        AccessContext::RemoteSmb => {
            sids.insert("S-1-5-2".to_string()); // NETWORK
        }
        AccessContext::LocalInteractive => {
            sids.insert("S-1-5-4".to_string()); // INTERACTIVE
        }
        AccessContext::Unspecified => {}
    }
    sids
}

/// Which local groups of a target server an account is in (ADR 0068) —
/// the way Windows builds a logon token: a local group is added when one of
/// its direct members is a SID already in the token (the account, its SID
/// history, its domain groups and their SID history, `Everyone`,
/// `Authenticated Users` and the well-knowns of the access context). Local
/// groups cannot contain local groups, so one level is exact.
///
/// Until ADR 0068 the local groups came from `NetUserGetLocalGroups`, which
/// in the lab missed groups entered through a nested domain group, a domain
/// local group, `Everyone` and `Authenticated Users` — rights were shown too
/// low, as a fact. A group reachable only through a logon-dependent SID
/// ([`is_logon_dependent_sid`]) is returned in `logon_dependent`, not as a
/// membership.
pub fn expand_local_groups(
    user_sid: &str,
    sid_history: &[Sid],
    memberships: &[GroupMembership],
    groups: &[LocalGroupDescriptor],
    access_context: AccessContext,
) -> LocalGroupExpansion {
    expand_local_groups_with(
        user_sid,
        sid_history,
        memberships,
        groups,
        access_context,
        None,
    )
}

/// [`expand_local_groups`] with `EveryoneIncludesAnonymous` as read from the
/// target (L17): a local group an anonymous logon reaches through Everyone is
/// then a membership (1) or none (0) instead of uncertain.
pub fn expand_local_groups_with(
    user_sid: &str,
    sid_history: &[Sid],
    memberships: &[GroupMembership],
    groups: &[LocalGroupDescriptor],
    access_context: AccessContext,
    anonymous_everyone: Option<bool>,
) -> LocalGroupExpansion {
    let mut token =
        build_token_sids_with_context(user_sid, sid_history, memberships, &[], access_context);
    if anonymous_gets_everyone(user_sid, anonymous_everyone) {
        token.insert(SID_EVERYONE.to_owned());
    }
    let mut out = LocalGroupExpansion::default();
    // Review CR-8: a local group reached only through a well-known a Guest /
    // anonymous token may lack is uncertain, not a membership.
    let uncertain_well_knowns = uncertain_well_knowns_with(user_sid, anonymous_everyone);
    for group in groups {
        let mut certain: Vec<Sid> = group
            .members
            .iter()
            .filter(|m| token.contains(&m.0))
            .cloned()
            .collect();
        let mut uncertain: Vec<Sid> = group
            .members
            .iter()
            .filter(|m| {
                !token.contains(&m.0)
                    && (is_logon_dependent_for(&m.0, access_context, &token)
                        || uncertain_well_knowns.contains(&m.0.as_str()))
            })
            .cloned()
            .collect();
        let sort_via = |via: &mut Vec<Sid>| {
            via.sort_by(|a, b| {
                (a.0 != user_sid)
                    .cmp(&(b.0 != user_sid))
                    .then_with(|| a.0.cmp(&b.0))
            });
            via.dedup();
        };
        if !certain.is_empty() {
            sort_via(&mut certain);
            out.certain.push(LocalGroupEntry {
                group: group.sid.clone(),
                name: group.name.clone(),
                via: certain,
            });
        } else if !uncertain.is_empty() {
            sort_via(&mut uncertain);
            out.logon_dependent.push(LocalGroupEntry {
                group: group.sid.clone(),
                name: group.name.clone(),
                via: uncertain,
            });
        }
    }
    // Deterministic output order regardless of the server's enumeration order.
    let by_name = |a: &LocalGroupEntry, b: &LocalGroupEntry| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then_with(|| a.group.0.cmp(&b.group.0))
    };
    out.certain.sort_by(by_name);
    out.logon_dependent.sort_by(by_name);
    out
}

/// `Everyone`.
pub const SID_EVERYONE: &str = "S-1-1-0";
/// `Authenticated Users`.
pub const SID_AUTHENTICATED_USERS: &str = "S-1-5-11";
/// `ANONYMOUS LOGON`.
pub const SID_ANONYMOUS_LOGON: &str = "S-1-5-7";

/// Whether `sid` is the built-in Guest account — RID 501 of a machine or
/// domain account domain (`S-1-5-21-a-b-c-501`).
pub fn is_guest_account(sid: &str) -> bool {
    sid.strip_prefix("S-1-5-21-")
        .and_then(|rest| rest.rsplit_once('-'))
        .is_some_and(|(domain, rid)| rid == "501" && domain.split('-').count() == 3)
}

/// The universal well-knowns **certainly absent** from this identity's token
/// (ADR 0072, lab-measured 2026-10-13 on Windows Server 2025): a real Guest
/// token (network and interactive logon) and the anonymous token carry no
/// `Authenticated Users`.
pub fn identity_absent_well_knowns(user_sid: &str) -> &'static [&'static str] {
    if user_sid == SID_ANONYMOUS_LOGON || is_guest_account(user_sid) {
        &[SID_AUTHENTICATED_USERS]
    } else {
        &[]
    }
}

/// The universal well-knowns whose presence in this identity's token is
/// **uncertain** (ADR 0072): `Everyone` is in the anonymous token only when
/// the target sets `EveryoneIncludesAnonymous` = 1 (measured: absent with the
/// default 0). Without that policy, ACEs for `Everyone` bound an anonymous
/// result; once it is read from the target (L17,
/// [`uncertain_well_knowns_with`]) Everyone is decided. A Guest token always
/// carries `Everyone` (measured).
pub fn identity_uncertain_well_knowns(user_sid: &str) -> &'static [&'static str] {
    if user_sid == SID_ANONYMOUS_LOGON {
        &[SID_EVERYONE]
    } else {
        &[]
    }
}

/// The uncertain well-knowns once the target's `EveryoneIncludesAnonymous`
/// is known (L17): with a value read, Everyone is decided for an anonymous
/// logon (measured on MS-01: 0 → absent, 1 → present) and no longer
/// uncertain.
pub fn uncertain_well_knowns_with(
    user_sid: &str,
    anonymous_everyone: Option<bool>,
) -> &'static [&'static str] {
    if user_sid == SID_ANONYMOUS_LOGON && anonymous_everyone.is_some() {
        &[]
    } else {
        identity_uncertain_well_knowns(user_sid)
    }
}

/// Whether an anonymous token certainly carries Everyone (L17).
pub fn anonymous_gets_everyone(user_sid: &str, anonymous_everyone: Option<bool>) -> bool {
    user_sid == SID_ANONYMOUS_LOGON && anonymous_everyone == Some(true)
}

/// `EveryoneIncludesAnonymous` as read from the target (L17): absent or 0 →
/// `Some(false)`, 1 → `Some(true)`; any other or unreadable value → `None`
/// (stays bounded, never guessed).
pub fn anonymous_everyone(value: &PolicyDword) -> Option<bool> {
    match value {
        PolicyDword::Absent | PolicyDword::Value(0) => Some(false),
        PolicyDword::Value(1) => Some(true),
        _ => None,
    }
}

/// `BUILTIN\Cryptographic Operators` — never a certain token group
/// (see [`DefaultPermissionEngine`], ADR 0071).
pub const SID_CRYPTOGRAPHIC_OPERATORS: &str = "S-1-5-32-569";

/// Builtin groups User Account Control turns deny-only in a filtered token,
/// lab-confirmed on Windows Server 2025 (ADR 0070/0071): Administrators,
/// Power Users, Account Operators, Server Operators, Print Operators, Backup
/// Operators, Pre-Windows 2000 Compatible Access, Network Configuration
/// Operators. (Cryptographic Operators is handled separately.)
pub const UAC_FILTERED_BUILTIN_GROUPS: [&str; 8] = [
    "S-1-5-32-544",
    "S-1-5-32-547",
    "S-1-5-32-548",
    "S-1-5-32-549",
    "S-1-5-32-550",
    "S-1-5-32-551",
    "S-1-5-32-554",
    "S-1-5-32-556",
];

/// RIDs of domain groups User Account Control turns deny-only: lab-confirmed
/// Domain Admins (512), Cert Publishers (517), Schema Admins (518),
/// Enterprise Admins (519), Group Policy Creator Owners (520). The domain
/// controller groups (498, 516, 521) are treated the same without a lab
/// test — for them a bound is the safe statement either way. Key Admins
/// (526/527) and DnsAdmins were lab-confirmed as **not** filtered.
pub const UAC_FILTERED_DOMAIN_RIDS: [u32; 8] = [498, 512, 516, 517, 518, 519, 520, 521];

/// `Local account and member of Administrators group` — in the token of a
/// local account in Administrators, deny-only when filtered.
pub const SID_LOCAL_ACCOUNT_AND_ADMIN: &str = "S-1-5-114";

/// Whether User Account Control may turn `sid` deny-only.
pub fn is_uac_filtered_group(sid: &str) -> bool {
    if UAC_FILTERED_BUILTIN_GROUPS.contains(&sid) {
        return true;
    }
    match sid
        .strip_prefix("S-1-5-21-")
        .and_then(|rest| rest.rsplit_once('-'))
    {
        Some((domain, rid)) => {
            domain.split('-').count() == 3
                && rid
                    .parse::<u32>()
                    .is_ok_and(|r| UAC_FILTERED_DOMAIN_RIDS.contains(&r))
        }
        None => false,
    }
}

/// The token groups User Account Control may filter (deny-only) for this
/// access (ADR 0070/0071), lab-confirmed:
///
/// - **over the network** only a **local account** is filtered (remote UAC);
///   a domain account keeps its groups;
/// - **in a local session** every account in such a group gets a filtered
///   token unless the session is elevated (the built-in Administrator is
///   exempt by default) — Stars cannot see elevation or the policies, so
///   the groups are deny-only with a bounded Allow side;
/// - an unspecified context may be either.
///
/// `token_groups` are all group SIDs of the token (domain, SID history,
/// local). `S-1-5-114` is added for a local account in Administrators.
pub fn uac_filtered_groups(
    token_groups: &[Sid],
    local_account: bool,
    context: AccessContext,
) -> Vec<Sid> {
    if context == AccessContext::RemoteSmb && !local_account {
        return Vec::new();
    }
    let mut filtered: Vec<Sid> = token_groups
        .iter()
        .filter(|s| is_uac_filtered_group(&s.0))
        .cloned()
        .collect();
    if local_account && filtered.iter().any(|s| s.0 == "S-1-5-32-544") {
        filtered.push(Sid(SID_LOCAL_ACCOUNT_AND_ADMIN.to_owned()));
    }
    filtered.sort_by(|a, b| a.0.cmp(&b.0));
    filtered.dedup();
    filtered
}

fn collect_user_sids(
    identity: &Identity,
    memberships: &[GroupMembership],
    local_group_sids: &[Sid],
    access_context: AccessContext,
) -> HashSet<String> {
    build_token_sids_with_context(
        &identity.sid.0,
        &identity.sid_history,
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
    /// Index-aligned with the input DACL: for each ACE, exactly the bits
    /// that ACE decided during the stored-order walk (granted bits for an
    /// Allow, denied bits for a Deny). `0` means the ACE either did not
    /// apply (inherit-only / not in the token) or matched but contributed
    /// nothing because all its bits had already been decided by an earlier
    /// ACE. The explanation path uses this to mark each ACE step as
    /// actually-contributing vs. matched-only (engine review 2026-06-12
    /// finding 1: traceability must be as exact as the calculation).
    decided_per_ace: Vec<u32>,
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
/// overlap). They are listed in the DACL order of each SID's first
/// contribution — the order in which `AccessCheck` reached them. Until
/// v1.9.0 they came out of a `HashMap` in a random order per process, so
/// two runs over the same DACL listed them differently (lab finding DET-2).
fn walk_dacl_stored_order(
    dacl: &[AceEntry],
    match_sids: &HashSet<String>,
    deny_only_sids: &HashSet<String>,
) -> DaclWalkOutcome {
    let mut granted: u32 = 0;
    let mut denied: u32 = 0;
    let mut contributions: Vec<ContributingAce> = Vec::new();
    let mut decided_per_ace = vec![0u32; dacl.len()];
    for (idx, ace) in dacl.iter().enumerate() {
        if !ace_applies_to_current_object(ace) {
            continue;
        }
        if !ace_matches(ace, match_sids, deny_only_sids) {
            continue;
        }
        let mask = expand_generic_rights(ace.mask.0);
        // First decision per bit wins — bits already decided cannot flip.
        let undecided = !(granted | denied);
        let bits = mask & undecided;
        if bits == 0 {
            continue;
        }
        decided_per_ace[idx] = bits;
        match ace.kind {
            AceKind::Allow => {
                granted |= bits;
                // DACLs are short; a linear lookup keeps the first-seen
                // order without a second index structure.
                match contributions.iter_mut().find(|c| c.sid.0 == ace.sid.0) {
                    Some(existing) => existing.mask.0 |= bits,
                    None => contributions.push(ContributingAce {
                        sid: Sid(ace.sid.0.clone()),
                        mask: AccessMask(bits),
                    }),
                }
            }
            AceKind::Deny => denied |= bits,
        }
    }
    DaclWalkOutcome {
        granted,
        denied,
        contributions,
        decided_per_ace,
    }
}

/// Whether `ace` applies to the token: its trustee is in the token, or it is
/// a Deny ACE for a deny-only (UAC-filtered) group (ADR 0070).
fn ace_matches(
    ace: &AceEntry,
    match_sids: &HashSet<String>,
    deny_only_sids: &HashSet<String>,
) -> bool {
    match_sids.contains(&ace.sid.0)
        || (ace.kind == AceKind::Deny && deny_only_sids.contains(&ace.sid.0))
}

/// `This Organization` (S-1-5-15).
pub const SID_THIS_ORGANIZATION: &str = "S-1-5-15";
/// `Other Organization` (S-1-5-1000).
pub const SID_OTHER_ORGANIZATION: &str = "S-1-5-1000";

/// [`is_logon_dependent_sid`] for a known token (ADR 0079): `This
/// Organization` and `Other Organization` exclude each other — a token holds
/// exactly one of them. When one is certainly in `token` (an account of a
/// trusted domain, decided from the trust's Selective Authentication; lab
/// 2026-10-17), the other is certainly absent rather than logon-dependent.
/// For any other token neither is in it, and the answer equals
/// [`is_logon_dependent_sid`].
pub fn is_logon_dependent_for(sid: &str, context: AccessContext, token: &HashSet<String>) -> bool {
    let decided_absent = match sid {
        SID_THIS_ORGANIZATION => token.contains(SID_OTHER_ORGANIZATION),
        SID_OTHER_ORGANIZATION => token.contains(SID_THIS_ORGANIZATION),
        _ => false,
    };
    !decided_absent && is_logon_dependent_sid(sid, context)
}

/// Well-known SIDs whose presence in a real access token depends on **how**
/// the user logs on — authentication package, organization of the
/// authenticating domain, logon type — which Stars does not model
/// (ADR 0065). An applicable ACE for one of them may or may not apply:
///
/// - always: `This Organization` (S-1-5-15), `Other Organization`
///   (S-1-5-1000), `This Organization Certificate` (S-1-5-65-1), the
///   authentication-assertion SIDs (S-1-18-*), the authentication-package
///   SIDs (`NTLM`/`SChannel`/`Digest Authentication`, S-1-5-64-*), `Local
///   account` (S-1-5-113) and `Local account and member of Administrators`
///   (S-1-5-114);
/// - for a local logon (and an unspecified context): `Remote Interactive
///   Logon` (S-1-5-14), `Console Logon` (S-1-2-1), `Terminal Server User`
///   (S-1-5-13) and `LOCAL` (S-1-2-0) — over SMB the logon is a network
///   logon, which never carries them. `LOCAL` is in a console session's
///   token but not in that of an interactive `LogonUser` (lab, ADR 0069);
/// - for an unspecified context additionally `NETWORK`, `INTERACTIVE` and
///   `LOCAL`, which the modelled contexts decide.
pub fn is_logon_dependent_sid(sid: &str, context: AccessContext) -> bool {
    const ALWAYS: [&str; 5] = [
        "S-1-5-15",
        "S-1-5-1000",
        "S-1-5-65-1",
        "S-1-5-113",
        "S-1-5-114",
    ];
    const LOCAL_LOGON: [&str; 4] = ["S-1-5-14", "S-1-2-1", "S-1-5-13", "S-1-2-0"];
    const CONTEXT: [&str; 3] = ["S-1-5-2", "S-1-5-4", "S-1-2-0"];
    if ALWAYS.contains(&sid) || sid.starts_with("S-1-18-") || sid.starts_with("S-1-5-64-") {
        return true;
    }
    match context {
        AccessContext::RemoteSmb => false,
        AccessContext::LocalInteractive => LOCAL_LOGON.contains(&sid),
        AccessContext::Unspecified => LOCAL_LOGON.contains(&sid) || CONTEXT.contains(&sid),
    }
}

/// Lower and upper bound of a result that depends on logon-dependent
/// trustees, with those trustees — see [`logon_dependent_bounds`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogonDependentBounds {
    /// The logon-dependent trustee SIDs of applicable ACEs, sorted.
    pub sids: Vec<String>,
    pub min: u32,
    pub max: u32,
}

/// Bounds the stored-order result over the logon-dependent trustees of
/// `dacl` (ADR 0065). `None` when there are none, or when they cannot
/// change this result (equal bounds — the result is then exact).
///
/// For each bit, the first applicable ACE containing it decides. Counting
/// every uncertain Allow as matching and no uncertain Deny gives the highest
/// possible outcome per bit; the opposite gives the lowest. The real token
/// lies somewhere in between, so the real result is within the bounds. The
/// owner bits are applied to both, as in the main evaluation.
///
/// `logon_dependent_groups` are local groups the account is in only through
/// a logon-dependent SID (ADR 0068); their ACEs are uncertain the same way.
/// `deny_only_groups` may be filtered out of the token by User Account
/// Control (ADR 0070): their Deny ACEs apply in both bounds, their Allow
/// ACEs only in the upper one. `uncertain_owner` — the object's owner when
/// it is such a group — makes `OWNER RIGHTS` ACEs uncertain and adds the
/// implicit owner grant to the upper bound.
#[allow(clippy::too_many_arguments)]
pub fn logon_dependent_bounds(
    dacl: &[AceEntry],
    match_sids: &HashSet<String>,
    context: AccessContext,
    logon_dependent_groups: &HashSet<String>,
    deny_only_groups: &HashSet<String>,
    owner_implicit_bits: u32,
    uncertain_owner: Option<&str>,
    // ADR 0076: the deny-only groups are certainly filtered — their Allow
    // ACEs do not apply instead of bounding the result.
    uac_filter_certain: bool,
) -> Option<LogonDependentBounds> {
    let mut uncertain: Vec<String> = dacl
        .iter()
        .filter(|ace| ace_applies_to_current_object(ace))
        .filter(|ace| !match_sids.contains(&ace.sid.0))
        .filter(|ace| {
            is_logon_dependent_for(&ace.sid.0, context, match_sids)
                || logon_dependent_groups.contains(&ace.sid.0)
                || (ace.kind == AceKind::Allow
                    && deny_only_groups.contains(&ace.sid.0)
                    && !uac_filter_certain)
                || (uncertain_owner.is_some() && ace.sid.0 == SID_OWNER_RIGHTS)
        })
        .map(|ace| ace.sid.0.clone())
        .collect();
    let owner_rights_ace = dacl
        .iter()
        .any(|ace| ace.sid.0 == SID_OWNER_RIGHTS && ace_applies_to_current_object(ace));
    let upper_owner_bits = if uncertain_owner.is_some() && !owner_rights_ace {
        owner_implicit_bits | FILE_READ_CONTROL | FILE_WRITE_DAC
    } else {
        owner_implicit_bits
    };
    if uncertain.is_empty() && upper_owner_bits == owner_implicit_bits {
        return None;
    }
    uncertain.sort();
    uncertain.dedup();
    let certain_allow = |sid: &str| match_sids.contains(sid);
    let certain_deny = |sid: &str| match_sids.contains(sid) || deny_only_groups.contains(sid);
    let maybe_allow = |sid: &str| certain_allow(sid) || uncertain.iter().any(|u| u == sid);
    let maybe_deny = |sid: &str| certain_deny(sid) || uncertain.iter().any(|u| u == sid);
    let max = walk_granted_with(dacl, &maybe_allow, &certain_deny) | upper_owner_bits;
    let min = walk_granted_with(dacl, &certain_allow, &maybe_deny) | owner_implicit_bits;
    if min == max {
        return None;
    }
    if uncertain.is_empty() {
        // Only the implicit owner grant is uncertain — name the owner group.
        if let Some(owner) = uncertain_owner {
            uncertain.push(owner.to_owned());
        }
    }
    Some(LogonDependentBounds {
        sids: uncertain,
        min,
        max,
    })
}

/// Granted bits of a stored-order walk in which Allow ACEs and Deny ACEs
/// match through different predicates — the building block of the bounds
/// above. Same per-bit "first decision wins" rule as
/// [`walk_dacl_stored_order`].
fn walk_granted_with(
    dacl: &[AceEntry],
    allow_matches: &dyn Fn(&str) -> bool,
    deny_matches: &dyn Fn(&str) -> bool,
) -> u32 {
    let mut granted: u32 = 0;
    let mut denied: u32 = 0;
    for ace in dacl {
        if !ace_applies_to_current_object(ace) {
            continue;
        }
        let applies = match ace.kind {
            AceKind::Allow => allow_matches(&ace.sid.0),
            AceKind::Deny => deny_matches(&ace.sid.0),
        };
        if !applies {
            continue;
        }
        let bits = expand_generic_rights(ace.mask.0) & !(granted | denied);
        match ace.kind {
            AceKind::Allow => granted |= bits,
            AceKind::Deny => denied |= bits,
        }
    }
    granted
}

/// Collects DACL entries that actually apply to the current object and whose
/// trustee SID belongs to the match SID set (token plus `S-1-3-4` when the
/// user is the owner).
///
/// **Important:** ACEs flagged `INHERIT_ONLY_ACE` are filtered out. They
/// apply only to children; a risk rule like `DirectUserAceRule` would
/// otherwise fire on an explicit user ACE that does not affect the current
/// object at all (follow-up finding 2).
fn collect_matched_aces(
    dacl: &[AceEntry],
    user_sids: &HashSet<String>,
    deny_only_sids: &HashSet<String>,
) -> Vec<AceEntry> {
    dacl.iter()
        .filter(|ace| {
            ace_applies_to_current_object(ace) && ace_matches(ace, user_sids, deny_only_sids)
        })
        .cloned()
        .collect()
}

/// Collects structured diagnostic markers for the DACL itself; also emits
/// a `warn!` per finding. The structured list flows into
/// `EffectivePermission.diagnostics` and from there into the DB history
/// and exports.
fn collect_diagnostics(dacl: &[AceEntry], path: &str) -> Vec<PermissionDiagnostic> {
    let mut out = Vec::new();
    match dacl_order_finding(dacl) {
        Some(DaclOrderFinding::NonCanonical(at)) => {
            warn!(
                path,
                at,
                "DACL is not in canonical order — evaluation follows stored ACE order \
                 (matches Windows AccessCheck)"
            );
            out.push(PermissionDiagnostic::NonCanonicalDaclOrder { at_index: at });
        }
        Some(DaclOrderFinding::InheritedLevelsUnknown(at)) => {
            debug!(
                path,
                at,
                "inherited Deny after inherited Allow — canonical across ancestor levels, \
                 not decidable from this DACL (known limitation L9)"
            );
            out.push(PermissionDiagnostic::InheritedDenyAfterInheritedAllow { at_index: at });
        }
        None => {}
    }
    out
}

/// What the order of a DACL says about canonical form (known limitation L9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaclOrderFinding {
    /// Never canonical: an explicit ACE after an inherited one, or an
    /// explicit Allow before an explicit Deny. Index of the first such ACE.
    NonCanonical(usize),
    /// Only an inherited Deny after an inherited Allow: canonical when they
    /// come from different ancestor levels, which the DACL does not record.
    /// Index of the first such Deny.
    InheritedLevelsUnknown(usize),
}

fn dacl_order_finding(dacl: &[AceEntry]) -> Option<DaclOrderFinding> {
    let mut seen_inherited = false;
    let mut seen_explicit_allow = false;
    let mut seen_inherited_allow = false;
    let mut ambiguous = None;
    for (i, ace) in dacl.iter().enumerate() {
        match (ace.inherited, &ace.kind) {
            (false, AceKind::Deny) if seen_inherited || seen_explicit_allow => {
                return Some(DaclOrderFinding::NonCanonical(i))
            }
            (false, AceKind::Allow) if seen_inherited => {
                return Some(DaclOrderFinding::NonCanonical(i))
            }
            (false, AceKind::Deny) => {}
            (false, AceKind::Allow) => seen_explicit_allow = true,
            (true, AceKind::Deny) => {
                seen_inherited = true;
                if seen_inherited_allow && ambiguous.is_none() {
                    ambiguous = Some(i);
                }
            }
            (true, AceKind::Allow) => {
                seen_inherited = true;
                seen_inherited_allow = true;
            }
        }
    }
    ambiguous.map(DaclOrderFinding::InheritedLevelsUnknown)
}

/// Human-readable label for the source kind shown in the explanation.
fn source_label(source: &MembershipPathSource) -> &'static str {
    match source {
        MembershipPathSource::PrimaryGroup => "PrimaryGroup",
        MembershipPathSource::DomainGroup => "DomainGroup",
        MembershipPathSource::LocalGroup => "LocalGroup",
        MembershipPathSource::LdapMatchingRule => "LdapMatchingRule",
        MembershipPathSource::AccountType => "AccountType",
        MembershipPathSource::TrustedDomainLogon => "TrustedDomainLogon",
    }
}

// Author / AGPL attribution marker, embedded openly in the compiled binary.
// `#[used]` keeps the linker from stripping it, so the author and license
// travel with the shipped artifact — not only with the source (source
// comments are dropped at compile time; this is not). This is intentional
// and documented in the README: Stars is AGPL-3.0 and derivative works must
// preserve attribution. It is data only and never read by engine logic.
#[used]
static ENGINE_ATTRIBUTION: &str = "Stars AD Permission Analyzer - permission engine - engineer: Birger Labinsch - (c) Birger Labinsch, AGPL-3.0; derivative works must preserve this author attribution.";

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
    let mut step = format_membership_step_base(gm, sid_names);
    // ADR 0063: the chain above is one shortest route. When the identity
    // also enters the group through other groups, say so — otherwise the
    // step reads as if removing the shown route removed the membership.
    if let Some(path) = gm.path.as_ref() {
        if !path.also_via.is_empty() {
            let hops: Vec<MembershipHop> = path
                .also_via
                .iter()
                .map(|h| MembershipHop {
                    sid: h.sid.clone(),
                    name: h
                        .name
                        .clone()
                        .filter(|n| !n.is_empty())
                        .or_else(|| sid_names.get(&h.sid.0).cloned()),
                })
                .collect();
            if let Some(list) = format_also_via(&hops) {
                step.push_str(&format!(
                    " [also a member through {list} — the shown chain is not the only route]"
                ));
            }
        }
    }
    // ADR 0059: when the group itself carries evaluated historical SIDs,
    // say so on the membership line — an ACE further down that matches
    // the group's old SID is then explainable from the step list alone.
    if !gm.group_sid_history.is_empty() {
        let sids: Vec<&str> = gm.group_sid_history.iter().map(|s| s.0.as_str()).collect();
        step.push_str(&format!(
            " [carries historical SID(s) (sIDHistory) in the evaluated token: {}]",
            sids.join(", ")
        ));
    }
    step
}

fn format_membership_step_base(
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
        // Membership confirmed, exact route not reconstructable — flag
        // explicitly so audits can tell it apart from a fully reconstructed
        // chain. Deliberately no "direct"/"transitive" claim: when the
        // route is unknown (unreadable local-group members, a truncated
        // memberOf), whether the membership is direct is unknown too.
        return format!(
            "Member of {target_display} [membership confirmed, exact chain unknown — source: {source}; the route could not be reconstructed (e.g. truncated memberOf, unreadable or nested local group)]"
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

/// What User Account Control does to a filtered group, for the context
/// (review CR-3, ADR 0070/0071).
fn uac_filter_reason(context: AccessContext) -> &'static str {
    match context {
        AccessContext::RemoteSmb => {
            "User Account Control makes this group deny-only in the remote token of a local \
             account (unless the server sets LocalAccountTokenFilterPolicy) — its Allow ACEs \
             count only without that filtering"
        }
        _ => {
            "User Account Control makes this group deny-only until the session is elevated — \
             its Allow ACEs count only in an elevated session"
        }
    }
}

/// Why a well-known SID is present only for certain logons (review CR-3).
fn logon_dependent_reason(sid: &str) -> &'static str {
    match sid {
        "S-1-2-0" => "LOCAL is present only for some local logons (ADR 0069)",
        "S-1-5-113" | "S-1-5-114" => {
            "present only in the token of a local account of the target computer"
        }
        "S-1-5-15" | "S-1-5-1000" | "S-1-5-65-1" => {
            "depends on the account's organisation relative to the target (trusts, selective \
             authentication)"
        }
        "S-1-5-14" | "S-1-2-1" | "S-1-5-13" => {
            "present only for a specific logon type (remote interactive, console, terminal \
             server)"
        }
        "S-1-5-2" | "S-1-5-4" => {
            "present only for a network or an interactive logon — the logon type is not \
             specified"
        }
        s if s.starts_with("S-1-5-64-") => {
            "present only for a specific authentication package (NTLM, SChannel, Digest)"
        }
        s if s.starts_with("S-1-18-") => "depends on how the logon was authenticated",
        _ => "present only for certain logons",
    }
}

/// Why an applicable ACE neither certainly applies nor certainly does not
/// (review CR-3) — `None` otherwise. The same predicate as
/// [`logon_dependent_bounds`], so every ACE that moves a bound is named.
fn uncertain_ace_reason(
    ace: &AceEntry,
    match_sids: &HashSet<String>,
    deny_only_sids: &HashSet<String>,
    uncertain_sids: &HashSet<String>,
    uncertain_owner: Option<&str>,
    context: AccessContext,
    user_sid: &str,
) -> Option<String> {
    let sid = ace.sid.0.as_str();
    if !ace_applies_to_current_object(ace) || match_sids.contains(sid) {
        return None;
    }
    if ace.kind == AceKind::Allow && deny_only_sids.contains(sid) {
        return Some(uac_filter_reason(context).to_owned());
    }
    if sid == SID_CRYPTOGRAPHIC_OPERATORS && uncertain_sids.contains(sid) {
        return Some(
            "Windows may leave Cryptographic Operators out of the token or make it deny-only \
             — not modelled"
                .to_owned(),
        );
    }
    if identity_uncertain_well_knowns(user_sid).contains(&sid) && uncertain_sids.contains(sid) {
        return Some(
            "Everyone is in an anonymous token only if the target sets \
             EveryoneIncludesAnonymous = 1 — Stars could not read that policy on the target \
             (ADR 0072)"
                .to_owned(),
        );
    }
    if uncertain_sids.contains(sid) {
        return Some(
            "a local group reached only through a SID that is present only for certain logons"
                .to_owned(),
        );
    }
    if is_logon_dependent_for(sid, context, match_sids) {
        return Some(logon_dependent_reason(sid).to_owned());
    }
    if uncertain_owner.is_some() && sid == SID_OWNER_RIGHTS {
        return Some(
            "OWNER RIGHTS applies only if the owner group is enabled in the token (User Account \
             Control)"
                .to_owned(),
        );
    }
    None
}

/// Inserts the share ACE steps (review CR-7; built by
/// `share_scanner::share_decision_steps` from the same DACL read as the
/// share mask) right before the "Share permission:" step, so the share side
/// is explained like the NTFS side. Without an applied share there is no
/// such step and nothing is inserted.
pub fn attach_share_provenance(path: &mut PermissionPath, share_steps: Vec<String>) {
    if let Some(at) = path
        .steps
        .iter()
        .position(|s| s.starts_with("Share permission: "))
    {
        path.steps.splice(at..at, share_steps);
    }
}

/// Remote UAC for a local account's network logon, decided from the
/// target's policies (ADR 0076). Lab matrix (MS-01, Windows Server 2025,
/// real SMB access, all four combinations): a local account other than the
/// built-in Administrator is filtered exactly when
/// `LocalAccountTokenFilterPolicy` = 0; the built-in Administrator (RID 500)
/// exactly when `FilterAdministratorToken` = 1 and
/// `LocalAccountTokenFilterPolicy` = 0. An absent value is the Windows
/// default 0 (`EnableLUA`: 1). `EnableLUA` = 0, a value other than 0 / 1 or
/// an unreadable value leave it `Unknown` — never guessed.
pub fn remote_uac_filtering(
    builtin_administrator: bool,
    enable_lua: &PolicyDword,
    local_account_token_filter_policy: &PolicyDword,
    filter_administrator_token: &PolicyDword,
) -> RemoteUacFiltering {
    fn flag(v: &PolicyDword, default: bool) -> Option<bool> {
        match v {
            PolicyDword::Value(0) => Some(false),
            PolicyDword::Value(1) => Some(true),
            PolicyDword::Absent => Some(default),
            PolicyDword::Value(_) | PolicyDword::Unreadable(_) => None,
        }
    }
    fn shown(v: &PolicyDword) -> String {
        match v {
            PolicyDword::Value(n) => n.to_string(),
            PolicyDword::Absent => "0 (not set, default)".to_owned(),
            PolicyDword::Unreadable(e) => format!("unreadable ({e})"),
        }
    }
    let (Some(lua), Some(latfp), Some(fat)) = (
        flag(enable_lua, true),
        flag(local_account_token_filter_policy, false),
        flag(filter_administrator_token, false),
    ) else {
        return RemoteUacFiltering::Unknown;
    };
    if !lua {
        // UAC disabled entirely — not measured in the lab, so not decided.
        return RemoteUacFiltering::Unknown;
    }
    let values = format!(
        "read from the target: LocalAccountTokenFilterPolicy = {}, FilterAdministratorToken = {}",
        shown(local_account_token_filter_policy),
        shown(filter_administrator_token)
    );
    if latfp {
        RemoteUacFiltering::NotFiltered {
            reason: format!(
                "{values} — remote User Account Control does not filter local accounts"
            ),
        }
    } else if builtin_administrator && !fat {
        RemoteUacFiltering::NotFiltered {
            reason: format!("{values} — the built-in Administrator keeps its full network token"),
        }
    } else {
        RemoteUacFiltering::Filtered {
            reason: format!(
                "{values} — remote User Account Control filters this local account's network token"
            ),
        }
    }
}

/// User Account Control for the **interactive** token on the target itself
/// (ADR 0076, lab-measured 2026-10-13 on MS-01 with real `LogonUser`
/// tokens): the built-in Administrator (RID 500) gets an unsplit, full token
/// when `FilterAdministratorToken` = 0 (the default); with 1 — and every
/// other account always — the token is limited, and whether the session is
/// elevated is a property of the logon Stars cannot see, so that stays
/// `Unknown` (bounded).
pub fn local_uac_filtering(
    builtin_administrator: bool,
    enable_lua: &PolicyDword,
    filter_administrator_token: &PolicyDword,
) -> RemoteUacFiltering {
    if !builtin_administrator {
        return RemoteUacFiltering::Unknown;
    }
    let lua = match enable_lua {
        PolicyDword::Absent | PolicyDword::Value(1) => true,
        _ => return RemoteUacFiltering::Unknown,
    };
    let fat = match filter_administrator_token {
        PolicyDword::Absent | PolicyDword::Value(0) => false,
        _ => return RemoteUacFiltering::Unknown,
    };
    if lua && !fat {
        RemoteUacFiltering::NotFiltered {
            reason: "read from the target: FilterAdministratorToken = 0 — the built-in \
                     Administrator's interactive token is not split (full token, measured)"
                .to_owned(),
        }
    } else {
        RemoteUacFiltering::Unknown
    }
}

/// Review CR-12 (frontends): above this many membership steps a frontend
/// may collapse the memberships that did not matter for the result.
pub const MEMBERSHIP_COLLAPSE_THRESHOLD: usize = 10;

/// A membership step a frontend may collapse: neither decisive for the
/// result nor carrying a reason to look at it (deny-only, uncertain, an
/// unknown chain). Every other step always stays visible.
pub fn is_collapsible_membership_step(step: &str) -> bool {
    step.starts_with("Member of ")
        && !["[decisive", "[deny-only", "[uncertain", "chain unknown"]
            .iter()
            .any(|marker| step.contains(marker))
}

/// Per step of a path: may it be collapsed? All `false` while the path has
/// at most [`MEMBERSHIP_COLLAPSE_THRESHOLD`] membership steps — a short list
/// is shown in full. The single rule for the GUI and the HTML report.
pub fn collapsible_steps(steps: &[String]) -> Vec<bool> {
    let memberships = steps.iter().filter(|s| s.starts_with("Member of ")).count();
    if memberships <= MEMBERSHIP_COLLAPSE_THRESHOLD {
        return vec![false; steps.len()];
    }
    steps
        .iter()
        .map(|s| is_collapsible_membership_step(s))
        .collect()
}

/// Short name of the evaluated logon (review CR-6) — for report headers.
pub fn access_context_summary(context: AccessContext) -> &'static str {
    match context {
        AccessContext::RemoteSmb => "network logon over SMB",
        AccessContext::LocalInteractive => {
            "interactive logon at the target computer, session not elevated"
        }
        AccessContext::Unspecified => "no specific logon type",
    }
}

/// The explanation step stating how the access is evaluated and which
/// implicit SIDs the token receives (review CR-6). Derived from the same
/// rules as `build_token_sids_with_context`, `identity_uncertain_well_knowns`
/// and `uac_filtered_groups`, so the text and the computation agree.
pub fn access_context_step(context: AccessContext, user_sid: &str) -> String {
    access_context_step_with(context, user_sid, None)
}

/// [`access_context_step`] with `EveryoneIncludesAnonymous` as read from the
/// target (L17).
pub fn access_context_step_with(
    context: AccessContext,
    user_sid: &str,
    anonymous_everyone: Option<bool>,
) -> String {
    let uncertain = uncertain_well_knowns_with(user_sid, anonymous_everyone);
    let absent = identity_absent_well_knowns(user_sid);
    let universal = match (
        uncertain.contains(&SID_EVERYONE),
        absent.contains(&SID_AUTHENTICATED_USERS),
    ) {
        (false, true) if user_sid == SID_ANONYMOUS_LOGON => {
            if anonymous_gets_everyone(user_sid, anonymous_everyone) {
                "Everyone (S-1-1-0) — the target sets EveryoneIncludesAnonymous = 1; no \
                 Authenticated Users (anonymous logon)"
                    .to_owned()
            } else {
                "no Everyone and no Authenticated Users — the target leaves \
                 EveryoneIncludesAnonymous at 0 (anonymous logon)"
                    .to_owned()
            }
        }
        (false, false) => "Everyone (S-1-1-0), Authenticated Users (S-1-5-11)".to_owned(),
        (false, true) => {
            "Everyone (S-1-1-0); no Authenticated Users (a Guest token never has it)".to_owned()
        }
        (true, _) => "no Authenticated Users (anonymous logon); Everyone only if the target \
                      sets EveryoneIncludesAnonymous = 1 — not read, so bounded"
            .to_owned(),
    };
    let summary = access_context_summary(context);
    match context {
        AccessContext::RemoteSmb => format!(
            "Evaluated as: {summary} — the token receives NETWORK (S-1-5-2), {universal}. \
             User Account Control filters the groups of local accounts only. Logon rights \
             (\"Access this computer from the network\") are not checked"
        ),
        AccessContext::LocalInteractive => format!(
            "Evaluated as: {summary} — the token receives INTERACTIVE (S-1-5-4), {universal}; \
             LOCAL (S-1-2-0) and the groups User Account Control filters are bounded (an \
             elevated session may have more). Logon rights (\"Allow log on locally\") are not \
             checked"
        ),
        AccessContext::Unspecified => format!(
            "Evaluated as: {summary} — the token receives {universal}; logon-type SIDs \
             (NETWORK, INTERACTIVE) are not assumed, the groups User Account Control filters \
             are bounded"
        ),
    }
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
    /// UAC-filtered groups — match Deny ACEs only (ADR 0070).
    deny_only_sids: &'a HashSet<String>,
    /// Index-aligned with `dacl`: the exact bits each ACE decided during
    /// the stored-order walk (engine review 2026-06-12 finding 1). `0`
    /// means the ACE matched the token but contributed no effective bits.
    decided_per_ace: &'a [u32],
    /// Number of NTFS ACEs the parser could not interpret. When >0 the
    /// explanation adds an explicit lower-confidence warning so a reader
    /// does not take the NTFS-effective mask as final (finding 3).
    unsupported_ntfs_count: usize,
    ntfs_raw: u32,
    denied_raw: u32,
    /// Bits added by the implicit owner rule (`0` when the rule did not
    /// fire or was suppressed by an OWNER RIGHTS ACE).
    owner_implicit_bits: u32,
    /// True when an `S-1-3-4` ACE governed the owner's rights.
    owner_rights_ace_present: bool,
    owner_sid: Option<&'a Sid>,
    share_mask: Option<AccessMask>,
    /// The resolved share-side status. Drives an explicit share-step so
    /// the audit text spells out *why* the effective mask equals NTFS in
    /// the unrestricted / read-failed / no-SMB cases instead of silently
    /// omitting the share line (engine review 2026-06-12 finding 5).
    share_status: &'a ShareEvalStatus,
    effective_raw: u32,
    sid_names: &'a std::collections::BTreeMap<String, String>,
    /// Bounds over logon-dependent trustees that decide bits of the NTFS
    /// result (ADR 0065); `None` when there are none.
    logon_dependent: Option<&'a LogonDependentBounds>,
    /// How the access is evaluated (review CR-6): stated as a step.
    access_context: AccessContext,
    /// The object has no DACL at all (review CR-10): stated as a step.
    null_dacl: bool,
    /// A file (not a folder) gets the parent-folder deletion note (CR-14).
    is_directory: bool,
    /// SIDs whose presence in the token is uncertain — logon-dependent
    /// local groups, Cryptographic Operators, Guest / anonymous well-knowns
    /// (review CR-3): their ACEs are listed with the reason.
    uncertain_sids: &'a HashSet<String>,
    /// The owner when it is a UAC-filtered group (implicit grant uncertain).
    uncertain_owner: Option<&'a str>,
    /// ADR 0076: remote UAC certainly filters the deny-only groups — why.
    uac_certain_reason: Option<&'a str>,
    /// L17: EveryoneIncludesAnonymous as read from the target.
    anonymous_everyone: Option<bool>,
    /// ADR 0077: the share ACE outcomes, appended to the trace.
    share_trace: &'a [AceOutcome],
    /// Determinability of the three values, from the finished result
    /// (`EffectivePermission::ntfs_determinable` etc., review CR-5).
    ntfs_determinable: bool,
    share_determinable: bool,
    effective_determinable: bool,
    /// Every reason a value is not determinable (`uncertainty()`).
    uncertainty: &'a [Uncertainty],
}

/// Creates an explainable permission path.
fn build_explanation(input: ExplanationInput<'_>) -> (PermissionPath, PermissionTrace) {
    let ExplanationInput {
        identity,
        memberships,
        dacl,
        match_sids,
        deny_only_sids,
        decided_per_ace,
        unsupported_ntfs_count,
        ntfs_raw,
        denied_raw,
        owner_implicit_bits,
        owner_rights_ace_present,
        owner_sid,
        share_mask,
        share_status,
        effective_raw,
        sid_names,
        logon_dependent,
        access_context,
        null_dacl,
        is_directory,
        uncertain_sids,
        uncertain_owner,
        uac_certain_reason,
        anonymous_everyone,
        share_trace,
        ntfs_determinable,
        share_determinable,
        effective_determinable,
        uncertainty,
    } = input;
    let mut steps: Vec<String> = Vec::new();

    let display_name = identity.name.as_deref().unwrap_or(identity.sid.0.as_str());
    steps.push(format!("User: {} ({})", display_name, identity.sid.0));

    // 1b. Historical SIDs (ADR 0056): each parsed sIDHistory value is part
    // of the evaluated token, so name it here — an ACE further down that
    // matches an old SID is then explainable straight from the step list.
    for old in &identity.sid_history {
        steps.push(format!(
            "Historical SID (sIDHistory): {} — included in the evaluated token \
             (migrated account; Windows includes it in the logon token within \
             the forest)",
            old.0
        ));
    }

    // 1c. Review CR-6: how the access is evaluated and which SIDs that adds
    // to the token — memberships "via … → INTERACTIVE → …" are explained by
    // this step, and so are the bounds of LOCAL and UAC-filtered groups.
    steps.push(access_context_step_with(
        access_context,
        &identity.sid.0,
        anonymous_everyone,
    ));

    // 2. Group memberships.
    //
    // De-duplicate identical edges: the same (target, via-chain, source) can
    // be reached through more than one resolution path — e.g. a local group
    // entered via two different domain groups, or the SAM/LSA fallback adding
    // the same local-group membership once per containing group. That would
    // otherwise print the exact same "Member of …" line twice and read like
    // two distinct memberships (lab hard-test finding F2). Collapsing steps
    // that render identically loses no information; the effective mask is
    // unaffected (token building already uses a set).
    //
    // Lab finding CLI3-1: on a domain controller a domain-local or builtin
    // group arrives twice — from LDAP and from the local-group lookup — with
    // different sources, so the lines differed and both were printed. One
    // step per group SID now; the routes the second source knew are merged
    // into the kept step's "also a member through" list (ADR 0063), so no
    // route is lost.
    let merged = adpa_core::model::merged_memberships_per_group(memberships);
    // Review CR-12: the groups whose ACEs decided bits of this result — in
    // a list of dozens (or thousands) of memberships, these are the ones
    // that matter.
    let decisive: HashSet<&str> = dacl
        .iter()
        .enumerate()
        .filter(|(idx, ace)| {
            ace_applies_to_current_object(ace)
                && ace_matches(ace, match_sids, deny_only_sids)
                && decided_per_ace.get(*idx).copied().unwrap_or(0) != 0
        })
        .map(|(_, ace)| ace.sid.0.as_str())
        .collect();
    let mut seen_membership_steps: HashSet<String> = HashSet::new();
    for gm in &merged {
        let mut step = format_membership_step(gm, sid_names);
        if decisive.contains(gm.group_sid.0.as_str()) {
            step.push_str(" [decisive — an ACE for this group decides bits of this result]");
        }
        // Review CR-3: a membership whose group is filtered or uncertain says
        // so where the administrator reads it.
        let group = gm.group_sid.0.as_str();
        if deny_only_sids.contains(group) {
            match uac_certain_reason {
                Some(reason) => step.push_str(&format!(
                    " [deny-only in this token — {reason}; its Allow ACEs do not apply]"
                )),
                None => step.push_str(&format!(
                    " [deny-only in a filtered token: {}]",
                    uac_filter_reason(access_context)
                )),
            }
        } else if uncertain_sids.contains(group) {
            step.push_str(" [uncertain — present in the token only for certain logons]");
        }
        if seen_membership_steps.insert(step.clone()) {
            steps.push(step);
        }
    }

    // 2b. Review CR-5: why the token above may lack SIDs. A token gap makes
    // every value below not determinable, so the reason is stated where the
    // token is described — not only in a separate report section.
    for u in uncertainty
        .iter()
        .filter(|u| u.layer == UncertainLayer::Token)
    {
        steps.push(format!(
            "{NOT_DETERMINABLE} — the token above may be incomplete: {}",
            u.reason
        ));
    }
    // 2c. ADR 0085: another DFS target may answer differently — every value
    // below is that of one target.
    for u in uncertainty
        .iter()
        .filter(|u| u.layer == UncertainLayer::Target)
    {
        steps.push(format!("{NOT_DETERMINABLE} — {}", u.reason));
    }

    // 3. Matching ACEs.
    //
    // Each ACE step is annotated with what it *actually contributed* to
    // the result, not just that its trustee was in the token (engine
    // review 2026-06-12 finding 1). `decided_per_ace[i]` carries the exact
    // bits this ACE decided during the stored-order walk:
    //   - inherit-only ACE → "not applied to this object";
    //   - applied ACE that decided bits → "→ granted/denied <bits>";
    //   - applied ACE that decided nothing (all bits already decided by an
    //     earlier ACE) → "matched, no effective bits contributed".
    // This keeps the audit text as exact as the calculation: a reader can
    // no longer mistake a merely-matched ACE for one that mattered.
    let mut matched_ace_steps = 0usize;
    let mut uncertain_ace_steps = 0usize;
    // ADR 0077: the structured twin of the ACE steps, decided by the same
    // predicates in the same place.
    let mut outcomes: Vec<AceOutcome> = Vec::new();
    let outcome = |ace: &AceEntry, effect: AceEffect| AceOutcome {
        layer: TraceLayer::Ntfs,
        kind: ace.kind,
        sid: ace.sid.clone(),
        trustee: trustee_with_sid(&ace.sid, sid_names),
        mask: ace.mask,
        inherited: ace.inherited,
        effect,
    };
    for (idx, ace) in dacl.iter().enumerate() {
        if !ace_matches(ace, match_sids, deny_only_sids) {
            // ADR 0076: an Allow for a certainly filtered group is listed
            // with the reason it does not apply.
            if let Some(reason) = uac_certain_reason.filter(|_| {
                ace.kind == AceKind::Allow
                    && ace_applies_to_current_object(ace)
                    && deny_only_sids.contains(&ace.sid.0)
            }) {
                let scope = if ace.inherited {
                    "[inherited]"
                } else {
                    "[explicit]"
                };
                steps.push(format!(
                    "Allow ACE {scope} for {} → {} (0x{:08X}) [not applied — the group is deny-only \
                     in this token: {reason}]",
                    display_for_sid(&ace.sid, None, sid_names),
                    NormalizedRights::new(expand_generic_rights(ace.mask.0)).display_name(),
                    ace.mask.0,
                ));
                outcomes.push(outcome(
                    ace,
                    AceEffect::NotApplied {
                        reason: format!("the group is deny-only in this token: {reason}"),
                    },
                ));
                continue;
            }
            // Review CR-3: an ACE that only bounds the result is listed like
            // the others, with its own reason.
            if let Some(reason) = uncertain_ace_reason(
                ace,
                match_sids,
                deny_only_sids,
                uncertain_sids,
                uncertain_owner,
                access_context,
                &identity.sid.0,
            ) {
                uncertain_ace_steps += 1;
                let kind = match ace.kind {
                    AceKind::Allow => "Allow",
                    AceKind::Deny => "Deny",
                };
                let scope = if ace.inherited {
                    "[inherited]"
                } else {
                    "[explicit]"
                };
                let rights = NormalizedRights::new(expand_generic_rights(ace.mask.0));
                let effect = match (logon_dependent.is_some(), ace.kind) {
                    (false, _) => "cannot change this result".to_owned(),
                    (true, AceKind::Allow) => {
                        "counted in the upper bound only, not in the shown value".to_owned()
                    }
                    (true, AceKind::Deny) => {
                        "counted in the lower bound only, not in the shown value".to_owned()
                    }
                };
                steps.push(format!(
                    "{kind} ACE {scope} for {} → {} (0x{:08X}) [UNCERTAIN — {reason}; {effect}]",
                    display_for_sid(&ace.sid, None, sid_names),
                    rights.display_name(),
                    ace.mask.0,
                ));
                outcomes.push(outcome(
                    ace,
                    AceEffect::Uncertain {
                        reason: format!("{reason}; {effect}"),
                    },
                ));
            }
            continue;
        }
        matched_ace_steps += 1;
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
        let decided = decided_per_ace.get(idx).copied().unwrap_or(0);
        outcomes.push(outcome(
            ace,
            if !ace_applies_to_current_object(ace) {
                AceEffect::InheritOnly
            } else if decided == 0 {
                AceEffect::NoEffect
            } else {
                AceEffect::Decided { bits: decided }
            },
        ));
        let contribution_note = if !ace_applies_to_current_object(ace) {
            " [inherit-only — not applied to this object]".to_string()
        } else if decided == 0 {
            " [matched, no effective bits contributed]".to_string()
        } else {
            let verb = match ace.kind {
                AceKind::Allow => "granted",
                AceKind::Deny => "denied",
            };
            let decided_rights = NormalizedRights::new(decided);
            format!(
                " [{verb} {} (0x{:08X})]",
                decided_rights.display_name(),
                decided
            )
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
                contribution_note,
            )),
            None => steps.push(format!(
                "{} ACE {} for {} → {} (0x{:08X}){}",
                kind,
                scope,
                ace.sid.0,
                rights.display_name(),
                ace.mask.0,
                contribution_note,
            )),
        }
    }

    // 3a. Review CR-10: the DACL states that explain a result without any
    // ACE step — the most critical state (NULL DACL) above all.
    if null_dacl {
        steps.push(
            "NULL DACL — the object has no access control list: Windows grants every access \
             to everyone (Full Control)"
                .to_string(),
        );
    } else if dacl.is_empty() {
        steps.push(
            "Empty DACL — the object's access control list has no entries: nobody is granted \
             anything through it (only the owner rule below can apply)"
                .to_string(),
        );
    } else if matched_ace_steps == 0 && uncertain_ace_steps == 0 {
        steps.push(
            "No ACE in the DACL applies to this token — nothing is granted or denied through it"
                .to_string(),
        );
    } else if matched_ace_steps == 0 {
        steps.push(
            "No ACE in the DACL certainly applies to this token — only the UNCERTAIN ACE(s) \
             listed above, which bound the result"
                .to_string(),
        );
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
        // Review CR-13: separate what a Deny really took away — bits an
        // applicable Allow ACE of this token would otherwise have granted —
        // from what it merely denies in advance (no Allow grants them).
        let allow_union = dacl
            .iter()
            .filter(|ace| {
                ace.kind == AceKind::Allow
                    && ace_applies_to_current_object(ace)
                    && ace_matches(ace, match_sids, deny_only_sids)
            })
            .fold(0u32, |acc, ace| acc | expand_generic_rights(ace.mask.0));
        let taken_away = denied_for_display & allow_union;
        let pre_empted = denied_for_display & !allow_union;
        let label = |bits: u32| {
            format!(
                "{} (0x{bits:08X})",
                NormalizedRights::new(bits).display_name()
            )
        };
        let detail = match (taken_away != 0, pre_empted != 0) {
            (true, false) => "an Allow ACE of this token would otherwise have granted all of them \
                 — the Deny takes them away"
                .to_owned(),
            (false, true) => "no Allow ACE of this token grants them — the Deny takes nothing \
                 away that would otherwise be granted"
                .to_owned(),
            _ => format!(
                "taken away (an Allow ACE of this token would otherwise grant them): {}; \
                 denied in advance only (no Allow ACE grants them): {}",
                label(taken_away),
                label(pre_empted)
            ),
        };
        steps.push(format!(
            "Deny aggregation: {} decided by Deny ACEs before any Allow could grant them — {detail}",
            label(denied_for_display),
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
    } else if let Some(owner) = uncertain_owner.filter(|_| !owner_rights_ace_present) {
        steps.push(format!(
            "Owner special rule: UNCERTAIN — the owner {} is a group User Account Control \
             filters; READ_CONTROL + WRITE_DAC are granted implicitly only while it is enabled \
             (elevated session)",
            display_for_sid(&Sid(owner.to_owned()), None, sid_names)
        ));
    } else if owner_rights_ace_present {
        steps.push(
            "OWNER RIGHTS (S-1-3-4) ACE present — owner rights are governed by that DACL entry; the implicit owner grant is suppressed".to_string(),
        );
    }

    // 4. NTFS effective — a fact only when determinable (review CR-5). The
    // NTFS-layer reasons follow as their own steps (4b, 4c).
    steps.push(format!(
        "NTFS effective: {}",
        rights_statement(ntfs_raw, ntfs_determinable)
    ));

    // 4b. Lower-confidence warning when ACEs could not be evaluated
    // (engine review 2026-06-12 finding 3). A hidden Deny among the
    // skipped ACEs could change the result, so the mask above is an
    // approximation, not a final answer.
    if unsupported_ntfs_count > 0 {
        steps.push(format!(
            "WARNING: {unsupported_ntfs_count} NTFS ACE(s) on this path could not be evaluated (object / callback / conditional / vendor-specific) — the NTFS effective mask above is a lower-confidence approximation and may be too permissive or too restrictive"
        ));
    }

    // 4b'. Review CR-14: a file can also be deleted through its folder.
    // Stars, like the Windows "Effective Access" tab, evaluates the file's
    // own DACL; one line answers "can X delete this file?" honestly.
    if !is_directory && ntfs_raw & FILE_DELETE == 0 {
        steps.push(
            "Note: this result has no DELETE on the file itself — Windows still lets anyone \
             delete the file who has \"Delete subfolders and files\" (FILE_DELETE_CHILD) on \
             its parent folder; that right is evaluated on the folder (finding \
             DELETE_CHILD_RIGHT), not in this result"
                .to_string(),
        );
    }

    // 4c. Logon-dependent trustees (ADR 0065): the NTFS result is a range.
    if let Some(bounds) = logon_dependent {
        let names: Vec<String> = bounds
            .sids
            .iter()
            .map(|sid| match sid_names.get(sid) {
                Some(name) => format!("{name} ({sid})"),
                None => sid.clone(),
            })
            .collect();
        steps.push(format!(
            "NOT DETERMINABLE: ACE(s) for {} count only for certain logons or session states (the reason is given at each UNCERTAIN step above) — the NTFS right lies between {} (0x{:08X}) and {} (0x{:08X})",
            names.join(", "),
            NormalizedRights::new(bounds.min).display_name(),
            bounds.min,
            NormalizedRights::new(bounds.max).display_name(),
            bounds.max,
        ));
    }

    // 5. Share side. Every share state gets an explicit step so the audit
    // text explains *why* the effective mask is what it is — the data
    // model already carries the state; the explanation must not omit it
    // (engine review 2026-06-12 finding 5).
    //
    // Review CR-5: the share and the effective value are facts only when
    // determinable; share-layer reasons are stated as steps (a failed read
    // has its own step, which already names the reason).
    let share_reasons = || {
        uncertainty
            .iter()
            .filter(|u| u.layer == UncertainLayer::Share)
            .map(|u| format!("{NOT_DETERMINABLE} — share: {}", u.reason))
            .collect::<Vec<String>>()
    };
    match share_status {
        ShareEvalStatus::Applied => {
            if let Some(share) = share_mask {
                steps.push(format!(
                    "Share permission: {}",
                    rights_statement(share.0, share_determinable)
                ));
                steps.extend(share_reasons());
                steps.push(format!(
                    "Effective (NTFS \u{2229} Share): {}",
                    rights_statement(effective_raw, effective_determinable)
                ));
                // Review CR-7: which side limits the result.
                let label = |bits: u32| {
                    format!(
                        "{} (0x{bits:08X})",
                        NormalizedRights::new(bits).display_name()
                    )
                };
                let prefix = if effective_determinable {
                    ""
                } else {
                    "From the known data: "
                };
                let removed_by_share = ntfs_raw & !share.0;
                let removed_by_ntfs = share.0 & !ntfs_raw;
                steps.push(if removed_by_share != 0 {
                    format!(
                        "{prefix}Limited by the share: NTFS grants {}, the share allows {} — the \
                         share removes {}",
                        label(ntfs_raw),
                        label(share.0),
                        label(removed_by_share)
                    )
                } else if removed_by_ntfs != 0 {
                    format!(
                        "{prefix}Limited by NTFS: the share allows {}, NTFS grants {} — the result \
                         follows NTFS",
                        label(share.0),
                        label(ntfs_raw)
                    )
                } else {
                    format!("{prefix}NTFS and share allow the same — neither side limits the other")
                });
            }
        }
        ShareEvalStatus::Unrestricted => {
            steps.push(
                "Share DACL unrestricted (NULL share DACL): SMB does not reduce the NTFS rights — effective = NTFS"
                    .to_string(),
            );
            steps.extend(share_reasons());
        }
        ShareEvalStatus::ReadFailed(reason) => {
            steps.push(format!(
                "Share permissions not determinable ({reason}): the share permission is {NOT_DETERMINABLE} — \
                 the displayed effective mask is NTFS-only and incomplete; the share can only \
                 restrict the NTFS right above, never extend it"
            ));
        }
        ShareEvalStatus::NotApplicable => {
            steps.push(
                "No SMB context: effective permission is NTFS-only (no share combination applied)"
                    .to_string(),
            );
            steps.extend(share_reasons());
        }
    }

    // ADR 0077: the groups the trace's ACEs reach the account through.
    outcomes.extend(share_trace.iter().cloned());
    let trace = trace_groups(
        outcomes,
        &identity.sid.0,
        &merged,
        &decisive,
        match_sids,
        deny_only_sids,
        uncertain_sids,
        access_context,
        sid_names,
    );
    (PermissionPath { steps }, trace)
}

/// `DOMAIN\name (SID)` when a name is known, else the SID.
fn trustee_with_sid(sid: &Sid, sid_names: &std::collections::BTreeMap<String, String>) -> String {
    match sid_names.get(&sid.0) {
        Some(name) => format!("{name} ({})", sid.0),
        None => sid.0.clone(),
    }
}

/// ADR 0077: the token groups the trace's ACEs name, classified like the
/// membership steps (deny-only, uncertain, implicit well-known) — only
/// those, so the trace stays small for an account in thousands of groups.
#[allow(clippy::too_many_arguments)]
fn trace_groups(
    aces: Vec<AceOutcome>,
    user_sid: &str,
    merged: &[GroupMembership],
    decisive: &HashSet<&str>,
    match_sids: &HashSet<String>,
    deny_only_sids: &HashSet<String>,
    uncertain_sids: &HashSet<String>,
    access_context: AccessContext,
    sid_names: &std::collections::BTreeMap<String, String>,
) -> PermissionTrace {
    let mut groups: Vec<TraceGroup> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut memberships_used = 0usize;
    for ace in &aces {
        let sid = ace.sid.0.as_str();
        if sid == user_sid || !seen.insert(sid.to_owned()) {
            continue;
        }
        let state_of = |sid: &str| {
            if deny_only_sids.contains(sid) {
                TraceGroupState::DenyOnly
            } else if uncertain_sids.contains(sid) {
                TraceGroupState::Uncertain
            } else {
                TraceGroupState::Member
            }
        };
        let group = if let Some(gm) = merged.iter().find(|m| m.group_sid.0 == sid) {
            memberships_used += 1;
            TraceGroup {
                sid: gm.group_sid.clone(),
                display: match gm.group_name.as_deref().filter(|n| !n.is_empty()) {
                    Some(name) => format!("{name} ({sid})"),
                    None => trustee_with_sid(&gm.group_sid, sid_names),
                },
                route: membership_route(gm, sid_names),
                state: state_of(sid),
                decisive: decisive.contains(sid),
            }
        } else if match_sids.contains(sid) {
            TraceGroup {
                sid: ace.sid.clone(),
                display: trustee_with_sid(&ace.sid, sid_names),
                route: implicit_route(sid, access_context).to_owned(),
                state: TraceGroupState::Implicit,
                decisive: decisive.contains(sid),
            }
        } else if matches!(ace.effect, AceEffect::Uncertain { .. }) {
            TraceGroup {
                sid: ace.sid.clone(),
                display: trustee_with_sid(&ace.sid, sid_names),
                route: logon_dependent_reason(sid).to_owned(),
                state: TraceGroupState::Uncertain,
                decisive: false,
            }
        } else {
            // A share ACE whose trustee is not in the token at all is never
            // in the trace (`share_ace_outcomes` leaves those out).
            continue;
        };
        groups.push(group);
    }
    // The memberships no ACE names — named, so the graph can list them.
    let other: Vec<TraceGroup> = merged
        .iter()
        .filter(|m| !seen.contains(&m.group_sid.0))
        .map(|gm| {
            let sid = gm.group_sid.0.as_str();
            TraceGroup {
                sid: gm.group_sid.clone(),
                display: match gm.group_name.as_deref().filter(|n| !n.is_empty()) {
                    Some(name) => format!("{name} ({sid})"),
                    None => trustee_with_sid(&gm.group_sid, sid_names),
                },
                route: membership_route(gm, sid_names),
                state: if deny_only_sids.contains(sid) {
                    TraceGroupState::DenyOnly
                } else if uncertain_sids.contains(sid) {
                    TraceGroupState::Uncertain
                } else {
                    TraceGroupState::Member
                },
                decisive: false,
            }
        })
        .collect();
    PermissionTrace {
        aces,
        other_groups: merged.len().saturating_sub(memberships_used),
        groups,
        other,
    }
}

/// `direct`, `via A → B` or "chain unknown" for a membership (ADR 0077).
fn membership_route(
    gm: &GroupMembership,
    sid_names: &std::collections::BTreeMap<String, String>,
) -> String {
    let Some(path) = gm.path.as_ref() else {
        return if gm.direct { "direct" } else { "transitive" }.to_owned();
    };
    if !path.complete {
        return "membership confirmed, exact chain unknown".to_owned();
    }
    if path.nodes.len() <= 2 {
        return "direct".to_owned();
    }
    let middle: Vec<String> = path.nodes[1..path.nodes.len() - 1]
        .iter()
        .enumerate()
        .map(|(i, sid)| {
            path.names
                .get(i + 1)
                .cloned()
                .flatten()
                .or_else(|| sid_names.get(&sid.0).cloned())
                .unwrap_or_else(|| sid.0.clone())
        })
        .collect();
    format!("via {}", middle.join(" → "))
}

/// Why an implicit well-known is in the token (ADR 0077).
fn implicit_route(sid: &str, access_context: AccessContext) -> &'static str {
    match sid {
        SID_EVERYONE | SID_AUTHENTICATED_USERS => "implicit — in every token of this logon",
        "S-1-5-2" => "implicit — network logon over SMB",
        "S-1-5-4" => "implicit — interactive logon",
        SID_OWNER_RIGHTS => "implicit — the account owns this object",
        _ => match access_context {
            AccessContext::RemoteSmb => "implicit — network logon",
            AccessContext::LocalInteractive => "implicit — interactive logon",
            AccessContext::Unspecified => "implicit",
        },
    }
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
    use adpa_core::traits::ResolutionProvenance;

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
            sid_history_count: 0,
            sid_history: Vec::new(),
        }
    }

    fn membership(user_sid: &str, group_sid: &str) -> GroupMembership {
        GroupMembership {
            member_sid: Sid(user_sid.into()),
            group_sid: Sid(group_sid.into()),
            direct: true,
            group_name: None,
            path: None,
            group_sid_history_count: 0,
            group_sid_history: Vec::new(),
        }
    }

    /// Membership whose group carries historical SIDs (ADR 0059).
    fn membership_with_history(user_sid: &str, group_sid: &str, old: &[&str]) -> GroupMembership {
        let mut gm = membership(user_sid, group_sid);
        gm.group_sid_history_count = old.len();
        gm.group_sid_history = old.iter().map(|s| Sid((*s).into())).collect();
        gm
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
            sd_hash: None,
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
            sd_hash: None,
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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
            })
            .unwrap()
    }

    /// Evaluates with an explicit share status — needed to exercise the
    /// Unrestricted / ReadFailed share-explanation steps (finding 5).
    fn eval_with_share(
        identity: Identity,
        file_system_object: FileSystemObject,
        share_status: ShareMaskStatus,
    ) -> EffectivePermission {
        DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity,
                group_memberships: vec![],
                file_system_object,
                share_status,
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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

    /// Lab hard-test finding F2: when the same membership edge arrives more
    /// than once (identical target + via-chain), the explanation path must
    /// list it only once — not print the same "Member of …" line twice.
    #[test]
    fn explanation_dedups_identical_membership_steps() {
        let p = eval(
            user(USER),
            // Two identical memberships in GROUP_A — as can happen when a
            // group is reached through more than one resolution path.
            vec![membership(USER, GROUP_A), membership(USER, GROUP_A)],
            fso(None, vec![allow_ace(GROUP_A, MASK_READ, false)]),
            None,
        );
        let member_steps = p
            .path_explanation
            .steps
            .iter()
            .filter(|s| s.starts_with("Member of") && s.contains(GROUP_A))
            .count();
        assert_eq!(
            member_steps, 1,
            "an identical membership edge must appear exactly once; got: {:?}",
            p.path_explanation.steps
        );
    }

    /// Lab finding CLI3-1: the same group from LDAP (DomainGroup) and from
    /// the local-group lookup (LocalGroup) is one step; a mediator only the
    /// local source knew is named as a further route.
    #[test]
    fn explanation_lists_a_group_from_two_sources_once() {
        const DOMAIN_ADMINS: &str = "S-1-5-21-1000-1000-1000-512";
        let ldap = direct_membership_with_path(
            USER,
            "alice",
            GROUP_A,
            "DL_Finance_RW",
            MembershipPathSource::DomainGroup,
        );
        let mut local = nested_membership(
            USER,
            "alice",
            DOMAIN_ADMINS,
            "Domain Admins",
            GROUP_A,
            "DL_Finance_RW",
        );
        if let Some(path) = local.path.as_mut() {
            path.source = MembershipPathSource::LocalGroup;
        }
        let p = eval(
            user(USER),
            vec![ldap, local],
            fso(None, vec![allow_ace(GROUP_A, MASK_READ, false)]),
            None,
        );
        let steps: Vec<&String> = p
            .path_explanation
            .steps
            .iter()
            .filter(|s| s.starts_with("Member of") && s.contains(GROUP_A))
            .collect();
        assert_eq!(steps.len(), 1, "{:?}", p.path_explanation.steps);
        assert!(steps[0].contains("source: DomainGroup"), "{}", steps[0]);
        assert!(
            steps[0].contains("also a member through Domain Admins (S-1-5-21-1000-1000-1000-512)"),
            "{}",
            steps[0]
        );
    }

    // --- Share-side explanation steps (engine review 2026-06-12 finding 5) ---

    /// A local NTFS-only analysis spells out that no SMB combination was
    /// applied, instead of silently omitting the share line.
    #[test]
    fn explanation_states_ntfs_only_when_no_smb_context() {
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, MASK_READ, false)]),
            None,
        );
        assert!(
            p.path_explanation
                .steps
                .iter()
                .any(|s| s.contains("No SMB context") && s.contains("NTFS-only")),
            "NTFS-only analysis must state the no-SMB reason; got: {:?}",
            p.path_explanation.steps
        );
    }

    /// A NULL share DACL (unrestricted) is spelled out as "SMB does not
    /// reduce the NTFS rights".
    #[test]
    fn explanation_states_unrestricted_share() {
        let p = eval_with_share(
            user(USER),
            fso(None, vec![allow_ace(USER, MASK_MODIFY, false)]),
            ShareMaskStatus::Unrestricted,
        );
        assert!(
            p.path_explanation
                .steps
                .iter()
                .any(|s| s.contains("Share DACL unrestricted") && s.contains("effective = NTFS")),
            "unrestricted share must be explained; got: {:?}",
            p.path_explanation.steps
        );
    }

    /// A failed share-DACL read is spelled out as incomplete / NTFS-only.
    #[test]
    fn explanation_states_share_read_failed() {
        let p = eval_with_share(
            user(USER),
            fso(None, vec![allow_ace(USER, MASK_MODIFY, false)]),
            ShareMaskStatus::ReadFailed("access denied".to_owned()),
        );
        assert!(
            p.path_explanation.steps.iter().any(|s| {
                s.contains("Share permissions not determinable")
                    && s.contains("access denied")
                    && s.contains("incomplete")
            }),
            "share read failure must be explained as incomplete; got: {:?}",
            p.path_explanation.steps
        );
    }

    /// The applied-share case still renders the intersection step.
    #[test]
    fn explanation_states_applied_share_intersection() {
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, MASK_MODIFY, false)]),
            Some(AccessMask(MASK_READ)),
        );
        assert!(
            p.path_explanation
                .steps
                .iter()
                .any(|s| s.contains("Effective (NTFS \u{2229} Share)")),
            "applied share must render the intersection step; got: {:?}",
            p.path_explanation.steps
        );
    }

    // --- Contribution-aware explanation (engine review 2026-06-12 finding 1) ---

    /// An ACE that actually decided bits is labeled with what it granted,
    /// not merely listed as "matched".
    #[test]
    fn explanation_labels_contributing_allow_with_granted_bits() {
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, MASK_READ, false)]),
            None,
        );
        let step = p
            .path_explanation
            .steps
            .iter()
            .find(|s| s.contains("Allow ACE") && s.contains(USER))
            .expect("Allow ACE step must exist");
        assert!(
            step.contains("granted"),
            "a contributing Allow must be labeled 'granted'; got: {step}"
        );
        assert!(
            step.contains(&format!("0x{:08X}", MASK_READ)),
            "the step must name the exact contributed bits; got: {step}"
        );
    }

    /// A later ACE whose bits were all already decided is labeled
    /// "matched, no effective bits contributed" — the reader must not
    /// mistake it for an ACE that mattered.
    #[test]
    fn explanation_marks_noncontributing_ace_as_matched_only() {
        let p = eval(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    allow_ace(USER, MASK_MODIFY, false),
                    // Everyone (always in the token) Allow Modify — decides
                    // nothing because the USER ACE already granted these bits.
                    allow_ace("S-1-1-0", MASK_MODIFY, false),
                ],
            ),
            None,
        );
        let everyone_step = p
            .path_explanation
            .steps
            .iter()
            .find(|s| s.starts_with("Allow ACE") && s.contains("S-1-1-0"))
            .expect("Everyone ACE step must exist");
        assert!(
            everyone_step.contains("matched, no effective bits contributed"),
            "a non-contributing ACE must be labeled matched-only; got: {everyone_step}"
        );
    }

    /// A Deny ACE that decided bits is labeled with what it denied.
    #[test]
    fn explanation_labels_contributing_deny_with_denied_bits() {
        let p = eval(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    deny_ace(USER, MASK_WRITE, false),
                    allow_ace(USER, MASK_FULL_CONTROL, false),
                ],
            ),
            None,
        );
        let deny_step = p
            .path_explanation
            .steps
            .iter()
            .find(|s| s.contains("Deny ACE"))
            .expect("Deny ACE step must exist");
        assert!(
            deny_step.contains("denied"),
            "a contributing Deny must be labeled 'denied'; got: {deny_step}"
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
        // Finding 3: also surfaced as a first-class structured diagnostic.
        assert!(
            p.diagnostics
                .iter()
                .any(|d| matches!(d, PermissionDiagnostic::UnsupportedNtfsAces { count: 2 })),
            "unsupported NTFS ACEs must appear as a structured diagnostic; got: {:?}",
            p.diagnostics
        );
        // ... and as an explicit lower-confidence step in the explanation.
        assert!(
            p.path_explanation
                .steps
                .iter()
                .any(|s| s.contains("lower-confidence approximation")),
            "explanation must warn the result is approximate; got: {:?}",
            p.path_explanation.steps
        );
    }

    #[test]
    fn no_unsupported_aces_yields_no_ntfs_diagnostic_or_warning() {
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, MASK_READ, false)]),
            None,
        );
        assert!(
            !p.diagnostics
                .iter()
                .any(|d| matches!(d, PermissionDiagnostic::UnsupportedNtfsAces { .. })),
            "no unsupported NTFS diagnostic when there are no unsupported ACEs"
        );
        assert!(
            !p.path_explanation
                .steps
                .iter()
                .any(|s| s.contains("lower-confidence approximation")),
            "no approximation warning on a clean DACL"
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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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

    /// Lab finding DET-2: `contributing_sids` came out of a `HashMap`, so
    /// two runs over the same DACL listed the contributors in a different
    /// order. They must follow the DACL order of each SID's first
    /// contribution, with later bits of the same SID merged into its entry.
    #[test]
    fn contributing_sids_follow_dacl_order_and_merge_per_sid() {
        const G1: &str = "S-1-5-21-1000-1000-1000-6001";
        const G2: &str = "S-1-5-21-1000-1000-1000-6002";
        const G3: &str = "S-1-5-21-1000-1000-1000-6003";
        let memberships = vec![
            membership(USER, G3),
            membership(USER, G1),
            membership(USER, G2),
        ];
        let dacl = vec![
            allow_ace(G2, FILE_READ_DATA, false),
            allow_ace(G3, FILE_WRITE_DATA, false),
            allow_ace(G1, FILE_EXECUTE, true),
            allow_ace(G2, FILE_READ_ATTRIBUTES, true),
        ];
        let first = eval(
            user(USER),
            memberships.clone(),
            fso(None, dacl.clone()),
            None,
        );
        let order: Vec<(&str, u32)> = first
            .contributing_sids
            .iter()
            .map(|c| (c.sid.0.as_str(), c.mask.0))
            .collect();
        assert_eq!(
            order,
            [
                (G2, FILE_READ_DATA | FILE_READ_ATTRIBUTES),
                (G3, FILE_WRITE_DATA),
                (G1, FILE_EXECUTE),
            ]
        );
        for _ in 0..20 {
            let again = eval(
                user(USER),
                memberships.clone(),
                fso(None, dacl.clone()),
                None,
            );
            assert_eq!(
                format!("{:?}", again.contributing_sids),
                format!("{:?}", first.contributing_sids)
            );
        }
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
            super::dacl_order_finding(&dacl),
            Some(super::DaclOrderFinding::NonCanonical(1)),
            "deny at index 1 follows allow at index 0 — non-canonical"
        );
    }

    /// Known limitation L9, lab case 2026-10-17 (a child folder of the DC-01
    /// group-kind fixture): an inherited Allow from the parent ahead of an inherited Deny from the
    /// grandparent is canonical in Windows. The DACL does not record the
    /// level, so Stars must not call it non-canonical — it reports that it
    /// cannot tell.
    #[test]
    fn inherited_deny_after_inherited_allow_is_not_called_non_canonical() {
        use adpa_core::model::PermissionDiagnostic;
        let dacl = vec![
            allow_ace(USER, MASK_READ, true), // inherited from the parent
            deny_ace(USER, MASK_WRITE, true), // inherited from the grandparent
            allow_ace(USER, MASK_MODIFY, true),
        ];
        assert_eq!(
            super::dacl_order_finding(&dacl),
            Some(super::DaclOrderFinding::InheritedLevelsUnknown(1))
        );
        let p = eval(user(USER), vec![], fso(None, dacl), None);
        assert_eq!(
            p.diagnostics,
            vec![PermissionDiagnostic::InheritedDenyAfterInheritedAllow { at_index: 1 }]
        );
        assert!(p.effective_determinable(), "informational only");
        let text = p.diagnostics[0].summary();
        assert!(text.contains("different ancestor levels") && text.contains("unaffected"));
        assert!(!text.to_lowercase().starts_with("non-canonical"));
    }

    /// Every order that is never canonical stays NonCanonical, even when an
    /// ambiguous inherited pair comes first.
    #[test]
    fn definite_order_violations_stay_non_canonical() {
        use super::DaclOrderFinding::NonCanonical;
        // explicit Allow after an inherited ACE
        let a = vec![
            allow_ace(USER, MASK_READ, true),
            allow_ace(USER, MASK_READ, false),
        ];
        assert_eq!(super::dacl_order_finding(&a), Some(NonCanonical(1)));
        // explicit Deny after an inherited ACE
        let b = vec![
            allow_ace(USER, MASK_READ, true),
            deny_ace(USER, MASK_READ, false),
        ];
        assert_eq!(super::dacl_order_finding(&b), Some(NonCanonical(1)));
        // explicit Deny after an explicit Allow
        let c = vec![
            deny_ace(USER, MASK_WRITE, false),
            allow_ace(USER, MASK_READ, false),
            deny_ace(USER, MASK_READ, false),
        ];
        assert_eq!(super::dacl_order_finding(&c), Some(NonCanonical(2)));
        // ambiguous pair first, definite violation later: definite wins
        let d = vec![
            allow_ace(USER, MASK_READ, true),
            deny_ace(USER, MASK_WRITE, true),
            allow_ace(USER, MASK_READ, false),
        ];
        assert_eq!(super::dacl_order_finding(&d), Some(NonCanonical(2)));
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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 4,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names,
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names,
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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
            // The group's ACE decides bits — marked decisive (review CR-12).
            &format!(
                "Member of {GROUP_A} [direct] [decisive — an ACE for this group decides bits of \
                 this result]"
            ),
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
        assert_eq!(super::dacl_order_finding(&dacl), None);
    }

    // --- Finding 4: AccessContext / kontextspezifische Well-Known-SIDs ---
    // --- Finding 4: AccessContext / context-specific well-known SIDs ---

    /// S-1-5-2 = NETWORK
    const SID_NETWORK: &str = "S-1-5-2";
    /// S-1-5-4 = INTERACTIVE
    const SID_INTERACTIVE: &str = "S-1-5-4";
    /// S-1-2-0 = LOCAL
    const SID_LOCAL: &str = "S-1-2-0";

    // --- ADR 0065: logon-dependent trustees bound the result ---

    const THIS_ORGANIZATION: &str = "S-1-5-15";
    const AUTH_ASSERTED: &str = "S-1-18-1";
    const REMOTE_INTERACTIVE: &str = "S-1-5-14";

    fn logon_marker(p: &EffectivePermission) -> Option<(Vec<String>, u32, u32)> {
        p.diagnostics.iter().find_map(|d| match d {
            PermissionDiagnostic::LogonDependentTrustees {
                sids,
                min_mask,
                max_mask,
            } => Some((sids.clone(), *min_mask, *max_mask)),
            _ => None,
        })
    }

    // --- ADR 0079: This / Other Organization decided for a trusted account ---

    /// Lab 2026-10-17 (real SMB logons across the corp.test ⇄ ext.test
    /// trust): without Selective Authentication the token holds This
    /// Organization and not Other Organization — with it the reverse. The
    /// resolver adds the one present as a membership; ACEs for both are then
    /// exact, never a range.
    #[test]
    fn a_decided_organization_sid_makes_both_organization_aces_exact() {
        const OTHER_ORGANIZATION: &str = "S-1-5-1000";
        for (present, absent) in [
            (THIS_ORGANIZATION, OTHER_ORGANIZATION),
            (OTHER_ORGANIZATION, THIS_ORGANIZATION),
        ] {
            let p = eval_with_context(
                user(USER),
                vec![membership(USER, present)],
                fso(
                    None,
                    vec![
                        allow_ace(present, MASK_READ, false),
                        allow_ace(absent, MASK_MODIFY, false),
                    ],
                ),
                None,
                AccessContext::RemoteSmb,
            );
            assert!(p.ntfs_determinable(), "{present}: exact");
            assert!(logon_marker(&p).is_none(), "{present}: no range");
            assert_eq!(
                p.ntfs_mask.0, MASK_READ,
                "{present} grants, {absent} does not"
            );
        }
    }

    /// Without either in the token (every account that is not resolved in a
    /// trusted domain) both stay logon-dependent, exactly as before.
    #[test]
    fn without_a_decided_organization_both_stay_logon_dependent() {
        let token: HashSet<String> = [USER.to_owned()].into_iter().collect();
        for sid in [THIS_ORGANIZATION, "S-1-5-1000"] {
            assert!(super::is_logon_dependent_for(
                sid,
                AccessContext::RemoteSmb,
                &token
            ));
            assert_eq!(
                super::is_logon_dependent_for(sid, AccessContext::RemoteSmb, &token),
                super::is_logon_dependent_sid(sid, AccessContext::RemoteSmb)
            );
        }
        let with_this: HashSet<String> = [USER.to_owned(), THIS_ORGANIZATION.to_owned()]
            .into_iter()
            .collect();
        assert!(!super::is_logon_dependent_for(
            "S-1-5-1000",
            AccessContext::RemoteSmb,
            &with_this
        ));
        // Any other logon-dependent SID is unaffected.
        assert!(super::is_logon_dependent_for(
            "S-1-18-1",
            AccessContext::RemoteSmb,
            &with_this
        ));
    }

    #[test]
    fn logon_dependent_allow_makes_the_result_a_range() {
        let p = eval_with_context(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    allow_ace(THIS_ORGANIZATION, MASK_MODIFY, true),
                    allow_ace(USER, MASK_READ, true),
                ],
            ),
            None,
            AccessContext::RemoteSmb,
        );
        // The shown mask treats the ACE as absent …
        assert_eq!(p.ntfs_mask.0, MASK_READ);
        // … and says it is only the lower bound.
        let (sids, min, max) = logon_marker(&p).expect("range marker");
        assert_eq!(sids, [THIS_ORGANIZATION]);
        assert_eq!(min, MASK_READ);
        assert_eq!(max, MASK_MODIFY);
        assert!(!p.ntfs_determinable() && p.is_incomplete());
        assert!(
            p.path_explanation
                .steps
                .iter()
                .any(|s| s.starts_with("NOT DETERMINABLE: ACE(s) for S-1-5-15")),
            "{:?}",
            p.path_explanation.steps
        );
    }

    #[test]
    fn logon_dependent_ace_that_cannot_change_the_result_keeps_it_exact() {
        // Every bit is already decided by the user's own Full Control ACE.
        let p = eval_with_context(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    allow_ace(USER, MASK_FULL_CONTROL, false),
                    allow_ace(THIS_ORGANIZATION, MASK_MODIFY, true),
                    deny_ace(AUTH_ASSERTED, MASK_WRITE, true),
                ],
            ),
            None,
            AccessContext::RemoteSmb,
        );
        assert_eq!(p.ntfs_mask.0, MASK_FULL_CONTROL);
        assert!(logon_marker(&p).is_none());
        assert!(p.ntfs_determinable());
    }

    #[test]
    fn logon_dependent_deny_lowers_the_minimum() {
        let p = eval_with_context(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    deny_ace(AUTH_ASSERTED, FILE_WRITE_DATA, false),
                    allow_ace(USER, MASK_MODIFY, false),
                ],
            ),
            None,
            AccessContext::RemoteSmb,
        );
        let (_, min, max) = logon_marker(&p).expect("range marker");
        assert_eq!(max, MASK_MODIFY);
        assert_eq!(min, MASK_MODIFY & !FILE_WRITE_DATA);
        assert_eq!(
            p.ntfs_mask.0, MASK_MODIFY,
            "shown mask treats the Deny as absent"
        );
    }

    #[test]
    fn inherit_only_logon_dependent_ace_is_ignored() {
        let p = eval_with_context(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    allow_ace_inherit_only(THIS_ORGANIZATION, MASK_MODIFY, false),
                    allow_ace(USER, MASK_READ, false),
                ],
            ),
            None,
            AccessContext::RemoteSmb,
        );
        assert!(logon_marker(&p).is_none());
    }

    #[test]
    fn remote_interactive_ace_depends_on_the_context() {
        let dacl = vec![
            allow_ace(REMOTE_INTERACTIVE, MASK_MODIFY, false),
            allow_ace(USER, MASK_READ, false),
        ];
        // Over SMB the logon is a network logon — the SID is certainly absent.
        let smb = eval_with_context(
            user(USER),
            vec![],
            fso(None, dacl.clone()),
            None,
            AccessContext::RemoteSmb,
        );
        assert!(logon_marker(&smb).is_none());
        assert!(smb.ntfs_determinable());
        // Locally it depends on console vs. remote desktop.
        let local = eval_with_context(
            user(USER),
            vec![],
            fso(None, dacl),
            None,
            AccessContext::LocalInteractive,
        );
        assert!(logon_marker(&local).is_some());
    }

    #[test]
    fn is_logon_dependent_sid_classifies_the_well_known_set() {
        for sid in [
            "S-1-5-15",
            "S-1-5-1000",
            "S-1-5-65-1",
            "S-1-18-1",
            "S-1-18-2",
            "S-1-5-64-10",
            "S-1-5-64-14",
            "S-1-5-113",
            "S-1-5-114",
        ] {
            for ctx in [
                AccessContext::RemoteSmb,
                AccessContext::LocalInteractive,
                AccessContext::Unspecified,
            ] {
                assert!(is_logon_dependent_sid(sid, ctx), "{sid} {ctx:?}");
            }
        }
        for modelled in ["S-1-1-0", "S-1-5-11", "S-1-5-18", "S-1-3-0", "S-1-5-32-544"] {
            assert!(
                !is_logon_dependent_sid(modelled, AccessContext::RemoteSmb),
                "{modelled}"
            );
        }
        assert!(!is_logon_dependent_sid("S-1-5-2", AccessContext::RemoteSmb));
        assert!(!is_logon_dependent_sid(
            "S-1-5-2",
            AccessContext::LocalInteractive
        ));
        assert!(is_logon_dependent_sid(
            "S-1-5-2",
            AccessContext::Unspecified
        ));
        assert!(!is_logon_dependent_sid("S-1-2-1", AccessContext::RemoteSmb));
        assert!(is_logon_dependent_sid(
            "S-1-2-1",
            AccessContext::LocalInteractive
        ));
        // ADR 0069: LOCAL depends on how the local logon happened; a network
        // logon never carries it.
        assert!(is_logon_dependent_sid(
            "S-1-2-0",
            AccessContext::LocalInteractive
        ));
        assert!(is_logon_dependent_sid(
            "S-1-2-0",
            AccessContext::Unspecified
        ));
        assert!(!is_logon_dependent_sid("S-1-2-0", AccessContext::RemoteSmb));
        // INTERACTIVE is in every interactive token (console, RDP, LogonUser).
        assert!(!is_logon_dependent_sid(
            "S-1-5-4",
            AccessContext::LocalInteractive
        ));
    }

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

    /// ADR 0069 (lab finding MS-2): a real console session's token carries
    /// LOCAL, an interactive `LogonUser` token does not — a LOCAL ACE
    /// bounds the result instead of being assumed to apply.
    #[test]
    fn local_ace_is_logon_dependent_in_local_interactive_context() {
        let p = eval_with_context(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(SID_LOCAL, MASK_READ, false)]),
            None,
            AccessContext::LocalInteractive,
        );
        assert_eq!(p.ntfs_mask.0, 0, "the shown mask treats LOCAL as absent");
        let (sids, min, max) = logon_marker(&p).expect("LOCAL bounds the result");
        assert_eq!(sids, vec![SID_LOCAL.to_string()]);
        assert_eq!(min, 0);
        assert_eq!(max, expand_generic_rights(MASK_READ));
        assert!(!p.effective_determinable());
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
            super::build_token_sids_with_context(USER, &[], &[], &[], AccessContext::Unspecified);
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
        let token =
            super::build_token_sids_with_context(USER, &[], &[], &[], AccessContext::RemoteSmb);
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
    fn build_token_sids_with_context_adds_interactive_but_not_local_for_local_interactive() {
        let token = super::build_token_sids_with_context(
            USER,
            &[],
            &[],
            &[],
            AccessContext::LocalInteractive,
        );
        assert!(
            token.contains(SID_INTERACTIVE),
            "INTERACTIVE must be added for LocalInteractive"
        );
        assert!(
            !token.contains(SID_LOCAL),
            "LOCAL is logon-dependent for LocalInteractive (ADR 0069), not in the token"
        );
        assert!(
            !token.contains(SID_NETWORK),
            "NETWORK must NOT be added for LocalInteractive"
        );
    }

    /// ADR 0056: the user's historical SIDs (sIDHistory) are part of the
    /// token in every access context.
    #[test]
    fn build_token_sids_with_context_includes_sid_history() {
        const OLD: &str = "S-1-5-21-4000-4000-4000-1104";
        let history = vec![Sid(OLD.into())];
        let token = super::build_token_sids_with_context(
            USER,
            &history,
            &[],
            &[],
            AccessContext::Unspecified,
        );
        assert!(token.contains(USER), "own SID must be present");
        assert!(token.contains(OLD), "historical SID must be present");
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
                also_via: Vec::new(),
            }),
            group_sid_history_count: 0,
            group_sid_history: Vec::new(),
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
                also_via: Vec::new(),
            }),
            group_sid_history_count: 0,
            group_sid_history: Vec::new(),
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
                also_via: Vec::new(),
            }),
            group_sid_history_count: 0,
            group_sid_history: Vec::new(),
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
            sd_hash: None,
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
        // A single-route membership must not claim further routes.
        assert!(
            !chain_step.contains("also a member through"),
            "no alternative route exists here:\n{chain_step}"
        );
    }

    #[test]
    fn explanation_discloses_further_routes_into_a_group() {
        // ADR 0063: the shown chain is one shortest route; further entries
        // into the group (here GRP_C, nameless in the path → name from the
        // SID table) must be named in the same step.
        const GROUP_C: &str = "S-1-5-21-1000-1000-1000-1300";
        let mut gm = nested_membership(USER, "max.mustermann", GROUP_A, "GRP_A", GROUP_B, "GRP_B");
        if let Some(path) = gm.path.as_mut() {
            path.also_via = vec![MembershipHop {
                sid: Sid(GROUP_C.into()),
                name: None,
            }];
        }
        let mut sid_names = std::collections::BTreeMap::new();
        sid_names.insert(GROUP_C.to_owned(), "EXAMPLE\\GRP_C".to_owned());
        let result = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![gm],
                file_system_object: fso_with_dacl(vec![allow_ace(
                    GROUP_B,
                    FILE_GENERIC_READ,
                    true,
                )]),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names,
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
            })
            .expect("evaluate");
        let step = result
            .path_explanation
            .steps
            .iter()
            .find(|s| s.contains("Member of") && s.contains("GRP_B"))
            .expect("membership step");
        assert!(
            step.contains("also a member through EXAMPLE\\GRP_C (S-1-5-21-1000-1000-1000-1300)"),
            "further route must be named with its resolved name:\n{step}"
        );
        assert!(step.contains("not the only route"), "{step}");
    }

    #[test]
    fn explanation_summarises_long_route_lists() {
        let mut gm = nested_membership(USER, "max.mustermann", GROUP_A, "GRP_A", GROUP_B, "GRP_B");
        if let Some(path) = gm.path.as_mut() {
            path.also_via = (0..8)
                .map(|i| MembershipHop {
                    sid: Sid(format!("S-1-5-21-1000-1000-1000-{}", 5000 + i)),
                    name: Some(format!("G{i}")),
                })
                .collect();
        }
        let result = eval(
            user(USER),
            vec![gm],
            fso_with_dacl(vec![allow_ace(GROUP_B, FILE_GENERIC_READ, true)]),
            None,
        );
        let step = result
            .path_explanation
            .steps
            .iter()
            .find(|s| s.contains("Member of") && s.contains("GRP_B"))
            .expect("membership step");
        assert!(step.contains("G4 (S-1-5-21-1000-1000-1000-5004)"), "{step}");
        assert!(
            !step.contains("G5 ("),
            "only the first five are spelled out:\n{step}"
        );
        assert!(step.contains("(+3 more)"), "{step}");
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
            group_sid_history_count: 0,
            group_sid_history: Vec::new(),
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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance {
                    identity_not_in_configured_ldap_base: true,
                    ..Default::default()
                },
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance {
                    identity_disabled_status_unknown: true,
                    ..Default::default()
                },
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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

    /// Test helper: a `PermissionEvaluationInput` with every incompleteness
    /// flag off. Tests flip only the field under test, which keeps them
    /// readable and shields them from unrelated field additions.
    fn base_input(
        identity: Identity,
        file_system_object: FileSystemObject,
    ) -> PermissionEvaluationInput {
        PermissionEvaluationInput {
            identity,
            group_memberships: vec![],
            file_system_object,
            share_status: ShareMaskStatus::NotApplicable,
            local_group_sids: vec![],
            local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
            logon_dependent_group_sids: Vec::new(),
            uac_filtered_group_sids: Vec::new(),
            remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
            anonymous_everyone: None,
            access_context: AccessContext::Unspecified,
            unsupported_share_ace_count: 0,
            sid_names: std::collections::BTreeMap::new(),
            resolution: ResolutionProvenance::default(),
            share_trace: Default::default(),
            selective_authentication: Default::default(),
            dfs: None,
        }
    }

    /// ADR 0052 (L3) / ADR 0056: a history count without parsed values
    /// (e.g. rows persisted under ADR 0052, or all values malformed) still
    /// surfaces as `SidHistoryPresent { count }` — nothing was evaluated,
    /// the under-report risk stays visible.
    #[test]
    fn engine_pushes_sid_history_present_diagnostic() {
        let mut identity = user(USER);
        identity.sid_history_count = 3;
        let result = DefaultPermissionEngine
            .evaluate(base_input(
                identity,
                fso(None, vec![allow_ace(USER, MASK_READ, false)]),
            ))
            .unwrap();
        assert!(
            result
                .diagnostics
                .contains(&PermissionDiagnostic::SidHistoryPresent { count: 3 }),
            "engine must push SidHistoryPresent {{ count }} when sid_history_count > 0; got {:?}",
            result.diagnostics
        );
    }

    /// No sIDHistory → no marker (no false positive).
    #[test]
    fn engine_no_sid_history_diagnostic_when_zero() {
        let result = DefaultPermissionEngine
            .evaluate(base_input(
                user(USER),
                fso(None, vec![allow_ace(USER, MASK_READ, false)]),
            ))
            .unwrap();
        assert!(
            !result
                .diagnostics
                .iter()
                .any(|d| matches!(d, PermissionDiagnostic::SidHistoryPresent { .. })),
            "no SidHistoryPresent when count is 0; got {:?}",
            result.diagnostics
        );
    }

    /// ADR 0056 acceptance case (deep review 2026-07-04 F1): the user's SID
    /// is `USER`, `sIDHistory` carries an old SID, and the ACL grants that
    /// old SID Modify. The engine must grant Modify via the historical SID,
    /// name it in the explanation path, mark it `SidHistoryEvaluated` — and
    /// must NOT flag the result incomplete for history reasons.
    #[test]
    fn engine_grants_access_via_historical_sid() {
        const OLD: &str = "S-1-5-21-4000-4000-4000-1104";
        let mut identity = user(USER);
        identity.sid_history_count = 1;
        identity.sid_history = vec![Sid(OLD.into())];
        let result = DefaultPermissionEngine
            .evaluate(base_input(
                identity,
                fso(None, vec![allow_ace(OLD, MASK_MODIFY, false)]),
            ))
            .unwrap();
        assert_eq!(
            result.ntfs_mask.0, MASK_MODIFY,
            "ACE on the historical SID must grant Modify"
        );
        assert!(
            result
                .diagnostics
                .contains(&PermissionDiagnostic::SidHistoryEvaluated { count: 1 }),
            "SidHistoryEvaluated must fire; got {:?}",
            result.diagnostics
        );
        assert!(
            !result
                .diagnostics
                .iter()
                .any(|d| matches!(d, PermissionDiagnostic::SidHistoryPresent { .. })),
            "fully parsed history must not raise the incompleteness marker; got {:?}",
            result.diagnostics
        );
        assert!(
            !result.is_incomplete(),
            "history-evaluated result must not be incomplete; got {:?}",
            result.diagnostics
        );
        assert!(
            result
                .path_explanation
                .steps
                .iter()
                .any(|s| s.contains("Historical SID (sIDHistory)") && s.contains(OLD)),
            "explanation must name the historical SID; got {:?}",
            result.path_explanation.steps
        );
    }

    /// ADR 0056: a Deny ACE on a historical SID must also be honored —
    /// history evaluation applies to the whole token, not only to grants.
    #[test]
    fn engine_honors_deny_on_historical_sid() {
        const OLD: &str = "S-1-5-21-4000-4000-4000-1104";
        let mut identity = user(USER);
        identity.sid_history_count = 1;
        identity.sid_history = vec![Sid(OLD.into())];
        let result = DefaultPermissionEngine
            .evaluate(base_input(
                identity,
                fso(
                    None,
                    vec![
                        deny_ace(OLD, MASK_WRITE, false),
                        allow_ace(USER, MASK_MODIFY, false),
                    ],
                ),
            ))
            .unwrap();
        assert_eq!(
            result.ntfs_mask.0,
            MASK_MODIFY & !MASK_WRITE,
            "Deny on the historical SID must strip the write bits"
        );
    }

    /// ADR 0056 partial parse: count 2 but only one value parsed → both
    /// markers fire — `SidHistoryEvaluated { count: 1 }` for the token part
    /// and `SidHistoryPresent { count: 1 }` for the un-evaluated remainder;
    /// the result stays incomplete.
    #[test]
    fn engine_partial_sid_history_parse_keeps_incompleteness() {
        const OLD: &str = "S-1-5-21-4000-4000-4000-1104";
        let mut identity = user(USER);
        identity.sid_history_count = 2;
        identity.sid_history = vec![Sid(OLD.into())];
        let result = DefaultPermissionEngine
            .evaluate(base_input(
                identity,
                fso(None, vec![allow_ace(USER, MASK_READ, false)]),
            ))
            .unwrap();
        assert!(
            result
                .diagnostics
                .contains(&PermissionDiagnostic::SidHistoryEvaluated { count: 1 }),
            "evaluated part must be visible; got {:?}",
            result.diagnostics
        );
        assert!(
            result
                .diagnostics
                .contains(&PermissionDiagnostic::SidHistoryPresent { count: 1 }),
            "un-evaluated remainder must stay visible; got {:?}",
            result.diagnostics
        );
        assert!(
            result.is_incomplete(),
            "partial parse must keep the result incomplete"
        );
    }

    /// ADR 0059 acceptance case: the user is a member of group G, G
    /// carries the historical SID S-Gold, and the ACL grants S-Gold
    /// Modify. The engine must grant Modify via the group's historical
    /// SID, mark it GroupSidHistoryEvaluated, name it on the membership
    /// step — and must NOT flag the result incomplete.
    #[test]
    fn engine_grants_access_via_group_historical_sid() {
        const G_OLD: &str = "S-1-5-21-5000-5000-5000-1201";
        let result = eval(
            user(USER),
            vec![membership_with_history(USER, GROUP_A, &[G_OLD])],
            fso(None, vec![allow_ace(G_OLD, MASK_MODIFY, false)]),
            None,
        );
        assert_eq!(
            result.ntfs_mask.0, MASK_MODIFY,
            "ACE on the group's historical SID must grant Modify"
        );
        assert!(
            result
                .diagnostics
                .contains(&PermissionDiagnostic::GroupSidHistoryEvaluated {
                    groups: 1,
                    count: 1
                }),
            "GroupSidHistoryEvaluated must fire; got {:?}",
            result.diagnostics
        );
        assert!(
            !result.is_incomplete(),
            "group-history-evaluated result must not be incomplete; got {:?}",
            result.diagnostics
        );
        assert!(
            result
                .path_explanation
                .steps
                .iter()
                .any(|s| s.contains("Member of")
                    && s.contains("carries historical SID(s) (sIDHistory)")
                    && s.contains(G_OLD)),
            "membership step must name the group's historical SID; got {:?}",
            result.path_explanation.steps
        );
    }

    /// ADR 0059: a Deny ACE on a group's historical SID must be honored.
    #[test]
    fn engine_honors_deny_on_group_historical_sid() {
        const G_OLD: &str = "S-1-5-21-5000-5000-5000-1201";
        let result = eval(
            user(USER),
            vec![membership_with_history(USER, GROUP_A, &[G_OLD])],
            fso(
                None,
                vec![
                    deny_ace(G_OLD, MASK_WRITE, false),
                    allow_ace(USER, MASK_MODIFY, false),
                ],
            ),
            None,
        );
        assert_eq!(
            result.ntfs_mask.0,
            MASK_MODIFY & !MASK_WRITE,
            "Deny on the group's historical SID must strip the write bits"
        );
    }

    /// ADR 0059 partial parse: group count 2 but only one value parsed →
    /// evaluated part informational, remainder keeps incompleteness.
    #[test]
    fn engine_partial_group_sid_history_parse_keeps_incompleteness() {
        const G_OLD: &str = "S-1-5-21-5000-5000-5000-1201";
        let mut gm = membership_with_history(USER, GROUP_A, &[G_OLD]);
        gm.group_sid_history_count = 2;
        let result = eval(
            user(USER),
            vec![gm],
            fso(None, vec![allow_ace(USER, MASK_READ, false)]),
            None,
        );
        assert!(
            result
                .diagnostics
                .contains(&PermissionDiagnostic::GroupSidHistoryEvaluated {
                    groups: 1,
                    count: 1
                }),
            "evaluated part must be visible; got {:?}",
            result.diagnostics
        );
        assert!(
            result
                .diagnostics
                .contains(&PermissionDiagnostic::GroupSidHistoryPresent { count: 1 }),
            "un-evaluated remainder must stay visible; got {:?}",
            result.diagnostics
        );
        assert!(
            result.is_incomplete(),
            "partial group-history parse must keep the result incomplete"
        );
    }

    /// ADR 0059: group history SIDs are part of the token set.
    #[test]
    fn build_token_sids_with_context_includes_group_sid_history() {
        const G_OLD: &str = "S-1-5-21-5000-5000-5000-1201";
        let memberships = vec![membership_with_history(USER, GROUP_A, &[G_OLD])];
        let token = super::build_token_sids_with_context(
            USER,
            &[],
            &memberships,
            &[],
            AccessContext::Unspecified,
        );
        assert!(token.contains(GROUP_A), "group SID must be present");
        assert!(
            token.contains(G_OLD),
            "group's historical SID must be present"
        );
    }

    /// ADR 0052 (L4): an identity resolved via an FSP (a trust boundary)
    /// surfaces the informational TrustBoundaryEffectsNotModeled marker.
    #[test]
    fn engine_pushes_trust_boundary_marker_when_fsp() {
        let mut input = base_input(
            user(USER),
            fso(None, vec![allow_ace(USER, MASK_READ, false)]),
        );
        input.resolution.identity_resolved_via_fsp = true;
        let result = DefaultPermissionEngine.evaluate(input).unwrap();
        assert!(
            result
                .diagnostics
                .contains(&PermissionDiagnostic::TrustBoundaryEffectsNotModeled),
            "trust-boundary marker must fire when resolved via FSP; got {:?}",
            result.diagnostics
        );
    }

    /// ADR 0078: an account of a trusted domain resolved on a DC of that
    /// domain carries the informational marker; the trust caveat only when
    /// the trust uses Selective Authentication (not modelled). The result
    /// stays exact — the marker is no incompleteness trigger.
    #[test]
    fn trusted_domain_account_marker_and_caveat_only_with_selective_auth() {
        for selective in [false, true] {
            let mut input = base_input(
                user(USER),
                fso(None, vec![allow_ace(USER, MASK_READ, false)]),
            );
            input.resolution.trusted_domain = Some(adpa_core::traits::TrustedDomainProvenance {
                domain: "ext.test".into(),
                home_only_groups: vec!["Users (S-1-5-32-545)".into()],
                sid_filtered: Vec::new(),
                selective_authentication: selective,
            });
            let result = DefaultPermissionEngine.evaluate(input).unwrap();
            assert!(result.diagnostics.iter().any(|d| matches!(
                d,
                PermissionDiagnostic::TrustedDomainAccountResolved { domain, .. } if domain == "ext.test"
            )));
            assert_eq!(
                result
                    .diagnostics
                    .contains(&PermissionDiagnostic::TrustBoundaryEffectsNotModeled),
                selective
            );
            assert!(result.effective_determinable(), "informational only");
        }
        // Without the provenance nothing changes.
        let plain = DefaultPermissionEngine
            .evaluate(base_input(
                user(USER),
                fso(None, vec![allow_ace(USER, MASK_READ, false)]),
            ))
            .unwrap();
        assert!(!plain
            .diagnostics
            .iter()
            .any(|d| matches!(d, PermissionDiagnostic::TrustedDomainAccountResolved { .. })));
    }

    /// ADR 0079 (L4), lab 2026-10-17: a refused logon (error 1935) means no
    /// access, exact; the permissions' view stays visible in the path.
    #[test]
    fn selective_authentication_denied_is_exactly_no_access() {
        use adpa_core::traits::SelectiveAuthenticationCheck;
        let mut input = base_input(
            user(USER),
            fso(None, vec![allow_ace(USER, MASK_MODIFY, false)]),
        );
        input.selective_authentication = Some(SelectiveAuthenticationCheck::Denied {
            server: "DC-01".into(),
        });
        let p = DefaultPermissionEngine.evaluate(input).unwrap();
        assert_eq!(p.ntfs_mask.0, MASK_MODIFY, "the DACL view is kept");
        assert_eq!(p.effective_mask.0, 0);
        assert!(
            p.effective_determinable(),
            "exact: Windows refuses the logon"
        );
        assert_eq!(p.effective_upper_bound(), 0, "risk rules see no access");
        assert!(p.diagnostics.iter().any(|d| matches!(
            d,
            PermissionDiagnostic::SelectiveAuthenticationDenied { .. }
        )));
        let last = p.path_explanation.steps.last().unwrap();
        assert!(last.starts_with("Logon refused"), "{last}");
        assert!(last.contains("No access (0x00000000)"));
    }

    /// ADR 0080, lab 2026-10-18 (C:\SyncTest, real token, locally and over
    /// SMB): Allow Modify + Deny "Write" (0x00100116) gives AccessCheck
    /// 0x000300A9 — the value stays, and the marker names the Deny.
    #[test]
    fn a_denied_synchronize_keeps_the_rights_and_names_the_deny() {
        let input = base_input(
            user(USER),
            fso(
                None,
                vec![
                    deny_ace(USER, 0x0010_0116, false),
                    allow_ace(USER, MASK_MODIFY, false),
                ],
            ),
        );
        let p = DefaultPermissionEngine.evaluate(input).unwrap();
        assert_eq!(p.ntfs_mask.0, 0x0003_00A9);
        assert_eq!(p.effective_mask.0, 0x0003_00A9, "the measured rights stay");
        assert!(p.effective_determinable());
        assert!(p
            .diagnostics
            .contains(&PermissionDiagnostic::SynchronizeNotGranted {
                cause: SynchronizeGap::DeniedByNtfsAce,
                certain: true,
            }));
        let last = p.path_explanation.steps.last().unwrap();
        assert!(
            last.starts_with("Note — SYNCHRONIZE is not granted"),
            "{last}"
        );
        assert!(!p.is_incomplete(), "informational only");
        assert!(p
            .synchronize_suffix()
            .is_some_and(|s| s.contains("access denied")));
        // Without the marker no suffix.
        let plain = DefaultPermissionEngine
            .evaluate(base_input(
                user(USER),
                fso(None, vec![allow_ace(USER, MASK_MODIFY, false)]),
            ))
            .unwrap();
        assert!(plain.synchronize_suffix().is_none());
    }

    /// ADR 0081: the graph's limiting side and the explanation step
    /// "Limited by …" follow one rule — checked over many mask pairs.
    #[test]
    fn limiting_side_agrees_with_the_explanation_step() {
        use crate::mask::{limiting_side, LimitingSide};
        let masks = [
            0x0012_0089u32,
            0x0012_00A9,
            0x0013_01BF,
            0x001F_01FF,
            0x0012_0116,
            0x0003_00A9,
            0x0010_0000,
            0x0001_0000,
        ];
        for ntfs in masks {
            for share in masks {
                let mut input =
                    base_input(user(USER), fso(None, vec![allow_ace(USER, ntfs, false)]));
                input.share_status = ShareMaskStatus::Applied(AccessMask(share));
                let p = DefaultPermissionEngine.evaluate(input).unwrap();
                let step = p
                    .path_explanation
                    .steps
                    .iter()
                    .find(|s| s.starts_with("Limited by") || s.starts_with("NTFS and share"))
                    .unwrap_or_else(|| panic!("no limit step for {ntfs:#x}/{share:#x}"));
                let expected = match limiting_side(p.ntfs_mask.0, share) {
                    LimitingSide::Share => "Limited by the share",
                    LimitingSide::Ntfs => "Limited by NTFS",
                    LimitingSide::Neither => "NTFS and share allow the same",
                };
                assert!(
                    step.starts_with(expected),
                    "{ntfs:#x}/{share:#x}: {step} vs {expected}"
                );
            }
        }
    }

    /// No ACE grants SYNCHRONIZE (special permissions without it, lab S3),
    /// and only the share lacks it; with it granted nothing is added.
    #[test]
    fn synchronize_not_granted_by_ntfs_or_share_and_not_when_granted() {
        let p = DefaultPermissionEngine
            .evaluate(base_input(
                user(USER),
                fso(None, vec![allow_ace(USER, 0x0003_00A9, false)]),
            ))
            .unwrap();
        assert_eq!(p.effective_mask.0, 0x0003_00A9);
        assert!(p
            .diagnostics
            .contains(&PermissionDiagnostic::SynchronizeNotGranted {
                cause: SynchronizeGap::NotGrantedByNtfs,
                certain: true,
            }));

        let mut share = base_input(
            user(USER),
            fso(None, vec![allow_ace(USER, MASK_MODIFY, false)]),
        );
        share.share_status = ShareMaskStatus::Applied(AccessMask(0x0002_00A9));
        let p = DefaultPermissionEngine.evaluate(share).unwrap();
        assert_eq!(p.effective_mask.0, 0x0002_00A9);
        assert!(p
            .diagnostics
            .contains(&PermissionDiagnostic::SynchronizeNotGranted {
                cause: SynchronizeGap::NotGrantedByShare,
                certain: true,
            }));

        for dacl in [
            vec![allow_ace(USER, MASK_MODIFY, false)],
            vec![allow_ace(USER, MASK_READ, false)],
            // Only SYNCHRONIZE left: nothing to use, no marker.
            vec![allow_ace(USER, 0x0010_0000, false)],
            vec![],
        ] {
            let p = DefaultPermissionEngine
                .evaluate(base_input(user(USER), fso(None, dacl)))
                .unwrap();
            assert!(!p
                .diagnostics
                .iter()
                .any(|d| matches!(d, PermissionDiagnostic::SynchronizeNotGranted { .. })));
        }
    }

    /// A refused logon (ADR 0079) is No access — no SYNCHRONIZE note then.
    #[test]
    fn no_synchronize_note_when_the_logon_is_refused() {
        use adpa_core::traits::SelectiveAuthenticationCheck;
        let mut input = base_input(
            user(USER),
            fso(
                None,
                vec![
                    deny_ace(USER, 0x0010_0116, false),
                    allow_ace(USER, MASK_MODIFY, false),
                ],
            ),
        );
        input.selective_authentication = Some(SelectiveAuthenticationCheck::Denied {
            server: "DC-01".into(),
        });
        let p = DefaultPermissionEngine.evaluate(input).unwrap();
        assert_eq!(p.effective_mask.0, 0);
        assert!(!p
            .diagnostics
            .iter()
            .any(|d| matches!(d, PermissionDiagnostic::SynchronizeNotGranted { .. })));
    }

    /// Not decidable: NTFS stays exact, the effective right is a range from
    /// No access to the DACL result.
    #[test]
    fn selective_authentication_unknown_opens_only_the_effective_right() {
        use adpa_core::traits::SelectiveAuthenticationCheck;
        let mut input = base_input(
            user(USER),
            fso(None, vec![allow_ace(USER, MASK_MODIFY, false)]),
        );
        input.selective_authentication = Some(SelectiveAuthenticationCheck::Unknown {
            server: "DC-01".into(),
            reason: "the computer object could not be read".into(),
        });
        let p = DefaultPermissionEngine.evaluate(input).unwrap();
        assert!(p.ntfs_determinable());
        assert!(!p.effective_determinable());
        assert_eq!(p.effective_upper_bound(), MASK_MODIFY);
        let last = p.path_explanation.steps.last().unwrap();
        assert!(
            last.starts_with(NOT_DETERMINABLE) && last.contains("logon"),
            "{last}"
        );
    }

    /// ADR 0085 (lab 2026-10-24): a DFS folder with one target is exact and
    /// names the target; with further targets the result is open — NTFS,
    /// share and effective alike — and the explanation says so.
    #[test]
    fn a_dfs_folder_with_further_targets_is_not_determinable() {
        let dfs = |others: Vec<String>, known: bool| adpa_core::model::DfsEvaluation {
            requested: r"\\corp.test\dfs\Projects\Sub".into(),
            target: r"\\FS-01.corp.test\DfsProj\Sub".into(),
            folder: Some(r"\\corp.test\dfs\Projects".into()),
            other_targets: others,
            other_targets_known: known,
        };
        let run = |d: adpa_core::model::DfsEvaluation| {
            let mut input = base_input(
                user(USER),
                fso(None, vec![allow_ace(USER, MASK_MODIFY, false)]),
            );
            input.dfs = Some(d);
            DefaultPermissionEngine.evaluate(input).unwrap()
        };

        let single = run(dfs(Vec::new(), true));
        assert!(single.effective_determinable(), "one target: exact");
        assert_eq!(single.effective_mask.0, MASK_MODIFY);
        assert!(single.diagnostics.iter().any(|d| matches!(
            d,
            PermissionDiagnostic::DfsTargetEvaluated { target, .. } if target.ends_with(r"DfsProj\Sub")
        )));

        for open in [
            run(dfs(vec![r"\\FS-02.corp.test\DfsProj".into()], true)),
            run(dfs(Vec::new(), false)),
        ] {
            assert!(!open.effective_determinable());
            assert!(!open.ntfs_determinable() && !open.share_determinable());
            let steps = &open.path_explanation.steps;
            assert!(
                steps
                    .iter()
                    .any(|s| s.starts_with(NOT_DETERMINABLE) && s.contains("DFS path")),
                "{steps:#?}"
            );
            assert!(
                steps
                    .iter()
                    .any(|s| s.starts_with("NTFS effective: ") && s.contains(NOT_DETERMINABLE)),
                "{steps:#?}"
            );
        }
    }

    /// ADR 0079 addendum: when the permissions grant nothing, "refused" and
    /// "allowed" meet — No access either way, exact; the marker only informs.
    /// With anything else uncertain the DACL result itself is open, and the
    /// logon still matters.
    #[test]
    fn selective_authentication_unknown_with_nothing_granted_is_exactly_no_access() {
        use adpa_core::model::LocalGroupEvalStatus;
        use adpa_core::traits::SelectiveAuthenticationCheck;
        let unknown = || SelectiveAuthenticationCheck::Unknown {
            server: "DC-01".into(),
            reason: "an ACE for S-1-5-4 decides it".into(),
        };
        let other = "S-1-5-21-9-9-9-1500";
        let marker_affects = |p: &EffectivePermission| {
            p.diagnostics.iter().find_map(|d| match d {
                PermissionDiagnostic::SelectiveAuthenticationUnknown { affects_result, .. } => {
                    Some(*affects_result)
                }
                _ => None,
            })
        };

        // No ACE reaches the account: the DACL result is exactly No access.
        let mut input = base_input(
            user(USER),
            fso(None, vec![allow_ace(other, MASK_MODIFY, false)]),
        );
        input.selective_authentication = Some(unknown());
        let p = DefaultPermissionEngine.evaluate(input).unwrap();
        assert_eq!(p.effective_mask.0, 0);
        assert!(p.effective_determinable(), "No access either way");
        assert!(!p.is_incomplete());
        assert_eq!(p.effective_upper_bound(), 0);
        assert_eq!(marker_affects(&p), Some(false));
        let last = p.path_explanation.steps.last().unwrap();
        assert!(last.starts_with("Logon not determinable — "), "{last}");
        assert!(last.contains("No access either way"), "{last}");
        assert!(
            last.ends_with("Effective: No access (0x00000000)."),
            "{last}"
        );
        assert!(
            !p.path_explanation
                .steps
                .iter()
                .any(|s| s.contains(NOT_DETERMINABLE)),
            "{:?}",
            p.path_explanation.steps
        );

        // Nothing granted, but the local groups of the server unknown: an ACE
        // for one of them could grant — the range stays open.
        let mut input = base_input(
            user(USER),
            fso(None, vec![allow_ace(other, MASK_MODIFY, false)]),
        );
        input.selective_authentication = Some(unknown());
        input.local_group_status = LocalGroupEvalStatus::NotAvailable("no access".into());
        let p = DefaultPermissionEngine.evaluate(input).unwrap();
        assert_eq!(p.effective_mask.0, 0);
        assert!(!p.effective_determinable());
        assert_eq!(marker_affects(&p), Some(true));
        assert!(p
            .uncertainty()
            .iter()
            .any(|u| u.layer == UncertainLayer::Logon));

        // Rights granted: the logon decides between them and No access.
        let mut input = base_input(
            user(USER),
            fso(None, vec![allow_ace(USER, MASK_MODIFY, false)]),
        );
        input.selective_authentication = Some(unknown());
        let p = DefaultPermissionEngine.evaluate(input).unwrap();
        assert!(!p.effective_determinable());
        assert_eq!(marker_affects(&p), Some(true));
    }

    /// Allowed: the result is the DACL result; with the check done, the
    /// "not modelled" trust caveat is gone (it stays without a check).
    #[test]
    fn selective_authentication_allowed_keeps_the_result_and_drops_the_caveat() {
        use adpa_core::traits::{SelectiveAuthenticationCheck, TrustedDomainProvenance};
        let trusted = TrustedDomainProvenance {
            domain: "ext.test".into(),
            home_only_groups: Vec::new(),
            sid_filtered: Vec::new(),
            selective_authentication: true,
        };
        let mut input = base_input(
            user(USER),
            fso(None, vec![allow_ace(USER, MASK_MODIFY, false)]),
        );
        input.resolution.trusted_domain = Some(trusted.clone());
        input.selective_authentication = Some(SelectiveAuthenticationCheck::Allowed {
            server: "DC-01".into(),
            via: "GG_ExtPartners (S-1-5-21-1-2-3-1110)".into(),
        });
        let p = DefaultPermissionEngine.evaluate(input).unwrap();
        assert_eq!(p.effective_mask.0, MASK_MODIFY);
        assert!(p.effective_determinable());
        assert!(!p
            .diagnostics
            .contains(&PermissionDiagnostic::TrustBoundaryEffectsNotModeled));
        assert!(p
            .path_explanation
            .steps
            .last()
            .unwrap()
            .starts_with("Logon allowed"));

        let mut unchecked = base_input(
            user(USER),
            fso(None, vec![allow_ace(USER, MASK_MODIFY, false)]),
        );
        unchecked.resolution.trusted_domain = Some(trusted);
        let q = DefaultPermissionEngine.evaluate(unchecked).unwrap();
        assert!(q
            .diagnostics
            .contains(&PermissionDiagnostic::TrustBoundaryEffectsNotModeled));
    }

    /// The trust-boundary marker also fires when the identity is outside the
    /// configured LDAP base (the other boundary signal).
    #[test]
    fn engine_pushes_trust_boundary_marker_when_outside_base() {
        let mut input = base_input(
            user(USER),
            fso(None, vec![allow_ace(USER, MASK_READ, false)]),
        );
        input.resolution.identity_not_in_configured_ldap_base = true;
        let result = DefaultPermissionEngine.evaluate(input).unwrap();
        assert!(
            result
                .diagnostics
                .contains(&PermissionDiagnostic::TrustBoundaryEffectsNotModeled),
            "trust-boundary marker must fire when outside the configured LDAP base; got {:?}",
            result.diagnostics
        );
    }

    /// A plain in-domain identity gets no trust-boundary marker.
    #[test]
    fn engine_no_trust_boundary_marker_for_plain_identity() {
        let result = DefaultPermissionEngine
            .evaluate(base_input(
                user(USER),
                fso(None, vec![allow_ace(USER, MASK_READ, false)]),
            ))
            .unwrap();
        assert!(
            !result
                .diagnostics
                .contains(&PermissionDiagnostic::TrustBoundaryEffectsNotModeled),
            "no trust-boundary marker for a plain in-domain identity; got {:?}",
            result.diagnostics
        );
    }

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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance {
                    identity_lookup_failure_reason: Some(
                        "LDAP bind failed: connection refused".to_owned(),
                    ),
                    ..Default::default()
                },
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance {
                    group_resolution_failure_reason: Some(
                        "LDAP group query timed out after 30s".to_owned(),
                    ),
                    ..Default::default()
                },
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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

    /// ADR 0066: each gap of the group resolution becomes a marker and
    /// makes the result not determinable.
    #[test]
    fn engine_turns_group_resolution_gaps_into_markers() {
        let result = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![],
                file_system_object: fso(None, vec![allow_ace(USER, MASK_READ, false)]),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance {
                    group_resolution_gaps: vec!["gap one".into(), "gap two".into()],
                    ..Default::default()
                },
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
            })
            .unwrap();
        let reasons: Vec<&str> = result
            .diagnostics
            .iter()
            .filter_map(|d| match d {
                PermissionDiagnostic::GroupResolutionIncomplete { reason } => Some(reason.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(reasons, ["gap one", "gap two"]);
        assert!(!result.effective_determinable());
    }

    /// ADR 0064 (lab finding AD3-1): an unresolvable SID makes the result
    /// incomplete; an orphaned SID gets the informational marker only.
    #[test]
    fn engine_marks_unresolvable_identity_incomplete_and_orphaned_informational() {
        let eval_with = |identity: Identity, provenance: ResolutionProvenance| {
            DefaultPermissionEngine
                .evaluate(PermissionEvaluationInput {
                    identity,
                    group_memberships: vec![],
                    file_system_object: fso(None, vec![allow_ace(USER, MASK_READ, false)]),
                    share_status: ShareMaskStatus::NotApplicable,
                    local_group_sids: vec![],
                    local_group_status: adpa_core::model::LocalGroupEvalStatus::NotQueried,
                    logon_dependent_group_sids: Vec::new(),
                    uac_filtered_group_sids: Vec::new(),
                    remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                    anonymous_everyone: None,
                    access_context: AccessContext::Unspecified,
                    unsupported_share_ace_count: 0,
                    sid_names: std::collections::BTreeMap::new(),
                    resolution: provenance,
                    share_trace: Default::default(),
                    selective_authentication: Default::default(),
                    dfs: None,
                })
                .unwrap()
        };
        let unresolvable = eval_with(
            Identity {
                kind: IdentityKind::Unknown,
                ..user(USER)
            },
            ResolutionProvenance {
                identity_unresolvable_reason: Some("belongs to the trusted domain ext.test".into()),
                ..Default::default()
            },
        );
        assert!(unresolvable.diagnostics.iter().any(|d| matches!(
            d,
            PermissionDiagnostic::IdentityNotResolvable { reason } if reason.contains("ext.test")
        )));
        assert!(unresolvable.is_incomplete());

        let orphaned = eval_with(
            Identity {
                kind: IdentityKind::Orphaned,
                ..user(USER)
            },
            ResolutionProvenance::default(),
        );
        assert!(orphaned
            .diagnostics
            .contains(&PermissionDiagnostic::IdentityOrphaned));
        assert!(
            !orphaned.is_incomplete(),
            "orphaned SID: evaluation is exact"
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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance {
                    identity_resolved_via_fsp: true,
                    ..Default::default()
                },
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance {
                    group_resolution_via_global_catalog: true,
                    ..Default::default()
                },
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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
                also_via: Vec::new(),
            }),
            group_sid_history_count: 0,
            group_sid_history: Vec::new(),
        };

        let result = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![membership(USER, GROUP_A), local_membership],
                file_system_object: fso(None, vec![allow_ace(BUILTIN_ADMINS, MASK_MODIFY, false)]),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: vec![Sid(BUILTIN_ADMINS.to_owned())],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::Applied,
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names,
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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
                also_via: Vec::new(),
            }),
            group_sid_history_count: 0,
            group_sid_history: Vec::new(),
        };

        let result = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![local_membership],
                file_system_object: fso(None, vec![allow_ace(BUILTIN_ADMINS, MASK_READ, false)]),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: vec![Sid(BUILTIN_ADMINS.to_owned())],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::Applied,
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::Unspecified,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                // Key setting: local-looking input, explicit RemoteSmb —
                // mirrors what CLI/GUI now produce via for_path_with_smb
                // when --smb-server / --share-name is provided.
                access_context: AccessContext::RemoteSmb,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
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
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::LocalInteractive,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
            })
            .unwrap();
        assert_eq!(
            result.effective_mask.0, 0,
            "NETWORK Allow must NOT take effect under LocalInteractive (got 0x{:08X})",
            result.effective_mask.0
        );
    }

    // --- ADR 0068: local groups expanded by SID like a logon does ---

    const LG_DIRECT: &str = "S-1-5-21-7-7-7-1003";
    const LG_DOMGRP: &str = "S-1-5-21-7-7-7-1004";
    const LG_AUTH: &str = "S-1-5-21-7-7-7-1005";
    const LG_INTER: &str = "S-1-5-21-7-7-7-1006";
    const LG_EVERY: &str = "S-1-5-21-7-7-7-1007";
    const LG_ORG: &str = "S-1-5-21-7-7-7-1008";
    const LG_OTHER: &str = "S-1-5-21-7-7-7-1009";

    fn local_group(sid: &str, name: &str, members: &[&str]) -> LocalGroupDescriptor {
        LocalGroupDescriptor {
            sid: Sid(sid.into()),
            name: name.into(),
            members: members.iter().map(|m| Sid((*m).into())).collect(),
        }
    }

    /// The MS-01 lab fixture in miniature: a local group per entry route.
    fn ms01_groups() -> Vec<LocalGroupDescriptor> {
        vec![
            local_group(LG_DIRECT, "msg_direct", &[USER]),
            local_group(LG_DOMGRP, "msg_domgrp", &[GROUP_B]),
            local_group(LG_AUTH, "msg_auth", &["S-1-5-11"]),
            local_group(LG_INTER, "msg_inter", &[SID_INTERACTIVE]),
            local_group(LG_EVERY, "msg_every", &["S-1-1-0"]),
            local_group(LG_ORG, "msg_org", &[THIS_ORGANIZATION]),
            local_group(LG_OTHER, "msg_other", &[OTHER]),
        ]
    }

    fn certain_names(e: &LocalGroupExpansion) -> Vec<String> {
        e.certain.iter().map(|g| g.name.clone()).collect()
    }

    fn uncertain_names(e: &LocalGroupExpansion) -> Vec<String> {
        e.logon_dependent.iter().map(|g| g.name.clone()).collect()
    }

    /// Lab finding MS-1: `NetUserGetLocalGroups` missed the groups entered
    /// through a nested domain group, `Authenticated Users` and `Everyone`.
    /// The expansion finds every one of them; GROUP_B stands for a group the
    /// account reaches only through nesting (it is in the resolved set).
    #[test]
    fn local_groups_are_entered_through_every_token_sid() {
        let memberships = vec![membership(USER, GROUP_A), membership(USER, GROUP_B)];
        let e = expand_local_groups(
            USER,
            &[],
            &memberships,
            &ms01_groups(),
            AccessContext::RemoteSmb,
        );
        assert_eq!(
            certain_names(&e),
            vec!["msg_auth", "msg_direct", "msg_domgrp", "msg_every"]
        );
        // Over SMB the logon is a network logon: INTERACTIVE is not in the
        // token, so msg_inter is no membership at all — not even uncertain.
        assert_eq!(uncertain_names(&e), vec!["msg_org"]);
        let direct = &e.certain[1];
        assert_eq!(direct.via, vec![Sid(USER.into())]);
        let domgrp = &e.certain[2];
        assert_eq!(domgrp.via, vec![Sid(GROUP_B.into())]);
    }

    #[test]
    fn interactive_member_depends_on_the_access_context() {
        let groups = ms01_groups();
        let local = expand_local_groups(USER, &[], &[], &groups, AccessContext::LocalInteractive);
        assert!(certain_names(&local).contains(&"msg_inter".to_string()));
        let unspecified = expand_local_groups(USER, &[], &[], &groups, AccessContext::Unspecified);
        assert!(!certain_names(&unspecified).contains(&"msg_inter".to_string()));
        assert!(uncertain_names(&unspecified).contains(&"msg_inter".to_string()));
        let smb = expand_local_groups(USER, &[], &[], &groups, AccessContext::RemoteSmb);
        assert!(!certain_names(&smb).contains(&"msg_inter".to_string()));
        assert!(!uncertain_names(&smb).contains(&"msg_inter".to_string()));
    }

    #[test]
    fn sid_history_and_group_sid_history_enter_local_groups() {
        let old_user = "S-1-5-21-5-5-5-1001";
        let old_group = "S-1-5-21-5-5-5-1100";
        let groups = vec![
            local_group(LG_DIRECT, "via_old_user", &[old_user]),
            local_group(LG_DOMGRP, "via_old_group", &[old_group]),
        ];
        let e = expand_local_groups(
            USER,
            &[Sid(old_user.into())],
            &[membership_with_history(USER, GROUP_A, &[old_group])],
            &groups,
            AccessContext::RemoteSmb,
        );
        assert_eq!(certain_names(&e), vec!["via_old_group", "via_old_user"]);
    }

    #[test]
    fn a_certain_route_wins_over_a_logon_dependent_one() {
        let groups = vec![local_group(LG_DIRECT, "both", &[THIS_ORGANIZATION, USER])];
        let e = expand_local_groups(USER, &[], &[], &groups, AccessContext::RemoteSmb);
        assert_eq!(certain_names(&e), vec!["both"]);
        assert!(e.logon_dependent.is_empty());
        assert_eq!(e.certain[0].via, vec![Sid(USER.into())]);
    }

    #[test]
    fn expansion_is_independent_of_server_order() {
        let memberships = vec![membership(USER, GROUP_A), membership(USER, GROUP_B)];
        let mut groups = ms01_groups();
        groups.push(local_group(
            "S-1-5-32-545",
            "Users",
            &["S-1-5-11", GROUP_A, USER, SID_INTERACTIVE],
        ));
        let a = expand_local_groups(USER, &[], &memberships, &groups, AccessContext::RemoteSmb);
        groups.reverse();
        for g in &mut groups {
            g.members.reverse();
        }
        let b = expand_local_groups(USER, &[], &memberships, &groups, AccessContext::RemoteSmb);
        assert_eq!(a, b);
        let users = a.certain.iter().find(|g| g.name == "Users").unwrap();
        // The account's own SID first, then by SID.
        assert_eq!(
            users.via,
            vec![
                Sid(USER.into()),
                Sid("S-1-5-11".into()),
                Sid(GROUP_A.into())
            ]
        );
    }

    #[test]
    fn no_member_in_the_token_is_no_membership() {
        let groups = vec![
            local_group(LG_OTHER, "other", &[OTHER]),
            local_group(LG_DIRECT, "empty", &[]),
        ];
        let e = expand_local_groups(USER, &[], &[], &groups, AccessContext::RemoteSmb);
        assert!(e.certain.is_empty() && e.logon_dependent.is_empty());
    }

    /// An ACE for a local group the account is in only through a
    /// logon-dependent SID bounds the result instead of being ignored.
    #[test]
    fn ace_for_a_logon_dependent_local_group_bounds_the_result() {
        let p = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![],
                file_system_object: fso(
                    None,
                    vec![
                        allow_ace(LG_ORG, MASK_MODIFY, false),
                        allow_ace(USER, MASK_READ, false),
                    ],
                ),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::Applied,
                logon_dependent_group_sids: vec![Sid(LG_ORG.into())],
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::RemoteSmb,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
            })
            .unwrap();
        let (sids, min, max) = logon_marker(&p).expect("bounded");
        assert_eq!(sids, vec![LG_ORG.to_string()]);
        assert_eq!(min, expand_generic_rights(MASK_READ));
        assert_eq!(max, expand_generic_rights(MASK_MODIFY | MASK_READ));
        assert!(!p.effective_determinable());
    }

    // --- ADR 0070: UAC-filtered groups of a local account ---

    const ADMINS: &str = "S-1-5-32-544";

    fn eval_uac(dacl: Vec<AceEntry>, owner: Option<&str>) -> EffectivePermission {
        DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                // The membership arrives through the local-group list too;
                // the engine must still treat it as deny-only.
                group_memberships: vec![membership(USER, ADMINS)],
                file_system_object: fso(owner, dacl),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: vec![Sid(ADMINS.into())],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::Applied,
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: vec![Sid(ADMINS.into())],
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::RemoteSmb,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
            })
            .unwrap()
    }

    /// Lab (MS-01): a local admin's Administrators group is filtered over
    /// SMB by default, not with LocalAccountTokenFilterPolicy = 1. The shown
    /// value is the filtered token, the upper bound the unfiltered one.
    #[test]
    fn allow_for_a_uac_filtered_group_bounds_the_result() {
        let p = eval_uac(
            vec![
                allow_ace(ADMINS, MASK_FULL_CONTROL, false),
                allow_ace(USER, MASK_READ, false),
            ],
            None,
        );
        assert_eq!(p.ntfs_mask.0, expand_generic_rights(MASK_READ));
        let (sids, min, max) = logon_marker(&p).expect("bounded");
        assert_eq!(sids, vec![ADMINS.to_string()]);
        assert_eq!(min, expand_generic_rights(MASK_READ));
        assert_eq!(max, MASK_FULL_CONTROL);
        assert!(!p.effective_determinable());
        assert!(p
            .diagnostics
            .iter()
            .any(|d| matches!(d, PermissionDiagnostic::UacFilteredGroups { groups } if groups.iter().any(|g| g.contains(ADMINS)))));
    }

    /// A filtered group is deny-only: its Deny ACE applies either way, so
    /// the result stays exact.
    #[test]
    fn deny_for_a_uac_filtered_group_always_applies() {
        let p = eval_uac(
            vec![
                deny_ace(ADMINS, MASK_WRITE, false),
                allow_ace(USER, MASK_MODIFY, false),
            ],
            None,
        );
        let expected = expand_generic_rights(MASK_MODIFY) & !expand_generic_rights(MASK_WRITE);
        assert_eq!(p.ntfs_mask.0, expected);
        assert!(logon_marker(&p).is_none(), "nothing uncertain");
        assert!(p.effective_determinable());
    }

    /// Owner = a filtered group: the implicit owner grant applies only to
    /// the unfiltered token — upper bound only.
    #[test]
    fn filtered_owner_group_bounds_the_implicit_owner_grant() {
        let p = eval_uac(vec![allow_ace(USER, MASK_READ, false)], Some(ADMINS));
        let read = expand_generic_rights(MASK_READ);
        assert_eq!(p.ntfs_mask.0, read, "filtered token: no owner grant");
        let (sids, min, max) = logon_marker(&p).expect("bounded by the owner grant");
        assert_eq!(sids, vec![ADMINS.to_string()]);
        assert_eq!(min, read);
        assert_eq!(max, read | FILE_READ_CONTROL | FILE_WRITE_DAC);
    }

    fn sids(list: &[&str]) -> Vec<Sid> {
        list.iter().map(|s| Sid((*s).into())).collect()
    }

    /// Lab (ADR 0070): a local account's filtered groups, plus S-1-5-114
    /// with Administrators — in every context, over SMB too.
    #[test]
    fn uac_filtered_groups_of_a_local_account() {
        let groups = sids(&[
            "S-1-5-32-545",
            ADMINS,
            "S-1-5-32-551",
            "S-1-5-21-7-7-7-1003",
        ]);
        for ctx in [
            AccessContext::RemoteSmb,
            AccessContext::LocalInteractive,
            AccessContext::Unspecified,
        ] {
            assert_eq!(
                uac_filtered_groups(&groups, true, ctx),
                // Sorted by SID string — deterministic.
                sids(&["S-1-5-114", ADMINS, "S-1-5-32-551"]),
                "{ctx:?}"
            );
        }
        // Not in Administrators: no S-1-5-114.
        assert_eq!(
            uac_filtered_groups(&sids(&["S-1-5-32-551"]), true, AccessContext::RemoteSmb),
            sids(&["S-1-5-32-551"])
        );
    }

    /// Lab (ADR 0071): a domain account keeps its groups over the network,
    /// but its filtered domain and builtin groups are deny-only in a local
    /// session that is not elevated; Key Admins and DnsAdmins are not.
    #[test]
    fn uac_filtered_groups_of_a_domain_account_depend_on_the_context() {
        let d = "S-1-5-21-1025961329-1437379190-2506159458";
        let groups = sids(&[
            &format!("{d}-512"),
            &format!("{d}-513"),
            &format!("{d}-519"),
            &format!("{d}-526"),
            &format!("{d}-1101"),
            ADMINS,
            "S-1-5-32-545",
            "S-1-5-32-554",
        ]);
        assert!(uac_filtered_groups(&groups, false, AccessContext::RemoteSmb).is_empty());
        let expected = sids(&[
            &format!("{d}-512"),
            &format!("{d}-519"),
            ADMINS,
            "S-1-5-32-554",
        ]);
        assert_eq!(
            uac_filtered_groups(&groups, false, AccessContext::LocalInteractive),
            expected
        );
        assert_eq!(
            uac_filtered_groups(&groups, false, AccessContext::Unspecified),
            expected
        );
    }

    #[test]
    fn domain_group_rids_are_matched_only_on_domain_sids() {
        assert!(is_uac_filtered_group("S-1-5-21-1-2-3-512"));
        assert!(is_uac_filtered_group("S-1-5-21-1-2-3-518"));
        assert!(!is_uac_filtered_group("S-1-5-21-1-2-3-526"));
        assert!(!is_uac_filtered_group("S-1-5-21-1-2-3-513"));
        // A RID 512 under a different authority shape is not a domain group.
        assert!(!is_uac_filtered_group("S-1-5-21-1-2-512"));
        assert!(!is_uac_filtered_group("S-1-5-21-1-2-3-4-512"));
        assert!(!is_uac_filtered_group("S-1-5-32-545"));
        assert!(is_uac_filtered_group("S-1-5-32-554"));
    }

    /// Lab (ADR 0071): Cryptographic Operators is absent from the token —
    /// over the network too — when the account is also in another filtered
    /// group. A membership from any source is real, but the token entry is
    /// never certain: its ACEs bound the result.
    #[test]
    fn cryptographic_operators_in_the_token_is_never_certain() {
        let p = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![membership(USER, SID_CRYPTOGRAPHIC_OPERATORS)],
                file_system_object: fso(
                    None,
                    vec![allow_ace(SID_CRYPTOGRAPHIC_OPERATORS, MASK_MODIFY, false)],
                ),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: vec![],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::Applied,
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: Vec::new(),
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::RemoteSmb,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
            })
            .unwrap();
        assert_eq!(p.ntfs_mask.0, 0);
        let (sids, min, max) = logon_marker(&p).expect("bounded");
        assert_eq!(sids, vec![SID_CRYPTOGRAPHIC_OPERATORS.to_string()]);
        assert_eq!((min, max), (0, expand_generic_rights(MASK_MODIFY)));
        // The membership itself stays visible in the local-group expansion.
        let groups = vec![local_group(SID_CRYPTOGRAPHIC_OPERATORS, "Crypto", &[USER])];
        let e = expand_local_groups(USER, &[], &[], &groups, AccessContext::RemoteSmb);
        assert_eq!(certain_names(&e), vec!["Crypto"]);
    }

    // --- Review CR-8 / ADR 0072: Guest and anonymous tokens ---

    const GUEST: &str = "S-1-5-21-1000-1000-1000-501";

    #[test]
    fn guest_account_is_recognised_only_as_rid_501_of_an_account_domain() {
        assert!(is_guest_account(GUEST));
        assert!(is_guest_account(
            "S-1-5-21-1948694518-2669005538-3518942002-501"
        ));
        assert!(!is_guest_account("S-1-5-21-1000-1000-1000-500"));
        assert!(!is_guest_account("S-1-5-21-1000-1000-501"));
        assert!(!is_guest_account("S-1-5-21-1000-1000-1000-1501"));
        assert!(!is_guest_account("S-1-5-32-546"));
    }

    #[test]
    fn guest_and_anonymous_tokens_leave_out_the_documented_well_knowns() {
        let guest = build_token_sids(GUEST, &[]);
        assert!(guest.contains(SID_EVERYONE));
        assert!(!guest.contains(SID_AUTHENTICATED_USERS));
        let anonymous = build_token_sids(SID_ANONYMOUS_LOGON, &[]);
        assert!(!anonymous.contains(SID_EVERYONE));
        assert!(!anonymous.contains(SID_AUTHENTICATED_USERS));
        let normal = build_token_sids(USER, &[]);
        assert!(normal.contains(SID_EVERYONE) && normal.contains(SID_AUTHENTICATED_USERS));
    }

    /// Guest (measured): Authenticated Users is certainly not in the token —
    /// its ACE does not apply, the result is exact.
    #[test]
    fn authenticated_users_ace_never_applies_to_a_guest() {
        let p = eval_with_context(
            user(GUEST),
            vec![],
            fso(
                None,
                vec![
                    allow_ace(SID_AUTHENTICATED_USERS, MASK_MODIFY, false),
                    allow_ace(SID_EVERYONE, MASK_READ, false),
                ],
            ),
            None,
            AccessContext::RemoteSmb,
        );
        assert_eq!(p.ntfs_mask.0, expand_generic_rights(MASK_READ));
        assert!(logon_marker(&p).is_none(), "exact, no range");
        assert!(p.effective_determinable());
        assert!(p.diagnostics.iter().any(|d| matches!(
            d,
            PermissionDiagnostic::GuestOrAnonymousToken { sids } if sids == &vec![SID_AUTHENTICATED_USERS.to_string()]
        )));
    }

    /// Every other account keeps Authenticated Users as a certain group.
    #[test]
    fn authenticated_users_ace_is_exact_for_a_normal_account() {
        let p = eval_with_context(
            user(USER),
            vec![],
            fso(
                None,
                vec![allow_ace(SID_AUTHENTICATED_USERS, MASK_MODIFY, false)],
            ),
            None,
            AccessContext::RemoteSmb,
        );
        assert_eq!(p.ntfs_mask.0, expand_generic_rights(MASK_MODIFY));
        assert!(logon_marker(&p).is_none());
        assert!(!p
            .diagnostics
            .iter()
            .any(|d| matches!(d, PermissionDiagnostic::GuestOrAnonymousToken { .. })));
    }

    /// Anonymous: an Everyone ACE is uncertain as well.
    #[test]
    fn everyone_ace_bounds_an_anonymous_result() {
        let p = eval_with_context(
            user(SID_ANONYMOUS_LOGON),
            vec![],
            fso(None, vec![allow_ace(SID_EVERYONE, MASK_READ, false)]),
            None,
            AccessContext::RemoteSmb,
        );
        assert_eq!(p.ntfs_mask.0, 0);
        let (sids, min, max) = logon_marker(&p).expect("bounded");
        assert_eq!(sids, vec![SID_EVERYONE.to_string()]);
        assert_eq!((min, max), (0, expand_generic_rights(MASK_READ)));
    }

    /// A local group a Guest could reach only through Authenticated Users is
    /// not a membership (measured: a Guest network token has no Users).
    #[test]
    fn local_group_through_authenticated_users_is_no_membership_for_a_guest() {
        let groups = vec![local_group(
            "S-1-5-32-545",
            "Users",
            &[SID_AUTHENTICATED_USERS],
        )];
        let e = expand_local_groups(GUEST, &[], &[], &groups, AccessContext::RemoteSmb);
        assert!(e.certain.is_empty());
        assert!(uncertain_names(&e).is_empty());
        let normal = expand_local_groups(USER, &[], &[], &groups, AccessContext::RemoteSmb);
        assert_eq!(certain_names(&normal), vec!["Users"]);
    }

    // --- Review CR-5: the explanation path never states an undeterminable
    // value as a fact ---

    fn step<'a>(p: &'a EffectivePermission, prefix: &str) -> Option<&'a str> {
        p.path_explanation
            .steps
            .iter()
            .find(|s| s.starts_with(prefix))
            .map(String::as_str)
    }

    /// The invariant behind CR-5: every value step of the path says
    /// NOT DETERMINABLE exactly when the result line does.
    fn assert_path_agrees_with_result(p: &EffectivePermission) {
        let ntfs = step(p, "NTFS effective: ").expect("NTFS step");
        assert_eq!(
            ntfs.contains(NOT_DETERMINABLE),
            !p.ntfs_determinable(),
            "NTFS step vs result: {:?}",
            p.path_explanation.steps
        );
        if let Some(share) = step(p, "Share permission: ") {
            assert_eq!(
                share.contains(NOT_DETERMINABLE),
                !p.share_determinable(),
                "share step vs result: {:?}",
                p.path_explanation.steps
            );
        }
        match step(p, "Effective (NTFS \u{2229} Share): ") {
            Some(effective) => assert_eq!(
                effective.contains(NOT_DETERMINABLE),
                !p.effective_determinable(),
                "effective step vs result: {:?}",
                p.path_explanation.steps
            ),
            // Without an applied share the NTFS step is the final value; a
            // share-side reason must then still be visible in the path.
            None => {
                if !p.effective_determinable() && p.ntfs_determinable() {
                    assert!(
                        p.path_explanation
                            .steps
                            .iter()
                            .any(|s| s.contains(NOT_DETERMINABLE)),
                        "share-side reason missing: {:?}",
                        p.path_explanation.steps
                    );
                }
            }
        }
        // An exact result never carries the marker anywhere in its path.
        if p.effective_determinable() {
            assert!(
                !p.path_explanation
                    .steps
                    .iter()
                    .any(|s| s.contains(NOT_DETERMINABLE)),
                "exact result with marker: {:?}",
                p.path_explanation.steps
            );
        }
    }

    fn cr5_dacl() -> FileSystemObject {
        fso(None, vec![allow_ace(USER, MASK_MODIFY, false)])
    }

    /// Exact values keep their established wording, as facts.
    #[test]
    fn explanation_states_exact_values_as_facts() {
        let p = eval(user(USER), vec![], cr5_dacl(), Some(AccessMask(MASK_READ)));
        let modify = expand_generic_rights(MASK_MODIFY);
        assert_eq!(
            step(&p, "NTFS effective: "),
            Some(format!("NTFS effective: Modify (0x{modify:08X})").as_str())
        );
        assert!(
            step(&p, "Share permission: ").is_some_and(|s| s.starts_with("Share permission: Read"))
        );
        assert!(step(&p, "Effective (NTFS \u{2229} Share): ")
            .is_some_and(|s| !s.contains(NOT_DETERMINABLE)));
        assert_path_agrees_with_result(&p);
    }

    /// A token gap: the reason is stated at the token, and NTFS, share and
    /// effective are all NOT DETERMINABLE — the CSV / HTML / GUI path no
    /// longer contradicts the result line.
    #[test]
    fn explanation_states_a_token_gap_and_no_value_as_fact() {
        let mut input = base_input(user(USER), cr5_dacl());
        input.share_status = ShareMaskStatus::Applied(AccessMask(MASK_READ));
        input.resolution.group_resolution_gaps = vec!["gap one".into()];
        let p = DefaultPermissionEngine.evaluate(input).unwrap();
        let token = step(&p, NOT_DETERMINABLE).expect("token reason step");
        assert!(token.contains("token above may be incomplete") && token.contains("gap one"));
        assert!(step(&p, "NTFS effective: ").is_some_and(|s| s.contains(NOT_DETERMINABLE)));
        assert!(step(&p, "Share permission: ").is_some_and(|s| s.contains(NOT_DETERMINABLE)));
        assert!(step(&p, "Effective (NTFS \u{2229} Share): ")
            .is_some_and(|s| s.contains(NOT_DETERMINABLE)));
        // The token reason precedes the ACE and value steps.
        let pos = |prefix: &str| {
            p.path_explanation
                .steps
                .iter()
                .position(|s| s.starts_with(prefix))
                .unwrap()
        };
        assert!(pos(NOT_DETERMINABLE) < pos("NTFS effective: "));
        assert_path_agrees_with_result(&p);
    }

    /// Only the share side uncertain: NTFS stays a fact, share and effective
    /// do not, and the share reason is named.
    #[test]
    fn explanation_marks_only_the_share_side_when_only_share_aces_are_uncertain() {
        let mut input = base_input(user(USER), cr5_dacl());
        input.share_status = ShareMaskStatus::Applied(AccessMask(MASK_READ));
        input.unsupported_share_ace_count = 1;
        let p = DefaultPermissionEngine.evaluate(input).unwrap();
        assert!(step(&p, "NTFS effective: ").is_some_and(|s| !s.contains(NOT_DETERMINABLE)));
        assert!(step(&p, "Share permission: ").is_some_and(|s| s.contains(NOT_DETERMINABLE)));
        assert!(step(&p, &format!("{NOT_DETERMINABLE} — share: ")).is_some());
        assert!(step(&p, "Effective (NTFS \u{2229} Share): ")
            .is_some_and(|s| s.contains(NOT_DETERMINABLE)));
        assert_path_agrees_with_result(&p);
    }

    /// A failed share read says the share value is not determinable and
    /// that the share can only restrict, never extend, the NTFS right.
    #[test]
    fn explanation_of_a_failed_share_read_states_the_only_safe_bound() {
        let p = eval_with_share(
            user(USER),
            cr5_dacl(),
            ShareMaskStatus::ReadFailed("access denied".to_owned()),
        );
        let s = step(&p, "Share permissions not determinable").expect("read-failed step");
        assert!(s.contains(NOT_DETERMINABLE) && s.contains("never extend"));
        assert_path_agrees_with_result(&p);
    }

    /// The invariant over every kind of uncertainty the engine produces.
    #[test]
    fn explanation_and_result_lines_agree_on_determinability_in_every_case() {
        use adpa_core::model::{LocalGroupEvalStatus, UnsupportedAce};
        let shares = [
            ShareMaskStatus::NotApplicable,
            ShareMaskStatus::Applied(AccessMask(MASK_READ)),
            ShareMaskStatus::Unrestricted,
            ShareMaskStatus::ReadFailed("access denied".to_owned()),
        ];
        type Mutate = fn(&mut PermissionEvaluationInput);
        let cases: [(&str, Mutate); 9] = [
            ("exact", |_| {}),
            ("group gap", |i| {
                i.resolution.group_resolution_gaps = vec!["gap".into()]
            }),
            ("local groups unavailable", |i| {
                i.local_group_status = LocalGroupEvalStatus::NotAvailable("RPC failed".into())
            }),
            ("unsupported NTFS ACE", |i| {
                i.file_system_object.unsupported_aces = vec![UnsupportedAce {
                    ace_type: 9,
                    flags: 0,
                    mask: 0x001F_01FF,
                }]
            }),
            ("logon-dependent ACE", |i| {
                i.file_system_object
                    .dacl
                    .push(allow_ace("S-1-5-1000", MASK_FULL_CONTROL, false));
                i.access_context = AccessContext::RemoteSmb;
            }),
            ("unsupported share ACE", |i| {
                i.unsupported_share_ace_count = 1
            }),
            ("global catalog", |i| {
                i.resolution.group_resolution_via_global_catalog = true
            }),
            // ADR 0072: Everyone is uncertain for an anonymous logon.
            ("anonymous", |i| {
                i.identity = user(SID_ANONYMOUS_LOGON);
                i.file_system_object
                    .dacl
                    .push(allow_ace(SID_EVERYONE, MASK_FULL_CONTROL, false));
            }),
            ("disabled (informational only)", |i| {
                i.identity.disabled = true
            }),
        ];
        for share in &shares {
            for (name, mutate) in &cases {
                let mut input = base_input(user(USER), cr5_dacl());
                input.share_status = share.clone();
                mutate(&mut input);
                let p = DefaultPermissionEngine.evaluate(input).unwrap();
                if *name == "exact" || name.starts_with("disabled") {
                    assert_eq!(
                        p.effective_determinable(),
                        !matches!(share, ShareMaskStatus::ReadFailed(_)),
                        "{name} / {share:?}"
                    );
                } else {
                    // Each case must really make the result uncertain, or the
                    // invariant below would be tested on exact results only.
                    assert!(!p.effective_determinable(), "{name} / {share:?}");
                }
                assert_path_agrees_with_result(&p);
            }
        }
    }

    // --- Explanation path v2 (review P3, ADR 0074): the invariant first ---

    /// The bits a step states as "[granted …]" / "[denied …]" (0 if none).
    fn decided_bits(step: &str, verb: &str) -> u32 {
        let Some(at) = step.find(&format!(" [{verb} ")) else {
            return 0;
        };
        let rest = &step[at..];
        let Some(hex_at) = rest.find("(0x") else {
            return 0;
        };
        u32::from_str_radix(&rest[hex_at + 3..hex_at + 11], 16).unwrap()
    }

    fn mask_of_step(step: &str) -> u32 {
        let hex_at = step.find("(0x").unwrap();
        u32::from_str_radix(&step[hex_at + 3..hex_at + 11], 16).unwrap()
    }

    /// Deterministic generator (no external crate): a 64-bit LCG.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self, n: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) % n
        }
    }

    /// The explanation path accounts for every bit of the NTFS result:
    /// the "[granted …]" bits of the ACE steps are pairwise disjoint (the
    /// first decision per bit wins), together with the owner rule they are
    /// exactly the NTFS mask, and the Deny aggregation step states exactly
    /// the "[denied …]" bits the owner rule does not restore. Checked over
    /// 3000 generated DACLs (allow / deny, explicit / inherited,
    /// inherit-only, generic rights, group and non-member trustees, owner
    /// or not).
    #[test]
    fn explanation_accounts_for_every_bit_of_the_ntfs_result() {
        const GROUP: &str = "S-1-5-21-1000-1000-1000-2001";
        const OTHER: &str = "S-1-5-21-1000-1000-1000-2002";
        // S-1-5-15 (This Organization) is always logon-dependent: its ACEs
        // bound the result and must each be named (review CR-3).
        let sids = [
            USER,
            GROUP,
            OTHER,
            SID_EVERYONE,
            SID_OWNER_RIGHTS,
            "S-1-5-15",
        ];
        let masks = [
            MASK_READ,
            MASK_MODIFY,
            MASK_FULL_CONTROL,
            FILE_WRITE_DAC,
            FILE_READ_CONTROL,
            0x1000_0000, // GENERIC_ALL
            0x8000_0000, // GENERIC_READ
            0x0010_0000, // SYNCHRONIZE
        ];
        let mut rng = Lcg(0x5EED_2026_1012);
        for case in 0..3000 {
            let n = rng.next(7) as usize;
            let dacl: Vec<AceEntry> = (0..n)
                .map(|_| {
                    let sid = sids[rng.next(sids.len() as u64) as usize];
                    let mask = masks[rng.next(masks.len() as u64) as usize];
                    let inherited = rng.next(2) == 0;
                    match rng.next(5) {
                        0 => deny_ace(sid, mask, inherited),
                        1 => allow_ace_inherit_only(sid, mask, inherited),
                        2 => deny_ace_inherit_only(sid, mask, inherited),
                        _ => allow_ace(sid, mask, inherited),
                    }
                })
                .collect();
            let owner = if rng.next(2) == 0 { USER } else { OTHER };
            let p = eval(
                user(USER),
                vec![membership(USER, GROUP)],
                fso(Some(owner), dacl.clone()),
                None,
            );
            let steps = &p.path_explanation.steps;
            let mut granted = 0u32;
            let mut denied = 0u32;
            for s in steps {
                let g = decided_bits(s, "granted");
                assert_eq!(granted & g, 0, "case {case}: bits granted twice: {steps:?}");
                granted |= g;
                denied |= decided_bits(s, "denied");
            }
            let owner_bits = if steps.iter().any(|s| s.starts_with("Owner special rule")) {
                FILE_READ_CONTROL | FILE_WRITE_DAC
            } else {
                0
            };
            assert_eq!(
                granted | owner_bits,
                p.ntfs_mask.0,
                "case {case}: path does not account for the NTFS mask; dacl {dacl:?}, steps {steps:?}"
            );
            let aggregation = steps
                .iter()
                .find(|s| s.starts_with("Deny aggregation"))
                .map_or(0, |s| mask_of_step(s));
            assert_eq!(
                aggregation,
                denied & !owner_bits,
                "case {case}: deny aggregation; steps {steps:?}"
            );
            // ADR 0077: the trace is the structured twin of the ACE steps —
            // one entry per ACE step, and its decided Allow bits are the
            // granted bits of the path.
            let ace_steps = steps
                .iter()
                .filter(|s| s.starts_with("Allow ACE") || s.starts_with("Deny ACE"))
                .count();
            assert_eq!(p.trace.aces.len(), ace_steps, "case {case}: trace vs steps");
            let traced: u32 = p
                .trace
                .aces
                .iter()
                .filter(|a| a.kind == AceKind::Allow)
                .map(|a| match a.effect {
                    AceEffect::Decided { bits } => bits,
                    _ => 0,
                })
                .fold(0, |acc, b| acc | b);
            assert_eq!(traced, granted, "case {case}: trace bits");
            // Every SID that moves a bound has its own UNCERTAIN step.
            if let Some((bounding, _, _)) = logon_marker(&p) {
                for sid in bounding {
                    assert!(
                        steps
                            .iter()
                            .any(|s| s.contains("[UNCERTAIN — ") && s.contains(sid.as_str())),
                        "case {case}: bounding SID {sid} not explained; steps {steps:?}"
                    );
                }
            }
        }
    }

    // --- Review CR-6: the evaluated logon is stated ---

    #[test]
    fn explanation_states_the_evaluated_logon_after_the_user() {
        let p = eval_with_context(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, MASK_READ, false)]),
            None,
            AccessContext::RemoteSmb,
        );
        let steps = &p.path_explanation.steps;
        assert!(steps[0].starts_with("User: "));
        assert!(
            steps[1].starts_with("Evaluated as: network logon over SMB"),
            "{steps:?}"
        );
        assert!(steps[1].contains("NETWORK (S-1-5-2)"));
        assert!(steps[1].contains("Authenticated Users (S-1-5-11)"));

        let local = access_context_step(AccessContext::LocalInteractive, USER);
        assert!(local.contains("INTERACTIVE (S-1-5-4)") && local.contains("not elevated"));
        assert!(local.contains("LOCAL (S-1-2-0)") && local.contains("bounded"));
        let none = access_context_step(AccessContext::Unspecified, USER);
        assert!(none.contains("not assumed") && !none.contains("S-1-5-2)"));
    }

    /// The step agrees with the token: what it says is added is in the token,
    /// what it says is not assumed is not.
    #[test]
    fn access_context_step_agrees_with_the_token() {
        for ctx in [
            AccessContext::RemoteSmb,
            AccessContext::LocalInteractive,
            AccessContext::Unspecified,
        ] {
            for sid in [USER, "S-1-5-21-1000-1000-1000-501", SID_ANONYMOUS_LOGON] {
                let token = build_token_sids_with_context(sid, &[], &[], &[], ctx);
                let step = access_context_step(ctx, sid);
                for (well_known, text) in [
                    (SID_EVERYONE, "Everyone (S-1-1-0)"),
                    (SID_AUTHENTICATED_USERS, "Authenticated Users (S-1-5-11)"),
                    ("S-1-5-2", "NETWORK (S-1-5-2)"),
                    ("S-1-5-4", "INTERACTIVE (S-1-5-4)"),
                ] {
                    assert_eq!(
                        token.contains(well_known),
                        step.contains(text),
                        "{ctx:?} / {sid}: {well_known} vs step {step}"
                    );
                }
            }
        }
    }

    // --- Review CR-10: DACL states are explained ---

    #[test]
    fn null_dacl_is_explained_as_full_access_for_everyone() {
        let p = eval(user(USER), vec![], fso_null_dacl(), None);
        assert!(p
            .path_explanation
            .steps
            .iter()
            .any(|s| s.starts_with("NULL DACL") && s.contains("every access to everyone")));
    }

    #[test]
    fn empty_dacl_and_no_matching_ace_are_explained() {
        let p = eval(user(USER), vec![], fso(None, vec![]), None);
        assert!(p
            .path_explanation
            .steps
            .iter()
            .any(|s| s.starts_with("Empty DACL")));
        assert_eq!(p.ntfs_mask.0, 0);

        let p = eval(
            user(USER),
            vec![],
            fso(
                None,
                vec![allow_ace("S-1-5-21-9-9-9-999", MASK_FULL_CONTROL, false)],
            ),
            None,
        );
        assert!(p
            .path_explanation
            .steps
            .iter()
            .any(|s| s.starts_with("No ACE in the DACL applies to this token")));

        // A matching ACE: no such step.
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, MASK_READ, false)]),
            None,
        );
        assert!(!p
            .path_explanation
            .steps
            .iter()
            .any(|s| s.starts_with("No ACE")
                || s.starts_with("Empty DACL")
                || s.starts_with("NULL DACL")));
    }

    // --- Review CR-3: bounded results are traceable ---

    /// Lab case rt_uac01 (domain account in MS-01's local Administrators,
    /// local path, DACL "Administrators: Full Control"): the path names the
    /// filtered membership, lists the ACE with the real reason and says that
    /// no ACE certainly applies — no more "member of Administrators, no ACE,
    /// no access" with a generic reason.
    #[test]
    fn uac_bounded_result_names_the_membership_the_ace_and_the_reason() {
        let p = DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![membership(USER, ADMINS)],
                file_system_object: fso(None, vec![allow_ace(ADMINS, MASK_FULL_CONTROL, false)]),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: vec![Sid(ADMINS.into())],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::Applied,
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: vec![Sid(ADMINS.into())],
                remote_uac: adpa_core::model::RemoteUacFiltering::Unknown,
                anonymous_everyone: None,
                access_context: AccessContext::LocalInteractive,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
            })
            .unwrap();
        let steps = &p.path_explanation.steps;
        let member = steps
            .iter()
            .find(|s| s.starts_with("Member of") && s.contains(ADMINS))
            .expect("membership step");
        assert!(member.contains("deny-only in a filtered token") && member.contains("elevated"));
        let ace = steps
            .iter()
            .find(|s| s.starts_with("Allow ACE") && s.contains(ADMINS))
            .expect("the bounding ACE is listed");
        assert!(ace.contains("[UNCERTAIN — User Account Control"), "{ace}");
        assert!(ace.contains("counted in the upper bound only"), "{ace}");
        assert!(steps
            .iter()
            .any(|s| s.starts_with("No ACE in the DACL certainly applies")));
        let range = steps
            .iter()
            .find(|s| s.starts_with("NOT DETERMINABLE: ACE(s) for"))
            .expect("range step");
        assert!(
            !range.contains("authentication type, organization"),
            "{range}"
        );
        assert!(
            range.contains("reason is given at each UNCERTAIN step"),
            "{range}"
        );
    }

    /// Over SMB the reason is remote UAC, not elevation.
    #[test]
    fn uac_reason_over_smb_is_remote_filtering() {
        let p = eval_uac(vec![allow_ace(ADMINS, MASK_FULL_CONTROL, false)], None);
        let ace = p
            .path_explanation
            .steps
            .iter()
            .find(|s| s.starts_with("Allow ACE") && s.contains(ADMINS))
            .expect("listed");
        assert!(ace.contains("LocalAccountTokenFilterPolicy"), "{ace}");
    }

    #[test]
    fn logon_dependent_aces_get_their_own_reason_and_effect() {
        // Allow This Organization: bounds the result.
        let p = eval_with_context(
            user(USER),
            vec![],
            fso(None, vec![allow_ace("S-1-5-15", MASK_MODIFY, false)]),
            None,
            AccessContext::RemoteSmb,
        );
        let ace = p
            .path_explanation
            .steps
            .iter()
            .find(|s| s.contains("S-1-5-15") && s.starts_with("Allow ACE"))
            .expect("listed");
        assert!(
            ace.contains("organisation") && ace.contains("upper bound"),
            "{ace}"
        );

        // An uncertain Allow whose bits a certain Allow already grants:
        // listed, and it says it cannot change the result.
        let p = eval_with_context(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    allow_ace(USER, MASK_MODIFY, false),
                    allow_ace("S-1-5-15", MASK_READ, false),
                ],
            ),
            None,
            AccessContext::RemoteSmb,
        );
        assert!(logon_marker(&p).is_none());
        let ace = p
            .path_explanation
            .steps
            .iter()
            .find(|s| s.contains("S-1-5-15") && s.starts_with("Allow ACE"))
            .expect("listed");
        assert!(ace.contains("cannot change this result"), "{ace}");
        assert!(!p
            .path_explanation
            .steps
            .iter()
            .any(|s| s.contains(NOT_DETERMINABLE)));
    }

    // --- Review CR-13: what a Deny really takes away ---

    fn deny_step(p: &EffectivePermission) -> String {
        p.path_explanation
            .steps
            .iter()
            .find(|s| s.starts_with("Deny aggregation"))
            .cloned()
            .expect("deny aggregation step")
    }

    #[test]
    fn deny_wording_separates_taken_away_from_denied_in_advance() {
        // Deny Write, later Allow Modify: the Deny takes the write bits away.
        let p = eval(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    deny_ace(USER, FILE_WRITE_DATA, false),
                    allow_ace(USER, MASK_MODIFY, false),
                ],
            ),
            None,
        );
        assert!(
            deny_step(&p).contains("the Deny takes them away"),
            "{}",
            deny_step(&p)
        );

        // Deny Full Control, only Allow Read: the read bits are taken away,
        // the rest is denied in advance only.
        let p = eval(
            user(USER),
            vec![],
            fso(
                None,
                vec![
                    deny_ace(USER, MASK_FULL_CONTROL, false),
                    allow_ace(USER, MASK_READ, true),
                ],
            ),
            None,
        );
        let d = deny_step(&p);
        assert!(
            d.contains("taken away (") && d.contains("denied in advance only"),
            "{d}"
        );

        // Deny without any Allow: nothing taken away.
        let p = eval(
            user(USER),
            vec![],
            fso(None, vec![deny_ace(USER, FILE_WRITE_DATA, false)]),
            None,
        );
        assert!(
            deny_step(&p).contains("takes nothing away"),
            "{}",
            deny_step(&p)
        );
    }

    // --- Review CR-12: which membership mattered ---

    #[test]
    fn decisive_memberships_are_marked() {
        const DECIDES: &str = "S-1-5-21-1000-1000-1000-3001";
        const IDLE: &str = "S-1-5-21-1000-1000-1000-3002";
        const LATE: &str = "S-1-5-21-1000-1000-1000-3003";
        let p = eval(
            user(USER),
            vec![
                membership(USER, DECIDES),
                membership(USER, IDLE),
                membership(USER, LATE),
            ],
            fso(
                None,
                vec![
                    allow_ace(DECIDES, MASK_MODIFY, false),
                    // Matches, but every bit is already decided.
                    allow_ace(LATE, MASK_READ, false),
                ],
            ),
            None,
        );
        let step = |sid: &str| {
            p.path_explanation
                .steps
                .iter()
                .find(|s| s.starts_with("Member of") && s.contains(sid))
                .cloned()
                .unwrap()
        };
        assert!(step(DECIDES).contains("[decisive"), "{}", step(DECIDES));
        assert!(!step(IDLE).contains("[decisive"));
        assert!(
            !step(LATE).contains("[decisive"),
            "a matched ACE that decided nothing"
        );
    }

    // --- Review CR-14: deletion through the parent folder ---

    #[test]
    fn a_file_without_delete_names_deletion_through_the_folder() {
        let mut file = fso(None, vec![allow_ace(USER, MASK_READ, false)]);
        file.is_directory = false;
        let p = eval(user(USER), vec![], file, None);
        assert!(p
            .path_explanation
            .steps
            .iter()
            .any(|s| s.contains("FILE_DELETE_CHILD") && s.contains("parent folder")));

        // A folder, or a file the account may delete anyway: no note.
        let mut folder = fso(None, vec![allow_ace(USER, MASK_READ, false)]);
        folder.is_directory = true;
        let mut deletable = fso(None, vec![allow_ace(USER, MASK_MODIFY, false)]);
        deletable.is_directory = false;
        for f in [folder, deletable] {
            let p = eval(user(USER), vec![], f, None);
            assert!(!p
                .path_explanation
                .steps
                .iter()
                .any(|s| s.contains("FILE_DELETE_CHILD")));
        }
    }

    // --- Review CR-7: share provenance and the limiting side ---

    #[test]
    fn explanation_names_the_side_that_limits_the_result() {
        let step_of = |share: u32, ntfs: u32| {
            let p = eval(
                user(USER),
                vec![],
                fso(None, vec![allow_ace(USER, ntfs, false)]),
                Some(AccessMask(share)),
            );
            p.path_explanation
                .steps
                .iter()
                .find(|s| s.starts_with("Limited by") || s.starts_with("NTFS and share"))
                .cloned()
                .expect("limiting-side step")
        };
        let share_limits = step_of(
            expand_generic_rights(MASK_READ),
            expand_generic_rights(MASK_MODIFY),
        );
        assert!(
            share_limits.starts_with("Limited by the share: NTFS grants Modify"),
            "{share_limits}"
        );
        let ntfs_limits = step_of(MASK_FULL_CONTROL, expand_generic_rights(MASK_READ));
        assert!(ntfs_limits.starts_with("Limited by NTFS"), "{ntfs_limits}");
        let same = step_of(MASK_FULL_CONTROL, MASK_FULL_CONTROL);
        assert!(same.starts_with("NTFS and share allow the same"), "{same}");
    }

    #[test]
    fn share_provenance_is_inserted_before_the_share_value() {
        let mut p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, MASK_MODIFY, false)]),
            Some(AccessMask(MASK_READ)),
        );
        attach_share_provenance(
            &mut p.path_explanation,
            vec!["Share ACE Allow for X".into()],
        );
        let steps = &p.path_explanation.steps;
        let at = steps
            .iter()
            .position(|s| s == "Share ACE Allow for X")
            .unwrap();
        assert!(steps[at + 1].starts_with("Share permission: "));

        // No applied share: nothing inserted.
        let mut p = eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, MASK_READ, false)]),
            None,
        );
        let before = p.path_explanation.steps.clone();
        attach_share_provenance(
            &mut p.path_explanation,
            vec!["Share ACE Allow for X".into()],
        );
        assert_eq!(p.path_explanation.steps, before);
    }

    // --- ADR 0076: remote UAC from the target's policies ---

    /// The lab matrix (MS-01, real SMB access, 2026-10-13).
    #[test]
    fn remote_uac_follows_the_measured_policy_matrix() {
        use adpa_core::model::PolicyDword::{Absent, Unreadable, Value};
        let d = |rid500: bool, latfp, fat| remote_uac_filtering(rid500, &Absent, &latfp, &fat);
        let filtered = |r: RemoteUacFiltering| matches!(r, RemoteUacFiltering::Filtered { .. });
        let not = |r: RemoteUacFiltering| matches!(r, RemoteUacFiltering::NotFiltered { .. });
        // local administrator (not RID 500): filtered exactly when LATFP = 0
        assert!(filtered(d(false, Absent, Absent)));
        assert!(not(d(false, Value(1), Absent)));
        assert!(filtered(d(false, Absent, Value(1))));
        assert!(not(d(false, Value(1), Value(1))));
        // built-in Administrator: filtered exactly when FAT = 1 and LATFP = 0
        assert!(not(d(true, Absent, Absent)));
        assert!(not(d(true, Value(1), Absent)));
        assert!(filtered(d(true, Value(0), Value(1))));
        assert!(not(d(true, Value(1), Value(1))));
        // never guessed: UAC off, unexpected values, unreadable values
        assert_eq!(
            remote_uac_filtering(false, &Value(0), &Absent, &Absent),
            RemoteUacFiltering::Unknown
        );
        assert_eq!(d(false, Value(2), Absent), RemoteUacFiltering::Unknown);
        assert_eq!(
            d(false, Unreadable("denied".into()), Absent),
            RemoteUacFiltering::Unknown
        );
        let RemoteUacFiltering::Filtered { reason } = d(false, Absent, Absent) else {
            panic!()
        };
        assert!(reason.contains("LocalAccountTokenFilterPolicy = 0 (not set, default)"));
    }

    /// Local interactive: only RID 500 with FAT = 0 is decided (measured).
    #[test]
    fn local_uac_decides_only_the_unsplit_builtin_administrator() {
        use adpa_core::model::PolicyDword::{Absent, Value};
        assert!(matches!(
            local_uac_filtering(true, &Absent, &Absent),
            RemoteUacFiltering::NotFiltered { .. }
        ));
        assert_eq!(
            local_uac_filtering(true, &Absent, &Value(1)),
            RemoteUacFiltering::Unknown
        );
        assert_eq!(
            local_uac_filtering(false, &Absent, &Absent),
            RemoteUacFiltering::Unknown
        );
        assert_eq!(
            local_uac_filtering(true, &Value(0), &Absent),
            RemoteUacFiltering::Unknown
        );
    }

    fn eval_remote_uac(remote_uac: RemoteUacFiltering) -> EffectivePermission {
        DefaultPermissionEngine
            .evaluate(PermissionEvaluationInput {
                identity: user(USER),
                group_memberships: vec![membership(USER, ADMINS)],
                file_system_object: fso(None, vec![allow_ace(ADMINS, MASK_FULL_CONTROL, false)]),
                share_status: ShareMaskStatus::NotApplicable,
                local_group_sids: vec![Sid(ADMINS.into())],
                local_group_status: adpa_core::model::LocalGroupEvalStatus::Applied,
                logon_dependent_group_sids: Vec::new(),
                uac_filtered_group_sids: vec![Sid(ADMINS.into())],
                remote_uac,
                anonymous_everyone: None,
                access_context: AccessContext::RemoteSmb,
                unsupported_share_ace_count: 0,
                sid_names: std::collections::BTreeMap::new(),
                resolution: ResolutionProvenance::default(),
                share_trace: Default::default(),
                selective_authentication: Default::default(),
                dfs: None,
            })
            .unwrap()
    }

    /// Certainly filtered: the Administrators Allow does not apply — an
    /// exact "no access" instead of a range, and the path says why.
    #[test]
    fn certainly_filtered_admin_group_gives_an_exact_result() {
        let p = eval_remote_uac(RemoteUacFiltering::Filtered {
            reason: "read from the target: LocalAccountTokenFilterPolicy = 0".into(),
        });
        assert_eq!(p.ntfs_mask.0, 0);
        assert!(logon_marker(&p).is_none(), "no range");
        assert!(p.effective_determinable());
        let steps = &p.path_explanation.steps;
        assert!(steps
            .iter()
            .any(|s| s.starts_with("Member of") && s.contains("deny-only in this token")));
        assert!(steps
            .iter()
            .any(|s| s.starts_with("Allow ACE")
                && s.contains("[not applied — the group is deny-only")));
        assert!(!steps.iter().any(|s| s.contains("[UNCERTAIN")));
        assert!(p.diagnostics.iter().any(|d| matches!(
            d,
            PermissionDiagnostic::RemoteUacPolicy { filtered: true, .. }
        )));
        // Unknown keeps the range (ADR 0070).
        let p = eval_remote_uac(RemoteUacFiltering::Unknown);
        assert!(logon_marker(&p).is_some());
    }

    // --- L17: EveryoneIncludesAnonymous read from the target ---

    fn eval_anonymous(anonymous_everyone: Option<bool>) -> EffectivePermission {
        let mut input = base_input(
            user(SID_ANONYMOUS_LOGON),
            fso(None, vec![allow_ace(SID_EVERYONE, MASK_READ, false)]),
        );
        input.access_context = AccessContext::RemoteSmb;
        input.anonymous_everyone = anonymous_everyone;
        DefaultPermissionEngine.evaluate(input).unwrap()
    }

    /// Measured on MS-01: the anonymous token has Everyone exactly when
    /// EveryoneIncludesAnonymous = 1. Read → exact; not read → bounded.
    #[test]
    fn everyone_for_an_anonymous_logon_follows_the_policy_read() {
        let off = eval_anonymous(Some(false));
        assert_eq!(off.ntfs_mask.0, 0);
        assert!(logon_marker(&off).is_none() && off.effective_determinable());
        assert!(off.diagnostics.iter().any(|d| matches!(
            d,
            PermissionDiagnostic::GuestOrAnonymousToken { sids } if sids.contains(&SID_EVERYONE.to_owned())
        )));
        let on = eval_anonymous(Some(true));
        assert_eq!(on.ntfs_mask.0, expand_generic_rights(MASK_READ));
        assert!(logon_marker(&on).is_none() && on.effective_determinable());
        let unknown = eval_anonymous(None);
        assert!(logon_marker(&unknown).is_some(), "not read: bounded");
        for (p, needle) in [
            (&off, "no Everyone and no Authenticated Users"),
            (&on, "EveryoneIncludesAnonymous = 1"),
            (&unknown, "not read, so bounded"),
        ] {
            assert!(
                p.path_explanation.steps[1].contains(needle),
                "{:?}",
                p.path_explanation.steps[1]
            );
        }
        // Review 2026-10-18: since L17 Stars reads the policy — no text may
        // claim it does not; the unread case says it could not be read.
        for p in [&off, &on, &unknown] {
            let all: Vec<String> = p
                .path_explanation
                .steps
                .iter()
                .cloned()
                .chain(p.diagnostics.iter().map(|d| d.summary()))
                .collect();
            assert!(!all.iter().any(|s| s.contains("does not read")), "{all:?}");
        }
        assert!(unknown
            .path_explanation
            .steps
            .iter()
            .any(|s| s.contains("could not read that policy on the target")));
        assert!(off.diagnostics.iter().any(|d| d
            .summary()
            .contains("Stars reads that policy on the target")));
    }

    #[test]
    fn local_group_through_everyone_for_anonymous_follows_the_policy_read() {
        let groups = vec![local_group("S-1-5-32-545", "Users", &[SID_EVERYONE])];
        let with = |v| {
            expand_local_groups_with(
                SID_ANONYMOUS_LOGON,
                &[],
                &[],
                &groups,
                AccessContext::RemoteSmb,
                v,
            )
        };
        assert_eq!(certain_names(&with(Some(true))), vec!["Users"]);
        let off = with(Some(false));
        assert!(off.certain.is_empty() && uncertain_names(&off).is_empty());
        assert_eq!(uncertain_names(&with(None)), vec!["Users"]);
    }

    /// The step agrees with the token for an anonymous logon in every case.
    #[test]
    fn access_context_step_agrees_with_the_anonymous_token() {
        for v in [None, Some(false), Some(true)] {
            let mut token = build_token_sids_with_context(
                SID_ANONYMOUS_LOGON,
                &[],
                &[],
                &[],
                AccessContext::RemoteSmb,
            );
            if anonymous_gets_everyone(SID_ANONYMOUS_LOGON, v) {
                token.insert(SID_EVERYONE.to_owned());
            }
            let step = access_context_step_with(AccessContext::RemoteSmb, SID_ANONYMOUS_LOGON, v);
            assert_eq!(
                token.contains(SID_EVERYONE),
                step.contains("Everyone (S-1-1-0)"),
                "{v:?}: {step}"
            );
            assert!(!step.contains("Authenticated Users (S-1-5-11)"));
        }
        assert_eq!(
            anonymous_everyone(&adpa_core::model::PolicyDword::Absent),
            Some(false)
        );
        assert_eq!(
            anonymous_everyone(&adpa_core::model::PolicyDword::Value(1)),
            Some(true)
        );
        assert_eq!(
            anonymous_everyone(&adpa_core::model::PolicyDword::Value(7)),
            None
        );
    }

    // --- Review CR-12 (frontends): collapsible memberships ---

    #[test]
    fn only_long_lists_collapse_and_never_what_matters() {
        let member = |i: usize, marker: &str| {
            format!("Member of G{i} (S-1-5-21-1-2-3-{i}) [direct]{marker}")
        };
        let mut steps = vec!["User: u (S-1-5-21-1-2-3-1000)".to_owned()];
        for i in 0..MEMBERSHIP_COLLAPSE_THRESHOLD {
            steps.push(member(i, ""));
        }
        assert!(
            collapsible_steps(&steps).iter().all(|c| !c),
            "short list in full"
        );
        steps.push(member(
            90,
            " [decisive — an ACE for this group decides bits of this result]",
        ));
        steps.push(member(91, " [deny-only in this token — …]"));
        steps.push(member(
            92,
            " [uncertain — present in the token only for certain logons]",
        ));
        steps.push("Member of G93 (S-1-5-21-1-2-3-93) [membership confirmed, exact chain unknown — source: LDAP]".to_owned());
        steps.push(
            "Allow ACE [explicit] for G90 → Read (0x00120089) [granted Read (0x00120089)]"
                .to_owned(),
        );
        let c = collapsible_steps(&steps);
        assert!(!c[0], "the user step stays");
        assert_eq!(
            c.iter().filter(|x| **x).count(),
            MEMBERSHIP_COLLAPSE_THRESHOLD
        );
        let last = steps.len() - 1;
        assert!(!c[last] && !c[last - 1] && !c[last - 2] && !c[last - 3] && !c[last - 4]);
    }

    // --- ADR 0077: the permission trace ---

    #[test]
    fn trace_classifies_the_groups_an_ace_reaches_the_account_through() {
        const DECIDES: &str = "S-1-5-21-1000-1000-1000-3101";
        const IDLE: &str = "S-1-5-21-1000-1000-1000-3102";
        let mut input = base_input(
            user(USER),
            fso(
                None,
                vec![
                    allow_ace(DECIDES, MASK_MODIFY, false),
                    allow_ace(SID_EVERYONE, MASK_READ, false),
                    allow_ace(ADMINS, MASK_FULL_CONTROL, false),
                    allow_ace("S-1-5-15", MASK_FULL_CONTROL, false),
                    allow_ace_inherit_only(DECIDES, MASK_FULL_CONTROL, false),
                ],
            ),
        );
        input.group_memberships = vec![
            membership(USER, DECIDES),
            membership(USER, IDLE),
            membership(USER, ADMINS),
        ];
        input.local_group_sids = vec![Sid(ADMINS.into())];
        input.uac_filtered_group_sids = vec![Sid(ADMINS.into())];
        input.access_context = AccessContext::RemoteSmb;
        let p = DefaultPermissionEngine.evaluate(input).unwrap();
        let t = &p.trace;
        let group = |sid: &str| t.groups.iter().find(|g| g.sid.0 == sid).unwrap();
        assert_eq!(group(DECIDES).state, TraceGroupState::Member);
        assert!(group(DECIDES).decisive);
        assert_eq!(group(DECIDES).route, "direct");
        assert_eq!(group(SID_EVERYONE).state, TraceGroupState::Implicit);
        assert_eq!(group(ADMINS).state, TraceGroupState::DenyOnly);
        assert_eq!(group("S-1-5-15").state, TraceGroupState::Uncertain);
        assert!(
            t.groups.iter().all(|g| g.sid.0 != IDLE),
            "no ACE → not in the graph"
        );
        assert_eq!(t.other_groups, 1, "IDLE is counted, not shown");
        assert_eq!(t.other.len(), 1, "and named for the graph");
        assert_eq!(t.other[0].sid.0, IDLE);
        assert!(!t.other[0].decisive);
        let effect = |sid: &str, kind: AceKind| {
            t.aces
                .iter()
                .filter(|a| a.sid.0 == sid && a.kind == kind)
                .map(|a| a.effect.clone())
                .collect::<Vec<_>>()
        };
        assert!(matches!(
            effect(DECIDES, AceKind::Allow)[0],
            AceEffect::Decided { .. }
        ));
        assert_eq!(effect(DECIDES, AceKind::Allow)[1], AceEffect::InheritOnly);
        assert!(matches!(
            effect(ADMINS, AceKind::Allow)[0],
            AceEffect::Uncertain { .. }
        ));
        assert!(matches!(
            effect("S-1-5-15", AceKind::Allow)[0],
            AceEffect::Uncertain { .. }
        ));
        assert!(t.aces.iter().all(|a| a.layer == TraceLayer::Ntfs));
    }

    /// Share outcomes passed in are part of the trace and link to groups.
    #[test]
    fn share_trace_is_merged_into_the_trace() {
        let mut input = base_input(
            user(USER),
            fso(None, vec![allow_ace(USER, MASK_MODIFY, false)]),
        );
        input.share_status = ShareMaskStatus::Applied(AccessMask(MASK_READ));
        input.share_trace = vec![AceOutcome {
            layer: TraceLayer::Share,
            kind: AceKind::Allow,
            sid: Sid(SID_EVERYONE.into()),
            trustee: "Everyone (S-1-1-0)".into(),
            mask: AccessMask(MASK_READ),
            inherited: false,
            effect: AceEffect::Decided { bits: MASK_READ },
        }];
        let p = DefaultPermissionEngine.evaluate(input).unwrap();
        assert_eq!(p.trace.aces.len(), 2);
        assert_eq!(p.trace.aces[1].layer, TraceLayer::Share);
        assert!(p
            .trace
            .groups
            .iter()
            .any(|g| g.sid.0 == SID_EVERYONE && g.state == TraceGroupState::Implicit));
    }

    /// An empty DACL gives an empty trace; a matching ACE fills it.
    #[test]
    fn trace_is_empty_only_without_aces() {
        assert!(eval(user(USER), vec![], fso(None, vec![]), None)
            .trace
            .is_empty());
        assert!(!eval(
            user(USER),
            vec![],
            fso(None, vec![allow_ace(USER, MASK_READ, false)]),
            None
        )
        .trace
        .is_empty());
    }
}
