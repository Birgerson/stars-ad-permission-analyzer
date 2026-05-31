//! Berechnung effektiver NTFS-Berechtigungen.
//! Calculation of effective NTFS permissions.
//!
//! Algorithmus / Algorithm:
//!   1. Alle SIDs des Benutzers sammeln (eigene SID + alle Gruppen-SIDs).
//!   2. DACL in gespeicherter ACE-Reihenfolge auswerten (Windows-AccessCheck-
//!      Semantik): erste Entscheidung pro Recht-Bit gewinnt. INHERIT_ONLY-
//!      ACEs werden für das aktuelle Objekt übersprungen, da sie nur für
//!      Kinder gelten. Generische Bits (GENERIC_*) werden vor der Auswertung
//!      auf spezifische Datei-Bits expandiert.
//!   3. Nicht-kanonisch sortierte DACLs werden erkannt und als Warnung
//!      protokolliert. Die Auswertung folgt dem tatsächlichen Stored Order —
//!      das entspricht dem Verhalten des Windows-AccessChecks.
//!   4. Owner-Sonderregel: Besitzer erhält immer READ_CONTROL + WRITE_DAC.
//!   5. Effektiv = restriktivere Kombination aus NTFS und Share (bitweise AND).
//!
//! Evaluation walks the DACL in its stored order (Windows AccessCheck
//! semantics): the first decision per right-bit wins. INHERIT_ONLY ACEs are
//! skipped for the current object because they only apply to children.
//! Generic bits (GENERIC_*) are expanded into specific file bits before
//! evaluation. Non-canonical DACL orderings are detected and logged as a
//! warning; evaluation still follows the stored order, which matches the
//! actual Windows AccessCheck behavior.

use std::collections::{HashMap, HashSet};

use adpa_core::{
    error::CoreError,
    model::{
        AccessContext, AccessMask, AceEntry, AceKind, ContributingAce, EffectivePermission,
        GroupMembership, Identity, PermissionDiagnostic, PermissionPath, ShareEvalStatus,
        ShareMaskStatus, Sid,
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

        // NULL-DACL bedeutet „kein Zugriffsschutz" — Windows gewährt jedem Vollzugriff.
        // Eine leere DACL (dacl == [] && null_dacl == false) hingegen verweigert alles.
        // NULL DACL means "no access control" — Windows grants everyone full access.
        // An empty DACL (dacl == [] && null_dacl == false) by contrast denies everything.
        let mut ntfs_raw = if input.file_system_object.null_dacl {
            MASK_FULL_CONTROL
        } else {
            evaluate_dacl_ordered(
                &input.file_system_object.dacl,
                &user_sids,
                &input.file_system_object.path.0,
            )
        };

        // Owner-Sonderregel: Besitzer erhält READ_CONTROL + WRITE_DAC unabhängig von der DACL.
        // Owner special rule: owner always gets READ_CONTROL + WRITE_DAC regardless of the DACL.
        if let Some(ref owner_sid) = input.file_system_object.owner_sid {
            if user_sids.contains(&owner_sid.0) {
                ntfs_raw |= FILE_READ_CONTROL | FILE_WRITE_DAC;
            }
        }

        // Share-Status auswerten: NotApplicable → effektiv = NTFS;
        // Applied → effektiv = NTFS ∩ Share; ReadFailed → effektiv = NTFS, aber
        // das Ergebnis trägt die ReadFailed-Markierung weiter (unvollständig).
        // Evaluate the share status: NotApplicable → effective = NTFS;
        // Applied → effective = NTFS ∩ Share; ReadFailed → effective = NTFS but
        // the result carries the ReadFailed marker (incomplete).
        let (share_mask_for_output, output_share_status, effective_raw) = match &input.share_status
        {
            ShareMaskStatus::NotApplicable => (None, ShareEvalStatus::NotApplicable, ntfs_raw),
            ShareMaskStatus::Applied(mask) => {
                (Some(*mask), ShareEvalStatus::Applied, ntfs_raw & mask.0)
            }
            // NULL-Share-DACL: SMB schraenkt nicht ein → effektiv = NTFS.
            // share_mask bleibt None, damit Reports keine kuenstliche Maske
            // 0xFFFFFFFF anzeigen. Der Unrestricted-Status trennt das sauber
            // von einer real gelesenen Special-Maske.
            // NULL share DACL: SMB does not restrict → effective = NTFS.
            // share_mask stays None so reports do not display an artificial
            // mask 0xFFFFFFFF. The Unrestricted status cleanly separates this
            // case from a real "special" mask that was actually read.
            ShareMaskStatus::Unrestricted => (None, ShareEvalStatus::Unrestricted, ntfs_raw),
            ShareMaskStatus::ReadFailed(msg) => {
                (None, ShareEvalStatus::ReadFailed(msg.clone()), ntfs_raw)
            }
        };

        let path_explanation = build_explanation(
            &input.identity,
            &input.group_memberships,
            &input.file_system_object.dacl,
            &user_sids,
            ntfs_raw,
            share_mask_for_output,
            effective_raw,
            &input.sid_names,
        );

        let contributing_sids =
            collect_contributing_sids(&input.file_system_object.dacl, &user_sids, ntfs_raw);

        let matched_aces = collect_matched_aces(&input.file_system_object.dacl, &user_sids);

        // Strukturierte Diagnose-Marker.
        //  - Folge-Befund 3 (NTFS): nicht-kanonische DACL-Reihenfolge.
        //    NULL-DACL hat keine ACEs zum Ordnen — nur für echte DACL.
        //  - Folge-Befund 2 (Share): unsupported Share-ACE-Typen, die der
        //    Share-Parser übersprungen hat. Der Aufrufer übermittelt den
        //    Count über `unsupported_share_ace_count`.
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
            // Diagnose: nicht unterstützte ACE-Typen auf diesem Pfad sichtbar weiterreichen.
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

/// Baut den Token-SID-Satz für einen Benutzer.
/// Builds the token SID set for a user.
///
/// Enthält die eigene SID, alle Gruppen-SIDs und die impliziten Well-Known-Principals
/// `Everyone` (S-1-1-0) und `Authenticated Users` (S-1-5-11), die in jedem
/// Windows-Access-Token vorhanden sind.
///
/// Contains the user SID, all group SIDs, and the implicit well-known principals
/// `Everyone` (S-1-1-0) and `Authenticated Users` (S-1-5-11), which are present
/// in every Windows access token.
///
/// Use this function everywhere a SID set is needed — CLI output, GUI share mask,
/// and the permission engine — so all three stay consistent.
///
/// Backwards-kompatibler Wrapper: nutzt `AccessContext::Unspecified` und fügt
/// daher keine kontextspezifischen Well-Knowns wie `NETWORK` hinzu.
/// Backwards-compatible wrapper: uses `AccessContext::Unspecified` and
/// therefore does not add context-specific well-knowns like `NETWORK`.
pub fn build_token_sids(user_sid: &str, memberships: &[GroupMembership]) -> HashSet<String> {
    build_token_sids_with_context(user_sid, memberships, &[], AccessContext::Unspecified)
}

/// Wie [`build_token_sids`], aber mit zusätzlichen SIDs lokaler Gruppen des
/// Zielservers (z. B. `BUILTIN\Administrators`), in denen der Benutzer Mitglied ist.
/// Like [`build_token_sids`], plus additional SIDs of local groups on the target
/// server (e.g. `BUILTIN\Administrators`) in which the user is a member.
///
/// **Deprecated:** verwendet implizit `AccessContext::Unspecified` und fügt
/// daher keine kontextspezifischen Well-Knowns hinzu — bei SMB-Pfaden fehlt
/// dann z. B. `NETWORK` im Token, was Share-ACEs gegen `NETWORK` unsichtbar
/// macht (siehe ADR 0019). Stattdessen `build_token_sids_with_context` mit
/// explizitem `AccessContext::for_path(path)` nutzen.
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

/// Vollständige Token-Konstruktion: eigene SID, AD-Gruppen, lokale
/// Server-Gruppen, universelle Well-Knowns (`Everyone`, `Authenticated
/// Users`) und kontextspezifische Well-Knowns:
///
/// - `RemoteSmb` → `NETWORK` (S-1-5-2)
/// - `LocalInteractive` → `INTERACTIVE` (S-1-5-4) + `LOCAL` (S-1-2-0)
/// - `Unspecified` → keine weiteren Well-Knowns
///
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
                                         // Kontextspezifische Well-Knowns / context-specific well-knowns
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

/// Prüft, ob ein ACE für das aktuelle Objekt anwendbar ist.
/// Checks whether an ACE applies to the current object.
///
/// Mit INHERIT_ONLY_ACE markierte ACEs gelten ausschließlich für Kinder
/// (Sub-Verzeichnisse / Dateien) und dürfen für das aktuelle Objekt nicht
/// zur effektiven Berechtigung beitragen. Ohne diesen Filter würde die
/// Engine z. B. einem Verzeichnis Rechte zusprechen, die Windows beim
/// `AccessCheck` für genau dieses Verzeichnis nicht anwenden würde.
///
/// ACEs flagged with INHERIT_ONLY_ACE apply only to children and must not
/// contribute to the effective permission on the current object. Without
/// this filter the engine would, for example, grant a directory rights
/// that Windows would not apply in `AccessCheck` for that directory.
fn ace_applies_to_current_object(ace: &AceEntry) -> bool {
    ace.propagation_flags & INHERIT_ONLY_ACE == 0
}

/// Sammelt die Allow-ACEs, die mindestens ein Bit zum NTFS-Ergebnis beigetragen haben, mit den
/// tatsächlich beigetragenen Bits pro SID (akkumuliert über mehrere ACEs derselben SID).
/// Collects allow ACEs that contributed at least one bit to the NTFS result, with the actually
/// contributed bits per SID (accumulated across multiple ACEs of the same SID).
///
/// Wird von der Risk Engine genutzt, um zu erkennen, ob Schreibzugriff über broad principals
/// (Everyone, Authenticated Users) zustande kam — und welche Bits diese genau beitrugen.
/// Used by the risk engine to detect whether write access originated from broad principals
/// (Everyone, Authenticated Users) — and exactly which bits they contributed.
fn collect_contributing_sids(
    dacl: &[AceEntry],
    user_sids: &HashSet<String>,
    ntfs_raw: u32,
) -> Vec<ContributingAce> {
    let mut by_sid: HashMap<String, u32> = HashMap::new();
    for ace in dacl {
        if ace.kind != AceKind::Allow
            || !user_sids.contains(&ace.sid.0)
            || !ace_applies_to_current_object(ace)
        {
            continue;
        }
        // Generische Bits müssen vor dem AND mit ntfs_raw expandiert werden,
        // sonst meldet eine ACE mit GENERIC_ALL irrtümlich „nichts beigetragen".
        // Generic bits must be expanded before the AND with ntfs_raw, otherwise
        // a GENERIC_ALL ACE would falsely report "contributed nothing".
        let contributed = expand_generic_rights(ace.mask.0) & ntfs_raw;
        if contributed != 0 {
            *by_sid.entry(ace.sid.0.clone()).or_insert(0) |= contributed;
        }
    }
    by_sid
        .into_iter()
        .map(|(sid_str, mask)| ContributingAce {
            sid: Sid(sid_str),
            mask: AccessMask(mask),
        })
        .collect()
}

/// Sammelt DACL-Einträge, die das aktuelle Objekt tatsächlich betreffen und deren
/// Trustee-SID zum Token-SID-Satz des Benutzers gehört.
/// Collects DACL entries that actually apply to the current object and whose
/// trustee SID belongs to the user's token SID set.
///
/// Liefert strukturierte ACE-Herkunft (Kind, inherited, Maske, SID) für Risikoregeln,
/// die nicht auf das Parsen von Erklärungstexten angewiesen sein sollen.
///
/// **Wichtig:** ACEs mit `INHERIT_ONLY_ACE`-Flag werden hier ausgefiltert. Sie
/// gelten ausschließlich für Kinder; eine Risikoregel wie `DirectUserAceRule`
/// würde sonst auf einen expliziten Benutzer-ACE feuern, der das aktuelle
/// Objekt gar nicht berührt (Folge-Befund 2).
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

/// Wertet die DACL in gespeicherter Reihenfolge aus.
/// Evaluates the DACL in its stored order.
///
/// Pro Recht-Bit gewinnt die erste passende Entscheidung — analog zum
/// Windows-`AccessCheck`. Vor der Auswertung werden generische Rechte
/// (GENERIC_*) auf spezifische Datei-Bits expandiert und ACEs mit
/// INHERIT_ONLY_ACE für das aktuelle Objekt übersprungen. Falls die DACL
/// nicht der Windows-Kanonik (explizit-Deny → explizit-Allow →
/// inherited-Deny → inherited-Allow) entspricht, wird eine Warnung
/// protokolliert; das Ergebnis folgt trotzdem dem Stored Order.
///
/// For each right-bit the first matching decision wins — analogous to
/// Windows `AccessCheck`. Before evaluation, generic rights (GENERIC_*) are
/// expanded into specific file bits and ACEs flagged INHERIT_ONLY_ACE are
/// skipped for the current object. If the DACL does not follow Windows
/// canonical order (explicit-deny → explicit-allow → inherited-deny →
/// inherited-allow) a warning is logged; the result still follows the
/// stored order.
fn evaluate_dacl_ordered(dacl: &[AceEntry], user_sids: &HashSet<String>, _path: &str) -> u32 {
    // Diagnose-Erkennung (inkl. warn-Log) erfolgt zentral in `collect_diagnostics`
    // im Aufruf-Pfad von `evaluate`, damit der Marker auch in der strukturierten
    // `EffectivePermission.diagnostics`-Liste landet (Folge-Befund 3).
    // Diagnostic detection (incl. warn log) lives centrally in
    // `collect_diagnostics` on the `evaluate` path so the marker also surfaces
    // in the structured `EffectivePermission.diagnostics` list (follow-up
    // finding 3).
    let mut granted: u32 = 0;
    let mut denied: u32 = 0;
    for ace in dacl {
        if !ace_applies_to_current_object(ace) {
            continue;
        }
        if !user_sids.contains(&ace.sid.0) {
            continue;
        }
        let mask = expand_generic_rights(ace.mask.0);
        // Erste Entscheidung pro Bit gewinnt — Bits, die schon entschieden
        // wurden, können nicht mehr umgedreht werden.
        // First decision per bit wins — bits already decided cannot flip.
        let undecided = !(granted | denied);
        let bits = mask & undecided;
        if bits == 0 {
            continue;
        }
        match ace.kind {
            AceKind::Allow => granted |= bits,
            AceKind::Deny => denied |= bits,
        }
    }
    granted
}

/// Sammelt strukturierte Diagnose-Marker, die einer effektiven Berechtigung
/// anhaftet (Folge-Befund 3). Erkennt nicht-kanonisch sortierte DACLs und
/// loggt sie zusätzlich als `warn!` — die strukturierte Liste landet im
/// `EffectivePermission.diagnostics`-Feld und damit auch in DB-Historie und
/// Exports.
///
/// Collects structured diagnostic markers attached to an effective permission
/// (follow-up finding 3). Detects non-canonical DACL orderings and also
/// emits a `warn!` — the structured list flows into
/// `EffectivePermission.diagnostics` and from there into DB history and
/// exports.
fn collect_diagnostics(dacl: &[AceEntry], path: &str) -> Vec<PermissionDiagnostic> {
    let mut out = Vec::new();
    if let Some(at) = first_non_canonical_position(dacl) {
        warn!(
            path,
            at,
            "Non-canonical DACL ordering detected — evaluation follows stored ACE order \
             (matches Windows AccessCheck), but tools like icacls flag this as anomalous"
        );
        out.push(PermissionDiagnostic::NonCanonicalDaclOrder { at_index: at });
    }
    out
}

/// Kanonische DACL-Reihenfolge (Windows): pro ACE eine monotone Phase
/// 0 (explizit Deny) → 1 (explizit Allow) → 2 (inherited Deny) → 3 (inherited Allow).
/// Liefert den Index des ersten ACEs, der diese Reihenfolge verletzt.
///
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

/// Erstellt einen erklärbaren Berechtigungspfad.
/// Creates an explainable permission path.
#[allow(clippy::too_many_arguments)]
fn build_explanation(
    identity: &Identity,
    memberships: &[GroupMembership],
    dacl: &[adpa_core::model::AceEntry],
    user_sids: &HashSet<String>,
    ntfs_raw: u32,
    share_mask: Option<AccessMask>,
    effective_raw: u32,
    sid_names: &std::collections::BTreeMap<String, String>,
) -> PermissionPath {
    let mut steps: Vec<String> = Vec::new();

    // 1. Benutzeridentität / user identity
    let display_name = identity.name.as_deref().unwrap_or(identity.sid.0.as_str());
    steps.push(format!("User: {} ({})", display_name, identity.sid.0));

    // 2. Gruppenmitgliedschaften / group memberships
    for gm in memberships {
        let via = if gm.direct { "direct" } else { "transitive" };
        // Anzeige-Reihenfolge: erst Name aus der Membership selbst (vom
        // jeweiligen Resolver gesetzt), sonst aus der globalen SID→Name-
        // Tabelle, sonst nur die SID.
        // Display order: first the name carried on the membership itself
        // (set by the respective resolver), then the global SID→name
        // table, finally the raw SID.
        let display = gm
            .group_name
            .as_deref()
            .or_else(|| sid_names.get(&gm.group_sid.0).map(String::as_str));
        match display {
            Some(name) => steps.push(format!("Member of {} ({}) [{}]", name, gm.group_sid.0, via)),
            None => steps.push(format!("Member of {} [{}]", gm.group_sid.0, via)),
        }
    }

    // 3. Zutreffende ACEs / matching ACEs
    for ace in dacl {
        if !user_sids.contains(&ace.sid.0) {
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
        // Generische Bits für die Anzeige expandieren, damit z. B. GENERIC_ALL
        // als „Full Control" sichtbar wird und nicht als „Special" erscheint.
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

    // 4. NTFS-effektiv / NTFS effective
    let ntfs_rights = NormalizedRights::new(ntfs_raw);
    steps.push(format!(
        "NTFS effective: {} (0x{:08X})",
        ntfs_rights.display_name(),
        ntfs_raw
    ));

    // 5. Share + Kombination (falls vorhanden / if present)
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
        NormalizedPath, Sid,
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
            // IO — gilt nur für Kinder, nicht für das aktuelle Objekt.
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
        // Group A: Read, Group B: Write → effektiv Read | Write
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
        // GROUP_A: Deny Read, GROUP_B: Allow Read → beide Gruppen → kein Read
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
        // Kritische Windows-Regel: explizites Allow schlägt geerbtes Deny
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

    // --- Keine Rechte / no rights ---

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

    // --- Berechtigungspfad / permission path ---

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
        // ACE auf S-1-1-0 (Everyone) muss für jeden Benutzer wirken.
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
        // ACE auf S-1-5-11 (Authenticated Users) muss für jeden authentifizierten Benutzer wirken.
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

    // --- Diagnose: nicht unterstützte ACEs / diagnostic: unsupported ACEs ---

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
        // Ein expliziter Benutzer-ACE und ein geerbter Gruppen-ACE; ein fremder ACE
        // darf nicht in matched_aces landen.
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

    // --- NULL-DACL vs. leere DACL ---

    #[test]
    fn null_dacl_grants_full_control_to_any_user() {
        // Windows-Semantik: NULL-DACL = kein Zugriffsschutz = jeder hat Vollzugriff.
        // Selbst ohne passende ACE oder Gruppenmitgliedschaft.
        let p = eval(user(USER), vec![], fso_null_dacl(), None);
        assert!(
            NormalizedRights::new(p.ntfs_mask.0).is_full_control(),
            "NULL DACL must yield Full Control; got 0x{:08X}",
            p.ntfs_mask.0
        );
    }

    #[test]
    fn empty_dacl_still_denies_access() {
        // Regression: leere DACL (null_dacl=false, dacl=[]) bleibt Deny-All.
        let p = eval(user(USER), vec![], fso(None, vec![]), None);
        assert_eq!(p.ntfs_mask.0, 0);
        assert_eq!(p.effective_mask.0, 0);
    }

    #[test]
    fn null_dacl_grants_even_to_user_with_no_groups() {
        // Sicherstellt, dass NULL-DACL nicht von Gruppenmitgliedschaft abhängt.
        let p = eval(user(OTHER), vec![], fso_null_dacl(), None);
        assert!(NormalizedRights::new(p.ntfs_mask.0).is_full_control());
    }

    // --- ShareMaskStatus-Ein-/Ausgabe / share mask status input/output ---

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
            })
            .unwrap();
        assert!(NormalizedRights::new(p.effective_mask.0).is_read());
        assert!(!NormalizedRights::new(p.effective_mask.0).is_modify());
        assert_eq!(p.share_status, ShareEvalStatus::Applied);
        assert_eq!(p.share_mask.unwrap().0, MASK_READ);
    }

    /// NULL-Share-DACL → effective = NTFS, kein kuenstlicher `Applied(0xFFFFFFFF)`.
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

    // --- Lokale Server-Gruppen / local server groups ---

    #[test]
    fn local_group_ace_grants_rights() {
        // ACE auf eine lokale Server-Gruppen-SID muss wirken, wenn die SID
        // im `local_group_sids` des Tokens ist — auch ohne AD-Mitgliedschaft.
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
        // Ohne lokale Gruppen-SID im Token wirkt der gleiche ACE nicht.
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
        // Explizites Deny auf Everyone muss Read blockieren — in kanonischer
        // Reihenfolge (Deny vor Allow). Vor Finding 2 hat die alte Bucket-
        // Logik die Reihenfolge ignoriert; jetzt entspricht das Verhalten dem
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

    // --- Finding 1: INHERIT_ONLY_ACE darf das aktuelle Objekt nicht beeinflussen ---
    // --- Finding 1: INHERIT_ONLY_ACE must not affect the current object ---

    #[test]
    fn inherit_only_allow_does_not_grant_to_current_object() {
        // ACE mit IO-Flag gilt nur für Kinder; für das aktuelle Objekt selbst
        // darf er keine Rechte beitragen.
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
        // Ein IO-Deny darf einen normalen Allow auf dem aktuellen Objekt nicht
        // verschlucken — das IO-Deny gilt nur für Kinder.
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
        // Folge-Befund 2: matched_aces wird von Risikoregeln (z. B.
        // DirectUserAceRule) konsumiert. INHERIT_ONLY-ACEs müssen daher
        // auch hier ausgefiltert sein, sonst feuert die Risikoregel auf
        // einen ACE, der das aktuelle Objekt gar nicht berührt.
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
        // Eine IO-ACE darf nicht in contributing_sids auftauchen, da sie zum
        // aktuellen Objekt nichts beigetragen hat.
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
        // Nur die "echte" Allow ACE darf beitragen.
        assert!(
            p.contributing_sids.iter().all(|c| c.mask.0 == MASK_READ),
            "INHERIT_ONLY ACE must not show up in contributing_sids"
        );
    }

    // --- Finding 3: Generische Bits (GENERIC_*) im NTFS-Pfad expandieren ---
    // --- Finding 3: expand generic bits (GENERIC_*) in the NTFS path ---

    #[test]
    fn generic_all_ace_yields_full_control() {
        // Ein NTFS-Allow mit GENERIC_ALL muss in der Engine als Full Control
        // wirken — nicht bei „Special" hängen bleiben.
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
        // Vorher: GENERIC_ALL & Share-Maske ergab 0. Erwartet: korrekte
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
        // GENERIC_ALL als Deny muss alle Bits sperren — vor Finding 3 hätte
        // der Roh-Deny-Bit 0x10000000 nichts spezifisches geblockt.
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

    // --- Finding 2: ACE-Reihenfolge / nicht-kanonische DACLs ---
    // --- Finding 2: ACE order / non-canonical DACLs ---

    #[test]
    fn non_canonical_allow_before_deny_first_wins() {
        // Nicht-kanonisch (Allow vor Deny für gleichen Trustee+Bit).
        // Windows-AccessCheck wertet in Reihenfolge aus → erstes Allow gewinnt.
        // Der alte Bucket-Algorithmus hätte fälschlich „Deny gewinnt" geliefert.
        //
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
        // Kanonischer Fall, aber explizit getestet, dass die Reihenfolge-
        // basierte Logik exakt die alte Vorrangregel reproduziert.
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
        // Kanonischer Standardfall: erstes Deny blockiert spätere Allow-Bits.
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
        // Die anderen Allow-Bits (außerhalb MASK_READ) müssen bestehen.
        assert!(
            p.ntfs_mask.0 & FILE_WRITE_DATA != 0,
            "non-denied bits from the allow must survive"
        );
    }

    #[test]
    fn detects_non_canonical_dacl_position() {
        // Direkter Test auf den Detektor — Allow vor Deny ist non-canonical.
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

    /// Folge-Befund 3: nicht-kanonische DACL muss als strukturierter
    /// Diagnose-Marker in `EffectivePermission.diagnostics` landen, nicht
    /// nur als warn-Log.
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
        // Regression: bei kanonischer DACL muss `diagnostics` leer sein.
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
        // NULL-DACL hat keine ACEs zum Ordnen — Detektor darf nicht feuern.
        let p = eval(user(USER), vec![], fso_null_dacl(), None);
        assert!(p.diagnostics.is_empty());
    }

    /// Folge-Befund 2: Engine pusht `UnsupportedShareAces` in die
    /// strukturierte Diagnose, wenn der Aufrufer einen Count > 0
    /// übergibt. Damit ist die Share-Diagnose symmetrisch zur NTFS-Seite.
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
            })
            .unwrap();
        assert!(
            !p.diagnostics
                .iter()
                .any(|d| matches!(d, PermissionDiagnostic::UnsupportedShareAces { .. })),
            "no UnsupportedShareAces diagnostic when count == 0"
        );
    }

    // --- Erklärungspfad: Namensauflösung über sid_names + group_name ---
    // --- Explanation path: name resolution via sid_names + group_name ---

    /// Memberships mit gesetztem `group_name` sollen den Namen im Step
    /// hinter den SID einfügen, ohne dass `sid_names` etwas dazu beiträgt.
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

    /// Ist kein `group_name` gesetzt, soll der Engine die `sid_names`-
    /// Tabelle konsultieren — Eintrag dort muss die gleiche Wirkung haben.
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

    /// Auch ACE-Trustees sollen den Namen aus `sid_names` führen, damit
    /// `Allow ACE for BUILTIN\Administrators (S-1-5-32-544) → Modify`
    /// statt nur `Allow ACE for S-1-5-32-544 → Modify` erscheint.
    /// ACE trustees should also display the name from `sid_names`, so
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

    /// Ohne Namen in beiden Quellen muss das alte Verhalten bestehen
    /// bleiben — nur die SID erscheint, keine erfundenen Klammern.
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
        // SMB-Zugriff: NETWORK muss implizit im Token sein, damit eine
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
        // Lokaler interaktiver Zugriff: NETWORK ist NICHT im Token. Eine
        // NETWORK-ACE darf nichts beitragen.
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
        // Default-Kontext: keine kontextspezifischen Well-Knowns. NETWORK-ACE
        // bleibt ohne Wirkung — gleiches Verhalten wie vor Finding 4 für alle
        // Aufrufer, die noch keinen Kontext setzen.
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
        // S-1-2-0 LOCAL ist zusätzlich zu INTERACTIVE Teil des lokalen Tokens.
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
        // Direkter Audit-Use-Case: ein „Deny NETWORK" muss bei SMB greifen
        // und ein Allow für den Benutzer überstimmen — vor Finding 4 wurde
        // das ignoriert, weil NETWORK nicht im Token war.
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
        // Universal well-knowns (Everyone, Authenticated Users) sind immer da,
        // auch ohne expliziten Kontext.
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
}
