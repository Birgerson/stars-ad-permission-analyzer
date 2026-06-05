// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Lokale Gruppenmitgliedschaften eines Benutzers auf einem Zielserver.
//! Local group memberships for a user on a target server.
//!
//! Auf einem Windows-Access-Token sind neben den AD-Gruppen-SIDs auch die SIDs
//! der lokalen Gruppen des Zielservers enthalten, in denen der Benutzer direkt
//! oder transitiv Mitglied ist (z. B. `BUILTIN\Administrators`, in dem oft eine
//! Domaenengruppe liegt). Ohne diese SIDs fehlen NTFS-/Share-ACEs, die ueber
//! lokale Gruppen wirken — die effektiven Rechte werden dann zu niedrig.
//!
//! On a Windows access token, alongside the AD group SIDs, are the SIDs of the
//! target server's local groups in which the user is a direct or transitive
//! member (e.g. `BUILTIN\Administrators`, which often contains a domain group).
//! Without these SIDs, NTFS/share ACEs that grant access via local groups are
//! missed and effective rights are computed too low.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use adpa_core::{
    error::CoreError,
    model::{GroupMembership, Identity, MembershipPath, MembershipPathSource, Sid},
};
use tracing::{debug, warn};
use windows_sys::Win32::Foundation::{LocalFree, ERROR_ACCESS_DENIED, FALSE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetLocalGroupGetMembers, NetUserGetLocalGroups, LG_INCLUDE_INDIRECT,
    LOCALGROUP_MEMBERS_INFO_2, LOCALGROUP_USERS_INFO_0, MAX_PREFERRED_LENGTH,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::LookupAccountNameW;

/// User-Not-Found-Statuscode aus lmerr.h / NERR_UserNotFound from lmerr.h.
const NERR_USER_NOT_FOUND: u32 = 2221;

/// Heuristik: tragt der Domain-String wie ein DNS-Suffix aussehende
/// Bestandteile (mindestens ein `.`)? In Trust-/Multi-Domain-Szenarien
/// liefert LSA üblicherweise den NetBIOS-Namen (`TRUSTED`), und das
/// `name@TRUSTED`-Format ist KEINE gültige Accountreferenz für
/// `NetUserGetLocalGroups`. Nur DNS-artige Suffixe (`corp.local`) sind
/// als UPN-Suffix valide.
/// Heuristic: does the domain string look like a DNS suffix (contains a
/// dot)? In trust / multi-domain scenarios LSA usually returns the NetBIOS
/// name (`TRUSTED`); `name@TRUSTED` is NOT a valid account reference for
/// `NetUserGetLocalGroups` — only DNS-style suffixes (`corp.local`) work
/// as UPN suffixes.
fn looks_like_dns_domain(domain: &str) -> bool {
    domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

/// Liefert eine **Kandidatenliste** von Accountnamen für
/// `NetUserGetLocalGroups`, in Präferenzreihenfolge. Der Aufrufer
/// probiert die Liste durch, bis eine Form vom Zielserver erkannt
/// wird (siehe [`resolve_local_group_sids_for_identity`]).
///
/// Schließt Review 2026-06-04 Runde 5 Finding 1: vorher baute Stars
/// blind `name@domain`, was bei NetBIOS-Domains (`alice@TRUSTED` statt
/// `TRUSTED\alice`) regelmäßig zu `NERR_USER_NOT_FOUND` führte — und
/// dieser Fall wurde stillschweigend als „keine lokalen Gruppen"
/// gewertet, nicht als Lücke.
///
/// Reihenfolge:
/// 1. `userPrincipalName` (echter UPN, wenn AD ihn gesetzt hat).
/// 2. `DOMAIN\name` (funktioniert sowohl für NetBIOS- als auch
///    DNS-Domains — der robusteste klassische NetAPI-Form).
/// 3. `name@domain` — nur wenn `domain` wie ein DNS-Suffix aussieht
///    (Punkt enthalten). Bei NetBIOS-Namen würde diese Form irreführend
///    konstruiert.
/// 4. `name` (rein) — lokale Konten ohne Domain.
///
/// Returns a **candidate list** of account names for
/// `NetUserGetLocalGroups`, in preference order. The caller iterates
/// until one form is recognized by the target server.
///
/// Closes review 2026-06-04 round 5 finding 1.
pub fn format_account_candidates_for_local_groups(identity: &Identity) -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();
    if let Some(upn) = identity
        .user_principal_name
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        candidates.push(upn.to_string());
    }
    let name = match identity.name.as_deref().filter(|s| !s.is_empty()) {
        Some(n) => n,
        None => return candidates,
    };
    if let Some(domain) = identity.domain.as_deref().filter(|s| !s.is_empty()) {
        let domain_backslash_name = format!("{domain}\\{name}");
        if !candidates.contains(&domain_backslash_name) {
            candidates.push(domain_backslash_name);
        }
        // Nur als UPN-Konstruktion wenn das Domain-Feld DNS-artig aussieht.
        // Only as UPN construction when the domain looks DNS-style.
        if looks_like_dns_domain(domain) {
            let upn_form = format!("{name}@{domain}");
            if !candidates.contains(&upn_form) {
                candidates.push(upn_form);
            }
        }
    }
    if !candidates.contains(&name.to_string()) {
        candidates.push(name.to_string());
    }
    candidates
}

/// Convenience-Wrapper, der den **ersten** Kandidaten aus
/// [`format_account_candidates_for_local_groups`] zurückgibt. Behält
/// die alte API für Aufrufer, die nur einen Namen wollen. Neue
/// Aufrufer sollten die Kandidatenliste verwenden, damit Trust-/
/// NetBIOS-Identities nicht still durchfallen.
/// Convenience wrapper returning the **first** candidate.
pub fn format_account_for_local_groups(identity: &Identity) -> Option<String> {
    format_account_candidates_for_local_groups(identity)
        .into_iter()
        .next()
}

/// Ergebnis eines `NetUserGetLocalGroups`-Aufrufs — trennt explizit
/// **„User nicht gefunden"** von **„User gefunden, aber in keinen
/// Gruppen"**. Der Unterschied ist für die Trust-/LSA-Pfade kritisch
/// (Review Runde 5 Finding 1).
/// `NetUserGetLocalGroups` outcome — separates **"user not found"**
/// from **"user found but has no group memberships"**.
#[derive(Debug, Clone)]
pub enum LocalGroupLookupOutcome {
    /// `NetUserGetLocalGroups` hat den Account gefunden und seine
    /// (möglicherweise leere) Gruppenliste zurückgegeben.
    /// Account was found; the returned vector is the actual group set.
    WithGroups(Vec<Sid>),
    /// `NetUserGetLocalGroups` hat den Account auf dem Zielserver nicht
    /// gefunden (`NERR_USER_NOT_FOUND`). Aufrufer entscheidet, ob das
    /// als Konfigurationsfehler (alle Kandidaten erschöpft) oder als
    /// Hinweis (anderen Kandidaten probieren) gewertet wird.
    /// Account was not known on the target server.
    UserNotFoundOnServer,
}

/// Liefert die SIDs aller lokalen Gruppen auf `server`, in denen `account` direkt
/// oder transitiv Mitglied ist (`LG_INCLUDE_INDIRECT`).
///
/// `server`: Zielserver (Hostname oder IP). `None` = lokaler Rechner.
/// `account`: typischerweise `DOMAIN\username` oder `username@domain`.
///
/// Returns the SIDs of all local groups on `server` in which `account` is a
/// direct or transitive member (`LG_INCLUDE_INDIRECT`).
///
/// `server`: target server (host name or IP). `None` = local machine.
/// `account`: typically `DOMAIN\username` or `username@domain`.
pub fn resolve_local_group_sids(
    server: Option<&str>,
    account: &str,
) -> Result<Vec<Sid>, CoreError> {
    // Backward-Compat-Wrapper über die strict-Variante: NERR_USER_NOT_FOUND
    // wird hier weiterhin als leere Liste interpretiert. Neue Aufrufer
    // sollten `resolve_local_group_sids_for_identity` verwenden, das die
    // Kandidaten-Liste durchprobiert und einen echten Fehler liefert,
    // wenn keiner erkannt wurde. Schließt Runde 5 Finding 1 in der
    // Tiefe — bewahrt aber die alte API für externe Konsumenten.
    // Backward-compatible wrapper around the strict variant.
    match resolve_local_group_sids_strict(server, account)? {
        LocalGroupLookupOutcome::WithGroups(v) => Ok(v),
        LocalGroupLookupOutcome::UserNotFoundOnServer => Ok(Vec::new()),
    }
}

/// Strict-Variante: trennt **„User nicht gefunden"** explizit von
/// **„User gefunden, leere Gruppenliste"**. Aufrufer (z. B.
/// [`resolve_local_group_sids_for_identity`]) brauchen diese
/// Unterscheidung, um Kandidatenlisten durchzuprobieren ohne stille
/// Skips.
/// Strict variant — distinguishes "not found" from "found, no groups".
pub fn resolve_local_group_sids_strict(
    server: Option<&str>,
    account: &str,
) -> Result<LocalGroupLookupOutcome, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let account_w = to_wide_null(account);

    let mut buf_ptr: *mut u8 = std::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;

    // SAFETY: server_ptr is either null or points to a valid null-terminated wide
    // string; account_w is a valid null-terminated wide string. buf_ptr is an OUT
    // pointer that NetApi allocates on success and we free below with NetApiBufferFree.
    let status = unsafe {
        NetUserGetLocalGroups(
            server_ptr,
            account_w.as_ptr(),
            0, // level 0 = LOCALGROUP_USERS_INFO_0
            LG_INCLUDE_INDIRECT,
            &mut buf_ptr,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
        )
    };

    if status != NO_ERROR {
        if !buf_ptr.is_null() {
            // SAFETY: buf_ptr may have been partially allocated; NetApiBufferFree
            // accepts the pointer from NetApi.
            unsafe { NetApiBufferFree(buf_ptr.cast()) };
        }
        return match status {
            ERROR_ACCESS_DENIED => Err(CoreError::AccessDenied(format!(
                "NetUserGetLocalGroups: access denied for '{account}' on {server:?}"
            ))),
            NERR_USER_NOT_FOUND => {
                debug!(
                    account,
                    ?server,
                    "NetUserGetLocalGroups: user not found on server"
                );
                Ok(LocalGroupLookupOutcome::UserNotFoundOnServer)
            }
            _ => Err(CoreError::LdapQuery(format!(
                "NetUserGetLocalGroups('{account}') failed with status {status}"
            ))),
        };
    }

    let mut sids = Vec::with_capacity(entries_read as usize);
    if !buf_ptr.is_null() && entries_read > 0 {
        // SAFETY: buf_ptr points to `entries_read` consecutive LOCALGROUP_USERS_INFO_0
        // entries allocated by NetApi.
        let entries = unsafe {
            std::slice::from_raw_parts(
                buf_ptr as *const LOCALGROUP_USERS_INFO_0,
                entries_read as usize,
            )
        };
        for entry in entries {
            // SAFETY: lgrui0_name is a valid null-terminated wide string inside the buffer.
            let name = unsafe { wide_ptr_to_string(entry.lgrui0_name) };
            if name.is_empty() {
                continue;
            }
            match lookup_account_sid(server, &name) {
                Some(sid_str) => {
                    debug!(local_group = %name, sid = %sid_str, "Local group resolved");
                    sids.push(Sid(sid_str));
                }
                None => warn!(local_group = %name, "Could not resolve local group SID"),
            }
        }
    }

    if !buf_ptr.is_null() {
        // SAFETY: see above.
        unsafe { NetApiBufferFree(buf_ptr.cast()) };
    }

    Ok(LocalGroupLookupOutcome::WithGroups(sids))
}

/// Versucht, lokale Gruppen für die `identity` auf dem `server` aufzulösen,
/// und probiert dabei mehrere Account-Namensformen
/// ([`format_account_candidates_for_local_groups`]) durch.
///
/// **Rückgabe:**
/// - `Ok(Vec<Sid>)` bei mindestens einem erkannten Kandidaten — der erste
///   `WithGroups`-Treffer gewinnt (auch wenn die Gruppenliste leer ist;
///   das bedeutet dann ehrlich: Account ist auf dem Server bekannt, hat aber
///   keine lokalen Gruppen).
/// - `Err(CoreError::Validation(reason))`, wenn **kein** Kandidat erkannt
///   wurde (alle `UserNotFoundOnServer`). Aufrufer setzen dann
///   `LocalGroupEvalStatus::NotAvailable(reason)` — das treibt die
///   `incomplete = true`-Logik in der Risk-Engine.
/// - `Err(...)` bei anderen technischen Fehlern (Access Denied, NetAPI-
///   Fehler) — sofort propagiert, kein Weiterprobieren.
///
/// Schließt Review 2026-06-04 Runde 5 Finding 1: vorher landete eine
/// LSA-/Trust-Identity oft im NERR_USER_NOT_FOUND-Pfad und wurde still
/// als `LocalGroupEvalStatus::Applied(0)` ausgewiesen — ACEs auf lokale
/// Servergruppen blieben unsichtbar ohne Incomplete-Marker.
///
/// Tries to resolve local groups for `identity` on `server`, iterating
/// over candidate account name forms.
pub fn resolve_local_group_sids_for_identity(
    server: Option<&str>,
    identity: &Identity,
) -> Result<Vec<Sid>, CoreError> {
    let candidates = format_account_candidates_for_local_groups(identity);
    if candidates.is_empty() {
        return Err(CoreError::Validation(format!(
            "Local groups: no usable account name form derivable from identity {}",
            identity.sid.0
        )));
    }
    let mut tried: Vec<String> = Vec::with_capacity(candidates.len());
    for candidate in &candidates {
        tried.push(candidate.clone());
        match resolve_local_group_sids_strict(server, candidate)? {
            LocalGroupLookupOutcome::WithGroups(sids) => {
                debug!(
                    ?server,
                    account = %candidate,
                    count = sids.len(),
                    "Local groups resolved via candidate"
                );
                return Ok(sids);
            }
            LocalGroupLookupOutcome::UserNotFoundOnServer => {
                debug!(
                    ?server,
                    account = %candidate,
                    "Candidate not known on server, trying next"
                );
            }
        }
    }
    Err(CoreError::Validation(format!(
        "NetUserGetLocalGroups: account for identity {} not known on {server:?} \
         (tried forms: {:?}). Local server group memberships are not available; \
         the result is marked incomplete.",
        identity.sid.0, tried
    )))
}

/// Eintrag in der `NetUserGetLocalGroups`-Antwort mit Name *und* SID. Die
/// reine `resolve_local_group_sids`-Variante wirft den Namen weg; für die
/// Ketten-Rekonstruktion brauchen wir aber beides, weil
/// `NetLocalGroupGetMembers` den Namen erwartet.
/// Entry in the `NetUserGetLocalGroups` response with both name and SID. The
/// plain `resolve_local_group_sids` variant discards the name; for chain
/// reconstruction we need both because `NetLocalGroupGetMembers` requires
/// the name.
#[derive(Debug, Clone)]
pub struct LocalGroupInfo {
    pub name: String,
    pub sid: Sid,
}

/// Ein Mitglied einer lokalen Gruppe in der Antwort von
/// `NetLocalGroupGetMembers` Level 2.
/// A member of a local group from `NetLocalGroupGetMembers` level 2.
#[derive(Debug, Clone)]
pub struct LocalGroupMember {
    /// SID des Mitglieds (None nur wenn die Konvertierung fehlschlug —
    /// sollte praktisch nicht vorkommen).
    /// Member SID (None only when conversion failed — should be vanishingly
    /// rare).
    pub sid: Option<Sid>,
    /// `DOMAIN\Name`-Darstellung wie von Windows geliefert; bei lokalen
    /// Konten ohne Domäne kann das einfach `Name` sein.
    /// `DOMAIN\name` form as returned by Windows; for local accounts without
    /// a domain it may just be `Name`.
    pub display_name: Option<String>,
}

/// Variante von [`resolve_local_group_sids`], die zusätzlich den Gruppen-
/// Namen mitliefert. Notwendig für die Ketten-Rekonstruktion.
/// Variant of [`resolve_local_group_sids`] that also returns the group
/// name. Required for chain reconstruction.
pub fn resolve_local_groups(
    server: Option<&str>,
    account: &str,
) -> Result<Vec<LocalGroupInfo>, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let account_w = to_wide_null(account);

    let mut buf_ptr: *mut u8 = std::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;

    // SAFETY: identisch zu resolve_local_group_sids — Pointer sind gültig oder
    // null, NetApi befüllt buf_ptr und wir geben ihn unten frei.
    // SAFETY: same as resolve_local_group_sids — pointers are valid or null,
    // NetApi populates buf_ptr and we free it below.
    let status = unsafe {
        NetUserGetLocalGroups(
            server_ptr,
            account_w.as_ptr(),
            0,
            LG_INCLUDE_INDIRECT,
            &mut buf_ptr,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
        )
    };

    if status != NO_ERROR {
        if !buf_ptr.is_null() {
            unsafe { NetApiBufferFree(buf_ptr.cast()) };
        }
        return match status {
            ERROR_ACCESS_DENIED => Err(CoreError::AccessDenied(format!(
                "NetUserGetLocalGroups: access denied for '{account}' on {server:?}"
            ))),
            NERR_USER_NOT_FOUND => {
                debug!(account, ?server, "user not found");
                Ok(Vec::new())
            }
            _ => Err(CoreError::LdapQuery(format!(
                "NetUserGetLocalGroups('{account}') failed with status {status}"
            ))),
        };
    }

    let mut result = Vec::with_capacity(entries_read as usize);
    if !buf_ptr.is_null() && entries_read > 0 {
        // SAFETY: see above
        let entries = unsafe {
            std::slice::from_raw_parts(
                buf_ptr as *const LOCALGROUP_USERS_INFO_0,
                entries_read as usize,
            )
        };
        for entry in entries {
            // SAFETY: lgrui0_name is a valid null-terminated wide string inside the buffer.
            let name = unsafe { wide_ptr_to_string(entry.lgrui0_name) };
            if name.is_empty() {
                continue;
            }
            if let Some(sid_str) = lookup_account_sid(server, &name) {
                result.push(LocalGroupInfo {
                    name,
                    sid: Sid(sid_str),
                });
            }
        }
    }

    if !buf_ptr.is_null() {
        unsafe { NetApiBufferFree(buf_ptr.cast()) };
    }
    Ok(result)
}

/// Listet die direkten Mitglieder einer lokalen Gruppe via
/// `NetLocalGroupGetMembers` Level 2. Liefert pro Mitglied SID + Anzeige­name.
/// Lists the direct members of a local group via `NetLocalGroupGetMembers`
/// level 2. Returns SID + display name per member.
pub fn get_local_group_members(
    server: Option<&str>,
    group_name: &str,
) -> Result<Vec<LocalGroupMember>, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let group_w = to_wide_null(group_name);

    let mut buf_ptr: *mut u8 = std::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;
    let mut resume: usize = 0;

    // SAFETY: server_ptr ist null oder eine gültige PCWSTR; group_w ist eine
    // gültige null-terminierte UTF-16-Sequenz; buf_ptr ist OUT-Pointer, den
    // wir mit NetApiBufferFree wieder freigeben.
    // SAFETY: server_ptr is null or a valid PCWSTR; group_w is a valid null-
    // terminated UTF-16 sequence; buf_ptr is an OUT pointer freed below via
    // NetApiBufferFree.
    let status = unsafe {
        NetLocalGroupGetMembers(
            server_ptr,
            group_w.as_ptr(),
            2,
            &mut buf_ptr,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
            &mut resume,
        )
    };

    if status != NO_ERROR {
        if !buf_ptr.is_null() {
            unsafe { NetApiBufferFree(buf_ptr.cast()) };
        }
        return match status {
            ERROR_ACCESS_DENIED => Err(CoreError::AccessDenied(format!(
                "NetLocalGroupGetMembers: access denied for '{group_name}' on {server:?}"
            ))),
            _ => Err(CoreError::LdapQuery(format!(
                "NetLocalGroupGetMembers('{group_name}') failed with status {status}"
            ))),
        };
    }

    let mut members = Vec::with_capacity(entries_read as usize);
    if !buf_ptr.is_null() && entries_read > 0 {
        // SAFETY: NetApi liefert genau entries_read konsekutive Strukturen.
        // SAFETY: NetApi returns exactly entries_read consecutive structs.
        let entries = unsafe {
            std::slice::from_raw_parts(
                buf_ptr as *const LOCALGROUP_MEMBERS_INFO_2,
                entries_read as usize,
            )
        };
        for e in entries {
            // SID via ConvertSidToStringSidW.
            let sid = if e.lgrmi2_sid.is_null() {
                None
            } else {
                let mut sid_str_ptr: *mut u16 = std::ptr::null_mut();
                // SAFETY: lgrmi2_sid ist eine gültige PSID aus dem NetApi-Buffer.
                // SAFETY: lgrmi2_sid is a valid PSID from the NetApi buffer.
                let ok = unsafe { ConvertSidToStringSidW(e.lgrmi2_sid, &mut sid_str_ptr) };
                if ok == FALSE || sid_str_ptr.is_null() {
                    None
                } else {
                    // SAFETY: sid_str_ptr ist eine null-terminierte UTF-16-Sequenz, von
                    // LocalAlloc allokiert; wir geben sie unten mit LocalFree frei.
                    // SAFETY: sid_str_ptr is a null-terminated UTF-16 sequence allocated
                    // via LocalAlloc; freed below with LocalFree.
                    let s = unsafe { wide_ptr_to_string(sid_str_ptr) };
                    unsafe { LocalFree(sid_str_ptr.cast()) };
                    if s.is_empty() {
                        None
                    } else {
                        Some(Sid(s))
                    }
                }
            };
            // SAFETY: lgrmi2_domainandname ist eine null-terminierte
            // UTF-16-Sequenz im NetApi-Buffer (oder null).
            // SAFETY: lgrmi2_domainandname is a null-terminated UTF-16
            // sequence inside the NetApi buffer (or null).
            let name = unsafe { wide_ptr_to_string(e.lgrmi2_domainandname) };
            let display_name = if name.is_empty() { None } else { Some(name) };
            members.push(LocalGroupMember { sid, display_name });
        }
    }

    if !buf_ptr.is_null() {
        unsafe { NetApiBufferFree(buf_ptr.cast()) };
    }
    Ok(members)
}

/// Rekonstruiert konkrete Mitgliedschafts-Ketten für jede lokale Gruppe,
/// in der `user_sid` direkt oder transitiv enthalten ist.
///
/// Vorgehen pro lokaler Gruppe `L`:
/// 1. Mitglieder von `L` via [`get_local_group_members`] holen.
/// 2. Ist die eigene `user_sid` als Mitglied gelistet → Kette `[user → L]`,
///    `complete = true`, Quelle `LocalGroup`.
/// 3. Ist ein bekannter Token-SID (Eigen-SID oder eine vom Aufrufer
///    gelieferte Domain-Gruppe) als Mitglied gelistet → Kette
///    `[user → vermittler → L]`, `complete = true`.
/// 4. Sonst Kette `[user, L]`, `complete = false` mit Quelle `LocalGroup`
///    (es ist über eine weitere lokale Gruppe verschachtelt; das auflösen
///    wir in einer späteren Ausbaustufe).
///
/// `known_member_sids_to_names` enthält die Domain-Gruppen, die der
/// Aufrufer aus `NetUserGetGroups` bereits aufgelöst hat, in der Form
/// `SID-String → Anzeigename`. Wird genutzt, um den Vermittler-Schritt 3
/// mit menschenlesbarem Namen zu beschriften.
///
/// Reconstructs concrete membership chains for every local group in which
/// `user_sid` is a direct or transitive member.
///
/// Per local group `L`:
/// 1. Fetch members of `L` via [`get_local_group_members`].
/// 2. If the user's own `user_sid` is listed → chain `[user → L]`,
///    `complete = true`, source `LocalGroup`.
/// 3. If a known token SID (own SID or a domain group supplied by the
///    caller) is listed → chain `[user → mediator → L]`,
///    `complete = true`.
/// 4. Otherwise chain `[user, L]`, `complete = false` with source
///    `LocalGroup` (nested via another local group — a later iteration
///    can resolve those).
///
/// `known_member_sids_to_names` carries the domain groups the caller has
/// already resolved via `NetUserGetGroups`, as `SID string → display name`.
/// Used to label the mediator step in case 3 with a human-readable name.
pub fn resolve_local_group_chains(
    server: Option<&str>,
    user_sid: &Sid,
    user_name: Option<&str>,
    known_member_sids_to_names: &std::collections::HashMap<String, String>,
    account: &str,
) -> Result<Vec<(Sid, Option<String>, MembershipPath)>, CoreError> {
    let local_groups = resolve_local_groups(server, account)?;
    let mut out: Vec<(Sid, Option<String>, MembershipPath)> = Vec::new();
    for lg in local_groups {
        let lg_display =
            lookup_account_for_sid_display(&lg.sid.0).unwrap_or_else(|| lg.name.clone());
        let members = match get_local_group_members(server, &lg.name) {
            Ok(m) => m,
            Err(e) => {
                // Wenn wir die Member nicht lesen koennen, bleibt die
                // Mitgliedschaft als bestaetigt (NetUserGetLocalGroups hat
                // sie ja geliefert) aber ohne konkreten Pfad — eine
                // sichtbare Annotation statt stillem Wegwerfen.
                // If we cannot read the members, the membership stays
                // confirmed (NetUserGetLocalGroups gave it to us) but
                // without a concrete path — a visible annotation rather
                // than a silent drop.
                debug!(local_group = %lg.name, error = %e, "members unreadable");
                out.push((
                    lg.sid.clone(),
                    Some(lg_display.clone()),
                    MembershipPath {
                        nodes: vec![user_sid.clone(), lg.sid.clone()],
                        names: vec![user_name.map(str::to_owned), Some(lg_display.clone())],
                        source: MembershipPathSource::LocalGroup,
                        complete: false,
                    },
                ));
                continue;
            }
        };

        // Kandidaten-Member-SIDs nach Reihenfolge der Präferenz:
        //   1. user_sid direkt → Kette mit 2 Knoten
        //   2. eine bekannte Token-SID (Eigene oder Domain-Gruppe) →
        //      Kette mit 3 Knoten (user → vermittler → L)
        // Candidate member SIDs in order of preference:
        //   1. user_sid directly → 2-node chain
        //   2. a known token SID (own or a domain group) → 3-node chain
        //      (user → mediator → L)
        let mut chain_via_self = false;
        let mut mediator: Option<(Sid, Option<String>)> = None;
        for m in &members {
            let Some(ref msid) = m.sid else { continue };
            if msid.0 == user_sid.0 {
                chain_via_self = true;
                break;
            }
            if mediator.is_none() {
                if let Some(name) = known_member_sids_to_names.get(&msid.0) {
                    mediator = Some((msid.clone(), Some(name.clone())));
                }
            }
        }

        let path = if chain_via_self {
            MembershipPath {
                nodes: vec![user_sid.clone(), lg.sid.clone()],
                names: vec![user_name.map(str::to_owned), Some(lg_display.clone())],
                source: MembershipPathSource::LocalGroup,
                complete: true,
            }
        } else if let Some((med_sid, med_name)) = mediator {
            MembershipPath {
                nodes: vec![user_sid.clone(), med_sid.clone(), lg.sid.clone()],
                names: vec![
                    user_name.map(str::to_owned),
                    med_name,
                    Some(lg_display.clone()),
                ],
                source: MembershipPathSource::LocalGroup,
                complete: true,
            }
        } else {
            // Vermutlich ueber eine andere lokale Gruppe verschachtelt —
            // ehrlich als incomplete kennzeichnen.
            // Likely nested via another local group — honestly flag as
            // incomplete.
            MembershipPath {
                nodes: vec![user_sid.clone(), lg.sid.clone()],
                names: vec![user_name.map(str::to_owned), Some(lg_display.clone())],
                source: MembershipPathSource::LocalGroup,
                complete: false,
            }
        };

        out.push((lg.sid, Some(lg_display), path));
    }
    Ok(out)
}

/// Identity-Variante von [`resolve_local_group_chains`] mit
/// Kandidaten-Loop analog zu [`resolve_local_group_sids_for_identity`].
/// Liefert `Vec<GroupMembership>` mit `MembershipPathSource::LocalGroup`,
/// damit der Berechtigungspfad jede lokale Servergruppe als Schritt
/// `Member of BUILTIN\\Administrators [source: LocalGroup]` ausweisen
/// kann.
///
/// Schließt Review 2026-06-05 Runde 6 Finding 1: die alte
/// `_sids_for_identity`-Variante lieferte nur SIDs für den Token-Bau —
/// damit war die Berechtigungsberechnung korrekt, aber der
/// Erklärungspfad lückenhaft. Aufrufer sehen jetzt zusätzlich die
/// Pfade.
///
/// Identity-aware variant of [`resolve_local_group_chains`] using the
/// same candidate-list loop as [`resolve_local_group_sids_for_identity`].
/// Returns `Vec<GroupMembership>` with
/// `MembershipPathSource::LocalGroup` so the explanation path renders
/// each local server group as a `Member of …` step.
pub fn resolve_local_group_chains_for_identity(
    server: Option<&str>,
    identity: &Identity,
    known_member_sids_to_names: &std::collections::HashMap<String, String>,
) -> Result<Vec<GroupMembership>, CoreError> {
    let candidates = format_account_candidates_for_local_groups(identity);
    if candidates.is_empty() {
        return Err(CoreError::Validation(format!(
            "Local group chains: no usable account name form derivable from identity {}",
            identity.sid.0
        )));
    }
    let user_name = identity.name.as_deref();
    let mut tried: Vec<String> = Vec::with_capacity(candidates.len());
    let mut last_err: Option<CoreError> = None;
    for candidate in &candidates {
        tried.push(candidate.clone());
        // Erst kurz pruefen ob der Account ueberhaupt auf dem Server
        // bekannt ist — wir nutzen die strict-Variante, die NERR_USER_
        // NOT_FOUND klar von "gefunden, keine Gruppen" trennt.
        // Probe via the strict variant first to separate
        // UserNotFoundOnServer from "found, no groups".
        match resolve_local_group_sids_strict(server, candidate) {
            Ok(LocalGroupLookupOutcome::UserNotFoundOnServer) => continue,
            Ok(LocalGroupLookupOutcome::WithGroups(_)) => {
                // Account bekannt — jetzt die Ketten mit demselben Namen
                // bauen, damit Mitgliederrekonstruktion ueber denselben
                // Account-Bezug laeuft.
                // Account known — reconstruct chains with the same name.
                match resolve_local_group_chains(
                    server,
                    &identity.sid,
                    user_name,
                    known_member_sids_to_names,
                    candidate,
                ) {
                    Ok(chains) => {
                        let memberships: Vec<GroupMembership> = chains
                            .into_iter()
                            .map(|(group_sid, group_name, path)| GroupMembership {
                                member_sid: identity.sid.clone(),
                                group_sid,
                                // direct = path über 2 Knoten + complete:
                                // direkte Mitgliedschaft auf der lokalen
                                // Gruppe; bei Mediator-Pfad (3 Knoten) ist
                                // sie transitiv.
                                // direct = 2-node complete path; mediator
                                // chain (3 nodes) is transitive.
                                direct: path.nodes.len() == 2 && path.complete,
                                group_name,
                                path: Some(path),
                            })
                            .collect();
                        return Ok(memberships);
                    }
                    Err(e) => {
                        last_err = Some(e);
                        // resolve_local_group_chains hat fuer diesen
                        // Kandidaten technisch gescheitert (z. B.
                        // NetLocalGroupGetMembers-Fehler). Wir versuchen
                        // den naechsten Kandidaten — vielleicht wird der
                        // Account dort mit anderem Namen gefunden.
                        // chains call failed for this candidate (e.g.
                        // NetLocalGroupGetMembers error); try next.
                        continue;
                    }
                }
            }
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        }
    }
    // Kein Kandidat erkannt — wenn wir unterwegs einen technischen
    // Fehler hatten, geben wir den weiter; sonst Validation.
    // No candidate matched — propagate technical error if any.
    if let Some(e) = last_err {
        return Err(e);
    }
    Err(CoreError::Validation(format!(
        "Local group chains: no account form for identity {} known on {server:?} \
         (tried: {:?}). Local server group memberships are not available; the result \
         is marked incomplete.",
        identity.sid.0, tried
    )))
}

/// Liefert die `DOMAIN\Name`-Darstellung einer SID per LookupAccountSidW —
/// kleine Variante speziell für den Anzeige­namen der lokalen Gruppe.
/// Returns the `DOMAIN\name` form of a SID via LookupAccountSidW — small
/// variant just for the local group's display label.
fn lookup_account_for_sid_display(sid_str: &str) -> Option<String> {
    use crate::sam::lookup_account_for_sid;
    let info = lookup_account_for_sid(sid_str).ok()?;
    if info.domain.is_empty() {
        Some(info.name)
    } else {
        Some(format!("{}\\{}", info.domain, info.name))
    }
}

/// Konvertiert einen Rust-String in eine null-terminierte UTF-16-Sequenz.
/// Converts a Rust string into a null-terminated UTF-16 sequence.
fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// # Safety
/// `p` muss ein gueltiger Zeiger auf eine null-terminierte UTF-16-Sequenz sein
/// oder null.
/// `p` must be a valid pointer to a null-terminated UTF-16 sequence, or null.
unsafe fn wide_ptr_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let len = (0usize..).take_while(|&i| *p.add(i) != 0).count();
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

/// Schlaegt einen Kontonamen auf dem angegebenen System nach und gibt die SID
/// als kanonischen S-R-I-...-String zurueck.
/// Looks up an account name on the given system and returns its SID as the
/// canonical S-R-I-... string.
fn lookup_account_sid(system: Option<&str>, name: &str) -> Option<String> {
    let system_w = system.map(to_wide_null);
    let system_ptr = system_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let name_w = to_wide_null(name);

    // Zwei-Schritt-Pattern: erst Groessen ermitteln, dann mit allokierten Puffern aufrufen.
    // Two-call pattern: query required sizes first, then call with the allocated buffers.
    let mut sid_size: u32 = 0;
    let mut domain_size: u32 = 0;
    let mut sid_use: i32 = 0;
    // SAFETY: name_w is a valid null-terminated wide string. Output pointers may be null
    // on the sizing call; Windows returns the required sizes via sid_size/domain_size.
    unsafe {
        LookupAccountNameW(
            system_ptr,
            name_w.as_ptr(),
            std::ptr::null_mut(),
            &mut sid_size,
            std::ptr::null_mut(),
            &mut domain_size,
            &mut sid_use,
        );
    }
    if sid_size == 0 {
        return None;
    }

    let mut sid_buf = vec![0u8; sid_size as usize];
    let mut domain_buf = vec![0u16; domain_size as usize];
    // SAFETY: buffers are sized per the previous sizing call.
    let ok = unsafe {
        LookupAccountNameW(
            system_ptr,
            name_w.as_ptr(),
            sid_buf.as_mut_ptr() as *mut _,
            &mut sid_size,
            domain_buf.as_mut_ptr(),
            &mut domain_size,
            &mut sid_use,
        )
    };
    if ok == FALSE {
        return None;
    }

    let mut sid_str: *mut u16 = std::ptr::null_mut();
    // SAFETY: sid_buf contains a valid SID written by LookupAccountNameW.
    let ok = unsafe { ConvertSidToStringSidW(sid_buf.as_ptr() as *mut _, &mut sid_str) };
    if ok == FALSE {
        return None;
    }
    // SAFETY: sid_str was allocated by Windows via LocalAlloc; we free it below.
    let s = unsafe { wide_ptr_to_string(sid_str) };
    unsafe { LocalFree(sid_str as *mut _) };
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lokaler Sanity-Check: Der eingebaute `Administrator` ist Mitglied der
    /// lokalen Gruppe `Administrators` (`BUILTIN\Administrators`, SID
    /// `S-1-5-32-544`).
    ///
    /// `#[ignore]` weil GitHub-Actions-Runner einen anderen Admin-Account-
    /// Layout haben (built-in `Administrator` ist oft deaktiviert oder
    /// existiert gar nicht; der CI-User heißt `runneradmin`). Auf einem
    /// normalen Windows lokal läuft der Test grün — explizit per
    /// `cargo test -- --ignored` auslösbar.
    ///
    /// Local sanity check: the built-in `Administrator` is a member of the
    /// local `Administrators` group (`BUILTIN\Administrators`, SID
    /// `S-1-5-32-544`).
    ///
    /// `#[ignore]` because GitHub Actions runners use a different admin
    /// account layout (built-in `Administrator` is often disabled or does
    /// not exist; the CI user is `runneradmin`). On a normal local Windows
    /// box the test passes — run explicitly via `cargo test -- --ignored`.
    #[test]
    #[ignore = "depends on local Administrator being enabled — fails on GitHub windows-latest"]
    fn administrator_is_in_local_administrators() {
        let sids = resolve_local_group_sids(None, "Administrator")
            .expect("NetUserGetLocalGroups for local Administrator must succeed");
        assert!(
            sids.iter().any(|s| s.0 == "S-1-5-32-544"),
            "Administrator must be in BUILTIN\\Administrators (S-1-5-32-544); got: {:?}",
            sids.iter().map(|s| s.0.as_str()).collect::<Vec<_>>()
        );
    }

    /// Unbekannter Benutzer liefert eine leere Liste ohne Fehler.
    /// Unknown user returns an empty list without an error.
    #[test]
    fn unknown_user_returns_empty() {
        let sids = resolve_local_group_sids(None, "definitely_not_a_real_user_zz_9f3a8b")
            .expect("call must succeed even for unknown users");
        assert!(sids.is_empty());
    }

    use adpa_core::model::IdentityKind;

    fn identity_with(name: Option<&str>, domain: Option<&str>, upn: Option<&str>) -> Identity {
        Identity {
            sid: Sid("S-1-5-21-1-2-3-1000".into()),
            name: name.map(String::from),
            domain: domain.map(String::from),
            kind: IdentityKind::User,
            disabled: false,
            user_principal_name: upn.map(String::from),
        }
    }

    #[test]
    fn format_prefers_upn_when_present() {
        let id = identity_with(
            Some("max.mustermann"),
            Some("testdomain.local"),
            Some("max@corp.example"),
        );
        assert_eq!(
            format_account_for_local_groups(&id).as_deref(),
            Some("max@corp.example")
        );
    }

    /// Review 2026-06-04 Runde 5 Finding 1: ohne UPN ist `DOMAIN\name`
    /// die erste Wahl (statt `name@domain`). Für eine DNS-artige Domain
    /// muss aber `name@dns` weiterhin als Fallback in der Kandidatenliste
    /// auftauchen.
    /// Round 5 finding 1: without UPN, prefer `DOMAIN\name`; DNS suffixes
    /// still get a UPN-style fallback in the candidate list.
    #[test]
    fn format_falls_back_to_domain_backslash_name_for_dns_domain() {
        let id = identity_with(Some("max.mustermann"), Some("testdomain.local"), None);
        let candidates = format_account_candidates_for_local_groups(&id);
        assert_eq!(candidates[0], "testdomain.local\\max.mustermann");
        assert!(
            candidates.contains(&"max.mustermann@testdomain.local".to_string()),
            "DNS-style domain must also produce the UPN-form fallback; got {candidates:?}"
        );
        // Convenience-Wrapper liefert den ersten Kandidaten.
        assert_eq!(
            format_account_for_local_groups(&id).as_deref(),
            Some("testdomain.local\\max.mustermann")
        );
    }

    /// Review 2026-06-04 Runde 5 Finding 1: bei einem NetBIOS-Domainnamen
    /// **darf** der `name@domain`-Fallback NICHT in der Kandidatenliste
    /// auftauchen — `alice@TRUSTED` ist kein gültiger UPN und führte
    /// produktiv zu stillen NERR_USER_NOT_FOUND.
    /// Round 5 finding 1: NetBIOS domain must NOT produce a `name@domain`
    /// candidate — that exact form was the production bug.
    #[test]
    fn format_netbios_domain_only_emits_domain_backslash_form() {
        let id = identity_with(Some("alice"), Some("TRUSTED"), None);
        let candidates = format_account_candidates_for_local_groups(&id);
        assert!(
            candidates.contains(&"TRUSTED\\alice".to_string()),
            "NetBIOS domain must produce DOMAIN\\name candidate; got {candidates:?}"
        );
        assert!(
            !candidates.contains(&"alice@TRUSTED".to_string()),
            "NetBIOS domain must NOT produce the misleading UPN-style form 'alice@TRUSTED' — that was the round 5 finding 1 bug; got {candidates:?}"
        );
    }

    #[test]
    fn format_returns_plain_name_without_domain() {
        let id = identity_with(Some("Administrator"), None, None);
        let candidates = format_account_candidates_for_local_groups(&id);
        assert_eq!(candidates, vec!["Administrator".to_string()]);
        assert_eq!(
            format_account_for_local_groups(&id).as_deref(),
            Some("Administrator")
        );
    }

    #[test]
    fn format_returns_empty_without_name() {
        let id = identity_with(None, Some("testdomain.local"), None);
        assert!(format_account_candidates_for_local_groups(&id).is_empty());
        assert_eq!(format_account_for_local_groups(&id), None);
    }

    #[test]
    fn format_ignores_empty_upn() {
        let id = identity_with(Some("Administrator"), Some("testdomain.local"), Some(""));
        // Empty UPN ist übersprungen, DOMAIN\name kommt zuerst (Round 5).
        // Empty UPN is skipped; DOMAIN\name comes first.
        assert_eq!(
            format_account_for_local_groups(&id).as_deref(),
            Some("testdomain.local\\Administrator")
        );
    }

    /// Heuristik: NetBIOS-Namen sind ohne Punkt, DNS-Suffixe haben Punkte.
    /// Heuristic: NetBIOS names have no dot; DNS suffixes do.
    #[test]
    fn looks_like_dns_domain_distinguishes_netbios_and_dns() {
        assert!(looks_like_dns_domain("corp.local"));
        assert!(looks_like_dns_domain("ad.example.com"));
        assert!(!looks_like_dns_domain("TRUSTED"));
        assert!(!looks_like_dns_domain("CORP"));
        assert!(!looks_like_dns_domain(".trailing"));
        assert!(!looks_like_dns_domain("leading."));
        assert!(!looks_like_dns_domain(""));
    }

    /// UPN-Eintrag hat absolute Priorität — auch wenn das Domain-Feld
    /// auf NetBIOS oder DNS gesetzt ist.
    /// UPN takes absolute priority.
    #[test]
    fn format_upn_wins_over_domain_form() {
        let id = identity_with(
            Some("alice"),
            Some("TRUSTED"),
            Some("alice@trusted.example"),
        );
        let candidates = format_account_candidates_for_local_groups(&id);
        assert_eq!(candidates[0], "alice@trusted.example");
    }
}
