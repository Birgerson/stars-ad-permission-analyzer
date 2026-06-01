//! Identitäts- und Gruppenauflösung über die lokalen Windows-LSA/SAM-APIs.
//! Identity and group resolution via the local Windows LSA/SAM APIs.
//!
//! Auf einem Domain Controller (und in der Regel auch auf domänen-
//! eingebundenen Mitgliedern, sofern der Cache aktuell ist) liefert
//! Windows die vollständige Identitäts- und Gruppenmitgliedschaft eines
//! Benutzers über die SAM/LSA-Schnittstellen — ganz ohne LDAP-Bind. Genau
//! das ist der Pfad, den Windows beim Login intern auch geht.
//!
//! Dieses Modul bietet die Bausteine und einen Convenience-Aufruf
//! [`resolve_identity_via_sam`], der eine SID in ein vollständiges
//! `(Identity, Vec<GroupMembership>)`-Paar überführt:
//!   * `LookupAccountSidW` → Name, Domäne, Kind,
//!   * `NetUserGetGroups` → globale (Domänen-)Gruppen,
//!   * `NetUserGetLocalGroups` (über `local_groups`) → lokale Gruppen
//!     des Zielsystems,
//!   * `LookupAccountNameW` → SID je Gruppenname.
//!
//! Mit dieser Auflösung sieht das `permission_engine` denselben Token-
//! SID-Satz, den Windows beim echten Zugriff aufbauen würde — und
//! `BUILTIN\Administrators` taucht für den Administrator auch ohne
//! LDAP-Verbindung im Token auf.
//!
//! On a domain controller (and usually on domain-joined members with a
//! current cache) Windows can supply the full identity and group
//! membership of an account via the SAM/LSA interfaces — no LDAP bind
//! required. This is exactly the path Windows itself walks during a
//! logon.
//!
//! This module provides the building blocks and a convenience call
//! [`resolve_identity_via_sam`] that turns a SID into a complete
//! `(Identity, Vec<GroupMembership>)` pair:
//!   * `LookupAccountSidW` → name, domain, kind,
//!   * `NetUserGetGroups` → global (domain) groups,
//!   * `NetUserGetLocalGroups` (via `local_groups`) → local groups on
//!     the target system,
//!   * `LookupAccountNameW` → SID per group name.
//!
//! With this resolution the `permission_engine` sees the same set of
//! token SIDs Windows would build for the real access — and
//! `BUILTIN\Administrators` shows up for the Administrator account
//! even without an LDAP connection.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use adpa_core::error::CoreError;
use adpa_core::model::{
    GroupMembership, Identity, IdentityKind, MembershipPath, MembershipPathSource, Sid,
};
use tracing::{debug, warn};
use windows_sys::Win32::Foundation::{LocalFree, ERROR_ACCESS_DENIED, FALSE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetUserGetGroups, GROUP_USERS_INFO_0, MAX_PREFERRED_LENGTH,
};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{
    LookupAccountNameW, LookupAccountSidW, SidTypeAlias, SidTypeComputer, SidTypeDeletedAccount,
    SidTypeGroup, SidTypeInvalid, SidTypeUnknown, SidTypeUser, SidTypeWellKnownGroup,
};

use crate::local_groups::resolve_local_group_sids;

/// User-Not-Found-Statuscode aus lmerr.h / NERR_UserNotFound from lmerr.h.
const NERR_USER_NOT_FOUND: u32 = 2221;

/// Auflösungsergebnis von `LookupAccountSidW`.
/// Resolution result of `LookupAccountSidW`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountInfo {
    /// Kontoname ohne Domänenpräfix, z. B. `Administrator`.
    /// Account name without domain prefix, e.g. `Administrator`.
    pub name: String,
    /// Authority-/Domänenname, z. B. `EXAMPLE` oder `BUILTIN`. Kann leer
    /// sein, wenn der SID-Typ keine Domäne hat (`SidTypeWellKnownGroup`
    /// in Sonderfällen).
    /// Authority/domain name, e.g. `EXAMPLE` or `BUILTIN`. May be empty
    /// when the SID type has no domain (rare `SidTypeWellKnownGroup`
    /// cases).
    pub domain: String,
    /// Kategorisiert das SID-Use-Feld aus der LSA-Antwort.
    /// Classifies the SID-Use field from the LSA response.
    pub kind: IdentityKind,
}

/// Schlägt einen SID-String über die lokale LSA nach und liefert Name,
/// Domäne und Kontotyp. Verwendet `ConvertStringSidToSidW` für die
/// String→Bytes-Konvertierung und `LookupAccountSidW` zur Auflösung.
/// Looks up a SID string via the local LSA and returns name, domain and
/// account kind. Uses `ConvertStringSidToSidW` for string-to-bytes
/// conversion and `LookupAccountSidW` for the lookup.
pub fn lookup_account_for_sid(sid_str: &str) -> Result<AccountInfo, CoreError> {
    let sid_w = to_wide_null(sid_str);
    let mut sid_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY: sid_w is a valid null-terminated wide string; sid_ptr is set
    // by Windows via LocalAlloc on success and must be released with
    // LocalFree below.
    let ok = unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut sid_ptr) };
    if ok == FALSE || sid_ptr.is_null() {
        return Err(CoreError::SidResolution(format!(
            "ConvertStringSidToSidW failed for '{sid_str}'"
        )));
    }

    let result = lookup_account_for_sid_ptr(sid_ptr);

    // SAFETY: sid_ptr was allocated by ConvertStringSidToSidW; LocalFree
    // is the documented release call.
    unsafe { LocalFree(sid_ptr) };
    result
}

fn lookup_account_for_sid_ptr(sid_ptr: *mut std::ffi::c_void) -> Result<AccountInfo, CoreError> {
    let mut name_size: u32 = 0;
    let mut domain_size: u32 = 0;
    let mut sid_use: i32 = 0;

    // Zwei-Schritt-Pattern: erst Größen ermitteln (Aufruf liefert
    // ERROR_INSUFFICIENT_BUFFER und setzt die nötigen Größen).
    // Two-call pattern: query required sizes first (the call returns
    // ERROR_INSUFFICIENT_BUFFER and writes the sizes).
    // SAFETY: sid_ptr is a valid SID buffer; output pointers may be null
    // on the sizing call.
    unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid_ptr,
            std::ptr::null_mut(),
            &mut name_size,
            std::ptr::null_mut(),
            &mut domain_size,
            &mut sid_use,
        );
    }

    if name_size == 0 {
        return Err(CoreError::SidResolution(
            "LookupAccountSidW: SID has no name on this system".to_owned(),
        ));
    }

    let mut name_buf = vec![0u16; name_size as usize];
    let mut domain_buf = vec![0u16; domain_size as usize];

    // SAFETY: buffers are sized per the sizing call.
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid_ptr,
            name_buf.as_mut_ptr(),
            &mut name_size,
            domain_buf.as_mut_ptr(),
            &mut domain_size,
            &mut sid_use,
        )
    };
    if ok == FALSE {
        return Err(CoreError::SidResolution(
            "LookupAccountSidW failed on the second call".to_owned(),
        ));
    }

    Ok(AccountInfo {
        name: wide_buf_to_string(&name_buf),
        domain: wide_buf_to_string(&domain_buf),
        kind: sid_use_to_kind(sid_use),
    })
}

/// Liefert die globalen (Domänen-)Gruppen, in denen `username` direktes
/// Mitglied ist. `NetUserGetGroups` ist die Domänen-Variante zu
/// `NetUserGetLocalGroups` und liefert keine geerbten Mitgliedschaften
/// (die deckt der LSA-Token-Bau separat ab).
/// Returns the global (domain) groups `username` is a direct member of.
/// `NetUserGetGroups` is the domain counterpart to
/// `NetUserGetLocalGroups` and does not include nested memberships
/// (those are handled separately during LSA token construction).
pub fn user_global_group_names(
    server: Option<&str>,
    username: &str,
) -> Result<Vec<String>, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let username_w = to_wide_null(username);

    let mut buf_ptr: *mut u8 = std::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;

    // SAFETY: server_ptr is either null or points to a valid null-terminated
    // wide string; username_w is null-terminated. buf_ptr is an OUT pointer
    // that NetApi allocates on success and we free below.
    let status = unsafe {
        NetUserGetGroups(
            server_ptr,
            username_w.as_ptr(),
            0, // level 0 = GROUP_USERS_INFO_0
            &mut buf_ptr,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
        )
    };

    if status != NO_ERROR {
        if !buf_ptr.is_null() {
            // SAFETY: buf_ptr was allocated by NetApi.
            unsafe { NetApiBufferFree(buf_ptr.cast()) };
        }
        return match status {
            ERROR_ACCESS_DENIED => Err(CoreError::AccessDenied(format!(
                "NetUserGetGroups: access denied for '{username}' on {server:?}"
            ))),
            NERR_USER_NOT_FOUND => {
                debug!(username, ?server, "NetUserGetGroups: user not found");
                Ok(Vec::new())
            }
            _ => Err(CoreError::LdapQuery(format!(
                "NetUserGetGroups('{username}') failed with status {status}"
            ))),
        };
    }

    let mut groups = Vec::with_capacity(entries_read as usize);
    if !buf_ptr.is_null() && entries_read > 0 {
        // SAFETY: buf_ptr points to `entries_read` consecutive
        // GROUP_USERS_INFO_0 records allocated by NetApi.
        let entries = unsafe {
            std::slice::from_raw_parts(buf_ptr as *const GROUP_USERS_INFO_0, entries_read as usize)
        };
        for entry in entries {
            // SAFETY: grui0_name is a valid null-terminated wide string
            // inside the NetApi-allocated buffer.
            let name = unsafe { wide_ptr_to_string(entry.grui0_name) };
            if !name.is_empty() {
                groups.push(name);
            }
        }
    }

    if !buf_ptr.is_null() {
        // SAFETY: buf_ptr was allocated by NetApi.
        unsafe { NetApiBufferFree(buf_ptr.cast()) };
    }

    Ok(groups)
}

/// Schlägt einen Konto- oder Gruppennamen auf dem angegebenen System
/// nach und gibt die SID als kanonischen S-R-I-...-String zurück.
/// Looks up an account or group name on the given system and returns
/// its SID as the canonical S-R-I-... string.
pub fn lookup_sid_for_account(system: Option<&str>, name: &str) -> Result<Sid, CoreError> {
    let system_w = system.map(to_wide_null);
    let system_ptr = system_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
    let name_w = to_wide_null(name);

    let mut sid_size: u32 = 0;
    let mut domain_size: u32 = 0;
    let mut sid_use: i32 = 0;
    // SAFETY: name_w is null-terminated; output pointers may be null on
    // the sizing call.
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
        return Err(CoreError::SidResolution(format!(
            "LookupAccountNameW: '{name}' has no SID on this system"
        )));
    }

    let mut sid_buf = vec![0u8; sid_size as usize];
    let mut domain_buf = vec![0u16; domain_size as usize];
    // SAFETY: buffers are sized per the sizing call.
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
        return Err(CoreError::SidResolution(format!(
            "LookupAccountNameW failed for '{name}'"
        )));
    }

    let mut sid_str: *mut u16 = std::ptr::null_mut();
    // SAFETY: sid_buf contains a valid SID written by LookupAccountNameW.
    let ok = unsafe { ConvertSidToStringSidW(sid_buf.as_ptr() as *mut _, &mut sid_str) };
    if ok == FALSE || sid_str.is_null() {
        return Err(CoreError::SidResolution(format!(
            "ConvertSidToStringSidW failed for '{name}'"
        )));
    }
    // SAFETY: sid_str was allocated by Windows via LocalAlloc.
    let s = unsafe { wide_ptr_to_string(sid_str) };
    // SAFETY: sid_str must be released with LocalFree per the API contract.
    unsafe { LocalFree(sid_str as *mut _) };
    Ok(Sid(s))
}

/// Convenience-Funktion, die `lookup_account_for_sid` +
/// `user_global_group_names` + `resolve_local_group_sids` kombiniert und das
/// Ergebnis in den fachlichen Typen `Identity` und `GroupMembership`
/// zurückgibt.
///
/// Auf einem Domain Controller ergibt das genau die Token-SID-Liste, die
/// Windows beim Aufbau eines Access Tokens für den Benutzer auch zusammenstellt
/// — inklusive `BUILTIN\Administrators`, wenn der Benutzer (direkt oder über
/// eine Domänengruppe) in dieser lokalen Gruppe ist.
///
/// Convenience wrapper combining `lookup_account_for_sid` +
/// `user_global_group_names` + `resolve_local_group_sids`, returning the
/// result in the domain types `Identity` and `GroupMembership`.
///
/// On a domain controller this produces exactly the token-SID list Windows
/// itself would assemble when building an access token for the user —
/// including `BUILTIN\Administrators` when the user is (directly or via a
/// domain group) in that local group.
pub fn resolve_identity_via_sam(
    sid_str: &str,
) -> Result<(Identity, Vec<GroupMembership>), CoreError> {
    let account = lookup_account_for_sid(sid_str)?;
    let account_kind = account.kind.clone();

    let identity = Identity {
        sid: Sid(sid_str.to_owned()),
        name: Some(account.name.clone()),
        domain: if account.domain.is_empty() {
            None
        } else {
            Some(account.domain.clone())
        },
        kind: account.kind,
        // Deaktiviert-Status lässt sich nicht ohne weitere SAM-Calls
        // (NetUserGetInfo Level 1+, mit UF_ACCOUNTDISABLE-Flag) ermitteln
        // — solange das nicht gebraucht wird, bleibt das Default-false. Das
        // ist konservativ, weil die Berechtigungsberechnung disabled-User
        // ohnehin als „Identität existiert" behandelt.
        // Disabled status cannot be derived without further SAM calls
        // (NetUserGetInfo level 1+ with the UF_ACCOUNTDISABLE flag). Until
        // we need it this stays at the default `false`, which is
        // conservative because the permission engine treats disabled users
        // as "identity exists" anyway.
        disabled: false,
        user_principal_name: None,
    };

    // Globale Gruppen nur sinnvoll für User-Konten.
    // Global groups only meaningful for user accounts.
    let mut memberships: Vec<GroupMembership> = Vec::new();
    if matches!(account_kind, IdentityKind::User) {
        match user_global_group_names(None, &account.name) {
            Ok(names) => {
                for group_name in names {
                    match lookup_sid_for_account(None, &group_name) {
                        Ok(group_sid) => {
                            let member_sid_val = Sid(sid_str.to_owned());
                            memberships.push(GroupMembership {
                                member_sid: member_sid_val.clone(),
                                group_sid: group_sid.clone(),
                                direct: true,
                                // NetUserGetGroups liefert den Namen direkt;
                                // den geben wir 1:1 weiter.
                                // NetUserGetGroups returns the name directly;
                                // we pass it through verbatim.
                                group_name: Some(group_name.clone()),
                                // SAM/NetAPI liefert eine flache Liste —
                                // wir kennen nur Benutzer → Gruppe als
                                // direkte Kante; verschachtelte Beziehungen
                                // (nested groups) sind über diese API nicht
                                // sichtbar. Pfad bleibt zwei SIDs lang und
                                // gilt als vollständig für die direkte
                                // Kante.
                                // SAM/NetAPI returns a flat list — only the
                                // user → group direct edge is visible;
                                // nested relationships are not exposed
                                // through this API. The path stays two SIDs
                                // long and is considered complete for the
                                // direct edge.
                                path: Some(MembershipPath {
                                    nodes: vec![member_sid_val, group_sid],
                                    names: vec![
                                        Some(account.name.clone()),
                                        Some(group_name.clone()),
                                    ],
                                    source: MembershipPathSource::DomainGroup,
                                    complete: true,
                                }),
                            });
                        }
                        Err(e) => warn!(
                            group_name,
                            error = %e,
                            "SAM: could not resolve domain group name to SID"
                        ),
                    }
                }
            }
            Err(e) => warn!(
                error = %e,
                "SAM: NetUserGetGroups failed; falling back to local groups only"
            ),
        }

        match resolve_local_group_sids(None, &account.name) {
            Ok(local_sids) => {
                for group_sid in local_sids {
                    // Lokale Gruppen-SID rückwärts in `DOMAIN\Name` auflösen,
                    // damit der Erklärungstext z. B. `BUILTIN\Administrators`
                    // statt nur `S-1-5-32-544` zeigt. Schlägt der Lookup fehl
                    // (sollte auf dem lokalen System nicht passieren), bleibt
                    // group_name = None und die Engine fällt auf die SID-
                    // Anzeige zurück.
                    // Reverse-resolve the local group SID into `DOMAIN\Name`
                    // so the explanation text shows e.g.
                    // `BUILTIN\Administrators` instead of just
                    // `S-1-5-32-544`. If the lookup fails (which should not
                    // happen on the local system) group_name stays None and
                    // the engine falls back to the SID display.
                    let group_name = lookup_account_for_sid(&group_sid.0).ok().map(|info| {
                        if info.domain.is_empty() {
                            info.name
                        } else {
                            format!("{}\\{}", info.domain, info.name)
                        }
                    });
                    let member_sid_val = Sid(sid_str.to_owned());
                    memberships.push(GroupMembership {
                        member_sid: member_sid_val.clone(),
                        group_sid: group_sid.clone(),
                        direct: false, // lokale Mitgliedschaft ggf. transitiv / local membership may be transitive
                        group_name: group_name.clone(),
                        // NetUserGetLocalGroups liefert die Endmenge der
                        // lokalen Gruppen, in denen der Benutzer enthalten
                        // ist — direkt oder über verschachtelte lokale
                        // Mitgliedschaften. Die konkrete Zwischenkette ist
                        // über diese API nicht ohne weiteres beobachtbar,
                        // daher markieren wir den Pfad als
                        // LdapMatchingRule mit `complete = false`. Wer den
                        // exakten Weg benötigt, kann später per
                        // NetLocalGroupGetMembers nachladen.
                        // NetUserGetLocalGroups returns the final set of
                        // local groups the user belongs to — either
                        // directly or via nested local memberships. The
                        // intermediate chain is not readily observable
                        // through this API, so we mark the path as
                        // LdapMatchingRule with `complete = false`. The
                        // exact route can be supplied later via
                        // NetLocalGroupGetMembers.
                        path: Some(MembershipPath {
                            nodes: vec![member_sid_val, group_sid],
                            names: vec![Some(account.name.clone()), group_name],
                            source: MembershipPathSource::LocalGroup,
                            complete: false,
                        }),
                    });
                }
            }
            Err(e) => warn!(
                error = %e,
                "SAM: NetUserGetLocalGroups failed; local group SIDs missing from token"
            ),
        }
    }

    Ok((identity, memberships))
}

/// Baut eine SID → Name-Übersetzungstabelle für die in `memberships`
/// enthaltenen Gruppen-SIDs und alle zusätzlich übergebenen SIDs auf
/// (z. B. ACE-Trustees aus der DACL des Zielobjekts).
///
/// Memberships, die selbst schon ein `group_name` tragen (vom LDAP- oder
/// SAM-Resolver gesetzt), übernehmen ihren Namen 1:1. Für alle übrigen
/// SIDs ruft die Funktion einmalig `lookup_account_for_sid` auf und
/// schreibt das Ergebnis als `DOMAIN\Name` (oder nur `Name`, wenn die
/// Authority leer ist) in die Tabelle. Nicht auflösbare SIDs erscheinen
/// nicht in der Map — die Engine fällt für sie auf die SID-Anzeige zurück
/// und schreibt nichts Erfundenes in den Erklärungstext.
///
/// Builds a SID → name lookup table for the group SIDs in `memberships`
/// plus any extra SIDs supplied (e.g. ACE trustees from the target's
/// DACL). Memberships that already carry a `group_name` (set by the
/// LDAP or SAM resolver) keep their name verbatim. All remaining SIDs
/// are resolved once via `lookup_account_for_sid` and the result is
/// stored as `DOMAIN\Name` (or just `Name` when the authority is
/// empty). SIDs that cannot be resolved are absent from the map — the
/// engine falls back to displaying the raw SID and never invents a
/// name in the explanation text.
pub fn build_sid_name_map<I>(
    memberships: &[GroupMembership],
    extra_sids: I,
) -> std::collections::BTreeMap<String, String>
where
    I: IntoIterator<Item = String>,
{
    use std::collections::{BTreeMap, HashSet};

    let mut map: BTreeMap<String, String> = BTreeMap::new();
    let mut tried: HashSet<String> = HashSet::new();

    // Memberships mit gesetztem Namen direkt übernehmen.
    // Memberships with a pre-set name go in verbatim.
    for m in memberships {
        if let Some(name) = m.group_name.as_deref().filter(|s| !s.is_empty()) {
            map.insert(m.group_sid.0.clone(), name.to_owned());
            tried.insert(m.group_sid.0.clone());
        }
    }

    // Restliche SIDs (Memberships ohne Namen + Extras) über LSA auflösen.
    // Resolve remaining SIDs (memberships without name + extras) via LSA.
    let candidates = memberships
        .iter()
        .map(|m| m.group_sid.0.clone())
        .chain(extra_sids);

    for sid in candidates {
        if !tried.insert(sid.clone()) {
            continue;
        }
        if let Ok(info) = lookup_account_for_sid(&sid) {
            let display = if info.domain.is_empty() {
                info.name
            } else {
                format!("{}\\{}", info.domain, info.name)
            };
            if !display.is_empty() {
                map.insert(sid, display);
            }
        }
    }

    map
}

/// Klassifiziert das `SID_NAME_USE`-Feld der LSA-Antwort.
/// Classifies the `SID_NAME_USE` field of the LSA response.
fn sid_use_to_kind(use_code: i32) -> IdentityKind {
    match use_code {
        x if x == SidTypeUser => IdentityKind::User,
        x if x == SidTypeGroup => IdentityKind::Group,
        x if x == SidTypeAlias => IdentityKind::Group,
        x if x == SidTypeWellKnownGroup => IdentityKind::WellKnown,
        x if x == SidTypeComputer => IdentityKind::Computer,
        x if x == SidTypeDeletedAccount => IdentityKind::Orphaned,
        x if x == SidTypeInvalid => IdentityKind::Unknown,
        x if x == SidTypeUnknown => IdentityKind::Unknown,
        _ => IdentityKind::Unknown,
    }
}

/// Konvertiert einen Rust-String in eine null-terminierte UTF-16-Sequenz.
/// Converts a Rust string to a null-terminated UTF-16 sequence.
fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// # Safety
/// `p` muss ein gültiger Zeiger auf eine null-terminierte UTF-16-Sequenz
/// sein oder null.
/// `p` must be a valid pointer to a null-terminated UTF-16 sequence, or
/// null.
unsafe fn wide_ptr_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let len = (0usize..).take_while(|&i| *p.add(i) != 0).count();
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

/// Stripped die abschließenden Nullen aus einem festen Puffer und liefert
/// den dekodierten String.
/// Strips trailing nulls from a fixed buffer and returns the decoded
/// string.
fn wide_buf_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Well-Known: `S-1-5-32-544` (auf en-US `BUILTIN\Administrators`,
    /// auf de-DE `VORDEFINIERT\Administratoren`). Beide Felder name +
    /// domain werden auf deutschen Systemen lokalisiert übersetzt —
    /// deshalb prüfen wir locale-unabhängig: Lookup gelingt, beide
    /// Strings sind nicht leer, Kind ist Group/WellKnown, und der
    /// Roundtrip `domain\name → SID` liefert die ursprüngliche SID.
    /// Well-known: `S-1-5-32-544` (on en-US `BUILTIN\Administrators`,
    /// on de-DE `VORDEFINIERT\Administratoren`). Both the name and the
    /// domain are localized on German installs — so the test asserts
    /// locale-independently: lookup succeeds, both strings are
    /// non-empty, kind is Group/WellKnown, and the `domain\name → SID`
    /// roundtrip recovers the original SID.
    #[test]
    fn lookup_well_known_builtin_administrators() {
        let info = lookup_account_for_sid("S-1-5-32-544")
            .expect("LookupAccountSidW must succeed for S-1-5-32-544");
        assert!(!info.name.is_empty(), "name must not be empty");
        assert!(!info.domain.is_empty(), "domain must not be empty");
        assert!(
            matches!(info.kind, IdentityKind::Group | IdentityKind::WellKnown),
            "S-1-5-32-544 must classify as Group or WellKnown, got: {:?}",
            info.kind
        );
        let qualified = format!("{}\\{}", info.domain, info.name);
        let sid_again = lookup_sid_for_account(None, &qualified)
            .expect("name → SID lookup must succeed for the recovered qualified name");
        assert_eq!(sid_again.0, "S-1-5-32-544");
    }

    /// Well-Known: `S-1-5-18` (auf en-US `NT AUTHORITY\SYSTEM`, auf
    /// de-DE `NT-AUTORITÄT\SYSTEM`). Wieder locale-unabhängige Asserts.
    /// Well-known: `S-1-5-18` (en-US `NT AUTHORITY\SYSTEM`, de-DE
    /// `NT-AUTORITÄT\SYSTEM`). Locale-independent assertions again.
    #[test]
    fn lookup_well_known_system() {
        let info = lookup_account_for_sid("S-1-5-18")
            .expect("LookupAccountSidW must succeed for S-1-5-18");
        assert!(!info.name.is_empty());
        assert!(!info.domain.is_empty());
        assert!(
            matches!(
                info.kind,
                IdentityKind::User | IdentityKind::Group | IdentityKind::WellKnown
            ),
            "S-1-5-18 must classify as User/Group/WellKnown, got: {:?}",
            info.kind
        );
        let qualified = format!("{}\\{}", info.domain, info.name);
        let sid_again =
            lookup_sid_for_account(None, &qualified).expect("name → SID lookup must succeed");
        assert_eq!(sid_again.0, "S-1-5-18");
    }

    /// Ungültige SID-Syntax muss einen `SidResolution`-Fehler ergeben,
    /// nicht panic'en.
    /// Invalid SID syntax must yield a `SidResolution` error, not a
    /// panic.
    #[test]
    fn invalid_sid_returns_resolution_error() {
        let err = lookup_account_for_sid("not-a-sid").expect_err("non-SID input must not succeed");
        match err {
            CoreError::SidResolution(_) => {}
            other => panic!("expected SidResolution, got {other:?}"),
        }
    }

    /// SID, die zwar syntaktisch korrekt ist, auf diesem System aber
    /// keinem Konto zugeordnet werden kann.
    /// Syntactically correct SID that has no account on this system.
    #[test]
    fn unmapped_but_valid_sid_returns_resolution_error() {
        // Fiktive SID in einer Domäne, die dieses System nicht kennt.
        // Fictional SID in a domain unknown to this system.
        let result = lookup_account_for_sid("S-1-5-21-9999999999-9999999999-9999999999-1234");
        assert!(
            matches!(result, Err(CoreError::SidResolution(_))),
            "unmapped SID should yield SidResolution error, got: {result:?}"
        );
    }

    /// DC-Test: liefert eine SAM-Auflösung des lokal eingebauten
    /// `Administrator`-Kontos überhaupt eine User-Identity inkl.
    /// mindestens einer Gruppenmitgliedschaft? `#[ignore]` weil das
    /// auf GitHub-Windows-Runnern (kein DC, Built-in-Administrator
    /// oft deaktiviert) nicht zuverlässig läuft.
    /// DC test: does SAM resolution of the built-in `Administrator`
    /// account yield a user identity with at least one group
    /// membership? `#[ignore]` because GitHub Windows runners (no DC,
    /// built-in Administrator usually disabled) do not run this
    /// reliably.
    #[test]
    #[ignore = "DC- oder Workstation-spezifisch; lokal mit `cargo test -- --ignored` ausführen"]
    fn resolve_local_administrator_yields_memberships() {
        let admin_sid = lookup_sid_for_account(None, "Administrator")
            .expect("local Administrator must resolve to a SID");
        let (identity, memberships) = resolve_identity_via_sam(&admin_sid.0)
            .expect("SAM resolution of local Administrator must succeed");
        assert!(matches!(identity.kind, IdentityKind::User));
        assert!(
            memberships.iter().any(|m| m.group_sid.0 == "S-1-5-32-544"),
            "Administrator must be in BUILTIN\\Administrators via SAM resolution"
        );
    }
}
