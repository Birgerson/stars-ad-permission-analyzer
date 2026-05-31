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
    model::{Identity, Sid},
};
use tracing::{debug, warn};
use windows_sys::Win32::Foundation::{LocalFree, ERROR_ACCESS_DENIED, FALSE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetUserGetLocalGroups, LG_INCLUDE_INDIRECT, LOCALGROUP_USERS_INFO_0,
    MAX_PREFERRED_LENGTH,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::LookupAccountNameW;

/// User-Not-Found-Statuscode aus lmerr.h / NERR_UserNotFound from lmerr.h.
const NERR_USER_NOT_FOUND: u32 = 2221;

/// Formatiert den Accountnamen einer Identity für `NetUserGetLocalGroups`.
///
/// Reihenfolge der Präferenz:
/// 1. `userPrincipalName` (z. B. `max.mustermann@testdomain.local`) — robust,
///    funktioniert für Domain-Benutzer ohne NetBIOS-Wissen.
/// 2. `sAMAccountName @ DNS-Domain` als UPN-ähnliche Konstruktion (Fallback,
///    wenn `userPrincipalName` nicht gesetzt ist; bei abweichendem UPN-Suffix
///    kann das fehlschlagen).
/// 3. Reiner `name` (lokale Konten ohne Domain).
///
/// Liefert `None`, wenn keine sinnvolle Namensform abgeleitet werden kann.
///
/// Formats an Identity's account name for `NetUserGetLocalGroups`.
///
/// Preference order:
/// 1. `userPrincipalName` (e.g. `max.mustermann@testdomain.local`) — robust,
///    works for domain users without NetBIOS knowledge.
/// 2. `sAMAccountName @ DNS domain` as a UPN-style construction (fallback if
///    `userPrincipalName` is missing; may fail when the UPN suffix differs).
/// 3. Plain `name` (local accounts without a domain).
///
/// Returns `None` if no usable name form can be derived.
pub fn format_account_for_local_groups(identity: &Identity) -> Option<String> {
    if let Some(upn) = identity
        .user_principal_name
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        return Some(upn.to_string());
    }
    let name = identity.name.as_deref().filter(|s| !s.is_empty())?;
    match identity.domain.as_deref().filter(|s| !s.is_empty()) {
        Some(domain) => Some(format!("{name}@{domain}")),
        None => Some(name.to_string()),
    }
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
                // Benutzer ist auf dem Zielserver nicht bekannt — kein Fehler im
                // fachlichen Sinn, aber wir koennen keine lokalen Gruppen liefern.
                // Account is not known on the target server — not a domain-level
                // error, but we cannot return any local groups.
                debug!(
                    account,
                    ?server,
                    "NetUserGetLocalGroups: user not found on server"
                );
                Ok(Vec::new())
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

    Ok(sids)
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

    #[test]
    fn format_falls_back_to_sam_at_dns_domain() {
        let id = identity_with(Some("max.mustermann"), Some("testdomain.local"), None);
        assert_eq!(
            format_account_for_local_groups(&id).as_deref(),
            Some("max.mustermann@testdomain.local")
        );
    }

    #[test]
    fn format_returns_plain_name_without_domain() {
        let id = identity_with(Some("Administrator"), None, None);
        assert_eq!(
            format_account_for_local_groups(&id).as_deref(),
            Some("Administrator")
        );
    }

    #[test]
    fn format_returns_none_without_name() {
        let id = identity_with(None, Some("testdomain.local"), None);
        assert_eq!(format_account_for_local_groups(&id), None);
    }

    #[test]
    fn format_ignores_empty_upn() {
        let id = identity_with(Some("Administrator"), Some("testdomain.local"), Some(""));
        assert_eq!(
            format_account_for_local_groups(&id).as_deref(),
            Some("Administrator@testdomain.local")
        );
    }
}
