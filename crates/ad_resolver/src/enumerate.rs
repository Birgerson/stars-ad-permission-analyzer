// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Inventarisierung sichtbarer Identitäten für die UX-Suchhilfe.
//! Inventory of visible identities for the UX search helper.
//!
//! Liefert eine flache Liste von `IdentitySnapshot`-Einträgen, die den
//! Namen, Typ, Domäne und ggf. Beschreibung jeder Identität enthält. Wird
//! von der GUI **nicht** zur Berechtigungs­berechnung verwendet — die hängt
//! nur an SIDs und Token. Die Funktion dient ausschließlich der Autocomplete-
//! Hilfe im Namensfeld („du tippst, ich schlage vor").
//!
//! Returns a flat list of `IdentitySnapshot` entries with name, type,
//! domain and an optional description. **Not** used for permission
//! evaluation by the GUI — that only depends on SIDs and tokens. The
//! function exists purely for the autocomplete helper in the name field
//! ("you type, I suggest").
//!
//! **Datenquellen:**
//! * `NetUserEnum`         → Domänen-User (auf einer DC) bzw. lokale User
//! * `NetGroupEnum`        → globale (Domänen-)Gruppen
//! * `NetLocalGroupEnum`   → lokale Gruppen (BUILTIN\… auf der DC)
//! * Hartcodierte Well-Known-Tabelle für `Everyone`, `Authenticated Users`,
//!   `SYSTEM` usw. — diese SIDs lassen sich nicht enumerieren, sind aber
//!   audit-relevant.
//!
//! **Data sources:**
//! * `NetUserEnum`         → domain users (on a DC) / local users elsewhere
//! * `NetGroupEnum`        → global (domain) groups
//! * `NetLocalGroupEnum`   → local groups (BUILTIN\… on the DC)
//! * Hard-coded well-known table for `Everyone`, `Authenticated Users`,
//!   `SYSTEM` etc. — those SIDs are not enumerable but matter for audit.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use adpa_core::error::CoreError;
use adpa_core::model::IdentityKind;
use tracing::{debug, warn};
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, NO_ERROR};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetGroupEnum, NetLocalGroupEnum, NetUserEnum, NetWkstaGetInfo,
    FILTER_NORMAL_ACCOUNT, GROUP_INFO_1, LOCALGROUP_INFO_1, MAX_PREFERRED_LENGTH, USER_INFO_10,
    WKSTA_INFO_100,
};

/// Eine einzelne Identität, wie sie im Suchvorschlag erscheint.
/// A single identity as it appears in the search suggestions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentitySnapshot {
    /// Anmeldename ohne Domänen­präfix, z. B. `Administrator`.
    /// Logon name without domain prefix, e.g. `Administrator`.
    pub name: String,
    /// Authority/Domäne, z. B. `TESTDOMAIN`, `BUILTIN`, `NT AUTHORITY`, leer
    /// für nicht-domain-gebundene Well-Knowns wie `Everyone`.
    /// Authority/domain, e.g. `TESTDOMAIN`, `BUILTIN`, `NT AUTHORITY`, empty
    /// for non-domain well-knowns like `Everyone`.
    pub domain: String,
    pub kind: IdentityKind,
    /// Beschreibung aus den NetAPI-Strukturen (`usri10_comment`,
    /// `grpi1_comment`, `lgrpi1_comment`) oder eine kurze Eigen­erklärung
    /// für Well-Knowns. Leer, wenn nichts vorlag.
    /// Description from the NetAPI structs (`usri10_comment`,
    /// `grpi1_comment`, `lgrpi1_comment`) or a short hand-written gloss
    /// for well-knowns. Empty when none.
    pub description: String,
}

impl IdentitySnapshot {
    /// Klassifiziert den Eintrag als „passt der Suchstring zu mir?".
    /// Sucht **case-insensitive** in Name und Domäne, sodass z. B. `bui`
    /// auch `BUILTIN\Administrators` matcht.
    /// Classifies the entry as "does the search string match me?".
    /// Case-insensitive search over name + domain so e.g. `bui` matches
    /// `BUILTIN\Administrators`.
    pub fn matches(&self, query: &str) -> bool {
        let q = query.to_lowercase();
        self.name.to_lowercase().contains(&q) || self.domain.to_lowercase().contains(&q)
    }

    /// Anzeigeform `DOMÄNE\Name`, ohne Backslash wenn keine Domäne.
    /// Display form `DOMAIN\Name`, no backslash when no domain.
    pub fn qualified_name(&self) -> String {
        if self.domain.is_empty() {
            self.name.clone()
        } else {
            format!("{}\\{}", self.domain, self.name)
        }
    }
}

/// Sammelt alle Identitäten, die für die Suchvorschläge relevant sind.
/// Fehler aus einzelnen Datenquellen werden als Warnung geloggt und führen
/// **nicht** zum Abbruch — die anderen Quellen liefern weiter.
/// Collects all identities relevant for the search suggestions. Errors in
/// individual sources are logged as warnings and **do not** abort — the
/// other sources still contribute.
pub fn enumerate_all() -> Vec<IdentitySnapshot> {
    let netbios_domain = local_netbios_domain().unwrap_or_default();
    let mut out: Vec<IdentitySnapshot> = Vec::new();

    out.extend(well_known_table());

    match list_users(None, &netbios_domain) {
        Ok(mut v) => out.append(&mut v),
        Err(e) => warn!(error = %e, "enumerate_all: NetUserEnum failed"),
    }
    match list_global_groups(None, &netbios_domain) {
        Ok(mut v) => out.append(&mut v),
        Err(e) => warn!(error = %e, "enumerate_all: NetGroupEnum failed"),
    }
    match list_local_groups(None) {
        Ok(mut v) => out.append(&mut v),
        Err(e) => warn!(error = %e, "enumerate_all: NetLocalGroupEnum failed"),
    }

    // Stabile, vorhersagbare Sortierung: zuerst Domäne, dann Name (locale-
    // unabhängig durch case-insensitive Vergleich).
    // Stable, predictable ordering: first by domain, then by name
    // (locale-independent via case-insensitive comparison).
    out.sort_by(|a, b| {
        a.domain
            .to_lowercase()
            .cmp(&b.domain.to_lowercase())
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    out.dedup_by(|a, b| a.name == b.name && a.domain == b.domain);

    debug!(count = out.len(), "enumerate_all: snapshot built");
    out
}

// ---------------------------------------------------------------------------
// NetUserEnum — Level 10 liefert Name, Komment und Full Name
// ---------------------------------------------------------------------------

fn list_users(server: Option<&str>, domain: &str) -> Result<Vec<IdentitySnapshot>, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());

    let mut out: Vec<IdentitySnapshot> = Vec::new();
    let mut resume_handle: u32 = 0;

    loop {
        let mut buf_ptr: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;

        // SAFETY: server_ptr ist entweder null oder zeigt auf eine gültige
        // null-terminierte UTF-16-Sequenz. buf_ptr und die Counter sind
        // OUT-Parameter, die von NetAPI gesetzt werden. Der NetApi-Puffer
        // wird unten mit NetApiBufferFree freigegeben.
        // SAFETY: server_ptr is either null or points to a valid null-
        // terminated UTF-16 sequence. buf_ptr and counters are OUT
        // parameters set by NetAPI. The NetApi buffer is freed below
        // via NetApiBufferFree.
        let status = unsafe {
            NetUserEnum(
                server_ptr,
                10,                    // Level 10 = USER_INFO_10
                FILTER_NORMAL_ACCOUNT, // nur "normale" User, keine Trust- oder Service-Konten
                &mut buf_ptr,
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            )
        };

        if !buf_ptr.is_null() && entries_read > 0 {
            // SAFETY: buf_ptr verweist auf `entries_read` aufeinanderfolgende
            // USER_INFO_10-Strukturen, die von NetAPI allokiert wurden.
            // SAFETY: buf_ptr references `entries_read` consecutive
            // USER_INFO_10 structs allocated by NetAPI.
            let entries = unsafe {
                std::slice::from_raw_parts(buf_ptr as *const USER_INFO_10, entries_read as usize)
            };
            for entry in entries {
                // SAFETY: alle Felder sind null-terminierte UTF-16-Strings
                // im NetApi-Puffer.
                // SAFETY: all fields are null-terminated UTF-16 strings in
                // the NetApi buffer.
                let name = unsafe { wide_ptr_to_string(entry.usri10_name) };
                if name.is_empty() {
                    continue;
                }
                let comment = unsafe { wide_ptr_to_string(entry.usri10_comment) };
                let full = unsafe { wide_ptr_to_string(entry.usri10_full_name) };
                let description = if !comment.is_empty() { comment } else { full };
                out.push(IdentitySnapshot {
                    name,
                    domain: domain.to_string(),
                    kind: IdentityKind::User,
                    description,
                });
            }
        }
        if !buf_ptr.is_null() {
            // SAFETY: NetApi-Puffer freigeben.
            // SAFETY: free the NetApi buffer.
            unsafe { NetApiBufferFree(buf_ptr.cast()) };
        }

        if status == NO_ERROR {
            break;
        }
        if status != ERROR_MORE_DATA {
            return Err(CoreError::LdapQuery(format!(
                "NetUserEnum failed with status {status}"
            )));
        }
        // Bei MORE_DATA: nächste Seite mit dem aktualisierten resume_handle.
        // On MORE_DATA: next page using the updated resume_handle.
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// NetGroupEnum — globale (Domänen-)Gruppen via Level 1
// ---------------------------------------------------------------------------

fn list_global_groups(
    server: Option<&str>,
    domain: &str,
) -> Result<Vec<IdentitySnapshot>, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());

    let mut out: Vec<IdentitySnapshot> = Vec::new();
    let mut resume_handle: usize = 0;

    loop {
        let mut buf_ptr: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;

        // SAFETY: siehe oben. resume_handle wird von NetAPI fortgeschrieben.
        // SAFETY: as above. resume_handle is updated in-place by NetAPI.
        let status = unsafe {
            NetGroupEnum(
                server_ptr,
                1, // Level 1 = GROUP_INFO_1
                &mut buf_ptr,
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            )
        };

        if !buf_ptr.is_null() && entries_read > 0 {
            // SAFETY: GROUP_INFO_1-Array aus NetApi-Puffer.
            // SAFETY: GROUP_INFO_1 array from NetApi buffer.
            let entries = unsafe {
                std::slice::from_raw_parts(buf_ptr as *const GROUP_INFO_1, entries_read as usize)
            };
            for entry in entries {
                // SAFETY: null-terminierte UTF-16-Strings.
                // SAFETY: null-terminated UTF-16 strings.
                let name = unsafe { wide_ptr_to_string(entry.grpi1_name) };
                if name.is_empty() {
                    continue;
                }
                let description = unsafe { wide_ptr_to_string(entry.grpi1_comment) };
                out.push(IdentitySnapshot {
                    name,
                    domain: domain.to_string(),
                    kind: IdentityKind::Group,
                    description,
                });
            }
        }
        if !buf_ptr.is_null() {
            // SAFETY: NetApi-Puffer freigeben.
            // SAFETY: free the NetApi buffer.
            unsafe { NetApiBufferFree(buf_ptr.cast()) };
        }

        if status == NO_ERROR {
            break;
        }
        if status != ERROR_MORE_DATA {
            return Err(CoreError::LdapQuery(format!(
                "NetGroupEnum failed with status {status}"
            )));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// NetLocalGroupEnum — lokale Gruppen (BUILTIN\… auf einer DC)
// ---------------------------------------------------------------------------

fn list_local_groups(server: Option<&str>) -> Result<Vec<IdentitySnapshot>, CoreError> {
    let server_w = server.map(to_wide_null);
    let server_ptr = server_w.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());

    let mut out: Vec<IdentitySnapshot> = Vec::new();
    let mut resume_handle: usize = 0;

    loop {
        let mut buf_ptr: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;

        // SAFETY: siehe oben.
        let status = unsafe {
            NetLocalGroupEnum(
                server_ptr,
                1, // Level 1 = LOCALGROUP_INFO_1
                &mut buf_ptr,
                MAX_PREFERRED_LENGTH,
                &mut entries_read,
                &mut total_entries,
                &mut resume_handle,
            )
        };

        if !buf_ptr.is_null() && entries_read > 0 {
            // SAFETY: LOCALGROUP_INFO_1-Array.
            let entries = unsafe {
                std::slice::from_raw_parts(
                    buf_ptr as *const LOCALGROUP_INFO_1,
                    entries_read as usize,
                )
            };
            for entry in entries {
                // SAFETY: null-terminierte UTF-16-Strings.
                let name = unsafe { wide_ptr_to_string(entry.lgrpi1_name) };
                if name.is_empty() {
                    continue;
                }
                let description = unsafe { wide_ptr_to_string(entry.lgrpi1_comment) };
                out.push(IdentitySnapshot {
                    name,
                    // Lokale Gruppen tragen formal die BUILTIN-Authority auf
                    // einer DC; auf einem Mitgliedsserver wäre die NetBIOS-
                    // Maschinenname die Authority. Für die UX-Anzeige sagen
                    // wir „BUILTIN" — der tatsächliche SID-Lookup über
                    // `LookupAccountNameW` benutzt das Feld nicht, sondern
                    // die lokale LSA, und kommt damit am Ende richtig raus.
                    // Local groups carry the BUILTIN authority on a DC; on
                    // a member server it would be the NetBIOS machine name.
                    // We display "BUILTIN" for UX; the actual SID lookup
                    // via `LookupAccountNameW` does not rely on this field
                    // and routes through the local LSA correctly.
                    domain: "BUILTIN".to_string(),
                    kind: IdentityKind::Group,
                    description,
                });
            }
        }
        if !buf_ptr.is_null() {
            // SAFETY: NetApi-Puffer freigeben.
            unsafe { NetApiBufferFree(buf_ptr.cast()) };
        }

        if status == NO_ERROR {
            break;
        }
        if status != ERROR_MORE_DATA {
            return Err(CoreError::LdapQuery(format!(
                "NetLocalGroupEnum failed with status {status}"
            )));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Well-Known-Tabelle
// ---------------------------------------------------------------------------

/// Eine hartcodierte Liste der audit-relevanten Well-Known-SIDs, die per
/// `NetUserEnum`/`NetGroupEnum` nicht zurückkommen. Die Authority-Strings
/// folgen den nicht-lokalisierten Microsoft-Namen, damit `LookupAccountNameW`
/// sie auf jedem System auflösen kann (auch auf deutschen Installationen,
/// wo der LSA-„Anzeige­name" lokalisiert ist).
/// A hard-coded list of audit-relevant well-known SIDs that NetUserEnum /
/// NetGroupEnum do not return. The authority strings use Microsoft's
/// non-localized names so `LookupAccountNameW` resolves them on any
/// system (including German installs where the LSA "display name" is
/// localized).
fn well_known_table() -> Vec<IdentitySnapshot> {
    let g = IdentityKind::WellKnown;
    vec![
        IdentitySnapshot {
            name: "Everyone".into(),
            domain: String::new(),
            kind: g.clone(),
            description: "Jeder, inkl. anonymer Zugriffe in bestimmten Konfigurationen".into(),
        },
        IdentitySnapshot {
            name: "Authenticated Users".into(),
            domain: "NT AUTHORITY".into(),
            kind: g.clone(),
            description: "Jeder authentifizierte Benutzer (kein Anonymous Logon)".into(),
        },
        IdentitySnapshot {
            name: "ANONYMOUS LOGON".into(),
            domain: "NT AUTHORITY".into(),
            kind: g.clone(),
            description: "Unauthentifizierte Zugriffe".into(),
        },
        IdentitySnapshot {
            name: "SYSTEM".into(),
            domain: "NT AUTHORITY".into(),
            kind: g.clone(),
            description: "Lokales System — Dienste laufen darunter".into(),
        },
        IdentitySnapshot {
            name: "LOCAL SERVICE".into(),
            domain: "NT AUTHORITY".into(),
            kind: g.clone(),
            description: "Lokaler Dienste-Account, kein Netz-Auth".into(),
        },
        IdentitySnapshot {
            name: "NETWORK SERVICE".into(),
            domain: "NT AUTHORITY".into(),
            kind: g.clone(),
            description: "Dienste-Account mit Computer-Identität im Netz".into(),
        },
        IdentitySnapshot {
            name: "NETWORK".into(),
            domain: "NT AUTHORITY".into(),
            kind: g.clone(),
            description: "Implizit jeder Zugriff via SMB/Netz".into(),
        },
        IdentitySnapshot {
            name: "INTERACTIVE".into(),
            domain: "NT AUTHORITY".into(),
            kind: g.clone(),
            description: "Lokal angemeldete Benutzer".into(),
        },
        IdentitySnapshot {
            name: "CREATOR OWNER".into(),
            domain: String::new(),
            kind: g,
            description: "Platzhalter für den Ersteller eines Objekts".into(),
        },
    ]
}

// ---------------------------------------------------------------------------
// Hilfsmittel
// ---------------------------------------------------------------------------

/// Liest den NetBIOS-Domänennamen über `NetWkstaGetInfo` (Level 100). Auf
/// einem Workgroup-Rechner liefert das den Computer-Namen statt einer
/// Domäne — für unsere UX ist beides brauchbar.
/// Reads the NetBIOS domain name via `NetWkstaGetInfo` (level 100). On a
/// workgroup host this returns the computer name instead of a domain —
/// either way is usable for our UX.
fn local_netbios_domain() -> Option<String> {
    let mut buf_ptr: *mut u8 = std::ptr::null_mut();
    // SAFETY: server-Parameter null = lokaler Host, level 100 ist gültig,
    // buf_ptr ist OUT.
    // SAFETY: null server = local host, level 100 is valid, buf_ptr is OUT.
    let status = unsafe { NetWkstaGetInfo(std::ptr::null(), 100, &mut buf_ptr) };
    if status != NO_ERROR || buf_ptr.is_null() {
        if !buf_ptr.is_null() {
            // SAFETY: NetApi-Puffer freigeben.
            unsafe { NetApiBufferFree(buf_ptr.cast()) };
        }
        return None;
    }
    // SAFETY: buf_ptr verweist auf eine WKSTA_INFO_100-Struktur.
    // SAFETY: buf_ptr refers to a WKSTA_INFO_100 struct.
    let info = unsafe { &*(buf_ptr as *const WKSTA_INFO_100) };
    // SAFETY: wki100_langroup ist ein null-terminierter UTF-16-String.
    // SAFETY: wki100_langroup is a null-terminated UTF-16 string.
    let name = unsafe { wide_ptr_to_string(info.wki100_langroup) };
    // SAFETY: NetApi-Puffer freigeben.
    unsafe { NetApiBufferFree(buf_ptr.cast()) };
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// # Safety
/// `p` muss ein gültiger Zeiger auf eine null-terminierte UTF-16-Sequenz
/// sein oder null.
/// `p` must be a valid pointer to a null-terminated UTF-16 sequence or
/// null.
unsafe fn wide_ptr_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let len = (0usize..).take_while(|&i| *p.add(i) != 0).count();
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Die Well-Known-Tabelle muss alle gängigen Audit-Identitäten enthalten.
    /// Das ist eine reine Codeprüfung — keine Windows-API.
    /// The well-known table must include the standard audit identities.
    /// Pure code check — no Windows API.
    #[test]
    fn well_known_table_includes_critical_entries() {
        let table = well_known_table();
        let names: Vec<&str> = table.iter().map(|i| i.name.as_str()).collect();
        for required in [
            "Everyone",
            "Authenticated Users",
            "SYSTEM",
            "NETWORK",
            "ANONYMOUS LOGON",
            "CREATOR OWNER",
        ] {
            assert!(
                names.contains(&required),
                "Well-Known-Tabelle fehlt: {required}"
            );
        }
    }

    /// Substring-Matching ist case-insensitive und sucht in Name + Domäne.
    /// Substring matching is case-insensitive and searches name + domain.
    #[test]
    fn matches_is_case_insensitive_and_covers_domain() {
        let s = IdentitySnapshot {
            name: "Administrator".into(),
            domain: "TESTDOMAIN".into(),
            kind: IdentityKind::User,
            description: String::new(),
        };
        assert!(s.matches("ADM"));
        assert!(s.matches("adm"));
        assert!(s.matches("TESTDOM"));
        assert!(s.matches("testdom"));
        assert!(!s.matches("krbtgt"));
    }

    /// Auf einem realen Windows-System liefert die Enumeration mindestens
    /// die Well-Known-Einträge + die lokalen Gruppen. `#[ignore]`, weil
    /// CI-Runner andere lokale Konten haben.
    /// On a real Windows host enumeration returns at least the well-known
    /// entries + local groups. `#[ignore]` because CI runners have
    /// different local account layouts.
    #[test]
    #[ignore = "läuft live gegen die LSA/NetAPI — lokal mit `cargo test -- --ignored`"]
    fn enumerate_returns_at_least_well_known_and_local_groups() {
        let all = enumerate_all();
        assert!(all.iter().any(|i| i.name == "Everyone"));
        // Lokale Gruppen tragen Authority "BUILTIN" in unserer UX.
        assert!(all.iter().any(|i| i.domain == "BUILTIN"));
    }
}
