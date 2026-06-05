// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Windows-DACL- und ACE-Lese-Logik über native Windows-APIs.
//! Windows DACL and ACE reading logic via native Windows APIs.
//!
//! Kapselt alle unsafe-Blöcke. Aufrufer erhalten typisierte Rust-Modelle.
//! Encapsulates all unsafe blocks. Callers receive typed Rust models.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use adpa_core::{
    error::CoreError,
    model::{AccessMask, AceEntry, AceKind, FileSystemObject, NormalizedPath, Sid, UnsupportedAce},
};
use tracing::{debug, warn};

use windows_sys::Win32::Foundation::{LocalFree, ERROR_ACCESS_DENIED, ERROR_SUCCESS, FALSE};
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION,
    DACL_SECURITY_INFORMATION, INHERITED_ACE, OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED,
};

// Nicht von windows-sys 0.59 als Konstante exportiert — Rohwerte aus WinNT.h
// Not exported as constants in windows-sys 0.59 — raw values from WinNT.h
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileAttributesW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    INVALID_FILE_ATTRIBUTES,
};

fn to_wide_null(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

// Roh-AceFlags-Bits, ohne von windows-sys abhängig zu sein.
// Raw AceFlags bits, decoupled from windows-sys.
const OBJECT_INHERIT_ACE: u8 = 0x01;
const CONTAINER_INHERIT_ACE: u8 = 0x02;
const NO_PROPAGATE_INHERIT_ACE: u8 = 0x04;
const INHERIT_ONLY_ACE: u8 = 0x08;

/// Zerlegt `ACE_HEADER::AceFlags` in die .NET-äquivalenten Felder
/// `inheritance_flags` (OI|CI — welche Kinder erben) und
/// `propagation_flags` (NP|IO — wie/ob es weiterpropagiert).
/// Der INHERITED-Bit (0x10) bleibt im separaten `inherited`-Bool und fließt
/// hier nicht ein. Die Audit-/Erfolg-Bits (0x40/0x80) interessieren uns
/// für DACLs nicht.
///
/// Splits `ACE_HEADER::AceFlags` into the .NET-equivalent fields
/// `inheritance_flags` (OI|CI — which children inherit) and
/// `propagation_flags` (NP|IO — how/whether it propagates). The INHERITED
/// bit (0x10) stays in the separate `inherited` boolean and is not folded
/// in here. Audit success/failure bits (0x40/0x80) are irrelevant for DACLs.
fn split_ace_flags(ace_flags: u8) -> (u32, u32) {
    let inheritance = ace_flags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
    let propagation = ace_flags & (NO_PROPAGATE_INHERIT_ACE | INHERIT_ONLY_ACE);
    (inheritance as u32, propagation as u32)
}

/// Konvertiert einen SID-Zeiger in den kanonischen S-R-I-... String.
/// Converts a SID pointer to the canonical S-R-I-... string.
///
/// # Safety
/// `sid` muss ein gültiger PSID-Zeiger sein, der für die Dauer des Aufrufs gültig bleibt.
/// `sid` must be a valid PSID pointer that remains valid for the duration of the call.
unsafe fn sid_ptr_to_string(sid: *const core::ffi::c_void) -> Result<String, CoreError> {
    let mut str_ptr: *mut u16 = std::ptr::null_mut();
    // SAFETY: sid is a valid PSID pointer provided by the Windows API (GetNamedSecurityInfoW
    // or GetAce). The OS allocates str_ptr via LocalAlloc; we must free it with LocalFree.
    if ConvertSidToStringSidW(sid as *mut _, &mut str_ptr) == FALSE {
        let err = get_last_error();
        return Err(CoreError::InvalidSecurityDescriptor(format!(
            "ConvertSidToStringSidW failed: error {err}"
        )));
    }
    // SAFETY: ConvertSidToStringSidW allocated a null-terminated wide string at str_ptr.
    let len = (0usize..).take_while(|&i| *str_ptr.add(i) != 0).count();
    let sid_string = String::from_utf16_lossy(std::slice::from_raw_parts(str_ptr, len));
    // SAFETY: str_ptr was allocated by LocalAlloc inside ConvertSidToStringSidW.
    LocalFree(str_ptr as *mut core::ffi::c_void);
    Ok(sid_string)
}

/// Liest Attribute, Owner-SID und DACL eines Pfades.
/// Reads attributes, owner SID and DACL for a path.
///
/// Der Eingabepfad wird vor allen Win32-Aufrufen in die Long-Path-Form
/// (`\\?\C:\…` bzw. `\\?\UNC\server\share\…`) umgewandelt, damit Pfade
/// jenseits von `MAX_PATH` (260 Zeichen) zuverlässig gelesen werden können.
/// Der im resultierenden `FileSystemObject` gespeicherte Pfad bleibt die
/// ursprüngliche Eingabeform (ohne Präfix), damit Reports lesbar bleiben.
///
/// The input path is converted into long-path form (`\\?\C:\…` or
/// `\\?\UNC\server\share\…`) before any Win32 call, so paths longer than
/// `MAX_PATH` (260 characters) can be read reliably. The path stored in
/// the resulting `FileSystemObject` remains the original input form
/// (without the prefix), keeping reports human-readable.
pub fn read_file_system_object(path: &str) -> Result<FileSystemObject, CoreError> {
    let api_path = validation::path::to_windows_api_path(path);
    let wide_path = to_wide_null(&api_path);

    // --- Dateiattribute (is_directory, is_reparse_point) ---
    // --- File attributes (is_directory, is_reparse_point) ---
    // SAFETY: wide_path is a valid null-terminated wide string for the duration of this call.
    let attrs = unsafe { GetFileAttributesW(wide_path.as_ptr()) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        let err = unsafe { get_last_error() };
        return match err {
            2 | 3 => {
                warn!(path, "Path not found");
                Err(CoreError::PathNotFound(path.into()))
            }
            5 => {
                warn!(path, "Access denied reading file attributes");
                Err(CoreError::AccessDenied(path.into()))
            }
            _ => {
                warn!(path, error = err, "GetFileAttributesW failed");
                Err(CoreError::InvalidSecurityDescriptor(format!(
                    "GetFileAttributesW({path}) failed: error {err}"
                )))
            }
        };
    }
    let is_directory = attrs & FILE_ATTRIBUTE_DIRECTORY != 0;
    let is_reparse_point = attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0;

    // --- Security Descriptor (Owner + DACL) ---
    let mut psid_owner: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut p_dacl: *mut ACL = std::ptr::null_mut();
    let mut p_sd: *mut core::ffi::c_void = std::ptr::null_mut();

    // SAFETY: wide_path is valid; all output pointers are valid stack variables.
    // p_sd is allocated by the OS via LocalAlloc on success and must be freed with LocalFree.
    let result = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut psid_owner,
            std::ptr::null_mut(),
            &mut p_dacl,
            std::ptr::null_mut(),
            &mut p_sd,
        )
    };

    if result != ERROR_SUCCESS {
        return match result {
            ERROR_ACCESS_DENIED => {
                warn!(path, "Access denied reading security descriptor");
                Err(CoreError::AccessDenied(path.into()))
            }
            _ => {
                warn!(path, error = result, "GetNamedSecurityInfoW failed");
                Err(CoreError::InvalidSecurityDescriptor(format!(
                    "GetNamedSecurityInfoW({path}) failed: error {result}"
                )))
            }
        };
    }

    // p_sd is now valid and must be freed with LocalFree before all return paths below.

    let owner_sid = if psid_owner.is_null() {
        None
    } else {
        // SAFETY: psid_owner points into the p_sd buffer, valid until LocalFree is called.
        unsafe { sid_ptr_to_string(psid_owner) }.ok().map(Sid)
    };

    // NULL-DACL und leere DACL fachlich trennen:
    // - NULL-DACL → null_dacl = true, dacl leer (Engine wertet als Vollzugriff).
    // - DACL vorhanden, aber leer → null_dacl = false, dacl leer (Deny-All).
    // Distinguish NULL DACL from empty DACL:
    // - NULL DACL → null_dacl = true, dacl empty (engine treats as full access).
    // - DACL present but empty → null_dacl = false, dacl empty (deny all).
    let (dacl, unsupported_aces, null_dacl) = if p_dacl.is_null() {
        (Vec::new(), Vec::new(), true)
    } else {
        // SAFETY: p_dacl points into the p_sd buffer, valid until LocalFree is called.
        let (entries, unsupported) = unsafe { parse_dacl(p_dacl) };
        (entries, unsupported, false)
    };

    // Vererbungsschutz: SE_DACL_PROTECTED im Security-Descriptor-Control-Feld.
    // Inheritance protection: SE_DACL_PROTECTED in the Security Descriptor control field.
    let inheritance_disabled = if p_sd.is_null() {
        false
    } else {
        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        // SAFETY: p_sd is a valid security descriptor until LocalFree is called.
        let ok = unsafe { GetSecurityDescriptorControl(p_sd, &mut control, &mut revision) };
        ok != FALSE && (control & SE_DACL_PROTECTED != 0)
    };

    // SAFETY: p_sd was allocated by GetNamedSecurityInfoW via LocalAlloc and is non-null.
    if !p_sd.is_null() {
        unsafe { LocalFree(p_sd) };
    }

    debug!(
        path,
        is_directory,
        is_reparse_point,
        aces = dacl.len(),
        inheritance_disabled,
        "FSO read successfully"
    );
    // Den im FSO gespeicherten Pfad ohne Long-Path-Präfix führen, damit
    // Reports/CSV/HTML lesbar bleiben. Wenn der Aufrufer (Walker) bereits
    // einen präfixierten Pfad weiterreicht (geerbt von `DirEntry::path()`),
    // wird das Präfix hier wieder entfernt.
    // Store the FSO path without the long-path prefix so reports/CSV/HTML
    // stay readable. If the caller (walker) passed in a prefixed path
    // (inherited from `DirEntry::path()`), strip it back here.
    let display_path = validation::path::strip_long_path_prefix(path);
    Ok(FileSystemObject {
        path: NormalizedPath(display_path),
        is_directory,
        owner_sid,
        dacl,
        inheritance_disabled,
        is_reparse_point,
        unsupported_aces,
        null_dacl,
    })
}

/// Ergebnis eines einzelnen ACE-Parse-Versuchs.
/// Result of a single ACE parse attempt.
enum ParseAceOutcome {
    /// ACE wurde vollständig geparst. / ACE was fully parsed.
    Entry(AceEntry),
    /// ACE-Typ wird nicht unterstützt — Diagnosedaten gespeichert.
    /// ACE type is not supported — diagnostic data saved.
    Unsupported(UnsupportedAce),
    /// SID konnte nicht gelesen werden — ACE wird übersprungen.
    /// SID could not be read — ACE is skipped.
    Skip,
}

/// Liest alle ACEs aus einem DACL.
/// Reads all ACEs from a DACL.
///
/// Gibt `(unterstützte ACEs, nicht unterstützte ACEs)` zurück.
/// Returns `(supported ACEs, unsupported ACEs)`.
///
/// # Safety
/// `dacl` muss ein gültiger, nicht-null DACL-Zeiger sein.
/// `dacl` must be a valid, non-null DACL pointer.
unsafe fn parse_dacl(dacl: *const ACL) -> (Vec<AceEntry>, Vec<UnsupportedAce>) {
    let mut acl_info = ACL_SIZE_INFORMATION {
        AceCount: 0,
        AclBytesInUse: 0,
        AclBytesFree: 0,
    };

    // SAFETY: dacl is valid; acl_info is a valid stack variable with the correct size.
    let ok = GetAclInformation(
        dacl,
        &mut acl_info as *mut _ as *mut core::ffi::c_void,
        std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
        AclSizeInformation,
    );

    if ok == FALSE {
        return (Vec::new(), Vec::new());
    }

    let mut entries = Vec::with_capacity(acl_info.AceCount as usize);
    let mut unsupported = Vec::new();

    for i in 0..acl_info.AceCount {
        let mut ace_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: dacl is valid; i is within bounds (0..AceCount).
        if GetAce(dacl, i, &mut ace_ptr) == FALSE || ace_ptr.is_null() {
            continue;
        }
        match parse_ace(ace_ptr) {
            ParseAceOutcome::Entry(e) => entries.push(e),
            ParseAceOutcome::Unsupported(u) => {
                warn!(
                    ace_type = u.ace_type,
                    flags = u.flags,
                    mask = format_args!("0x{:08X}", u.mask),
                    "Unsupported ACE type — recorded as diagnostic, not evaluated"
                );
                unsupported.push(u);
            }
            ParseAceOutcome::Skip => {}
        }
    }

    (entries, unsupported)
}

/// Parst einen einzelnen ACE-Zeiger.
/// Parses a single ACE pointer.
///
/// # Safety
/// `ace_ptr` muss ein gültiger ACE-Zeiger aus GetAce sein.
/// `ace_ptr` must be a valid ACE pointer obtained from GetAce.
unsafe fn parse_ace(ace_ptr: *mut core::ffi::c_void) -> ParseAceOutcome {
    // SAFETY: ace_ptr points to a valid ACE structure returned by GetAce.
    let header = &*(ace_ptr as *const ACE_HEADER);
    let ace_flags = header.AceFlags;
    let (inheritance_flags, propagation_flags) = split_ace_flags(ace_flags);

    match header.AceType {
        ACCESS_ALLOWED_ACE_TYPE => {
            // SAFETY: AceType is ACCESS_ALLOWED_ACE_TYPE, layout matches ACCESS_ALLOWED_ACE.
            let ace = &*(ace_ptr as *const ACCESS_ALLOWED_ACE);
            let sid_ptr = std::ptr::addr_of!(ace.SidStart) as *const core::ffi::c_void;
            match sid_ptr_to_string(sid_ptr) {
                Ok(sid_str) => ParseAceOutcome::Entry(AceEntry {
                    kind: AceKind::Allow,
                    sid: Sid(sid_str),
                    mask: AccessMask(ace.Mask),
                    inherited: ace_flags & (INHERITED_ACE as u8) != 0,
                    inheritance_flags,
                    propagation_flags,
                }),
                Err(_) => ParseAceOutcome::Skip,
            }
        }
        ACCESS_DENIED_ACE_TYPE => {
            // SAFETY: AceType is ACCESS_DENIED_ACE_TYPE, layout matches ACCESS_DENIED_ACE.
            let ace = &*(ace_ptr as *const ACCESS_DENIED_ACE);
            let sid_ptr = std::ptr::addr_of!(ace.SidStart) as *const core::ffi::c_void;
            match sid_ptr_to_string(sid_ptr) {
                Ok(sid_str) => ParseAceOutcome::Entry(AceEntry {
                    kind: AceKind::Deny,
                    sid: Sid(sid_str),
                    mask: AccessMask(ace.Mask),
                    inherited: ace_flags & (INHERITED_ACE as u8) != 0,
                    inheritance_flags,
                    propagation_flags,
                }),
                Err(_) => ParseAceOutcome::Skip,
            }
        }
        _ => {
            // Alle Standard-ACE-Typen (0–15+) haben Mask direkt nach dem ACE_HEADER.
            // All standard ACE types (0–15+) have Mask immediately after ACE_HEADER.
            // SAFETY: Mask field position is identical across all standard Windows ACE types.
            let ace = &*(ace_ptr as *const ACCESS_ALLOWED_ACE);
            ParseAceOutcome::Unsupported(UnsupportedAce {
                ace_type: header.AceType,
                flags: ace_flags,
                mask: ace.Mask,
            })
        }
    }
}

/// Ruft GetLastError auf — Hilfsfunktion zur Lesbarkeit.
/// Calls GetLastError — helper for readability.
#[inline]
unsafe fn get_last_error() -> u32 {
    windows_sys::Win32::Foundation::GetLastError()
}

#[cfg(test)]
mod tests {
    use super::*;
    use adpa_core::model::AceKind;

    #[test]
    fn windows_dir_is_readable() {
        let fso = read_file_system_object("C:\\Windows").expect("C:\\Windows must be readable");
        assert!(fso.is_directory, "C:\\Windows must be a directory");
        assert!(
            !fso.is_reparse_point,
            "C:\\Windows must not be a reparse point"
        );
    }

    #[test]
    fn windows_dir_has_owner() {
        let fso = read_file_system_object("C:\\Windows").unwrap();
        let sid = fso.owner_sid.expect("C:\\Windows must have an owner SID");
        assert!(
            sid.0.starts_with("S-"),
            "Owner SID must start with S-, got: {}",
            sid.0
        );
    }

    #[test]
    fn windows_dir_has_dacl_entries() {
        let fso = read_file_system_object("C:\\Windows").unwrap();
        assert!(!fso.dacl.is_empty(), "C:\\Windows must have DACL entries");
    }

    #[test]
    fn windows_dir_has_allow_aces() {
        let fso = read_file_system_object("C:\\Windows").unwrap();
        let has_allow = fso.dacl.iter().any(|e| e.kind == AceKind::Allow);
        assert!(has_allow, "C:\\Windows must have at least one Allow ACE");
    }

    #[test]
    fn nonexistent_path_returns_not_found() {
        let result = read_file_system_object("C:\\zzz_adpa_nonexistent_xyzabc_test");
        assert!(
            matches!(result, Err(CoreError::PathNotFound(_))),
            "Expected PathNotFound, got: {result:?}"
        );
    }

    #[test]
    fn system32_is_readable_directory() {
        let fso =
            read_file_system_object("C:\\Windows\\System32").expect("System32 must be readable");
        assert!(fso.is_directory);
        assert!(fso.owner_sid.is_some());
        assert!(!fso.dacl.is_empty());
    }

    #[test]
    fn access_masks_are_nonzero() {
        let fso = read_file_system_object("C:\\Windows").unwrap();
        for ace in &fso.dacl {
            assert_ne!(ace.mask.0, 0, "ACE mask must not be zero");
        }
    }

    // --- split_ace_flags ---

    #[test]
    fn split_ace_flags_isolates_inheritance_and_propagation() {
        // OI | CI | IO | INHERITED → inheritance = OI|CI, propagation = IO
        // (INHERITED bleibt im inherited-Bool, nicht in den Flag-Feldern.)
        let (inh, prop) = split_ace_flags(0x01 | 0x02 | 0x08 | 0x10);
        assert_eq!(inh, 0x03, "inheritance_flags must contain OI | CI");
        assert_eq!(prop, 0x08, "propagation_flags must contain IO");
    }

    #[test]
    fn split_ace_flags_inherit_only_lives_in_propagation() {
        let (inh, prop) = split_ace_flags(0x08); // pure IO
        assert_eq!(inh, 0, "IO must not appear in inheritance_flags");
        assert_eq!(prop, 0x08, "IO must appear in propagation_flags");
    }

    #[test]
    fn split_ace_flags_zero_yields_zero() {
        let (inh, prop) = split_ace_flags(0);
        assert_eq!(inh, 0);
        assert_eq!(prop, 0);
    }

    #[test]
    fn split_ace_flags_ignores_audit_bits() {
        // SUCCESSFUL_ACCESS_ACE_FLAG (0x40) / FAILED_ACCESS_ACE_FLAG (0x80)
        // sind Audit-Bits und gehören weder in inheritance noch in propagation.
        let (inh, prop) = split_ace_flags(0x40 | 0x80);
        assert_eq!(inh, 0);
        assert_eq!(prop, 0);
    }

    /// Synthetischer Test: ein ACE mit unbekanntem Typ (z.B. SYSTEM_AUDIT_ACE_TYPE = 2)
    /// wird als UnsupportedAce mit ACE-Typ und Maske gespeichert, nicht verworfen.
    ///
    /// Synthetic test: an ACE with an unknown type (e.g. SYSTEM_AUDIT_ACE_TYPE = 2)
    /// is recorded as UnsupportedAce with type and mask, not silently dropped.
    #[test]
    fn unsupported_ace_type_recorded_as_diagnostic() {
        // Minimal ACE buffer with the same memory layout as ACCESS_ALLOWED_ACE:
        // AceType(u8) | AceFlags(u8) | AceSize(u16) | Mask(u32)
        // We use type 2 (SYSTEM_AUDIT_ACE_TYPE) — not handled by parse_ace.
        #[repr(C)]
        struct FakeAce {
            ace_type: u8,
            ace_flags: u8,
            ace_size: u16,
            mask: u32,
        }
        let fake = FakeAce {
            ace_type: 2, // SYSTEM_AUDIT_ACE_TYPE
            ace_flags: 0,
            ace_size: 8,
            mask: 0x001F_01FF,
        };

        let outcome = unsafe { parse_ace(&fake as *const FakeAce as *mut core::ffi::c_void) };

        match outcome {
            ParseAceOutcome::Unsupported(u) => {
                assert_eq!(u.ace_type, 2, "ace_type must be preserved");
                assert_eq!(u.mask, 0x001F_01FF, "mask must be preserved");
            }
            _ => panic!("expected ParseAceOutcome::Unsupported for type 2"),
        }
    }
}
