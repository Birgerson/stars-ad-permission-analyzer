// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Windows DACL and ACE reading logic via native Windows APIs.
//!
//! Encapsulates all unsafe blocks. Callers receive typed Rust models.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use adpa_core::{
    error::CoreError,
    model::{AccessMask, AceEntry, AceKind, FileSystemObject, NormalizedPath, Sid, UnsupportedAce},
};
use tracing::{debug, warn};

use std::collections::HashMap;

use windows_sys::Win32::Foundation::{LocalFree, ERROR_ACCESS_DENIED, ERROR_SUCCESS, FALSE};
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    GetSecurityDescriptorLength, ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, ACE_HEADER, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, INHERITED_ACE, OWNER_SECURITY_INFORMATION,
    SE_DACL_PROTECTED,
};

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

// Raw AceFlags bits, decoupled from windows-sys.
const OBJECT_INHERIT_ACE: u8 = 0x01;
const CONTAINER_INHERIT_ACE: u8 = 0x02;
const NO_PROPAGATE_INHERIT_ACE: u8 = 0x04;
const INHERIT_ONLY_ACE: u8 = 0x08;

/// `propagation_flags` (NP|IO — wie/ob es weiterpropagiert).
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

/// Converts a SID pointer to the canonical S-R-I-... string.
///
/// # Safety
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

/// Parsed, owned result of reading a security descriptor — cacheable by
/// SD hash (engine review 2026-06-12 finding 2). Carries the raw SD bytes
/// so a hash hit is confirmed by a full byte comparison before reuse:
/// correctness before speed, a collision degrades to a fresh parse rather
/// than a wrong DACL.
#[derive(Clone)]
pub struct ParsedSecurity {
    sd_bytes: Vec<u8>,
    owner_sid: Option<Sid>,
    dacl: Vec<AceEntry>,
    unsupported_aces: Vec<UnsupportedAce>,
    null_dacl: bool,
    inheritance_disabled: bool,
}

/// Per-scan cache: SD hash → parsed security descriptor. On a directory
/// tree where most objects inherit one DACL from a shared parent, this
/// turns thousands of repeated `parse_dacl` + SID-string conversions into
/// a single parse per distinct descriptor.
pub type SdCache = HashMap<u64, ParsedSecurity>;

/// Stable 64-bit FNV-1a hash over the raw security-descriptor bytes.
/// Deterministic (no random seed) so the value is also usable as a
/// storage-side dedup key across runs.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Parses owner, DACL, and inheritance state from a live security
/// descriptor into an owned [`ParsedSecurity`].
///
/// # Safety
/// `psid_owner`, `p_dacl`, and `p_sd` must be valid pointers into the same
/// live security descriptor (valid until the caller frees `p_sd`).
unsafe fn parse_security(
    psid_owner: *mut core::ffi::c_void,
    p_dacl: *mut ACL,
    p_sd: *mut core::ffi::c_void,
    sd_bytes: Vec<u8>,
) -> ParsedSecurity {
    let owner_sid = if psid_owner.is_null() {
        None
    } else {
        sid_ptr_to_string(psid_owner).ok().map(Sid)
    };

    // Distinguish NULL DACL from empty DACL:
    // - NULL DACL → null_dacl = true, dacl empty (engine treats as full access).
    // - DACL present but empty → null_dacl = false, dacl empty (deny all).
    let (dacl, unsupported_aces, null_dacl) = if p_dacl.is_null() {
        (Vec::new(), Vec::new(), true)
    } else {
        let (entries, unsupported) = parse_dacl(p_dacl);
        (entries, unsupported, false)
    };

    // Inheritance protection: SE_DACL_PROTECTED in the SD control field.
    let inheritance_disabled = if p_sd.is_null() {
        false
    } else {
        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        let ok = GetSecurityDescriptorControl(p_sd, &mut control, &mut revision);
        ok != FALSE && (control & SE_DACL_PROTECTED != 0)
    };

    ParsedSecurity {
        sd_bytes,
        owner_sid,
        dacl,
        unsupported_aces,
        null_dacl,
        inheritance_disabled,
    }
}

/// Reads attributes, owner SID and DACL for a single path.
///
/// The input path is converted into long-path form (`\\?\C:\…` or
/// `\\?\UNC\server\share\…`) before any Win32 call, so paths longer than
/// `MAX_PATH` (260 characters) can be read reliably. The path stored in
/// the resulting `FileSystemObject` remains the original input form
/// (without the prefix), keeping reports human-readable.
///
/// For a tree walk use [`read_file_system_object_cached`] with a shared
/// [`SdCache`] so an inherited DACL is parsed once, not once per object.
pub fn read_file_system_object(path: &str) -> Result<FileSystemObject, CoreError> {
    let mut cache = SdCache::new();
    read_file_system_object_cached(path, &mut cache)
}

/// Like [`read_file_system_object`], but reuses an already-parsed security
/// descriptor from `cache` when this object's descriptor is byte-identical
/// to one seen earlier in the same scan (engine review 2026-06-12
/// finding 2).
pub fn read_file_system_object_cached(
    path: &str,
    cache: &mut SdCache,
) -> Result<FileSystemObject, CoreError> {
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

    // Dedup by raw-SD hash (finding 2). Copy the descriptor bytes, hash
    // them, and reuse a cached parse only after a full byte comparison
    // confirms the match — a hash collision must never yield a wrong DACL.
    // SAFETY: p_sd points to a valid SD of `sd_len` bytes until LocalFree.
    let sd_len = if p_sd.is_null() {
        0usize
    } else {
        unsafe { GetSecurityDescriptorLength(p_sd) as usize }
    };
    let sd_bytes: Vec<u8> = if p_sd.is_null() || sd_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(p_sd as *const u8, sd_len) }.to_vec()
    };
    let sd_hash = fnv1a_64(&sd_bytes);

    // Validate before reuse: a hash hit is only trusted when the raw bytes
    // are identical. Compute the decision first so the immutable cache
    // borrow ends before the (mutable) insert on a miss.
    let hit: Option<ParsedSecurity> = match cache.get(&sd_hash) {
        Some(cached) if cached.sd_bytes == sd_bytes => Some(cached.clone()),
        _ => None,
    };
    let parsed = match hit {
        Some(p) => p,
        None => {
            // Miss or (rare) collision: parse fresh.
            // SAFETY: psid_owner, p_dacl and p_sd are valid until LocalFree below.
            let p = unsafe { parse_security(psid_owner, p_dacl, p_sd, sd_bytes) };
            // `or_insert_with` keeps an existing entry on a collision rather
            // than evicting the descriptor that legitimately owns the slot.
            cache.entry(sd_hash).or_insert_with(|| p.clone());
            p
        }
    };

    // SAFETY: p_sd was allocated by GetNamedSecurityInfoW via LocalAlloc and is non-null.
    if !p_sd.is_null() {
        unsafe { LocalFree(p_sd) };
    }

    debug!(
        path,
        is_directory,
        is_reparse_point,
        aces = parsed.dacl.len(),
        inheritance_disabled = parsed.inheritance_disabled,
        "FSO read successfully"
    );
    // Store the FSO path without the long-path prefix so reports/CSV/HTML
    // stay readable. If the caller (walker) passed in a prefixed path
    // (inherited from `DirEntry::path()`), strip it back here.
    let display_path = validation::path::strip_long_path_prefix(path);
    Ok(FileSystemObject {
        path: NormalizedPath(display_path),
        is_directory,
        owner_sid: parsed.owner_sid,
        dacl: parsed.dacl,
        inheritance_disabled: parsed.inheritance_disabled,
        is_reparse_point,
        unsupported_aces: parsed.unsupported_aces,
        null_dacl: parsed.null_dacl,
        sd_hash: Some(sd_hash),
    })
}

/// Result of a single ACE parse attempt.
enum ParseAceOutcome {
    Entry(AceEntry),
    /// ACE type is not supported — diagnostic data saved.
    Unsupported(UnsupportedAce),
    /// SID could not be read — ACE is skipped.
    Skip,
}

/// Reads all ACEs from a DACL.
///
/// Returns `(supported ACEs, unsupported ACEs)`.
///
/// # Safety
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

/// Parses a single ACE pointer.
///
/// # Safety
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
        let (inh, prop) = split_ace_flags(0x40 | 0x80);
        assert_eq!(inh, 0);
        assert_eq!(prop, 0);
    }

    /// Synthetic test: an ACE with an unknown type (e.g. SYSTEM_AUDIT_ACE_TYPE = 2).
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

    // --- Security-descriptor dedup (engine review 2026-06-12 finding 2) ---

    #[test]
    fn fnv1a_64_is_deterministic_and_distinguishes() {
        assert_eq!(fnv1a_64(b"abc"), fnv1a_64(b"abc"), "same bytes → same hash");
        assert_ne!(
            fnv1a_64(b"abc"),
            fnv1a_64(b"abd"),
            "different bytes → different hash (FNV-1a)"
        );
        assert_eq!(
            fnv1a_64(b""),
            0xcbf2_9ce4_8422_2325,
            "FNV-1a empty = offset basis"
        );
    }

    #[test]
    fn read_sets_sd_hash() {
        let fso = read_file_system_object("C:\\Windows").unwrap();
        assert!(
            fso.sd_hash.is_some(),
            "a read object must carry its SD hash"
        );
    }

    #[test]
    fn sd_cache_reuses_identical_descriptor() {
        // Reading the same path twice through one cache must key on a single
        // descriptor and reuse it — the cache holds exactly one entry and the
        // two reads report the same hash.
        let mut cache = SdCache::new();
        let a = read_file_system_object_cached("C:\\Windows", &mut cache).unwrap();
        let b = read_file_system_object_cached("C:\\Windows", &mut cache).unwrap();
        assert_eq!(
            cache.len(),
            1,
            "identical descriptor must occupy one cache slot"
        );
        assert_eq!(
            a.sd_hash, b.sd_hash,
            "identical descriptor → identical hash"
        );
        assert_eq!(a.dacl.len(), b.dacl.len(), "reused parse must match");
    }
}
