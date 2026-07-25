// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Safe SID-to-string conversion on top of [`LocalFreeGuard`].
//!
//! `ConvertSidToStringSidW` hands the caller an OS-allocated string that
//! must be released with `LocalFree`. Before this helper existed, that
//! conversion was hand-rolled at five places across the workspace, each
//! with a manual `LocalFree` — leak-free today, but exactly the fragile
//! alloc→work→free pattern [`LocalFreeGuard`] was built to eliminate
//! (win_safe review 2026-07-25, W-1/W-2). This is the single shared
//! implementation: the guard owns the string on every path.
//!
//! [`LocalFreeGuard`]: crate::localalloc::LocalFreeGuard

use crate::localalloc::LocalFreeGuard;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;

/// Converts a PSID to the canonical `S-R-I-…` string via
/// `ConvertSidToStringSidW`. The OS-allocated string is owned by a
/// [`LocalFreeGuard`], so it is released on every path — including any
/// future early return added between conversion and use.
///
/// Returns `Err(code)` with the `GetLastError` value when the conversion
/// fails (for example for a structurally invalid SID). The string is
/// decoded with `from_utf16_lossy` — hence the name; canonical SID
/// strings are pure ASCII, so no real value is ever altered.
///
/// # Safety
///
/// `sid` must be a valid PSID pointer that stays valid for the duration
/// of the call.
pub unsafe fn sid_to_string_lossy(sid: *const core::ffi::c_void) -> Result<String, u32> {
    let mut str_ptr: *mut u16 = core::ptr::null_mut();
    // SAFETY (caller contract): `sid` is a valid PSID. On success the OS
    // allocates `str_ptr` via LocalAlloc. The null double-check guards
    // against a contract-violating TRUE-with-null result — better an
    // error than a null dereference below.
    if ConvertSidToStringSidW(sid as *mut _, &mut str_ptr) == 0 || str_ptr.is_null() {
        return Err(GetLastError());
    }
    // SAFETY: free responsibility moves to the guard *immediately*, before
    // any other work — the whole point of this helper (review W-1).
    let _guard = LocalFreeGuard::new(str_ptr.cast());
    // SAFETY: on success `str_ptr` is a valid null-terminated UTF-16
    // string; the length loop stops at the terminator.
    let len = (0usize..).take_while(|&i| *str_ptr.add(i) != 0).count();
    Ok(String::from_utf16_lossy(core::slice::from_raw_parts(
        str_ptr, len,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;

    /// Round-trip through the real Windows APIs: build the binary SID for
    /// the well-known `S-1-1-0` (Everyone) via the inverse conversion,
    /// then convert it back through the helper.
    #[test]
    fn roundtrip_wellknown_sid() {
        let sid_w: Vec<u16> = "S-1-1-0".encode_utf16().chain(Some(0)).collect();
        let mut psid: *mut core::ffi::c_void = core::ptr::null_mut();
        // SAFETY: sid_w is a valid null-terminated wide string; psid is
        // an out-pointer the OS fills via LocalAlloc on success.
        let ok = unsafe { ConvertStringSidToSidW(sid_w.as_ptr(), &mut psid) };
        assert_ne!(ok, 0, "ConvertStringSidToSidW must accept S-1-1-0");
        // SAFETY: psid was allocated by ConvertStringSidToSidW; the guard
        // owns the LocalFree.
        let _guard = unsafe { LocalFreeGuard::new(psid) };
        // SAFETY: psid is a valid PSID for the duration of the call.
        let s = unsafe { sid_to_string_lossy(psid) }.unwrap();
        assert_eq!(s, "S-1-1-0");
    }

    /// A structurally invalid SID (revision 0) must yield an error, not a
    /// crash — ConvertSidToStringSidW validates without over-reading
    /// (same technique as the fs_scanner bad-SID ACE test).
    #[test]
    fn invalid_sid_yields_error() {
        let bogus = [0u8; 8];
        // SAFETY: the API validates the revision byte first and fails
        // without reading past the 8 supplied bytes.
        let result = unsafe { sid_to_string_lossy(bogus.as_ptr().cast()) };
        assert!(result.is_err());
    }
}
