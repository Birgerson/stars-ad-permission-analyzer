// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Network drives (review CR-22).
//!
//! A path such as `Z:\Data` looks local, but when `Z:` is a mapped network
//! drive every object below it is reached over SMB: the share permission
//! and the file server's local groups and policies apply, not this
//! machine's. Lab 2026-11-21: `Z:\Sub` (Z: mapped to a share that grants
//! Read) was reported as exact Modify with "no SMB context", while the same
//! folder through its UNC path was correctly Read & Execute.
//!
//! [`network_drive_target`] tells whether a drive-letter path lies on a
//! network drive and returns the UNC path it maps to. Read-only: two
//! queries of this machine's own drive table, nothing on the server.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::NetworkManagement::WNet::{
    WNetGetUniversalNameW, UNIVERSAL_NAME_INFOW, UNIVERSAL_NAME_INFO_LEVEL,
};
use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;

/// `DRIVE_REMOTE` (winbase.h): the drive is a remote (network) drive.
const DRIVE_REMOTE: u32 = 4;
/// `ERROR_MORE_DATA`: the buffer was too small; the size needed is returned.
const ERROR_MORE_DATA: u32 = 234;
/// Upper bound for the buffer Stars allocates for the answer — far above a
/// UNC path of the longest supported length (32,767 UTF-16 units), so a
/// size the system reports above it is treated as invalid.
const MAX_BUFFER_BYTES: u32 = 128 * 1024;

/// The drive letter of a drive-letter path (`Z:\…`, `z:`), or `None` for
/// any other form (UNC, relative, long-path prefixed). Pure.
pub fn drive_letter(path: &str) -> Option<char> {
    let mut chars = path.chars();
    let letter = chars.next().filter(char::is_ascii_alphabetic)?;
    (chars.next() == Some(':') && matches!(chars.next(), None | Some('\\') | Some('/')))
        .then(|| letter.to_ascii_uppercase())
}

/// `Ok(None)` when `path` is not on a network drive (not a drive-letter
/// path, or a local drive); `Ok(Some(unc))` with the UNC path it maps to
/// (`\\server\share\…`); `Err(reason)` for a network drive whose UNC path
/// cannot be read — never a silent fallback to a local evaluation.
pub fn network_drive_target(path: &str) -> Result<Option<String>, String> {
    let Some(letter) = drive_letter(path) else {
        return Ok(None);
    };
    let root = wide(&format!("{letter}:\\"));
    // SAFETY: `root` is a NUL-terminated UTF-16 string that lives for the
    // duration of the call; GetDriveTypeW only reads it.
    let kind = unsafe { GetDriveTypeW(root.as_ptr()) };
    if kind != DRIVE_REMOTE {
        return Ok(None);
    }
    let unc = universal_name(path).map_err(|why| {
        format!("{letter}: is a network drive, but Windows did not return its UNC path ({why})")
    })?;
    tracing::info!(path, unc, "Path lies on a network drive");
    Ok(Some(unc))
}

/// `WNetGetUniversalNameW` for `path`: the UNC form of a path on a mapped
/// drive. `Err` says why not.
fn universal_name(path: &str) -> Result<String, String> {
    let wpath = wide(path);
    let mut size: u32 = 1024;
    for _ in 0..2 {
        if size == 0 || size > MAX_BUFFER_BYTES {
            return Err(format!("implausible buffer size {size}"));
        }
        // u64 storage keeps the buffer aligned for the pointer-sized
        // UNIVERSAL_NAME_INFOW at its start.
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let mut len = (buf.len() * 8) as u32;
        // SAFETY: `wpath` is NUL-terminated and outlives the call; `buf` is
        // a writable, 8-byte-aligned buffer whose byte length is passed in
        // `len`, which receives the size needed on ERROR_MORE_DATA.
        let rc = unsafe {
            WNetGetUniversalNameW(
                wpath.as_ptr(),
                UNIVERSAL_NAME_INFO_LEVEL,
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc == ERROR_MORE_DATA {
            size = len;
            continue;
        }
        if rc != 0 {
            return Err(format!("Windows error {rc}"));
        }
        let bytes = buf.len() * 8;
        let base = buf.as_ptr() as usize;
        // SAFETY: on success the buffer starts with a UNIVERSAL_NAME_INFOW
        // (aligned, see above).
        let ptr = unsafe { (*(buf.as_ptr() as *const UNIVERSAL_NAME_INFOW)).lpUniversalName };
        let start = ptr as usize;
        // The string must lie inside the buffer Stars passed; anything else
        // is not trusted.
        if ptr.is_null()
            || start < base
            || start >= base + bytes
            || !(start - base).is_multiple_of(2)
        {
            return Err("the answer points outside its buffer".to_owned());
        }
        let max_units = (base + bytes - start) / 2;
        // SAFETY: `start` points into `buf` (checked above) and at most
        // `max_units` UTF-16 units up to the end of `buf` are read.
        let units = unsafe { std::slice::from_raw_parts(ptr as *const u16, max_units) };
        let end = units
            .iter()
            .position(|&u| u == 0)
            .ok_or_else(|| "the answer is not terminated".to_owned())?;
        return Ok(String::from_utf16_lossy(&units[..end]));
    }
    Err("the buffer size kept changing".to_owned())
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drive_letter_recognizes_only_drive_letter_paths() {
        assert_eq!(drive_letter(r"Z:\Data"), Some('Z'));
        assert_eq!(drive_letter(r"z:\"), Some('Z'));
        assert_eq!(drive_letter("c:"), Some('C'));
        assert_eq!(drive_letter("C:/x"), Some('C'));
        for other in [r"\\srv\share", r"\\?\C:\x", "relative", r"1:\x", "C:x", ""] {
            assert_eq!(drive_letter(other), None, "{other}");
        }
    }

    /// The system drive is never a network drive; a UNC path is not a
    /// drive-letter path at all.
    #[test]
    fn local_and_unc_paths_are_not_network_drives() {
        let system = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        assert_eq!(
            network_drive_target(&format!(r"{system}\Windows")),
            Ok(None)
        );
        assert_eq!(network_drive_target(r"\\srv\share\x"), Ok(None));
    }
}
