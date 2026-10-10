// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Stable directory identity — volume serial number + file ID — for the
//! walker's reparse-point loop detection over SMB (ADR 0062).
//!
//! Over SMB, `GetFinalPathNameByHandleW` (what `std::fs::canonicalize`
//! uses) does not reliably resolve a server-side junction: once the client
//! has enumerated the junction's parent directory, it reports the path the
//! junction was *opened through* instead of its target. The file ID the
//! server returns for the opened directory is the same no matter which
//! route led to it, so it identifies a directory where the path cannot.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FileIdInfo, GetFileInformationByHandleEx, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};

/// Closes the wrapped handle on drop, on every return path.
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful CreateFileW call (the
        // guard is only constructed for a valid handle) and is closed
        // exactly once, here.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Returns the identity of the directory `path` resolves to, as
/// `"fid:<volume serial>:<file id>"`, or `None` when it cannot be
/// determined.
///
/// The open follows reparse points (no `FILE_FLAG_OPEN_REPARSE_POINT`), so
/// a junction yields the identity of its *target*. `None` is returned when
/// the open or the query fails, or when the server reports a zero volume
/// serial or file ID — some non-Windows SMB servers do, and a zero would
/// make unrelated directories look identical. Callers fall back to the
/// path-based identity in that case.
///
/// Only `FILE_ID_INFO` is used: the older `GetFileInformationByHandle`
/// reports a volume serial of 0 over SMB (observed against Windows Server
/// 2022), which cannot tell two volumes behind one share apart.
pub(crate) fn directory_identity(path: &str) -> Option<String> {
    let api_path = validation::path::to_windows_api_path(path);
    let wide: Vec<u16> = OsStr::new(&api_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the
    // call; the security-attributes and template-handle pointers are null,
    // which CreateFileW permits. FILE_FLAG_BACKUP_SEMANTICS is required to
    // open a directory handle.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return None;
    }
    let guard = HandleGuard(handle);

    let mut info = FILE_ID_INFO {
        VolumeSerialNumber: 0,
        FileId: windows_sys::Win32::Storage::FileSystem::FILE_ID_128 {
            Identifier: [0; 16],
        },
    };
    // SAFETY: `guard.0` is a valid open handle; `info` is a properly
    // aligned FILE_ID_INFO and the size passed is exactly its size, so the
    // call cannot write past it.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            guard.0,
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if ok == 0 {
        return None;
    }
    identity_key(info.VolumeSerialNumber, info.FileId.Identifier)
}

/// Formats a volume serial + 128-bit file ID as the loop-detection key.
/// Pure, so the zero-rejection rule is unit-testable without a filesystem.
fn identity_key(volume_serial: u64, file_id: [u8; 16]) -> Option<String> {
    let id = u128::from_le_bytes(file_id);
    if volume_serial == 0 || id == 0 {
        return None;
    }
    Some(format!("fid:{volume_serial:016x}:{id:032x}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_key_formats_serial_and_id() {
        let mut id = [0u8; 16];
        id[0] = 0xC3;
        id[1] = 0x71;
        id[8] = 0x02;
        // Little-endian bytes: high 64 bits = 0x2, low 64 bits = 0x71c3.
        assert_eq!(
            identity_key(0x9c6e_9943_6e99_16dc, id).as_deref(),
            Some("fid:9c6e99436e9916dc:000000000000000200000000000071c3")
        );
    }

    #[test]
    fn identity_key_rejects_zero_serial_or_zero_id() {
        let mut id = [0u8; 16];
        id[0] = 1;
        assert_eq!(identity_key(0, id), None, "zero volume serial");
        assert_eq!(identity_key(1, [0; 16]), None, "zero file id");
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let d = std::env::temp_dir().join(format!("adpa-fid-{tag}-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&d).expect("create temp dir");
        d
    }

    #[test]
    fn same_directory_has_the_same_identity_and_others_differ() {
        let root = temp_dir("same");
        let a = root.join("a");
        let b = root.join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let ia = directory_identity(&a.to_string_lossy()).expect("identity of a");
        let ia_again = directory_identity(&format!("{}\\", a.to_string_lossy()))
            .expect("a with trailing separator");
        let ib = directory_identity(&b.to_string_lossy()).expect("identity of b");
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(ia, ia_again);
        assert_ne!(ia, ib);
        assert!(ia.starts_with("fid:"), "{ia}");
    }

    /// The property the walker relies on: a junction resolves to the
    /// identity of its target directory.
    #[test]
    fn junction_has_the_identity_of_its_target() {
        let root = temp_dir("junction");
        let target = root.join("target");
        std::fs::create_dir_all(&target).unwrap();
        let link = root.join("link");
        let status = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &link.to_string_lossy(),
                &target.to_string_lossy(),
            ])
            .status()
            .expect("spawn mklink");
        assert!(
            status.success(),
            "mklink /J failed ({status}) — this test requires NTFS junctions"
        );
        let it = directory_identity(&target.to_string_lossy()).expect("identity of target");
        let il = directory_identity(&link.to_string_lossy()).expect("identity via junction");
        let _ = std::process::Command::new("cmd")
            .args(["/C", "rmdir", &link.to_string_lossy()])
            .status();
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(it, il);
    }

    #[test]
    fn nonexistent_path_has_no_identity() {
        assert_eq!(
            directory_identity(r"C:\adpa-definitely-missing-dir-7f3a"),
            None
        );
    }
}
