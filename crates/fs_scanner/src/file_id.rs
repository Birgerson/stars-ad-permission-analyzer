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

use adpa_core::model::{LinkInfo, LinkKind};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FileIdInfo, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_ID_INFO, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

/// `FSCTL_GET_REPARSE_POINT` (winioctl.h).
const FSCTL_GET_REPARSE_POINT: u32 = 0x0009_00A8;
/// `IO_REPARSE_TAG_MOUNT_POINT`: a junction (winnt.h).
const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
/// `IO_REPARSE_TAG_SYMLINK`: a symbolic link (winnt.h).
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
/// `SYMLINK_FLAG_RELATIVE`: the target is relative to the link's folder.
const SYMLINK_FLAG_RELATIVE: u32 = 1;
/// `MAXIMUM_REPARSE_DATA_BUFFER_SIZE` (winnt.h).
const MAX_REPARSE_DATA: usize = 16 * 1024;

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
#[cfg(test)]
pub(crate) fn directory_identity(path: &str) -> Option<String> {
    probe_directory(path).identity
}

/// What one open of a directory tells the walker: its identity (see
/// [`directory_identity`]) and the path the handle was really opened on
/// (ADR 0085).
pub(crate) struct DirectoryProbe {
    pub(crate) identity: Option<String>,
    /// Why `identity` is `None` (ADR 0088): the open or the query failed,
    /// or the server reports no file ID.
    pub(crate) identity_error: Option<String>,
    /// `\\server\share\…` the redirector opened, or `None`.
    pub(crate) final_path: Option<String>,
}

/// Opens `path` and reads both its identity and its final path. ADR 0088
/// (lab 2026-10-25): one failed open during a busy scan made a directory
/// already enumerated through a junction look new, so its content was
/// listed twice — a failure is retried twice (after 50 ms and 250 ms)
/// before it stands.
pub(crate) fn probe_directory(path: &str) -> DirectoryProbe {
    let mut probe = probe_directory_once(path);
    for (retry, pause) in [50, 250].into_iter().enumerate() {
        if probe.identity.is_some() {
            break;
        }
        let first = probe.identity_error.clone().unwrap_or_default();
        std::thread::sleep(std::time::Duration::from_millis(pause));
        probe = probe_directory_once(path);
        if probe.identity.is_some() {
            tracing::info!(
                path,
                retry = retry + 1,
                first_error = first,
                "Directory identity read on retry"
            );
        }
    }
    probe
}

fn probe_directory_once(path: &str) -> DirectoryProbe {
    let guard = match open_for_attributes(path) {
        Ok(guard) => guard,
        Err(code) => {
            return DirectoryProbe {
                identity: None,
                identity_error: Some(format!(
                    "the folder could not be opened, Windows error {code}"
                )),
                final_path: None,
            }
        }
    };
    let (identity, identity_error) = match identity_of(&guard) {
        Ok(id) => (Some(id), None),
        Err(reason) => (None, Some(reason)),
    };
    DirectoryProbe {
        identity,
        identity_error,
        final_path: final_path_of(&guard),
    }
}

/// The UNC path the redirector really opened for `path`, as
/// `\\server\share\…` — for a path through a DFS namespace the folder
/// target this machine is referred to (ADR 0085, lab 2026-10-24:
/// `\\corp.test\dfs\Projects\Sub` → `\\FS-01.corp.test\DfsProj\Sub`; a
/// plain UNC path comes back with the same server and share, only the case
/// normalized). `None` for a local path or when the open or the query fails.
///
/// Over SMB the components *below* the share are not reliable for a
/// server-side junction (ADR 0062); callers use only server and share.
pub fn final_unc_path(path: &str) -> Option<String> {
    let guard = open_for_attributes(path).ok()?;
    final_path_of(&guard)
}

/// Reads the target the junction or symbolic link at `path` stores
/// (`FSCTL_GET_REPARSE_POINT` on the link itself, not its target). `None`
/// when the link cannot be opened or read, is neither a junction nor a
/// symbolic link, or its data fails validation.
pub(crate) fn link_target(path: &str) -> Option<LinkInfo> {
    let guard = open_handle(
        path,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )
    .ok()?;
    let mut buf = vec![0u8; MAX_REPARSE_DATA];
    let mut returned: u32 = 0;
    // SAFETY: `guard.0` is a valid open handle; there is no input buffer;
    // `buf` is a writable buffer whose length is passed explicitly, and
    // `returned` receives the byte count. No OVERLAPPED: a synchronous call.
    let ok = unsafe {
        DeviceIoControl(
            guard.0,
            FSCTL_GET_REPARSE_POINT,
            std::ptr::null(),
            0,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return None;
    }
    parse_reparse_data(buf.get(..returned as usize)?)
}

/// Parses a `REPARSE_DATA_BUFFER` of a junction or symbolic link. Every
/// length and offset Windows (or an SMB server) returned is checked before
/// use; anything out of bounds, odd-sized, empty or with control characters
/// gives `None`. Pure.
fn parse_reparse_data(data: &[u8]) -> Option<LinkInfo> {
    let u16_at = |b: &[u8], o: usize| b.get(o..o + 2).map(|x| u16::from_le_bytes([x[0], x[1]]));
    let tag = data
        .get(0..4)
        .map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))?;
    let body_len = u16_at(data, 4)? as usize;
    let body = data.get(8..8 + body_len)?;
    let (kind, names_at, relative) = match tag {
        IO_REPARSE_TAG_MOUNT_POINT => (LinkKind::Junction, 8, false),
        IO_REPARSE_TAG_SYMLINK => {
            let flags = body
                .get(8..12)
                .map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))?;
            (
                LinkKind::SymbolicLink,
                12,
                flags & SYMLINK_FLAG_RELATIVE != 0,
            )
        }
        _ => return None,
    };
    let names = body.get(names_at..)?;
    let name = |offset: usize, len: usize| -> Option<String> {
        if !offset.is_multiple_of(2) || !len.is_multiple_of(2) {
            return None;
        }
        let units: Vec<u16> = names
            .get(offset..offset.checked_add(len)?)?
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16(&units).ok()
    };
    let print = name(u16_at(body, 4)? as usize, u16_at(body, 6)? as usize)?;
    let target = if print.is_empty() {
        let substitute = name(u16_at(body, 0)? as usize, u16_at(body, 2)? as usize)?;
        substitute
            .strip_prefix(r"\??\")
            .map(str::to_owned)
            .unwrap_or(substitute)
    } else {
        print
    };
    if target.is_empty() || target.len() > 32_767 || target.chars().any(char::is_control) {
        return None;
    }
    Some(LinkInfo {
        kind,
        target,
        relative,
    })
}

fn open_for_attributes(path: &str) -> Result<HandleGuard, u32> {
    open_handle(path, FILE_FLAG_BACKUP_SEMANTICS)
}

/// Opens `path` for its attributes with the given flags; the Windows error
/// when the open fails.
fn open_handle(path: &str, flags: FILE_FLAGS_AND_ATTRIBUTES) -> Result<HandleGuard, u32> {
    let api_path = validation::path::to_windows_api_path(path);
    let wide: Vec<u16> = OsStr::new(&api_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the
    // call; the security-attributes and template-handle pointers are null,
    // which CreateFileW permits. FILE_FLAG_BACKUP_SEMANTICS (in `flags`) is
    // required to open a directory handle.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            flags,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        // SAFETY: reads the calling thread's last-error value, set by the
        // failed CreateFileW call above.
        return Err(unsafe { GetLastError() });
    }
    Ok(HandleGuard(handle))
}

/// `\\server\share\…` of an open handle, `None` unless it is a UNC path.
fn final_path_of(guard: &HandleGuard) -> Option<String> {
    let mut buf: Vec<u16> = vec![0; 1024];
    loop {
        // SAFETY: `guard.0` is a valid open handle; `buf` is a writable
        // buffer whose length in UTF-16 units is passed explicitly.
        let n = unsafe {
            GetFinalPathNameByHandleW(
                guard.0,
                buf.as_mut_ptr(),
                buf.len() as u32,
                FILE_NAME_NORMALIZED,
            )
        } as usize;
        if n == 0 {
            return None;
        }
        if n < buf.len() {
            let raw = String::from_utf16(&buf[..n]).ok()?;
            return unc_form(&raw);
        }
        // Too small: `n` is the size needed, terminator included. Bounded
        // by the longest Windows path.
        if n > 32_768 {
            return None;
        }
        buf = vec![0; n];
    }
}

/// `\\?\UNC\server\share\…` → `\\server\share\…`; anything else → `None`.
fn unc_form(raw: &str) -> Option<String> {
    let unc = validation::path::strip_long_path_prefix(raw);
    validation::path::parse_unc_components(&unc).map(|_| unc)
}

/// The identity of an open handle, or why there is none.
fn identity_of(guard: &HandleGuard) -> Result<String, String> {
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
        // SAFETY: reads the last-error value of the failed call above.
        let code = unsafe { GetLastError() };
        return Err(format!(
            "the server did not return its file ID, Windows error {code}"
        ));
    }
    identity_key(info.VolumeSerialNumber, info.FileId.Identifier).ok_or_else(|| {
        "the server reports a volume serial or file ID of 0 (some non-Windows SMB servers do)"
            .to_owned()
    })
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
    fn unc_form_keeps_only_unc_paths() {
        assert_eq!(
            unc_form(r"\\?\UNC\FS-01.corp.test\DfsProj\Sub").as_deref(),
            Some(r"\\FS-01.corp.test\DfsProj\Sub")
        );
        assert_eq!(unc_form(r"\\?\C:\data"), None);
        assert_eq!(unc_form(r"C:\data"), None);
    }

    #[test]
    fn a_local_path_has_no_final_unc_path() {
        let root = temp_dir("final");
        assert_eq!(final_unc_path(&root.to_string_lossy()), None);
        let _ = std::fs::remove_dir_all(&root);
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

    /// ADR 0088: a probe that fails (after its retries) says why.
    #[test]
    fn a_failed_probe_says_why() {
        let p = probe_directory(r"C:\adpa-definitely-missing-dir-7f3a");
        assert!(p.identity.is_none() && p.final_path.is_none());
        let why = p.identity_error.expect("a reason");
        assert!(
            why.contains("could not be opened")
                && (why.ends_with("error 2") || why.ends_with("error 3")),
            "{why}"
        );
        // A readable directory has an identity and no reason.
        let ok = probe_directory(&std::env::temp_dir().to_string_lossy());
        assert!(ok.identity.is_some() && ok.identity_error.is_none());
    }

    /// A `REPARSE_DATA_BUFFER` as Windows returns it: header, the four name
    /// offsets/lengths, the flags for a symbolic link, then both names.
    fn reparse_buffer(tag: u32, flags: Option<u32>, substitute: &str, print: &str) -> Vec<u8> {
        let utf16 = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let (sub, pr) = (utf16(substitute), utf16(print));
        let mut names = sub.clone();
        names.extend([0, 0]);
        let print_offset = names.len();
        names.extend(&pr);
        names.extend([0, 0]);
        let mut body = Vec::new();
        body.extend(0u16.to_le_bytes());
        body.extend((sub.len() as u16).to_le_bytes());
        body.extend((print_offset as u16).to_le_bytes());
        body.extend((pr.len() as u16).to_le_bytes());
        if let Some(f) = flags {
            body.extend(f.to_le_bytes());
        }
        body.extend(names);
        let mut data = Vec::new();
        data.extend(tag.to_le_bytes());
        data.extend((body.len() as u16).to_le_bytes());
        data.extend([0, 0]);
        data.extend(body);
        data
    }

    #[test]
    fn reparse_data_of_junctions_and_symbolic_links_is_parsed() {
        let junction = reparse_buffer(
            IO_REPARSE_TAG_MOUNT_POINT,
            None,
            r"\??\T:\Enterprise\Finance\P01",
            r"T:\Enterprise\Finance\P01",
        );
        assert_eq!(
            parse_reparse_data(&junction),
            Some(LinkInfo {
                kind: LinkKind::Junction,
                target: r"T:\Enterprise\Finance\P01".into(),
                relative: false,
            })
        );
        let absolute = reparse_buffer(
            IO_REPARSE_TAG_SYMLINK,
            Some(0),
            r"\??\T:\Enterprise\Finance\P02_2021",
            r"T:\Enterprise\Finance\P02_2021",
        );
        let parsed = parse_reparse_data(&absolute).unwrap();
        assert_eq!(parsed.kind, LinkKind::SymbolicLink);
        assert!(!parsed.relative);
        assert_eq!(parsed.target, r"T:\Enterprise\Finance\P02_2021");
        let relative = reparse_buffer(IO_REPARSE_TAG_SYMLINK, Some(1), r"..\P02", r"..\P02");
        assert!(parse_reparse_data(&relative).unwrap().relative);
        // No print name: the substitute name, without `\??\`.
        let no_print = reparse_buffer(IO_REPARSE_TAG_MOUNT_POINT, None, r"\??\C:\data", "");
        assert_eq!(parse_reparse_data(&no_print).unwrap().target, r"C:\data");
    }

    /// Values from the OS (or an SMB server) are validated before use.
    #[test]
    fn malformed_reparse_data_is_rejected() {
        let good = reparse_buffer(IO_REPARSE_TAG_SYMLINK, Some(0), r"\??\C:\x", r"C:\x");
        assert!(parse_reparse_data(&good).is_some());
        // Truncated anywhere.
        for len in [0, 3, 7, 12, 19, good.len() - 1] {
            assert_eq!(parse_reparse_data(&good[..len]), None, "length {len}");
        }
        // Another reparse tag (e.g. a cloud file placeholder).
        let mut other = good.clone();
        other[0..4].copy_from_slice(&0x9000_001Au32.to_le_bytes());
        assert_eq!(parse_reparse_data(&other), None);
        // A declared body longer than the data.
        let mut long = good.clone();
        long[4..6].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(parse_reparse_data(&long), None);
        // An odd or out-of-range print-name offset.
        let mut odd = good.clone();
        odd[12..14].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(parse_reparse_data(&odd), None);
        let mut far = good.clone();
        far[12..14].copy_from_slice(&4000u16.to_le_bytes());
        assert_eq!(parse_reparse_data(&far), None);
        // A control character in the stored target.
        let ctl = reparse_buffer(
            IO_REPARSE_TAG_SYMLINK,
            Some(0),
            "\\??\\C:\\a\u{7}b",
            "C:\\a\u{7}b",
        );
        assert_eq!(parse_reparse_data(&ctl), None);
        // Neither name set.
        let empty = reparse_buffer(IO_REPARSE_TAG_MOUNT_POINT, None, "", "");
        assert_eq!(parse_reparse_data(&empty), None);
    }

    /// A real junction (`mklink /J` needs no privilege): its stored target is
    /// read from the link itself, not from what it points to.
    #[test]
    fn the_target_of_a_real_junction_is_read() {
        let root = std::env::temp_dir().join(format!("adpa-link-target-{}", std::process::id()));
        let target = root.join("target");
        let link = root.join("link");
        std::fs::create_dir_all(&target).unwrap();
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
        assert!(status.success(), "mklink /J failed ({status})");
        let read = link_target(&link.to_string_lossy());
        let _ = std::process::Command::new("cmd")
            .args(["/C", "rmdir", &link.to_string_lossy()])
            .status();
        let _ = std::fs::remove_dir_all(&root);
        let read = read.expect("link target of a junction");
        assert_eq!(read.kind, LinkKind::Junction);
        assert_eq!(
            read.target.to_lowercase(),
            target.to_string_lossy().to_lowercase()
        );
        // A plain directory is no link.
        assert_eq!(link_target(&std::env::temp_dir().to_string_lossy()), None);
    }
}
