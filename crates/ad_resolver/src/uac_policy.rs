// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Read-only access to the User Account Control policy values of an
//! analysis target (ADR 0076).
//!
//! Remote UAC — whether a local account's **network** token is filtered —
//! is decided by `LocalAccountTokenFilterPolicy` and
//! `FilterAdministratorToken` under
//! `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
//! (`EnableLUA` = 0 switches UAC off). Stars reads them through the remote
//! registry with `KEY_QUERY_VALUE` only — it never writes. A value that
//! cannot be read is reported as such; the caller then keeps the bounded
//! result (ADR 0070).

use adpa_core::model::PolicyDword;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegConnectRegistryW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_QUERY_VALUE, REG_DWORD,
};

const POLICIES_SYSTEM: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

/// The UAC policy values of one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetUacPolicy {
    pub enable_lua: PolicyDword,
    pub local_account_token_filter_policy: PolicyDword,
    pub filter_administrator_token: PolicyDword,
}

impl TargetUacPolicy {
    fn unreadable(reason: &str) -> Self {
        Self {
            enable_lua: PolicyDword::Unreadable(reason.to_owned()),
            local_account_token_filter_policy: PolicyDword::Unreadable(reason.to_owned()),
            filter_administrator_token: PolicyDword::Unreadable(reason.to_owned()),
        }
    }
}

/// Closes a registry handle on drop.
struct KeyGuard(HKEY);

impl Drop for KeyGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle was opened by RegConnectRegistryW /
            // RegOpenKeyExW and is closed exactly once here.
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Reads the UAC policy values of `server` (`None` = this machine).
/// An invalid server name is never passed to the API.
pub fn read_target_uac_policy(server: Option<&str>) -> TargetUacPolicy {
    let machine = match server {
        Some(s) => match validation::net::validate_smb_server(s) {
            Ok(v) => Some(wide(&format!(r"\\{}", v.0))),
            Err(_) => return TargetUacPolicy::unreadable("invalid server name"),
        },
        None => None,
    };
    let mut root: HKEY = std::ptr::null_mut();
    // SAFETY: `machine` is a null-terminated UTF-16 string (or null for the
    // local machine); `root` receives a handle owned by the guard below.
    let rc = unsafe {
        RegConnectRegistryW(
            machine.as_ref().map_or(std::ptr::null(), |m| m.as_ptr()),
            HKEY_LOCAL_MACHINE,
            &mut root,
        )
    };
    if rc != ERROR_SUCCESS {
        return TargetUacPolicy::unreadable(&format!("remote registry not reachable (error {rc})"));
    }
    let root = KeyGuard(root);
    let path = wide(POLICIES_SYSTEM);
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: valid root handle, null-terminated path, read-only access mask.
    let rc = unsafe { RegOpenKeyExW(root.0, path.as_ptr(), 0, KEY_QUERY_VALUE, &mut key) };
    if rc == ERROR_FILE_NOT_FOUND {
        return TargetUacPolicy {
            enable_lua: PolicyDword::Absent,
            local_account_token_filter_policy: PolicyDword::Absent,
            filter_administrator_token: PolicyDword::Absent,
        };
    }
    if rc != ERROR_SUCCESS {
        return TargetUacPolicy::unreadable(&format!("policy key not readable (error {rc})"));
    }
    let key = KeyGuard(key);
    TargetUacPolicy {
        enable_lua: query_dword(key.0, "EnableLUA"),
        local_account_token_filter_policy: query_dword(key.0, "LocalAccountTokenFilterPolicy"),
        filter_administrator_token: query_dword(key.0, "FilterAdministratorToken"),
    }
}

/// One REG_DWORD value; any other type or size is `Unreadable` — values
/// from the OS are validated like input.
fn query_dword(key: HKEY, name: &str) -> PolicyDword {
    let name_w = wide(name);
    let mut kind: u32 = 0;
    let mut data: u32 = 0;
    let mut size: u32 = std::mem::size_of::<u32>() as u32;
    // SAFETY: valid key handle, null-terminated name; the buffer is a u32
    // and its size is passed explicitly.
    let rc = unsafe {
        RegQueryValueExW(
            key,
            name_w.as_ptr(),
            std::ptr::null(),
            &mut kind,
            (&mut data as *mut u32).cast(),
            &mut size,
        )
    };
    match rc {
        ERROR_SUCCESS if kind == REG_DWORD && size == 4 => PolicyDword::Value(data),
        ERROR_SUCCESS => PolicyDword::Unreadable(format!("{name} has an unexpected type")),
        ERROR_FILE_NOT_FOUND => PolicyDword::Absent,
        other => PolicyDword::Unreadable(format!("{name} not readable (error {other})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_server_is_never_queried() {
        let p = read_target_uac_policy(Some(r"bad\server"));
        assert!(matches!(p.enable_lua, PolicyDword::Unreadable(_)));
        assert!(matches!(
            p.local_account_token_filter_policy,
            PolicyDword::Unreadable(_)
        ));
    }

    /// The local machine's values are readable (or absent) — a smoke test
    /// of the read path; it never writes.
    #[test]
    fn local_policy_is_readable() {
        let p = read_target_uac_policy(None);
        assert!(!matches!(p.enable_lua, PolicyDword::Unreadable(_)), "{p:?}");
    }
}
