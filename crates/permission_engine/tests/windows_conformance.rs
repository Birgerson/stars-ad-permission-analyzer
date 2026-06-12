// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! Windows authorization conformance harness (engine review 2026-06-12
//! finding 2).
//!
//! The engine's unit tests prove the stored-order DACL algorithm against
//! hand-written fixtures. This harness proves the same algorithm against
//! the **operating system's own ACL evaluation** — it builds a real
//! in-memory Windows ACL for the current user, asks Windows for the
//! effective rights via `GetEffectiveRightsFromAclW`, feeds the
//! equivalent `AceEntry` sequence into [`DefaultPermissionEngine`], and
//! asserts the two effective masks agree.
//!
//! These tests are `#[ignore]` by default: they require a real Windows
//! desktop/lab session and exercise Win32 APIs. Run them explicitly:
//!
//! ```text
//! cargo test -p permission_engine --test windows_conformance -- --ignored
//! ```
//!
//! Scope and honest limitation: `GetEffectiveRightsFromAclW` returns the
//! effective rights for a single trustee from a DACL. It is the closest
//! single-call ground truth for the core stored-order algorithm, and it
//! is exactly what the engine computes for one trustee. A fuller
//! conformance step — comparing token-based, multi-group evaluation
//! against `AccessCheck`/`AuthzAccessCheck` with a constructed token —
//! is a documented next extension (see docs/known-limitations.md). This
//! harness deliberately uses concrete file-rights masks (no `GENERIC_*`)
//! so the comparison is bit-exact and not clouded by generic expansion.

#![cfg(windows)]

use std::ptr;

use adpa_core::model::{
    AccessContext, AccessMask, AceEntry, AceKind, FileSystemObject, Identity, IdentityKind,
    LocalGroupEvalStatus, NormalizedPath, ShareMaskStatus, Sid,
};
use adpa_core::traits::{PermissionEvaluationInput, PermissionEvaluator};
use permission_engine::mask::{MASK_FULL_CONTROL, MASK_READ, MASK_WRITE};
use permission_engine::DefaultPermissionEngine;

use windows_sys::Win32::Foundation::{LocalFree, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetEffectiveRightsFromAclW, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    AddAccessAllowedAce, AddAccessDeniedAce, GetLengthSid, GetTokenInformation, InitializeAcl,
    TokenUser, ACL, ACL_REVISION, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// A single ACE in a conformance fixture: kind + concrete access mask.
#[derive(Clone, Copy)]
struct FixtureAce {
    kind: AceKind,
    mask: u32,
}

/// Returns the current process user's SID as a canonical string and as a
/// raw owned byte buffer (the live `PSID` for Win32 calls).
///
/// # Safety
/// Calls Win32 token APIs; the returned buffer owns the SID bytes for the
/// duration of the test.
unsafe fn current_user_sid() -> (String, Vec<u8>) {
    let mut token: HANDLE = INVALID_HANDLE_VALUE;
    let ok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token);
    assert!(ok != 0, "OpenProcessToken failed");

    // First call: discover the required buffer size.
    let mut needed: u32 = 0;
    GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
    assert!(needed > 0, "GetTokenInformation size probe failed");

    let mut buf = vec![0u8; needed as usize];
    let ok = GetTokenInformation(
        token,
        TokenUser,
        buf.as_mut_ptr().cast(),
        needed,
        &mut needed,
    );
    assert!(ok != 0, "GetTokenInformation(TokenUser) failed");

    // SAFETY: buf holds a TOKEN_USER whose Sid points inside the same buffer.
    let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
    let psid = token_user.User.Sid;
    assert!(!psid.is_null(), "token user SID is null");

    // Copy the SID bytes into an owned buffer so it outlives `buf`.
    let sid_len = GetLengthSid(psid) as usize;
    let mut sid_bytes = vec![0u8; sid_len];
    ptr::copy_nonoverlapping(psid.cast::<u8>(), sid_bytes.as_mut_ptr(), sid_len);

    // Stringify for the AceEntry / token.
    let mut wide: *mut u16 = ptr::null_mut();
    let ok = ConvertSidToStringSidW(psid, &mut wide);
    assert!(ok != 0 && !wide.is_null(), "ConvertSidToStringSidW failed");
    let mut len = 0usize;
    while *wide.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(wide, len);
    let sid_str = String::from_utf16_lossy(slice);
    LocalFree(wide.cast());

    (sid_str, sid_bytes)
}

/// Asks Windows for the effective rights of `sid_bytes` against an ACL
/// built from `fixture` (ACEs added in the given order).
///
/// # Safety
/// Builds and passes raw Win32 structures.
unsafe fn windows_effective_mask(fixture: &[FixtureAce], sid_bytes: &mut [u8]) -> u32 {
    // DWORD-aligned ACL buffer, generously sized for a handful of ACEs.
    let mut acl_buf = vec![0u32; 256];
    let pacl = acl_buf.as_mut_ptr() as *mut ACL;
    let ok = InitializeAcl(pacl, (acl_buf.len() * 4) as u32, ACL_REVISION);
    assert!(ok != 0, "InitializeAcl failed");

    let psid = sid_bytes.as_mut_ptr().cast();
    for ace in fixture {
        let ok = match ace.kind {
            AceKind::Allow => AddAccessAllowedAce(pacl, ACL_REVISION, ace.mask, psid),
            AceKind::Deny => AddAccessDeniedAce(pacl, ACL_REVISION, ace.mask, psid),
        };
        assert!(ok != 0, "AddAccess*Ace failed");
    }

    let trustee = TRUSTEE_W {
        pMultipleTrustee: ptr::null_mut(),
        MultipleTrusteeOperation: 0,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_USER,
        ptstrName: psid.cast(),
    };

    let mut access: u32 = 0;
    let rc = GetEffectiveRightsFromAclW(pacl, &trustee, &mut access);
    assert_eq!(rc, 0, "GetEffectiveRightsFromAclW failed with {rc}");
    access
}

/// Runs the Stars engine over the same fixture for `sid_str` and returns
/// the effective NTFS mask.
fn stars_effective_mask(fixture: &[FixtureAce], sid_str: &str) -> u32 {
    let dacl: Vec<AceEntry> = fixture
        .iter()
        .map(|a| AceEntry {
            kind: a.kind,
            sid: Sid(sid_str.to_string()),
            mask: AccessMask(a.mask),
            inherited: false,
            inheritance_flags: 0,
            propagation_flags: 0,
        })
        .collect();

    let fso = FileSystemObject {
        path: NormalizedPath(r"C:\conformance\fixture".to_string()),
        is_directory: true,
        owner_sid: None,
        dacl,
        inheritance_disabled: true,
        is_reparse_point: false,
        unsupported_aces: vec![],
        null_dacl: false,
        sd_hash: None,
    };

    let identity = Identity {
        sid: Sid(sid_str.to_string()),
        name: Some("conformance-user".to_string()),
        domain: None,
        kind: IdentityKind::User,
        disabled: false,
        user_principal_name: None,
    };

    let result = DefaultPermissionEngine
        .evaluate(PermissionEvaluationInput {
            identity,
            group_memberships: vec![],
            file_system_object: fso,
            share_status: ShareMaskStatus::NotApplicable,
            local_group_sids: vec![],
            local_group_status: LocalGroupEvalStatus::NotQueried,
            access_context: AccessContext::Unspecified,
            unsupported_share_ace_count: 0,
            sid_names: std::collections::BTreeMap::new(),
            group_resolution_via_sam_fallback: false,
            identity_not_in_configured_ldap_base: false,
            identity_disabled_status_unknown: false,
            identity_lookup_failure_reason: None,
            group_resolution_failure_reason: None,
            identity_resolved_via_fsp: false,
            group_resolution_via_global_catalog: false,
        })
        .expect("engine evaluation must succeed");
    result.ntfs_mask.0
}

/// Compares Windows and Stars effective masks for one fixture.
fn assert_conformance(label: &str, fixture: &[FixtureAce]) {
    // SAFETY: all calls operate on locally owned buffers.
    let (sid_str, mut sid_bytes) = unsafe { current_user_sid() };
    let win = unsafe { windows_effective_mask(fixture, &mut sid_bytes) };
    let stars = stars_effective_mask(fixture, &sid_str);
    assert_eq!(
        win, stars,
        "{label}: Windows GetEffectiveRightsFromAclW (0x{win:08X}) != Stars engine (0x{stars:08X})"
    );
}

#[test]
#[ignore = "requires a Windows session; run with --ignored"]
fn conformance_allow_read_execute() {
    assert_conformance(
        "Allow Read & Execute",
        &[FixtureAce {
            kind: AceKind::Allow,
            mask: MASK_READ,
        }],
    );
}

#[test]
#[ignore = "requires a Windows session; run with --ignored"]
fn conformance_allow_full_control() {
    assert_conformance(
        "Allow Full Control",
        &[FixtureAce {
            kind: AceKind::Allow,
            mask: MASK_FULL_CONTROL,
        }],
    );
}

#[test]
#[ignore = "requires a Windows session; run with --ignored"]
fn conformance_deny_write_over_allow_full() {
    // Canonical order: explicit Deny first, then Allow. Windows removes
    // the denied bits; Stars must agree.
    assert_conformance(
        "Deny Write then Allow Full",
        &[
            FixtureAce {
                kind: AceKind::Deny,
                mask: MASK_WRITE,
            },
            FixtureAce {
                kind: AceKind::Allow,
                mask: MASK_FULL_CONTROL,
            },
        ],
    );
}

#[test]
#[ignore = "requires a Windows session; run with --ignored"]
fn conformance_two_allows_accumulate() {
    assert_conformance(
        "Allow Read then Allow Write",
        &[
            FixtureAce {
                kind: AceKind::Allow,
                mask: MASK_READ,
            },
            FixtureAce {
                kind: AceKind::Allow,
                mask: MASK_WRITE,
            },
        ],
    );
}
