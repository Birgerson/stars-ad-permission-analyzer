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
//! These tests are `#[ignore]` by default — they require a real Windows
//! session/token and exercise Win32 APIs, so they are kept out of the
//! plain `cargo test --workspace` run. Run them explicitly:
//!
//! ```text
//! cargo test -p permission_engine --test windows_conformance -- --ignored
//! ```
//!
//! The CI workflow runs exactly this command in a dedicated `conformance`
//! job on `windows-latest` for every push (`.github/workflows/ci.yml`),
//! so conformance is verified per commit rather than only locally.
//!
//! Two levels of ground truth:
//!
//! - **Single-trustee** via `GetEffectiveRightsFromAclW`: the closest
//!   single-call truth for the core stored-order algorithm, exactly what
//!   the engine computes for one trustee.
//! - **Token-based, multi-group** via `AccessCheck`: builds an absolute
//!   security descriptor plus a duplicated impersonation token and asks
//!   the OS for the `MAXIMUM_ALLOWED` access across a DACL whose ACEs
//!   target several principals in the token (the user plus the implicit
//!   `Everyone` / `Authenticated Users`). This exercises real
//!   multi-principal evaluation, including a Deny on one group beating an
//!   Allow on another.
//!
//! A further step — `AuthzAccessCheck` with a fully synthetic token
//! (arbitrary forged group memberships) — needs `SeCreateTokenPrivilege`
//! and is left as optional future work.
//!
//! The harness deliberately uses concrete file-rights masks (no
//! `GENERIC_*`) so the comparison is bit-exact and not clouded by generic
//! expansion.

#![cfg(windows)]

use std::ptr;

use adpa_core::model::{
    AccessContext, AccessMask, AceEntry, AceKind, FileSystemObject, Identity, IdentityKind,
    LocalGroupEvalStatus, NormalizedPath, ShareMaskStatus, Sid,
};
use adpa_core::traits::{PermissionEvaluationInput, PermissionEvaluator, ResolutionProvenance};
use permission_engine::mask::{MASK_FULL_CONTROL, MASK_READ, MASK_WRITE};
use permission_engine::DefaultPermissionEngine;

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, GetEffectiveRightsFromAclW, TRUSTEE_IS_SID,
    TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    AccessCheck, AddAccessAllowedAce, AddAccessDeniedAce, DuplicateToken, GetLengthSid,
    GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor, SetSecurityDescriptorDacl,
    SetSecurityDescriptorGroup, SetSecurityDescriptorOwner, TokenUser, ACL, ACL_REVISION,
    GENERIC_MAPPING, PRIVILEGE_SET, SECURITY_DESCRIPTOR, SECURITY_IMPERSONATION_LEVEL,
    TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// `SecurityImpersonation` impersonation level (winnt.h).
const SECURITY_IMPERSONATION: SECURITY_IMPERSONATION_LEVEL = 2;
/// `MAXIMUM_ALLOWED` desired-access flag (winnt.h) — asks `AccessCheck`
/// to return the maximal access the token is granted, i.e. the effective
/// mask, exactly what the Stars engine computes.
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// File `GENERIC_MAPPING` (FILE_GENERIC_* from winnt.h).
fn file_generic_mapping() -> GENERIC_MAPPING {
    GENERIC_MAPPING {
        GenericRead: MASK_READ,
        GenericWrite: MASK_WRITE,
        GenericExecute: 0x0012_00A0,
        GenericAll: MASK_FULL_CONTROL,
    }
}

/// Which principal an ACE in a multi-group fixture targets — and, for the
/// owner-related fixtures, which principal owns the object.
#[derive(Clone, Copy)]
enum Principal {
    User,
    Everyone,
    AuthenticatedUsers,
    /// Well-known `OWNER RIGHTS` (Windows Server 2008+). An ACE for this
    /// SID governs the *owner's* rights and replaces the implicit
    /// `READ_CONTROL | WRITE_DAC` grant.
    OwnerRights,
}

impl Principal {
    fn sid_string(self, user_sid: &str) -> String {
        match self {
            Principal::User => user_sid.to_string(),
            Principal::Everyone => "S-1-1-0".to_string(),
            Principal::AuthenticatedUsers => "S-1-5-11".to_string(),
            Principal::OwnerRights => "S-1-3-4".to_string(),
        }
    }
}

/// One ACE in a multi-group fixture: kind + mask + target principal.
#[derive(Clone, Copy)]
struct MultiAce {
    kind: AceKind,
    mask: u32,
    principal: Principal,
}

/// Converts a SID string into an owned byte buffer (live PSID).
///
/// # Safety
/// Calls Win32; the returned buffer owns the SID bytes.
unsafe fn sid_bytes_from_string(s: &str) -> Vec<u8> {
    let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let mut psid: *mut core::ffi::c_void = ptr::null_mut();
    let ok = ConvertStringSidToSidW(wide.as_ptr(), &mut psid);
    assert!(
        ok != 0 && !psid.is_null(),
        "ConvertStringSidToSidW({s}) failed"
    );
    let len = GetLengthSid(psid) as usize;
    let mut bytes = vec![0u8; len];
    ptr::copy_nonoverlapping(psid.cast::<u8>(), bytes.as_mut_ptr(), len);
    LocalFree(psid);
    bytes
}

/// Asks Windows `AccessCheck` for the effective (MAXIMUM_ALLOWED) mask of
/// the current process token against a DACL built from a multi-principal
/// fixture, with the object owned by `user_bytes`.
///
/// # Safety
/// Builds and passes raw Win32 security structures and a duplicated
/// impersonation token.
unsafe fn windows_accesscheck_mask(
    fixture: &[MultiAce],
    user_sid: &str,
    user_bytes: &mut [u8],
    owner: Principal,
) -> u32 {
    // Build one owned PSID buffer per distinct principal.
    let mut everyone = sid_bytes_from_string("S-1-1-0");
    let mut auth = sid_bytes_from_string("S-1-5-11");
    let mut owner_rights = sid_bytes_from_string("S-1-3-4");

    // DWORD-aligned ACL buffer.
    let mut acl_buf = vec![0u32; 256];
    let pacl = acl_buf.as_mut_ptr() as *mut ACL;
    assert!(
        InitializeAcl(pacl, (acl_buf.len() * 4) as u32, ACL_REVISION) != 0,
        "InitializeAcl failed"
    );
    {
        // Scoped so the mutable borrows of the SID buffers end before the
        // owner pointer below is taken.
        let mut psid_for = |p: Principal| -> *mut core::ffi::c_void {
            match p {
                Principal::User => user_bytes.as_mut_ptr().cast(),
                Principal::Everyone => everyone.as_mut_ptr().cast(),
                Principal::AuthenticatedUsers => auth.as_mut_ptr().cast(),
                Principal::OwnerRights => owner_rights.as_mut_ptr().cast(),
            }
        };
        for ace in fixture {
            let psid = psid_for(ace.principal);
            let ok = match ace.kind {
                AceKind::Allow => AddAccessAllowedAce(pacl, ACL_REVISION, ace.mask, psid),
                AceKind::Deny => AddAccessDeniedAce(pacl, ACL_REVISION, ace.mask, psid),
            };
            assert!(ok != 0, "AddAccess*Ace failed");
        }
    }

    // Absolute security descriptor. The owner is the fixture's `owner`
    // principal — normally the user, but the owner-semantics fixtures set a
    // *group* SID here to ask Windows whether the implicit owner grant
    // applies in that case. The group stays the user throughout.
    let mut sd: SECURITY_DESCRIPTOR = std::mem::zeroed();
    let psd: *mut core::ffi::c_void = (&mut sd as *mut SECURITY_DESCRIPTOR).cast();
    // 1 == SECURITY_DESCRIPTOR_REVISION
    assert!(
        InitializeSecurityDescriptor(psd, 1) != 0,
        "InitializeSecurityDescriptor failed"
    );
    let owner_psid: *mut core::ffi::c_void = match owner {
        Principal::User => user_bytes.as_mut_ptr().cast(),
        Principal::Everyone => everyone.as_mut_ptr().cast(),
        Principal::AuthenticatedUsers => auth.as_mut_ptr().cast(),
        Principal::OwnerRights => owner_rights.as_mut_ptr().cast(),
    };
    assert!(
        SetSecurityDescriptorOwner(psd, owner_psid, 0) != 0,
        "SetSecurityDescriptorOwner failed"
    );
    let group_psid: *mut core::ffi::c_void = user_bytes.as_mut_ptr().cast();
    assert!(
        SetSecurityDescriptorGroup(psd, group_psid, 0) != 0,
        "SetSecurityDescriptorGroup failed"
    );
    assert!(
        SetSecurityDescriptorDacl(psd, 1, pacl, 0) != 0,
        "SetSecurityDescriptorDacl failed"
    );

    // Impersonation token duplicated from the process token.
    let mut proc_token: HANDLE = INVALID_HANDLE_VALUE;
    assert!(
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut proc_token
        ) != 0,
        "OpenProcessToken failed"
    );
    let mut imp_token: HANDLE = INVALID_HANDLE_VALUE;
    assert!(
        DuplicateToken(proc_token, SECURITY_IMPERSONATION, &mut imp_token) != 0,
        "DuplicateToken failed"
    );

    let mapping = file_generic_mapping();
    let mut priv_set: PRIVILEGE_SET = std::mem::zeroed();
    let mut priv_len: u32 = std::mem::size_of::<PRIVILEGE_SET>() as u32;
    let mut granted: u32 = 0;
    let mut status: i32 = 0;
    let ok = AccessCheck(
        psd,
        imp_token,
        MAXIMUM_ALLOWED,
        &mapping,
        &mut priv_set,
        &mut priv_len,
        &mut granted,
        &mut status,
    );
    let _ = user_sid; // kept for symmetry with the Stars side
    CloseHandle(imp_token);
    CloseHandle(proc_token);
    let _ = (&mut everyone, &mut auth);
    assert!(ok != 0, "AccessCheck failed");
    granted
}

/// Runs the Stars engine over the same multi-principal fixture and returns
/// the effective NTFS mask. The object owner is the user (matching the
/// AccessCheck SD), and the engine's token implicitly contains Everyone
/// and Authenticated Users — the same principals the real process token
/// holds.
fn stars_multigroup_mask(fixture: &[MultiAce], user_sid: &str, owner: Principal) -> u32 {
    let dacl: Vec<AceEntry> = fixture
        .iter()
        .map(|a| AceEntry {
            kind: a.kind,
            sid: Sid(a.principal.sid_string(user_sid)),
            mask: AccessMask(a.mask),
            inherited: false,
            inheritance_flags: 0,
            propagation_flags: 0,
        })
        .collect();

    let fso = FileSystemObject {
        path: NormalizedPath(r"C:\conformance\multigroup".to_string()),
        is_directory: true,
        owner_sid: Some(Sid(owner.sid_string(user_sid))),
        dacl,
        inheritance_disabled: true,
        is_reparse_point: false,
        unsupported_aces: vec![],
        null_dacl: false,
        sd_hash: None,
    };

    let identity = Identity {
        sid: Sid(user_sid.to_string()),
        name: Some("conformance-user".to_string()),
        domain: None,
        kind: IdentityKind::User,
        disabled: false,
        user_principal_name: None,
        sid_history_count: 0,
        sid_history: Vec::new(),
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
            resolution: ResolutionProvenance::default(),
        })
        .expect("engine evaluation must succeed");
    result.ntfs_mask.0
}

/// Compares Windows `AccessCheck` (token-based, multi-principal) against
/// the Stars engine for one multi-group fixture.
fn assert_multigroup_conformance(label: &str, fixture: &[MultiAce]) {
    assert_multigroup_conformance_owned_by(label, fixture, Principal::User);
}

/// Like [`assert_multigroup_conformance`], but lets the fixture choose which
/// principal **owns** the object. Used by the owner-semantics fixtures: the
/// implicit `READ_CONTROL | WRITE_DAC` owner grant and its suppression by an
/// `OWNER RIGHTS` ACE were previously only unit-tested, never confirmed
/// against the real OS.
fn assert_multigroup_conformance_owned_by(label: &str, fixture: &[MultiAce], owner: Principal) {
    // SAFETY: all calls operate on locally owned buffers / handles.
    let (sid_str, mut user_bytes) = unsafe { current_user_sid() };
    let win = unsafe { windows_accesscheck_mask(fixture, &sid_str, &mut user_bytes, owner) };
    let stars = stars_multigroup_mask(fixture, &sid_str, owner);
    assert_eq!(
        win, stars,
        "{label}: Windows AccessCheck (0x{win:08X}) != Stars engine (0x{stars:08X})"
    );
}

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
        sid_history_count: 0,
        sid_history: Vec::new(),
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
            resolution: ResolutionProvenance::default(),
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

// ---------------------------------------------------------------------------
// Multi-group, token-based conformance against Windows AccessCheck.
//
// The fixtures above use a single trustee and GetEffectiveRightsFromAclW.
// These exercise the harder, more realistic case the engine must get
// right: a token that holds *several* principals, where access is granted
// or denied across different group SIDs. The ground truth is the real OS
// authorization call AccessCheck against the current process token; the
// engine is fed the same owner and the same principals (the user plus the
// implicit Everyone / Authenticated Users it adds to every token).
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires a Windows session; run with --ignored"]
fn conformance_multigroup_two_groups_accumulate() {
    // Read granted via Everyone, Write granted via Authenticated Users —
    // the effective mask must be their union.
    assert_multigroup_conformance(
        "Allow Everyone Read + Allow AuthUsers Write",
        &[
            MultiAce {
                kind: AceKind::Allow,
                mask: MASK_READ,
                principal: Principal::Everyone,
            },
            MultiAce {
                kind: AceKind::Allow,
                mask: MASK_WRITE,
                principal: Principal::AuthenticatedUsers,
            },
        ],
    );
}

#[test]
#[ignore = "requires a Windows session; run with --ignored"]
fn conformance_multigroup_deny_one_group_over_allow_another() {
    // The critical multi-group interaction: a Deny on one group (first, in
    // canonical order) must beat an Allow on another group.
    assert_multigroup_conformance(
        "Deny AuthUsers Write + Allow Everyone Full",
        &[
            MultiAce {
                kind: AceKind::Deny,
                mask: MASK_WRITE,
                principal: Principal::AuthenticatedUsers,
            },
            MultiAce {
                kind: AceKind::Allow,
                mask: MASK_FULL_CONTROL,
                principal: Principal::Everyone,
            },
        ],
    );
}

// ---------------------------------------------------------------------------
// Owner semantics and mask expansion.
//
// These close the gap the 2026-07-25 review identified: the owner special
// rule, the OWNER RIGHTS (S-1-3-4) suppression and generic-rights expansion
// were covered by unit tests only — the conformance net stopped at the
// stored-order algorithm. Windows is the ground truth for all three.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires a Windows session; run with --ignored"]
fn conformance_owner_implicit_read_control_and_write_dac() {
    // The object is owned by the user, and the DACL grants only Read. The
    // owner nevertheless holds READ_CONTROL + WRITE_DAC implicitly, so the
    // effective mask must exceed the DACL. Pins the implicit owner grant
    // against the OS instead of against our own assumption.
    assert_multigroup_conformance_owned_by(
        "owner (user) with Allow user Read",
        &[MultiAce {
            kind: AceKind::Allow,
            mask: MASK_READ,
            principal: Principal::User,
        }],
        Principal::User,
    );
}

#[test]
#[ignore = "requires a Windows session; run with --ignored"]
fn conformance_owner_rights_ace_replaces_implicit_grant() {
    // OWNER RIGHTS (S-1-3-4) present: per Windows Server 2008+ semantics the
    // ACE governs the owner's rights and the implicit READ_CONTROL +
    // WRITE_DAC bonus is suppressed. Stars implements exactly that — this
    // asks the OS whether the implementation matches.
    assert_multigroup_conformance_owned_by(
        "owner (user) with an OWNER RIGHTS Allow Read ACE",
        &[MultiAce {
            kind: AceKind::Allow,
            mask: MASK_READ,
            principal: Principal::OwnerRights,
        }],
        Principal::User,
    );
}

// NOTE — why there is no generic-rights conformance fixture (2026-07-25):
// an ACE carrying a raw `GENERIC_*` bit was measured against `AccessCheck`
// and the two deliberately disagree: Windows returned the generic bit
// **unmapped** (`0x8000_0000` still set) while Stars expands it into the
// specific `FILE_GENERIC_READ` bits. That is not an engine defect —
// `AccessCheck` maps generic bits only in the *DesiredAccess* argument, not
// inside ACE masks (mapping ACE masks is the job of whoever creates the
// ACL, and `SetNamedSecurityInfo` does it). A fixture built with
// `AddAccessAllowedAce` therefore constructs a descriptor Windows itself
// would never store on disk, so the comparison measures the fixture, not
// the engine. `expand_generic_rights` stays defensive for the rare
// hand-crafted ACL and is covered by unit tests in `mask.rs`.

#[test]
#[ignore = "requires a Windows session; run with --ignored"]
fn conformance_owner_is_a_group_in_the_token() {
    // The decisive experiment for the open review question: the object is
    // owned by a *group* that is in the token (Everyone), not by the user's
    // own SID. Stars treats "owner SID is anywhere in the token" as
    // ownership and adds the implicit grant; Windows only honours a group
    // owner when the group carries SE_GROUP_OWNER in the token. If the two
    // disagree, Stars over-reports READ_CONTROL | WRITE_DAC here.
    assert_multigroup_conformance_owned_by(
        "owner is Everyone (a token group), DACL grants user Read",
        &[MultiAce {
            kind: AceKind::Allow,
            mask: MASK_READ,
            principal: Principal::User,
        }],
        Principal::Everyone,
    );
}

#[test]
#[ignore = "requires a Windows session; run with --ignored"]
fn conformance_multigroup_user_ace_and_group_ace() {
    // A direct user ACE plus a group ACE accumulate.
    assert_multigroup_conformance(
        "Allow user Read + Allow Everyone Modify",
        &[
            MultiAce {
                kind: AceKind::Allow,
                mask: MASK_READ,
                principal: Principal::User,
            },
            MultiAce {
                kind: AceKind::Allow,
                mask: 0x0013_01BF, // MASK_MODIFY
                principal: Principal::Everyone,
            },
        ],
    );
}
