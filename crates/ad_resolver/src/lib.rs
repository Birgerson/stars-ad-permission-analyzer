// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! ad_resolver — Active Directory access, SID resolution, and group resolution via LDAP.
//!
//! The re-exports below are the crate's **convenience surface**: they cover
//! what the frontends actually consume. Building blocks used only inside the
//! crate are deliberately *not* re-exported (ad_resolver review 2026-07-25,
//! AD-4) — every re-export is a maintenance promise. They remain reachable
//! through their module path (e.g. `ad_resolver::sam::lookup_account_for_sid`)
//! if a caller ever needs them.

pub mod config;
#[cfg(windows)]
pub mod enumerate;
pub mod ldap_client;
#[cfg(windows)]
pub mod local_account;
#[cfg(windows)]
pub mod local_groups;
pub mod principal;
pub mod resolver;
#[cfg(windows)]
pub mod sam;
pub mod selective_auth;
pub mod sid_util;
pub mod trusted;
pub mod trusts;
#[cfg(windows)]
pub mod uac_policy;

pub use config::{LdapConfig, TlsMode};
#[cfg(windows)]
pub use enumerate::{enumerate_all, IdentitySnapshot};
#[cfg(windows)]
pub use local_groups::{
    local_group_memberships, read_local_group_table, resolve_local_group_sids_strict,
    LocalGroupChains, LocalGroupLookupOutcome, LocalGroupTable,
};
#[cfg(not(windows))]
pub use principal::NoLsaBackend;
#[cfg(windows)]
pub use principal::WindowsLsaBackend;
pub use principal::{
    DisabledStatus, EngineFlags, GroupResolutionStatus, IdentityBackend, IdentityScopeStatus,
    LdapIdentityBackend, LsaAccountInfo, LsaBackend, PrincipalInput, PrincipalResolution,
    PrincipalResolver, TrustContext, TrustedDomainBackend,
};
pub use resolver::LdapResolver;
#[cfg(windows)]
pub use sam::{
    build_sid_name_map, build_sid_name_map_for_target, identity_display, lookup_sid_for_account,
    resolve_identity_via_sam, SamResolution, SidNameResolver,
};
pub use trusted::LdapTrustedDomainBackend;
pub use trusts::resolve_domain_trusts;
#[cfg(windows)]
pub use uac_policy::{read_everyone_includes_anonymous, read_target_uac_policy, TargetUacPolicy};
