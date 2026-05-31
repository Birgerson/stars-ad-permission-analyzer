//! ad_resolver — Active-Directory-Zugriff, SID-Auflösung und Gruppenauflösung via LDAP.
//! ad_resolver — Active Directory access, SID resolution, and group resolution via LDAP.

pub mod config;
#[cfg(windows)]
pub mod enumerate;
pub mod ldap_client;
#[cfg(windows)]
pub mod local_groups;
pub mod resolver;
#[cfg(windows)]
pub mod sam;
pub mod sid_util;

pub use config::{LdapConfig, TlsMode};
#[cfg(windows)]
pub use enumerate::{enumerate_all, IdentitySnapshot};
#[cfg(windows)]
pub use local_groups::{format_account_for_local_groups, resolve_local_group_sids};
pub use resolver::LdapResolver;
#[cfg(windows)]
pub use sam::{
    build_sid_name_map, lookup_account_for_sid, lookup_sid_for_account, resolve_identity_via_sam,
    user_global_group_names, AccountInfo,
};
