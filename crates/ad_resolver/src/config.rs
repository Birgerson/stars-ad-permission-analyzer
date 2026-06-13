// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Birger Labinsch

//! LDAP-Verbindungskonfiguration.
//! LDAP connection configuration.

/// TLS mode for the LDAP connection.
///
/// StartTLS is not yet implemented (requires ldap3 feature flags).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TlsMode {
    /// LDAPS (ldaps://server:636) — encrypted from the first byte, recommended.
    #[default]
    Ldaps,

    /// No TLS (ldap://server:389) — bind password is transmitted in plaintext.
    /// Only use with explicit --insecure-ldap / GUI warning.
    Insecure,

    /// Clear TCP transport (ldap://server:389) on which a SASL
    /// GSSAPI/Kerberos **sign+seal** security layer is installed at bind
    /// time. This is *not* plaintext: after the bind the traffic is
    /// integrity-protected and encrypted by Kerberos, which is exactly
    /// what a hardened Windows Server (LDAP signing enforced) requires —
    /// **without needing an LDAPS certificate**. On Windows the bind uses
    /// the system SSPI with the current logon's Kerberos credentials
    /// (single sign-on); no bind DN or password is used. See ADR 0051.
    GssapiSign,
}

/// Connection parameters for an LDAP/Active Directory server.
///
/// `Debug` is hand-implemented and masks the bind password so an accidental
/// `{config:?}` does not leak secrets into logs.
#[derive(Clone)]
pub struct LdapConfig {
    /// LDAP server address (IP or hostname).
    pub server: String,

    /// LDAP port (default: 636 for LDAPS, 389 for unencrypted LDAP,
    /// 3269/3268 for the Global Catalog).
    pub port: u16,

    /// Base DN for all searches, e.g. "DC=testdomain,DC=local".
    /// May be empty in Global Catalog mode — the GC indexes the whole
    /// forest and an empty base searches all partitions.
    pub base_dn: String,

    /// Bind DN for authentication, e.g. "CN=Administrator,CN=Users,DC=testdomain,DC=local".
    pub bind_dn: String,

    /// Bind password. Never logged.
    pub bind_password: String,

    /// Timeout for LDAP operations in seconds.
    pub timeout_secs: u64,

    /// TLS mode. Default: Ldaps (encrypted).
    pub tls_mode: TlsMode,

    /// `true` when the connection targets the Global Catalog
    /// (port 3269 LDAPS / 3268 plain). The GC indexes the entire
    /// forest, so identity lookups (SID, UPN) are forest-wide — but
    /// only **universal** group memberships are replicated completely;
    /// global and domain-local memberships of foreign domains can be
    /// missing. Consumers must treat GC-resolved memberships as
    /// potentially incomplete (known-limitations L2).
    pub global_catalog: bool,
}

impl LdapConfig {
    /// Creates a configuration with LDAPS (secure default, port 636).
    pub fn new(
        server: impl Into<String>,
        base_dn: impl Into<String>,
        bind_dn: impl Into<String>,
        bind_password: impl Into<String>,
    ) -> Self {
        Self {
            server: server.into(),
            port: 636,
            base_dn: base_dn.into(),
            bind_dn: bind_dn.into(),
            bind_password: bind_password.into(),
            timeout_secs: 10,
            tls_mode: TlsMode::Ldaps,
            global_catalog: false,
        }
    }

    /// Creates a configuration for unencrypted LDAP (port 389).
    ///
    /// Only for test and development environments without LDAPS support.
    pub fn new_insecure(
        server: impl Into<String>,
        base_dn: impl Into<String>,
        bind_dn: impl Into<String>,
        bind_password: impl Into<String>,
    ) -> Self {
        Self {
            server: server.into(),
            port: 389,
            base_dn: base_dn.into(),
            bind_dn: bind_dn.into(),
            bind_password: bind_password.into(),
            timeout_secs: 10,
            tls_mode: TlsMode::Insecure,
            global_catalog: false,
        }
    }

    /// Creates a Global Catalog configuration over LDAPS (port 3269).
    ///
    /// `base_dn` may be empty — the GC indexes the whole forest and an
    /// empty base searches all partitions. Identity lookups (SID, UPN)
    /// become forest-wide; group memberships resolved through the GC are
    /// potentially incomplete (only universal groups replicate fully) —
    /// Stars marks them accordingly (known-limitations L2).
    pub fn new_global_catalog(
        server: impl Into<String>,
        base_dn: impl Into<String>,
        bind_dn: impl Into<String>,
        bind_password: impl Into<String>,
    ) -> Self {
        Self {
            server: server.into(),
            port: 3269,
            base_dn: base_dn.into(),
            bind_dn: bind_dn.into(),
            bind_password: bind_password.into(),
            timeout_secs: 10,
            tls_mode: TlsMode::Ldaps,
            global_catalog: true,
        }
    }

    /// Creates an unencrypted Global Catalog configuration (port 3268).
    ///
    /// Only for test and development environments without LDAPS support.
    pub fn new_global_catalog_insecure(
        server: impl Into<String>,
        base_dn: impl Into<String>,
        bind_dn: impl Into<String>,
        bind_password: impl Into<String>,
    ) -> Self {
        Self {
            server: server.into(),
            port: 3268,
            base_dn: base_dn.into(),
            bind_dn: bind_dn.into(),
            bind_password: bind_password.into(),
            timeout_secs: 10,
            tls_mode: TlsMode::Insecure,
            global_catalog: true,
        }
    }

    /// Creates a signed-bind configuration: clear LDAP transport on port
    /// 389 with a SASL GSSAPI/Kerberos sign+seal layer installed at bind.
    ///
    /// This is the cert-free way to talk to a hardened DC that enforces
    /// LDAP signing (rejecting plain binds with `strongerAuthRequired`).
    /// On Windows the bind uses the current logon's Kerberos credentials
    /// via SSPI (single sign-on), so no bind DN / password is supplied —
    /// run Stars as the domain account whose context you want to use.
    /// See ADR 0051.
    pub fn new_signed(server: impl Into<String>, base_dn: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            port: 389,
            base_dn: base_dn.into(),
            bind_dn: String::new(),
            bind_password: String::new(),
            timeout_secs: 10,
            tls_mode: TlsMode::GssapiSign,
            global_catalog: false,
        }
    }

    /// Returns the LDAP URL.
    pub fn url(&self) -> String {
        match self.tls_mode {
            TlsMode::Ldaps => format!("ldaps://{}:{}", self.server, self.port),
            // GSSAPI sign+seal runs over a clear TCP transport; the security
            // layer is established by the SASL bind, not the URL scheme.
            TlsMode::Insecure | TlsMode::GssapiSign => {
                format!("ldap://{}:{}", self.server, self.port)
            }
        }
    }
}

impl std::fmt::Debug for LdapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Password is rendered as a placeholder only ("***" or "<empty>").
        let pw_placeholder: &str = if self.bind_password.is_empty() {
            "<empty>"
        } else {
            "***"
        };
        f.debug_struct("LdapConfig")
            .field("server", &self.server)
            .field("port", &self.port)
            .field("base_dn", &self.base_dn)
            .field("bind_dn", &self.bind_dn)
            .field("bind_password", &pw_placeholder)
            .field("timeout_secs", &self.timeout_secs)
            .field("tls_mode", &self.tls_mode)
            .field("global_catalog", &self.global_catalog)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_password() {
        let cfg = LdapConfig::new("dc.test.local", "DC=test,DC=local", "CN=Admin", "S3cret!");
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("S3cret!"),
            "Debug must not contain the plaintext password; got: {dbg}"
        );
        assert!(
            dbg.contains("***"),
            "Debug must show a masking placeholder; got: {dbg}"
        );
    }

    #[test]
    fn global_catalog_uses_port_3269_with_ldaps() {
        let cfg = LdapConfig::new_global_catalog("dc.test.local", "", "CN=Admin", "pw");
        assert_eq!(cfg.port, 3269);
        assert_eq!(cfg.tls_mode, TlsMode::Ldaps);
        assert!(cfg.global_catalog);
        assert_eq!(cfg.url(), "ldaps://dc.test.local:3269");
        assert!(cfg.base_dn.is_empty(), "empty base = all forest partitions");
    }

    #[test]
    fn global_catalog_insecure_uses_port_3268_plain() {
        let cfg = LdapConfig::new_global_catalog_insecure("dc.test.local", "", "CN=Admin", "pw");
        assert_eq!(cfg.port, 3268);
        assert_eq!(cfg.tls_mode, TlsMode::Insecure);
        assert!(cfg.global_catalog);
        assert_eq!(cfg.url(), "ldap://dc.test.local:3268");
    }

    #[test]
    fn signed_uses_port_389_clear_transport_and_no_credentials() {
        let cfg = LdapConfig::new_signed("dc.corp.local", "DC=corp,DC=local");
        assert_eq!(cfg.port, 389);
        assert_eq!(cfg.tls_mode, TlsMode::GssapiSign);
        assert!(!cfg.global_catalog);
        // GSSAPI uses the current Windows logon (SSO) — no bind creds.
        assert!(cfg.bind_dn.is_empty());
        assert!(cfg.bind_password.is_empty());
        // Clear TCP transport; the seal is established by the SASL bind.
        assert_eq!(cfg.url(), "ldap://dc.corp.local:389");
    }

    #[test]
    fn regular_configs_are_not_global_catalog() {
        assert!(!LdapConfig::new("s", "b", "d", "p").global_catalog);
        assert!(!LdapConfig::new_insecure("s", "b", "d", "p").global_catalog);
    }

    #[test]
    fn debug_marks_empty_password_distinctly() {
        let cfg = LdapConfig::new("dc.test.local", "DC=test,DC=local", "CN=Admin", "");
        let dbg = format!("{cfg:?}");
        assert!(
            dbg.contains("<empty>"),
            "expected <empty> marker; got: {dbg}"
        );
    }
}
