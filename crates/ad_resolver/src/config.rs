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
}

/// Connection parameters for an LDAP/Active Directory server.
///
/// `Debug` is hand-implemented and masks the bind password so an accidental
/// `{config:?}` does not leak secrets into logs.
#[derive(Clone)]
pub struct LdapConfig {
    /// LDAP server address (IP or hostname).
    pub server: String,

    /// LDAP port (default: 636 for LDAPS, 389 for unencrypted LDAP).
    pub port: u16,

    /// Base DN for all searches, e.g. "DC=testdomain,DC=local".
    pub base_dn: String,

    /// Bind DN for authentication, e.g. "CN=Administrator,CN=Users,DC=testdomain,DC=local".
    pub bind_dn: String,

    /// Bind password. Never logged.
    pub bind_password: String,

    /// Timeout for LDAP operations in seconds.
    pub timeout_secs: u64,

    /// TLS mode. Default: Ldaps (encrypted).
    pub tls_mode: TlsMode,
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
        }
    }

    /// Returns the LDAP URL.
    pub fn url(&self) -> String {
        match self.tls_mode {
            TlsMode::Ldaps => format!("ldaps://{}:{}", self.server, self.port),
            TlsMode::Insecure => format!("ldap://{}:{}", self.server, self.port),
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
    fn debug_marks_empty_password_distinctly() {
        let cfg = LdapConfig::new("dc.test.local", "DC=test,DC=local", "CN=Admin", "");
        let dbg = format!("{cfg:?}");
        assert!(
            dbg.contains("<empty>"),
            "expected <empty> marker; got: {dbg}"
        );
    }
}
