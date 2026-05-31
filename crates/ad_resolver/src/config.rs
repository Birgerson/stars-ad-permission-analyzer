//! LDAP-Verbindungskonfiguration.
//! LDAP connection configuration.

/// TLS-Modus für die LDAP-Verbindung.
/// TLS mode for the LDAP connection.
///
/// StartTLS ist derzeit nicht implementiert (abhängig von ldap3-Feature-Flags).
/// StartTLS is not yet implemented (requires ldap3 feature flags).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TlsMode {
    /// LDAPS (ldaps://server:636) — verschlüsselt ab dem ersten Byte, empfohlen.
    /// LDAPS (ldaps://server:636) — encrypted from the first byte, recommended.
    #[default]
    Ldaps,

    /// Kein TLS (ldap://server:389) — Bind-Passwort wird im Klartext übertragen.
    /// No TLS (ldap://server:389) — bind password is transmitted in plaintext.
    /// Nur mit explizitem --insecure-ldap / GUI-Warnung verwenden.
    /// Only use with explicit --insecure-ldap / GUI warning.
    Insecure,
}

/// Verbindungsparameter für einen LDAP/Active-Directory-Server.
/// Connection parameters for an LDAP/Active Directory server.
///
/// `Debug` ist hand-implementiert und maskiert das Bind-Passwort, damit ein
/// versehentliches `{config:?}` keine Secrets in Logs schreibt.
/// `Debug` is hand-implemented and masks the bind password so an accidental
/// `{config:?}` does not leak secrets into logs.
#[derive(Clone)]
pub struct LdapConfig {
    /// LDAP-Server-Adresse (IP oder Hostname).
    /// LDAP server address (IP or hostname).
    pub server: String,

    /// LDAP-Port (Standard: 636 für LDAPS, 389 für unverschlüsseltes LDAP).
    /// LDAP port (default: 636 for LDAPS, 389 for unencrypted LDAP).
    pub port: u16,

    /// Base DN für alle Suchen, z.B. "DC=testdomain,DC=local".
    /// Base DN for all searches, e.g. "DC=testdomain,DC=local".
    pub base_dn: String,

    /// Bind-DN für die Authentifizierung, z.B. "CN=Administrator,CN=Users,DC=testdomain,DC=local".
    /// Bind DN for authentication, e.g. "CN=Administrator,CN=Users,DC=testdomain,DC=local".
    pub bind_dn: String,

    /// Bind-Passwort. Wird nicht geloggt.
    /// Bind password. Never logged.
    pub bind_password: String,

    /// Timeout für LDAP-Operationen in Sekunden.
    /// Timeout for LDAP operations in seconds.
    pub timeout_secs: u64,

    /// TLS-Modus. Standard: Ldaps (verschlüsselt).
    /// TLS mode. Default: Ldaps (encrypted).
    pub tls_mode: TlsMode,
}

impl LdapConfig {
    /// Erstellt eine Konfiguration mit LDAPS (sicherer Standard, Port 636).
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

    /// Erstellt eine Konfiguration für unverschlüsseltes LDAP (Port 389).
    /// Creates a configuration for unencrypted LDAP (port 389).
    ///
    /// Nur für Test- und Entwicklungsumgebungen ohne LDAPS-Unterstützung.
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

    /// Gibt die LDAP-URL zurück.
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
        // Passwort wird ausschließlich als Platzhalter („***" bzw. „<empty>") ausgegeben.
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
