# ADR 0051 — Signed LDAP bind (SASL GSSAPI/Kerberos) for hardened DCs

**Status:** Accepted
**Date:** 2026-06-13

## Context

A live hard-test against a three-domain Windows Server 2025 lab (review
2026-06-13, finding F1) showed that Stars could not establish *any* LDAP
connection to a default-hardened domain controller:

- Plain LDAP on port 389 (`--insecure-ldap`) is rejected with
  `strongerAuthRequired` — Windows Server 2022/2025 enforce LDAP signing by
  default and refuse an unsigned simple bind.
- LDAPS on port 636 requires a server certificate the client trusts. The
  lab DCs had no LDAPS certificate, so the TLS handshake was reset
  (`os error 10054`); even when a certificate exists it must be issued by a
  CA the Stars host trusts and match the FQDN.

Stars only ever did a `simple_bind` (clear or over LDAPS). It did **not**
support the third path that every native Windows tool (`ldp.exe`,
`Get-ADUser`, RSAT) uses by default: an LDAP bind with a **SASL sign+seal
security layer** negotiated via Kerberos. That layer satisfies the DC's
signing requirement over a clear port-389 connection **without any
certificate**.

Because Stars' headline capability — recursive nested group resolution via
`LDAP_MATCHING_RULE_IN_CHAIN` — is gated entirely behind an LDAP
connection, this gap meant that against a stock hardened DC Stars fell back
to the SAM/LSA path, which by design does not resolve deep global-group
nesting. The core value proposition could not run.

## Decision

Add a **signed-LDAP** mode that binds with SASL GSSAPI/Kerberos sign+seal
over a clear port-389 connection.

- **Dependency:** enable the `ldap3` `gssapi` feature. On Windows this uses
  the system SSPI (via `cross-krb5`); no external Kerberos SDK is needed
  and it links cleanly on the standard MSVC toolchain.
- **Bind:** `ldap_client::connect` branches on a new
  `TlsMode::GssapiSign`. For that mode it calls
  `Ldap::sasl_gssapi_bind(server_fqdn)` instead of `simple_bind`. On a
  clear connection ldap3 installs the Kerberos **confidentiality
  (sign+seal)** security layer, which is exactly what the hardened DC
  requires. `server` must be the DC's **FQDN** — it forms the
  `ldap/<fqdn>` service principal name.
- **Credentials:** the GSSAPI bind uses the **current Windows logon**
  (SSPI single sign-on). No bind DN or password is supplied. Run Stars as
  the domain account whose context you want to audit. `LdapConfig::new_signed`
  therefore takes only `(server, base_dn)`.
- **Surface:**
  - CLI: `--ldap-signing` on `analyze` and `scan`. Mutually exclusive with
    `--insecure-ldap`; ignores `--global-catalog` (it is a domain-DC bind
    on 389). No `--bind-dn` / `ADPA_BIND_PASSWORD` required.
  - GUI: a fifth LDAP mode "Signed LDAP — Kerberos sign & seal, port 389"
    on the Analyze and Scan Tree tabs. `LdapParams` gains a `signing`
    field; the mode→params (`from_mode`) and params→`LdapConfig`
    (`to_config`) mappings stay unit-tested, and an empty bind DN is
    accepted in this mode.

## Consequences

- Stars can now query a default-hardened Windows Server 2022/2025 DC
  **without a certificate and without weakening the server**, unlocking
  recursive nested-group resolution there.
- **Kerberos requires a real logon (TGT).** A process running in a network
  logon without delegation (e.g. a bare WinRM remoting session) has no TGT
  and the GSSAPI bind fails — the classic "double hop". Signed LDAP works
  from an interactive, console, or batch (service / scheduled-task) logon.
  This is inherent to Kerberos, not a Stars limitation.
- The signed bind does not take an explicit username/password; it always
  uses the caller's identity. Binding as a *different* account would need a
  separate credential-handling path and is deliberately out of scope here.

## Verification (live)

On the lab, run as `T0LAB\Administrator` via a batch logon (scheduled
task, so a Kerberos TGT exists), analyzing as `T0LAB\mm0002` with
`--ldap-signing -s tier0.tier0.lab -b DC=tier0,DC=lab`:

- No SAM/LSA-fallback diagnostic — the LDAP signed bind connected.
- The full five-level nested chain resolved recursively:
  `mm0002 → ST_T0_Inner → ST_T0_L2 → ST_T0_L3 → ST_T0_L4 → ST_T0_L5`,
  which the SAM/LSA path could not produce (direct groups only).

Unit tests cover the config (`new_signed` → port 389, `GssapiSign`, no
credentials, `ldap://` URL) and the GUI mode mapping (mode 4 → signing).
The end-to-end bind needs a real DC + TGT and is verified manually as
above (it cannot run in the certificate-less CI runner without a domain).
