# ADR 0037 — Propagate validated wrappers consistently

**Status:** Accepted
**Date:** 2026-06-04

## Context

Review 2026-06-04 round 3 finding 2 (Medium) showed that the validation
layer worked formally correctly (`validate_sid`, `validate_ldap_endpoint`,
`validate_dn`, `validate_smb_server`, `validate_share_name`,
`validate_identity_query` return typed wrappers with trimmed values), but
the callers **kept processing the raw string** in several places:

- `validate_sid("  S-1-5-18  ")` returns `ValidatedSid("S-1-5-18")` — but
  CLI and GUI checked with `user.starts_with("S-1-")` on the raw string.
  Whitespace-surrounded SIDs were thereby not classified as a SID and ended
  up in the name search.
- `validate_connection_inputs(...)` returned only `Result<(), Err>` — the
  trimmed values from `validate_ldap_endpoint`, `validate_dn`, etc. were
  discarded, and the original `Option<String>` raw value went unchanged to
  `LdapConfig::new(...)` and `get_share_dacl(...)`.

Consequence: in production, two audit runs with identical visible inputs
(one with, one without whitespace) could lead to different results — an
audit-reproducibility defect that materially violated the architecture rule
**"validation before processing"**.

## Decision

`validate_connection_inputs` now returns a **normalized struct** in CLI and
GUI whose fields contain the trimmed values:

```rust
// CLI
struct NormalizedConnectionInputs {
    server:     Option<String>,
    base_dn:    Option<String>,
    bind_dn:    Option<String>,
    smb_server: Option<String>,
    share_name: Option<String>,
}

// GUI (additionally the whole LdapParams clone with trimmed fields)
pub struct NormalizedConnectionInputs {
    smb_server: Option<String>,
    share_name: Option<String>,
    ldap:       Option<LdapParams>,  // trimmed
}
```

The consumers (CLI `run_analyze`/`run_scan`, GUI
`handle_analyze`/`handle_scan_path`) use **exclusively** the normalized
values from validation onward. The original `Option<String>` fields are
reassigned or shadowed after the validation call.

For the user input this now applies consistently too:

```rust
let user = if user.starts_with("S-1-") {
    validate_sid(&user)?.0      // trimmed SID
} else {
    validate_identity_query(&user)?.0  // trimmed name
};
```

`PrincipalInput::Auto(...)` additionally trims in the classification
(`classify()`) — defense in depth.

## Consequences

**Positive:**

- Reproducible audit results between CLI and GUI for whitespace-padded
  inputs.
- The architecture rule "validation before processing" is now satisfied not
  only nominally but materially — the trimmed values actually flow on to
  LDAP/NetAPI/SID processing.
- A clearly recognizable entry point for future validation extensions
  (e.g. additional hostname normalization).

**Negative:**

- Slightly more code at the call sites (5 additional `let` assignments per
  validation block). Accepted.

## Closes

Review 2026-06-04 round 3, finding 2 (validated identity and connection
values as raw strings).

## References

- ADR 0036 — unified principal-resolution pipeline (also uses trimmed
  inputs).
- AGENTS.md DoD rule 11: "validate all affected inputs"; DoD rule 12:
  "validation errors tested".
