# ADR 0005 — CLI prototype and formatted output

## Status
Accepted

## Context

Steps 8 and 9 of the development roadmap require a runnable CLI that ties together all previously built components (fs_scanner, ad_resolver, permission_engine) and produces a human-readable report. The goal at this stage is correctness and technical validation, not end-user polish.

## Decision

### CLI binary (`crates/cli`)

The CLI uses **clap** with a single `analyze` subcommand. Required arguments:

| Argument | Description |
|---|---|
| `--path` | Local or UNC path to analyze |
| `--user` | SID (`S-1-5-…`) or sAMAccountName (`DOMAIN\User` or `user`) |
| `--server` | AD/LDAP server hostname or IP (optional) |
| `--base-dn` | LDAP base DN, required when `--server` is given |
| `--bind-dn` | LDAP bind account DN, required when `--server` is given |
| `--bind-password` | Bind password; can also be passed via `ADPA_BIND_PASSWORD` env var |

Offline mode (no `--server`): only SID format is accepted; group memberships are not resolved and the report carries a warning.

### Resolution logic

1. If the user string starts with `S-1-`: treat as SID, call `resolve_identity` via `IdentityResolver` trait.
2. Otherwise: call `lookup_by_samaccount` on `LdapResolver`, which strips a `DOMAIN\` prefix before querying LDAP by `sAMAccountName`.

### Output format

A single `print_report` function in `output.rs` renders a fixed-width (65-char) box-drawing report with these sections:

1. **Identity** — path, resolved name, SID, status/kind, optional offline warning.
2. **Resolved Groups** — direct vs. transitive, shown only when non-empty.
3. **DACL** — owner, inheritance state, all ACE entries with Kind/Scope/Rights/SID columns.
4. **Matching ACEs** — ACEs that apply to the queried identity (user SID + all group SIDs).
5. **Effective Rights** — NTFS mask, share mask (if provided), combined effective mask.
6. **Explanation Path** — human-readable steps from `PermissionPath`.

The output deliberately avoids color or ANSI codes so it remains usable in log files and piped output without special handling.

## Alternatives considered

- **JSON output flag**: deferred to step 10 (exporter crate); the current formatted output is sufficient for technical validation.
- **Interactive shell**: not in scope; the tool is single-shot by design.
- **Color output (termcolor/crossterm)**: deferred until the output format is stable.

## Consequences

- The full analysis pipeline (`DACL read → identity resolve → group resolve → effective rights → explanation`) can now be executed end-to-end from the command line.
- Integration tests against a real AD domain can be scripted using the CLI binary.
- The output format serves as the specification for the future HTML report (step 17).
