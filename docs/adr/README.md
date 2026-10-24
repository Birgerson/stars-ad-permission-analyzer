# Architecture Decision Records

This directory contains every architecture decision Stars has made, in chronological order. ADRs are append-only — when a later decision supersedes an earlier one, both stay in the record so the rationale chain remains visible.

## Language

All ADRs are written in US English, matching the repository-wide language convention. The records were migrated in stages: ADRs 0045–0048 (Round 10) on 2026-06-07, ADRs 0001–0015 on 2026-06-08, and the remaining ADRs 0016–0044 on 2026-06-15. Bilingual section headers were collapsed to the English form throughout, and any bilingual prose was reduced to its English version — the decisions themselves are unchanged. The `language` job in `.github/workflows/ci.yml` now enforces US English across all ADRs, so new and existing records stay consistent.

## References to `AGENTS.md`

Several ADRs, and comments in the code, cite `AGENTS.md` — for example
"AGENTS.md base rule 1" or "DoD point 11". That is the project's internal
development rulebook for the AI tools that implement Stars; it is
deliberately not published, and the records keep their wording. Every
principle they cite is stated in the public documents:

| Cited principle | Public statement |
| --- | --- |
| Read-only: Stars never changes a target system | [features-and-limitations.md — what Stars does not do](../features-and-limitations.md#what-stars-does-not-do-by-design), [SECURITY.md](../../SECURITY.md) |
| Priorities: security, correctness, traceability, testability, stability, performance, usability, aesthetics | [audit-criteria.md §1](../audit-criteria.md#1-core-principles) |
| Validate every input before it is processed | [technical-documentation.md §13](../technical-documentation.md#13-validation-at-system-boundaries) |
| Large environments are the default case; no silent omission | [features-and-limitations.md](../features-and-limitations.md), [SECURITY.md](../../SECURITY.md) |
| Updates: signed, checksummed, channel-aware, rollback-capable, offline source | [known-limitations.md L12](../known-limitations.md#l12--application-updates-are-manual-update_manager-is-a-deliberate-extension-point) |
| No credentials in the repository or in logs | [SECURITY.md — secrets in the repository](../../SECURITY.md#secrets-in-the-repository) |

## Index

| ADR | Title |
|---|---|
| 0001 | Core engine before GUI |
| 0002 | `adpa_core` as the crate name |
| 0003 | NTFS DACL reading |
| 0004 | ACE normalization |
| 0005 | CLI prototype |
| 0006 | CSV export |
| 0007 | SQLite cache |
| 0008 | Multi-folder scan |
| 0009 | SMB share scanner |
| 0010 | NTFS / share permission combination |
| 0011 | GUI `egui` prototype (later replaced by Slint) |
| 0012 | Access-check semantics |
| 0013 | `AccessContext` enum |
| 0014 | LDAP paging and transitive groups |
| 0015 | Long-path normalization |
| 0016 | GUI scan error persistence |
| 0017 | Share scan preserves NULL DACL |
| 0018 | CSV export audit completeness |
| 0019 | Share token uses `AccessContext` |
| 0020 | `matched_aces` excludes INHERIT_ONLY |
| 0021 | Permission diagnostics vector |
| 0022 | Scan-depth validation at the CLI/GUI boundary |
| 0023 | Share DACL stored-order evaluation |
| 0024 | Unsupported share ACEs as structured diagnostic |
| 0025 | NULL DACL classification fix |
| 0026 | Share-scan result carries the share DACL scan |
| 0027 | `SensitivePathRule` requires effective access |
| 0028 | Update-manager skeleton |
| 0029 | Membership-path reconstruction |
| 0030 | Update-manager path validation and policy split |
| 0031 | Shared UNC components and `effective_smb_target` |
| 0032 | Identity input dispatcher and LDAP timeouts |
| 0033 | Visible diagnostics for SAM fallback and disabled identities |
| 0034 | Multi-domain LSA fallback for identity resolution |
| 0035 | SAM disabled status via `NetUserGetInfo` |
| 0036 | Unified principal resolution pipeline |
| 0037 | Validated wrappers propagated |
| 0038 | Share trustees in the scan output |
| 0039 | Failed-resolution diagnostics |
| 0040 | Local-group candidate name list (superseded by 0068) |
| 0041 | Local-group memberships in the explanation path |
| 0042 | Deny aggregation step in the explanation path |
| 0043 | Effective access context with SMB hints |
| 0044 | Shared `path_trustees` module |
| 0045 | RAII guard for Windows resources (`win_safe`) |
| 0046 | `PathTrusteeEntry` enum |
| 0047 | `SmbAuditContext` typed wrapper |
| 0048 | SID→name map caller owned |
| 0049 | Streaming tree-walk callback |
| 0050 | Streaming CLI scan with lazy SID→name cache |
| 0051 | Signed LDAP bind (GSSAPI/Kerberos sign+seal) |
| 0052 | SID history (L3) & cross-forest trust (L4) visibility markers |
| 0053 | Standalone group-membership view (identity → groups) |
| 0054 | GUI LDAP timeout control (GUI/CLI parity) |
| 0055 | Group → Members (reverse / downward view), v1 direct members |
| 0056 | Evaluate the user's `sIDHistory` SIDs into the access token |
| 0057 | SemVer pre-release precedence in the update version policy |
| 0058 | Reparse handling: real cycles vs duplicate targets |
| 0059 | Evaluate the groups' `sIDHistory` SIDs into the access token |
| 0060 | Read-only trust-topology inventory (`trustAttributes` / `trustDirection`) |
| 0061 | Manual, read-only update check with a configurable, validated source |
| 0062 | Directory identity by volume serial + file ID for scans over SMB |
| 0063 | Deterministic membership routes and disclosure of further routes |
| 0064 | Orphaned only with evidence; unresolvable SIDs are incomplete |
| 0065 | Results that cannot be determined are never stated as facts |
| 0066 | No silent drops in group resolution |
| 0067 | Only security groups count; cross-check against tokenGroups |
| 0068 | Local groups of the target server expanded by SID |
| 0069 | `LOCAL` is logon-dependent for a local access |
| 0070 | Local accounts of the target server |
| 0071 | User Account Control for every account on a local access |
| 0072 | Guest and anonymous tokens |
| 0073 | Risk rules judge the upper bound |
| 0074 | Explanation path v2: every right traceable |
| 0075 | A share without security descriptor is not determinable |
| 0076 | Remote UAC decided from the target's policies |
| 0077 | Permission graph: the explanation path as a lane diagram |
| 0078 | Accounts of a trusted domain, resolved on its domain controller |
| 0079 | Selective Authentication and the organization SIDs of trusted-domain accounts |
| 0080 | SYNCHRONIZE missing from the effective right |
| 0081 | Permission graph v2: two bands, layer results, routes on click |
| 0082 | Modular GUI: design tokens, components, one module per tab |
