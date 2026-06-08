# Architecture Decision Records

This directory contains every architecture decision Stars has made, in chronological order. ADRs are append-only — when a later decision supersedes an earlier one, both stay in the record so the rationale chain remains visible.

## Language

All ADRs from 2026-06-07 onwards are written in US English to match the repository-wide language convention. ADRs 0045–0048 (Round 10) were retroactively retranslated into US English on the same date.

ADRs 0001–0015 were retranslated to US English on 2026-06-08.

ADRs 0016–0044 still carry German prose in their bodies. The technical content in those files (code samples, file paths, struct names, test names) is already English; only the explanatory text is German. The decisions themselves are unchanged. The bilingual section headers (`## Kontext / Context` etc.) were collapsed to the English form across all 0001–0044 in the same commit, so headings are uniform throughout the index. Migrating the remaining German prose is not blocking — the CI language check explicitly excludes 0001–0044 — and is intended to be picked up opportunistically when a future change touches one of these files. New ADRs from 0049 onwards must be English, enforced by the `language` job in `.github/workflows/ci.yml`.

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
| 0040 | Local-group candidate name list |
| 0041 | Local-group memberships in the explanation path |
| 0042 | Deny aggregation step in the explanation path |
| 0043 | Effective access context with SMB hints |
| 0044 | Shared `path_trustees` module |
| 0045 | RAII guard for Windows resources (`win_safe`) |
| 0046 | `PathTrusteeEntry` enum |
| 0047 | `SmbAuditContext` typed wrapper |
| 0048 | SID→name map caller owned |
