# ADR 0031 — Central UNC decomposition and explicit SMB target server

**Status:** Accepted
**Date:** 2026-06-04

## Context

ChatGPT code review 2026-06-04, findings 1, 2, and 4 all hit the same place
in the CLI/GUI orchestration:

- **Finding 1 (High):** the CLI function `unc_components` in
  `crates/cli/src/main.rs` did not check the double-slash prefix. For
  `C:\Windows\SYSVOL` — a core path on every domain controller — it
  returned `Some(("C:", "Windows"))`. Consequence: local groups were
  resolved against a server named `C:` and `NetShareGetInfo("C:", "Windows")`
  started a share-DACL lookup even though the caller had not requested an
  SMB context. The GUI had had the fix for a while (see
  `crates/gui/src/worker.rs` with prefix check and regression test); the
  CLI did not.

- **Finding 4 (Medium):** both variants worked on the unnormalized path
  string. `\\?\UNC\server\share\folder` was decomposed after
  `trim_start_matches` as `Server=?`, `Share=UNC`. Long-path UNC is
  relevant in production on large file servers with long paths.

- **Finding 2 (High):** `collect_local_group_sids_for_path` did not accept
  the explicitly set `--smb-server` at all. Local groups came from the path
  server, but the share DACL from the override server — a token mismatch
  especially with ACEs on `SERVER\Administrators`, `BUILTIN\Users`, or
  file-server-local application groups.

## Decision

1. **One source of truth** for UNC decomposition in the `validation`
   crate:

   - `validation::path::parse_unc_components(path) -> Option<(String, String)>`
     normalizes the long-path prefix beforehand (`\\?\UNC\…` → `\\…`),
     explicitly excludes the local long-path form (`\\?\C:\…`), and checks
     the double slash/backslash prefix before the split.
   - `validation::path::effective_smb_target(path, explicit_smb_server) -> Option<String>`
     prioritizes the explicitly set server over the UNC server derived from
     the path.

2. **CLI and GUI both use the same helper.** The two old local
   `unc_components` implementations are gone without replacement —
   `crates/cli/src/main.rs` and `crates/gui/src/worker.rs` import
   exclusively from `validation::path`.

3. **`collect_local_group_sids_for_path`** now additionally takes
   `explicit_smb_server: Option<&str>` in CLI and GUI and calls
   `effective_smb_target` for the server choice.

4. **`resolve_scan_share_status` (CLI)** and **`resolve_share_status`
   (GUI)** derive server and share via the central helpers. The call
   contract stays: local path without override → `NotApplicable`.

## Rationale

- **One place, one truth.** The GUI already had the local-path guard — the
  CLI did not. That was a real trust gap, which the reviewer rightly set to
  high severity.
- **Validation is the right layer.** Paths are validated there anyway; UNC
  decomposition reads the same inputs and belongs in the same module.
- **Forward compatibility with the long-path form.** The engine could
  already process `\\?\UNC\…`, only the orchestration helpers could not.
  The fix aligns both worlds.

## Consequences

- There are no external consumers of the `unc_components` function in CLI /
  GUI — the symbols were `fn`-private or module-private.
- Tests stay visible in `validation::path` (the central place) plus a GUI
  smoke test that blocks the sentinel constellation from finding 1
  (`C:\Windows\SYSVOL` without override → `NotApplicable`).

## Tests

Nine regression tests in `validation::path::tests`:

- `parse_unc_components_rejects_local_paths` — `C:\Windows\SYSVOL`,
  `C:\Windows`, `D:\Data\Department`, `\singlebackslash\foo`, `""`.
- `parse_unc_components_accepts_classic_unc` — `\\server\share\sub`,
  `//server/share`.
- `parse_unc_components_handles_long_path_unc` — hostname and IP address as
  long-path UNC.
- `parse_unc_components_rejects_local_long_path` — `\\?\C:\…`, `\\?\D:\…`.
- `parse_unc_components_rejects_incomplete_unc` — `\\server`, `\\server\`.
- `effective_smb_target_prefers_explicit_server_for_local_path` — local
  path + override → override server.
- `effective_smb_target_prefers_explicit_server_for_unc` — UNC + override →
  override server.
- `effective_smb_target_falls_back_to_unc_server` — no override → UNC.
- `effective_smb_target_returns_none_for_local_path_without_override`.

Plus GUI: `share_status_does_not_treat_local_path_as_unc`.

## Closes

ChatGPT code review 2026-06-04, findings 1 (High), 2 (High), and 4 (Medium).
