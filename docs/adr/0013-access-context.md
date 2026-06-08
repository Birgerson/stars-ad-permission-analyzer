# ADR 0013 — Access context in the token (`AccessContext`)

**Status:** Accepted
**Date:** 2026-05-24

## Context

The permission engine built the token SID set independently of the logon type. The only implicit additions were `Everyone` (S-1-1-0) and `Authenticated Users` (S-1-5-11). The real Windows `AccessCheck` adds further well-known SIDs depending on the logon:

- Remote SMB logon → `NETWORK` (S-1-5-2)
- local interactive logon → `INTERACTIVE` (S-1-5-4) and `LOCAL` (S-1-2-0)

Consequence of the previous behaviour:

- ACEs on `NETWORK` (typical for SMB audit setups: "Deny NETWORK <X>") were never evaluated during SMB analyses — the engine could look too generous and at the same time miss broad-group risks via `NETWORK`.
- Symmetric problem with `INTERACTIVE` for local analyses.

See review finding 4.

## Decision

1. **New enum `AccessContext`** in `adpa_core::model`:

   ```rust
   pub enum AccessContext {
       LocalInteractive,  // adds INTERACTIVE + LOCAL
       RemoteSmb,         // adds NETWORK
       #[default]
       Unspecified,       // adds nothing context-specific
   }
   ```

   `Unspecified` is the default and exactly reproduces the previous behaviour — existing callers that don't yet set a context get no surprise behaviour change.

2. **`PermissionEvaluationInput.access_context`** as a new mandatory field. The engine extends the token according to the context and passes the result through otherwise unchanged.

3. **Auto-detection at the caller:** `AccessContext::for_path(path)` derives the context from the path shape:

   - UNC (`\\server\…`, incl. long-path form `\\?\UNC\…`) → `RemoteSmb`
   - local path (`C:\…`, incl. `\\?\C:\…`) → `LocalInteractive`

   CLI and GUI call this helper once per analyse/scan invocation.

4. **Backwards-compatible public API:** `build_token_sids` and `build_token_sids_with_local` stay and delegate to `build_token_sids_with_context(_, _, _, AccessContext::Unspecified)`. New callers use the `_with_context` variant.

## Rationale

- **Correctness gain without risk for existing callers:** the `Unspecified` default leaves every old code path unchanged. Only callers that actively set the context (CLI, GUI) get the more correct behaviour.
- **No GUI/CLI-specific token logic:** the engine stays the only place where token SIDs are assembled — callers only supply the context. This prevents token extensions from being duplicated or forgotten later.
- **Deliberately minimal set of well-knowns:** only `NETWORK`, `INTERACTIVE`, `LOCAL`. Further logon types (`BATCH` S-1-5-3, `SERVICE` S-1-5-6, `REMOTE_INTERACTIVE` S-1-5-14) can be added later once a concrete audit use case requires them.

## Consequences

- 9 new tests in `permission_engine::engine::tests`: NETWORK applies in the SMB context, not in the others; INTERACTIVE/LOCAL symmetrically; `Unspecified` is the previous behaviour; Deny-NETWORK overrides a user Allow in the SMB audit path.
- 5 new tests in `adpa_core::model::tests` for `for_path` (standard path, UNC, long-path UNC, long-path local).
- Persistence and export are unaffected — `AccessContext` only lives on the input side. `EffectivePermission` stays unchanged.
- Existing ADRs are not revoked; ADR 0012 (AccessCheck semantics) and 0013 (this one) complement each other.
