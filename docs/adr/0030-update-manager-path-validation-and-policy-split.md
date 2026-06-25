# ADR 0030 — Update manager: path validation and policy layer

**Status:** Accepted
**Date:** 2026-06-01

## Context

ADR 0028 set up the `update_manager` crate as a skeleton: manifest with
signature and SHA-256 file hashes, `RejectAllVerifier` as the safe default,
no installation path. The later production installation logic is still
missing — which does not mean the skeleton is already safe enough today.

Reviewer findings 2026-05-31 #6 and #7 show two concrete weaknesses:

1. **Manifest path check too lax.** The old check rejected only empty
   paths, leading separators, and `..` substrings. Paths like
   `C:\Temp\evil.exe`, `C:evil.exe` (drive-relative), mixed separators,
   reserved Windows device names, or ADS notation (`file.txt:ads`) would
   have passed the filter. No exploit path today, because no installation
   logic exists — as soon as it arrives, the gap is a
   write-outside-of-install-directory risk.

2. **`verify_manifest` is called a "complete check" but verifies only
   integrity.** Fields like `platform`, `channel`, `app_version`,
   `issued_at` are accepted structurally, but not checked against the
   running installation. Later code reading could mistake the call for a
   full approval and skip the policy check.

## Decision

1. **`validate_manifest_relative_path` as the central path check.** In
   `update_manager::manifest` it rejects:
   - empty paths, null bytes
   - UNC and long-path prefixes (`\\…`, `\\?\…`, and `/` variants)
   - leading separators (`/abs/path`, `\abs\path`)
   - `.` and `..` segments (traversal)
   - empty segments (`a//b`)
   - reserved Windows device names (`NUL`, `CON`, `COM1`, …)
   - `:` in a segment — catches both drive letters (`C:foo`) and ADS
     notation (`file.txt:ads`)
   - characters from `FORBIDDEN_PATH_CHARS` (`< > " | ? *`)
   - control characters

   Accepted are relative paths with `/` and `\` as separators; manifests
   should remain platform-neutral to write.

   `UpdateManifest::validate_schema` calls the function per file entry
   instead of the old substring heuristic.

2. **Separation of integrity ↔ policy.**
   - `verify_manifest` is renamed to **`verify_manifest_integrity`** —
     schema, signature, file hashes. Cryptographic and structural
     correctness, no platform/version/time assumptions.
   - **`verify_update_policy(manifest, &UpdatePolicyContext)`** checks, in
     this order:
     1. Platform matches `current_platform`.
     2. Channel matches `allowed_channel`.
     3. `app_version` is (dotted numeric) higher than `current_version`,
        unless `allow_downgrade == true`.
     4. `issued_at` is ISO-8601-parseable.
     5. `issued_at` is no further than `max_future_skew` in the future.
     6. `issued_at` is no further than `max_age` in the past.
   - Before a real installation, **both** calls must succeed.

3. **`UpdatePolicyContext` as plain old data.** The caller builds the
   context from its configuration and the system clock (`Utc::now()` in
   production, deterministic in tests). Fields: `current_version`,
   `current_platform`, `allowed_channel`, `allow_downgrade`, `now_utc`,
   `max_age`, `max_future_skew`.

4. **Version comparison pragmatic.** `compare_dotted_versions` splits both
   strings at `.`, parses segments as `u64`, compares segment by segment,
   padding shorter versions with `0`. Pre-release suffixes after `-` (and
   `+`) are truncated for the comparison — the project so far ships only
   pure `major.minor.patch`. SemVer pre-release ordering is a v1.x+
   extension, should it become necessary.

## Rationale

- **Path checking is defense in depth.** Even though no installation logic
  exists today, "extensible later without re-review" is the goal. We park
  the filter where it belongs: at the manifest entrance.
- **Parity with `validation::path`.** The constants `FORBIDDEN_PATH_CHARS`
  and `RESERVED_DEVICE_NAMES` are identical to the user path check. Anyone
  who accepts manifest paths more loosely than user inputs has the order
  backwards.
- **Rename instead of double maintenance.** The old name `verify_manifest`
  is not kept as an alias. The risk of someone seeing the old "complete
  check" name and forgetting a policy check is greater than the migration
  effort (no external callers, only tests in the same crate).
- **Dotted-numeric is enough today.** The software is on v1.0.0, writes
  v1.1.0; no pre-releases in the production channel.

## Consequences

- External consumers of `verify_manifest` (there are none today) would need
  to rename.
- `UpdatePolicyContext::current_version` is a `String` — that will be a
  small migration on the transition to real SemVer. Currently the most
  pragmatic cut.
- `chrono` is new as a workspace dependency in `update_manager`; fitting,
  because the main project uses it anyway.

## Tests

25 new tests in the `update_manager` crate:

- 14 path tests (`crates/update_manager/src/manifest.rs::tests`): accepted
  relative paths, drive-absolute, drive-relative, parent/current-dir
  segments, reserved device names, ADS, UNC, long-path, leading
  separators, empty segments, forbidden characters, control characters +
  null bytes, empty path.
- 11 policy and comparison tests (`verifier.rs::tests`): matching standard
  path, wrong platform, wrong channel, downgrade without approval,
  re-install (same version), downgrade with approval, far-future manifests
  outside the skew tolerance, within the skew tolerance, expired
  `issued_at`, non-parseable `issued_at`, dotted-numeric ordering and
  pre-release strip.

## Closes

ChatGPT code review 2026-05-31, findings 6 (Medium) and 7 (Low).
