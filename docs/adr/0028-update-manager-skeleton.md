# ADR 0028 — update_manager: manifest schema + pluggable signature verification

**Status:** Accepted
**Date:** 2026-05-25

## Context

AGENTS.md §13 mandates `update_manager` as a fixed architectural building
block:

> Update and patch installation must be considered a fixed part of the
> product architecture. Updates must be versioned. Updates must be
> digitally signed. Signatures must be verified before installation.
> Checksums must additionally be validated. Update metadata must be
> validated against a fixed schema.

Previously only a stub existed: `UpdateManager::check_for_updates` and
`verify_package` returned `Err(NotYetImplemented)`. There was no manifest
schema, no hash verification, no trait boundary for signature verification.
This meant every later implementation step was simultaneously schema
design — risky, because the schema choice determines the compatibility of
all later update packages.

## Decision

1. **Define the manifest schema** (`update_manager::manifest`):
   - `UpdateManifest { manifest_version, app_version, channel, platform,
     issued_at, files, signature }` as a Serde-serializable struct.
   - `ManifestFile { path, sha256, size_bytes }` — SHA-256 as lowercase hex
     (exactly 64 characters), size as an additional sanity check.
   - `TargetPlatform` as a closed enum (`windows-x86_64` /
     `windows-aarch64`) — no Linux/macOS, matching the project's read-only
     Windows focus.
   - `from_json` validates the schema structurally before anything is
     further processed.

2. **Signature verification as a trait** (`update_manager::verifier`):
   - `SignatureVerifier::verify(body, signature_b64)` — no prescribed
     algorithm. Production implementations carry the public key and
     algorithm.
   - `RejectAllVerifier` as the default — as long as no production verifier
     is configured, **everything** is rejected. This is the most important
     security property: an unconfigured system must never accidentally
     accept updates.

3. **`signable_bytes` canonicalizes the manifest without the `signature`
   field**, so that a signature does not sign itself.

4. **`verify_manifest` orchestrates the full chain**: schema → signature →
   file hashes. Each stage returns a descriptive `CoreError`.

## Rationale

- **Schema-first**: whoever first designs the manifest freezes the
  wire-form compatibility. Here it is deliberately minimal and
  forward-compatible (new fields can be added via `#[serde(default)]`
  without bumping the manifest version).
- **Pluggable verifier**: the crypto backend (Ed25519 / RSA-PSS) depends on
  which code-signing solution is chosen later. The separation keeps the
  schema free of algorithm assumptions.
- **Reject-by-default**: AGENTS.md requires "no update without a valid
  signature". The default verifier enforces this without special cases —
  even a perfectly formed manifest with valid hashes is rejected if no
  concrete verifier is configured.
- **Path-traversal protection in the schema**: `..`, a leading `/` or `\`
  in a `ManifestFile.path` would, at install time, break out of the target
  directory. The validation already rejects such paths at parse time, long
  before files would be written — defense in depth, since the installation
  routine itself must also still do path canonicalization.
- **`size_bytes` sanity check before hashing**: allows fast rejection of
  truncated downloads, without first computing SHA-256 over possibly many
  MB.

## Consequences

- 16 new tests in `update_manager`:
  - 6 manifest tests (parse-success, unsigned-reject, short SHA-256, path
    traversal, zero-byte file, signable-bytes strip).
  - 10 verifier tests (SHA-256 vector, RejectAll behavior, size/hash
    mismatch, full workflow, error chains, default-reject on a well-formed
    manifest).
- New public API: `UpdateManifest`, `ManifestFile`, `TargetPlatform`,
  `SignatureVerifier`, `RejectAllVerifier`, `verify_manifest`,
  `sha256_hex`. Re-exported via `update_manager::*`.
- No schema migration needed in persistence — `update_manager` holds no SQL
  table of its own.
- `UpdateManager::check_for_updates` / `verify_package` remain stubs with
  `Err(NotImplemented)`. They will move onto the manifest/verifier
  infrastructure introduced here in a next iteration.
- Still open (deliberately not part of this step): download path, rollback
  mechanics, anti-rollback marker, schema migrations within the update
  installation, update-source validation, offline update path. Each of
  these extensions can be added without a schema break.
