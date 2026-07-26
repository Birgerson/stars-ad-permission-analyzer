# ADR 0061 — Manual, read-only update check with a configurable, validated source

## Status
Accepted (2026-07-26)

## Context

AGENTS.md §13 mandates update/patch installation as a fixed architecture
component; `update_manager` has carried the prepared building blocks
(manifest schema, signature-verifier trait with reject-by-default, SemVer
policy incl. the F4 rc-before-final fix) since ADR 0028/0030 — without any
consumer. Known limitation L12 documented: "application updates are
manual". The user asked for the missing first step: *Stars should be able
to tell you when a newer version is published.*

Stars runs on domain controllers, frequently in hardened or offline
networks. Two constraints follow directly:

1. **No automatic phone-home.** An audit tool that contacts the internet
   unprompted at startup is unacceptable in exactly the environments Stars
   targets — and on an offline DC it would produce a startup error for a
   feature nobody asked to run.
2. **The check must be read-only.** Downloading or installing anything
   crosses into the signed-feed install flow, which remains gated behind
   the (unimplemented) signature pipeline — reject-by-default stands.

## Decision

1. **Manual only.** The check runs exclusively on explicit user action:
   the `Check for updates` button in the GUI Info tab, or
   `adpa check-update` in the CLI. No startup check, no timer, no beacon.
2. **Read-only by construction.** `update_manager::checker` fetches one
   JSON document (GitHub `releases/latest` shape), compares the published
   tag against the running version via the tested `AppVersion` SemVer
   precedence (a system on `1.7.9-rc1` sees the final `1.7.9` as an
   update — F4), and reports. No download, no install, no state change.
3. **Configurable, validated source** (user decision; AGENTS.md: "the
   update source must be configurable, but validated"). The default is
   the official GitHub release feed; GUI and CLI accept an override. The
   new `validation::update_source::validate_update_source` gates every
   source: **HTTPS only** (plain http, `file://` and UNC are rejected —
   an unencrypted update endpoint is tamperable in transit), **no
   embedded credentials** (they leak into logs and shell history), no
   fragment, no whitespace/control characters, 2048-character cap.
4. **Honest failure on offline systems.** The fetch uses a 10-second
   timeout, a 256 KB response cap and the User-Agent header the GitHub
   API requires; a connection failure surfaces as "could not reach the
   update source" — the expected answer on an offline DC, not a hidden
   error. An unparseable tag is a loud error naming the tag, never a
   silent "no update".
5. **Placement.** Parsing, tag normalization and comparison are
   network-free-testable functions in `update_manager::checker`; the
   `ureq` HTTPS fetch (rustls, no OpenSSL system dependency) is a thin
   wrapper. GUI work runs on the worker thread, so the timeout never
   blocks the UI.

## Consequences

- `update_manager` gains its first production consumers (CLI + GUI);
  the install-flow modules (`manifest`, `verifier`, `manager`) remain
  prepared-but-unwired, documented as such.
- L12 is narrowed: updates are still installed manually, but Stars now
  answers "is there one?" on demand.
- Corporate proxies are not auto-detected in this first stage (direct
  HTTPS only); documented in the user guide. A proxy-aware or
  offline-file source is a separate, deliberate extension.
- The check discloses the tool's User-Agent (name + version) to the
  configured source when — and only when — the user triggers it.

Implementation by Claude (AI), prompted and reviewed by Birger Labinsch.
