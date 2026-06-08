# ADR 0001 — Core engine before GUI

**Status:** Accepted
**Date:** 2026-05-20

## Context

The project analyses Active Directory permissions, NTFS ACLs, and SMB shares. Correct effective-rights computation is complex and must be fully testable.

## Decision

The core engine (`permission_engine`, `ad_resolver`, `fs_scanner`, `share_scanner`) is built and tested fully before a GUI is added. The GUI technology (egui, iced, Tauri, Slint) is only picked once the core engine is stable.

## Rationale

- Duplicating permission logic in the GUI would cause inconsistencies.
- Without a stable core engine, the GUI cannot be meaningfully validated.
- The CLI enables early integration and regression testing without a GUI.

## Consequences

- The GUI crate exists but is empty for now.
- All domain changes flow through the core crates, not through GUI code.
