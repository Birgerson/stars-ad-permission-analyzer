# ADR 0011 — GUI prototype with egui/eframe

## Status
**Superseded by the later Slint switch** (no formal superseding ADR; the switch is recorded in the v0.2.0-rc7..rc11 CHANGELOG entries). Kept here for historical context. The current GUI is inline Slint in `crates/gui/src/main.rs` and uses the software backend — see the rationale in `crates/gui/Cargo.toml`.

## Context

Step 15 builds the first GUI prototype on top of the stable core engine. The core engine (permission calculation, NTFS ACL reading, SMB share scanner, AD resolver, persistence) was stable after Step 14. A GUI technology had to be selected; the choice was intentionally deferred until this point.

Candidates evaluated:

| Technology | Pros | Cons |
|------------|------|------|
| egui/eframe | Pure Rust, no JS/webview, excellent for data tables, Windows-native via OpenGL/Vulkan | No HTML/CSS styling flexibility |
| Tauri       | Web UI, modern look | Requires Node.js toolchain, webview security surface |
| iced        | Pure Rust, good async support | API less mature, fewer widgets |
| Slint       | Native look, DSL | Separate DSL, additional toolchain |

## Decision (historical)

**egui 0.31 / eframe 0.31** was chosen.

Reasons (still valid in principle, but invalidated by the Windows Server / RDP / VirtIO-GPU deployment target — see the Slint switch):

- Pure Rust: no extra toolchain, no Node.js, no JavaScript bundle.
- Immediate-mode rendering: no complex state synchronisation between UI and model.
- `eframe::run_native` provides a native Windows window via OpenGL/WGL.
- Well-suited for data-table-heavy layouts (permission results, scan rows).
- Active maintenance and established in the Rust ecosystem.

### Structure (historical)

```
crates/gui/src/
├── main.rs         — eframe entry point, tracing setup, window options
├── app.rs          — AdpaApp struct, Tab enum, eframe::App impl
├── worker.rs       — WorkerRequest / WorkerEvent enums, spawn_worker()
├── analyze_view.rs — AnalyzeState, draw_analyze_tab()
└── scan_view.rs    — ScanState, draw_scan_tab()
```

### Tabs

**Analyze** — single path + user SID → effective permission + explanation path
**Scan Tree** — recursive tree scan with live-updating results table

Both tabs support an optional LDAP section for full group resolution via Active Directory. Without LDAP credentials the analysis runs in SID-only mode (the same as `adpa scan`).

### Worker thread model

Analysis and scan operations run in a dedicated `std::thread` that owns a `tokio::runtime::Runtime`. Communication uses `std::sync::mpsc` channels:

```
UI thread  ──[WorkerRequest]──►  worker thread
UI thread  ◄─[WorkerEvent]────   worker thread
```

The worker calls `ctx.request_repaint()` after sending events so the UI frame loop picks up results immediately. The UI polls `rx.try_recv()` in every `update()` call and keeps calling `ctx.request_repaint()` while `is_running` is true.

### Architecture rules

- The GUI contains no permission logic. All evaluation goes through `DefaultPermissionEngine` and `fs_scanner::read_fso`.
- `AnalyzeState` and `ScanState` are pure UI state; they hold results as already-computed `EffectivePermission` values or `ScanRow` structs.
- Passwords for LDAP are handled via `TextEdit::password(true)` and are never logged.

## Known limitations (historical)

- The scan runs to completion; no incremental cancellation within a running scan (cancellation is signalled by dropping the sender channel when the window closes).
- Large scans (>100 k paths) keep all rows in memory. Virtualization will be added in a later step.
- The GUI binary (`adpa-gui`) is distinct from the CLI binary (`adpa`).

## Alternatives considered

See the candidates table above. Tauri was the closest alternative; rejected because of the JavaScript / webview build chain and the larger attack surface for a security analysis tool.

## Why this ADR is superseded

The deployment target is a Windows Server domain controller on Proxmox with VirtIO-GPU. That environment has no modern OpenGL ICD and no D3D11/12 path — GPU-based toolkits (eframe/wgpu, iced/wgpu) start a window that turns black and closes. Slint's software renderer writes directly into a GDI bitmap and needs no GPU at all. The codebase migrated to inline Slint shortly after this ADR was written. The worker-thread / channel model survived the switch and is the same in the current implementation.

## Consequences (no longer current)

- `crates/gui/Cargo.toml` now defines `[[bin]] name = "adpa-gui"` and adds the Slint dependency (see the actual `Cargo.toml` file; the `eframe`/`egui` entries were removed in commit `ece89ad`).
- The empty `src/lib.rs` stub remains as a harmless empty library crate.
- `cargo build -p gui` produces `adpa-gui.exe`.
