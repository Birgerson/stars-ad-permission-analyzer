# ADR 0011 — GUI-Prototyp mit egui/eframe

## Status
Accepted

## Kontext / Context

Step 15 builds the first GUI prototype on top of the stable core engine.
The core engine (permission calculation, NTFS ACL reading, SMB share scanner, AD
resolver, persistence) was stable after Step 14.  A GUI technology had to be
selected; the choice was intentionally deferred until this point.

Candidates evaluated:

| Technology | Pros | Cons |
|------------|------|------|
| egui/eframe | Pure Rust, no JS/webview, excellent for data tables, Windows-native via OpenGL/Vulkan | No HTML/CSS styling flexibility |
| Tauri       | Web UI, modern look | Requires Node.js toolchain, webview security surface |
| iced        | Pure Rust, good async support | API less mature, fewer widgets |
| Slint       | Native look, DSL | Separate DSL, additional toolchain |

## Entscheidung / Decision

**egui 0.31 / eframe 0.31** was chosen.

Reasons:
- Pure Rust: no extra toolchain, no Node.js, no JavaScript bundle
- Immediate-mode rendering: no complex state synchronisation between UI and model
- `eframe::run_native` provides a native Windows window via OpenGL/WGL
- Well-suited for data-table-heavy layouts (permission results, scan rows)
- Active maintenance and established in the Rust ecosystem

### Struktur / Structure

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

Both tabs support an optional LDAP section for full group resolution via Active
Directory. Without LDAP credentials the analysis runs in SID-only mode (the same
as `adpa scan`).

### Worker-Thread-Modell / Worker thread model

Analysis and scan operations run in a dedicated `std::thread` that owns a
`tokio::runtime::Runtime`. Communication uses `std::sync::mpsc` channels:

```
UI thread  ──[WorkerRequest]──►  worker thread
UI thread  ◄─[WorkerEvent]────   worker thread
```

The worker calls `ctx.request_repaint()` after sending events so that the UI
frame loop picks up results immediately.  The UI polls `rx.try_recv()` in every
`update()` call and keeps calling `ctx.request_repaint()` while `is_running` is
true.

### Architekturregeln / Architecture rules

- The GUI contains no permission logic.  All evaluation goes through
  `DefaultPermissionEngine` and `fs_scanner::read_fso`.
- `AnalyzeState` and `ScanState` are pure UI state; they hold results as
  already-computed `EffectivePermission` values or `ScanRow` structs.
- Passwords for LDAP are handled via `TextEdit::password(true)` and are never
  logged.

## Bekannte Einschränkungen / Known limitations

- The scan runs to completion; no incremental cancellation within a running scan
  (cancellation is signalled by dropping the sender channel when the window
  closes).
- Large scans (>100 k paths) keep all rows in memory.  Virtualization will be
  added in a later step.
- The GUI binary (`adpa-gui`) is distinct from the CLI binary (`adpa`).

## Alternativen erwogen / Alternatives considered

See the candidates table above.  Tauri was the closest alternative; rejected
because of the JavaScript / webview build chain and the larger attack surface for
a security analysis tool.

## Konsequenzen / Consequences

- `crates/gui/Cargo.toml` now defines `[[bin]] name = "adpa-gui"` and adds
  `eframe`, `egui`, and all core crate dependencies.
- The empty `src/lib.rs` stub remains as a harmless empty library crate.
- `cargo build -p gui` produces `adpa-gui.exe`.
- Step 16 (risk engine) and Step 17 (HTML report) will add new tabs or menu
  actions to the GUI.
