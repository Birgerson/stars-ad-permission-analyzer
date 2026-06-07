# Stars — Installation and Uninstallation

### Installation

Get the current Windows installer from the [Releases page](https://github.com/Birgerson/stars-ad-permission-analyzer/releases).

1. Click the latest release.
2. Download `Stars-vX.Y.Z-Setup.exe` from *Assets*.
3. Double-click — **no administrator rights required.** A **Stars** icon appears on the desktop.

The installer places the application under `C:\Program Files\Stars\`, adds a "Stars" start menu entry, and installs **no background services** and **no auto-start components**.

> **Note on code signing:** The installer is currently **not code-signed**. Windows SmartScreen will warn on first launch ("Windows protected your PC — unrecognized publisher"). A code-signing certificate is planned but not yet in place.

### System requirements

- Windows 10 / Windows 11 / Windows Server
- Network access to the target file server (for SMB shares)
- LDAP access to Active Directory (optional, for full group resolution)
- Sufficient read permissions on the paths to be analyzed

No additional runtime needed — Stars is a native Windows application.

### Development setup

Developers and CI builds may also run the `.exe` files from `target/release/` (`adpa.exe`, `adpa-gui.exe`) directly after `cargo build --release`:

```powershell
cargo build --release -p cli   # adpa.exe
cargo build --release -p gui   # adpa-gui.exe
```

Requirement: [Rust toolchain](https://rustup.rs/) for Windows (MSVC target). The regular delivery path is and remains the installer.

### Uninstallation

Stars is removed via **"Programs and Features"** (`appwiz.cpl`) or the start menu entry **"Stars deinstallieren"**. The uninstaller runs in the current user profile — **administrator rights are not required.**

> **Before uninstalling:** close Stars. If `Stars.exe` is still running, the uninstaller aborts with a notice instead of failing partway.

#### By default, the uninstaller removes

- `%LOCALAPPDATA%\Stars\` (program directory, shortcuts, uninstaller itself)
- The "Programs and Features" entry

#### By default, the uninstaller keeps

- `%APPDATA%\Stars\stars_data.db` (scan history, identity cache)
- `%LOCALAPPDATA%\Stars\logs\` (GUI log files)

Both therefore survive a reinstall — the audit history is evidence and should not vanish accidentally with the tool.

#### Remove everything

To remove everything completely: on the uninstaller's component page, check the additional **"Audit-Historie und Logs entfernen"** option. It is deliberately **off by default** — the decision must be made explicitly.
