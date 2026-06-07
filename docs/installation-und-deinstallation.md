# Stars — Installation und Deinstallation

[**Deutsch**](#deutsch) · [**English**](#english)

---

## <a name="deutsch"></a>Deutsch

### Installation

Den aktuellen Windows-Installer gibt es auf der [Releases-Seite](https://github.com/Birgerson/stars-ad-permission-analyzer/releases).

1. Auf den neuesten Release klicken.
2. `Stars-vX.Y.Z-Setup.exe` unter *Assets* herunterladen.
3. Doppelklick — **keine Administratorrechte erforderlich.** Ein **Stars**-Symbol erscheint auf dem Desktop.

Der Installer legt die Anwendung nach `C:\Program Files\Stars\` ab, erstellt einen Start-Menü-Eintrag „Stars" und installiert **keine Hintergrunddienste** und **keine Auto-Start-Komponenten**.

> **Hinweis zur Signatur:** Der Installer ist aktuell **nicht codesigned**. Beim ersten Start warnt Windows SmartScreen entsprechend („Computer durch unbekannten Herausgeber geschützt"). Ein Code-Signing-Zertifikat ist eingeplant, aber noch nicht eingerichtet.

### Systemvoraussetzungen

- Windows 10 / Windows 11 / Windows Server
- Netzwerkzugriff auf den Ziel-Dateiserver (für SMB-Freigaben)
- LDAP-Zugriff auf Active Directory (optional, für vollständige Gruppenauflösung)
- Ausreichende Leserechte auf die zu analysierenden Pfade

Keine zusätzliche Laufzeitumgebung nötig — Stars ist eine native Windows-Anwendung.

### Entwicklungs-Setup

Für Entwickler und CI-Builds lassen sich die `.exe`-Dateien aus `target/release/` (`adpa.exe`, `adpa-gui.exe`) nach `cargo build --release` auch ohne Installer direkt starten:

```powershell
cargo build --release -p cli   # adpa.exe
cargo build --release -p gui   # adpa-gui.exe
```

Voraussetzung: [Rust Toolchain](https://rustup.rs/) für Windows (MSVC-Target). Der reguläre Auslieferungsweg ist und bleibt der Installer.

### Deinstallation

Stars wird über **„Programme und Features"** (`appwiz.cpl`) oder den Startmenü-Eintrag **„Stars deinstallieren"** entfernt. Der Uninstaller läuft im aktuellen Benutzerprofil — **Administratorrechte sind nicht nötig.**

> **Vor der Deinstallation:** Stars beenden. Wenn `Stars.exe` noch läuft, bricht der Uninstaller mit einem Hinweis ab statt teilweise zu scheitern.

#### Standardmäßig entfernt der Uninstaller

- `%LOCALAPPDATA%\Stars\` (Programmverzeichnis, Verknüpfungen, Uninstaller selbst)
- Den Eintrag in „Programme und Features"

#### Standardmäßig bleibt erhalten

- `%APPDATA%\Stars\stars_data.db` (Scan-Historie, Identitäts-Cache)
- `%LOCALAPPDATA%\Stars\logs\` (Logfiles der GUI)

Beide überleben damit eine Neuinstallation — die Audit-Historie ist Beweismittel und sollte nicht versehentlich mit dem Tool verloren gehen.

#### Vollständig entfernen

Wer alles vollständig entfernen will: auf der Komponenten-Seite des Uninstallers die zusätzliche Option **„Audit-Historie und Logs entfernen"** anhaken. Diese ist bewusst standardmäßig **deaktiviert** — die Entscheidung soll explizit gefällt werden.

---

## <a name="english"></a>English

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
