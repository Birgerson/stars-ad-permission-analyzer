# Stars — Scan-Historie und Datenbank

[**Deutsch**](#deutsch) · [**English**](#english)

---

## <a name="deutsch"></a>Deutsch

Stars persistiert seine Scan-Historie in einer **SQLite-Datenbank**, damit der Delta-Tab zwei Läufe vergleichen kann und Identitätsauflösungen über mehrere Sessions zwischengespeichert sind.

### Standort

```
%APPDATA%\Stars\stars_data.db
```

Auf einem typischen Windows-Server-DC ist das:

```
C:\Users\<Anwender>\AppData\Roaming\Stars\stars_data.db
```

Falls `%APPDATA%` nicht gesetzt ist, fällt die Anwendung auf das Verzeichnis der EXE zurück (relevant nur für `cargo run` während der Entwicklung).

### Was gespeichert wird

| Tabelle | Inhalt |
|---|---|
| `scan_runs` | Eine Zeile pro abgeschlossenem Scan: UUID, Startzeit, Endzeit, Zielpfad |
| `effective_permissions` | Alle ausgewerteten Pfade pro Lauf mit Identitäts-Snapshot, NTFS-Maske, Share-Maske, effektiver Maske, Erklärungspfad, Diagnose-Markern |
| `scan_errors` | Walk- und Eval-Fehler pro Scan (z. B. „Access denied", „Path not found") |
| `identities` | Cache für Identity-Auflösungen (SID → Name, Domäne, Kind, Disabled-Status). **Hinweis:** seit v1.5.16 wird der Identity-Snapshot pro Permission-Zeile in `effective_permissions` selbst gespeichert — diese Tabelle ist nur noch ein Cache für Live-Lookups, **nicht mehr die Quelle historischer Reports** (Audit-Integrität). |
| `group_memberships` | Auflösungs-Cache für rekursive Gruppenmitgliedschaften |

### Eigenschaften

- **Wird beim ersten Start automatisch angelegt;** Migrationsskripte (Schema v1 → aktuelle Version) laufen idempotent durch.
- **Pro Benutzerprofil getrennt** — jeder Windows-User hat seine eigene Historie.
- **Überlebt eine Deinstallation** — der Installer entfernt standardmäßig nur sein Install-Verzeichnis, die Audit-Historie bleibt erhalten. Wer die Historie loswerden will, löscht den Ordner `%APPDATA%\Stars\` manuell oder nutzt die Komponenten-Option des Uninstallers (siehe [Installation und Deinstallation](installation-und-deinstallation.md)).
- **Snapshot-stabil:** Historische Scan-Daten sind seit v1.5.16 unveränderlich gegenüber späteren Identity-Updates. Wenn ein User zwischen zwei Scans deaktiviert wird, zeigt der ältere Scan beim Re-Read trotzdem den Zustand zum Scan-Zeitpunkt (siehe Schema-Migration v7).
- **Kein Passwort, keine Verschlüsselung.** Wer Zugriff auf das Benutzerprofil hat, kann die Daten lesen. Für sensible Audit-Daten den Profilpfad selbst absichern (NTFS-Berechtigungen, BitLocker).
- **Inspizierbar mit jedem SQLite-Tool** (DB Browser for SQLite, DBeaver, `sqlite3.exe`) — read-only, ohne dass Stars läuft.

### Wenn die Datenbank nicht erreichbar ist

Schlägt das Öffnen oder Schreiben fehl (fehlende Schreibrechte, Plattenplatz voll), läuft der Scan trotzdem durch — Stars unterdrückt das nicht. Die Persistenz-Meldung erscheint als Fehler in der Statuszeile, damit der Befund nicht still unter den Tisch fällt.

### Delta-Vergleich

Der Delta-Tab vergleicht zwei Scan-Läufe und meldet Pfade als `Added`, `Removed` oder `Changed`. Seit v1.5.16 deckt der `Changed`-Vergleich nicht nur die effektive Maske ab, sondern auch:

- NTFS- und Share-Masken-Komposition (gleiche Endmaske bei anderer Ursache)
- `share_status` (z. B. Wechsel von `Applied` zu `ReadFailed`)
- `local_group_status` (z. B. Wechsel auf `NotAvailable`)
- `unsupported_ace_count`
- Diagnose-Marker

Die Anzeige nennt die konkreten Gründe — z. B. „Geändert (NTFS mask + share status)".

---

## <a name="english"></a>English

Stars persists its scan history in a **SQLite database** so the Delta tab can compare two runs and identity resolutions are cached across sessions.

### Location

```
%APPDATA%\Stars\stars_data.db
```

On a typical Windows Server DC this is:

```
C:\Users\<account>\AppData\Roaming\Stars\stars_data.db
```

If `%APPDATA%` is not set, the application falls back to the directory next to the EXE (only relevant for `cargo run` during development).

### What is stored

| Table | Content |
|---|---|
| `scan_runs` | One row per completed scan: UUID, start time, end time, target path |
| `effective_permissions` | Every evaluated path per run with an identity snapshot, NTFS mask, share mask, effective mask, explanation path, diagnostic markers |
| `scan_errors` | Walk and eval errors per scan (e.g. "Access denied", "Path not found") |
| `identities` | Cache for identity resolutions (SID → name, domain, kind, disabled status). **Note:** since v1.5.16 the identity snapshot is stored per permission row in `effective_permissions` itself — this table is now only a cache for live lookups, **no longer the source for historical reports** (audit integrity). |
| `group_memberships` | Resolution cache for recursive group memberships |

### Properties

- **Created automatically on first start;** migration scripts (schema v1 → current) run idempotently.
- **Separate per user profile** — every Windows user has their own history.
- **Survives uninstallation** — by default the uninstaller removes only its install directory; the audit history stays. To get rid of it, delete `%APPDATA%\Stars\` manually, or use the uninstaller's optional component (see [Installation and uninstallation](installation-und-deinstallation.md)).
- **Snapshot-stable:** Historical scan data has been immutable against later identity updates since v1.5.16. If a user gets disabled between two scans, the older scan still shows their state at scan time when reloaded (see schema migration v7).
- **No password, no encryption.** Anyone with access to the user profile can read the data. Protect the profile path itself (NTFS permissions, BitLocker) for sensitive audit data.
- **Inspectable with any SQLite tool** (DB Browser for SQLite, DBeaver, `sqlite3.exe`) — read-only, without Stars running.

### When the database is unreachable

If opening or writing fails (no write permissions, disk full), the scan still runs — Stars does not suppress that. The persistence message appears as an error in the status bar so the finding does not silently disappear.

### Delta comparison

The Delta tab compares two scan runs and reports paths as `Added`, `Removed`, or `Changed`. Since v1.5.16 the `Changed` comparison covers not only the effective mask but also:

- NTFS and share mask composition (same final mask with a different cause)
- `share_status` (e.g. flip from `Applied` to `ReadFailed`)
- `local_group_status` (e.g. flip to `NotAvailable`)
- `unsupported_ace_count`
- Diagnostic markers

The UI names the concrete reasons — e.g. "Changed (NTFS mask + share status)".
