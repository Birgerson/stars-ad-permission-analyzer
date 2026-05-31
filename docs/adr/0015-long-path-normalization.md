# ADR 0015 — Long-Path-Normalisierung für Win32-Aufrufe

**Status:** Akzeptiert / Accepted  
**Datum / Date:** 2026-05-24

## Kontext / Context

Die Pfadvalidierung in `validation::path` lässt Pfade bis zu 32.767
Zeichen zu (Windows-Extended-Length-Limit). Der NTFS-Scanner reichte
solche Pfade jedoch unverändert an `GetFileAttributesW` und
`GetNamedSecurityInfoW` weiter — diese Win32-Wide-APIs sind ohne
`\\?\`-Präfix auf `MAX_PATH` (260 Zeichen) limitiert. Ein vom Tool
formal akzeptierter Pfad konnte also zur Laufzeit am Win32-Aufruf
scheitern, ohne dass das aus der Validierung absehbar war — ein
gebrochenes Versprechen.

Auch `std::fs::read_dir` im Walker traf dasselbe Problem für die
Verzeichnis-Enumeration.

Siehe Review-Befund 5.

## Entscheidung / Decision

1. **Neuer Pfadtyp `WindowsApiPath`** in `validation::path` plus zwei
   freistehende Helper:

   ```rust
   pub fn to_windows_api_path(path: &str) -> String;
   pub fn strip_long_path_prefix(path: &str) -> String;
   ```

   - `to_windows_api_path` wandelt um:
     - `C:\…` → `\\?\C:\…`
     - `\\server\share\…` → `\\?\UNC\server\share\…`
     - bereits präfixierte Pfade bleiben unverändert (idempotent)
     - alles andere (relativ etc.) bleibt unverändert
   - `strip_long_path_prefix` ist die Umkehrung — wird im FSO-Bau
     genutzt, um den im Report sichtbaren Pfad menschenlesbar zu
     halten.

2. **Anwendung im NTFS-Scanner:** `read_file_system_object` normalisiert
   den Eingabepfad **einmal** vor den Win32-Aufrufen. Der im
   resultierenden `FileSystemObject` gespeicherte Pfad wird vorher per
   `strip_long_path_prefix` wieder bereinigt, damit Reports und
   Persistenz die ursprüngliche, lesbare Form sehen.

3. **Anwendung im Walker:** `walk_dir` ruft `std::fs::read_dir` mit dem
   normalisierten Pfad auf. Die `DirEntry::path()`-Rückgaben vererben
   den `\\?\`-Präfix an die Kinder — `to_windows_api_path` ist
   idempotent, also gibt es keine doppelte Präfixierung. Der
   FSO-Bau in `read_file_system_object` entfernt den Präfix wieder
   für die Anzeige.

4. **Keine Lockerung der Validierung.** Pfade in der `\\?\…`-Form
   bleiben in `validate_local_path` / `validate_unc_path` weiterhin
   verboten (`?` und `:` sind in Segmenten verbotene Zeichen). Der
   Präfix ist eine interne Optimierung des Scanners, nicht ein
   benutzerseitiges Eingabeformat.

## Begründung / Rationale

- **Konsistenz mit der Validierung:** Was die Validierung zulässt
  (bis 32.767 Zeichen), soll der Scanner auch lesen können.
- **Minimal-invasiv:** Die externe API (CLI/GUI/Trait-Signaturen)
  bleibt unverändert; der Präfix lebt nur zwischen Validierung und
  Win32-Aufruf.
- **Reports bleiben lesbar:** Anwender sehen weiterhin
  `C:\Users\…` statt `\\?\C:\Users\…`.
- **Idempotenz** des Konverters erlaubt es, ihn beliebig oft
  anzuwenden ohne Spezialfall-Behandlung — der Walker und der
  ACL-Reader können beide ihre eigenen Konvertierungen durchführen.

## Konsequenzen / Consequences

- 11 neue Tests in `validation::path::tests`: vier Roundtrip-/
  Strip-/Idempotenz-Tests, sieben Fall-Tests
  (`to_windows_api_path` für UNC/Local/Long/präfixiert sowie
  `WindowsApiPath::from(&Validated…)`).
- 1 neuer Integrationstest in `fs_scanner::walker::tests` baut unter
  `TEMP` eine 12-stufige Verzeichniskette von ~412 Zeichen, scannt
  sie ohne `\\?\`-Präfix und prüft: keine Fehler, 13 Objekte
  (Root + Tiefe), tiefster Pfad > 260, FSO-Pfade tragen kein Präfix.
- `fs_scanner` hängt jetzt von `validation` ab — die Long-Path-
  Mechanik ist Validierungs-/Pfad-Semantik, kein Scanner-Detail.
- Eine spätere bewusste Erweiterung der Validierung um
  `\\?\…`-Format ist möglich, falls externe Aufrufer ihn doch direkt
  übergeben wollen — Pflicht ist sie nicht.
