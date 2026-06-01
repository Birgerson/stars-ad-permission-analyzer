# ADR 0030 — Update-Manager: Pfadvalidierung und Policy-Schicht

**Status:** Akzeptiert / Accepted
**Datum / Date:** 2026-06-01

## Kontext / Context

ADR 0028 hat den `update_manager`-Crate als Skelett aufgesetzt: Manifest
mit Signatur und SHA-256-Datei-Hashes, `RejectAllVerifier` als sicherer
Default, kein Installations-Pfad. Die spätere produktive
Installationslogik fehlt noch — was nicht heißt, dass das Skelett heute
schon sicher genug ist.

Reviewer-Befunde 2026-05-31 #6 und #7 zeigen zwei konkrete Schwächen:

1. **Manifest-Pfadprüfung zu lax.** Die alte Prüfung lehnte nur leere
   Pfade, führende Separatoren und `..`-Substrings ab. Pfade wie
   `C:\Temp\evil.exe`, `C:evil.exe` (drive-relativ), gemischte
   Separatoren, reservierte Windows-Gerätenamen oder ADS-Notation
   (`file.txt:ads`) hätten den Filter passiert. Heute kein
   Exploit-Pfad, weil keine Installationslogik existiert — sobald sie
   kommt, ist die Lücke ein Write-outside-of-install-directory-Risiko.

2. **`verify_manifest` heißt „Complete check", prüft aber nur
   Integrität.** Felder wie `platform`, `channel`, `app_version`,
   `issued_at` werden strukturell akzeptiert, aber nicht gegen die
   laufende Installation geprüft. Späteres Code-Lesen könnte den Aufruf
   für eine vollständige Freigabe halten und die Policy-Prüfung
   überspringen.

## Entscheidung / Decision

1. **`validate_manifest_relative_path` als zentrale Pfadprüfung.** In
   `update_manager::manifest` lehnt sie ab:
   - leere Pfade, Null-Bytes
   - UNC- und Long-Path-Präfixe (`\\…`, `\\?\…`, sowie `/`-Varianten)
   - führende Separatoren (`/abs/path`, `\abs\path`)
   - `.`- und `..`-Segmente (Traversal)
   - leere Segmente (`a//b`)
   - reservierte Windows-Geräte­namen (`NUL`, `CON`, `COM1`, …)
   - `:` in einem Segment — fängt sowohl Laufwerksbuchstaben (`C:foo`)
     als auch ADS-Notation (`file.txt:ads`) ab
   - Zeichen aus `FORBIDDEN_PATH_CHARS` (`< > " | ? *`)
   - Steuerzeichen

   Akzeptiert sind relative Pfade mit `/` und `\` als Separator;
   Manifeste sollen plattform-neutral schreibbar bleiben.

   `UpdateManifest::validate_schema` ruft die Funktion pro Datei-
   Eintrag statt der alten Substring-Heuristik.

2. **Trennung Integrität ↔ Policy.**
   - `verify_manifest` ist umbenannt zu **`verify_manifest_integrity`**
     — Schema, Signatur, Datei-Hashes. Cryptographische und
     strukturelle Korrektheit, keine Plattform-/Versions-/Zeit-
     Annahmen.
   - **`verify_update_policy(manifest, &UpdatePolicyContext)`** prüft
     in dieser Reihenfolge:
     1. Plattform stimmt mit `current_platform` überein.
     2. Kanal stimmt mit `allowed_channel` überein.
     3. `app_version` ist (dotted numeric) höher als `current_version`,
        außer `allow_downgrade == true`.
     4. `issued_at` ist ISO-8601-parsebar.
     5. `issued_at` liegt nicht weiter als `max_future_skew` in der
        Zukunft.
     6. `issued_at` liegt nicht weiter als `max_age` in der
        Vergangenheit.
   - Vor einer realen Installation müssen **beide** Calls erfolgreich
     sein.

3. **`UpdatePolicyContext` als Plain-Old-Data.** Der Aufrufer baut den
   Kontext aus seiner Konfiguration und der Systemuhr (`Utc::now()` in
   Produktion, deterministisch in Tests). Felder:
   `current_version`, `current_platform`, `allowed_channel`,
   `allow_downgrade`, `now_utc`, `max_age`, `max_future_skew`.

4. **Versionsvergleich pragmatisch.** `compare_dotted_versions` splittet
   beide Strings an `.`, parst Segmente als `u64`, vergleicht
   segmentweise mit Auffüllen kürzerer Versionen durch `0`. Pre-Release-
   Suffixe nach `-` (und `+`) werden für den Vergleich abgeschnitten —
   das Projekt liefert bisher nur reine `major.minor.patch`. SemVer-
   Pre-Release-Ordering ist eine v1.x+-Erweiterung, sollte sie nötig
   werden.

## Begründung / Rationale

- **Pfadprüfung ist defense-in-depth.** Auch wenn heute keine
  Installationslogik existiert, ist „später ergänzbar ohne Re-Review"
  das Ziel. Wir parken den Filter dort, wo er hingehört: am
  Manifest-Eingang.
- **Gleichheit zu `validation::path`.** Die Constants
  `FORBIDDEN_PATH_CHARS` und `RESERVED_DEVICE_NAMES` sind identisch zur
  Benutzer-Pfadprüfung. Wer Manifest-Pfade lockerer akzeptiert als
  Benutzer-Eingaben, hat die Reihenfolge falsch herum.
- **Namensumbenennung statt Doppel-Pflege.** Der alte Name
  `verify_manifest` wird nicht als Alias erhalten. Risiko, dass
  jemand den alten „Complete check"-Namen sieht und auf eine
  Policy-Prüfung vergisst, ist größer als der Migrations­aufwand
  (keine externen Aufrufer, nur Tests im selben Crate).
- **Dotted-Numeric reicht heute.** Die Software ist auf v1.0.0,
  schreibt v1.1.0; keine Pre-Releases im produktiven Kanal.

## Konsequenzen / Consequences

- Externe Konsumenten von `verify_manifest` (gibt es heute keine) wären
  umbenennungspflichtig.
- `UpdatePolicyContext::current_version` ist ein `String` — das wird
  beim Übergang auf echte SemVer eine kleine Migration. Aktuell der
  pragmatischste Schnitt.
- `chrono` ist neu als Workspace-Dependency in `update_manager`;
  passend, weil das Hauptprojekt es ohnehin nutzt.

## Tests / Tests

25 neue Tests im `update_manager`-Crate:

- 14 Pfadtests (`crates/update_manager/src/manifest.rs::tests`):
  akzeptierte relative Pfade, Drive-absolut, Drive-relativ,
  Parent-/Current-Dir-Segmente, reservierte Gerätenamen, ADS, UNC,
  Long-Path, führende Separatoren, leere Segmente, verbotene Zeichen,
  Steuerzeichen + Null-Bytes, leerer Pfad.
- 11 Policy- und Vergleichstests (`verifier.rs::tests`): passender
  Standard-Pfad, falsche Plattform, falscher Kanal, Downgrade ohne
  Freigabe, Re-Install (gleiche Version), Downgrade mit Freigabe,
  zukunftsweite Manifeste außerhalb der Skew-Toleranz, innerhalb der
  Skew-Toleranz, abgelaufenes `issued_at`, nicht parsbares
  `issued_at`, dotted-numerische Ordnung und Pre-Release-Strip.

## Schließt / Closes

ChatGPT-Code-Review 2026-05-31, Findings 6 (Medium) und 7 (Low).
