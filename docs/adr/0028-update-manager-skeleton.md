# ADR 0028 — update_manager: Manifest-Schema + pluggable Signaturprüfung

**Status:** Akzeptiert / Accepted
**Datum / Date:** 2026-05-25

## Kontext / Context

AGENTS.md §13 schreibt `update_manager` als festen Architekturbaustein
vor:

> Update- und Patch-Installation müssen als fester Bestandteil der
> Produktarchitektur berücksichtigt werden. Updates müssen versioniert
> sein. Updates müssen digital signiert sein. Signaturen müssen vor
> der Installation geprüft werden. Prüfsummen müssen zusätzlich
> validiert werden. Update-Metadaten müssen gegen ein festes Schema
> validiert werden.

Bisher existierte nur ein Stub: `UpdateManager::check_for_updates`
und `verify_package` lieferten `Err(NotYetImplemented)`. Es gab kein
Manifest-Schema, keine Hash-Verifikation, keine Trait-Grenze für die
Signaturprüfung. Damit war jeder spätere Implementierungsschritt
gleichzeitig Schema-Design — riskant, weil die Schema-Wahl die
Kompatibilität aller späteren Update-Pakete bestimmt.

## Entscheidung / Decision

1. **Manifest-Schema festlegen** (`update_manager::manifest`):
   - `UpdateManifest { manifest_version, app_version, channel,
     platform, issued_at, files, signature }` als
     Serde-serialisierbare Struktur.
   - `ManifestFile { path, sha256, size_bytes }` — SHA-256 als
     lowercase-Hex (exakt 64 Zeichen), Größe als zusätzlicher
     Sanity-Check.
   - `TargetPlatform` als geschlossenes Enum
     (`windows-x86_64` / `windows-aarch64`) — kein Linux/macOS,
     entspricht dem Read-only-Windows-Fokus des Projekts.
   - `from_json` validiert Schema strukturell, bevor irgendetwas
     weiter verarbeitet wird.

2. **Signaturprüfung als Trait** (`update_manager::verifier`):
   - `SignatureVerifier::verify(body, signature_b64)` — kein
     vorgegebener Algorithmus. Produktive Implementierungen tragen
     Public-Key und Algorithmus.
   - `RejectAllVerifier` als Default — solange kein produktiver
     Verifier konfiguriert ist, wird **alles** abgelehnt. Das ist
     die wichtigste Sicherheitseigenschaft: ein nicht konfiguriertes
     System darf nie zufällig Updates akzeptieren.

3. **`signable_bytes` kanonisiert das Manifest ohne `signature`-Feld**,
   damit eine Signatur sich nicht selbst signiert.

4. **`verify_manifest` orchestriert die volle Kette**:
   Schema → Signatur → Datei-Hashes. Jede Stufe liefert einen
   sprechenden `CoreError`.

## Begründung / Rationale

- **Schema-First**: Wer als Erstes das Manifest entwirft, friert die
  Wire-Form-Kompatibilität ein. Hier ist sie bewusst minimal und
  forward-kompatibel (neue Felder per `#[serde(default)]` ergänzbar,
  ohne Manifest-Version zu erhöhen).
- **Pluggable Verifier**: Krypto-Backend (Ed25519 / RSA-PSS) hängt
  davon ab, welche Code-Signing-Lösung später gewählt wird. Trennung
  hält das Schema frei von Algorithmus-Annahmen.
- **Reject-by-default**: AGENTS.md verlangt „Kein Update ohne gültige
  Signatur". Der Default-Verifier setzt das ohne Sonderfälle durch —
  selbst ein perfekt geformtes Manifest mit gültigen Hashes wird
  abgelehnt, wenn kein konkreter Verifier konfiguriert ist.
- **Pfad-Traversal-Schutz im Schema**: `..`, führender `/` oder `\`
  in einem `ManifestFile.path` würde bei der Installation aus dem
  Zielverzeichnis ausbrechen. Die Validierung lehnt solche Pfade
  bereits beim Parsen ab, lange bevor Dateien geschrieben würden —
  Defense-in-Depth, da die Installations-Routine selbst auch noch
  Pfad-Canonicalization machen muss.
- **`size_bytes`-Sanity-Check vor dem Hashen**: erlaubt schnelles
  Ablehnen abgeschnittener Downloads, ohne erst SHA-256 über
  möglicherweise viele MB zu rechnen.

## Konsequenzen / Consequences

- 16 neue Tests in `update_manager`:
  - 6 Manifest-Tests (parse-success, unsigned-reject, kurze
    SHA-256, Pfad-Traversal, zero-byte-file, signable-bytes-strip).
  - 10 Verifier-Tests (SHA-256-Vektor, RejectAll-Verhalten,
    Größen-/Hash-Mismatch, vollständiger Workflow, Fehlerketten,
    Default-Reject auf wohlgeformtem Manifest).
- Neue öffentliche API: `UpdateManifest`, `ManifestFile`,
  `TargetPlatform`, `SignatureVerifier`, `RejectAllVerifier`,
  `verify_manifest`, `sha256_hex`. Re-export über
  `update_manager::*`.
- Keine Schema-Migration in der Persistenz nötig — `update_manager`
  hält keine eigene SQL-Tabelle.
- `UpdateManager::check_for_updates` / `verify_package` bleiben
  weiter Stubs mit `Err(NotImplemented)`. Sie wandern in einer
  nächsten Iteration auf die hier eingeführte
  Manifest-/Verifier-Infrastruktur.
- Noch offen (bewusst nicht Teil dieses Schritts): Download-Pfad,
  Rollback-Mechanik, Anti-Rollback-Marker, Schema-Migrationen
  innerhalb der Update-Installation, Update-Quellen-Validierung,
  Offline-Updatepfad. Jede dieser Erweiterungen kann ohne Schema-
  Bruch ergänzt werden.
