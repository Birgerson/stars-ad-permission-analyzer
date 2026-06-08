# ADR 0022 — `max_depth` zentral validieren am CLI-/GUI-Boundary

**Status:** Accepted  
**Date:** 2026-05-25

## Context

`validation::numbers::validate_scan_depth` (Min 0, Max 512) existiert
seit dem ersten validation-Setup, wurde aber von CLI und GUI-Worker
nicht aufgerufen. Beide reichten `max_depth: Option<u32>` direkt aus
dem `clap::Parser` bzw. der GUI-State in `WalkConfig` weiter. Die
GUI-DragValue begrenzte den Wert nur visuell auf 0..=50 — ein
programmatischer Aufruf oder ein UI-Refactoring hätte das umgangen.

AGENTS.md Definition-of-Done, Punkt 11 fordert explizit, dass
**alle betroffenen Eingaben validiert werden**, bevor sie weiter-
verarbeitet werden. Numerische Scan-Steuerwerte sind unter
„Zu validierende Eingabetypen" ausdrücklich genannt.

Folge-Review (2026-05-25), Finding 3 (Low).

## Decision

1. **Neuer Helfer `validate_optional_scan_depth(Option<u32>)`** in
   `validation::numbers`, der `None` durchreicht (= unbegrenzte Tiefe,
   gewünschtes Verhalten) und `Some(d)` durch den bestehenden
   `validate_scan_depth` schickt. Damit hat die `Option`-API einen
   einzigen Aufrufpunkt.

2. **CLI** (`crates/cli/src/main.rs`) ruft den Validator direkt nach
   `validate_path` und vor dem Walk-Setup. Bei Fehler `anyhow::anyhow!`
   mit klarer Begründung — analog zur bestehenden Path-/SID-/LDAP-
   Validierung.

3. **GUI-Worker** (`crates/gui/src/worker.rs`) validiert direkt nach
   `validate_path` über das bestehende `make_early_summary`-Closure —
   so landet der Validierungsfehler sowohl im UI-Event als auch in der
   persistierten `scan_errors`-Liste, konsistent mit den anderen
   Setup-Fehlern (vgl. ADR 0016).

4. **`WalkConfig` bleibt unverändert** (`max_depth: Option<u32>`).
   Eine API-Änderung auf `Option<ScanDepth>` wäre type-sicherer, aber
   ein größerer Refactor in `fs_scanner` ohne unmittelbaren
   Korrektheitsgewinn. „Validate at the boundary, then unwrap" ist
   ein gängiges Rust-Pattern und passt hier.

## Rationale

- **Single-Source-of-Truth für Grenzen** — `MAX_SCAN_DEPTH = 512`
  lebt in einer Konstante, die der Validator durchsetzt. Spätere
  Anpassungen wirken überall gleich.
- **Defense in depth**: GUI-Widget-Begrenzung (visuell), Validator
  (programmatisch), Walker (operativ). Wenn eine Ebene umgangen
  wird, fängt die nächste.
- **Konsistenz mit Path/SID/LDAP**: alle anderen User-Eingaben in
  CLI und GUI laufen durch denselben Validierungs-Pattern; Scan-
  Tiefe schließt jetzt diese Lücke.

## Consequences

- 4 neue Unit-Tests in `validation::numbers::tests`:
  - `optional_scan_depth_none_passes_through`
  - `optional_scan_depth_some_within_limit_accepted`
  - `optional_scan_depth_some_at_boundary_accepted`
  - `optional_scan_depth_some_above_limit_rejected`
- Keine API-Brüche, keine Schema-Migration.
- DoD-Punkt 11 für die Scan-Tiefe ist erfüllt; Punkte 12
  („Validierungsfehler getestet") gleich mit.
