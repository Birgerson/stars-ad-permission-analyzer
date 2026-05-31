# ADR 0001 — Core Engine vor GUI

**Status:** Akzeptiert / Accepted  
**Datum / Date:** 2026-05-20

## Kontext / Context

Das Projekt analysiert Active-Directory-Berechtigungen, NTFS-ACLs und SMB-Freigaben.
Die korrekte Berechnung effektiver Rechte ist komplex und muss vollständig testbar sein.

## Entscheidung / Decision

Die Core Engine (`permission_engine`, `ad_resolver`, `fs_scanner`, `share_scanner`)
wird vollständig entwickelt und getestet, bevor eine GUI gebaut wird.
Die GUI-Technologie (egui, iced, Tauri, Slint) wird erst nach stabiler Core Engine gewählt.

## Begründung / Rationale

- Berechtigungslogik in der GUI duplizieren würde zu Inkonsistenzen führen.
- Ohne stabile Core Engine lässt sich die GUI nicht sinnvoll validieren.
- Die CLI erlaubt frühe Integration- und Regressionstests ohne GUI.

## Konsequenzen / Consequences

- GUI-Crate ist angelegt, aber vorerst leer.
- Alle fachlichen Änderungen gehen durch Core-Crates, nicht durch GUI-Code.
