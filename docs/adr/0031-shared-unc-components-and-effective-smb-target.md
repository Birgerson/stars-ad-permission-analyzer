# ADR 0031 — Zentrale UNC-Zerlegung und expliziter SMB-Zielserver

**Status:** Akzeptiert / Accepted
**Datum / Date:** 2026-06-04

## Kontext / Context

ChatGPT-Code-Review 2026-06-04, Findings 1, 2 und 4 trafen alle dieselbe
Stelle der CLI-/GUI-Orchestrierung:

- **Finding 1 (High):** Die CLI-Funktion `unc_components` in
  `crates/cli/src/main.rs` prüfte das doppelte Slash-Präfix nicht. Für
  `C:\Windows\SYSVOL` — Kernpfad auf jedem Domain Controller — lieferte
  sie `Some(("C:", "Windows"))`. Folge: lokale Gruppen wurden gegen einen
  Server namens `C:` aufgelöst und `NetShareGetInfo("C:", "Windows")`
  startete einen Share-DACL-Lookup, obwohl der Aufrufer keinen SMB-Kontext
  angefragt hatte. Die GUI hatte den Fix längst (siehe
  `crates/gui/src/worker.rs` mit Prefix-Prüfung und Regressionstest); die
  CLI nicht.

- **Finding 4 (Medium):** Beide Varianten arbeiteten am unnormalisierten
  Pfad-String. `\\?\UNC\server\share\folder` wurde nach `trim_start_matches`
  als `Server=?`, `Share=UNC` zerlegt. Long-Path-UNC ist auf grossen
  Fileservern mit langen Pfaden produktiv relevant.

- **Finding 2 (High):** `collect_local_group_sids_for_path` nahm den
  explizit gesetzten `--smb-server` gar nicht entgegen. Lokale Gruppen
  kamen vom Pfad-Server, die Share-DACL aber vom Override-Server — ein
  Token-Mismatch besonders bei ACEs auf `SERVER\Administrators`,
  `BUILTIN\Users` oder fileserverlokalen Applikations­gruppen.

## Entscheidung / Decision

1. **Eine Quelle der Wahrheit** für UNC-Zerlegung im `validation`-Crate:

   - `validation::path::parse_unc_components(path) -> Option<(String, String)>`
     normalisiert vorab das Long-Path-Präfix (`\\?\UNC\…` → `\\…`),
     schliesst lokale Long-Path-Form (`\\?\C:\…`) explizit aus und prüft
     das doppelte Slash-/Backslash-Präfix vor dem Split.
   - `validation::path::effective_smb_target(path, explicit_smb_server)
     -> Option<String>` priorisiert den explizit gesetzten Server vor dem
     aus dem Pfad abgeleiteten UNC-Server.

2. **CLI und GUI nutzen beide den gleichen Helfer**. Die zwei alten
   lokalen `unc_components`-Implementierungen sind ersatzlos weg —
   `crates/cli/src/main.rs` und `crates/gui/src/worker.rs` importieren
   ausschliesslich aus `validation::path`.

3. **`collect_local_group_sids_for_path`** nimmt in CLI und GUI jetzt
   zusätzlich `explicit_smb_server: Option<&str>` entgegen und ruft
   `effective_smb_target` für die Server-Wahl.

4. **`resolve_scan_share_status` (CLI)** und **`resolve_share_status`
   (GUI)** leiten Server und Share über die zentralen Helfer ab. Der
   Aufruf­vertrag bleibt: lokaler Pfad ohne Override → `NotApplicable`.

## Begründung / Rationale

- **Eine Stelle, eine Wahrheit.** Die GUI hatte den Lokal-Pfad-Guard
  bereits — die CLI nicht. Das war eine echte Vertrauenslücke, die der
  Reviewer zu Recht auf High-Severity gesetzt hat.
- **Validation ist die richtige Schicht.** Pfade werden ohnehin dort
  validiert; UNC-Zerlegung liest dieselben Eingaben und gehört in dasselbe
  Modul.
- **Vorwärts-Kompatibilität mit Long-Path-Form.** Die Engine konnte
  `\\?\UNC\…` schon verarbeiten, nur die Orchestrierungs-Helfer nicht.
  Der Fix richtet beide Welten aufeinander aus.

## Konsequenzen / Consequences

- Externe Konsumenten der `unc_components`-Funktion in CLI / GUI gibt es
  nicht — die Symbole waren `fn`-private bzw. modul-private.
- Tests bleiben sichtbar in `validation::path` (zentrale Stelle) plus ein
  GUI-Smoke-Test, der die Sentinel-Konstellation aus Finding 1
  (`C:\Windows\SYSVOL` ohne Override → `NotApplicable`) abblockt.

## Tests / Tests

Neun Regressionstests in `validation::path::tests`:

- `parse_unc_components_rejects_local_paths` — `C:\Windows\SYSVOL`,
  `C:\Windows`, `D:\Daten\Abteilung`, `\singlebackslash\foo`, `""`.
- `parse_unc_components_accepts_classic_unc` — `\\server\share\sub`,
  `//server/share`.
- `parse_unc_components_handles_long_path_unc` — Hostname und
  IP-Adresse als Long-Path-UNC.
- `parse_unc_components_rejects_local_long_path` — `\\?\C:\…`,
  `\\?\D:\…`.
- `parse_unc_components_rejects_incomplete_unc` — `\\server`, `\\server\`.
- `effective_smb_target_prefers_explicit_server_for_local_path` — lokaler
  Pfad + Override → Override-Server.
- `effective_smb_target_prefers_explicit_server_for_unc` — UNC + Override
  → Override-Server.
- `effective_smb_target_falls_back_to_unc_server` — kein Override → UNC.
- `effective_smb_target_returns_none_for_local_path_without_override`.

Plus GUI: `share_status_does_not_treat_local_path_as_unc`.

## Schließt / Closes

ChatGPT-Code-Review 2026-06-04, Findings 1 (High), 2 (High) und 4 (Medium).
