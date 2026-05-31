# ADR 0013 — Zugriffskontext im Token (`AccessContext`)

**Status:** Akzeptiert / Accepted  
**Datum / Date:** 2026-05-24

## Kontext / Context

Die Permission Engine baute den Token-SID-Satz bisher unabhängig vom
Logon-Typ. Implizit hinzugefügt wurden nur `Everyone` (S-1-1-0) und
`Authenticated Users` (S-1-5-11). Windows ergänzt im realen
`AccessCheck` jedoch je nach Logon noch weitere Well-Known-SIDs:

- Remote-SMB-Logon → `NETWORK` (S-1-5-2)
- lokal interaktiver Logon → `INTERACTIVE` (S-1-5-4) und `LOCAL` (S-1-2-0)

Konsequenz im alten Verhalten:

- ACEs auf `NETWORK` (typisch für SMB-Audit-Setups: „Deny NETWORK ‹X›")
  wurden bei SMB-Analysen nie ausgewertet — die Engine konnte zu
  großzügig wirken und gleichzeitig Broad-Group-Risiken über `NETWORK`
  übersehen.
- Symmetrisches Problem bei `INTERACTIVE` für lokale Analysen.

Siehe Review-Befund 4.

## Entscheidung / Decision

1. **Neuer Enum `AccessContext`** in `adpa_core::model`:

   ```rust
   pub enum AccessContext {
       LocalInteractive,  // adds INTERACTIVE + LOCAL
       RemoteSmb,         // adds NETWORK
       #[default]
       Unspecified,       // adds nothing context-specific
   }
   ```

   `Unspecified` ist der Default und reproduziert exakt das alte
   Verhalten — bestehende Aufrufer, die noch keinen Kontext setzen,
   bekommen keine Verhaltensänderung untergeschoben.

2. **`PermissionEvaluationInput.access_context`** als neues Pflichtfeld.
   Die Engine ergänzt den Token gemäß dem Kontext und reicht das
   Ergebnis sonst unverändert weiter.

3. **Auto-Detection im Aufrufer:** `AccessContext::for_path(path)`
   leitet den Kontext aus der Pfadform ab:

   - UNC (`\\server\…`, inkl. Long-Path-Form `\\?\UNC\…`) → `RemoteSmb`
   - lokaler Pfad (`C:\…`, inkl. `\\?\C:\…`) → `LocalInteractive`

   CLI und GUI nutzen diesen Helfer einmalig pro Analyse-/Scan-Aufruf.

4. **Backwards-kompatible Public-API:** `build_token_sids` und
   `build_token_sids_with_local` bleiben erhalten und delegieren auf
   `build_token_sids_with_context(_, _, _, AccessContext::Unspecified)`.
   Neue Aufrufer verwenden die `_with_context`-Variante.

## Begründung / Rationale

- **Korrektheitsgewinn ohne Risiko für bestehende Aufrufer:** Der
  Default `Unspecified` lässt jeden alten Code unverändert funktionieren.
  Nur Aufrufer, die den Kontext aktiv setzen (CLI, GUI), bekommen das
  korrektere Verhalten.
- **Keine GUI-/CLI-spezifische Token-Logik:** Die Engine bleibt der
  einzige Ort, an dem Token-SIDs zusammengebaut werden — die Aufrufer
  liefern nur den Kontext. Das verhindert, dass Token-Erweiterungen
  später dupliziert oder vergessen werden.
- **Bewusst minimaler Satz Well-Knowns:** Nur `NETWORK`, `INTERACTIVE`,
  `LOCAL`. Weitere Logon-Typen (`BATCH` S-1-5-3, `SERVICE` S-1-5-6,
  `REMOTE_INTERACTIVE` S-1-5-14) lassen sich später hinzufügen, sobald
  ein konkreter Audit-Use-Case sie braucht.

## Konsequenzen / Consequences

- 9 neue Tests in `permission_engine::engine::tests`: NETWORK greift im
  SMB-Kontext, nicht in den anderen; INTERACTIVE/LOCAL spiegelbildlich;
  `Unspecified` ist das alte Verhalten; Deny-NETWORK überstimmt ein
  User-Allow im SMB-Audit-Pfad.
- 5 neue Tests in `adpa_core::model::tests` für `for_path`
  (Standardpfad, UNC, Long-Path-UNC, Long-Path-lokal).
- Persistenz/Export sind nicht betroffen — `AccessContext` lebt nur auf
  der Eingabeseite. `EffectivePermission` bleibt unverändert.
- Bestehende ADRs werden nicht widerrufen; ADR 0012
  (AccessCheck-Semantik) und 0013 (dieser) ergänzen sich.
