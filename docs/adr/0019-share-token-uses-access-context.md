# ADR 0019 — Share-Token nutzt denselben AccessContext wie der NTFS-Token

**Status:** Accepted  
**Date:** 2026-05-24

## Context

ADR 0013 hat den `AccessContext` eingeführt: für UNC-Pfade fügt die
Engine `NETWORK` (S-1-5-2) implizit in den Access-Token auf, für lokale
Pfade `INTERACTIVE` + `LOCAL`. Dieses Bit floss korrekt in den
NTFS-Auswertungspfad ein.

Die Share-Maske wird jedoch **nicht** vom NTFS-Evaluator berechnet,
sondern vorab durch zwei eigene Helfer:

- `crates/cli/src/main.rs`: `resolve_scan_share_status`
- `crates/gui/src/worker.rs`: `resolve_share_status`

Beide bauten den Token über `build_token_sids_with_local`, welcher
intern auf `build_token_sids_with_context(_, _, _, Unspecified)`
delegiert. **Konsequenz**: Während der NTFS-Pfad bei einem UNC-Scan
`NETWORK` im Token hatte, fehlte derselbe SID im Share-Pfad —
Share-ACEs auf `NETWORK` (z. B. ein `Deny NETWORK Read`) wurden
ignoriert. Da das finale Ergebnis `NTFS ∩ Share` ist, vergiftete der
schwächere Share-Token jede effektive SMB-Berechnung.

Der Folge-Review (2026-05-24) hat das als High-Priority-Befund 1
korrekt identifiziert.

## Decision

1. **`resolve_scan_share_status` (CLI) und `resolve_share_status` (GUI)
   nehmen einen neuen Pflicht-Parameter `access_context: AccessContext`.**

2. **Beide bauen den Token jetzt über
   `build_token_sids_with_context(..., access_context)`** statt
   `build_token_sids_with_local`. Damit landet bei `RemoteSmb`
   automatisch `NETWORK` im Token (und bei `LocalInteractive`
   `INTERACTIVE` + `LOCAL`).

3. **Beide Aufrufer (CLI scan + analyze, GUI scan + analyze)
   berechnen `AccessContext::for_path(path)` und reichen genau
   denselben Wert sowohl an `resolve_*share_status` als auch an
   `PermissionEvaluationInput.access_context` weiter.** Damit ist
   ausgeschlossen, dass NTFS- und Share-Pfad mit unterschiedlichen
   Token-Kontexten auswerten.

4. **`build_token_sids_with_context` wird aus `permission_engine`
   re-exportiert.** `build_token_sids_with_local` bleibt aus
   Rückwärts-Kompatibilität bestehen, ist aber für CLI/GUI nicht mehr
   die richtige Wahl.

## Rationale

- **Korrektheit hat Vorrang vor Geschwindigkeit** (AGENTS.md,
  Grundregel 1). Eine in zwei Schritten falsch berechnete Maske ist
  ein direkter Audit-Schaden.
- **Symmetrie NTFS ↔ Share** — wenn die Engine kontextsensitiv ist,
  muss es der Share-Pfad auch sein, sonst poisoned der schwächere
  Token das `NTFS ∩ Share`-Ergebnis.
- **`AccessContext` einmal pro Aufruf ableiten und durchreichen** ist
  weniger fehlerträchtig als zweimal `for_path(path)` aufzurufen —
  letzteres wäre korrekt, aber durchgereicht zu sehen macht die
  Symmetrie offensichtlich.

## Consequences

- 3 neue Tests in `share_scanner::scanner::tests`:
  - `deny_network_share_ace_does_nothing_without_network_in_token`
    (Regressions-Baseline für das alte Verhalten — dient als
    expliziter „so war es vorher kaputt"-Marker)
  - `deny_network_share_ace_blocks_read_when_network_in_token`
    (das neue Sollverhalten)
  - `allow_network_share_ace_grants_when_network_in_token`
    (spiegelbildlich für Allow-NETWORK-Only-ACEs)
- Keine Schemaänderung, kein DB-Migration nötig.
- ADR 0013 bleibt gültig — dieser ADR ergänzt die fehlende
  Anwendung im Share-Pfad.
- Der bestehende `build_token_sids_with_local` ist nach diesem ADR
  formal noch öffentlich, in Produktivpfaden aber nicht mehr in
  Verwendung. Eine spätere Deprecation ist denkbar.
